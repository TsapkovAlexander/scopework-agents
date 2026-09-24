package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Защёлки против отката подписанного состояния (ADR-0093, решение 5).
//
// Последний принятый номер, sha256 его нагрузки и наибольший serial
// сертификата. Без них повтор старого честно подписанного пакета вернул бы
// хост к прежнему составу — подпись у такого пакета верна.
//
// hostId не закрепляется (ADR-0092, решение 4): пересоздание хоста на
// платформе при том же ключе агента заперло бы выкаты до ручного снятия файла.
// Привязка — только отпечаток агента.

// stateLatchFile — имя файла в каталоге состояния агента.
const stateLatchFile = "state-trust.json"

// stateLatchMaxBytes — файл пишет только агент, и он меньше полукилобайта.
// Больший — не наш, и читать его целиком незачем.
const stateLatchMaxBytes = 4 << 10

var latchHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// stateLatchDisk — форма файла. Версия отдельным полем: другой формат
// защёлок новой сборки агента не должен молча читаться как этот.
type stateLatchDisk struct {
	V                int    `json:"v"`
	AgentFingerprint string `json:"agentFingerprint"`
	Seq              int64  `json:"seq"`
	PayloadSHA256    string `json:"payloadSha256"`
	MaxCertSerial    int64  `json:"maxCertSerial"`
}

// latchSync — fsync файла или каталога. Переменная — ради теста, который
// проверяет, что синхронизируются оба и в этом порядке.
var latchSync = func(f *os.File) error { return f.Sync() }

// loadStateLatch читает защёлки для отпечатка fingerprint.
//
// Нет файла или он чужого отпечатка — свежая защёлка: переустановка агента —
// действие root на хосте, и проверка начинается заново. Файл есть, но не
// читается или не разбирается — ошибка, а не сброс к умолчанию: сброс открыл
// бы дорогу повтору старого пакета. Снимает такой файл человек на сервере.
func loadStateLatch(stateDir, fingerprint string) (hoststate.Latch, error) {
	f, err := os.Open(filepath.Join(stateDir, stateLatchFile))
	if errors.Is(err, fs.ErrNotExist) {
		return hoststate.Latch{}, nil
	}
	if err != nil {
		return hoststate.Latch{}, fmt.Errorf("файл защёлок не открывается: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, stateLatchMaxBytes+1))
	if err != nil {
		return hoststate.Latch{}, fmt.Errorf("файл защёлок не читается: %w", err)
	}
	if len(raw) > stateLatchMaxBytes {
		return hoststate.Latch{}, fmt.Errorf("файл защёлок больше %d байт", stateLatchMaxBytes)
	}

	var disk stateLatchDisk
	if err := signenv.DecodeStrict(raw, &disk); err != nil {
		return hoststate.Latch{}, fmt.Errorf("файл защёлок не разбирается: %w", err)
	}
	if disk.V != 1 {
		return hoststate.Latch{}, fmt.Errorf("файл защёлок версии %d, агент читает 1", disk.V)
	}
	// Файл пишется только после принятого пакета, поэтому все поля заданы.
	// Пустое или нулевое поле — порча, и считать её «ничего не принято»
	// значило бы сбросить защёлку.
	if !latchHex64.MatchString(disk.AgentFingerprint) || disk.Seq < 1 ||
		!latchHex64.MatchString(disk.PayloadSHA256) || disk.MaxCertSerial < 1 {
		return hoststate.Latch{}, errors.New("файл защёлок испорчен: поля вне допустимых значений")
	}
	if disk.AgentFingerprint != fingerprint {
		return hoststate.Latch{}, nil
	}
	return hoststate.Latch{
		AgentFingerprint: disk.AgentFingerprint,
		Seq:              disk.Seq,
		PayloadSHA256:    disk.PayloadSHA256,
		MaxCertSerial:    disk.MaxCertSerial,
	}, nil
}

// saveStateLatch записывает защёлки так, чтобы после сбоя питания на диске
// оказалась либо прежняя, либо новая версия, и новая — действительно на
// диске. У номера отчёта ADR-0077 шов без fsync принят; здесь он вернул бы
// прежний номер, и агент принял бы пакет, который уже отверг бы.
//
// writeFileAtomic для этого не годится: он не делает fsync ни файла, ни
// каталога.
func saveStateLatch(stateDir string, l hoststate.Latch) error {
	raw, err := json.Marshal(stateLatchDisk{
		V:                1,
		AgentFingerprint: l.AgentFingerprint,
		Seq:              l.Seq,
		PayloadSHA256:    l.PayloadSHA256,
		MaxCertSerial:    l.MaxCertSerial,
	})
	if err != nil {
		return err
	}

	// Временный файл — в том же каталоге: rename атомарен только в пределах
	// одной файловой системы.
	tmp, err := os.CreateTemp(stateDir, ".state-trust-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := latchSync(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync файла защёлок: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, filepath.Join(stateDir, stateLatchFile)); err != nil {
		return err
	}

	// Без fsync каталога переименование может не пережить сбой питания, и на
	// диске останется прежний файл.
	dir, err := os.Open(stateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := latchSync(dir); err != nil {
		return fmt.Errorf("fsync каталога защёлок: %w", err)
	}
	return nil
}
