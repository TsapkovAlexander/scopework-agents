package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Номер отчёта такта (ADR-0077, решение 1).
//
// ЗАЧЕМ. Неудачная отправка теряла такт без следа и у агента, и у платформы:
// молчание агента и потерянный отчёт снаружи неразличимы. С номером платформа
// сама видит пропуск, сброс эпохи и откат — без доверия к тому, что агент о
// себе рассказывает.
//
// ЭПОХА ВМЕСТО ОДНОГО СЧЁТЧИКА. Файл номера на чужом сервере может пропасть
// (переустановка, чистка каталога, root клиента). Счёт с единицы в той же
// эпохе выглядел бы откатом номера — сигналом, который открывает инцидент.
// Новая случайная эпоха честно говорит «счёт начат заново».

// MaxReportSeq — 2^53−1, наибольшее целое, которое платформа разбирает из JSON
// без потери точности. Следующий номер после него округлился бы в уже
// выданный.
const MaxReportSeq int64 = 1<<53 - 1

var reportEpochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ReportNumber — ключ отчёта такта.
type ReportNumber struct {
	Epoch string `json:"epoch"`
	Seq   int64  `json:"seq"`
}

func (p Paths) reportSeqPath() string {
	return filepath.Join(p.StateDir, "report-seq.json")
}

// ReserveReportNumber выдаёт следующий номер и записывает его на диск ДО
// отправки.
//
// Порядок обязателен: номер, отправленный и не записанный, после рестарта был
// бы выдан второй раз — то есть рестарт выглядел бы откатом. Не удалось
// записать — номера нет, и такт уходит без секции report: пропуск номера
// платформа переживёт, повтор — нет.
func ReserveReportNumber(p Paths) (ReportNumber, error) {
	next, ok := loadReportNumber(p)
	if ok && next.Seq < MaxReportSeq {
		next.Seq++
	} else {
		epoch, err := newReportEpoch()
		if err != nil {
			return ReportNumber{}, err
		}
		next = ReportNumber{Epoch: epoch, Seq: 1}
	}

	raw, err := json.Marshal(next)
	if err != nil {
		return ReportNumber{}, err
	}
	if err := writeFileAtomic(p.reportSeqPath(), raw, 0o600); err != nil {
		return ReportNumber{}, fmt.Errorf("номер отчёта не записан: %w", err)
	}
	return next, nil
}

// loadReportNumber — прежний номер. Битый файл равносилен отсутствующему:
// продолжать счёт с догадки хуже, чем честно начать новую эпоху.
func loadReportNumber(p Paths) (ReportNumber, bool) {
	raw, err := os.ReadFile(p.reportSeqPath())
	if err != nil {
		return ReportNumber{}, false
	}
	var n ReportNumber
	if json.Unmarshal(raw, &n) != nil ||
		!reportEpochPattern.MatchString(n.Epoch) ||
		n.Seq < 1 || n.Seq > MaxReportSeq {
		return ReportNumber{}, false
	}
	return n, true
}

func newReportEpoch() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("не удалось получить случайную эпоху: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
