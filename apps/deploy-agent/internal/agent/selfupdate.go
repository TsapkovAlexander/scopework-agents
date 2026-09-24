package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Самообновление агента.
//
// ЗАЧЕМ. Возможности агента приезжают вместе с его версией, а обновлялся он
// только руками: «зайдите на сервер и выполните команду установки заново».
// На практике это означало парк хостов с разными агентами и молча не
// работающие новые функции — боевой случай: защита домена паролем
// «включилась» в интерфейсе, а старый агент поля политики не знал и оставил
// домен открытым.
//
// КАК. Платформа объявляет целевую версию и сумму бинаря в ответе heartbeat.
// Агент, увидев расхождение, скачивает бинарь СО СВОЕЙ ЖЕ платформы (другого
// доверенного источника у него нет — тот же принцип, что в install.sh),
// сверяет sha256 из heartbeat-ответа, атомарно подменяет собственный файл и
// замещает процесс через exec. Systemd при этом ничего не замечает: PID тот
// же, Type=simple, никаких перезапусков-штормов.
//
// ДОВЕРИЕ. Сумма приезжает по TLS от платформы, которой агент уже доверяет
// адресом (https обязателен в клиенте). Подмена бинаря по пути требует
// сломать TLS до платформы — тот же уровень, на котором держится и выдача
// желаемого состояния с паролями БД.

// selfUpdateRetryAfter — экран от бесконечного цикла обновления.
//
// Если после подмены бинаря версия так и не совпала с целью (кривая сборка
// платформы: сумма от одного бинаря, ldflags от другого), без этого экрана
// агент качал бы и перезапускался каждый цикл. Час — достаточно, чтобы шум
// заметили по логам, и достаточно редко, чтобы не мешать хосту работать.
const selfUpdateRetryAfter = time.Hour

const updateMarkerFile = "self-update.json"

// agentExecutable — путь собственного бинаря. Подменяется тестами: иначе
// проверка подмены переписала бы бинарь самого прогона.
var agentExecutable = os.Executable

type updateMarker struct {
	Target string    `json:"target"`
	At     time.Time `json:"at"`
}

func (p Paths) updateMarkerPath() string { return filepath.Join(p.StateDir, updateMarkerFile) }

func readUpdateMarker(p Paths) *updateMarker {
	raw, err := os.ReadFile(p.updateMarkerPath())
	if err != nil {
		return nil
	}
	var m updateMarker
	if json.Unmarshal(raw, &m) != nil || m.Target == "" {
		return nil
	}
	return &m
}

func writeUpdateMarker(p Paths, target string) error {
	raw, err := json.Marshal(updateMarker{Target: target, At: time.Now()})
	if err != nil {
		return err
	}
	return os.WriteFile(p.updateMarkerPath(), raw, 0o600)
}

// ClearUpdateMarker снимает защиту от повторной попытки, когда обновление
// удалось: текущая версия совпала с целью маркера. Маркер ЧУЖОЙ цели
// остаётся — он всё ещё охраняет от цикла на той цели.
func ClearUpdateMarker(p Paths, currentVersion string) {
	m := readUpdateMarker(p)
	if m == nil {
		return
	}
	if m.Target == strings.TrimSpace(currentVersion) {
		_ = os.Remove(p.updateMarkerPath())
	}
}

func shouldSelfUpdate(current, target, targetSha string, m *updateMarker, now time.Time) bool {
	current = strings.TrimSpace(current)
	target = strings.TrimSpace(target)
	targetSha = strings.TrimSpace(targetSha)

	if target == "" || targetSha == "" {
		// Платформа без версии (сборка вне CI) или без бинаря — сравнивать
		// и проверять нечем.
		return false
	}
	if current == target {
		return false
	}
	// ОТКАТ ВЕРСИИ ЗАПРЕЩЁН (задача С1.3).
	//
	// Раньше агент шёл на любую версию, которую назвала платформа, — в том
	// числе на СТАРУЮ. Это готовый способ снять уже поставленную защиту:
	// платформа (или тот, кто ею завладел) объявляет целью версию, где ещё нет
	// compose-guard или проверки путей, агент послушно откатывается, и дальше
	// работает разбор без запретов.
	//
	// Обе версии должны читаться как MAJOR.MINOR.PATCH: нечитаемая цель — не
	// повод откатываться, это повод не трогать работающего агента.
	if !isNewerAgentVersion(current, target) {
		fmt.Fprintf(os.Stderr,
			"самообновление отклонено: цель %q не новее текущей %q — откат версии запрещён\n",
			target, current)
		return false
	}
	if m != nil && m.Target == target && now.Sub(m.At) < selfUpdateRetryAfter {
		return false
	}
	return true
}

// isNewerAgentVersion — строго ли target новее current (обе MAJOR.MINOR.PATCH).
//
// Нечитаемая версия с любой стороны — «не новее»: обновление по непонятной
// метке опаснее, чем его отсутствие.
func isNewerAgentVersion(current, target string) bool {
	c, okc := parseAgentVersion(current)
	t, okt := parseAgentVersion(target)
	if !okc || !okt {
		return false
	}
	for i := 0; i < 3; i++ {
		if t[i] != c[i] {
			return t[i] > c[i]
		}
	}
	return false
}

func parseAgentVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return out, false
		}
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return out, false
			}
			n = n*10 + int(ch-'0')
			if n > 1_000_000 {
				return out, false
			}
		}
		out[i] = n
	}
	return out, true
}

// verifyAgentBinary — проверки скачанного, ДО подмены собственного файла.
//
// Сумма — главное; ELF-магия и непустота отсекают самый частый мусор ещё
// понятнее: страницу ошибки от прокси вместо бинаря видно по первой строке
// сообщения, а не по несовпадению хешей.
func verifyAgentBinary(path, expectedSha string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("скачанный бинарь пуст")
	}
	if len(raw) < 4 || !bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return fmt.Errorf("скачанное не является линукс-бинарём (нет ELF-заголовка)")
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, strings.TrimSpace(expectedSha)) {
		return fmt.Errorf("контрольная сумма не совпала: получено %s, ожидалось %s", got, expectedSha)
	}
	return nil
}

// replaceAgentBinary атомарно подменяет бинарь: временный файл в ТОМ ЖЕ
// каталоге (rename между файловыми системами не атомарен), права 0755,
// затем rename поверх. Запущенный процесс продолжает работать со старым
// inode — это штатно, exec подхватит новый файл.
func replaceAgentBinary(binPath string, content []byte) error {
	dir := filepath.Dir(binPath)
	tmp, err := os.CreateTemp(dir, ".agent-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	// Временный файл убираем при любом исходе: после rename его уже нет и
	// Remove промолчит, а при ошибке — не оставим мусора рядом с бинарём.
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, binPath)
}

// PrepareSelfUpdate решает, нужно ли обновляться, и если да — скачивает,
// проверяет и подменяет бинарь. Возвращает путь для exec.
//
// Никогда не роняет агента: любой сбой — это лог и работа дальше старой
// версией. Хуже необновлённого агента только мёртвый.
func PrepareSelfUpdate(
	ctx context.Context,
	client *Client,
	p Paths,
	hb HeartbeatResponse,
	currentVersion string,
) (string, bool) {
	targetSha := hb.TargetAgentSha256.ForArch(runtime.GOARCH)
	if !shouldSelfUpdate(currentVersion, hb.TargetAgentVersion, targetSha, readUpdateMarker(p), time.Now()) {
		return "", false
	}
	// Испорченные ключи в сборке — отказ ДО загрузки: скачанное всё равно не
	// прошло бы проверку подписи. Маркер — чтобы не повторять это каждый такт.
	if err := ReleaseKeysError(); err != nil {
		fmt.Fprintf(os.Stderr, "самообновление: %v, обновление отменено\n", err)
		_ = writeUpdateMarker(p, hb.TargetAgentVersion)
		return "", false
	}

	binPath, err := agentExecutable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "самообновление: путь к бинарю не определился: %v\n", err)
		return "", false
	}

	fmt.Printf("самообновление: %s -> %s\n", currentVersion, hb.TargetAgentVersion)

	content, signature, err := client.DownloadAgentBinary(ctx, runtime.GOARCH)
	if err != nil {
		fmt.Fprintf(os.Stderr, "самообновление: загрузка не удалась: %v\n", err)
		return "", false
	}

	// Проверка до подмены — на временных данных.
	sum := sha256.Sum256(content)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), strings.TrimSpace(targetSha)) {
		fmt.Fprintf(os.Stderr, "самообновление: сумма бинаря не совпала, обновление отменено\n")
		// Помечаем цель как неудачную: без этого следующая итерация качала бы
		// тот же битый бинарь каждый цикл.
		_ = writeUpdateMarker(p, hb.TargetAgentVersion)
		return "", false
	}
	// ПОДПИСЬ ВЫПУСКА (ADR-0082, задача С1.3). Сумма выше отвечает на вопрос
	// «дошло ли целым» — она приезжает от той же стороны, что и файл. Подпись
	// отвечает на вопрос «то ли прислали»: ключ лежит офлайн у человека, и
	// платформа, которой завладели, подписать чужой бинарь не может.
	//
	// Пока ключ не выпущен, проверка пропускается (см. release_trust.go): иначе
	// правка сломала бы всех работающих агентов в день, когда подписывать нечем.
	if err := VerifyReleaseSignature(
		ReleaseBinaryMessage(hb.TargetAgentVersion, hex.EncodeToString(sum[:]), runtime.GOARCH),
		signature,
	); err != nil {
		fmt.Fprintf(os.Stderr, "самообновление: %v, обновление отменено\n", err)
		_ = writeUpdateMarker(p, hb.TargetAgentVersion)
		return "", false
	}

	if len(content) < 4 || !bytes.Equal(content[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		fmt.Fprintf(os.Stderr, "самообновление: скачанное не является бинарём, обновление отменено\n")
		_ = writeUpdateMarker(p, hb.TargetAgentVersion)
		return "", false
	}

	// Маркер ставится ДО подмены: если новый бинарь окажется с неверной
	// версией внутри, защита от цикла уже будет на диске.
	if err := writeUpdateMarker(p, hb.TargetAgentVersion); err != nil {
		fmt.Fprintf(os.Stderr, "самообновление: маркер не записался (%v), обновление отложено\n", err)
		return "", false
	}

	if err := replaceAgentBinary(binPath, content); err != nil {
		fmt.Fprintf(os.Stderr, "самообновление: подмена бинаря не удалась: %v\n", err)
		// Отдельная подсказка на самый частый и самый непрозрачный случай:
		// systemd-юнит с ProtectSystem=full делает /usr только для чтения, и
		// каталог бинаря в него не входит. Агент при этом исправно пытается
		// обновиться каждую минуту и остаётся на прежней версии навсегда —
		// понять причину по строке «read-only file system» почти невозможно.
		if errors.Is(err, syscall.EROFS) || strings.Contains(err.Error(), "read-only file system") {
			fmt.Fprintf(os.Stderr,
				"самообновление: каталог %s недоступен на запись из-под systemd. "+
					"Выполните команду подключения сервера заново — она перепишет юнит "+
					"с нужными правами (ReadWritePaths).\n",
				filepath.Dir(binPath))
		}
		return "", false
	}

	return binPath, true
}
