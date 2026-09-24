package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

func testHex(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func testLatch(fingerprint string, seq int64) hoststate.Latch {
	return hoststate.Latch{
		AgentFingerprint: fingerprint,
		Seq:              seq,
		PayloadSHA256:    testHex("payload"),
		MaxCertSerial:    8,
	}
}

// Запись обязана дойти до диска: без fsync файла и каталога сбой питания
// вернёт прежний номер, и агент примет пакет, который уже отверг бы
// (ADR-0093, решение 5).
func TestLatchDurableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	fp := testHex("agent")

	var synced []string
	prev := latchSync
	latchSync = func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		kind := "файл"
		if info.IsDir() {
			kind = "каталог"
		}
		synced = append(synced, kind)
		return f.Sync()
	}
	t.Cleanup(func() { latchSync = prev })

	want := testLatch(fp, 5)
	if err := saveStateLatch(dir, want); err != nil {
		t.Fatal(err)
	}
	if strings.Join(synced, ",") != "файл,каталог" {
		t.Fatalf("fsync: %v, ожидалось сначала файл, затем каталог", synced)
	}
	got, err := loadStateLatch(dir, fp)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("прочитано %+v, записано %+v", got, want)
	}

	// Сбой fsync — ошибка записи, и прежняя защёлка остаётся как была.
	latchSync = func(*os.File) error { return errors.New("диск отказал") }
	if err := saveStateLatch(dir, testLatch(fp, 6)); err == nil {
		t.Fatal("сбой fsync не стал ошибкой записи")
	}
	got, err = loadStateLatch(dir, fp)
	if err != nil || got != want {
		t.Fatalf("после сбоя записи защёлка %+v (%v), ожидалась прежняя", got, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("после сбоя в каталоге остались временные файлы: %d записей", len(entries))
	}
}

func TestLatchMissingIsFresh(t *testing.T) {
	got, err := loadStateLatch(t.TempDir(), testHex("agent"))
	if err != nil {
		t.Fatalf("нет файла — ошибка %v, ожидалась свежая защёлка", err)
	}
	if got != (hoststate.Latch{}) {
		t.Fatalf("свежая защёлка не пустая: %+v", got)
	}
}

// Испорченный файл — отказ, а не сброс к умолчанию: сброс открыл бы дорогу
// повтору старого пакета (ADR-0093, решение 5).
func TestLatchCorruptRefuses(t *testing.T) {
	fp := testHex("agent")
	good := `{"v":1,"agentFingerprint":"` + fp + `","seq":5,"payloadSha256":"` + testHex("payload") + `","maxCertSerial":8}`
	cases := map[string]string{
		"не JSON":             "{обрезано",
		"пустой файл":         "",
		"другая версия":       strings.Replace(good, `"v":1`, `"v":2`, 1),
		"без версии":          strings.Replace(good, `"v":1,`, "", 1),
		"незнакомое поле":     strings.Replace(good, `"v":1,`, `"v":1,"extra":true,`, 1),
		"данные после JSON":   good + " {}",
		"отрицательный номер": strings.Replace(good, `"seq":5`, `"seq":-1`, 1),
		"хеш не hex64":        strings.Replace(good, testHex("payload"), "abc", 1),
		"отпечаток не hex64":  strings.Replace(good, fp, "short", 1),
		"serial ноль":         strings.Replace(good, `"maxCertSerial":8`, `"maxCertSerial":0`, 1),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, stateLatchFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := loadStateLatch(dir, fp); err == nil {
				t.Fatalf("испорченный файл принят: %+v", got)
			}
		})
	}

	t.Run("не читается", func(t *testing.T) {
		dir := t.TempDir()
		// Каталог на месте файла — чтение падает, а файл «есть».
		if err := os.Mkdir(filepath.Join(dir, stateLatchFile), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStateLatch(dir, fp); err == nil {
			t.Fatal("нечитаемый файл сочтён отсутствующим")
		}
	})

	t.Run("целый файл читается", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, stateLatchFile), []byte(good), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStateLatch(dir, fp); err != nil {
			t.Fatalf("образец испорченных случаев сам не читается: %v", err)
		}
	})
}

// Защёлка другого отпечатка — след прежней установки агента: переустановка —
// действие root на хосте, и проверка начинается заново.
func TestLatchOtherFingerprintIsFresh(t *testing.T) {
	dir := t.TempDir()
	if err := saveStateLatch(dir, testLatch(testHex("old-agent"), 40)); err != nil {
		t.Fatal(err)
	}
	got, err := loadStateLatch(dir, testHex("agent"))
	if err != nil {
		t.Fatal(err)
	}
	if got != (hoststate.Latch{}) {
		t.Fatalf("защёлка чужого отпечатка не сброшена: %+v", got)
	}
}

func TestLatchFilePerm0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateLatchFile)
	// Прежний файл с широкими правами: запись заменяет его, а не наследует.
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := saveStateLatch(dir, testLatch(testHex("agent"), 1)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("права файла защёлок %o, ожидалось 600", perm)
	}
}
