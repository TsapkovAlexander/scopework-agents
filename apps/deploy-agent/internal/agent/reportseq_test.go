package agent

import (
	"encoding/json"
	"os"
	"regexp"
	"runtime"
	"testing"
)

// Номер отчёта такта (ADR-0077, решение 1). Платформа по нему отличает
// пропуск от сброса и отката, поэтому всё, что ломает счёт, ломает и сигнал:
// рестарт, начинающий с единицы, выглядел бы откатом номера.

var epochPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestReserveReportNumberStartsAndContinues(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}

	first, err := ReserveReportNumber(p)
	if err != nil {
		t.Fatal(err)
	}
	if !epochPattern.MatchString(first.Epoch) || first.Seq != 1 {
		t.Fatalf("первый номер %+v, ожидалась новая эпоха и seq=1", first)
	}

	// Функция не держит состояния в памяти: второй вызов — то же, что вызов
	// после рестарта процесса, счёт обязан продолжиться с диска.
	second, err := ReserveReportNumber(p)
	if err != nil {
		t.Fatal(err)
	}
	if second.Epoch != first.Epoch || second.Seq != 2 {
		t.Fatalf("после рестарта %+v, ожидалась та же эпоха и seq=2", second)
	}

	var onDisk ReportNumber
	raw, err := os.ReadFile(p.reportSeqPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &onDisk); err != nil || onDisk != second {
		t.Fatalf("на диске %s, ожидалось %+v", raw, second)
	}
}

func TestReserveReportNumberNewEpochOnBrokenOrMissingFile(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	first, err := ReserveReportNumber(p)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(){
		"битый JSON": func() { writeRaw(t, p, `{"epoch":`) },
		"эпоха в верхнем регистре": func() { writeRaw(t, p, `{"epoch":"3F2A9C1E0B7D4E6FA1C2D3E4F5A6B7C8","seq":5}`) },
		"seq ноль":    func() { writeRaw(t, p, `{"epoch":"3f2a9c1e0b7d4e6fa1c2d3e4f5a6b7c8","seq":0}`) },
		"файл удалён": func() { _ = os.Remove(p.reportSeqPath()) },
	}
	for name, spoil := range cases {
		t.Run(name, func(t *testing.T) {
			spoil()
			got, err := ReserveReportNumber(p)
			if err != nil {
				t.Fatal(err)
			}
			if got.Seq != 1 || !epochPattern.MatchString(got.Epoch) || got.Epoch == first.Epoch {
				t.Fatalf("получено %+v, ожидалась новая эпоха и seq=1", got)
			}
		})
	}
}

// 2^53−1 — предел целого числа, которое платформа разбирает без потери
// точности. Шагнуть за него значит отправить номер, который на той стороне
// округлится и совпадёт с предыдущим.
func TestReserveReportNumberRollsEpochAtMaxSeq(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	const epoch = "3f2a9c1e0b7d4e6fa1c2d3e4f5a6b7c8"

	writeRaw(t, p, `{"epoch":"`+epoch+`","seq":9007199254740990}`)
	got, err := ReserveReportNumber(p)
	if err != nil || got.Epoch != epoch || got.Seq != MaxReportSeq {
		t.Fatalf("до предела: %+v, %v", got, err)
	}

	got, err = ReserveReportNumber(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch == epoch || got.Seq != 1 {
		t.Fatalf("после предела %+v, ожидалась новая эпоха и seq=1", got)
	}
}

// Не удалось записать — номера нет. Отправить номер, не записанный на диск,
// значит после рестарта выдать его второй раз, а это откат номера.
func TestReserveReportNumberFailsOnReadOnlyDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("права каталога не ограничивают root")
	}
	p := Paths{StateDir: t.TempDir()}
	if err := os.Chmod(p.StateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p.StateDir, 0o700) })

	if got, err := ReserveReportNumber(p); err == nil {
		t.Fatalf("резерв в каталоге только для чтения прошёл: %+v", got)
	}
}

func writeRaw(t *testing.T, p Paths, content string) {
	t.Helper()
	if err := os.WriteFile(p.reportSeqPath(), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
