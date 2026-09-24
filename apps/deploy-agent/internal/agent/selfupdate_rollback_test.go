package agent

import (
	"testing"
	"time"
)

// Откат версии агента запрещён (задача С1.3).
//
// Платформа называет агенту целевую версию, и до 18.09.2026 он шёл на любую —
// включая старую. Это готовый способ снять уже поставленную защиту: объявить
// целью версию, где ещё нет compose-guard или проверки путей, и дождаться, пока
// агент послушно откатится.
func TestSelfUpdateRefusesRollback(t *testing.T) {
	cases := []struct {
		name    string
		current string
		target  string
		want    bool
	}{
		{"на новую — идём", "2.0.0", "2.1.0", true},
		{"патч новее — идём", "2.0.0", "2.0.1", true},
		{"мажор новее — идём", "2.9.9", "3.0.0", true},
		{"откат на предыдущую — нет", "2.1.0", "2.0.0", false},
		{"откат мажора — нет", "3.0.0", "2.9.9", false},
		{"та же версия — нет", "2.0.0", "2.0.0", false},
		{"нечитаемая цель — нет", "2.0.0", "latest", false},
		{"нечитаемая текущая — нет", "dev", "2.0.0", false},
		{"мусор с ведущим нулём — нет", "2.0.0", "2.01.0", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSelfUpdate(tc.current, tc.target, "0123456789abcdef", nil, time.Now())
			if got != tc.want {
				t.Fatalf("shouldSelfUpdate(%q -> %q) = %v, ожидалось %v",
					tc.current, tc.target, got, tc.want)
			}
		})
	}
}

// Сравнение версий — отдельно: от него зависит, можно ли увести агента назад.
func TestIsNewerAgentVersion(t *testing.T) {
	if !isNewerAgentVersion("1.0.0", "1.0.1") {
		t.Error("1.0.1 новее 1.0.0")
	}
	if isNewerAgentVersion("1.10.0", "1.9.9") {
		t.Error("1.9.9 не новее 1.10.0 — сравнение по числам, а не по строкам")
	}
	if isNewerAgentVersion("2.0.0", "2.0.0") {
		t.Error("та же версия не новее")
	}
	if isNewerAgentVersion("", "2.0.0") || isNewerAgentVersion("2.0.0", "") {
		t.Error("пустая версия не участвует в сравнении")
	}
}
