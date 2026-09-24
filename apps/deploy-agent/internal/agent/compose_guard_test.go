package agent

import (
	"strings"
	"testing"
)

// Правила политики проверяет pkg/composeguard (guard_test.go, те же имена
// тестов). Здесь — то, что зависит от агента: чей текст перед нами и что его
// обёртка отдаёт политике то же, что пакет.

const allowedRoot = "/opt/tracedocs/deploy/repos/backend"
const appRoot = "/opt/tracedocs/deploy/apps/backend"

func check(t *testing.T, json string) []composeViolation {
	t.Helper()
	v, err := checkComposeSafety([]byte(json), []string{allowedRoot, appRoot}, nil)
	if err != nil {
		t.Fatalf("разбор не удался: %v", err)
	}
	return v
}

// «Свой compose» (0185) — текст писал клиент, guard обязан включаться так же,
// как для репозиторного compose. Шаблоны каталога и рендер образа — нет: их
// пишет платформа.
func TestUntrustedComposeBySource(t *testing.T) {
	cases := map[string]bool{
		"git":      true,
		"compose":  true,
		"template": false,
		"image":    false,
	}
	for source, want := range cases {
		app := DesiredApp{SourceType: source}
		if got := app.UntrustedCompose(); got != want {
			t.Errorf("UntrustedCompose(%q) = %v, ожидалось %v", source, got, want)
		}
	}
}

// uts: host — пространство имён UTS хоста. Законного значения у стека клиента
// нет; пустое — норма после нормализации. В копии политики агента ключ стоял в
// разрешительном списке без правила и в режиме root проходил: в режиме proxy
// его ловил только dockerproxy.go.
func TestComposeGuardBlocksUtsHost(t *testing.T) {
	v := check(t, `{"services":{"x":{"uts":"host"}}}`)
	if len(v) != 1 || !strings.Contains(v[0].Reason, "uts") {
		t.Fatalf("uts: host не отклонено своим правилом: %v", v)
	}
	if ok := check(t, `{"services":{"x":{"uts":""}}}`); len(ok) != 0 {
		t.Fatalf("пустой uts отклонён: %v", ok)
	}
}

// cgroup_parent выводит контейнер из ветки cgroup docker в произвольную ветку
// хоста — мимо пределов и учёта, которые демон ставит своим контейнерам. Та же
// дыра копии агента, что у uts: ключ в разрешительном списке, правила нет.
func TestComposeGuardBlocksCgroupParent(t *testing.T) {
	v := check(t, `{"services":{"x":{"cgroup_parent":"/system.slice"}}}`)
	if len(v) != 1 || !strings.Contains(v[0].Reason, "cgroup_parent") {
		t.Fatalf("cgroup_parent не отклонён своим правилом: %v", v)
	}
	if ok := check(t, `{"services":{"x":{"cgroup_parent":""}}}`); len(ok) != 0 {
		t.Fatalf("пустой cgroup_parent отклонён: %v", ok)
	}
}
