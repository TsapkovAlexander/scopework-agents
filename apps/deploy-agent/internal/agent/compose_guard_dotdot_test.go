package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Сегмент `..` в абсолютном пути compose.
//
// Относительные пути compose очищает сам (`./l/../x` → `<каталог>/x`, и демону
// уходит уже очищенный путь), а абсолютные отдаёт как написаны — в bind,
// secrets.file и build.additional_contexts (замерено на compose v5.3.1).
// filepath.Clean убирает `l/..` лексически, ядро разрешает `..` после ссылки:
// при `l -> <вне>/deep` путь `<корень>/l/../secret` ведёт в `<вне>/secret`.
func TestComposeGuardDotDotPosleSsylki(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "app")
	outside := filepath.Join(tmp, "outside")
	for _, d := range []string{root, filepath.Join(outside, "deep"), filepath.Join(outside, "secret")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	// Строкой, а не filepath.Join: Join очистил бы `..` так же, как guard.
	src := root + "/l/../secret"
	svc := func(v map[string]any) map[string]any {
		return map[string]any{"services": map[string]any{"app": v}}
	}
	cases := []struct {
		name  string
		model map[string]any
	}{
		{"bind", svc(map[string]any{"volumes": []any{map[string]any{"type": "bind", "source": src, "target": "/h"}}})},
		{"bind, .. в конце", svc(map[string]any{"volumes": []any{map[string]any{"type": "bind", "source": root + "/l/..", "target": "/h"}}})},
		{"secrets.file", map[string]any{
			"services": map[string]any{"app": map[string]any{"image": "nginx"}},
			"secrets":  map[string]any{"k": map[string]any{"file": src}},
		}},
		{"build.additional_contexts", svc(map[string]any{"build": map[string]any{"context": root, "additional_contexts": map[string]any{"x": root + "/l/.."}}})},
		{"build.context", svc(map[string]any{"build": map[string]any{"context": root + "/l/.."}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.model)
			v, err := checkComposeSafety(raw, []string{root}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(v) == 0 {
				t.Fatalf("guard пропустил `..` после ссылки: %s", raw)
			}
		})
	}
}

// `..` — сегмент, а не подстрока; очищенный compose'ом относительный путь
// проходит как раньше.
func TestComposeGuardDvePointsVImeniProhodit(t *testing.T) {
	root := t.TempDir()
	for _, src := range []string{root + "/a..b", root + "/a..b/data", root + "/..hidden", root + "/data"} {
		t.Run(src, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"services": map[string]any{"app": map[string]any{
				"volumes": []any{map[string]any{"type": "bind", "source": src, "target": "/h"}},
			}}})
			v, err := checkComposeSafety(raw, []string{root}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(v) != 0 {
				t.Fatalf("guard отбил законный путь %s: %v", src, v)
			}
		})
	}
}
