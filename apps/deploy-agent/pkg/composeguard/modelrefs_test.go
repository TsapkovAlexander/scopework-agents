package composeguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Вторая линия: ссылки на файлы в модели самого compose. Модели здесь —
// ровно того вида, что печатает `docker compose config` с ModelRefArgs
// (пути уже абсолютные); на настоящем compose их проверяет
// TestStackFileRefsDifferential.
func TestModelFileRefs(t *testing.T) {
	outside := stackDir(t, map[string]string{"neighbour.env": "PASSWORD=x\n"})
	root := stackDir(t, map[string]string{"a.env": "A=1\n"})
	if err := os.Symlink(filepath.Join(outside, "neighbour.env"), filepath.Join(root, "link.env")); err != nil {
		t.Fatal(err)
	}
	sf := StackFiles{Root: root, ProjectDir: root, AllowedAbs: []string{"/opt/agent/apps/x/.env"}}
	in := filepath.Join(root, "a.env")
	nb := "/opt/tracedocs/deploy/apps/neighbour/.env"

	refused := []struct{ name, model, want string }{
		{"env_file-outside", `{"services":{"app":{"env_file":[{"path":"` + nb + `","required":false}]}}}`, "env_file"},
		{"env_file-string", `{"services":{"app":{"env_file":["` + nb + `"]}}}`, "env_file"},
		{"env_file-variable", `{"services":{"app":{"env_file":[{"path":"` + root + `/${S}","required":false}]}}}`, "env_file"},
		{"env_file-parent", `{"services":{"app":{"env_file":[{"path":"` + root + `/../x/.env"}]}}}`, "env_file"},
		{"env_file-relative-parent", `{"services":{"app":{"env_file":[{"path":"../x/.env"}]}}}`, "env_file"},
		{"env_file-symlink-out", `{"services":{"app":{"env_file":[{"path":"` + filepath.Join(root, "link.env") + `"}]}}}`, "env_file"},
		{"label_file-outside", `{"services":{"app":{"label_file":["/etc/passwd"]}}}`, "label_file"},
		{"extends-left", `{"services":{"app":{"extends":{"file":"/etc/x.yml","service":"a"}}}}`, "extends"},
		{"include-left", `{"include":[{"path":["/opt/x/compose.yml"]}],"services":{"app":{}}}`, "include"},
		{"env_file-unknown-form", `{"services":{"app":{"env_file":[{"file":"a.env"}]}}}`, "env_file"},
		{"not-json", `services: {}`, "не читается"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			v := CheckModelFileRefs([]byte(tc.model), sf)
			mustRefuse(t, tc.name, v, tc.want)
			// Текст отказа — без путей и имён сервисов: если разбор текста
			// ошибся и compose прочёл чужое описание, его имена не уезжают.
			for _, x := range v {
				if strings.Contains(x.String(), "/") || strings.Contains(x.String(), "app") {
					t.Fatalf("в тексте отказа путь или имя сервиса: %s", x)
				}
			}
		})
	}

	accepted := []struct{ name, model string }{
		{"inside", `{"services":{"app":{"env_file":[{"path":"` + in + `","required":true}],"label_file":["` + in + `"]}}}`},
		{"missing-inside", `{"services":{"app":{"env_file":[{"path":"` + filepath.Join(root, "absent.env") + `","required":false}]}}}`},
		{"relative-inside", `{"services":{"app":{"env_file":["a.env"]}}}`},
		{"agent-own-env", `{"services":{"app":{"env_file":[{"path":"/opt/agent/apps/x/.env"}]}}}`},
		{"extends-same-file", `{"services":{"app":{"extends":"base"},"base":{}}}`},
		{"no-refs", `{"services":{"app":{"image":"nginx"}}}`},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if v := CheckModelFileRefs([]byte(tc.model), sf); len(v) != 0 {
				t.Fatalf("законная модель отвергнута: %v", v)
			}
		})
	}
}
