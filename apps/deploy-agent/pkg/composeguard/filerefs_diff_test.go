package composeguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Дифференциальная проверка: враждебные формы описания прогоняются через
// настоящий `docker compose config`, и если compose видит ссылку наружу
// приложения — на .env или описание соседа, — CheckStackFileRefs обязан
// отказать, а вторая линия (CheckModelFileRefs) — отказать по той же модели.
//
// Разбор YAML здесь свой, и оба обхода второго круга были расхождением с
// go-yaml. Список форм в TestStackFileRefsRefusesAttacks проверяет, что
// разбор думает; этот тест — что думает compose. Без docker он не зеленеет
// молча, а пропускается со словами «проверка не проведена».
func TestStackFileRefsDifferential(t *testing.T) {
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("проверка не проведена: docker compose недоступен (" + err.Error() + ")")
	}

	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nb := filepath.Join(base, "neighbour")
	if err := os.MkdirAll(nb, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		".env":               "LEAKED_SECRET=1\n",
		"docker-compose.yml": "services:\n  nbsvc:\n    image: alpine\n    env_file: .env\n",
	} {
		if err := os.WriteFile(filepath.Join(nb, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	envV := "[{path: NB/.env, required: false}]"
	envJ := `[{"path": "NB/.env", "required": false}]`
	values := map[string][2]string{ // поле → значение YAML и JSON
		"env_file":   {envV, envJ},
		"label_file": {"NB/.env", `"NB/.env"`},
		"extends":    {"{file: NB/docker-compose.yml, service: nbsvc}", `{"file": "NB/docker-compose.yml", "service": "nbsvc"}`},
	}
	// Обёртки: K — имя поля, V — значение, J — значение в JSON, B — имя поля
	// в base64. Каждая — способ поставить ключ сервиса туда, где его может не
	// увидеть разбор текста.
	serviceForms := map[string]string{
		"block":                     "services:\n  app:\n    image: alpine\n    K: V\n",
		"flow":                      "services:\n  app: {image: alpine, K: V}\n",
		"json":                      `{"services": {"app": {"image": "alpine", "K": J}}}` + "\n",
		"json-colon-next-line":      `{"services": {"app": {"image": "alpine", "K"` + "\n" + `: J}}}` + "\n",
		"multiline-dq-hash":         "services:\n  app: {image: alpine, labels: {a: \"x\n    #y\"}, K: V}\n",
		"multiline-sq-hash":         "services:\n  app: {image: alpine, labels: {a: 'x\n    #y'}, K: V}\n",
		"multiline-dq-block":        "services:\n  app:\n    image: alpine\n    labels:\n      a: \"x\n    #y\"\n    K: V\n",
		"explicit-key-flow":         "services:\n  app: {image: alpine, ? K\n    : V}\n",
		"explicit-key-flow-nospace": "services:\n  app: {image: alpine, ?K : V}\n",
		"explicit-key-block":        "services:\n  app:\n    image: alpine\n    ? K\n    : V\n",
		"anchor-merge":              "x-a: &a\n  K: V\nservices:\n  app:\n    <<: *a\n    image: alpine\n",
		"merge-list":                "x-a: &a\n  K: V\nx-b: &b\n  image: alpine\nservices:\n  app:\n    <<: [*b, *a]\n",
		"tag-str-key":               "services:\n  app:\n    image: alpine\n    !!str K: V\n",
		"tag-binary-key":            "services:\n  app:\n    image: alpine\n    !!binary B: V\n",
		"quoted-key-dq":             "services:\n  app:\n    image: alpine\n    \"K\": V\n",
		"quoted-key-sq":             "services:\n  app:\n    image: alpine\n    'K': V\n",
		"escaped-key":               "services:\n  app:\n    image: alpine\n    \"E\": V\n",
		"flow-plain-continuation":   "services:\n  app: {image: alpine, labels: {a: foo\n    \"x, y\" }, K: V}\n",
		"block-plain-continuation":  "services:\n  app:\n    image: alpine\n    labels:\n      k: foo\n        - {x\n    K: V\n",
		"flow-value-next-line":      "services:\n  app: {image: alpine, K:\n    V}\n",
		"flow-comment":              "services:\n  app: {image: alpine, # c\n    K: V}\n",
		"block-scalar-then-key":     "services:\n  app:\n    image: alpine\n    command: |\n      echo \"{\n    K: V\n",
		"tab-after-colon":           "services:\n  app:\n    image: alpine\n    K:\tV\n",
		"crlf":                      "services:\r\n  app:\r\n    image: alpine\r\n    K: V\r\n",
		"multi-document":            "services:\n  app:\n    image: alpine\n---\nservices:\n  app:\n    K: V\n",
		"anchor-on-value":           "services:\n  app:\n    image: alpine\n    K: &p V\n",
		"override-tag":              "services:\n  app:\n    image: alpine\n    K: !override V\n",
		"alias-key":                 "x-k: &k K\nservices:\n  app:\n    image: alpine\n    *k : V\n",
		"value-after-comment-line":  "services:\n  app:\n    image: alpine\n    K:\n      # c\n      V\n",
	}
	includeForms := map[string]string{
		"include-block":           "include:\n  - NB/docker-compose.yml\nservices:\n  app:\n    image: alpine\n",
		"include-flow-document":   "{include: [NB/docker-compose.yml], services: {app: {image: alpine}}}\n",
		"include-json":            `{"include": ["NB/docker-compose.yml"], "services": {"app": {"image": "alpine"}}}` + "\n",
		"include-multiline-quote": "{services: {app: {image: alpine}}, x-l: 'x\n  #y', include: [NB/docker-compose.yml]}\n",
		"include-explicit-key":    "{services: {app: {image: alpine}}, ? include\n  : [NB/docker-compose.yml]}\n",
		"include-long-form":       "include:\n  - path: NB/docker-compose.yml\nservices:\n  app:\n    image: alpine\n",
	}

	type tcase struct{ name, compose string }
	var cases []tcase
	for form, tpl := range serviceForms {
		for field, v := range values {
			// Экранирование имени: `_` как \u005f.
			esc := strings.ReplaceAll(field, "_", `\u005f`)
			if form == "escaped-key" && esc == field {
				continue
			}
			text := strings.NewReplacer("K", field, "V", v[0], "J", v[1], "B", base64.StdEncoding.EncodeToString([]byte(field)), "E", esc).Replace(tpl)
			cases = append(cases, tcase{field + "/" + form, text})
		}
	}
	for form, text := range includeForms {
		cases = append(cases, tcase{"include/" + form, text})
	}

	seen := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.ReplaceAll(tc.compose, "NB", nb)
			root := filepath.Join(base, "apps", strings.NewReplacer("/", "-", "_", "-").Replace(tc.name))
			if err := os.MkdirAll(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "docker-compose.yml"), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			model, ok := composeRefModelForTest(t, root)
			if !ok {
				t.Logf("compose форму не принял — утечь через неё нечему")
				return
			}
			refs, reads := outsideRefs(t, model, nb)
			if !refs && !reads {
				t.Logf("compose ссылки наружу не видит")
				return
			}
			seen[tc.name] = true
			sf := StackFiles{Root: root, ProjectDir: root}
			if v := CheckStackFileRefs(sf); len(v) == 0 {
				t.Fatalf("compose видит файл соседа, а разбор текста пропустил:\n%s\nмодель:\n%s", text, model)
			}
			if refs {
				if v := CheckModelFileRefs([]byte(model), sf); len(v) == 0 {
					t.Fatalf("вторая линия не видит файла соседа в модели:\n%s", model)
				}
			}
		})
	}

	// Тест, в котором compose ни разу не увидел соседа, ничего не проверил:
	// обе формы обхода второго круга обязаны доходить до compose.
	for _, must := range []string{"env_file/multiline-dq-hash", "env_file/explicit-key-flow", "include/include-block"} {
		if !seen[must] {
			t.Errorf("форма %s не дошла до compose как ссылка наружу — дифференциальная проверка ничего не доказывает", must)
		}
	}
}

// outsideRefs — что в модели пришло от соседа: refs — env_file или
// label_file сервиса ведут в его каталог; reads — compose прочёл его файлы
// (сервис из его описания или значение из его .env).
func outsideRefs(t *testing.T, model, nb string) (refs, reads bool) {
	t.Helper()
	var m struct {
		Services map[string]map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal([]byte(model), &m); err != nil {
		t.Fatalf("модель compose не читается: %v", err)
	}
	for name, svc := range m.Services {
		if name == "nbsvc" {
			reads = true
		}
		for _, field := range []string{"env_file", "label_file"} {
			if strings.Contains(string(svc[field]), nb) {
				refs = true
			}
		}
	}
	return refs, reads || strings.Contains(model, "LEAKED_SECRET")
}

// composeRefModelForTest — модель второй линии: окружение — список, а не
// наследство, как у подписанта, чтобы переменные машины не влияли на разбор.
func composeRefModelForTest(t *testing.T, dir string) (string, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, ModelRefArgs...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	if cfg := os.Getenv("DOCKER_CONFIG"); cfg != "" {
		cmd.Env = append(cmd.Env, "DOCKER_CONFIG="+cfg)
	}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		t.Fatalf("docker compose config не уложился в срок")
	}
	return string(out), err == nil
}
