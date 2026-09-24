package composeguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stackDir раскладывает файлы стека во временном каталоге: ключ — путь от
// корня, значение — содержимое. Возвращает корень с раскрытыми ссылками
// (на macOS временный каталог лежит за /var → /private/var).
func stackDir(t *testing.T, files map[string]string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func checkText(t *testing.T, compose string) []Violation {
	t.Helper()
	root := stackDir(t, map[string]string{"docker-compose.yml": compose})
	return CheckStackFileRefs(StackFiles{Root: root, ProjectDir: root})
}

func mustRefuse(t *testing.T, name string, v []Violation, want string) {
	t.Helper()
	if len(v) == 0 {
		t.Fatalf("%s: не отвергнуто", name)
	}
	joined := ""
	for _, x := range v {
		joined += x.String() + "\n"
	}
	if !strings.Contains(joined, want) {
		t.Fatalf("%s: в нарушениях нет %q:\n%s", name, want, joined)
	}
}

// Атаки из замечания Б2: каждая — способ заставить compose прочитать файл
// вне приложения или выбрать файл значением, которое подпись не покрывает.
func TestStackFileRefsRefusesAttacks(t *testing.T) {
	cases := []struct {
		name, compose, want string
	}{
		{"env_file-long-form-secret-var",
			"services:\n  app:\n    image: nginx:1\n    env_file:\n      - path: ${S}\n        required: false\n",
			"подстановка переменной"},
		{"env_file-long-form-absolute",
			"services:\n  app:\n    image: nginx:1\n    env_file:\n      - path: /opt/tracedocs/deploy/apps/neighbour/.env\n        required: false\n",
			"абсолютный путь"},
		{"env_file-flow-long-form",
			"services:\n  app:\n    image: nginx:1\n    env_file: [{path: \"${S}\", required: false}]\n",
			"подстановка переменной"},
		{"env_file-short-absolute",
			"services:\n  app:\n    env_file: /opt/tracedocs/deploy/apps/other/.env\n",
			"абсолютный путь"},
		{"env_file-parent",
			"services:\n  app:\n    env_file:\n      - ../other/.env\n",
			"выход через .."},
		{"env_file-dollar-short",
			"services:\n  app:\n    env_file: $S\n",
			"подстановка переменной"},
		{"include-env_file-absolute",
			"include:\n  - path: other.yml\n    env_file: /opt/tracedocs/deploy/apps/neighbour/.env\nservices:\n  app:\n    image: nginx:1\n",
			"абсолютный путь"},
		{"include-path-absolute",
			"include:\n  - /opt/tracedocs/deploy/apps/neighbour/docker-compose.yml\n",
			"абсолютный путь"},
		{"include-project-directory",
			"include:\n  - path: a.yml\n    project_directory: /opt/tracedocs/deploy/apps/neighbour\n",
			"абсолютный путь"},
		{"include-remote",
			"include:\n  - oci://registry.example/stack:latest\n",
			"допустимы только"},
		{"extends-absolute",
			"services:\n  app:\n    image: nginx:1\n    extends:\n      file: /etc/hosts\n      service: x\n",
			"абсолютный путь"},
		{"extends-flow-absolute",
			"services:\n  app:\n    extends: {file: /etc/hosts, service: x}\n",
			"абсолютный путь"},
		{"label_file-absolute",
			"services:\n  app:\n    image: nginx:1\n    label_file: /opt/tracedocs/deploy/apps/neighbour/.env\n",
			"абсолютный путь"},
		{"json-compose",
			`{"services":{"app":{"image":"nginx:1","env_file":["/etc/x.env"]}}}`,
			"абсолютный путь"},
		{"anchor-merge",
			"x-common: &common\n  env_file: /opt/tracedocs/deploy/apps/neighbour/.env\nservices:\n  app:\n    <<: *common\n    image: nginx:1\n",
			"абсолютный путь"},
		{"alias-as-value",
			"x-p: &p /etc/x.env\nservices:\n  app:\n    env_file: *p\n",
			"не разобрана"},
		{"escaped-key",
			"services:\n  app:\n    \"env\\x5ffile\": /etc/x.env\n",
			"экранирование"},
		{"alias-as-key",
			"x-k: &k env_file\nservices:\n  app:\n    *k : /etc/x.env\n",
			"псевдоним"},
		{"explicit-key",
			"services:\n  app:\n    ? env_file\n    : /etc/x.env\n",
			"явный ключ"},
		{"block-scalar",
			"services:\n  app:\n    env_file: |\n      /etc/x.env\n",
			"не разобрана"},
		{"tagged-value",
			"services:\n  app:\n    env_file: !!str /etc/x.env\n",
			"не разобрана"},
		{"unknown-long-form-key",
			"services:\n  app:\n    env_file:\n      - path: a.env\n        from: /etc/x.env\n",
			"неизвестен"},
		// Строка без кавычек продолжается на следующей, более глубокой строке:
		// YAML склеивает её в один путь `a /../../etc/x`.
		{"folded-plain-inline",
			"services:\n  app:\n    env_file: a\n      /../../etc/x.env\n",
			"не разобрана"},
		{"folded-plain-block",
			"services:\n  app:\n    env_file:\n      a\n      /../../etc/x.env\n",
			"не разобрана"},
		{"folded-plain-flow",
			"services:\n  app: {image: x, env_file: a\n    /../../etc/x.env}\n",
			"не разобрана"},
		// Разрывы строк, которые YAML (go-yaml у compose) считает переводом
		// строки, а регулярные выражения — нет, и метка порядка байтов в
		// начале: ключ за ними обязан найтись.
		{"line-separator",
			"services:\n  app:\n    image: x\u2028    env_file: /etc/x.env\n",
			"абсолютный путь"},
		{"next-line",
			"services:\n  app:\n    image: x\u0085    env_file: /etc/x.env\n",
			"абсолютный путь"},
		{"bare-cr",
			"services:\r  app:\r    env_file: a\r      /../../etc/x.env\r",
			"не разобрана"},
		{"bom-include",
			"\ufeffinclude:\n  - /opt/tracedocs/deploy/apps/neighbour/docker-compose.yml\n",
			"абсолютный путь"},
		{"multiline-flow",
			"services:\n  app: {\n    image: nginx,\n    env_file: [\n      /etc/x.env\n    ]\n  }\n",
			"абсолютный путь"},

		// Формы, которые уже не проходили до лексического прохода, — держать.
		{"tab-after-colon", "services:\n  app:\n    image: a\n    env_file:\t/etc/x.env\n", "абсолютный путь"},
		{"comment-in-line", "services:\n  app:\n    image: a # env_file: ok.env\n    env_file: /etc/x.env\n", "абсолютный путь"},
		{"multi-document", "services:\n  app:\n    image: a\n---\nservices:\n  app:\n    env_file: /etc/x.env\n", "абсолютный путь"},
		{"flow-document-include", "{include: [/opt/tracedocs/deploy/apps/neighbour/docker-compose.yml], services: {app: {image: a}}}\n", "абсолютный путь"},
		{"anchor-on-value", "services:\n  app:\n    env_file: &p /etc/x.env\n", "абсолютный путь"},
		{"value-next-line", "services:\n  app:\n    env_file:\n      /etc/x.env\n", "абсолютный путь"},
		{"crlf", "services:\r\n  app:\r\n    env_file: /etc/x.env\r\n", "абсолютный путь"},
		// go-yaml `-\t` не принимает вовсе; отказ здесь — любой, лишь бы был.
		{"dash-tab", "services:\n  app:\n    env_file:\n      -\t/etc/x.env\n", "допустимы только"},

		// Замечание второго круга: строка в кавычках продолжается на строке,
		// начатой `#`, а ключ стоит на той же строке после закрывающей
		// кавычки. Прежний разбор счёл строку комментарием.
		{"multiline-double-quote-env_file",
			"services:\n  app: {image: alpine, labels: {a: \"x\n    #y\"}, env_file: [{path: /opt/tracedocs/deploy/apps/neighbour/.env, required: false}]}\n",
			"многострочная строка"},
		{"multiline-single-quote-env_file",
			"services:\n  app: {image: alpine, labels: {a: 'x\n    #y'}, env_file: [{path: /opt/tracedocs/deploy/apps/neighbour/.env, required: false}]}\n",
			"многострочная строка"},
		{"multiline-quote-label_file",
			"services:\n  app: {image: alpine, labels: {a: \"x\n    #y\"}, label_file: /opt/tracedocs/deploy/apps/neighbour/.env}\n",
			"многострочная строка"},
		{"multiline-quote-include",
			"{services: {app: {image: alpine}}, x-l: 'x\n  #y', include: [/opt/tracedocs/deploy/apps/neighbour/docker-compose.yml]}\n",
			"многострочная строка"},
		{"multiline-quote-extends",
			"services:\n  app: {image: alpine, labels: {a: \"x\n    #y\"}, extends: {file: /opt/tracedocs/deploy/apps/neighbour/docker-compose.yml, service: app}}\n",
			"многострочная строка"},
		{"multiline-quote-block-key",
			"services:\n  app:\n    image: alpine\n    labels:\n      a: \"x\n    #y\"\n    env_file: /etc/x.env\n",
			"многострочная строка"},
		{"quote-escaped-newline",
			"services:\n  app: {image: alpine, labels: {a: \"x\\\n    #y\"}, env_file: /etc/x.env}\n",
			"многострочная строка"},

		// Замечание второго круга: явный ключ внутри скобок, двоеточие на
		// следующей строке. Прежняя проверка ловила `?` только в начале строки.
		{"explicit-key-in-flow",
			"services:\n  app: {image: alpine, ? env_file\n    : [{path: /opt/tracedocs/deploy/apps/neighbour/.env, required: false}]}\n",
			"явный ключ"},
		{"explicit-key-in-flow-no-space",
			"services:\n  app: {image: alpine, ?env_file : /etc/x.env}\n",
			"явный ключ"},
		{"explicit-key-after-bracket",
			"services:\n  app:\n    image: alpine\n    labels: [? a]\n",
			"явный ключ"},
		{"explicit-key-after-dash-mid-line",
			"services:\n  app:\n    image: alpine\n    x-l: - ? env_file\n",
			"явный ключ"},
		{"value-indicator-without-key",
			"{\"services\": {\"app\": {\"image\": \"a\", \"env_file\"\n: [\"/etc/x.env\"]}}}\n",
			"двоеточие без ключа"},

		// Прочие формы, на которых разбор платформы и go-yaml могут разойтись.
		{"tag-binary-key",
			"services:\n  app:\n    image: a\n    !!binary ZW52X2ZpbGU=: /etc/x.env\n",
			"тег YAML"},
		{"tag-str-key", "services:\n  app:\n    image: a\n    !!str env_file: /etc/x.env\n", "тег YAML"},
		{"anchor-on-key", "services:\n  app:\n    image: a\n    &k env_file: /etc/x.env\n", "якорь или тег на ключе"},
		{"alias-key-no-space", "x-k: &k env_file\nservices:\n  app:\n    image: a\n    *k: /etc/x.env\n", "псевдоним"},
		{"collection-key", "services:\n  app: {image: a, [x]: y}\n", "составной ключ"},
		{"tab-indent", "services:\n  app:\n    image: a\n\tenv_file: /etc/x.env\n", "табуляция"},
		{"unclosed-bracket", "services:\n  app: {image: a, labels: [x\n", "скобка"},
		{"stray-bracket", "services:\n  app: {image: a}}\n", "непарная скобка"},
		{"comma-in-block", "services:\n  app:\n    image: a\n    , env_file: /etc/x.env\n", "запятая"},
		{"dash-in-flow", "services:\n  app: {image: a, labels: [- x]}\n", "внутри скобок"},
		{"reserved-indicator", "services:\n  app:\n    image: @a\n", "не может начинать"},
		{"document-marker-in-flow", "services: {app: {image: a,\n---\n env_file: /etc/x.env}}\n", "маркер документа"},
		{"block-scalar-explicit-indent", "services:\n  app:\n    image: a\n    command: |2\n        x\n", "явный отступ"},
		{"block-scalar-in-flow", "services:\n  app: {image: a, command: |\n    x}\n", "блочная строка"},

		// Разбор угадывает продолжение строки без кавычек так же, как go-yaml:
		// кавычка или скобка в продолжении — текст, а не начало значения.
		{"flow-plain-continuation-quote",
			"services:\n  app: {image: a, labels: {a: foo\n    \"x, env_file: /etc/x.env, y\" }}\n",
			"абсолютный путь"},
		{"block-plain-continuation-brace",
			"x-a:\n  k: foo\n    - {x\n  \"b #\": {env_file: /etc/x.env}\nservices:\n  app:\n    image: a\n",
			"абсолютный путь"},
		{"flow-colon-before-bracket", "services:\n  app: {image: a, env_file:[/etc/x.env]}\n", "абсолютный путь"},
		{"flow-value-next-line",
			"services:\n  app: {image: a, env_file:\n    /etc/x.env}\n",
			"абсолютный путь"},
		{"block-scalar-then-key",
			"services:\n  app:\n    image: a\n    command: |\n      echo \"{\n    env_file: /etc/x.env\n",
			"абсолютный путь"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustRefuse(t, tc.name, checkText(t, tc.compose), tc.want)
		})
	}
}

// Законные формы проходят: без этого проверка отказывала бы выкатам, которые
// шли годами.
func TestStackFileRefsAcceptsLegitimate(t *testing.T) {
	cases := []struct{ name, compose string }{
		{"short", "services:\n  app:\n    env_file: .env\n"},
		{"list-dot", "services:\n  app:\n    env_file:\n      - ./config/app.env\n"},
		{"compact-list", "services:\n  app:\n    env_file:\n    - .env\n    image: nginx:1\n"},
		{"flow-list", "services:\n  app:\n    env_file: [.env, config/extra.env]\n"},
		{"long-form", "services:\n  app:\n    env_file:\n      - path: ./local.env\n        required: false\n      - .env\n"},
		{"flow-map-item", "services:\n  app:\n    env_file: [{path: local.env, required: false}]\n"},
		{"comment-after", "services:\n  app:\n    env_file: .env  # local overrides\n"},
		{"commented-out", "services:\n  app:\n    # env_file: /opt/other/.env\n    image: nginx:1\n"},
		{"include-relative", "include:\n  - infra/db.yml\n  - path: infra/cache.yml\n    env_file: infra/cache.env\nservices:\n  app:\n    image: nginx:1\n"},
		{"extends-same-file", "services:\n  base:\n    image: nginx:1\n  app:\n    extends: base\n"},
		{"extends-relative", "services:\n  app:\n    extends:\n      file: common/services.yml\n      service: web\n"},
		{"label_file", "services:\n  app:\n    label_file: ./app.labels\n"},
		{"docker-sock-not-this-rule", "services:\n  app:\n    volumes:\n      - /var/run/docker.sock:/x\n"},
		{"image-render", "name: ${APP_SLUG}\nservices:\n  app:\n    image: nginx:1\n    env_file:\n      - .env\n    networks:\n      - edge\n"},
		{"quoted-key", "services:\n  app:\n    \"env_file\": '.env'\n"},
		{"json-multiline", "{\n  \"services\": {\n    \"app\": {\n      \"image\": \"nginx:1\",\n      \"env_file\": [\".env\"]\n    }\n  }\n}\n"},
		{"block-scalar-shell", "services:\n  app:\n    image: a\n    command: |\n      echo \"it's { [ # not a comment\n      - x: y\n    env_file: .env\n"},
		{"folded-scalar", "services:\n  app:\n    image: a\n    command: >-\n      sh -c 'a'\n      \"b\"\n    env_file: .env\n"},
		{"reset-tag", "services:\n  app:\n    image: a\n    env_file: !reset []\n"},
		{"override-tag-value", "services:\n  app:\n    image: a\n    env_file: !override [.env]\n"},
		{"override-tag-map", "services:\n  app: !override\n    image: a\n    env_file: .env\n"},
		{"merge-list", "x-a: &a\n  image: a\nx-b: &b\n  env_file: .env\nservices:\n  app:\n    <<: [*a, *b]\n"},
		{"plain-multiline-block", "services:\n  app:\n    image: a\n    healthcheck:\n      test: curl -f http://localhost\n        || exit 1\n    env_file: .env\n"},
		{"quoted-key-after-plain", "services:\n  app:\n    environment:\n      A: b\n      \"C\": d\n    env_file: .env\n"},
		{"comment-after-quote", "services:\n  app:\n    image: \"a\"#c\n    env_file: .env\n"},
		{"shell-vars", "services:\n  app:\n    image: a\n    command: [\"sh\", \"-c\", \"echo ${A:?need} $$B\"]\n    env_file: .env\n"},
		{"flow-colon-before-comma", "services:\n  app: {image: a, labels: {a:, b: c}, env_file:}\n"},
		{"flow-question", "services:\n  app:\n    image: a\n    command: [wget, http://x/?a=b]\n    labels: {a: b?c, url: http://x:80/}\n"},
		{"url-question", "services:\n  app:\n    image: a\n    healthcheck:\n      test: wget -q http://x/?a=b\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v := checkText(t, tc.compose); len(v) != 0 {
				t.Fatalf("законная форма отвергнута: %v", v)
			}
		})
	}
}

// Путь относительный, но ведёт символьной ссылкой наружу: такую ссылку может
// принести репозиторий. Проверка текста её не видит — только диск.
func TestStackFileRefsRefusesSymlinkEscape(t *testing.T) {
	outside := stackDir(t, map[string]string{"neighbour.env": "PASSWORD=x\n", "other.yml": "services: {}\n"})

	for _, tc := range []struct{ name, compose, link, target string }{
		{"env_file", "services:\n  app:\n    env_file: secrets.env\n", "secrets.env", "neighbour.env"},
		{"include", "include:\n  - inc.yml\n", "inc.yml", "other.yml"},
		{"dir-link", "services:\n  app:\n    env_file: shared/neighbour.env\n", "shared", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := stackDir(t, map[string]string{"docker-compose.yml": tc.compose})
			if err := os.Symlink(filepath.Join(outside, tc.target), filepath.Join(root, tc.link)); err != nil {
				t.Fatal(err)
			}
			mustRefuse(t, tc.name, CheckStackFileRefs(StackFiles{Root: root, ProjectDir: root}), "символьной ссылке")
		})
	}

	// Сам файл описания по имени — ссылка на описание соседа.
	root := stackDir(t, map[string]string{})
	if err := os.Symlink(filepath.Join(outside, "other.yml"), filepath.Join(root, "docker-compose.override.yml")); err != nil {
		t.Fatal(err)
	}
	mustRefuse(t, "override-link", CheckStackFileRefs(StackFiles{Root: root, ProjectDir: root}), "символьной ссылке")
}

// Включённое описание проверяется так же, как основное: иначе абсолютный
// env_file достаточно переложить в файл, на который указывает include.
func TestStackFileRefsFollowsIncludeAndExtends(t *testing.T) {
	for _, tc := range []struct{ name, entry, nested string }{
		{"include", "include:\n  - infra/db.yml\n", "services:\n  db:\n    env_file: /opt/tracedocs/deploy/apps/neighbour/.env\n"},
		{"extends", "services:\n  app:\n    extends:\n      file: common.yml\n      service: web\n", "services:\n  web:\n    label_file: /etc/passwd\n"},
		{"override", "services:\n  app:\n    image: nginx:1\n", "services:\n  app:\n    env_file: /etc/x.env\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"docker-compose.yml": tc.entry}
			switch tc.name {
			case "include":
				files["infra/db.yml"] = tc.nested
			case "extends":
				files["common.yml"] = tc.nested
			case "override":
				files["docker-compose.override.yml"] = tc.nested
			}
			root := stackDir(t, files)
			mustRefuse(t, tc.name, CheckStackFileRefs(StackFiles{Root: root, ProjectDir: root}), "абсолютный путь")
		})
	}
}

// Явный файл описания (восстановление из копии) и абсолютный путь, который
// агент пишет сам: свой .env синтетического compose.
func TestStackFileRefsExplicitEntryAndAllowedAbs(t *testing.T) {
	root := stackDir(t, map[string]string{".env": "A=1\n"})
	set := stackDir(t, map[string]string{"docker-compose.yml": "services:\n  app:\n    env_file:\n      - " +
		filepath.Join(root, ".env") + "\n"})
	sf := StackFiles{Root: root, ProjectDir: root, Entries: []string{filepath.Join(set, "docker-compose.yml")}}
	mustRefuse(t, "explicit", CheckStackFileRefs(sf), "абсолютный путь")

	sf.AllowedAbs = []string{filepath.Join(root, ".env")}
	if v := CheckStackFileRefs(sf); len(v) != 0 {
		t.Fatalf("свой .env агента отвергнут: %v", v)
	}
}

// Текст нарушения не несёт содержимого прочитанных файлов: у подписанта он
// ложится в базу и на карточку релиза.
func TestStackFileRefsViolationCarriesNoFileContent(t *testing.T) {
	root := stackDir(t, map[string]string{
		"docker-compose.yml": "include:\n  - infra/db.yml\n",
		"infra/db.yml":       "x-secret: TOPSECRET-VALUE\nservices:\n  db:\n    env_file: /etc/x.env\n",
	})
	for _, v := range CheckStackFileRefs(StackFiles{Root: root, ProjectDir: root}) {
		if strings.Contains(v.String(), "TOPSECRET") {
			t.Fatalf("содержимое файла в тексте нарушения: %s", v)
		}
	}
}
