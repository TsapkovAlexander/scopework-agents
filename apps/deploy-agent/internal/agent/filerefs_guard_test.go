package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ссылки на файлы (env_file, label_file, include, extends) проверяются ДО
// первого `docker compose`: эти поля compose исполняет сам, читая файл, и
// нормализованная модель уже несёт содержимое чужого .env как environment.
// Здесь проверяется место вызова — сама политика в composeguard/filerefs_test.go.

// Шаблон, образ и «свой compose»: `env_file` с секретной переменной в пути
// отвергнут, а нормализация даже не запускалась.
func TestApplyOneRefusesFileRefsBeforeComposeConfig(t *testing.T) {
	for _, source := range []string{"template", "image", "compose"} {
		t.Run(source, func(t *testing.T) {
			normalized := false
			prev := composeConfig
			composeConfig = func(context.Context, composeTarget) (string, error) {
				normalized = true
				return `{"services":{"app":{"image":"nginx"}}}`, nil
			}
			t.Cleanup(func() { composeConfig = prev })

			calls := installFakeDocker(t, "")
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			app := DesiredApp{
				Slug:       "shop",
				SourceType: source,
				Compose: "services:\n  app:\n    image: nginx\n    env_file:\n" +
					"      - path: ${S}\n        required: false\n",
				Env:       map[string]string{"S": "/opt/tracedocs/deploy/apps/neighbour/.env"},
				ApplySpec: ApplySpec{StableChecks: 1},
			}

			var written AppliedRecord
			_, err := applyOne(context.Background(), p, app, func(string, string) {}, &written)
			if err == nil || !strings.Contains(err.Error(), "подстановка переменной") {
				t.Fatalf("источник %s: env_file со значением секрета не отвергнут: %v", source, err)
			}
			if normalized {
				t.Fatalf("источник %s: docker compose config вызван до проверки ссылок", source)
			}
			for _, c := range calls() {
				if c.hasArg("config") || c.hasArg("up") {
					t.Fatalf("источник %s: docker %s после отказа", source, c.line())
				}
			}
		})
	}
}

// Репозиторий: описание читает сам compose, и до этой проверки текст
// репозитория не смотрел никто — модель, лёгшая в служебный каталог, уже не
// несла env_file, только его содержимое.
func TestPrepareRepoComposeRefusesFileRefsBeforeDocker(t *testing.T) {
	for name, compose := range map[string]string{
		"include-env_file": "include:\n  - path: infra.yml\n    env_file: /opt/tracedocs/deploy/apps/neighbour/.env\n" +
			"services:\n  app:\n    image: nginx\n",
		"extends-absolute": "services:\n  app:\n    extends:\n      file: /opt/tracedocs/deploy/apps/neighbour/docker-compose.yml\n      service: app\n",
		"label_file":       "services:\n  app:\n    image: nginx\n    label_file: /etc/tracedocs/deploy/agent.env\n",
	} {
		t.Run(name, func(t *testing.T) {
			calls := installFakeDocker(t, "")
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			app := gitApp()
			repo := p.repoDir(app.Slug)
			if err := os.MkdirAll(repo, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(repo, "docker-compose.yml"), []byte(compose), 0o640); err != nil {
				t.Fatal(err)
			}

			_, err := prepareRepoCompose(context.Background(), p, app, filepath.Join(p.appDir(app.Slug), ".env"))
			var refusal *composeRefusal
			if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "абсолютный путь") {
				t.Fatalf("ссылка наружу в репозитории не отвергнута: %v", err)
			}
			if n := len(calls()); n != 0 {
				t.Fatalf("docker вызван до проверки ссылок (%d раз): %s", n, describeCalls(calls()))
			}
		})
	}
}

// Синтетическое описание сборки из Dockerfile ссылается на свой .env
// абсолютным путём — его пишет сам агент, и проверка его пропускает. Чужой
// абсолютный путь в том же месте — нет.
func TestPrepareRepoComposeAllowsOwnSyntheticEnv(t *testing.T) {
	installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	seedDockerfile(t, p, app.Slug)
	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	if _, err := prepareRepoCompose(context.Background(), p, app, filepath.Join(p.appDir(app.Slug), ".env")); err != nil {
		var refusal *composeRefusal
		if errors.As(err, &refusal) {
			t.Fatalf("свой .env синтетического описания отвергнут: %v", err)
		}
	}

	// Тот же абсолютный путь в описании из репозитория (не синтетическом) —
	// обычная ссылка наружу рабочей копии.
	app.BuildMethod = buildMethodCompose
	_, err := prepareRepoCompose(context.Background(), p, app, filepath.Join(p.appDir(app.Slug), ".env"))
	var refusal *composeRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("абсолютный env_file в описании репозитория не отвергнут: %v", err)
	}
}

// modelWithNeighbourEnv — модель, в которой compose видит env_file соседа, а
// текст описания чист: так выглядит промах разбора текста (первой линии).
const modelWithNeighbourEnv = `{"services":{"app":{"image":"nginx","env_file":[` +
	`{"path":"/opt/tracedocs/deploy/apps/neighbour/.env","required":false}]}}}`

// Вторая линия на месте вызова: разбор текста ничего не нашёл, а модель
// compose (без чтения env_file) ссылается на .env соседа — отказ до
// нормализации, которая этот файл прочла бы, и до подъёма.
func TestApplyOneRefusesModelFileRefsBeforeNormalization(t *testing.T) {
	for _, source := range []string{"template", "image", "compose"} {
		t.Run(source, func(t *testing.T) {
			normalized := false
			prev := composeConfig
			composeConfig = func(context.Context, composeTarget) (string, error) {
				normalized = true
				return `{"services":{"app":{"image":"nginx"}}}`, nil
			}
			t.Cleanup(func() { composeConfig = prev })

			calls := installFakeDockerModel(t, "", modelWithNeighbourEnv)
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			app := DesiredApp{
				Slug:       "shop",
				SourceType: source,
				Compose:    "services:\n  app:\n    image: nginx\n",
				ApplySpec:  ApplySpec{StableChecks: 1},
			}
			var written AppliedRecord
			_, err := applyOne(context.Background(), p, app, func(string, string) {}, &written)
			if err == nil || !strings.Contains(err.Error(), "после разбора docker compose") {
				t.Fatalf("источник %s: env_file соседа в модели не отвергнут: %v", source, err)
			}
			if strings.Contains(err.Error(), "neighbour") {
				t.Fatalf("источник %s: путь из модели в тексте отказа: %v", source, err)
			}
			if normalized {
				t.Fatalf("источник %s: нормализация с чтением env_file вызвана до второй линии", source)
			}
			for _, c := range calls() {
				if c.hasArg("config") && !c.hasArg("--no-env-resolution") {
					t.Fatalf("источник %s: docker %s до второй линии", source, c.line())
				}
				if c.hasArg("up") {
					t.Fatalf("источник %s: подъём после отказа", source)
				}
			}
		})
	}
}

// Репозиторий: вторая линия стоит и перед разбором, который кладёт модель в
// служебный каталог уже с содержимым env_file.
func TestPrepareRepoComposeRefusesModelFileRefs(t *testing.T) {
	calls := installFakeDockerModel(t, "", modelWithNeighbourEnv)
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	app := gitApp()
	repo := p.repoDir(app.Slug)
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "docker-compose.yml"), []byte("services:\n  app:\n    image: nginx\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	_, err := prepareRepoCompose(context.Background(), p, app, filepath.Join(p.appDir(app.Slug), ".env"))
	var refusal *composeRefusal
	if !errors.As(err, &refusal) || !strings.Contains(err.Error(), "после разбора docker compose") {
		t.Fatalf("env_file соседа в модели не отвергнут: %v", err)
	}
	got := calls()
	if len(got) != 1 || !got[0].hasArg("--no-env-resolution") || !got[0].hasArg("--no-interpolate") {
		t.Fatalf("ожидался ровно один вызов compose без чтения env_file: %s", describeCalls(got))
	}
}
