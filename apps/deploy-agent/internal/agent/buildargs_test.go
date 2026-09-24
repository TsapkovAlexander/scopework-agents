package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Переменные сборки для приложения из репозитория.
//
// ЗАЧЕМ. Next.js вшивает NEXT_PUBLIC_* в клиентский бандл НА СБОРКЕ. Платформа
// отдавала их только в рантайм, поэтому приложение поднималось здоровым и
// показывало в браузере undefined вместо адреса API. Замерено на переносимых
// приложениях: у b2b-admin-web таких переменных 11, у b2c-web 7 — шесть из
// девяти живых git-приложений без них не работают.
//
// В сборку уходят ТОЛЬКО открытые переменные. Аргументы сборки видны в
// `docker history` собранного образа, и секрет, переданный туда, оседает в
// метаданных слоёв навсегда — ровно это мы нашли у Coolify, где в образах
// лежат SUPABASE_SERVICE_ROLE_KEY и токены. Повторять нельзя.

func TestSelectBuildArgs(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want []string
	}{
		{
			name: "обычные переменные проходят",
			in:   map[string]string{"NEXT_PUBLIC_API": "https://a", "PORT": "3000"},
			want: []string{"NEXT_PUBLIC_API", "PORT"},
		},
		{
			// Те же правила, что у .env: имя уезжает в командную строку docker,
			// и значение вида `FOO\nBAR=baz` дописало бы лишний аргумент.
			name: "негодное имя отбрасывается",
			in:   map[string]string{"OK": "1", "с пробелом": "2", "2CIFRY": "3", "": "4"},
			want: []string{"OK"},
		},
		{
			// APP_SLUG задаёт имя compose-проекта, APP_DOMAIN — адрес в прокси.
			// Отдать их в сборку значит позволить репозиторию их переопределить.
			name: "служебные имена платформы отбрасываются",
			in:   map[string]string{"APP_SLUG": "x", "APP_DOMAIN": "y", "COMPOSE_FILE": "z", "GOOD": "1"},
			want: []string{"GOOD"},
		},
		{
			name: "пусто на входе — пусто на выходе",
			in:   map[string]string{},
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectBuildArgs(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("selectBuildArgs() = %v, ожидалось %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("selectBuildArgs()[%d] = %q, ожидалось %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// Порядок обязан быть устойчивым: имена уезжают в текст compose, а его
// отпечаток решает, переприменять ли стек. Плавающий порядок означал бы
// пересборку на каждом цикле агента.
func TestSelectBuildArgsIsSorted(t *testing.T) {
	got := selectBuildArgs(map[string]string{"B": "1", "A": "2", "C": "3"})
	if strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("порядок не отсортирован: %v", got)
	}
}

// Объявление ARG обязательно: без него docker игнорирует --build-arg, и
// значение до сборки не доходит. Coolify подставляет ARG сам, поэтому в
// переносимых репозиториях объявлений может не быть вовсе.
func TestInjectBuildArgs(t *testing.T) {
	src := "FROM node:22 AS deps\nRUN npm ci\n\nFROM node:22 AS runner\nCOPY . .\nCMD [\"node\"]\n"
	out := injectBuildArgs(src, []string{"NEXT_PUBLIC_API", "PORT"})

	// После КАЖДОГО FROM: в многоступенчатой сборке область видимости
	// аргумента заканчивается на следующей ступени, и объявление только
	// сверху не дошло бы до той, где идёт npm run build.
	if strings.Count(out, "ARG NEXT_PUBLIC_API") != 2 {
		t.Fatalf("ARG объявлен не после каждого FROM:\n%s", out)
	}
	if strings.Count(out, "ARG PORT") != 2 {
		t.Fatalf("второй аргумент объявлен не везде:\n%s", out)
	}

	// Исходные строки сохраняются полностью и в прежнем порядке.
	for _, line := range []string{"FROM node:22 AS deps", "RUN npm ci", "COPY . .", "CMD [\"node\"]"} {
		if !strings.Contains(out, line) {
			t.Fatalf("потеряна строка %q:\n%s", line, out)
		}
	}
	// ARG идёт ПОСЛЕ FROM, а не перед ним.
	if strings.Index(out, "ARG NEXT_PUBLIC_API") < strings.Index(out, "FROM node:22 AS deps") {
		t.Fatal("ARG оказался выше первого FROM")
	}
}

func TestInjectBuildArgsNoArgs(t *testing.T) {
	src := "FROM alpine\nRUN true\n"
	if out := injectBuildArgs(src, nil); out != src {
		t.Fatalf("без аргументов файл обязан остаться прежним:\n%s", out)
	}
}

// Регистр директивы и отступ — на усмотрение автора Dockerfile.
func TestInjectBuildArgsCaseAndIndent(t *testing.T) {
	out := injectBuildArgs("  from  alpine:3\nRUN true\n", []string{"A"})
	if strings.Count(out, "ARG A") != 1 {
		t.Fatalf("строчная from не распознана:\n%s", out)
	}
}

// Слово FROM внутри команды — не начало ступени.
func TestInjectBuildArgsIgnoresFromInsideCommands(t *testing.T) {
	out := injectBuildArgs("FROM alpine\nRUN echo FROM alpine >/tmp/x\nCOPY --from=0 /a /b\n", []string{"A"})
	if strings.Count(out, "ARG A") != 1 {
		t.Fatalf("FROM внутри команды принят за ступень:\n%s", out)
	}
}

// Полный путь: переменные сборки доезжают до compose и до Dockerfile.
//
// Ровно тот сценарий, который был сломан: без объявленных ARG и без
// build.args приложение собиралось с undefined вместо адреса API, а стек
// при этом рапортовал healthy.
func TestSyntheticComposeCarriesBuildArgs(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.BuildArgs = map[string]string{
		"NEXT_PUBLIC_SUPABASE_URL": "https://api.example.com",
		"APP_SLUG":                 "попытка увести имя проекта",
	}

	// Оригинальный Dockerfile — как его пишет клиент, без единого ARG.
	dir := p.repoDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	original := "FROM node:22 AS build\nRUN npm run build\n\nFROM node:22\nCMD [\"node\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	compose, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compose, "dockerfile: "+buildDockerfileName) {
		t.Fatalf("сборка идёт не по сгенерированному файлу:\n%s", compose)
	}
	if !strings.Contains(compose, "NEXT_PUBLIC_SUPABASE_URL: ${NEXT_PUBLIC_SUPABASE_URL}") {
		t.Fatalf("аргумент не объявлен в compose:\n%s", compose)
	}
	// Значение подставляет docker compose из .env — в тексте compose его быть
	// не должно: рабочая копия попадает в сборочный контекст.
	if strings.Contains(compose, "https://api.example.com") {
		t.Fatalf("значение переменной попало в текст compose:\n%s", compose)
	}
	// Служебное имя платформы в сборку не уходит.
	if strings.Contains(compose, "APP_SLUG: $") {
		t.Fatalf("APP_SLUG уехал в аргументы сборки:\n%s", compose)
	}

	generated, err := os.ReadFile(filepath.Join(dir, buildDockerfileName))
	if err != nil {
		t.Fatalf("сгенерированный Dockerfile не создан: %v", err)
	}
	if strings.Count(string(generated), "ARG NEXT_PUBLIC_SUPABASE_URL") != 2 {
		t.Fatalf("ARG объявлен не после каждого FROM:\n%s", generated)
	}

	// Оригинал клиента не тронут.
	kept, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil || string(kept) != original {
		t.Fatalf("оригинальный Dockerfile изменён:\n%s", kept)
	}
}

// Без переменных сборки лишнего файла в рабочей копии не появляется, и
// собираем по оригиналу.
func TestSyntheticComposeWithoutBuildArgs(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.BuildArgs = nil

	seedDockerfile(t, p, app.Slug)
	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}
	compose, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(compose, "dockerfile: Dockerfile\n") {
		t.Fatalf("должен собираться по оригиналу:\n%s", compose)
	}
	if strings.Contains(compose, "args:") {
		t.Fatalf("пустая секция args не нужна:\n%s", compose)
	}
	if _, err := os.Stat(filepath.Join(p.repoDir(app.Slug), buildDockerfileName)); err == nil {
		t.Fatal("сгенерирован лишний Dockerfile при отсутствии переменных сборки")
	}
}
