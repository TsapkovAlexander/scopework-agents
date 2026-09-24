package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitApp() DesiredApp {
	return DesiredApp{
		Slug:       "backend",
		SourceType: "git",
		GitRepo:    "git@github.com:acme/backend.git",
		GitBranch:  "main",
		GitKey:     "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
	}
}

// Адрес репозитория и имя ветки уезжают в аргументы git. Значение, начинающееся
// с дефиса, git прочитает как флаг — а `--upload-pack=` это выполнение
// произвольной команды на нашей стороне.
func TestValidateGitSourceRejectsFlags(t *testing.T) {
	bad := []DesiredApp{
		{Slug: "ok", SourceType: "git", GitRepo: "--upload-pack=/bin/sh", GitBranch: "main", GitKey: "k"},
		{Slug: "ok", SourceType: "git", GitRepo: "git@github.com:a/b.git", GitBranch: "--upload-pack=x", GitKey: "k"},
		{Slug: "ok", SourceType: "git", GitRepo: "-x", GitBranch: "main", GitKey: "k"},
		// HTTPS не поддержан: он потребовал бы хранить токен открытым в URL.
		{Slug: "ok", SourceType: "git", GitRepo: "https://github.com/a/b.git", GitBranch: "main", GitKey: "k"},
		// Пробелы и переводы строк.
		{Slug: "ok", SourceType: "git", GitRepo: "git@github.com:a/b.git extra", GitBranch: "main", GitKey: "k"},
		{Slug: "ok", SourceType: "git", GitRepo: "git@github.com:a/b.git", GitBranch: "main\nx", GitKey: "k"},
		// Имя пользователя с ведущим дефисом: `[user@]host` git отдаёт в ssh
		// одним аргументом, и там это читается как флаг — `-F<конфиг>` даёт
		// ProxyCommand, то есть выполнение произвольной команды.
		{Slug: "ok", SourceType: "git", GitRepo: "-F.ssh@github.com:a/b.git", GitBranch: "main", GitKey: "k"},
		{Slug: "ok", SourceType: "git", GitRepo: "--upload-pack@github.com:a/b", GitBranch: "main", GitKey: "k"},
		// Выход за пределы: slug задаёт путь на диске.
		{Slug: "../escape", SourceType: "git", GitRepo: "git@github.com:a/b.git", GitBranch: "main", GitKey: "k"},
		// Без ключа клонировать нечем, и молча пропускать это нельзя.
		{Slug: "ok", SourceType: "git", GitRepo: "git@github.com:a/b.git", GitBranch: "main", GitKey: "  "},
	}

	for _, app := range bad {
		if err := validateGitSource(app); err == nil {
			t.Errorf("принят недопустимый источник: %+v", app)
		}
	}
}

func TestValidateGitSourceAcceptsRealForms(t *testing.T) {
	good := []DesiredApp{
		gitApp(),
		{Slug: "web", SourceType: "git", GitRepo: "git@gitlab.com:group/sub/app.git", GitBranch: "release/2.0", GitKey: "k"},
		{Slug: "web", SourceType: "git", GitRepo: "ssh://git@git.example.com:2222/team/app.git", GitBranch: "main", GitKey: "k"},
		{Slug: "web", SourceType: "git", GitRepo: "git@github.com:acme/app", GitBranch: "feature-1", GitKey: "k"},
	}

	for _, app := range good {
		if err := validateGitSource(app); err != nil {
			t.Errorf("отвергнут допустимый источник %q: %v", app.GitRepo, err)
		}
	}
}

// Ключ обязан лечь с правами 0600 в каталог 0700: ssh отказывается работать с
// ключом, который доступен кому-то ещё, и это верное поведение.
func TestWriteGitKeyPermissions(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}

	path, err := writeGitKey(p, gitApp())
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("права ключа %o, ожидалось 600", perm)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("права каталога ключей %o, ожидалось 700", perm)
	}

	// ssh не читает ключ без хвостового перевода строки и выдаёт невнятное
	// «invalid format» — на боевой установке это часы поисков.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Error("ключ записан без хвостового перевода строки")
	}
	if strings.Contains(string(raw), "\n\n-----END") {
		t.Error("в ключе появился лишний перевод строки")
	}
}

// Каталог ключей мог остаться от прежней версии с расширенными правами;
// MkdirAll их не сужает.
func TestWriteGitKeyNarrowsExistingDir(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	dir := filepath.Join(p.StateDir, "git-keys")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := writeGitKey(p, gitApp()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("права существующего каталога не сужены: %o", perm)
	}
}

// Команда ssh должна брать ровно наш ключ. Без IdentitiesOnly ssh переберёт все
// ключи из агента и из ~/.ssh и уйдёт в репозиторий не с тем ключом либо
// упрётся в лимит попыток.
func TestGitSSHCommand(t *testing.T) {
	cmd := gitSSHCommand("/etc/tracedocs/deploy/git-keys/backend")

	for _, want := range []string{
		"-i /etc/tracedocs/deploy/git-keys/backend",
		"IdentitiesOnly=yes",
		"BatchMode=yes",
		"StrictHostKeyChecking=accept-new",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("в команде ssh нет %q: %s", want, cmd)
		}
	}
}

func TestReadComposeFromRepo(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	dir := p.repoDir("backend")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Ни одного из ожидаемых имён — понятная ошибка, а не пустой compose.
	if _, err := readComposeFromRepo(p, DesiredApp{Slug: "backend"}); err == nil {
		t.Fatal("отсутствие файла не считается ошибкой")
	}

	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := readComposeFromRepo(p, DesiredApp{Slug: "backend"})
	if err != nil || !strings.Contains(got, "services") {
		t.Fatalf("получено %q, ошибка %v", got, err)
	}

	// docker-compose.yml имеет приоритет: он идёт первым в списке имён.
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {primary: {}}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err = readComposeFromRepo(p, DesiredApp{Slug: "backend"})
	if err != nil || !strings.Contains(got, "primary") {
		t.Fatalf("приоритет имён нарушен: %q, ошибка %v", got, err)
	}
}

func TestReadComposeFromRepoRejectsEmpty(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	dir := p.repoDir("backend")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("   \n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// Пустой файл дошёл бы до docker compose и дал бы там невнятную ошибку.
	if _, err := readComposeFromRepo(p, DesiredApp{Slug: "backend"}); err == nil {
		t.Fatal("пустой compose принят")
	}
}

// writeSyntheticCompose кладёт то, чего в репозитории нет, — Dockerfile и
// static-репозитории по определению не содержат compose. Проверяем ровно то,
// от чего зависит остальной конвейер: имя проекта (${APP_SLUG} — иначе
// container_name разъедется с конвенцией в proxy.go), имя сервиса "app" и
// подключение к общей сети прокси.
func TestWriteSyntheticComposeDockerfile(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile

	seedDockerfile(t, p, app.Slug)
	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	got, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"name: ${APP_SLUG}",
		"app:",
		"build:",
		"dockerfile: Dockerfile",
		"networks:",
		EdgeNetwork,
		// Переменные и секреты обязаны доезжать до контейнера: --env-file у
		// docker compose задаёт только подстановку ${VAR} в самом YAML, в
		// окружение процессов он ничего не кладёт. До env_file переменные
		// dockerfile-приложения молча не попадали в контейнер вовсе.
		"env_file:",
		p.appDir(app.Slug) + "/.env",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в синтетическом compose нет %q:\n%s", want, got)
		}
	}
	// Порт агент не решает — это дело Dockerfile/образа, а Caddy обращается
	// к контейнеру напрямую по InternalPort из желаемого состояния.
	if strings.Contains(got, "ports:") || strings.Contains(got, "expose:") {
		t.Errorf("compose не должен объявлять порт сам:\n%s", got)
	}
}

func TestWriteSyntheticComposeStatic(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodStatic

	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	got, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"name: ${APP_SLUG}",
		"image: nginx:alpine",
		// Только эта директория репозитория — не /, не /etc, не соседний
		// каталог: bind-монтирование за пределами рабочей копии отклонила бы
		// verifyComposeSafety, а тут его вообще не должно возникать.
		".:/usr/share/nginx/html:ro",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в синтетическом compose нет %q:\n%s", want, got)
		}
	}
}

// Неизвестный способ сборки — дефект сервера (BFF уже проверяет допустимые
// значения), а не то, что агент должен пытаться угадать.
func TestWriteSyntheticComposeRejectsUnknownMethod(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = "buildpack-of-the-future"

	if err := writeSyntheticCompose(p, app); err == nil {
		t.Fatal("неизвестный способ сборки принят")
	}
}

// Способ сборки задаёт сервер на каждом цикле — стек, оставленный клиентом не
// по адресу (или от прошлого выбора build_method), не должен побеждать.
func TestWriteSyntheticComposeOverwritesExisting(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile

	dir := p.repoDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(stray, []byte("services:\n  evil:\n    image: evil\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	seedDockerfile(t, p, app.Slug)
	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	got, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "evil") {
		t.Errorf("синтетический compose не перебил чужой файл:\n%s", got)
	}
}

// Смена ветки или адреса репозитория обязана приводить к переприменению: у
// git-приложения Compose всегда пустой, и без этих полей отпечаток не менялся
// бы, а агент держал бы стек из старой ветки.
func TestConfigHashCoversGitSource(t *testing.T) {
	base := gitApp()
	baseHash := configHash(base)

	changedBranch := base
	changedBranch.GitBranch = "develop"
	if configHash(changedBranch) == baseHash {
		t.Error("смена ветки не изменила отпечаток")
	}

	changedRepo := base
	changedRepo.GitRepo = "git@github.com:acme/other.git"
	if configHash(changedRepo) == baseHash {
		t.Error("смена репозитория не изменила отпечаток")
	}

	// Смена способа сборки (например, dockerfile → static) тоже не трогает ни
	// Compose (пуст в обоих случаях), ни GitRepo, ни GitBranch — без явного
	// отпечатка агент решил бы, что применять нечего.
	changedBuildMethod := base
	changedBuildMethod.BuildMethod = buildMethodDockerfile
	if configHash(changedBuildMethod) == baseHash {
		t.Error("смена способа сборки не изменила отпечаток")
	}

	// Ротация ключа кода не меняет — переприменять из-за неё нечего.
	rotatedKey := base
	rotatedKey.GitKey = "другой ключ"
	if configHash(rotatedKey) != baseHash {
		t.Error("ротация ключа не должна менять отпечаток")
	}
}

// ---------------------------------------------------------------------------
// Подключение через GitHub App: доступ по токену установки
// ---------------------------------------------------------------------------

func githubAppApp() DesiredApp {
	return DesiredApp{
		Slug:       "site",
		SourceType: "git",
		GitRepo:    "acme/site",
		GitBranch:  "main",
		GitToken:   "ghs_testonlytoken",
	}
}

func TestValidateGitSourceAcceptsGithubAppForm(t *testing.T) {
	good := []DesiredApp{
		githubAppApp(),
		{Slug: "site", SourceType: "git", GitRepo: "Acme-Corp/my.repo-1", GitBranch: "release/2.0", GitToken: "t"},
	}

	for _, app := range good {
		if err := validateGitSource(app); err != nil {
			t.Errorf("отвергнут допустимый репозиторий %q: %v", app.GitRepo, err)
		}
	}
}

// Форма адреса и способ доступа связаны жёстко. Разрешить их вразнобой значит
// позволить серверу (или тому, кто его перехватил) отправить токен установки
// на произвольный хост: credential helper отдал бы его туда, куда указывает
// адрес.
func TestValidateGitSourceRejectsTokenWithForeignHost(t *testing.T) {
	bad := []DesiredApp{
		// SSH-адрес вместе с токеном: чужой хост получил бы токен GitHub.
		{Slug: "site", SourceType: "git", GitRepo: "git@evil.example.com:a/b.git", GitBranch: "main", GitToken: "t"},
		// Готовый HTTPS-адрес — тоже мимо: агент собирает его сам и только к github.com.
		{Slug: "site", SourceType: "git", GitRepo: "https://evil.example.com/a/b.git", GitBranch: "main", GitToken: "t"},
		{Slug: "site", SourceType: "git", GitRepo: "https://github.com/a/b.git", GitBranch: "main", GitToken: "t"},
		// Выход на другой путь GitHub через ../ и лишние сегменты.
		{Slug: "site", SourceType: "git", GitRepo: "a/../../evil", GitBranch: "main", GitToken: "t"},
		{Slug: "site", SourceType: "git", GitRepo: "a/b/c", GitBranch: "main", GitToken: "t"},
		{Slug: "site", SourceType: "git", GitRepo: "acme", GitBranch: "main", GitToken: "t"},
		// Ведущий дефис в сегменте: GitHub такого владельца не выдаёт, а нам он
		// однажды прочитается как флаг.
		{Slug: "site", SourceType: "git", GitRepo: "-acme/site", GitBranch: "main", GitToken: "t"},
		// Ветка проверяется одинаково на обоих путях.
		{Slug: "site", SourceType: "git", GitRepo: "acme/site", GitBranch: "--upload-pack=x", GitToken: "t"},
	}

	for _, app := range bad {
		if err := validateGitSource(app); err == nil {
			t.Errorf("принят недопустимый источник: %+v", app)
		}
	}
}

// Токен не должен появляться ни в командной строке, ни в конфигурации git:
// argv виден в `ps` любому процессу на хосте клиента.
func TestGitCredentialHelperKeepsTokenInEnvironment(t *testing.T) {
	helper := gitCredentialHelper()

	if strings.Contains(helper, "ghs_") {
		t.Fatalf("токен подставлен прямо в helper: %q", helper)
	}
	if !strings.Contains(helper, "$"+gitTokenEnvName) {
		t.Fatalf("helper не читает токен из окружения: %q", helper)
	}
	if !strings.Contains(helper, "username="+gitTokenUser) {
		t.Fatalf("helper не отдаёт имя пользователя: %q", helper)
	}
}

// Приложение с ключом ходит по ssh, приложение с токеном — нет. Перепутанный
// путь означал бы либо ssh без ключа, либо токен, отданный в ssh-команду.
func TestFetchRepoUsesTokenPathWithoutWritingKey(t *testing.T) {
	app := githubAppApp()

	if !app.usesToken() {
		t.Fatal("приложение с токеном не опознано")
	}
	if gitApp().usesToken() {
		t.Fatal("приложение с ключом ошибочно опознано как токенное")
	}

	// На токенном пути ключа на диске не появляется вовсе: удалять после OOM
	// или SIGKILL было бы нечего, потому что писать нечего.
	p := Paths{StateDir: t.TempDir()}
	if _, err := os.Stat(p.gitKeyPath(app.Slug)); !os.IsNotExist(err) {
		t.Fatalf("ключ появился на диске для токенного приложения: %v", err)
	}
}

// Токен установки НЕ входит в отпечаток конфигурации — и это не мелочь.
//
// Сервер выписывает его заново на каждый опрос, поэтому в отпечатке он делал бы
// каждый цикл «изменением конфигурации»: агент пересобирал бы и перезапускал
// стек раз в минуту, вечно. Ровно по той же причине из отпечатка исключён ключ.
func TestConfigHashIgnoresRotatingToken(t *testing.T) {
	first := githubAppApp()
	second := githubAppApp()
	second.GitToken = "ghs_completely_different_token"

	if configHash(first) != configHash(second) {
		t.Fatal("смена токена изменила отпечаток: стек будет перезапускаться на каждом опросе")
	}

	// А вот смена ветки обязана его изменить, иначе агент продолжит держать
	// стек из старой.
	third := githubAppApp()
	third.GitBranch = "release/2.0"
	if configHash(first) == configHash(third) {
		t.Fatal("смена ветки не изменила отпечаток")
	}
}

// Статика — единственный способ сборки, где образ наш (nginx:alpine) и wget
// гарантирован, поэтому healthcheck объявляется в синтетическом compose.
// Для dockerfile-сборок его НЕ должно быть: инструменты внутри образа
// клиента неизвестны, и болтающийся CMD валил бы здоровый контейнер.
func TestSyntheticComposeHealthcheckOnlyForStatic(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}

	static := DesiredApp{Slug: "site", BuildMethod: buildMethodStatic}
	if err := writeSyntheticCompose(p, static); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(p.repoDir("site"), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "healthcheck:") {
		t.Fatalf("у статики нет healthcheck:\n%s", raw)
	}

	built := DesiredApp{Slug: "api", BuildMethod: buildMethodDockerfile}
	seedDockerfile(t, p, built.Slug)
	if err := writeSyntheticCompose(p, built); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(p.repoDir("api"), "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "healthcheck:") {
		t.Fatalf("dockerfile-сборке навязан healthcheck с неизвестными инструментами:\n%s", raw)
	}
}

// ---------------------------------------------------------------------------
// Публичный репозиторий (0178)
// ---------------------------------------------------------------------------

func TestValidateGitSourcePublicRepo(t *testing.T) {
	base := DesiredApp{Slug: "kuma", GitBranch: "master"}

	// Валидный анонимный источник: https, без ключа и токена.
	ok := base
	ok.GitRepo = "https://github.com/louislam/uptime-kuma.git"
	if err := validateGitSource(ok); err != nil {
		t.Fatalf("валидный публичный адрес отвергнут: %v", err)
	}

	// Ключ рядом с публичным адресом — рассинхрон сервера, не молчим.
	withKey := ok
	withKey.GitKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := validateGitSource(withKey); err == nil {
		t.Fatal("публичный адрес с ключом принят")
	}

	// Обходы формы: креды в URL, IP, односегментный хост, http, query.
	for _, repo := range []string{
		"https://user:pass@github.com/a/b.git",
		"https://user@github.com/a/b.git",
		"https://192.168.1.10/a/b.git",
		"https://localhost/a/b.git",
		"https://github.com/a/b.git%40evil",
		"https://github.com/a/b?ref=x",
		"http://github.com/a/b.git",
	} {
		bad := base
		bad.GitRepo = repo
		if err := validateGitSource(bad); err == nil {
			t.Fatalf("недопустимый публичный адрес принят: %s", repo)
		}
	}
}

func TestPublicRepoCloneURLAndAuth(t *testing.T) {
	app := DesiredApp{
		Slug:      "kuma",
		GitRepo:   "https://github.com/louislam/uptime-kuma.git",
		GitBranch: "master",
	}
	if !app.isPublicRepo() {
		t.Fatal("https-адрес не опознан как публичный")
	}
	if app.usesToken() {
		t.Fatal("публичный источник не должен считаться токенным")
	}
	// Адрес уезжает в git как есть — учётным данным в нём взяться неоткуда,
	// форма это гарантирует.
	if got := app.cloneURL(); got != app.GitRepo {
		t.Fatalf("cloneURL изменил публичный адрес: %q", got)
	}
	if strings.Contains(app.cloneURL(), "@") {
		t.Fatal("в адресе клона появились учётные данные")
	}
}

// Аддоны (0186): postgres/redis рендерятся в синтетический compose рядом с
// app — в той же compose-сети, с пришпиленным образом из каталога сервера.
func TestWriteSyntheticComposeWithAddons(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.Addons = []AddonSpec{
		{Kind: "postgres", Service: "db",
			Image: "postgres:16.6-alpine@sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef"},
		{Kind: "redis", Service: "redis",
			Image: "redis:7.4-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2"},
	}

	seedDockerfile(t, p, app.Slug)
	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}
	got, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"  db:\n",
		"postgres:16.6-alpine@sha256:",
		"POSTGRES_PASSWORD: ${ADDON_POSTGRES_PASSWORD}",
		"db-data:/var/lib/postgresql/data",
		"pg_isready",
		"  redis:\n",
		"redis-cli",
		"volumes:\n  db-data: {}",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в compose с аддонами нет %q:\n%s", want, got)
		}
	}
	// Пароль не приезжает открытым текстом — только интерполяцией из .env.
	if strings.Contains(got, "ADDON_POSTGRES_PASSWORD:") && !strings.Contains(got, "${ADDON_POSTGRES_PASSWORD}") {
		t.Errorf("пароль аддона попал в compose открыто:\n%s", got)
	}
}

// Негодный аддон — отказ применения, не молчаливый пропуск: приложение с
// DATABASE_URL, указывающим в никуда, упало бы позже и непонятнее.
func TestWriteSyntheticComposeRejectsBadAddon(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	base := gitApp()
	base.BuildMethod = buildMethodDockerfile

	for name, addon := range map[string]AddonSpec{
		"неизвестный вид":     {Kind: "mysql", Service: "db", Image: "postgres:16@sha256:" + strings.Repeat("a", 64)},
		"образ без дайджеста": {Kind: "postgres", Service: "db", Image: "postgres:16.6-alpine"},
		"кривое имя сервиса":  {Kind: "postgres", Service: "evil }\n", Image: "postgres:16@sha256:" + strings.Repeat("a", 64)},
	} {
		app := base
		app.Addons = []AddonSpec{addon}
		if err := writeSyntheticCompose(p, app); err == nil {
			t.Errorf("%s: аддон принят", name)
		}
	}
}

// seedDockerfile кладёт в рабочую копию минимальный Dockerfile.
//
// Нужен тестам способа сборки «образ из Dockerfile»: writeSyntheticCompose
// теперь проверяет наличие файла ДО записи compose — раньше отсутствие
// всплывало сырым текстом docker на фазе build, минутами позже.
func seedDockerfile(t *testing.T, p Paths, slug string) {
	t.Helper()
	dir := p.repoDir(slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог рабочей копии не создан: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o640); err != nil {
		t.Fatalf("Dockerfile не записан: %v", err)
	}
}

// Отсутствие Dockerfile — отказ ДО подъёма, с указанием, что путь только
// корневой. Раньше проверки не было вовсе у приложений без переменных сборки.
func TestSyntheticComposeRequiresDockerfile(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.BuildArgs = nil

	err := writeSyntheticCompose(p, app)
	if err == nil {
		t.Fatal("отсутствие Dockerfile не замечено")
	}
	if !strings.Contains(err.Error(), "Dockerfile") || !strings.Contains(err.Error(), "корне") {
		t.Fatalf("текст отказа не объясняет причину: %v", err)
	}
}

// Смена адреса репозитория опознаётся, неизменившийся — нет.
//
// Ветка деструктивная: расхождение сносит рабочую копию целиком. Ложное
// «сменился» означало бы полный переклон на КАЖДОМ применении — на большом
// репозитории это упирается в пятиминутный срок команды git, и выкат, который
// раньше проходил, начинает падать без видимой причины.
func TestRepoChanged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git недоступен")
	}
	dir := t.TempDir()
	ctx := context.Background()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	run("remote", "add", "origin", "git@github.com:acme/api.git")

	var auth gitAuth
	if repoChanged(ctx, dir, auth, "git@github.com:acme/api.git") {
		t.Fatal("неизменившийся адрес признан сменившимся — был бы переклон каждый раз")
	}
	if !repoChanged(ctx, dir, auth, "git@github.com:acme/other.git") {
		t.Fatal("смена адреса не опознана — чужие файлы остались бы в рабочей копии")
	}

	// Каталог без репозитория: «неизвестно» трактуется как «сменился».
	if !repoChanged(ctx, t.TempDir(), auth, "git@github.com:acme/api.git") {
		t.Fatal("каталог без репозитория признан совпадающим")
	}
}
