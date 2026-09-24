package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Контракт желаемого состояния между BFF и агентом.
//
// Ту же фикстуру читает TypeScript
// (`apps/web/src/lib/deploy/desiredState.test.ts`). Смысл в том, чтобы
// расхождение имён полей падало здесь, а не проявлялось на хосте клиента как
// стек, поднявшийся без конфигурации, или как пороги, которые не применились.
//
// Обычные тесты этого не ловят: каждая сторона проверяет саму себя и остаётся
// внутренне непротиворечивой ровно до первого выката.

func loadDesiredStateFixture(t *testing.T) DesiredState {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..",
		"packages", "deploy-core", "fixtures", "desired-state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не удалось прочитать эталон контракта: %v", err)
	}

	// DisallowUnknownFields — ради того сценария, из-за которого фикстура и
	// заведена: поле добавили в BFF и забыли в агенте. Без него такой эталон
	// разбирался бы молча, а расхождение всплывало бы на хосте клиента.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var state DesiredState
	if err := dec.Decode(&state); err != nil {
		t.Fatalf("эталон не разбирается структурами агента: %v", err)
	}
	return state
}

func TestDesiredStateFixtureParses(t *testing.T) {
	state := loadDesiredStateFixture(t)

	// Шесть приложений: стек из каталога, репозиторий по SSH-ключу, репозиторий
	// через GitHub App, публичный репозиторий без учётных данных (0178),
	// перехваченный стек на своём compose (0206) и обновление шаблона без данных
	// (backupSpec `{"stateless": true}`, 0156). По одному на каждый путь,
	// который агент обязан понимать.
	if len(state.Apps) != 6 {
		t.Fatalf("приложений в эталоне %d, ожидалось 6", len(state.Apps))
	}
	if len(state.Registries) != 1 {
		t.Fatalf("реестров в эталоне %d, ожидалось 1", len(state.Registries))
	}
}

// Поля, добавленные позже остальных, — первые кандидаты на расхождение: их
// добавляют на одной стороне и забывают на другой.
func TestDesiredStateFixtureCarriesTemplateFiles(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[0]

	if len(app.Files) != 2 {
		t.Fatalf("файлов шаблона %d, ожидалось 2 — поле files не доехало", len(app.Files))
	}
	if app.Files[0].Path != "volumes/api/kong.yml" {
		t.Fatalf("путь файла %q", app.Files[0].Path)
	}
	if app.Files[0].Mode != "0644" {
		t.Fatalf("режим файла %q", app.Files[0].Mode)
	}
	if app.Files[0].Content == "" {
		t.Fatal("содержимое файла пустое")
	}
}

// Маршруты публикации — самое свежее поле контракта, и потому первый кандидат
// на расхождение: добавили на одной стороне, забыли на другой.
func TestDesiredStateFixtureCarriesRoutes(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[0]

	if len(app.Routes) != 2 {
		t.Fatalf("маршрутов %d, ожидалось 2 — поле routes не доехало", len(app.Routes))
	}
	if app.Routes[0].Service != "app" || app.Routes[0].Port != 8000 {
		t.Fatalf("первичный маршрут разобран неверно: %+v", app.Routes[0])
	}
	if app.Routes[1].Service != "studio" {
		t.Fatalf("маршрут панели разобран неверно: %+v", app.Routes[1])
	}

	// Политики доступа на маршруте панели: все три типа сосуществуют.
	if len(app.Routes[1].Policies) != 3 {
		t.Fatalf("политик %d, ожидалось 3 — поле policies не доехало", len(app.Routes[1].Policies))
	}
	if p := app.Routes[1].Policies[0]; p.Type != "basic_auth" || p.Username != "admin" || !safeBcryptHash.MatchString(p.PasswordHash) {
		t.Fatalf("политика basic_auth разобрана неверно: %+v", p)
	}
	if p := app.Routes[1].Policies[1]; p.Type != "ip_allowlist" || len(p.Cidrs) != 2 {
		t.Fatalf("политика ip_allowlist разобрана неверно: %+v", p)
	}
	if p := app.Routes[1].Policies[2]; p.Type != "forward_auth" {
		t.Fatalf("политика forward_auth разобрана неверно: %+v", p)
	}

	// Конфиг прокси обязан получить обе цели, а защищённый маршрут — все три
	// политики. PlatformBaseURL обязателен: без него forward_auth сделает
	// fail-closed и маршрут не опубликуется вовсе.
	conf := renderCaddyfile([]DesiredApp{app}, ProxyOptions{PlatformBaseURL: "https://scopework.ru"})
	if !strings.Contains(conf, "supabase-studio-1:3000") {
		t.Fatalf("маршрут панели не доехал до конфига прокси:\n%s", conf)
	}
	if !strings.Contains(conf, "basic_auth {") || !strings.Contains(conf, "\tadmin ") {
		t.Fatalf("защита маршрута не доехала до конфига прокси:\n%s", conf)
	}
	if !strings.Contains(conf, "@denied not remote_ip 203.0.113.7 10.0.0.0/8") {
		t.Fatalf("список IP не доехал до конфига прокси:\n%s", conf)
	}
	if !strings.Contains(conf, "forward_auth https://scopework.ru {") {
		t.Fatalf("forward_auth не доехал до конфига прокси:\n%s", conf)
	}
}

func TestDesiredStateFixtureCarriesApplySpec(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[0]

	if app.ApplySpec.WaitTimeoutSeconds != 600 {
		t.Fatalf("таймаут %d, ожидалось 600 — поле applySpec не доехало",
			app.ApplySpec.WaitTimeoutSeconds)
	}
	if app.ApplySpec.normalized().WaitTimeout().Seconds() != 600 {
		t.Fatal("значение шаблона потеряно при нормализации")
	}
}

func TestDesiredStateFixtureCarriesBackupSpec(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[0]

	if !app.NeedsBackup {
		t.Fatal("признак резервной копии не доехал")
	}
	if len(app.BackupSpec.Postgres) != 1 || app.BackupSpec.Postgres[0].Service != "db" {
		t.Fatalf("задание на копию базы разобрано неверно: %+v", app.BackupSpec)
	}
	if len(app.BackupSpec.Volumes) != 2 {
		t.Fatalf("томов в задании %d, ожидалось 2", len(app.BackupSpec.Volumes))
	}
}

// У приложения из репозитория files приходит пустым намеренно: файлы лежат в
// рабочей копии, и запись поверх подменяла бы код клиента.
func TestDesiredStateFixtureGitAppHasNoFiles(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[1]

	if !app.FromGit() {
		t.Fatal("приложение не опознано как собираемое из репозитория")
	}
	if len(app.Files) != 0 {
		t.Fatalf("приложению из репозитория приехали файлы шаблона: %+v", app.Files)
	}
	if app.ShouldRun() {
		t.Fatal("признак absent не разобран")
	}
}

// Приложение, подключённое через GitHub App: вместо ключа приезжает токен.
//
// Поле добавлялось последним, и именно такие поля расходятся между сторонами
// незаметно: BFF уже шлёт, агент ещё не читает — а выглядит это на хосте как
// «репозиторий недоступен», без единого намёка на причину.
func TestDesiredStateFixtureCarriesInstallationToken(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[2]

	if !app.FromGit() {
		t.Fatal("приложение не опознано как собираемое из репозитория")
	}
	if !app.usesToken() {
		t.Fatal("токен установки не доехал — поле gitToken потеряно")
	}
	if app.GitKey != "" {
		t.Fatal("вместе с токеном приехал ещё и ключ: сервер обязан слать что-то одно")
	}
	if err := validateGitSource(app); err != nil {
		t.Fatalf("эталонное приложение не прошло проверку агента: %v", err)
	}

	// Адрес собирается агентом и не содержит учётных данных: он оседает в
	// .git/config на хосте клиента и во выводе любой упавшей команды.
	url := app.cloneURL()
	if url != "https://github.com/acme/site.git" {
		t.Fatalf("адрес клона %q", url)
	}
	if strings.Contains(url, app.GitToken) || strings.Contains(url, "@") {
		t.Fatalf("токен попал в адрес репозитория: %q", url)
	}
}

// BuildMethod — свежее поле контракта: способ получить образ сервиса app из
// репозитория, когда в нём нет своего docker-compose.yml. Расхождение имён
// здесь означало бы, что агент тихо продолжает искать compose там, где его
// никогда не будет, — а такая ошибка сегодня уже явная и понятная
// (readComposeFromRepo), но только если поле действительно доехало.
func TestDesiredStateFixtureCarriesBuildMethod(t *testing.T) {
	state := loadDesiredStateFixture(t)

	// Шаблонное приложение: поле не используется вовсе (source_type=template),
	// но JSON null обязан лечь в значение по умолчанию, а не сломать разбор.
	if state.Apps[0].BuildMethod != "" {
		t.Fatalf("у приложения из каталога build_method %q, ожидалась пустая строка",
			state.Apps[0].BuildMethod)
	}

	// backend: обычный docker-compose.yml из репозитория — путь, которым
	// платформа умела развёртывать git-приложения ещё до этого поля.
	if state.Apps[1].BuildMethod != buildMethodCompose {
		t.Fatalf("у backend build_method %q, ожидалось %q", state.Apps[1].BuildMethod, buildMethodCompose)
	}
	if state.Apps[1].needsSyntheticCompose() {
		t.Fatal("compose не должен считаться способом, требующим синтеза")
	}

	// site: собирается из Dockerfile — агент обязан сам положить compose в
	// рабочую копию репозитория, а не искать несуществующий файл.
	if state.Apps[2].BuildMethod != buildMethodDockerfile {
		t.Fatalf("у site build_method %q, ожидалось %q", state.Apps[2].BuildMethod, buildMethodDockerfile)
	}
	if !state.Apps[2].needsSyntheticCompose() {
		t.Fatal("dockerfile обязан считаться способом, требующим синтеза")
	}
}

// Признак первого релиза и отметка удаления данных — свежие поля контракта,
// и оба управляют операциями с необратимыми последствиями: отказом
// разворачиваться и удалением томов. Расхождение имён здесь означало бы, что
// защита молча не работает.
func TestDesiredStateFixtureCarriesDataFlags(t *testing.T) {
	state := loadDesiredStateFixture(t)

	if !state.Apps[0].FirstRelease {
		t.Fatal("признак первого релиза не доехал — защита от чужих данных выключена")
	}
	if state.Apps[0].PurgeData {
		t.Fatal("удаление данных включилось само — оно обязано быть явным выбором")
	}
	if !state.Apps[1].PurgeData {
		t.Fatal("отметка удаления данных не доехала")
	}
	if state.Apps[1].FirstRelease {
		t.Fatal("повторный выкат помечен первым релизом — отказ сработает на своих данных")
	}
}

// Публичный репозиторий (0178): ни ключа, ни токена — клон анонимный, и
// эталон обязан проходить проверку агента именно в таком виде. Поле,
// перепутанное на одной из сторон, всплыло бы здесь, а не отказом клона
// на хосте клиента.
func TestDesiredStateFixturePublicGitApp(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[3]

	if !app.FromGit() {
		t.Fatal("приложение не опознано как собираемое из репозитория")
	}
	if !app.isPublicRepo() {
		t.Fatal("https-адрес не опознан как публичный источник")
	}
	if app.usesToken() || app.GitKey != "" {
		t.Fatal("публичному приложению приехали учётные данные")
	}
	if err := validateGitSource(app); err != nil {
		t.Fatalf("эталонное публичное приложение не прошло проверку агента: %v", err)
	}
	if app.cloneURL() != app.GitRepo {
		t.Fatalf("адрес клона изменён: %q", app.cloneURL())
	}
	if !app.needsSyntheticCompose() {
		t.Fatal("dockerfile-сборка обязана требовать синтеза compose")
	}
}

// Аддоны (0186) — разрешённый список сервисов рядом с приложением. Проверяем,
// что поле доезжает и рендерится в синтетический compose.
func TestDesiredStateFixtureCarriesAddons(t *testing.T) {
	apps := loadDesiredStateFixture(t).Apps

	site := apps[2]
	if site.Slug != "site" {
		t.Fatalf("порядок приложений в эталоне изменился: %q", site.Slug)
	}
	if len(site.Addons) != 2 {
		t.Fatalf("аддонов %d, ожидалось 2 — поле addons не доехало", len(site.Addons))
	}
	if site.Addons[0].Kind != "postgres" || site.Addons[0].Service != "db" {
		t.Fatalf("аддон postgres разобран неверно: %+v", site.Addons[0])
	}

	rendered, err := renderAddonServices(site.Addons)
	if err != nil {
		t.Fatalf("аддоны эталона не рендерятся: %v", err)
	}
	if !strings.Contains(rendered.services, "POSTGRES_PASSWORD: ${ADDON_POSTGRES_PASSWORD}") {
		t.Fatalf("рендер postgres без интерполяции пароля:\n%s", rendered.services)
	}
}

// Перехваченный стек (0206): свой compose, файлы конфигурации и разрешённые
// имена томов. Поле adoptedVolumes управляет проверкой, снимающей запрет, —
// расхождение имён здесь означало бы, что стек не поднимается вовсе (список не
// доехал) либо что запрет снят не тем приложением.
func TestDesiredStateFixtureCarriesAdoptedStack(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[4]

	if app.SourceType != "compose" || !app.UntrustedCompose() {
		t.Fatalf("перехваченный стек не опознан как свой compose: %q", app.SourceType)
	}
	if len(app.AdoptedVolumes) != 2 {
		t.Fatalf("разрешённых томов %d, ожидалось 2 — поле adoptedVolumes не доехало",
			len(app.AdoptedVolumes))
	}

	// Файлы конфигурации теперь едут и своему compose: стек, монтирующий
	// kong.yml, без них поднимается с пустым каталогом, созданным докером, и
	// проходит health gate — шлюз при этом не знает ни одного маршрута.
	if len(app.Files) != 1 || app.Files[0].Path != "volumes/api/kong.yml" {
		t.Fatalf("файлы конфигурации не доехали до своего compose: %+v", app.Files)
	}

	// Сквозная проверка: ровно те имена принимаются guard'ом, а соседнее — нет.
	// Без неё поле могло бы доехать и не использоваться.
	normalized := `{"name":"sigma-supabase","services":{"db":{"image":"x"}},"volumes":{
		"db-data":{"name":"` + app.AdoptedVolumes[0] + `"},
		"stolen":{"name":"neighbour_db-data"}
	}}`
	v, err := checkComposeSafety([]byte(normalized),
		[]string{"/opt/tracedocs/deploy/apps/sigma-supabase"}, app.AdoptedVolumes)
	if err != nil {
		t.Fatalf("разбор не удался: %v", err)
	}
	if len(v) != 1 || !strings.Contains(v[0].Reason, "neighbour_db-data") {
		t.Fatalf("разрешение оказалось не узким: %v", v)
	}
}

// Блокировка адресов (0204) — хостовое поле контракта, а не поле приложения:
// первый кандидат на расхождение именно потому, что живёт рядом с apps и
// registries, а не внутри них.
func TestDesiredStateFixtureCarriesDenyIPs(t *testing.T) {
	state := loadDesiredStateFixture(t)

	if len(state.DenyIPs) != 3 {
		t.Fatalf("записей блокировки %d, ожидалось 3 — поле denyIps не доехало", len(state.DenyIPs))
	}

	// Список применяется ко всем доменам хоста, включая маршруты со своими
	// политиками: бан обязан стоять до пароля и до forward_auth.
	conf := renderCaddyfile(state.Apps, ProxyOptions{PlatformBaseURL: "https://scopework.ru", DenyIPs: state.DenyIPs})
	if !strings.Contains(conf, "@banned remote_ip 198.51.100.0/24 203.0.113.7 2001:db8:dead::/64") {
		t.Fatalf("блокировка не доехала до конфига прокси:\n%s", conf)
	}
	banAt := strings.Index(conf, "respond @banned 403")
	authAt := strings.Index(conf, "basic_auth {")
	if banAt == -1 || authAt == -1 || banAt > authAt {
		t.Fatalf("блокировка обязана стоять до проверки пароля:\n%s", conf)
	}
}

// Папка приложения и контекст сборки (0284) — поля, без которых монорепо не
// развернуть вовсе. Расхождение имён здесь означало бы, что агент продолжает
// читать корень репозитория, где нужного compose нет и не будет, а платформа
// показывает в интерфейсе выбранную человеком папку.
func TestDesiredStateFixtureCarriesBaseDir(t *testing.T) {
	state := loadDesiredStateFixture(t)

	// Приложение из корня: пустая строка, то есть поведение до появления поля.
	if state.Apps[1].GitBaseDir != "" || state.Apps[1].GitBuildContextRoot {
		t.Fatalf("у backend папка %q, контекст из корня %v — ожидался корень репозитория",
			state.Apps[1].GitBaseDir, state.Apps[1].GitBuildContextRoot)
	}

	// site — монорепо: приложение в apps/web, сборка из корня.
	site := state.Apps[2]
	if site.GitBaseDir != "apps/web" {
		t.Fatalf("у site папка приложения %q, ожидалась apps/web", site.GitBaseDir)
	}
	if !site.GitBuildContextRoot {
		t.Fatal("у site не доехал контекст сборки из корня — сборка монорепо упала бы на COPY")
	}
	if err := validateGitSource(site); err != nil {
		t.Fatalf("эталонное монорепо-приложение не прошло проверку агента: %v", err)
	}
}

// Обновление шаблона без данных: deploy_upgrade_app копирует в релиз
// `{"stateless": true}` шаблона (CHECK templates_backup_spec_declared, 0156), и
// web отдаёт его как есть. До того как поле появилось в BackupSpec, строгий
// разбор подписанного состояния отвергал такой пакет целиком
// (unsupported_content) — на каждом такте и для всех приложений хоста.
func TestDesiredStateFixtureCarriesStatelessBackupSpec(t *testing.T) {
	app := loadDesiredStateFixture(t).Apps[5]
	if !app.BackupSpec.Stateless || !app.BackupSpec.isEmpty() || app.NeedsBackup {
		t.Fatalf("задание на копию приложения без данных разобрано неверно: %+v, needsBackup %v",
			app.BackupSpec, app.NeedsBackup)
	}
}

// Хостовые поля, которые web кладёт рядом с apps (desiredStatePayload.ts):
// база платформенных поддоменов и хранилище копий. Эталон обязан нести их,
// иначе строгий разбор подписанного состояния их ни разу не видел.
func TestDesiredStateFixtureCarriesHostFields(t *testing.T) {
	state := loadDesiredStateFixture(t)
	if state.PlatformSubdomainBase == "" {
		t.Fatal("platformSubdomainBase не доехал")
	}
	if state.ObjectStorage == nil || state.ObjectStorage.SecretKey == "" || !state.ObjectStorage.Multipart {
		t.Fatalf("objectStorage не доехал: %+v", state.ObjectStorage)
	}
}

// Эталон обязан нести КАЖДОЕ поле, которое знают структуры агента, хотя бы в
// одном месте. Строгий разбор подписанного состояния проверяет только то, что
// в эталоне есть: поле, которого в нём нет, ни разу не проходило стык web →
// подписант → агент, и расхождение имён в нём всплыло бы на хосте клиента
// отказом всему пакету, как `stateless` в backupSpec.
func TestDesiredStateFixtureCoversEveryAgentField(t *testing.T) {
	raw := readContractFixture(t, "desired-state.json")
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	present := map[string]bool{}
	collectJSONPaths(doc, "", present)

	var missing []string
	for _, path := range structJSONPaths(reflect.TypeOf(DesiredState{}), "") {
		if !present[path] {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("поля агента, которых нет в desired-state.json: %s", strings.Join(missing, ", "))
	}
}

// structJSONPaths — пути json-полей типа: `apps[].backupSpec.stateless`.
// Поля с тегом "-" не приезжают по сети и в контракт не входят.
func structJSONPaths(t reflect.Type, prefix string) []string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		if t.Kind() == reflect.Slice {
			prefix += "[]"
		}
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" || name == "" || !f.IsExported() {
			continue
		}
		path := prefix + "." + name
		out = append(out, path)
		out = append(out, structJSONPaths(f.Type, path)...)
	}
	return out
}

func collectJSONPaths(v any, prefix string, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			out[prefix+"."+k] = true
			collectJSONPaths(child, prefix+"."+k, out)
		}
	case []any:
		for _, child := range x {
			collectJSONPaths(child, prefix+"[]", out)
		}
	}
}
