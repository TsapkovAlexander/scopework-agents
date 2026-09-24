//go:build dockersmoke

package agent

// Прогон НАСТОЯЩЕГО восстановления из копии против НАСТОЯЩЕГО Docker (ADR-0063).
//
// restore_test.go и restore_rules_test.go проверяют операцию через поддельный
// docker: какие команды, в каком порядке, с какими флагами. Вернулись ли
// данные, поддельный docker сказать не может — psql у него ничего не вливает, а
// tar ничего не распаковывает. Здесь проверяется ровно это.
//
// Сценарий один на оба шаблона: настоящий Apply поднимает стек, в базу ложится
// запись А, настоящий CreateBackup снимает набор с работающего стека, ложится
// запись Б, настоящий RestoreBackup возвращает набор.
//
// n8n: после восстановления в таблице РОВНО одна строка А, а метка в томе
// приложения — снова А. «А есть» прошло бы и тогда, когда дамп лёг поверх
// прежней базы и Б осталась. compose — из миграции 0142, backup_spec — из 0155:
// то, что платформа выдаёт клиенту, а не пересказ.
//
// Supabase: дамп на чистую базу этого образа не ложится (ADR-0063, решение 9),
// и восстановление обязано отказать до `down` — стек не пересоздан, в таблице А
// и Б, флага нет. Комплект шаблона — как у apply_docker_test.go
// (`scripts/smoke-deploy-template.ts --bundle-only`).
//
// Собирается отдельным тегом и не участвует в обычном `go test ./...`: без
// docker-демона ему нечего делать.
//
//	go test -count=1 -tags dockersmoke -run '^TestRestoreN8nOnRealDocker$' -v -timeout 30m ./internal/agent/
//	SMOKE_BUNDLE=/tmp/комплект go test -count=1 -tags dockersmoke \
//	  -run '^TestRestoreSupabaseOnRealDocker$' -v -timeout 60m ./internal/agent/
//
// Прогон идёт и на машине разработчика рядом с чужими стеками. Поэтому slug —
// с префиксом tdrestore-, порты хоста и имена контейнеров проверяются до
// подъёма, а уборка трогает только проект и тома своего slug.

import (
	"context"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Записи до и после копии. Латиница — чтобы сравнение не зависело от
// кодировки клиента psql внутри контейнера.
const (
	restoreProbeBefore = "A-before-backup"
	restoreProbeAfter  = "B-after-backup"
)

// Метка в томе приложения n8n. Тома, кроме базы, возвращает архив, а не дамп,
// и без метки их распаковка осталась бы непроверенной.
const n8nRestoreMark = "/home/node/.n8n/restore-probe"

func TestRestoreN8nOnRealDocker(t *testing.T) {
	pg := PostgresBackup{Service: "db", User: "n8n", Database: "n8n"}
	app := DesiredApp{
		Slug:         "tdrestore-n8n",
		ReleaseID:    "00000000-0000-4000-8000-00000000e201",
		Desired:      "present",
		SourceType:   "template",
		FirstRelease: true,
		Compose:      n8nComposeFromMigration(t),
		// Секреты случайные на каждый прогон: база настоящая и живёт на машине
		// разработчика, константа в коде стала бы паролем с известным значением.
		Env: map[string]string{
			"POSTGRES_PASSWORD":  rand.Text(),
			"N8N_ENCRYPTION_KEY": rand.Text(),
			"TZ":                 "Europe/Moscow",
		},
		// deploy.n8n_backup_spec() из миграции 0155.
		BackupSpec: BackupSpec{Postgres: []PostgresBackup{pg}, Volumes: []string{"db-data", "app-data"}},
		// Запас на скачивание образов при первом подъёме.
		ApplySpec: ApplySpec{WaitTimeoutSeconds: 600},
	}

	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	start := time.Now()

	prepareRestoreHost(t, ctx, p, app)
	applyForRestore(t, ctx, p, app)
	t.Logf("стек поднят за %s", time.Since(start).Round(time.Second))

	psqlOnApp(t, ctx, p, app, pg, "CREATE TABLE public.restore_probe (label text PRIMARY KEY)")
	psqlOnApp(t, ctx, p, app, pg, "INSERT INTO public.restore_probe VALUES ('"+restoreProbeBefore+"')")
	writeN8nMark(t, ctx, p, app, restoreProbeBefore)

	setDir := backupForRestore(t, ctx, p, app)
	t.Logf("набор снят: %s", filepath.Base(setDir))

	psqlOnApp(t, ctx, p, app, pg, "INSERT INTO public.restore_probe VALUES ('"+restoreProbeAfter+"')")
	writeN8nMark(t, ctx, p, app, restoreProbeAfter)
	// Б обязана действительно лечь: иначе «после восстановления ровно А»
	// доказывало бы не восстановление, а несработавшую запись.
	requireProbeRows(t, ctx, p, app, pg, "2:"+restoreProbeBefore+","+restoreProbeAfter)
	if got := readN8nMark(t, ctx, p, app); got != restoreProbeAfter {
		t.Fatalf("метка Б в томе приложения не записалась: %q", got)
	}

	restoreStart := time.Now()
	if err := RestoreBackup(ctx, p, app, setDir); err != nil {
		t.Fatalf("восстановление не удалось: %v", err)
	}
	t.Logf("восстановление заняло %s", time.Since(restoreStart).Round(time.Second))

	requireProbeRows(t, ctx, p, app, pg, "1:"+restoreProbeBefore)
	if got := readN8nMark(t, ctx, p, app); got != restoreProbeBefore {
		t.Errorf("том приложения не вернулся из архива: метка %q, ожидалась %q", got, restoreProbeBefore)
	}
	requireStackRunning(t, ctx, p, app)
}

func TestRestoreSupabaseOnRealDocker(t *testing.T) {
	app := loadSmokeApp(t)
	app.Slug = "tdrestore-supa"
	// Домен шаблону Supabase нужен сам по себе, а не только прокси: из него
	// собираются STORAGE_PUBLIC_URL и API_EXTERNAL_URL, и storage с пустым
	// доменом падает на разборе `https://` (прогон 11.09.2026). Зона .invalid не
	// разрешается никогда.
	app.Domain = "tdrestore-supa.smoke.invalid"
	// Публикацию этот тест не проверяет. Без маршрутов и с нулевым портом
	// VerifyRoutes не стучится в адрес контейнера, недоступный с хоста Docker
	// Desktop.
	app.Routes = nil
	app.InternalPort = 0
	app.FirstRelease = true
	if len(app.BackupSpec.Postgres) != 1 {
		t.Fatalf("в комплекте ожидалась одна база в backup_spec, их %d", len(app.BackupSpec.Postgres))
	}
	pg := app.BackupSpec.Postgres[0]

	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()
	start := time.Now()

	prepareRestoreHost(t, ctx, p, app)
	applyForRestore(t, ctx, p, app)
	t.Logf("стек поднят за %s", time.Since(start).Round(time.Second))

	psqlOnApp(t, ctx, p, app, pg, "CREATE TABLE public.restore_probe (label text PRIMARY KEY)")
	psqlOnApp(t, ctx, p, app, pg, "INSERT INTO public.restore_probe VALUES ('"+restoreProbeBefore+"')")

	setDir := backupForRestore(t, ctx, p, app)
	t.Logf("набор снят: %s", filepath.Base(setDir))

	psqlOnApp(t, ctx, p, app, pg, "INSERT INTO public.restore_probe VALUES ('"+restoreProbeAfter+"')")
	requireProbeRows(t, ctx, p, app, pg, "2:"+restoreProbeBefore+","+restoreProbeAfter)
	containersBefore := projectContainerIDs(t, app.Slug)

	// Дамп Supabase на чистую базу не ложится: роль, которую создаёт сервис
	// realtime, в дамп не входит (прогон 11.09.2026, см. databaseImageRefusal).
	// Значит, восстановление обязано отказать ДО `down`: стек тот же, данные те
	// же, флага нет.
	err := RestoreBackup(ctx, p, app, setDir)
	if err == nil {
		t.Fatal("восстановление на образе supabase/postgres не отказало — " +
			"либо правило отказа не сработало, либо дамп теперь ложится и тест пора менять на «ровно А»")
	}
	t.Logf("отказ: %v", err)
	for _, want := range []string{"Supabase", "не поддерживается", "не останавливался", "не тронуты"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в отказе нет %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "ERROR") {
		t.Errorf("отказ пришёл от psql, то есть уже после down: %v", err)
	}

	if after := projectContainerIDs(t, app.Slug); !slices.Equal(containersBefore, after) {
		t.Errorf("контейнеры стека пересозданы — стек останавливали: было %v, стало %v", containersBefore, after)
	}
	requireProbeRows(t, ctx, p, app, pg, "2:"+restoreProbeBefore+","+restoreProbeAfter)
	requireStackRunning(t, ctx, p, app)
}

// n8nComposeFromMigration — compose шаблона n8n ровно в том виде, в каком его
// хранит платформа: текст между маркерами `$compose$` миграции 0142.
//
// Файла нет или разметка другая — t.Fatal, а не Skip: пропуск здесь выглядел бы
// зелёным прогоном, который ничего не проверил.
func n8nComposeFromMigration(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "dev_ops", "supabase", "migrations", "0142_deploy_template_n8n.sql")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("миграция шаблона n8n не читается: %v", err)
	}
	parts := strings.Split(string(raw), "$compose$")
	if len(parts) != 3 || !strings.Contains(parts[1], "services:") {
		t.Fatalf("в %s не найден compose между двумя маркерами $compose$ (частей %d)", path, len(parts))
	}
	return parts[1]
}

// prepareRestoreHost проверяет, что хост чист по slug, и регистрирует уборку.
//
// Остатки прошлого прогона убираются по имени проекта, а не из каталога
// приложения: тот жил во временной папке упавшего теста и уже удалён.
func prepareRestoreHost(t *testing.T, ctx context.Context, p Paths, app DesiredApp) {
	t.Helper()
	requireNoHostBindings(t, ctx, app)

	// Уборка сети регистрируется ПЕРВОЙ: t.Cleanup выполняется в обратном
	// порядке, а снять сеть можно только после стека.
	if exec.Command("docker", "network", "inspect", EdgeNetwork).Run() != nil {
		t.Cleanup(func() { removeEdgeNetworkIfUnused(t) })
	}
	t.Cleanup(func() {
		forceCleanup(t, p, app)
		if len(containersOnHost(t, app.Slug)) > 0 || len(volumesOnHost(t, app.Slug)) > 0 {
			removeProjectLeftovers(t, app.Slug)
		}
	})

	if len(containersOnHost(t, app.Slug)) > 0 || len(volumesOnHost(t, app.Slug)) > 0 {
		t.Logf("остатки прошлого прогона %s — убираю", app.Slug)
		removeProjectLeftovers(t, app.Slug)
		if c, v := containersOnHost(t, app.Slug), volumesOnHost(t, app.Slug); len(c) > 0 || len(v) > 0 {
			t.Fatalf("хост не чист после уборки: контейнеры %v, тома %v", c, v)
		}
	}

	if err := ensureEdgeNetwork(ctx); err != nil {
		t.Fatalf("сеть прокси: %v", err)
	}
}

// requireNoHostBindings — стек не занимает на хосте ничего общего с соседями:
// ни портов, ни фиксированных имён контейнеров, ни сети хоста. Прогон идёт рядом
// с чужими стеками, и совпадение сорвало бы их работу, а не наш тест.
//
// Модель снимается тем же compose, что поднимает стек, а не чтением YAML.
func requireNoHostBindings(t *testing.T, ctx context.Context, app DesiredApp) {
	t.Helper()
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(app.Compose), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte(renderEnv(app)), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := composeConfigJSON(ctx, dir, envPath)
	if err != nil {
		t.Fatalf("модель стека не снята: %v", err)
	}
	model, err := parseComposeModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	services, _ := model["services"].(map[string]any)
	for name, value := range services {
		service, _ := value.(map[string]any)
		for _, key := range []string{"ports", "container_name", "network_mode"} {
			if _, set := service[key]; set {
				t.Fatalf("сервис %s задаёт %s — прогон рядом с чужими стеками небезопасен", name, key)
			}
		}
	}
}

// removeProjectLeftovers снимает проект по имени, без файла описания, и тома
// по префиксу slug.
func removeProjectLeftovers(t *testing.T, slug string) {
	t.Helper()
	// Пустой каталог: compose не должен подхватить чужое описание стека из
	// текущего каталога.
	dir, err := os.MkdirTemp("", "tdrestore-down-")
	if err != nil {
		t.Logf("каталог для уборки не создан: %v", err)
		return
	}
	defer os.RemoveAll(dir)

	cmd := exec.Command("docker", "compose", "-p", slug, "down", "-v", "--remove-orphans")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Logf("docker compose -p %s down: %v: %s", slug, err, tail(string(out), 300))
	}
	if _, failed := removeAppVolumes(context.Background(), slug); len(failed) > 0 {
		t.Logf("остались тома: %v", failed)
	}
}

// removeEdgeNetworkIfUnused снимает сеть прокси, которую создал прогон, — если
// на неё не ссылается ни один контейнер, включая остановленные: сеть, снятая
// из-под остановленного контейнера, не даст ему запуститься.
func removeEdgeNetworkIfUnused(t *testing.T) {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-a", "-q", "--filter", "network="+EdgeNetwork).Output()
	if err != nil {
		t.Logf("сеть %s не снята: список контейнеров не получен: %v", EdgeNetwork, err)
		return
	}
	if users := strings.Fields(string(out)); len(users) > 0 {
		t.Logf("сеть %s не снята: на неё ссылаются контейнеры %v", EdgeNetwork, users)
		return
	}
	if out, err := exec.Command("docker", "network", "rm", EdgeNetwork).CombinedOutput(); err != nil {
		t.Logf("сеть %s не снята: %v: %s", EdgeNetwork, err, tail(string(out), 200))
	}
}

func applyForRestore(t *testing.T, ctx context.Context, p Paths, app DesiredApp) {
	t.Helper()
	results := Apply(ctx, p, []DesiredApp{app}, nil)
	if len(results) != 1 {
		t.Fatalf("результатов %d, ожидался 1", len(results))
	}
	if results[0].Status != "healthy" {
		t.Fatalf("стек не поднялся: %s, подробности: %v", results[0].Status, results[0].Detail)
	}
}

func backupForRestore(t *testing.T, ctx context.Context, p Paths, app DesiredApp) string {
	t.Helper()
	setDir, err := CreateBackup(ctx, p, app, app.BackupSpec)
	if err != nil {
		t.Fatalf("копия не снята: %v", err)
	}
	if setDir == "" {
		t.Fatal("CreateBackup не вернул каталог набора — копия не снималась")
	}
	return setDir
}

// execOnApp выполняет команду в сервисе стека из каталога приложения — тем же
// путём, что CreateBackup и RestoreBackup. stdout без stderr: вывод сравнивается.
func execOnApp(t *testing.T, ctx context.Context, p Paths, app DesiredApp, service string, args ...string) string {
	t.Helper()
	dir := p.appDir(app.Slug)
	out, err := dockerComposeParsed(ctx, dir, filepath.Join(dir, ".env"),
		append([]string{"exec", "-T", service}, args...)...)
	if err != nil {
		t.Fatalf("docker compose exec %s %v: %v", service, args, err)
	}
	return strings.TrimSpace(out)
}

// psqlOnApp — запрос тем пользователем, что в backup_spec: он же снимает дамп и
// вливает его обратно.
func psqlOnApp(t *testing.T, ctx context.Context, p Paths, app DesiredApp, pg PostgresBackup, sql string) string {
	t.Helper()
	return execOnApp(t, ctx, p, app, pg.Service,
		"psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", pg.User, "-d", pg.Database, "-At", "-c", sql)
}

// requireProbeRows сравнивает состав таблицы пробы целиком — «число:метки».
func requireProbeRows(t *testing.T, ctx context.Context, p Paths, app DesiredApp, pg PostgresBackup, want string) {
	t.Helper()
	got := psqlOnApp(t, ctx, p, app, pg,
		"SELECT count(*) || ':' || coalesce(string_agg(label, ',' ORDER BY label), '') FROM public.restore_probe")
	if got != want {
		t.Fatalf("в таблице пробы %q, ожидалось %q", got, want)
	}
}

func writeN8nMark(t *testing.T, ctx context.Context, p Paths, app DesiredApp, value string) {
	t.Helper()
	execOnApp(t, ctx, p, app, "app", "sh", "-c", "printf %s "+value+" > "+n8nRestoreMark)
}

func readN8nMark(t *testing.T, ctx context.Context, p Paths, app DesiredApp) string {
	t.Helper()
	return execOnApp(t, ctx, p, app, "app", "cat", n8nRestoreMark)
}

// requireStackRunning — флага восстановления нет, а стек работает и держится так
// же, как после выката. И после удачного восстановления, и после отказа.
func requireStackRunning(t *testing.T, ctx context.Context, p Paths, app DesiredApp) {
	t.Helper()
	if hasRestoreFlag(p, app.Slug) {
		t.Error("флаг восстановления остался")
	}
	if len(containersOnHost(t, app.Slug)) == 0 {
		t.Fatal("контейнеров проекта нет — стек не работает")
	}
	dir := p.appDir(app.Slug)
	if err := waitStable(ctx, dir, filepath.Join(dir, ".env"), app.ApplySpec.normalized()); err != nil {
		t.Errorf("стек не работает: %v", err)
	}
}

// projectContainerIDs — полные идентификаторы контейнеров проекта. `down` и
// следующий `up` пересоздают контейнеры, поэтому совпадение до и после значит,
// что стек не останавливали.
func projectContainerIDs(t *testing.T, slug string) []string {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-a", "-q", "--no-trunc",
		"--filter", "label=com.docker.compose.project="+slug).Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	ids := strings.Fields(string(out))
	slices.Sort(ids)
	return ids
}
