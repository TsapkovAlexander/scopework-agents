//go:build dockersmoke

package agent

// Прогон НАСТОЯЩИХ Apply и Cleanup против НАСТОЯЩЕГО Docker.
//
// Остальные тесты пакета проверяют чистые функции на выдуманных входах:
// filterAppVolumes получает список строк, staleDataRefusal — готовый набор
// томов. Это ловит ошибки в правилах и не ловит ошибки во взаимодействии с
// docker — а обе новые возможности состоят именно из него: одна СЧИТЫВАЕТ
// тома с хоста и отказывается разворачиваться, вторая их УДАЛЯЕТ.
//
// Здесь проверяется полный путь агента: запись файлов шаблона, сборка .env,
// подъём с ожиданием здоровья, отказ поверх чужих данных, снятие стека вместе
// с томами. Всё, кроме получения задания по сети.
//
// Собирается отдельным тегом и не участвует в обычном `go test ./...`: без
// docker-демона и без комплекта шаблона ему нечего делать.
//
//	GOOS=linux GOARCH=amd64 go test -c -tags dockersmoke -o /tmp/agent.test ./internal/agent
//	SMOKE_BUNDLE=/tmp/комплект /tmp/agent.test -test.v -test.run TestAgent
//
// Комплект (desired-app.json + файлы шаблона) готовит
// `scripts/smoke-deploy-template.ts --bundle-only`.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadSmokeApp(t *testing.T) DesiredApp {
	t.Helper()

	bundle := os.Getenv("SMOKE_BUNDLE")
	if bundle == "" {
		t.Skip("SMOKE_BUNDLE не задан — комплект шаблона не подготовлен")
	}

	raw, err := os.ReadFile(filepath.Join(bundle, "desired-app.json"))
	if err != nil {
		t.Fatalf("комплект не читается: %v", err)
	}

	var app DesiredApp
	if err := json.Unmarshal(raw, &app); err != nil {
		t.Fatalf("комплект не разбирается структурами агента: %v", err)
	}
	if app.Slug == "" || app.Compose == "" || len(app.Files) == 0 {
		t.Fatalf("комплект неполон: slug=%q, compose=%d байт, файлов %d",
			app.Slug, len(app.Compose), len(app.Files))
	}
	return app
}

// Состояние хоста, а не отчёт агента: отчёт может быть каким угодно, а тома
// либо есть, либо нет.
func volumesOnHost(t *testing.T, slug string) []string {
	t.Helper()
	out, err := exec.Command("docker", "volume", "ls", "--format", "{{.Name}}").Output()
	if err != nil {
		t.Fatalf("docker volume ls: %v", err)
	}
	return filterAppVolumes(strings.Split(strings.TrimSpace(string(out)), "\n"), slug)
}

func containersOnHost(t *testing.T, slug string) []string {
	t.Helper()
	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "label=com.docker.compose.project="+slug,
		"--format", "{{.Names}}").Output()
	if err != nil {
		t.Fatalf("docker ps: %v", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// Уборка обязана отработать при любом исходе: оставленный стек сломает
// следующий прогон ровно тем дефектом, который тест ищет.
func forceCleanup(t *testing.T, p Paths, app DesiredApp) {
	t.Helper()
	dir := p.appDir(app.Slug)
	if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
		cmd := exec.Command("docker", "compose", "--env-file", filepath.Join(dir, ".env"),
			"down", "-v", "--remove-orphans")
		cmd.Dir = dir
		_ = cmd.Run()
	}
	if _, failed := removeAppVolumes(context.Background(), app.Slug); len(failed) > 0 {
		t.Logf("остались тома: %v", failed)
	}
}

func TestAgentRaisesTemplateOnRealDocker(t *testing.T) {
	app := loadSmokeApp(t)
	app.FirstRelease = true

	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	t.Cleanup(func() { forceCleanup(t, p, app) })

	if left := volumesOnHost(t, app.Slug); len(left) > 0 {
		t.Fatalf("хост не чист, тома с прошлого прогона: %v", left)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	if err := ensureEdgeNetwork(ctx); err != nil {
		t.Fatalf("сеть прокси: %v", err)
	}

	phases := map[string]bool{}
	results := Apply(ctx, p, []DesiredApp{app}, func(_, phase, _ string) { phases[phase] = true })

	if len(results) != 1 {
		t.Fatalf("результатов %d, ожидался 1", len(results))
	}
	if results[0].Status != "healthy" {
		t.Fatalf("стек не поднялся: %s, подробности: %v", results[0].Status, results[0].Detail)
	}

	// Отчёт о ходе — часть обещания пользователю: без него страница снова
	// показывает застывшее «Разворачивается» на всё время подъёма.
	for _, want := range []string{"up", "stabilize"} {
		if !phases[want] {
			t.Errorf("фаза %q ни разу не отчиталась", want)
		}
	}

	// Файлы шаблона доехали на хост и попали внутрь контейнеров: без них база
	// поднимается без служебных ролей, а шлюз — без маршрутов.
	dir := p.appDir(app.Slug)
	for _, f := range app.Files {
		if _, err := os.Stat(filepath.Join(dir, f.Path)); err != nil {
			t.Errorf("файл шаблона %s не записан: %v", f.Path, err)
		}
	}

	if got := len(containersOnHost(t, app.Slug)); got == 0 {
		t.Fatal("контейнеров проекта нет — стек объявлен здоровым впустую")
	}
	if len(volumesOnHost(t, app.Slug)) == 0 {
		t.Fatal("тома не созданы — данным стека негде лежать")
	}
}

// Ключевой сценарий: приложение удалили, тома остались, создали новое с тем же
// идентификатором. Раньше стек поднимался поверх ЧУЖОЙ базы со старыми
// паролями и выглядел почти работающим.
func TestAgentRefusesToDeployOverStaleData(t *testing.T) {
	app := loadSmokeApp(t)
	app.FirstRelease = true

	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	t.Cleanup(func() { forceCleanup(t, p, app) })

	// Данные «прошлого приложения»: создаются напрямую, как они и остаются
	// после удаления без отметки.
	stale := app.Slug + "_db-data"
	if out, err := exec.Command("docker", "volume", "create", stale).CombinedOutput(); err != nil {
		t.Fatalf("не удалось создать том: %v: %s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	results := Apply(ctx, p, []DesiredApp{app}, nil)
	if len(results) != 1 {
		t.Fatalf("результатов %d, ожидался 1", len(results))
	}
	if results[0].Status != "failed" {
		t.Fatalf("агент развернул стек поверх чужих данных: %s", results[0].Status)
	}

	// Текст отказа читает человек, у которого только что «ничего не
	// развернулось». Он обязан называть и причину, и оба выхода: удалить
	// данные или взять другое имя.
	msg, _ := results[0].Detail["error"].(string)
	for _, want := range []string{app.Slug, stale, "«удалить данные»", "другой идентификатор"} {
		if !strings.Contains(msg, want) {
			t.Errorf("в отказе нет %q:\n%s", want, msg)
		}
	}

	// И главное: отказ должен быть ДО того, как что-либо тронуто.
	if got := containersOnHost(t, app.Slug); len(got) > 0 {
		t.Errorf("после отказа остались контейнеры: %v", got)
	}
}

// Обратная сторона: отметка «удалить данные» обязана снести именно тома этого
// приложения и не тронуть соседние.
func TestAgentPurgesDataOnlyForItsOwnApp(t *testing.T) {
	app := loadSmokeApp(t)
	app.FirstRelease = true

	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	t.Cleanup(func() { forceCleanup(t, p, app) })

	neighbour := app.Slug + "2_db-data"
	if out, err := exec.Command("docker", "volume", "create", neighbour).CombinedOutput(); err != nil {
		t.Fatalf("не удалось создать том соседа: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "volume", "rm", "-f", neighbour).Run() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	if err := ensureEdgeNetwork(ctx); err != nil {
		t.Fatalf("сеть прокси: %v", err)
	}
	if r := Apply(ctx, p, []DesiredApp{app}, nil); len(r) != 1 || r[0].Status != "healthy" {
		t.Fatalf("подготовительный подъём не удался: %+v", r)
	}
	if len(volumesOnHost(t, app.Slug)) == 0 {
		t.Fatal("после подъёма нет томов — удалять нечего")
	}

	absent := app
	absent.Desired = "absent"
	absent.PurgeData = true
	Cleanup(ctx, p, []DesiredApp{absent})

	if left := volumesOnHost(t, app.Slug); len(left) > 0 {
		t.Errorf("тома пережили удаление с отметкой: %v", left)
	}
	if got := containersOnHost(t, app.Slug); len(got) > 0 {
		t.Errorf("контейнеры пережили удаление: %v", got)
	}

	// Сосед отличается от нашего идентификатора одним символом — ровно тот
	// случай, на котором сравнение по префиксу без разделителя снесло бы
	// данные чужого приложения.
	out, err := exec.Command("docker", "volume", "inspect", neighbour).CombinedOutput()
	if err != nil {
		t.Errorf("удалён том соседнего приложения %s: %v: %s", neighbour, err, out)
	}
}

// Воспроизведение дефекта «второй выкат поднимает старый образ».
//
// Комплект шаблона здесь не нужен и не запрашивается: дефект живёт не в
// желаемом состоянии, а в семантике самого compose — `up` собирает образ,
// только если его нет. Поэтому берётся минимальный стек со `build:` и без
// `image:`, ровно как его пишет writeSyntheticCompose для сборки из Dockerfile.
//
// Тест утверждает обе половины:
//
//  1. один `up` после изменения исходника образ НЕ меняет — это и есть дефект,
//     из-за которого прод месяцами работал на коде первого выката;
//  2. `buildImages` перед `up` его меняет — это исправление;
//  3. dropUnusedImages убирает вытесненный слой и не трогает ничего больше.
func TestRebuildProducesNewImageOnRealDocker(t *testing.T) {
	dir := t.TempDir()
	project := "tracedocs-build-smoke"

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("APP_SLUG="+project+"\n"), 0o600); err != nil {
		t.Fatalf("не удалось записать .env: %v", err)
	}

	// `build:` без `image:` — та же форма, что у синтетического compose.
	// Долгоживущая команда нужна, чтобы контейнер оставался на месте:
	// `docker compose images` читает состояние контейнеров проекта.
	compose := "name: ${APP_SLUG}\n" +
		"services:\n" +
		"  app:\n" +
		"    build:\n      context: .\n      dockerfile: Dockerfile\n" +
		"    command: [\"sleep\", \"600\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o640); err != nil {
		t.Fatalf("не удалось записать compose: %v", err)
	}

	writeDockerfile := func(marker string) {
		t.Helper()
		body := "FROM busybox:1.36\nRUN echo " + marker + " > /marker\n"
		if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(body), 0o640); err != nil {
			t.Fatalf("не удалось записать Dockerfile: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Cleanup(func() {
		down := exec.Command("docker", "compose", "--env-file", envPath, "down", "-v", "--remove-orphans")
		down.Dir = dir
		_ = down.Run()
	})

	up := func() {
		t.Helper()
		if out, err := dockerComposeEnv(ctx, dir, envPath, "up", "-d"); err != nil {
			t.Fatalf("docker compose up: %v: %s", err, out)
		}
	}

	// Пути агента buildImages нужны только для подсказки про лимит реестра:
	// в пустом каталоге состояния отметки установщика нет, и подсказка молчит.
	p := Paths{StateDir: t.TempDir()}

	writeDockerfile("v1")
	if err := buildImages(ctx, p, dir, envPath, nil); err != nil {
		t.Fatalf("первая сборка: %v", err)
	}
	up()

	first := projectImageIDs(ctx, dir, envPath)
	if len(first) != 1 {
		t.Fatalf("после первого подъёма образов %d, ожидался 1: %v", len(first), first)
	}

	// Половина первая: исходник изменился, собран не был — образ прежний.
	writeDockerfile("v2")
	up()

	if stale := projectImageIDs(ctx, dir, envPath); len(stale) != 1 || stale[0] != first[0] {
		t.Fatalf("ожидался прежний образ %v (это и есть воспроизводимый дефект), получено %v",
			first, stale)
	}

	// Половина вторая: сборка перед подъёмом даёт новый образ.
	if err := buildImages(ctx, p, dir, envPath, nil); err != nil {
		t.Fatalf("пересборка: %v", err)
	}
	up()

	second := projectImageIDs(ctx, dir, envPath)
	if len(second) != 1 {
		t.Fatalf("после пересборки образов %d, ожидался 1: %v", len(second), second)
	}
	if second[0] == first[0] {
		t.Fatalf("образ не изменился после правки Dockerfile: %s", second[0])
	}

	// Половина третья: вытесненный слой убран, действующий на месте.
	dropUnusedImages(ctx, first, second)

	if out, err := exec.Command("docker", "image", "inspect", first[0]).CombinedOutput(); err == nil {
		t.Errorf("вытесненный образ %s остался на диске: %s", first[0], out)
	}
	if out, err := exec.Command("docker", "image", "inspect", second[0]).CombinedOutput(); err != nil {
		t.Errorf("действующий образ %s удалён по ошибке: %v: %s", second[0], err, out)
	}
}
