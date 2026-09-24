package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Сверка дрейфа (ADR-0078): базовая линия, статусы, толкование и то, что
// уходит наружу.

var driftNow = time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)

const driftTestEpoch = "0123456789abcdef0123456789abcdef"

func driftCatalogApp() DesiredApp {
	return DesiredApp{
		Slug:      "shop-front",
		Desired:   "present",
		ReleaseID: "release-1",
		Compose:   "services:\n  app:\n    image: nginx\n",
		Env:       map[string]string{"SHOP_KEY": "shop-value"},
	}
}

func driftGitApp(domain string) DesiredApp {
	return DesiredApp{
		Slug:       "repo-app",
		Desired:    "present",
		ReleaseID:  "release-1",
		SourceType: "git",
		GitRepo:    "https://example.com/repo.git",
		GitBranch:  "main",
		Domain:     domain,
		Env:        map[string]string{"REPO_KEY": "repo-value"},
	}
}

// deployFiles кладёт файлы приложения так, как их пишет applyOne, и отметку
// с базовой линией.
func deployFiles(t *testing.T, p Paths, app DesiredApp, compose string, withHashes bool) {
	t.Helper()
	dir := p.appDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	env := renderEnv(app)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o640); err != nil {
		t.Fatal(err)
	}
	rec := AppliedRecord{ReleaseID: app.ReleaseID, ConfigHash: configHash(app), Status: "healthy"}
	if withHashes {
		rec.ComposeSha256 = sha256Hex(compose)
		rec.EnvSha256 = sha256Hex(env)
	}
	state := LoadApplied(p)
	state.Apps[app.Slug] = rec
	if err := SaveApplied(p, state); err != nil {
		t.Fatal(err)
	}
}

func observe(t *testing.T, p Paths, apps []DesiredApp) ([]DriftRecord, func() error) {
	t.Helper()
	records, commit, err := ObserveDrift(p, apps, ProxyOptions{}, driftNow)
	if err != nil {
		t.Fatalf("сверка упала: %v", err)
	}
	return records, commit
}

func findDrift(records []DriftRecord, object, slug string) *DriftRecord {
	for i := range records {
		if records[i].Object == object && records[i].Slug == slug {
			return &records[i]
		}
	}
	return nil
}

func mustDrift(t *testing.T, records []DriftRecord, object, slug, status, disposition string) DriftRecord {
	t.Helper()
	r := findDrift(records, object, slug)
	if r == nil {
		t.Fatalf("нет записи %s/%s среди %+v", object, slug, records)
	}
	if r.Status != status || r.Disposition != disposition {
		t.Fatalf("%s/%s: статус %q/%q, ожидалось %q/%q", object, slug, r.Status, r.Disposition, status, disposition)
	}
	return *r
}

func testPaths(t *testing.T) Paths {
	return Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
}

// --------------------------------------------------------------------------
// A4: базовая линия в applied.json
// --------------------------------------------------------------------------

// applied.json прежней версии агента читается, а пустые хеши не пишутся вовсе.
func TestAppliedRecordReadsLegacyWithoutHashes(t *testing.T) {
	p := testPaths(t)
	legacy := `{"apps":{"shop-front":{"release_id":"release-1","config_hash":"abc","status":"healthy","last_attempt":"2026-09-01T00:00:00Z"}}}`
	if err := os.WriteFile(appliedPath(p), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, ok := LoadApplied(p).Apps["shop-front"]
	if !ok || rec.ReleaseID != "release-1" || rec.ComposeSha256 != "" || rec.EnvSha256 != "" {
		t.Fatalf("прежний applied.json прочитан неверно: %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "sha256") {
		t.Fatalf("пустые хеши попали в файл: %s", raw)
	}
}

func appliedRecord(t *testing.T, p Paths, slug string) AppliedRecord {
	t.Helper()
	rec, ok := LoadApplied(p).Apps[slug]
	if !ok {
		t.Fatalf("нет отметки %s", slug)
	}
	return rec
}

func readHash(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Hex(string(raw))
}

// Хеши — ровно тех байтов, что агент положил на диск.
func TestApplyRecordsWrittenHashes(t *testing.T) {
	installFakeDocker(t, "")
	p := testPaths(t)
	app := restoreFlagApplyApp("services: {}\n")
	app.Env = map[string]string{"K": "v"}

	if r := Apply(context.Background(), p, []DesiredApp{app}, nil); len(r) != 1 || r[0].Status != "healthy" {
		t.Fatalf("выкат не дошёл до healthy: %+v", r)
	}
	rec := appliedRecord(t, p, app.Slug)
	if want := readHash(t, filepath.Join(p.appDir(app.Slug), "docker-compose.yml")); rec.ComposeSha256 != want {
		t.Errorf("compose_sha256 %q, на диске %q", rec.ComposeSha256, want)
	}
	if want := readHash(t, filepath.Join(p.appDir(app.Slug), ".env")); rec.EnvSha256 != want {
		t.Errorf("env_sha256 %q, на диске %q", rec.EnvSha256, want)
	}
}

// Неудачный выкат переносит хеш того, чего не переписал, и обновляет хеш
// того, что переписал.
func TestApplyFailureKeepsBaselineOfUntouchedFiles(t *testing.T) {
	installFakeDocker(t, "")
	p := testPaths(t)
	app := restoreFlagApplyApp("services: {}\n")
	if r := Apply(context.Background(), p, []DesiredApp{app}, nil); len(r) != 1 || r[0].Status != "healthy" {
		t.Fatalf("первый выкат: %+v", r)
	}
	before := appliedRecord(t, p, app.Slug)

	// Пустой compose: .env уже переписан, описание стека — нет.
	next := restoreFlagApplyApp("")
	next.ReleaseID = "release-3"
	next.Env = map[string]string{"K": "changed"}
	if r := Apply(context.Background(), p, []DesiredApp{next}, nil); len(r) != 1 || r[0].Status != "failed" {
		t.Fatalf("выкат не упал: %+v", r)
	}
	after := appliedRecord(t, p, app.Slug)
	if after.ComposeSha256 != before.ComposeSha256 || after.ComposeSha256 == "" {
		t.Errorf("хеш compose не перенесён: было %q, стало %q", before.ComposeSha256, after.ComposeSha256)
	}
	if want := readHash(t, filepath.Join(p.appDir(app.Slug), ".env")); after.EnvSha256 != want {
		t.Errorf("хеш переписанного .env %q, на диске %q", after.EnvSha256, want)
	}
}

// Ветка отказа до записи файлов переносит прежние хеши, а не обнуляет.
func TestApplyRefusalCarriesHashes(t *testing.T) {
	installFakeDocker(t, "")
	p := testPaths(t)
	app := restoreFlagApplyApp("services: {}\n")
	if r := Apply(context.Background(), p, []DesiredApp{app}, nil); len(r) != 1 || r[0].Status != "healthy" {
		t.Fatalf("первый выкат: %+v", r)
	}
	before := appliedRecord(t, p, app.Slug)

	// Негодное задание на копию — отказ раньше любой записи файлов.
	next := restoreFlagApplyApp("services: {}\n")
	next.ReleaseID = "release-3"
	next.NeedsBackup = true
	next.BackupSpec = BackupSpec{Volumes: []string{"../bad"}}
	if r := Apply(context.Background(), p, []DesiredApp{next}, nil); len(r) != 1 || r[0].Status != "failed" {
		t.Fatalf("выкат не упал: %+v", r)
	}
	after := appliedRecord(t, p, app.Slug)
	if after.ComposeSha256 != before.ComposeSha256 || after.EnvSha256 != before.EnvSha256 || after.EnvSha256 == "" {
		t.Errorf("отказ обнулил базовую линию: было %+v, стало %+v", before, after)
	}
}

// --------------------------------------------------------------------------
// A5: сверка
// --------------------------------------------------------------------------

// Смена домена у git-приложения не даёт ложного дрейфа .env ни с базовой
// линией, отрисованной из желаемого, ни с записанной.
func TestDriftGitDomainChangeIsNotMismatch(t *testing.T) {
	for _, withHashes := range []bool{false, true} {
		p := testPaths(t)
		old := driftGitApp("old.example.com")
		deployFiles(t, p, old, "services: {}\n", withHashes)

		records, _ := observe(t, p, []DesiredApp{driftGitApp("new.example.com")})
		mustDrift(t, records, "env", "repo-app", "match", "")
		if withHashes {
			mustDrift(t, records, "compose", "repo-app", "match", "")
		} else {
			// Compose из репозитория без клона не отрисовать — «нет данных».
			mustDrift(t, records, "compose", "repo-app", "no_baseline", "")
		}
	}
}

// Прежний applied.json у не-git приложения: базовая линия отрисовывается из
// желаемого, пока отпечаток совпадает, и закрепляется после фиксации.
func TestDriftLegacyCatalogBaseline(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	deployFiles(t, p, app, app.Compose, false)

	records, commit := observe(t, p, []DesiredApp{app})
	mustDrift(t, records, "compose", app.Slug, "match", "")
	mustDrift(t, records, "env", app.Slug, "match", "")
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	rec := appliedRecord(t, p, app.Slug)
	if rec.ComposeSha256 != sha256Hex(app.Compose) || rec.EnvSha256 != sha256Hex(renderEnv(app)) {
		t.Fatalf("базовая линия не закреплена: %+v", rec)
	}

	// Желаемое сменилось раньше, чем закрепили: отрисовать применённое не из
	// чего.
	q := testPaths(t)
	deployFiles(t, q, app, app.Compose, false)
	changed := driftCatalogApp()
	changed.Compose = "services: {}\n"
	records, _ = observe(t, q, []DesiredApp{changed})
	mustDrift(t, records, "compose", app.Slug, "no_baseline", "")
	mustDrift(t, records, "env", app.Slug, "no_baseline", "")
}

func TestDriftComposeEditIsForeign(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	deployFiles(t, p, app, app.Compose, true)
	edited := app.Compose + "    privileged: true\n"
	if err := os.WriteFile(filepath.Join(p.appDir(app.Slug), "docker-compose.yml"), []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	records, _ := observe(t, p, []DesiredApp{app})
	r := mustDrift(t, records, "compose", app.Slug, "mismatch", "foreign")
	if r.DiskSha != sha256Hex(edited) || r.ExpectedSha != sha256Hex(app.Compose) {
		t.Fatalf("хеши записи %q/%q", r.DiskSha, r.ExpectedSha)
	}
	mustDrift(t, records, "env", app.Slug, "match", "")
}

func TestDriftEditOverPending(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	deployFiles(t, p, app, app.Compose, true)
	if err := os.WriteFile(filepath.Join(p.appDir(app.Slug), "docker-compose.yml"), []byte("services: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	pending := driftCatalogApp()
	pending.ReleaseID = "release-2"
	records, _ := observe(t, p, []DesiredApp{pending})
	mustDrift(t, records, "compose", app.Slug, "mismatch", "foreign_over_pending")
	// Диск совпал с применённым, а желаемое ушло вперёд — наше в пути.
	mustDrift(t, records, "env", app.Slug, "match", "in_transit")
}

func TestDriftMissingAndUnreadable(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	deployFiles(t, p, app, app.Compose, true)
	dir := p.appDir(app.Slug)
	if err := os.Remove(filepath.Join(dir, "docker-compose.yml")); err != nil {
		t.Fatal(err)
	}
	// Каталог на месте файла не читается и под root — chmod root не остановил бы.
	if err := os.Remove(filepath.Join(dir, ".env")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".env"), 0o700); err != nil {
		t.Fatal(err)
	}

	records, _ := observe(t, p, []DesiredApp{app})
	r := mustDrift(t, records, "compose", app.Slug, "missing", "foreign")
	if r.DiskSha != "" || r.ExpectedSha != sha256Hex(app.Compose) {
		t.Fatalf("хеши отсутствующего файла %q/%q", r.DiskSha, r.ExpectedSha)
	}
	mustDrift(t, records, "env", app.Slug, "unreadable", "")
}

// Событие — на переходе статуса и при первом наблюдении; без фиксации
// последнее известное не сдвигается.
func TestDriftEventsOnlyOnTransition(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	apps := []DesiredApp{app}
	deployFiles(t, p, app, app.Compose, true)

	first, commit := observe(t, p, apps)
	if len(first) != 2 {
		t.Fatalf("первое наблюдение: %+v", first)
	}
	// Не зафиксировали — повтор того же события.
	if again, _ := observe(t, p, apps); len(again) != 2 {
		t.Fatalf("без фиксации событие потерялось: %+v", again)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if quiet, _ := observe(t, p, apps); len(quiet) != 0 {
		t.Fatalf("без смены статуса событие повторилось: %+v", quiet)
	}

	if err := os.WriteFile(filepath.Join(p.appDir(app.Slug), "docker-compose.yml"), []byte("services: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	changed, commit := observe(t, p, apps)
	if len(changed) != 1 {
		t.Fatalf("переход статуса: %+v", changed)
	}
	mustDrift(t, changed, "compose", app.Slug, "mismatch", "foreign")
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if quiet, _ := observe(t, p, apps); len(quiet) != 0 {
		t.Fatalf("mismatch повторился: %+v", quiet)
	}
}

// Снятое приложение забывается без события, а вернувшееся — снова первое
// наблюдение.
func TestDriftForgetsRemovedApp(t *testing.T) {
	p := testPaths(t)
	app := driftCatalogApp()
	deployFiles(t, p, app, app.Compose, true)
	_, commit := observe(t, p, []DesiredApp{app})
	if err := commit(); err != nil {
		t.Fatal(err)
	}

	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{}}); err != nil {
		t.Fatal(err)
	}
	records, commit := observe(t, p, nil)
	if len(records) != 0 {
		t.Fatalf("снятие приложения дало событие: %+v", records)
	}
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(p.StateDir, "drift-state.json"))
	if strings.Contains(string(raw), app.Slug) {
		t.Fatalf("снятое приложение осталось в drift-state.json: %s", raw)
	}

	deployFiles(t, p, app, app.Compose, true)
	if records, _ := observe(t, p, []DesiredApp{app}); len(records) != 2 {
		t.Fatalf("вернувшееся приложение без первого наблюдения: %+v", records)
	}
}

// Наружу по .env не уходит ничего, кроме факта: ни хешей, ни имён ключей, ни
// значений. Проверяются байты секции так, как они уедут, и файл очереди.
func TestDriftEnvLeaksNothingInSerializedReport(t *testing.T) {
	const key, value = "LEAKCHECK_KEY_NAME", "leakcheck-value-7f3a"
	p := testPaths(t)
	app := driftCatalogApp()
	app.Env = map[string]string{key: value}
	deployFiles(t, p, app, app.Compose, true)

	envPath := filepath.Join(p.appDir(app.Slug), ".env")
	expected, _ := os.ReadFile(envPath)
	edited := string(expected) + key + "_2='" + value + "-2'\n"
	if err := os.WriteFile(envPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	records, _ := observe(t, p, []DesiredApp{app})
	mustDrift(t, records, "env", app.Slug, "mismatch", "foreign")

	queue := LoadReportQueue(p)
	if err := queue.Enqueue(driftTestEpoch, 1, records); err != nil {
		t.Fatal(err)
	}
	section := queue.Section(ReportNumber{Epoch: driftTestEpoch, Seq: 1})
	raw, err := json.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	queueFile, _ := os.ReadFile(p.reportQueuePath())

	for name, body := range map[string]string{"секция": string(raw), "очередь": string(queueFile)} {
		for _, secret := range []string{key, value, sha256Hex(string(expected)), sha256Hex(edited)} {
			if strings.Contains(body, secret) {
				t.Errorf("%s содержит %q:\n%s", name, secret, body)
			}
		}
	}

	var decoded struct {
		Drift []map[string]any `json:"drift"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	sawEnv := false
	for _, item := range decoded.Drift {
		if item["object"] != "env" {
			continue
		}
		sawEnv = true
		if _, ok := item["diskSha"]; ok {
			t.Errorf("у env есть diskSha: %v", item)
		}
		if _, ok := item["expectedSha"]; ok {
			t.Errorf("у env есть expectedSha: %v", item)
		}
	}
	if !sawEnv {
		t.Fatalf("запись env не доехала до секции: %s", raw)
	}
}

// --------------------------------------------------------------------------
// A6: Caddyfile, вариант (а)
// --------------------------------------------------------------------------

// installFakeSS подменяет ss пустым ответом: на машине прогона порты 80/443
// может держать что угодно, и прокси не дошёл бы до записи отметок.
func installFakeSS(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ss"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func reloadCalls(calls []fakeDockerCall) int {
	n := 0
	for _, c := range calls {
		for _, a := range c.Args {
			if a == "reload" {
				n++
				break
			}
		}
	}
	return n
}

// Ручная правка Caddyfile видна сверкой до перезаписи; дальше всё как было:
// файл перезаписан, reload — только при смене желаемого.
func TestDriftCaddyfileEditReportedWithoutForcedReload(t *testing.T) {
	calls := installFakeDocker(t, "")
	installFakeSS(t)
	p := testPaths(t)
	apps := []DesiredApp{{Slug: "shop-front", Desired: "present", Domain: "shop.example.com", InternalPort: 80}}
	ctx := context.Background()

	if err := EnsureProxy(ctx, p, apps, ProxyOptions{}); err != nil {
		t.Fatalf("прокси: %v", err)
	}
	if n := reloadCalls(calls()); n != 1 {
		t.Fatalf("первая запись: reload %d раз", n)
	}
	written := renderCaddyfile(apps, ProxyOptions{})
	marker, err := os.ReadFile(filepath.Join(p.StateDir, "proxy-written.sha256"))
	if err != nil || string(marker) != sha256Hex(written) {
		t.Fatalf("отметка записанного %q, %v", marker, err)
	}

	caddyfile := filepath.Join(p.proxyDir(), "conf", "Caddyfile")
	edited := written + "\nhandmade.example.com {\n\trespond 200\n}\n"
	if err := os.WriteFile(caddyfile, []byte(edited), 0o640); err != nil {
		t.Fatal(err)
	}

	records, _ := observe(t, p, apps)
	r := mustDrift(t, records, "caddyfile", "", "mismatch", "foreign")
	if r.DiskSha != sha256Hex(edited) || r.ExpectedSha != sha256Hex(written) {
		t.Fatalf("хеши Caddyfile %q/%q", r.DiskSha, r.ExpectedSha)
	}

	if err := EnsureProxy(ctx, p, apps, ProxyOptions{}); err != nil {
		t.Fatalf("прокси повторно: %v", err)
	}
	if n := reloadCalls(calls()); n != 1 {
		t.Fatalf("желаемое не менялось, а reload вызван: всего %d", n)
	}
	if got := readHash(t, caddyfile); got != sha256Hex(written) {
		t.Fatal("правленый Caddyfile не перезаписан")
	}
	records, _ = observe(t, p, apps)
	mustDrift(t, records, "caddyfile", "", "match", "")
}
