package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Сверка дрейфа после восстановления из копии (ADR-0078): файлы, которые
// вернул набор, — запись агента, а не чужая правка. Но только те, что
// действительно вернулись: оборванное восстановление не вправе спрятать
// ручную правку за хешем копии.

func writeAppFile(t *testing.T, p Paths, slug, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.appDir(slug), name), []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

// restoreDriftApp — приложение из writeRestoreFixture с базовой линией по
// файлам, которые фикстура положила в каталог приложения.
func restoreDriftApp(t *testing.T, p Paths) DesiredApp {
	t.Helper()
	app := DesiredApp{Slug: "n8n", Desired: "present", ReleaseID: "release-1", ApplySpec: ApplySpec{StableChecks: 1}}
	dir := p.appDir(app.Slug)
	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{app.Slug: {
		ReleaseID:     app.ReleaseID,
		ConfigHash:    configHash(app),
		Status:        "healthy",
		ComposeSha256: readHash(t, filepath.Join(dir, "docker-compose.yml")),
		EnvSha256:     readHash(t, filepath.Join(dir, ".env")),
	}}}); err != nil {
		t.Fatal(err)
	}
	return app
}

// Откат неудачного обновления вернул прежний .env из копии: сверка обязана
// видеть его своим, а не правкой поверх записанного выкатом.
func TestDriftRollbackAfterFailedApplyIsNotForeign(t *testing.T) {
	installFakeDocker(t, "")
	p := testPaths(t)
	app := restoreFlagApplyApp("services: {}\n")
	app.Env = map[string]string{"K": "v"}
	if r := Apply(context.Background(), p, []DesiredApp{app}, nil); len(r) != 1 || r[0].Status != "healthy" {
		t.Fatalf("первый выкат: %+v", r)
	}
	envPath := filepath.Join(p.appDir(app.Slug), ".env")
	before := readHash(t, envPath)

	// Пустой compose роняет выкат после записи нового .env — откат обязан
	// вернуть прежний.
	next := restoreFlagApplyApp("")
	next.ReleaseID = "release-3"
	next.Env = map[string]string{"K": "changed"}
	next.NeedsBackup = true
	next.BackupSpec = BackupSpec{Volumes: []string{"app-data"}}
	r := Apply(context.Background(), p, []DesiredApp{next}, nil)
	if len(r) != 1 || r[0].Status != "failed" || r[0].Detail["rolled_back"] != true {
		t.Fatalf("выкат не упал с откатом: %+v", r)
	}
	if readHash(t, envPath) != before {
		t.Fatal("откат не вернул .env из копии — проверять базовую линию не на чем")
	}

	if rec := appliedRecord(t, p, app.Slug); rec.EnvSha256 != before {
		t.Errorf("базовая линия .env %q, а откат вернул %q", rec.EnvSha256, before)
	}
	records, _ := observe(t, p, []DesiredApp{next})
	mustDrift(t, records, "env", app.Slug, "match", "")
	mustDrift(t, records, "compose", app.Slug, "match", "")
}

// Восстановление по кнопке владельца: вернувшийся из набора compose — запись
// агента. Правка после восстановления — снова чужая.
func TestDriftOwnerRestoreAdoptsRestoredFiles(t *testing.T) {
	installFakeDocker(t, "")
	p := testPaths(t)
	writeRestoreFixture(t, p, "n8n", nil)
	app := restoreDriftApp(t, p)
	composePath := filepath.Join(p.appDir(app.Slug), "docker-compose.yml")
	fromSet := readHash(t, filepath.Join(p.backupsDir(app.Slug), restoreTestSet, "docker-compose.yml"))

	got, err := runRestoreTask(t, p, []DesiredApp{app}, restoreTestSet)
	if err != nil || got.Error != "" {
		t.Fatalf("восстановление упало: %v (отчёт: %q)", err, got.Error)
	}
	if readHash(t, composePath) != fromSet {
		t.Fatal("восстановление не вернуло compose из набора — проверять базовую линию не на чем")
	}

	if rec := appliedRecord(t, p, app.Slug); rec.ComposeSha256 != fromSet {
		t.Errorf("базовая линия compose %q, а из набора вернулся %q", rec.ComposeSha256, fromSet)
	}
	records, commit := observe(t, p, []DesiredApp{app})
	mustDrift(t, records, "compose", app.Slug, "match", "")
	mustDrift(t, records, "env", app.Slug, "match", "")
	if err := commit(); err != nil {
		t.Fatal(err)
	}

	edited := "# описание из копии\nservices: {}\n    privileged: true\n"
	writeAppFile(t, p, app.Slug, "docker-compose.yml", edited)
	records, _ = observe(t, p, []DesiredApp{app})
	r := mustDrift(t, records, "compose", app.Slug, "mismatch", "foreign")
	if r.DiskSha != sha256Hex(edited) || r.ExpectedSha != fromSet {
		t.Fatalf("хеши правки после восстановления %q/%q", r.DiskSha, r.ExpectedSha)
	}
}

// Восстановление оборвалось до записи файлов: на диске ручная правка, и она
// обязана остаться видна. Базовая линия — прежняя, а не хеш копии и не хеш
// того, что лежит на диске.
func TestDriftInterruptedRestoreKeepsForeignEdit(t *testing.T) {
	calls := installFakeDocker(t, "down")
	p := testPaths(t)
	writeRestoreFixture(t, p, "n8n", nil)
	app := restoreDriftApp(t, p)
	baseline := appliedRecord(t, p, app.Slug)

	edited := "# описание текущего релиза\nservices: {}\n    privileged: true\n"
	writeAppFile(t, p, app.Slug, "docker-compose.yml", edited)

	got, _ := runRestoreTask(t, p, []DesiredApp{app}, restoreTestSet)
	if got.Error == "" {
		t.Fatalf("поддельный отказ docker не сорвал восстановление:\n%s", describeCalls(calls()))
	}
	if readHash(t, filepath.Join(p.appDir(app.Slug), "docker-compose.yml")) != sha256Hex(edited) {
		t.Fatal("восстановление дошло до записи compose — обрыв не тот, что проверяется")
	}

	if rec := appliedRecord(t, p, app.Slug); rec.ComposeSha256 != baseline.ComposeSha256 {
		t.Errorf("оборванное восстановление сдвинуло базовую линию compose: было %q, стало %q",
			baseline.ComposeSha256, rec.ComposeSha256)
	}
	records, _ := observe(t, p, []DesiredApp{app})
	r := mustDrift(t, records, "compose", app.Slug, "mismatch", "foreign")
	if r.DiskSha != sha256Hex(edited) || r.ExpectedSha != baseline.ComposeSha256 {
		t.Fatalf("хеши правки %q/%q, ожидалось %q/%q", r.DiskSha, r.ExpectedSha, sha256Hex(edited), baseline.ComposeSha256)
	}
}
