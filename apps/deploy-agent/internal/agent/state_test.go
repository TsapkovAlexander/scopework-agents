package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sampleApp() DesiredApp {
	return DesiredApp{
		Slug:      "n8n",
		Domain:    "n8n.example.com",
		ReleaseID: "rel-1",
		Compose:   "services: {}",
		Env:       map[string]string{"TZ": "UTC"},
		Desired:   "present",
	}
}

// Главное, ради чего отметки заводились: уже применённое не трогаем.
// Без этого агент поднимал бы все стеки заново каждую минуту.
func TestAppliedSkipsUnchanged(t *testing.T) {
	app := sampleApp()
	rec := AppliedRecord{
		ReleaseID:  app.ReleaseID,
		ConfigHash: configHash(app),
		Status:     "healthy",
	}

	should, reason := needsApply(rec, true, app, time.Now(), false)
	if should {
		t.Fatalf("неизменившееся приложение применяется заново: %s", reason)
	}
}

func TestAppliedDetectsNewRelease(t *testing.T) {
	app := sampleApp()
	rec := AppliedRecord{
		ReleaseID:  "rel-0",
		ConfigHash: configHash(app),
		Status:     "healthy",
	}

	should, _ := needsApply(rec, true, app, time.Now(), false)
	if !should {
		t.Fatal("новый релиз не подхвачен")
	}
}

// Релиз может остаться тем же, а переменные смениться — по одному
// идентификатору релиза это не поймать.
func TestAppliedDetectsChangedVars(t *testing.T) {
	app := sampleApp()
	rec := AppliedRecord{
		ReleaseID:  app.ReleaseID,
		ConfigHash: configHash(app),
		Status:     "healthy",
	}

	changed := sampleApp()
	changed.Env = map[string]string{"TZ": "Europe/Moscow"}

	should, _ := needsApply(rec, true, changed, time.Now(), false)
	if !should {
		t.Fatal("смена переменных не подхвачена")
	}
}

// Смена домена меняет .env, а значит и конфиг прокси — переприменить нужно.
func TestAppliedDetectsChangedDomain(t *testing.T) {
	app := sampleApp()
	rec := AppliedRecord{ReleaseID: app.ReleaseID, ConfigHash: configHash(app), Status: "healthy"}

	moved := sampleApp()
	moved.Domain = "other.example.com"

	if should, _ := needsApply(rec, true, moved, time.Now(), false); !should {
		t.Fatal("смена домена не подхвачена")
	}
}

// Сломанный стек не должен занимать весь цикл агента: три замера ожидания,
// отказ, и всё сначала через минуту.
func TestAppliedBacksOffAfterFailure(t *testing.T) {
	app := sampleApp()
	now := time.Now()
	rec := AppliedRecord{
		ReleaseID:   app.ReleaseID,
		ConfigHash:  configHash(app),
		Status:      "failed",
		LastAttempt: now.Add(-1 * time.Minute),
	}

	if should, _ := needsApply(rec, true, app, now, false); should {
		t.Fatal("повтор сразу после неудачи — стек будет долбиться каждую минуту")
	}
}

// Но и забывать о неудаче нельзя: причина может уйти сама.
func TestAppliedRetriesAfterBackoff(t *testing.T) {
	app := sampleApp()
	now := time.Now()
	rec := AppliedRecord{
		ReleaseID:   app.ReleaseID,
		ConfigHash:  configHash(app),
		Status:      "failed",
		LastAttempt: now.Add(-failedRetryDelay - time.Minute),
	}

	if should, _ := needsApply(rec, true, app, now, false); !should {
		t.Fatal("после паузы повтор не произошёл — приложение потеряно навсегда")
	}
}

func TestAppliedFirstTimeApplies(t *testing.T) {
	if should, _ := needsApply(AppliedRecord{}, false, sampleApp(), time.Now(), false); !should {
		t.Fatal("новое приложение не применяется")
	}
}

// Отметки должны переживать перезапуск агента.
func TestAppliedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := Paths{StateDir: dir, WorkDir: filepath.Join(dir, "work")}

	state := AppliedState{Apps: map[string]AppliedRecord{
		"n8n": {ReleaseID: "rel-1", ConfigHash: "abc", Status: "healthy", LastAttempt: time.Now()},
	}}
	if err := SaveApplied(p, state); err != nil {
		t.Fatalf("SaveApplied: %v", err)
	}

	loaded := LoadApplied(p)
	if loaded.Apps["n8n"].ReleaseID != "rel-1" {
		t.Fatalf("отметка не восстановилась: %+v", loaded.Apps)
	}

	// Файл лежит рядом с ключом — права не должны быть шире 0600.
	info, err := os.Stat(appliedPath(p))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права на файл отметок %v, ожидали 0600", info.Mode().Perm())
	}
}

// Повреждённый файл не должен ронять агента.
func TestAppliedCorruptedFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	p := Paths{StateDir: dir}
	if err := os.WriteFile(appliedPath(p), []byte("{не json"), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded := LoadApplied(p)
	if loaded.Apps == nil {
		t.Fatal("повреждённый файл дал nil-карту — дальше будет паника")
	}
}

// Уборка не должна трогать приложения, которые должны работать.
func TestCleanupKeepsRunningApps(t *testing.T) {
	dir := t.TempDir()
	p := Paths{StateDir: dir, WorkDir: filepath.Join(dir, "work")}

	_ = SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		"keep": {ReleaseID: "r1", Status: "healthy"},
	}})

	removed := Cleanup(context.Background(), p, []DesiredApp{
		{Slug: "keep", Desired: "present"},
	})

	if len(removed) != 0 {
		t.Fatalf("уборка сняла работающее приложение: %v", removed)
	}
	if _, ok := LoadApplied(p).Apps["keep"]; !ok {
		t.Fatal("отметка о работающем приложении потеряна")
	}
}

// Приложение, помеченное absent, снимается. Каталога нет — значит стек уже
// не развёрнут, и достаточно убрать отметку.
func TestCleanupRemovesAbsent(t *testing.T) {
	dir := t.TempDir()
	p := Paths{StateDir: dir, WorkDir: filepath.Join(dir, "work")}

	_ = SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		"gone": {ReleaseID: "r1", Status: "healthy"},
	}})

	Cleanup(context.Background(), p, []DesiredApp{
		{Slug: "gone", Desired: "absent"},
	})

	if _, ok := LoadApplied(p).Apps["gone"]; ok {
		t.Fatal("отметка об остановленном приложении осталась")
	}
}

// Мусор в отметках не должен приводить к обращению к файловой системе по
// произвольному пути.
func TestCleanupIgnoresMalformedSlug(t *testing.T) {
	dir := t.TempDir()
	p := Paths{StateDir: dir, WorkDir: filepath.Join(dir, "work")}

	_ = SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		"../../etc": {ReleaseID: "r1", Status: "healthy"},
	}})

	Cleanup(context.Background(), p, nil)

	if _, ok := LoadApplied(p).Apps["../../etc"]; ok {
		t.Fatal("недопустимый slug остался в отметках")
	}
}

// Удаление обязано ЗАВЕРШАТЬСЯ, а не только выполняться.
//
// Двухфазное удаление устроено так: сервер помечает приложение absent, агент
// снимает стек, а подтверждением служит PresentSlugs — список того, что
// реально развёрнуто. Список строится по каталогам в WorkDir/apps.
//
// Уборка снимала стек, удаляла .env, рабочую копию и тома, но каталог
// приложения оставляла. PresentSlugs продолжал докладывать слаг как живой,
// сервер не подтверждал удаление НИКОГДА, и карточка навсегда застревала в
// состоянии «Удаляется» — при том что на хосте не оставалось ни контейнера,
// ни тома. Наблюдалось на b2c-web.
func TestRemoveAppDirEndsDeletion(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	dir := p.appDir("b2c-web")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("name: x\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if got := PresentSlugs(p); len(got) != 1 || got[0] != "b2c-web" {
		t.Fatalf("до уборки приложение обязано числиться развёрнутым, получено %v", got)
	}

	removeAppDir(p, "b2c-web")

	if got := PresentSlugs(p); len(got) != 0 {
		t.Fatalf("после уборки слаг всё ещё числится развёрнутым: %v — сервер не подтвердит удаление", got)
	}
}

// Каталог могли снести руками между циклами: повторный вызов не обязан
// жаловаться, иначе журнал агента заполнится шумом на каждом цикле.
func TestRemoveAppDirIsIdempotent(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	removeAppDir(p, "нет-такого")
	removeAppDir(p, "нет-такого")
}

// Наследство прежней версии агента: git-приложение применено, отпечаток тот же,
// релиз тот же — но описания стека в служебном каталоге нет, потому что старый
// агент поднимал такие стеки из рабочей копии.
//
// Без переприменения проверка здоровья и восстановление, работающие теперь
// только из служебного каталога, остались бы без файла НАВСЕГДА: причины
// тронуть приложение у агента больше нет ни одной. Стек при этом продолжал бы
// крутиться под прежним именем проекта — осиротевшим.
func TestApplyWhenComposeMissingInAppDir(t *testing.T) {
	app := sampleApp()
	rec := AppliedRecord{ReleaseID: app.ReleaseID, ConfigHash: configHash(app), Status: "healthy"}

	if should, _ := needsApply(rec, true, app, time.Now(), false); should {
		t.Fatal("применённое приложение трогается без причины")
	}

	should, reason := needsApply(rec, true, app, time.Now(), true)
	if !should {
		t.Fatal("приложение без описания стека в служебном каталоге не переприменяется")
	}
	if reason == "" {
		t.Fatal("причина переприменения не названа")
	}
}

// Смена домена не перевыкатывает приложение из репозитория.
//
// APP_DOMAIN уезжает в .env всегда, и для приложения из каталога это нужно: в
// шаблоне Supabase адрес подставлен в переменные сервисов, и без пересоздания
// контейнеров он не заработает. У приложения из репозитория переменной не
// пользуется никто — но отпечаток она меняла, и агент шёл в полный цикл со
// сборкой образа. Панель и ответ API при этом обещают «стек не
// перезапускается»: обещание было ложным.
func TestDomainChangeDoesNotRebuildGitApp(t *testing.T) {
	app := sampleApp()
	app.SourceType = "git"
	app.GitRepo = "git@github.com:o/r.git"
	app.GitBranch = "main"
	app.Domain = "old.example.com"

	moved := app
	moved.Domain = "new.example.com"

	if configHash(app) != configHash(moved) {
		t.Fatal("смена домена меняет отпечаток git-приложения: агент пересоберёт образ")
	}

	// У приложения из каталога — наоборот: без переприменения новый адрес не
	// заработает, потому что подставлен в переменные сервисов шаблона.
	tpl := sampleApp()
	tpl.SourceType = "template"
	tpl.Domain = "old.example.com"
	tplMoved := tpl
	tplMoved.Domain = "new.example.com"
	if configHash(tpl) == configHash(tplMoved) {
		t.Fatal("смена домена шаблонного приложения не переприменяется — адрес не заработает")
	}
}
