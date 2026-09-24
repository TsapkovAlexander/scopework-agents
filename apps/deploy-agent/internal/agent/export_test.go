package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Слепок — единственная операция агента, которая читает секреты чужого стека.
// Поэтому проверяется не «работает ли», а «не выходит ли за границы»: имя
// проекта и путь приходят по сети, а агент работает от root.

func TestSafeProjectName(t *testing.T) {
	for _, ok := range []string{"supabase", "h804o84oc008ko0ko0owocwo", "my-stack_2", "a.b"} {
		if !safeProjectName(ok) {
			t.Errorf("законное имя проекта отвергнуто: %q", ok)
		}
	}
	// Всё, чем можно попытаться сбежать из сравнения с меткой или подсунуть
	// агенту команду.
	for _, bad := range []string{"", "../etc", "a b", "проект", "a;rm -rf /", "$(id)", string(make([]byte, 65))} {
		if safeProjectName(bad) {
			t.Errorf("недопустимое имя проекта принято: %q", bad)
		}
	}
}

func TestSafeVolumeName(t *testing.T) {
	if !safeVolumeName("abc123_supabase-storage") {
		t.Error("законное имя тома отвергнуто")
	}
	for _, bad := range []string{"", "a", "-leading", "with space", "с кириллицей", "a/b"} {
		if safeVolumeName(bad) {
			t.Errorf("недопустимое имя тома принято: %q", bad)
		}
	}
}

// Путь монтирования обязан лежать ВНУТРИ каталога стека. Иначе «сними слепок»
// превращается в «прочитай /etc/shadow»: монтирования приходят из docker, но
// сам каталог стека — из меток, и промах здесь стоит чужих файлов.
func TestRelativeToDirStaysInside(t *testing.T) {
	root := "/data/coolify/services/abc"

	rel, ok := relativeToDir(root+"/volumes/api/kong.yml", root)
	if !ok || rel != "volumes/api/kong.yml" {
		t.Fatalf("путь внутри каталога разобран неверно: %q, ok=%v", rel, ok)
	}

	for _, outside := range []string{
		"/etc/shadow",
		"/var/run/docker.sock",
		root + "-evil/secret",   // сосед с похожим именем
		root,                    // сам каталог — не файл внутри него
		root + "/../other/file", // выход через ..
	} {
		if _, ok := relativeToDir(outside, root); ok {
			t.Errorf("путь вне каталога стека принят: %q", outside)
		}
	}
}

// Кавычки в .env — не украшение: docker compose снимает их сам, и если
// перенести пароль вместе с апострофами, стек поднимется и не сможет
// подключиться к собственной базе. Ровно это сегодня и произошло при ручной
// проверке ключа.
func TestParseEnvFileStripsQuotes(t *testing.T) {
	env := parseEnvFile(`
# комментарий
APP_SLUG='sigma-supabase'
JWT="eyJhbGciOiJIUzI1NiJ9.payload=="
PLAIN=value
EMPTY=
SPACED = with space
BROKEN
`)

	cases := map[string]string{
		"APP_SLUG": "sigma-supabase",
		"JWT":      "eyJhbGciOiJIUzI1NiJ9.payload==",
		"PLAIN":    "value",
		"EMPTY":    "",
		"SPACED":   "with space",
	}
	for key, want := range cases {
		if got, ok := env[key]; !ok || got != want {
			t.Errorf("%s = %q (ok=%v), ожидалось %q", key, got, ok, want)
		}
	}
	if _, ok := env["BROKEN"]; ok {
		t.Error("строка без знака равенства принята за переменную")
	}
	if _, ok := env["#"]; ok {
		t.Error("комментарий принят за переменную")
	}
}

func TestUniqueSorted(t *testing.T) {
	got := uniqueSorted([]string{"b", "a", "b", "", "c"})
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("список томов: %v", got)
	}
}

func TestDirSizeCountsFilesOnly(t *testing.T) {
	dir := t.TempDir()
	if err := writeFileAtomic(filepath.Join(dir, "a.txt"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "nested")
	if err := writeFileAtomic(filepath.Join(sub, "b.txt"), []byte("123"), 0o644); err != nil {
		// writeFileAtomic не создаёт каталоги — пропускаем вложенность, если так.
		t.Skip("вложенный каталог не создан")
	}

	files, bytes := dirSize(dir)
	if files != 2 || bytes != 8 {
		t.Fatalf("файлов %d, байт %d — ожидалось 2 и 8", files, bytes)
	}
}

// --------------------------------------------------------------------------
// Перенос данных: порядок операций
// --------------------------------------------------------------------------
//
// Единственная операция агента, которая останавливает ЧУЖОЙ РАБОТАЮЩИЙ стек.
// Проверяется здесь не «скопировалось ли» — это делает dockersmoke, — а
// порядок и обязательства, потому что каждое нарушение уже стоило бы простоя
// боевого сервиса:
//
//   - образ для копирования тянется ДО остановки: на боевом хосте первый же
//     pull упёрся в 429 от Docker Hub, и сделай мы его после — стек остался бы
//     лежать из-за лимита чужого реестра;
//   - размер источника считается ПОСЛЕ остановки: живой MinIO пишет между
//     замером и стопом, и сверка расходилась бы на удачном переносе;
//   - при ЛЮБОМ отказе стек поднимается обратно: провал операции не должен
//     означать лежащий прод;
//   - имя проекта передаётся явно (-p): без него compose выводит его из имени
//     каталога, и промах означал бы копирование каталога под работающей
//     записью — молча и с сошедшейся сверкой.

type fakeDocker struct {
	calls []string
	fail  map[string]error
	out   map[string]string
}

func (f *fakeDocker) run(_ context.Context, args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, "docker "+key)
	for prefix, err := range f.fail {
		if strings.HasPrefix(key, prefix) {
			return "отказ", err
		}
	}
	for prefix, out := range f.out {
		if strings.HasPrefix(key, prefix) {
			return out, nil
		}
	}
	return "", nil
}

func (f *fakeDocker) compose(_ context.Context, dir string, args ...string) (string, error) {
	key := strings.Join(args, " ")
	f.calls = append(f.calls, "compose["+filepath.Base(dir)+"] "+key)
	for prefix, err := range f.fail {
		if strings.HasPrefix("compose "+key, prefix) {
			return "отказ", err
		}
	}
	for prefix, out := range f.out {
		if strings.HasPrefix("compose "+key, prefix) {
			return out, nil
		}
	}
	return "", nil
}

func (f *fakeDocker) indexOf(t *testing.T, substr string) int {
	t.Helper()
	for i, c := range f.calls {
		if strings.Contains(c, substr) {
			return i
		}
	}
	t.Fatalf("вызова %q не было; было: %v", substr, f.calls)
	return -1
}

func (f *fakeDocker) has(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

// migrateFixture готовит каталог стека с одним файлом внутри.
func migrateFixture(t *testing.T) (workingDir, rel string) {
	t.Helper()
	workingDir = t.TempDir()
	rel = "volumes/storage"
	if err := os.MkdirAll(filepath.Join(workingDir, rel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, rel, "object"), []byte("данные"), 0o644); err != nil {
		t.Fatal(err)
	}
	return workingDir, rel
}

func newMigrateDeps(f *fakeDocker, workingDir string) migrateDeps {
	return migrateDeps{
		docker:     f.run,
		compose:    f.compose,
		workingDir: func(context.Context, string) (string, error) { return workingDir, nil },
		freeBytes:  func(string) (int64, error) { return 1 << 40, nil },
	}
}

func TestMigratePullsCopyImageBeforeStoppingStack(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{}

	if _, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage",
		newMigrateDeps(f, workingDir)); err != nil {
		t.Fatalf("перенос не должен был упасть: %v", err)
	}

	if f.indexOf(t, "image inspect") > f.indexOf(t, "stop") {
		t.Errorf("образ для копирования тянется после остановки стека: %v", f.calls)
	}
}

func TestMigrateCountsSourceAfterStop(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{}
	deps := newMigrateDeps(f, workingDir)

	measuredAt := -1
	deps.dirSize = func(string) (int, int64) {
		measuredAt = len(f.calls)
		return 1, 6
	}

	if _, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage", deps); err != nil {
		t.Fatalf("перенос не должен был упасть: %v", err)
	}
	if measuredAt <= f.indexOf(t, "stop") {
		t.Errorf("источник посчитан до остановки стека: замер на шаге %d, вызовы %v", measuredAt, f.calls)
	}
}

func TestMigrateRestartsStackOnFailure(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{fail: map[string]error{"run --rm": fmt.Errorf("нет места")}}

	res, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage",
		newMigrateDeps(f, workingDir))
	if err == nil {
		t.Fatal("ожидался отказ копирования")
	}
	if !f.has("start") {
		t.Errorf("после отказа стек не поднят обратно: %v", f.calls)
	}
	if !res.Restored {
		t.Error("в отчёте не сказано, что стек возвращён в работу")
	}
}

// Успех оставляет стек ОСТАНОВЛЕННЫМ намеренно: следом платформа поднимает
// свой стек на тех же данных, и работающий чужой писал бы в каталог, копию
// которого мы уже сняли. Но человек обязан узнать об этом из отчёта, а не по
// отсутствию сайта.
func TestMigrateLeavesStackStoppedOnSuccessAndSaysSo(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{}

	res, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage",
		newMigrateDeps(f, workingDir))
	if err != nil {
		t.Fatalf("перенос не должен был упасть: %v", err)
	}
	if f.has("start") {
		t.Errorf("после удачного переноса стек подняли обратно — данные разойдутся: %v", f.calls)
	}
	if !res.StackStopped || res.Restored {
		t.Errorf("отчёт не сообщает, что стек оставлен остановленным: %+v", res)
	}
}

func TestMigratePassesProjectNameExplicitly(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{}

	if _, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage",
		newMigrateDeps(f, workingDir)); err != nil {
		t.Fatalf("перенос не должен был упасть: %v", err)
	}
	for _, c := range f.calls {
		if strings.HasPrefix(c, "compose[") && !strings.Contains(c, "-p abc") {
			t.Errorf("compose вызван без явного имени проекта: %q", c)
		}
	}
}

// Стоп с чужим именем проекта отрабатывает успешно и не останавливает ничего.
// Без проверки «а правда ли встало» мы бы копировали каталог под работающей
// записью — и сверка при этом могла бы сойтись.
func TestMigrateRefusesWhenStackStillRunning(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{out: map[string]string{"compose -p abc ps": "деадбиф\n"}}

	_, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage",
		newMigrateDeps(f, workingDir))
	if err == nil {
		t.Fatal("копирование пошло по живому каталогу: отказа не было")
	}
	if f.has("run --rm") {
		t.Errorf("копирование началось при работающем стеке: %v", f.calls)
	}
}

func TestMigrateRefusesWithoutFreeSpace(t *testing.T) {
	workingDir, rel := migrateFixture(t)
	f := &fakeDocker{}
	deps := newMigrateDeps(f, workingDir)
	deps.freeBytes = func(string) (int64, error) { return 1024, nil }
	deps.dirSize = func(string) (int, int64) { return 1, 1 << 30 }

	_, err := migrateDataDir(context.Background(), "abc", rel, "abc_storage", deps)
	if err == nil {
		t.Fatal("перенос начат при нехватке места")
	}
	if f.has("stop") {
		t.Errorf("стек остановлен до проверки свободного места: %v", f.calls)
	}
}

// Стеками платформы задания управлять не могут.
//
// Имя проекта в задании не проверял никто: фильтр «наш/чужой» жил только в
// разметке кнопок. Запрос с именем прокси останавливал его — то есть гасил все
// домены сервера разом.
func TestRefuseManagedStackByName(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}

	for _, project := range []string{proxyProjectName, "tracedocs-anything"} {
		err := refuseManagedStack(context.Background(), p, project)
		if err == nil {
			t.Fatalf("%s: отказа нет", project)
		}
		if !strings.Contains(err.Error(), "платформы") {
			t.Fatalf("%s: непонятный текст отказа: %v", project, err)
		}
	}
}

// Стек, лежащий в каталогах платформы, заданиями не управляется.
//
// Проверка по каталогу — основная: она опознаёт и приложения, и прокси по
// фактическому расположению, тогда как проверка по имени спасает только те
// стеки, чьё имя начинается с зарезервированного префикса.
func TestManagedRootsCoverAppDirs(t *testing.T) {
	work := t.TempDir()
	p := Paths{StateDir: t.TempDir(), WorkDir: work}
	roots := ManagedRoots(p)

	managed := []string{
		filepath.Join(work, "apps", "shop"),
		filepath.Join(work, "repos", "shop"),
		p.proxyDir(),
	}
	for _, dir := range managed {
		if !withinRoots(filepath.Clean(dir), roots) {
			t.Fatalf("%s не признан каталогом платформы — задание остановило бы свой стек", dir)
		}
	}

	// Соседний каталог с общим префиксом строки — чужой: разделитель в
	// сравнении на месте, и законный перехват не запрещается.
	foreign := []string{
		work + "-other/apps/shop",
		filepath.Join(work, "appsomething", "shop"),
		"/srv/customer/stack",
	}
	for _, dir := range foreign {
		if withinRoots(filepath.Clean(dir), roots) {
			t.Fatalf("%s признан каталогом платформы — перехват чужого стека запрещён напрасно", dir)
		}
	}
}

// --------------------------------------------------------------------------
// Восстановление из копии: отказ обязан доехать до платформы
// --------------------------------------------------------------------------
//
// Задание живёт в pending, пока агент не отчитался: платформа держит человеку
// «восстанавливаем…», а агент берёт то же задание каждую минуту. На этом уже
// обожглись слепок стека и плановая копия, поэтому проверяется здесь не
// «восстановилось ли», а то, что КАЖДЫЙ отказ на входе уезжает отчётом с
// внятной причиной. Саму операцию проверяют restore_test.go — через поддельный
// docker, порядок шагов и флаги — и restore_docker_test.go против настоящего
// Docker (тег dockersmoke): вернулись ли данные.

type restoreReport struct {
	TaskID string `json:"taskId"`
	Result struct {
		Set string `json:"set"`
		MS  int64  `json:"ms"`
	} `json:"result"`
	Error string `json:"error"`
}

// runRestoreTask прогоняет задание на восстановление против поддельной
// платформы и возвращает то, что агент ей сказал.
func runRestoreTask(t *testing.T, p Paths, apps []DesiredApp, set string) (restoreReport, error) {
	t.Helper()

	var got restoreReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("отчёт агента не разбирается: %v", err)
		}
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(srv.Close)

	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	task := HostTask{ID: "task-1", Kind: "restore", Project: "n8n", BackupSet: set}
	return got, RunTask(t.Context(), NewClient(srv.URL, "test"), id, p, task, apps, nil)
}

// Приложение удалили между постановкой задания и тактом: разворачивать копию
// того, чего платформа больше не знает, значит поднять на хосте стек, которым
// никто не управляет.
func TestRunTaskRestoreReportsUnknownApp(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}

	got, err := runRestoreTask(t, p, nil, "20260910-120000")
	if err == nil {
		t.Fatal("восстановление неизвестного приложения не отвергнуто")
	}
	if !strings.Contains(got.Error, "не найдено в желаемом состоянии") {
		t.Fatalf("платформа не узнала причину отказа: %q", got.Error)
	}
}

// Кривое имя набора отвергается ДО обращения к диску и к docker: оно уезжает в
// путь, и `..` в нём вывело бы распаковку за рабочий каталог.
func TestRunTaskRestoreRefusesBadSetName(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	apps := []DesiredApp{{Slug: "n8n"}}

	for _, set := range []string{"", "../../etc", "latest"} {
		got, err := runRestoreTask(t, p, apps, set)
		if err == nil {
			t.Fatalf("принято имя набора %q", set)
		}
		if !strings.Contains(got.Error, "недопустимое имя набора") {
			t.Fatalf("для %q платформа получила %q", set, got.Error)
		}
	}
}

// Набор мог унести ротация: на хосте держатся последние backup_keep наборов, а
// платформа помнит все снятые. Отказ обязан назвать причину — иначе человек
// получит ошибку docker про пустой каталог и будет гадать, что она означает.
func TestRunTaskRestoreReportsMissingSet(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	apps := []DesiredApp{{Slug: "n8n"}}

	got, err := runRestoreTask(t, p, apps, "20260910-120000")
	if err == nil {
		t.Fatal("восстановление из несуществующего набора не отвергнуто")
	}
	if !strings.Contains(got.Error, "не найден") {
		t.Fatalf("платформа не узнала причину отказа: %q", got.Error)
	}

	// Файл с именем набора — не набор. Проверка на каталог нужна отдельно:
	// os.Stat на файле ошибки не даёт, и без неё агент пошёл бы гасить стек
	// ради распаковки того, что распаковать нельзя.
	if err := os.MkdirAll(p.backupsDir("n8n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.backupsDir("n8n"), "20260910-120000"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err = runRestoreTask(t, p, apps, "20260910-120000")
	if err == nil {
		t.Fatal("файл принят за набор копий")
	}
	if !strings.Contains(got.Error, "не найден") {
		t.Fatalf("платформа не узнала причину отказа: %q", got.Error)
	}
}

// --------------------------------------------------------------------------
// Слепок: дайджест образа
// --------------------------------------------------------------------------
//
// Нормализация пришпиливает образ дайджестом из слепка, чтобы перенесённый
// стек поднялся тем же образом, что работал, а не тем, куда уехал тег. У
// контейнера поля RepoDigests нет — оно есть только у образа, и слепок, который
// читал его у контейнера, всегда отдавал идентификатор образа. По такому
// «дайджесту» реестр образ не отдаст.

// installSnapshotDocker кладёт в PATH поддельный docker для слепка: список
// контейнеров, их `inspect` (два сервиса одного проекта в каталоге dir) и
// `image inspect` — ответом imageJSON с кодом imageExit.
func installSnapshotDocker(t *testing.T, dir, imageJSON string, imageExit int) {
	t.Helper()
	compose := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(compose, []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	labels := func(service string) string {
		raw, _ := json.Marshal(map[string]string{
			"com.docker.compose.project":              "h804",
			"com.docker.compose.project.working_dir":  dir,
			"com.docker.compose.project.config_files": compose,
			"com.docker.compose.service":              service,
		})
		return string(raw)
	}
	containers := `[
  {"Name": "/supabase-db-h804", "Image": "sha256:aaa",
   "Config": {"Image": "supabase/postgres:15.8.1.048", "Labels": ` + labels("supabase-db") + `},
   "Mounts": []},
  {"Name": "/b2c-bff-h804", "Image": "sha256:738f974a0807c4adc723703646d266803705c89708dccb92b1c242e70331d298",
   "Config": {"Image": "h804-bff:latest", "Labels": ` + labels("b2c-bff") + `},
   "Mounts": []}
]`

	bin := t.TempDir()
	data := t.TempDir()
	for name, body := range map[string]string{"containers.json": containers, "images.json": imageJSON} {
		if err := os.WriteFile(filepath.Join(data, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"data=" + shellQuote(data) + "\n" +
		`case "$1 $2" in` + "\n" +
		`  "ps --all") printf 'c1\nc2\n';;` + "\n" +
		`  "image inspect") cat "$data/images.json"; exit ` + fmt.Sprint(imageExit) + `;;` + "\n" +
		`  inspect*) cat "$data/containers.json";;` + "\n" +
		`  *) echo "поддельный docker: неожиданный вызов $*" >&2; exit 2;;` + "\n" +
		`esac` + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestExportSnapshotTakesImageDigest(t *testing.T) {
	installSnapshotDocker(t, t.TempDir(), `[
  {"Id": "sha256:aaa", "RepoDigests": [
    "mirror.local/supabase/postgres@sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "supabase/postgres@sha256:f64a22b9b9e95ea31b317122123d8da78ce0e7647548f4a30d91cf6d2d522c1c"
  ]},
  {"Id": "sha256:738f974a0807c4adc723703646d266803705c89708dccb92b1c242e70331d298", "RepoDigests": []}
]`, 0)

	snap, err := CollectSnapshot(context.Background(), "h804")
	if err != nil {
		t.Fatalf("слепок упал: %v", err)
	}
	// Дайджест того репозитория, из которого контейнер запущен: дайджест
	// зеркала в supabase/postgres не найдётся.
	if got := snap.Digests["supabase-db"]; got != "sha256:f64a22b9b9e95ea31b317122123d8da78ce0e7647548f4a30d91cf6d2d522c1c" {
		t.Fatalf("дайджест образа из реестра: %q", got)
	}
	// Локальная сборка RepoDigests не имеет: ответ — идентификатор образа.
	if got := snap.Digests["b2c-bff"]; !strings.HasPrefix(got, "sha256:738f974a") {
		t.Fatalf("образ без RepoDigests: %q", got)
	}
}

// Осмотр образа не удался — слепок снимается: рецепт без дайджестов полезнее
// отказа, а пустое поле нормализация превращает в честное «не удалось
// определить дайджест», а не в пришпиливание идентификатором.
func TestExportSnapshotWithoutImageAnswer(t *testing.T) {
	installSnapshotDocker(t, t.TempDir(), "", 1)

	snap, err := CollectSnapshot(context.Background(), "h804")
	if err != nil {
		t.Fatalf("отказ осмотра образа уронил слепок: %v", err)
	}
	if snap.Compose == "" {
		t.Fatal("слепок без описания стека")
	}
	for _, svc := range []string{"supabase-db", "b2c-bff"} {
		got, ok := snap.Digests[svc]
		if !ok {
			t.Fatalf("сервис %s пропал из слепка: %v", svc, snap.Digests)
		}
		if got != "" {
			t.Fatalf("без ответа об образе дайджест %s обязан быть пустым: %q", svc, got)
		}
	}
}
