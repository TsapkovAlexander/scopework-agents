package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Папка приложения внутри репозитория (0284).
//
// Значение приходит с сервера и склеивается с путём рабочей копии, а результат
// становится и корнем раздачи статики, и контекстом сборки. Проверки здесь —
// про то, что за пределы копии выйти нечем.

func seedBaseDir(t *testing.T, p Paths, slug, base string) string {
	t.Helper()
	dir := filepath.Join(p.repoDir(slug), base)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("каталог %s не создан: %v", base, err)
	}
	return dir
}

func TestValidateGitBaseDirForm(t *testing.T) {
	ok := []string{"", "apps", "apps/web", "apps/web/service_1", "a-b.c"}
	for _, base := range ok {
		if err := validateGitBaseDir(base); err != nil {
			t.Errorf("законная папка %q отвергнута: %v", base, err)
		}
	}

	// Выход наверх, абсолютный путь, скрытый каталог, пустые сегменты и
	// хвостовой слэш: последние два дают два разных значения для одного
	// каталога, то есть разъехавшийся отпечаток состояния при том же стеке.
	bad := []string{
		"..", "../etc", "apps/../..", "apps/..", "/etc", "/apps/web",
		".git", "apps/.git", "apps//web", "apps/", "apps/web ", "apps\tweb",
		strings.Repeat("a", maxGitBaseDirLen+1),
	}
	for _, base := range bad {
		if err := validateGitBaseDir(base); err == nil {
			t.Errorf("опасная папка %q принята", base)
		}
	}
}

// Форма проверяется ДО клона: отказ не должен ждать сетевой операции.
func TestValidateGitSourceChecksBaseDir(t *testing.T) {
	app := gitApp()
	app.GitBaseDir = "../../etc"
	if err := validateGitSource(app); err == nil {
		t.Fatal("папка с выходом наверх принята при проверке источника")
	}

	app.GitBaseDir = "apps/web"
	if err := validateGitSource(app); err != nil {
		t.Fatalf("законная папка отвергнута: %v", err)
	}
}

// Симлинк в репозитории — код клиента, и коммит с `apps/web -> /etc`
// превратил бы раздачу статики в раздачу системных файлов сервера.
func TestAppDirRejectsSymlinkEscape(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.GitBaseDir = "apps"

	repo := p.repoDir(app.Slug)
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repo, "apps")); err != nil {
		t.Skipf("симлинки недоступны: %v", err)
	}

	if _, err := repoAppDir(p, app); err == nil {
		t.Fatal("симлинк за пределы рабочей копии принят")
	}
}

// Симлинк ВНУТРЬ копии законен: монорепозитории так связывают пакеты.
func TestAppDirAllowsSymlinkInsideRepo(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.GitBaseDir = "current"

	repo := p.repoDir(app.Slug)
	real := seedBaseDir(t, p, app.Slug, "releases/v2")
	if err := os.Symlink(real, filepath.Join(repo, "current")); err != nil {
		t.Skipf("симлинки недоступны: %v", err)
	}

	got, err := repoAppDir(p, app)
	if err != nil {
		t.Fatalf("симлинк внутрь копии отвергнут: %v", err)
	}
	// Путь ЛЕКСИЧЕСКИЙ: его агент отдаёт docker, а тот пишет его в метку
	// рабочего каталога, по которой платформа узнаёт свои стеки.
	if want := filepath.Join(repo, "current"); got != want {
		t.Fatalf("получен каталог %q, ожидался %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(real, "..")); err != nil {
		t.Fatal(err)
	}
}

func TestAppDirRequiresExistingDirectory(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	repo := p.repoDir(app.Slug)
	if err := os.MkdirAll(repo, 0o750); err != nil {
		t.Fatal(err)
	}

	// Папки нет: отказ здесь понятнее, чем «no such file or directory» из
	// docker минутами позже.
	app.GitBaseDir = "apps/web"
	if _, err := repoAppDir(p, app); err == nil {
		t.Fatal("несуществующая папка принята")
	}

	// Файл вместо папки.
	if err := os.WriteFile(filepath.Join(repo, "apps"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	app.GitBaseDir = "apps"
	if _, err := repoAppDir(p, app); err == nil {
		t.Fatal("файл принят за папку приложения")
	}
}

// Пустое значение — рабочая копия целиком: приложения, созданные до появления
// поля, обязаны работать без единой правки.
func TestAppDirEmptyIsRepoRoot(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	if err := os.MkdirAll(p.repoDir(app.Slug), 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := repoAppDir(p, app)
	if err != nil {
		t.Fatal(err)
	}
	if got != p.repoDir(app.Slug) {
		t.Fatalf("получен каталог %q, ожидалась сама рабочая копия %q", got, p.repoDir(app.Slug))
	}
}

// Описание стека ищется в папке приложения, а не в корне.
func TestReadComposeFromRepoUsesBaseDir(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.GitBaseDir = "apps/web"

	dir := seedBaseDir(t, p, app.Slug, "apps/web")
	// В корне лежит compose СОСЕДНЕГО назначения: до появления поля платформа
	// подняла бы именно его.
	if err := os.WriteFile(filepath.Join(p.repoDir(app.Slug), "docker-compose.yml"),
		[]byte("services: {root: {}}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"),
		[]byte("services: {web: {}}\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	got, err := readComposeFromRepo(p, app)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "web") || strings.Contains(got, "root") {
		t.Fatalf("прочитан compose не из папки приложения: %q", got)
	}
}

// Отсутствие файла называет папку: иначе человек ищет ошибку в корне.
func TestReadComposeFromRepoNamesBaseDir(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.GitBaseDir = "apps/web"
	seedBaseDir(t, p, app.Slug, "apps/web")

	_, err := readComposeFromRepo(p, app)
	if err == nil {
		t.Fatal("отсутствие описания стека не замечено")
	}
	if !strings.Contains(err.Error(), "apps/web") {
		t.Fatalf("отказ не называет папку приложения: %v", err)
	}
}

// Синтетический compose кладётся В ПАПКУ приложения и собирает из неё же.
func TestWriteSyntheticComposeInBaseDir(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.GitBaseDir = "apps/web"

	dir := seedBaseDir(t, p, app.Slug, "apps/web")
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	// В корне рабочей копии его быть не должно: там живёт чужой код.
	if _, err := os.Stat(filepath.Join(p.repoDir(app.Slug), "docker-compose.yml")); err == nil {
		t.Fatal("синтетический compose записан в корень репозитория")
	}

	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("compose не записан в папку приложения: %v", err)
	}
	got := string(raw)
	if !strings.Contains(got, "context: .\n") {
		t.Fatalf("контекст сборки не равен папке приложения: %s", got)
	}
	if !strings.Contains(got, "dockerfile: Dockerfile\n") {
		t.Fatalf("Dockerfile указан не по имени: %s", got)
	}
}

// Флаг «собирать из корня» — ради монорепо: Dockerfile лежит в подпапке, а
// копирует корневые package.json и lock-файл.
func TestWriteSyntheticComposeBuildContextRoot(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.GitBaseDir = "apps/web"
	app.GitBuildContextRoot = true

	dir := seedBaseDir(t, p, app.Slug, "apps/web")
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM scratch\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, "context: "+p.repoDir(app.Slug)+"\n") {
		t.Fatalf("контекстом сборки стал не корень репозитория: %s", got)
	}
	// Путь к Dockerfile абсолютный: относительный («../..») был бы неверен,
	// если папка приложения — симлинк.
	if !strings.Contains(got, "dockerfile: "+filepath.Join(dir, "Dockerfile")+"\n") {
		t.Fatalf("Dockerfile указан не абсолютным путём в папке приложения: %s", got)
	}
}

// Dockerfile ищется в папке приложения, и отказ называет её.
func TestSyntheticComposeRequiresDockerfileInBaseDir(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.GitBaseDir = "apps/web"
	seedBaseDir(t, p, app.Slug, "apps/web")

	// В корне Dockerfile ЕСТЬ — и это не должно спасать: собираем не его.
	if err := os.WriteFile(filepath.Join(p.repoDir(app.Slug), "Dockerfile"),
		[]byte("FROM scratch\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	err := writeSyntheticCompose(p, app)
	if err == nil {
		t.Fatal("Dockerfile из корня принят за файл приложения в подпапке")
	}
	if !strings.Contains(err.Error(), "apps/web") {
		t.Fatalf("отказ не называет папку приложения: %v", err)
	}
}

// Статика раздаётся из папки приложения, а не из всей рабочей копии — иначе
// наружу уезжает и код соседних сервисов монорепо.
func TestWriteSyntheticComposeStaticBaseDir(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	app := gitApp()
	app.BuildMethod = buildMethodStatic
	app.GitBaseDir = "site"

	dir := seedBaseDir(t, p, app.Slug, "site")
	if err := writeSyntheticCompose(p, app); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("compose не записан в папку приложения: %v", err)
	}
	if !strings.Contains(string(raw), "- .:/usr/share/nginx/html:ro") {
		t.Fatalf("корнем раздачи стала не папка приложения: %s", raw)
	}
}

// Смена папки обязана менять отпечаток: ни адрес, ни ветка, ни способ сборки
// при этом не меняются, и без отпечатка агент держал бы стек прежнего сервиса.
func TestConfigHashCoversBaseDir(t *testing.T) {
	app := gitApp()
	app.BuildMethod = buildMethodDockerfile
	app.GitBaseDir = "apps/web"

	moved := app
	moved.GitBaseDir = "apps/api"
	if configHash(app) == configHash(moved) {
		t.Fatal("смена папки приложения не меняет отпечаток")
	}

	rebuilt := app
	rebuilt.GitBuildContextRoot = true
	if configHash(app) == configHash(rebuilt) {
		t.Fatal("смена контекста сборки не меняет отпечаток")
	}
}

// Принадлежность стека рабочей копии — по вложению каталога, а не по точному
// совпадению: приложение с папкой поднимается из подкаталога.
func TestDirWithin(t *testing.T) {
	root := "/opt/tracedocs/deploy/repos/web"

	for _, path := range []string{root, root + "/apps/web"} {
		if !dirWithin(path, root) {
			t.Errorf("свой каталог %q не признан вложенным", path)
		}
	}
	// Соседнее приложение с похожим именем — чужое. По этому признаку гасят
	// стеки, и ошибка здесь останавливает работающее приложение.
	for _, path := range []string{root + "2", "/opt/tracedocs/deploy/repos/web-api", "", "/opt"} {
		if dirWithin(path, root) {
			t.Errorf("чужой каталог %q признан вложенным", path)
		}
	}
}
