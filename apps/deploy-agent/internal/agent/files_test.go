package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Файлы шаблона приходят с сервера и ложатся на диск рядом с секретами
// платформы. Проверяем именно то, что отличает «положить конфиг» от «записать
// куда угодно на хосте клиента».

func tempPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	return Paths{
		StateDir: filepath.Join(root, "state"),
		WorkDir:  filepath.Join(root, "work"),
	}
}

func TestTemplateFilesWritten(t *testing.T) {
	p := tempPaths(t)
	dir := p.appDir("supabase")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	err := writeTemplateFiles(dir, []DesiredFile{
		{Path: "volumes/api/kong.yml", Content: "_format_version: '2.1'\n", Mode: "0644"},
		{Path: "volumes/db/init.sql", Content: "create schema app;\n"},
	})
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "volumes", "api", "kong.yml"))
	if err != nil {
		t.Fatalf("файл не создан: %v", err)
	}
	if string(raw) != "_format_version: '2.1'\n" {
		t.Fatalf("содержимое не совпадает: %q", raw)
	}

	// Каталоги должны быть проходимы для процесса внутри контейнера: bind-mount
	// отдаёт файл с его собственными правами, и 0700 на каталоге сделал бы
	// конфиг нечитаемым для postgres или kong, которые работают не от root.
	info, err := os.Stat(filepath.Join(dir, "volumes", "db"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("права каталога %v, ожидалось 0755", info.Mode().Perm())
	}
}

func TestTemplateFileRejectsEscape(t *testing.T) {
	p := tempPaths(t)
	dir := p.appDir("supabase")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Каждый из этих путей означал бы запись за пределы каталога приложения:
	// в конфиг systemd, в authorized_keys, в чужое приложение на том же хосте.
	cases := []string{
		"/etc/systemd/system/evil.service",
		"../../../root/.ssh/authorized_keys",
		"volumes/../../escape.txt",
		"./../sibling/docker-compose.yml",
		`volumes\..\..\escape.txt`,
		"",
		"   ",
	}

	for _, path := range cases {
		if err := writeTemplateFiles(dir, []DesiredFile{{Path: path, Content: "x"}}); err == nil {
			t.Fatalf("путь %q принят, а должен быть отвергнут", path)
		}
	}

	// И ничего не должно было появиться на диске.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("каталог не пуст после отказов: %v", entries)
	}
}

// docker-compose.yml и .env пишет сам агент. Разреши их перезапись — и
// «какой compose реально запущен» перестало бы определяться релизом, а .env
// с секретами можно было бы подменить содержимым файла шаблона.
func TestTemplateFileCannotOverwriteAgentFiles(t *testing.T) {
	p := tempPaths(t)
	dir := p.appDir("supabase")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"docker-compose.yml", ".env", "./.env", "docker-compose.yaml"} {
		if err := writeTemplateFiles(dir, []DesiredFile{{Path: path, Content: "x"}}); err == nil {
			t.Fatalf("перезапись %q разрешена", path)
		}
	}
}

func TestTemplateFilesBounded(t *testing.T) {
	p := tempPaths(t)
	dir := p.appDir("supabase")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Размер ограничен намеренно: желаемое состояние приходит по сети, и
	// платформа не должна уметь занять диск клиента файлами конфигурации.
	big := []DesiredFile{{Path: "big.bin", Content: strings.Repeat("a", maxTemplateFileBytes+1)}}
	if err := writeTemplateFiles(dir, big); err == nil {
		t.Fatal("слишком большой файл принят")
	}

	many := make([]DesiredFile, maxTemplateFiles+1)
	for i := range many {
		many[i] = DesiredFile{Path: "f" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Content: "x"}
	}
	if err := writeTemplateFiles(dir, many); err == nil {
		t.Fatal("превышение числа файлов принято")
	}
}

func TestTemplateFileModeRestricted(t *testing.T) {
	p := tempPaths(t)
	dir := p.appDir("supabase")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	// Бит setuid на файле, который потом монтируется в контейнер, — не то,
	// что должно приезжать из желаемого состояния.
	if err := writeTemplateFiles(dir, []DesiredFile{{Path: "a.sh", Content: "x", Mode: "4755"}}); err == nil {
		t.Fatal("недопустимый режим принят")
	}

	if err := writeTemplateFiles(dir, []DesiredFile{{Path: "a.sh", Content: "x", Mode: "0755"}}); err != nil {
		t.Fatalf("допустимый режим отвергнут: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "a.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("права файла %v, ожидалось 0755", info.Mode().Perm())
	}
}

// Файлы участвуют в отпечатке конфигурации: правка kong.yml в каталоге без
// смены версии иначе не доехала бы до хоста никогда — агент считал бы, что
// применять нечего.
func TestConfigHashCoversTemplateFiles(t *testing.T) {
	base := DesiredApp{
		Slug:    "supabase",
		Compose: "name: x",
		Env:     map[string]string{"A": "1"},
		Files:   []DesiredFile{{Path: "volumes/api/kong.yml", Content: "one"}},
	}
	changed := base
	changed.Files = []DesiredFile{{Path: "volumes/api/kong.yml", Content: "two"}}

	if configHash(base) == configHash(changed) {
		t.Fatal("изменение файла шаблона не меняет отпечаток конфигурации")
	}
}

// Docker при монтировании несуществующего пути создаёт его каталогом. Стоит
// стеку один раз подняться без файлов шаблона — и `volumes/db/roles.sql`
// становится каталогом, после чего атомарная запись отказывает навсегда:
// rename не заменяет каталог файлом. Ровно так встал первый боевой выкат.
func TestTemplateFileReplacesDirectoryLeftByDocker(t *testing.T) {
	p := tempPaths(t)
	dir := p.appDir("supabase")
	if err := os.MkdirAll(filepath.Join(dir, "volumes", "db", "roles.sql"), 0o755); err != nil {
		t.Fatal(err)
	}

	err := writeTemplateFiles(dir, []DesiredFile{
		{Path: "volumes/db/roles.sql", Content: "alter user authenticator;\n"},
	})
	if err != nil {
		t.Fatalf("каталог на месте файла не заменён: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "volumes", "db", "roles.sql"))
	if err != nil {
		t.Fatalf("файл не создан: %v", err)
	}
	if string(raw) != "alter user authenticator;\n" {
		t.Fatalf("содержимое не совпадает: %q", raw)
	}
}

// ─── С1.8: симлинк, созданный контейнером, уводит запись за пределы приложения ──
//
// Пути файлов шаблона проверены от `..` и абсолютных, но контейнер работает в
// том же каталоге и волен положить туда симлинк. Тогда безобидное имя вроде
// `volumes/db/roles.sql` пишется по ссылке — куда укажет контейнер.
func TestWriteTemplateFilesRefusesSymlinkedDir(t *testing.T) {
	appDir := t.TempDir()
	outside := t.TempDir()

	// Так это и выглядит на хосте: контейнер подменил свой подкаталог ссылкой.
	if err := os.Symlink(outside, filepath.Join(appDir, "volumes")); err != nil {
		t.Fatalf("симлинк не создан: %v", err)
	}

	err := writeTemplateFiles(appDir, []DesiredFile{
		{Path: "volumes/roles.sql", Content: "SELECT 1;", Mode: "0644"},
	})
	if err == nil {
		t.Fatal("запись через симлинк разрешена: файл ушёл за пределы каталога приложения")
	}
	if _, statErr := os.Stat(filepath.Join(outside, "roles.sql")); statErr == nil {
		t.Fatal("файл записан по ссылке наружу")
	}
}

// Сам файл тоже может оказаться ссылкой — подмена уже существующего.
func TestWriteTemplateFilesRefusesSymlinkedFile(t *testing.T) {
	appDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "target.sql")
	if err := os.WriteFile(outside, []byte("old"), 0o644); err != nil {
		t.Fatalf("цель не создана: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(appDir, "roles.sql")); err != nil {
		t.Fatalf("симлинк не создан: %v", err)
	}

	if err := writeTemplateFiles(appDir, []DesiredFile{
		{Path: "roles.sql", Content: "SELECT 2;", Mode: "0644"},
	}); err == nil {
		t.Fatal("запись поверх симлинка разрешена")
	}
	if data, _ := os.ReadFile(outside); string(data) != "old" {
		t.Fatal("содержимое цели симлинка изменено")
	}
}

// Обычная запись в подкаталог работает: запрет ссылок не должен ломать шаблоны.
func TestWriteTemplateFilesWritesOrdinaryNestedFile(t *testing.T) {
	appDir := t.TempDir()
	if err := writeTemplateFiles(appDir, []DesiredFile{
		{Path: "volumes/db/roles.sql", Content: "SELECT 1;", Mode: "0644"},
	}); err != nil {
		t.Fatalf("обычная запись отклонена: %v", err)
	}
	if _, err := os.Stat(filepath.Join(appDir, "volumes", "db", "roles.sql")); err != nil {
		t.Fatalf("файл не записан: %v", err)
	}
}
