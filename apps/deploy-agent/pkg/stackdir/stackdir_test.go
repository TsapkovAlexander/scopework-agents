package stackdir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Эталон выписан литералом из поведения renderEnv агента на HEAD 26f11cf8, а
// не получен вызовом той же функции: подписант и агент обязаны собрать один и
// тот же `.env` до байта, иначе подстановка у подписанта разойдётся с хостом, и
// проверка после подстановки на агенте отвергнет то, что подписано.
func TestRenderEnvGolden(t *testing.T) {
	got := RenderEnv("n8n", "n8n.example.com", map[string]string{
		"ZETA":                 "last",
		"PASSWORD":             "p@ss word#not-comment",
		"SECRET":               "a$UNSET${APP_SLUG}b",
		"QUOTE":                "it's",
		"TZ":                   "UTC\nAPP_SLUG=hijacked\r\x00",
		"APP_SLUG":             "hijacked",
		"APP_DOMAIN":           "evil.example.com",
		"COMPOSE_PROJECT_NAME": "global",
		"DOCKER_HOST":          "tcp://evil:2375",
		"bad-key":              "dropped",
		"1LEADING_DIGIT":       "dropped",
		"_under":               "kept",
		"EMPTY":                "",
	})
	const want = "# Файл создан агентом Scopework. Правки перезаписываются.\n" +
		"APP_SLUG='n8n'\n" +
		"APP_DOMAIN='n8n.example.com'\n" +
		"EMPTY=''\n" +
		"PASSWORD='p@ss word#not-comment'\n" +
		"QUOTE='it'\\''s'\n" +
		"SECRET='a$UNSET${APP_SLUG}b'\n" +
		"TZ='UTCAPP_SLUG=hijacked'\n" +
		"ZETA='last'\n" +
		"_under='kept'\n"
	if got != want {
		t.Fatalf(".env разошёлся с эталоном HEAD\nполучено:\n%s\nожидалось:\n%s", got, want)
	}
}

// Пустая карта — только шапка и служебные переменные: приложение без своих
// переменных всё равно получает имя проекта и домен.
func TestRenderEnvWithoutVars(t *testing.T) {
	const want = "# Файл создан агентом Scopework. Правки перезаписываются.\n" +
		"APP_SLUG='demo-app'\n" +
		"APP_DOMAIN=''\n"
	if got := RenderEnv("demo-app", "", nil); got != want {
		t.Fatalf("получено:\n%q\nожидалось:\n%q", got, want)
	}
}

func TestIsReservedEnvKey(t *testing.T) {
	for key, want := range map[string]bool{
		"APP_SLUG": true, "APP_DOMAIN": true,
		"COMPOSE_PROJECT_NAME": true, "COMPOSE_FILE": true, "DOCKER_HOST": true,
		"APP_SLUGX": false, "MY_COMPOSE_X": false, "PORT": false,
	} {
		if got := IsReservedEnvKey(key); got != want {
			t.Errorf("IsReservedEnvKey(%q) = %v, ожидалось %v", key, got, want)
		}
	}
}

func TestSafeSlugAndEnvKey(t *testing.T) {
	for slug, want := range map[string]bool{
		"n8n": true, "my-app-2": true, "a": false, "ab": false, "abc": true,
		"-ab": false, "ab-": false, "Ab1": false, "a_b": false,
		strings.Repeat("a", 40): true, strings.Repeat("a", 41): false,
	} {
		if got := SafeSlug.MatchString(slug); got != want {
			t.Errorf("SafeSlug(%q) = %v, ожидалось %v", slug, got, want)
		}
	}
	for key, want := range map[string]bool{
		"A": true, "_x": true, "A1_B": true, "1A": false, "A-B": false, "A B": false, "": false,
	} {
		if got := SafeEnvKey.MatchString(key); got != want {
			t.Errorf("SafeEnvKey(%q) = %v, ожидалось %v", key, got, want)
		}
	}
}

// Путь файла шаблона задаёт недоверенный вход. Всё, что ведёт за каталог
// приложения или на файлы, которыми агент поднимает стек, — отказ до записи.
func TestResolveFilePathRejectsEscape(t *testing.T) {
	appDir := filepath.Join(string(os.PathSeparator), "opt", "tracedocs", "deploy", "apps", "demo")
	for _, raw := range []string{
		"",
		"   ",
		"/etc/passwd",
		"../other/.env",
		"volumes/../../other/.env",
		"a/./b",
		`volumes\kong.yml`,
		"volumes/kong.yml\x00",
		"volumes/ko ng.yml",
		"docker-compose.yml",
		"Docker-Compose.YAML",
		"compose.yml",
		"compose.yaml",
		".env",
		strings.Repeat("a", 97),
	} {
		if got, err := ResolveFilePath(appDir, raw); err == nil {
			t.Errorf("путь %q принят как %q", raw, got)
		}
	}

	for raw, want := range map[string]string{
		"volumes/api/kong.yml":  filepath.Join(appDir, "volumes", "api", "kong.yml"),
		"volumes//db/init.sql":  filepath.Join(appDir, "volumes", "db", "init.sql"),
		" config/app.env ":      filepath.Join(appDir, "config", "app.env"),
		"nested/.env":           filepath.Join(appDir, "nested", ".env"),
		"nested/compose.yml":    filepath.Join(appDir, "nested", "compose.yml"),
		strings.Repeat("a", 96): filepath.Join(appDir, strings.Repeat("a", 96)),
	} {
		got, err := ResolveFilePath(appDir, raw)
		if err != nil {
			t.Errorf("законный путь %q отвергнут: %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ResolveFilePath(%q) = %q, ожидалось %q", raw, got, want)
		}
	}
}

func TestParseFileMode(t *testing.T) {
	for raw, want := range map[string]os.FileMode{
		"":     0o644,
		"  ":   0o644,
		"0644": 0o644,
		"644":  0o644,
		"0600": 0o600,
		"0755": 0o755,
		"0400": 0o400,
		"0440": 0o440,
		"0444": 0o444,
		"0640": 0o640,
	} {
		got, err := ParseFileMode(raw)
		if err != nil || got != want {
			t.Errorf("ParseFileMode(%q) = %o, %v; ожидалось %o", raw, got, err, want)
		}
	}
	for _, raw := range []string{"0777", "4755", "2755", "1777", "0666", "rw-r--r--", "0o644", "9", "-1"} {
		if got, err := ParseFileMode(raw); err == nil {
			t.Errorf("права %q приняты как %o", raw, got)
		}
	}
}
