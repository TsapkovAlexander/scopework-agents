package agent

import (
	"strings"
	"testing"
)

func envFor(vars map[string]string) string {
	return renderEnv(DesiredApp{
		Slug:   "n8n",
		Domain: "n8n.example.com",
		Env:    vars,
	})
}

// Значение уходит в .env, который читает docker compose. Без кавычек compose
// обрезает значение по ` #` и подставляет `$VAR` — пароль доехал бы до
// контейнера искажённым, и понять это можно было бы только по тому, что
// приложение не может подключиться к своей базе.
func TestEnvValuesAreQuoted(t *testing.T) {
	out := envFor(map[string]string{
		"PASSWORD": "p@ss word#not-comment",
	})

	if !strings.Contains(out, `PASSWORD='p@ss word#not-comment'`) {
		t.Fatalf("значение не заключено в кавычки:\n%s", out)
	}
}

// Подстановка переменных внутри значения должна быть выключена: иначе пароль
// с символом доллара молча превращался бы в другой пароль.
func TestEnvValueWithDollarIsLiteral(t *testing.T) {
	out := envFor(map[string]string{"SECRET": "a$UNSET${APP_SLUG}b"})

	if !strings.Contains(out, `SECRET='a$UNSET${APP_SLUG}b'`) {
		t.Fatalf("подстановка не отключена:\n%s", out)
	}
}

// Одинарная кавычка внутри значения закрыла бы строку и сломала весь файл.
func TestEnvValueWithSingleQuoteIsEscaped(t *testing.T) {
	out := envFor(map[string]string{"PASSWORD": "it's"})

	if !strings.Contains(out, `PASSWORD='it'\''s'`) {
		t.Fatalf("одинарная кавычка не экранирована:\n%s", out)
	}
}

// APP_SLUG задаёт имя compose-проекта. В .env при дубликате побеждает
// последняя строка, а служебные пишутся первыми — значит переменная
// приложения с таким именем увела бы имя проекта, и `up --remove-orphans`
// снёс бы контейнеры соседнего приложения на том же хосте.
func TestEnvReservedKeysCannotBeOverridden(t *testing.T) {
	out := envFor(map[string]string{
		"APP_SLUG":             "hijacked",
		"APP_DOMAIN":           "evil.example.com",
		"COMPOSE_PROJECT_NAME": "global",
		"DOCKER_HOST":          "tcp://evil:2375",
	})

	if strings.Contains(out, "hijacked") || strings.Contains(out, "evil.example.com") {
		t.Fatalf("служебная переменная переопределена:\n%s", out)
	}
	if strings.Contains(out, "COMPOSE_PROJECT_NAME") || strings.Contains(out, "DOCKER_HOST") {
		t.Fatalf("переменная управления compose/docker просочилась:\n%s", out)
	}
	if !strings.Contains(out, `APP_SLUG='n8n'`) {
		t.Fatalf("собственное значение APP_SLUG потеряно:\n%s", out)
	}
}

// Перевод строки в значении дописал бы в .env отдельную переменную.
func TestEnvValueNewlinesStripped(t *testing.T) {
	out := envFor(map[string]string{"TZ": "UTC\nAPP_SLUG=hijacked"})

	if strings.Contains(out, "hijacked") && strings.Contains(out, "\nAPP_SLUG='hijacked'") {
		t.Fatalf("перевод строки создал новую переменную:\n%s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range lines {
		if strings.Count(l, "=") > 0 && !strings.Contains(l, "'") && !strings.HasPrefix(l, "#") {
			t.Fatalf("строка без кавычек — значит значение разорвало файл: %q", l)
		}
	}
}

// Имя переменной приходит с сервера, но агент обязан проверить его сам.
func TestEnvRejectsMalformedKeys(t *testing.T) {
	out := envFor(map[string]string{
		"OK_KEY":    "value",
		"bad key":   "value",
		"bad-key":   "value",
		"9starts":   "value",
		"inject\nX": "value",
	})

	if !strings.Contains(out, "OK_KEY=") {
		t.Fatal("корректный ключ потерян")
	}
	for _, bad := range []string{"bad key", "bad-key", "9starts", "inject"} {
		if strings.Contains(out, bad) {
			t.Fatalf("недопустимый ключ %q попал в файл:\n%s", bad, out)
		}
	}
}

// Имя вставшего контейнера вытаскивается из отказа compose.
//
// Без этого причина падения оставалась в журнале контейнера, а пользователь
// видел только «dependency failed to start ... is unhealthy» и шёл за ответом
// по SSH — туда, куда платформа обязана его не пускать.
func TestUnhealthyServiceFromComposeOutput(t *testing.T) {
	cases := []struct{ out, want string }{
		{
			out:  " Container doc-patients-api-1  Error dependency api failed to start\ndependency failed to start: container doc-patients-api-1 is unhealthy",
			want: "doc-patients-api-1",
		},
		{
			out:  "dependency failed to start: container shop-worker-2 exited (1)",
			want: "shop-worker-2",
		},
		{
			// Отказ без имени контейнера: дочитывать нечего, и выдумывать имя
			// нельзя — `docker logs` по мусору вернул бы чужой журнал.
			out:  "docker compose up: network shop_default not found",
			want: "",
		},
	}

	for _, c := range cases {
		match := unhealthyServiceRe.FindStringSubmatch(c.out)
		got := ""
		if match != nil {
			got = match[1]
			if got == "" {
				got = match[2]
			}
		}
		if got != c.want {
			t.Fatalf("из %q получено %q, ожидалось %q", c.out, got, c.want)
		}
	}
}
