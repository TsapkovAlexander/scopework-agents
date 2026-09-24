package agent

import (
	"strings"
	"testing"
)

// Хвост вывода docker уезжает в историю релизов и виден любому участнику
// проекта — включая тех, у кого прав на управление развёртыванием нет.
func TestRedactSecrets(t *testing.T) {
	env := map[string]string{
		"POSTGRES_PASSWORD": "S3cr3tP@ssw0rd-long",
		"TZ":                "Europe/Moscow",
		"PORT":              "3000",
	}

	text := "connection refused: postgres://n8n:S3cr3tP@ssw0rd-long@db:5432/n8n"
	got := redactSecrets(text, env)

	if strings.Contains(got, "S3cr3tP@ssw0rd-long") {
		t.Fatalf("пароль остался в тексте: %s", got)
	}
	if !strings.Contains(got, redactedMarker) {
		t.Fatalf("замены не произошло: %s", got)
	}
	// Остальной текст должен остаться читаемым, иначе разбирать отказ нечем.
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("текст ошибки испорчен: %s", got)
	}
}

// Короткие значения не затираем: `3000` встречается в любом выводе, и замена
// превратила бы его в кашу, не добавив защиты.
func TestRedactSecretsKeepsShortValues(t *testing.T) {
	got := redactSecrets("listening on 3000", map[string]string{"PORT": "3000"})
	if got != "listening on 3000" {
		t.Fatalf("короткое значение затёрто: %s", got)
	}
}

// Длинное значение заменяется раньше короткого: иначе «pass» затёрло бы часть
// «password123456», и остаток остался бы в выводе.
func TestRedactSecretsPrefersLongest(t *testing.T) {
	env := map[string]string{"A": "password", "B": "password123456"}
	got := redactSecrets("value=password123456", env)
	if strings.Contains(got, "123456") {
		t.Fatalf("остаток длинного значения не затёрт: %s", got)
	}
}

func TestRedactSecretsHandlesEmpty(t *testing.T) {
	if got := redactSecrets("", map[string]string{"A": "longvalue"}); got != "" {
		t.Error("пустой текст изменён")
	}
	if got := redactSecrets("текст", nil); got != "текст" {
		t.Error("текст изменён при отсутствии переменных")
	}
}

// Токен установки и приватный ключ обязаны затираться наравне с переменными.
//
// В вывод git они попасть не должны by design — в argv их нет, в адрес они не
// подставляются. Но хвост ошибки формируем не мы, а уезжает он на сервер и
// оттуда на экран любому участнику проекта, включая тех, у кого прав на
// управление развёртыванием нет.
func TestRedactionCoversRepositoryCredentials(t *testing.T) {
	app := DesiredApp{
		Env:      map[string]string{"DATABASE_URL": "postgres://user:supersecret@db/app"},
		GitToken: "ghs_tokenvaluethatmustnotleak",
		GitKey:   "-----BEGIN OPENSSH PRIVATE KEY-----\nsecretkeymaterial\n-----END",
	}

	text := "fatal: не удалось получить ghs_tokenvaluethatmustnotleak и " +
		"postgres://user:supersecret@db/app"
	got := redactSecrets(text, app.redactionValues())

	if strings.Contains(got, "ghs_tokenvaluethatmustnotleak") {
		t.Fatalf("токен остался в отчёте: %q", got)
	}
	if strings.Contains(got, "postgres://user:supersecret@db/app") {
		t.Fatalf("переменная осталась в отчёте: %q", got)
	}

	// Приложение без доступов к репозиторию не должно платить копированием
	// карты на каждой ошибке.
	plain := DesiredApp{Env: map[string]string{"A": "b"}}
	if len(plain.redactionValues()) != 1 {
		t.Fatal("лишние значения в наборе затирания")
	}
}
