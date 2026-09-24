// Package stackdir — как из желаемого состояния собирается каталог стека:
// `.env` и пути файлов шаблона. Один код на агента и подписанта: подписант
// строит модель compose тем же `.env` и в тех же путях, что агент на хосте.
// Разойдись они — подстановка у подписанта и на хосте дала бы разные модели, и
// агент, повторяющий политику после подстановки, отверг бы подписанное.
//
// Только лексика и строки: запись на диск и проверка симлинков остаются у
// агента, подписант раскладывает файлы в своём временном каталоге.
package stackdir

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SafeSlug ограничивает то, что попадёт в путь на диске и в имя проекта
// docker compose. Сервер уже проверяет slug регулярным выражением, но агент
// живёт на чужой машине и обязан не доверять входу второй раз: одна ошибка на
// той стороне не должна превращаться в запись за пределы рабочего каталога.
var SafeSlug = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)

// SafeEnvKey — имя переменной окружения. Всё остальное отбрасываем: значение
// вида `FOO\nBAR=baz` иначе дописало бы в .env лишнюю строку.
var SafeEnvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Имена, которые приложение переопределить не может.
//
// APP_SLUG задаёт имя compose-проекта, APP_DOMAIN — адрес в конфиге прокси.
// В .env при дубликате ключа побеждает ПОСЛЕДНЯЯ строка, а служебные пишутся
// первыми — значит без этого списка переменная приложения с именем APP_SLUG
// увела бы имя проекта, и `up --remove-orphans` снёс бы контейнеры соседа.
// Префиксы COMPOSE_ и DOCKER_ управляют самим compose и docker.
var reservedEnvKeys = map[string]bool{
	"APP_SLUG":   true,
	"APP_DOMAIN": true,
}

func IsReservedEnvKey(key string) bool {
	if reservedEnvKeys[key] {
		return true
	}
	return strings.HasPrefix(key, "COMPOSE_") || strings.HasPrefix(key, "DOCKER_")
}

// QuoteEnvValue заключает значение в одинарные кавычки.
//
// Без кавычек docker compose обрабатывает значение как выражение: обрезает
// его по ` #` (комментарий), подставляет `${VAR}` и `$VAR` из окружения.
// Пароль вида `p@ss$SOMETHING!` доехал бы до контейнера обрезанным, а
// `x${APP_SLUG}y` подставил бы чужую переменную. В одинарных кавычках
// подстановка выключена полностью.
//
// Сама одинарная кавычка внутри значения закрыла бы строку, поэтому она
// экранируется приёмом `'\”`: закрыть, вставить экранированную, открыть снова.
func QuoteEnvValue(value string) string {
	cleaned := strings.NewReplacer("\n", "", "\r", "", "\x00", "").Replace(value)
	return "'" + strings.ReplaceAll(cleaned, "'", `'\''`) + "'"
}

// RenderEnv собирает .env. Ключи сортируются, чтобы файл не менялся от порядка
// в ответе сервера и не давал ложных «изменений» при сравнении.
func RenderEnv(slug, domain string, env map[string]string) string {
	keys := make([]string, 0, len(env)+2)
	for k := range env {
		// Вход с сервера проверяем второй раз: агент живёт на чужой машине,
		// и одна ошибка на той стороне не должна становиться проблемой здесь.
		if SafeEnvKey.MatchString(k) && !IsReservedEnvKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# Файл создан агентом Scopework. Правки перезаписываются.\n")

	// Служебные переменные шаблона: имя проекта compose и домен.
	fmt.Fprintf(&b, "APP_SLUG=%s\n", QuoteEnvValue(slug))
	fmt.Fprintf(&b, "APP_DOMAIN=%s\n", QuoteEnvValue(domain))

	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, QuoteEnvValue(env[k]))
	}
	return b.String()
}

// Права, которые вообще бывают у конфигурационного файла.
//
// 0644 по умолчанию, а не 0600: файл монтируется в контейнер, и процесс внутри
// работает не от root. Собственные же файлы агента (.env) остаются 0600 —
// в них секреты, и в контейнер они попадают переменными, а не файлом.
//
// setuid, setgid и sticky не допускаются вовсе: бит, приехавший по сети, на
// файле, который потом монтируется в контейнер, — это не конфигурация.
var allowedFileModes = map[os.FileMode]bool{
	0o400: true,
	0o440: true,
	0o444: true,
	0o600: true,
	0o640: true,
	0o644: true,
	0o755: true,
}

// Имена, которыми распоряжается сам агент. Разреши их перезапись — и «какой
// compose реально запущен» перестанет определяться релизом, а .env с паролями
// можно будет подменить содержимым из желаемого состояния.
var agentOwnedNames = map[string]bool{
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
	"compose.yml":         true,
	"compose.yaml":        true,
	".env":                true,
}

// SafeFileComponent — один элемент пути. Узко и намеренно: пробелы, кавычки и
// управляющие символы в именах файлов конфигурации не нужны никому, а вот
// разбирать из-за них поведение compose пришлось бы долго.
func SafeFileComponent(part string) bool {
	if part == "" || part == "." || part == ".." {
		return false
	}
	if len(part) > 96 {
		return false
	}
	for _, r := range part {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// ResolveFilePath проверяет путь и возвращает его в очищенном виде.
//
// Проверяется КАЖДЫЙ элемент отдельно, а не только результат filepath.Clean:
// очистка сама по себе схлопывает `a/../../b` в `../b`, и полагаться на то,
// что вызывающий заметит ведущие `..`, — лишний шаг, на котором ошибаются.
func ResolveFilePath(appDir, raw string) (string, error) {
	path := strings.TrimSpace(raw)
	if path == "" {
		return "", fmt.Errorf("пустой путь файла шаблона")
	}
	// Обратный слеш разделителем на Linux не является, но его наличие почти
	// всегда означает путь, собранный не для этой системы.
	if strings.ContainsAny(path, "\\\x00") {
		return "", fmt.Errorf("недопустимый символ в пути %q", tail(path, 80))
	}
	if strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("абсолютный путь в файле шаблона: %q", tail(path, 80))
	}

	parts := strings.Split(path, "/")
	clean := make([]string, 0, len(parts))
	for _, part := range parts {
		// Пустые элементы дают "a//b" — не ошибка по смыслу, но и не то, что
		// пишет человек; приводим к каноническому виду молча.
		if part == "" {
			continue
		}
		if !SafeFileComponent(part) {
			return "", fmt.Errorf("недопустимый элемент пути %q в %q", tail(part, 40), tail(path, 80))
		}
		clean = append(clean, part)
	}
	if len(clean) == 0 {
		return "", fmt.Errorf("пустой путь файла шаблона")
	}
	if agentOwnedNames[strings.ToLower(clean[len(clean)-1])] && len(clean) == 1 {
		return "", fmt.Errorf("файл %q принадлежит агенту и не может прийти из шаблона", clean[0])
	}

	full := filepath.Join(appDir, filepath.Join(clean...))

	// Последний рубеж: даже если разбор выше окажется дырявым, результат
	// обязан остаться внутри каталога приложения.
	if full != appDir && !strings.HasPrefix(full, appDir+string(os.PathSeparator)) {
		return "", fmt.Errorf("путь выходит за пределы каталога приложения: %q", tail(path, 80))
	}
	return full, nil
}

func ParseFileMode(raw string) (os.FileMode, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0o644, nil
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("нечитаемые права файла %q", tail(value, 20))
	}
	mode := os.FileMode(parsed)
	if !allowedFileModes[mode] {
		return 0, fmt.Errorf("недопустимые права файла %q", tail(value, 20))
	}
	return mode, nil
}

// tail — хвост строки для текста ошибки: путь пришёл по сети и может быть
// сколь угодно длинным, а текст уходит в отчёт на платформу.
func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
