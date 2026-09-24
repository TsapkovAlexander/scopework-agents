package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Восстановление приложения из набора копий: правила, по которым идёт
// операция (ADR-0063).
//
// Сама операция живёт в backup.go. Здесь то, на чём она принимает решения:
// флаг «идёт восстановление», поиск тома базы, образ базы, на котором дамп не
// ложится, проверка набора до остановки стека и текст отказа psql. Отдельно — потому что каждое из них стоит
// данных клиента при ошибке, а внутри операции, которая гасит стек, они
// тестами не проверяются.

// --------------------------------------------------------------------------
// Флаг «идёт восстановление»
// --------------------------------------------------------------------------
//
// Сбой после `down` оставляет тома наполовину из копии, наполовину прежними.
// Следующий такт видит стек лежащим, и самовосстановление поднимает его на
// смешанных данных — приложение выглядит работающим, а вернуть прежнее
// содержимое очищенных томов уже нечем. Флаг стоит от начала операции до её
// удачного конца, и пока он есть, самовосстановление стек не трогает.
//
// ОТДЕЛЬНЫЙ ФАЙЛ, А НЕ ПОЛЕ В applied.json. Выкат переписывает запись
// приложения в applied.json целиком (`state.Apps[app.Slug] = AppliedRecord{…}`
// сразу после автоотката), и флаг, поставленный автооткатом, стёрся бы той же
// итерацией — ровно тогда, когда он нужен.

// restoreFlagPath — флаг одного приложения в каталоге состояния агента.
func restoreFlagPath(p Paths, slug string) string {
	return filepath.Join(p.StateDir, "restore-"+slug+".json")
}

// setRestoreFlag ставит флаг перед тем, как операция тронет стек.
//
// Имя набора в файле — для человека, который разбирает сорвавшееся
// восстановление на хосте: решению агента хватает самого файла.
func setRestoreFlag(p Paths, slug, set string) error {
	if !safeSlug.MatchString(slug) {
		return fmt.Errorf("недопустимый slug приложения: %q", slug)
	}
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(struct {
		Set string `json:"set"`
	}{Set: set})
	if err != nil {
		return err
	}
	// 0600: секретов во флаге нет, но он лежит рядом с ключом агента, и
	// расширять права в этом каталоге незачем.
	return writeFileAtomic(restoreFlagPath(p, slug), data, 0o600)
}

// hasRestoreFlag — прервано ли восстановление приложения.
//
// «Флага нет» — только когда файла нет. Любая другая ошибка означает «флаг
// есть»: ошибка в эту сторону оставляет стек лежать до решения человека, в
// обратную — поднимает его на смешанных томах. Содержимое не разбирается
// по той же причине: разбор мог бы только превратить «есть» в «нет», а битый
// или пустой файл — сомнение, при котором стек не поднимаем.
//
// Недопустимый slug к диску не ходит: флаг под таким slug поставить нельзя,
// запись отказывает раньше.
func hasRestoreFlag(p Paths, slug string) bool {
	if !safeSlug.MatchString(slug) {
		return false
	}
	_, err := os.Lstat(restoreFlagPath(p, slug))
	return !errors.Is(err, fs.ErrNotExist)
}

// clearRestoreFlag снимает флаг после удачного восстановления или выката.
// Флага не было — это не ошибка: снимать зовут и там, где его никто не ставил.
func clearRestoreFlag(p Paths, slug string) error {
	if !safeSlug.MatchString(slug) {
		return fmt.Errorf("недопустимый slug приложения: %q", slug)
	}
	if err := os.Remove(restoreFlagPath(p, slug)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// --------------------------------------------------------------------------
// Том базы
// --------------------------------------------------------------------------
//
// backup_spec называет сервис базы и тома, но не говорит, какой том чей. А
// ошибка в этой связи стоит очистки не того тома: том базы при восстановлении
// очищается и не распаковывается, базу возвращает дамп. Поэтому связь берётся
// из нормализованной модели compose, и всё, кроме однозначного случая, —
// отказ до остановки стека с названием случая.
//
// Каталог данных по другому пути (PGDATA в подкаталоге, свой образ) тоже
// получает отказ: правило расширяется явно, а не догадкой.

// postgresDataDir — каталог данных официального образа postgres. Том базы у
// всех шаблонов каталога смонтирован именно сюда.
const postgresDataDir = "/var/lib/postgresql/data"

// databaseVolume возвращает КЛЮЧ тома базы из compose; полное имя тома docker
// собирает volumeName(slug, ключ).
//
// Тексты отказов называют случай и сервис, но не значения из модели: отказ
// уезжает в журнал восстановлений, который читает любой участник проекта, а в
// описании стека из набора стоят пути хоста и имена томов как есть. Значений
// переменных там нет и быть не может: модель всегда снимается с
// `--no-interpolate` (composemodel.go), и `${…}` доезжают сюда нераскрытыми —
// наружу вышло бы имя переменной клиента.
func databaseVolume(model map[string]any, spec BackupSpec, pg PostgresBackup) (string, error) {
	services, _ := model["services"].(map[string]any)
	service, ok := services[pg.Service].(map[string]any)
	if !ok {
		return "", fmt.Errorf("сервис базы %s не найден в описании стека из набора копий", pg.Service)
	}
	mounts, ok := service["volumes"].([]any)
	if !ok {
		return "", fmt.Errorf("у сервиса базы %s нет списка монтирований в описании стека из набора копий", pg.Service)
	}

	for _, raw := range mounts {
		// Нормализованная модель пишет монтирования только объектами. Строка
		// значит, что модель не та, что мы ждём, и её выводам не верим целиком —
		// в том числе про соседние записи.
		mount, ok := raw.(map[string]any)
		if !ok {
			return "", fmt.Errorf("у сервиса базы %s монтирование записано строкой, а не объектом: "+
				"связь тома с каталогом данных из такой записи не читается", pg.Service)
		}
		if target, _ := mount["target"].(string); path.Clean(target) != postgresDataDir {
			continue
		}

		switch kind, _ := mount["type"].(string); kind {
		case "volume":
		case "bind":
			return "", fmt.Errorf("у сервиса базы %s каталог данных смонтирован с хоста (bind), а не томом docker",
				pg.Service)
		default:
			return "", fmt.Errorf("у сервиса базы %s каталог данных смонтирован не томом docker", pg.Service)
		}

		// Имя уходит в аргументы docker и в очистку тома. `${...}` без
		// подстановки и анонимный том сюда не проходят.
		source, _ := mount["source"].(string)
		if !safeIdent.MatchString(source) {
			return "", fmt.Errorf("у сервиса базы %s том каталога данных без допустимого имени", pg.Service)
		}
		for _, declared := range spec.Volumes {
			if declared == source {
				return source, nil
			}
		}
		return "", fmt.Errorf("у сервиса базы %s том каталога данных не объявлен в backup_spec.volumes",
			pg.Service)
	}

	return "", fmt.Errorf("у сервиса базы %s нет монтирования в %s: том базы не определить",
		pg.Service, postgresDataDir)
}

// --------------------------------------------------------------------------
// Образ базы, на котором дамп не ложится (ADR-0063, решение 9)
// --------------------------------------------------------------------------
//
// Прогон 11.09.2026 на шаблоне Supabase (supabase/postgres:17.6.1.136): на
// чистой базе после init-скриптов образа нет роли supabase_realtime_admin — её
// создаёт сервис realtime своими миграциями при первом старте, а дамп одной
// базы ролей не переносит. psql встаёт на первом `ALTER … OWNER TO` этой роли,
// и транзакция откатывается целиком. Всё остальное — расширения, событийные
// триггеры, схемы auth и storage — на чистую базу ложится.
//
// Отказ — до `down`: восстановление, которое сорвётся на дампе, оставило бы
// приложение лежать с очищенными томами.
//
// Признак — образ сервиса базы в описании стека из набора, а не имя шаблона:
// набор своего шаблона не хранит, а дамп не ложится из-за того, что приносит
// именно этот образ и его стек.

// unsupportedDatabaseImage — образ базы, которую дамп не возвращает. Подстрокой,
// а не началом: образ приходит и с реестром впереди (public.ecr.aws/…).
const unsupportedDatabaseImage = "supabase/postgres"

// databaseImageRefusal — отказ восстанавливать базу на образе, где дамп не
// ложится.
//
// «Supabase» в тексте с заглавной не для красоты: `supabase` — значение
// DASHBOARD_USERNAME по умолчанию у шаблона, и затирание значений переменных на
// выходе RestoreBackup превратило бы строчное слово в звёздочки.
func databaseImageRefusal(model map[string]any, pg PostgresBackup) error {
	services, _ := model["services"].(map[string]any)
	service, _ := services[pg.Service].(map[string]any)
	image, _ := service["image"].(string)
	if !strings.Contains(image, unsupportedDatabaseImage) {
		return nil
	}
	return fmt.Errorf("восстановление базы %s из копии на образе базы Supabase не поддерживается: "+
		"роли, которые сервисы стека создают при первом запуске, в дамп не входят, и на чистую базу "+
		"он не ложится. Стек не останавливался, данные не тронуты", pg.Database)
}

// composeModelOfSet снимает нормализованную модель стека с каталога НАБОРА
// копий, а не работающего приложения: стек вернётся описанием из копии, и
// ключи томов у релизов могут разниться.
//
// Модель живёт только в памяти — ни на диск, ни в журнал.
func composeModelOfSet(ctx context.Context, setDir string) (map[string]any, error) {
	raw, err := composeConfigJSON(ctx, setDir, filepath.Join(setDir, ".env"))
	if err != nil {
		return nil, err
	}
	return parseComposeModel(raw)
}

// --------------------------------------------------------------------------
// Проверка набора до остановки стека
// --------------------------------------------------------------------------
//
// Всё, что проверяется без стека, проверяется раньше `down`: битый архив или
// отсутствующий дамп, найденные после, — уже простой с очищенными томами.

// volumeOfArchive — ключ тома по имени архива в наборе, `vol-<ключ>.tar.gz`.
// Второй результат — архив ли это вообще; годность ключа проверяет вызывающий.
func volumeOfArchive(name string) (string, bool) {
	if !strings.HasPrefix(name, "vol-") || !strings.HasSuffix(name, ".tar.gz") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(name, "vol-"), ".tar.gz"), true
}

// checkRestoreSet проверяет набор копий на диске и возвращает имена архивов
// томов в нём.
//
// Базу возвращает только дамп, поэтому набор без годного дампа объявленной
// базы — отказ: пофайловая копия тома снята с работающего Postgres и
// согласованной не является.
func checkRestoreSet(setDir string, spec BackupSpec) ([]string, error) {
	// Сервис базы входит в путь к дампу, ключ тома — в команду оболочки.
	if err := spec.validate(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(setDir)
	if err != nil {
		return nil, fmt.Errorf("набор копий недоступен: %w", err)
	}

	var archives []string
	hasDump := false
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "db-") && strings.HasSuffix(name, ".sql") {
			hasDump = true
			continue
		}
		vol, ok := volumeOfArchive(name)
		if !ok {
			continue
		}
		if !safeIdent.MatchString(vol) {
			return nil, fmt.Errorf("недопустимое имя тома в наборе копий: %q", tail(vol, 60))
		}
		archives = append(archives, name)
	}

	// Набор своего backup_spec не хранит, а релиз мог его потерять: правка
	// переменных или домена вставляет релиз без описания копии. Без объявленной
	// базы дамп не применится, и том базы вернулся бы пофайловой копией —
	// восстановление отчиталось бы успехом с несогласованной базой.
	if hasDump && len(spec.Postgres) == 0 {
		return nil, fmt.Errorf("в наборе копий есть дамп базы, а в текущем релизе приложения база " +
			"не объявлена (backup_spec без postgres): вернуть её пофайловой копией тома нельзя, " +
			"нужен релиз, в котором база объявлена")
	}

	for _, pg := range spec.Postgres {
		name := "db-" + pg.Service + ".sql"
		// Lstat: ссылка на файл вне набора — не дамп из копии.
		info, err := os.Lstat(filepath.Join(setDir, name))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("в наборе копий нет дампа базы %s (%s)", pg.Database, name)
		case err != nil:
			return nil, fmt.Errorf("дамп базы %s в наборе копий (%s) не читается: %w", pg.Database, name, err)
		case !info.Mode().IsRegular():
			return nil, fmt.Errorf("дамп базы %s в наборе копий (%s) — не обычный файл", pg.Database, name)
		case info.Size() == 0:
			return nil, fmt.Errorf("дамп базы %s в наборе копий (%s) пуст", pg.Database, name)
		}
	}

	return archives, nil
}

// verifyVolumeArchive читает архив тома целиком, не распаковывая его.
//
// Список файлов уходит в /dev/null внутри контейнера: содержимое тома клиента
// в память агента не попадает, а набор смонтирован только на чтение.
//
// Имя архива стоит в `sh -c` строкой, и это безопасно ТОЛЬКО потому, что ключ
// тома прошёл safeIdent: в нём нет ни пробелов, ни символов оболочки. Проверка
// здесь же, а не только у вызывающего: строку для оболочки собирает эта функция.
func verifyVolumeArchive(ctx context.Context, setDir, archive string) error {
	if vol, ok := volumeOfArchive(archive); !ok || !safeIdent.MatchString(vol) {
		return fmt.Errorf("недопустимое имя тома в наборе копий: %q", tail(archive, 60))
	}

	cmd := newDockerCmd(ctx, "", "run", "--rm",
		"-v", setDir+":/from:ro",
		"alpine:3.21",
		"sh", "-c", "tar tzf /from/"+archive+" > /dev/null")
	if err := runStreaming(cmd, io.Discard); err != nil {
		return fmt.Errorf("архив %s в наборе копий не читается: %w", archive, err)
	}
	return nil
}

// --------------------------------------------------------------------------
// Текст отказа psql
// --------------------------------------------------------------------------
//
// Отчёт о восстановлении ложится в журнал (deploy_app_restores), который
// читает любой участник проекта. А в выводе psql рядом с причиной лежат данные
// клиента: у COPY строка данных — в CONTEXT, у нарушения ключа значение — в
// DETAIL, у неверного значения — прямо в строке ERROR. Поэтому до отчёта
// доезжает одна строка причины, и всё в кавычках в ней закрыто, кроме имён
// объектов: имя нужно для разбора, а неизвестное по умолчанию закрыто.

// psqlFailureMaxBytes — предел текста отказа в отчёте.
const psqlFailureMaxBytes = 200

// psqlStderrTailBytes — сколько хвоста stderr psql держать в памяти. Причина
// идёт последней строкой (ON_ERROR_STOP), а сколько psql напечатает до неё,
// заранее не известно: это вывод чужого дампа, и предела у него нет.
const psqlStderrTailBytes = 64 << 10

// fromFirstFullLine — хвост вывода без первой строки, если буфер переполнялся.
//
// Строка, обрезанная спереди, могла начаться посреди значения клиента, а её
// начало — DETAIL: или CONTEXT: — потеряно, и psqlFailure не узнал бы в ней
// продолжение сообщения.
func fromFirstFullLine(tail string, max int) string {
	if len(tail) < max {
		return tail
	}
	if i := strings.IndexByte(tail, '\n'); i >= 0 {
		return tail[i+1:]
	}
	return ""
}

// psqlSourcePrefix — метка, которую psql ставит перед сообщением сервера:
// `psql:<stdin>:48: ERROR:  …`. Номер строки дампа причину не объясняет.
var psqlSourcePrefix = regexp.MustCompile(`^psql:[^:\s]*:[0-9]+:\s*`)

// psqlContinuations — строки, продолжающие сообщение. В них текст запроса и
// данные, а не причина, поэтому в отчёт они не идут никогда — даже если внутри
// данных встретилось слово ERROR.
var psqlContinuations = []string{"DETAIL:", "CONTEXT:", "HINT:", "LINE ", "QUERY:", "WHERE:"}

// quotedNameWords — слова, после которых PostgreSQL берёт в кавычки имя
// объекта, а не значение: `relation "public.orders" does not exist`.
var quotedNameWords = map[string]bool{
	"relation": true, "table": true, "column": true, "constraint": true, "schema": true,
	"role": true, "user": true, "database": true, "extension": true, "function": true,
	"type": true, "index": true, "sequence": true, "view": true, "trigger": true,
	"policy": true, "publication": true, "encoding": true, "collation": true,
	"language": true, "tablespace": true, "operator": true, "domain": true,
	"server": true, "parameter": true,
}

// psqlFailure сводит stderr psql к одной строке для отчёта.
//
// Берётся первая строка с ERROR или FATAL, от слова серьёзности до конца.
// Нет такой (отказал сам `docker compose exec`) — последняя содержательная
// строка. Нет и её — пустая строка: вызывающий скажет «psql завершился с
// ошибкой» сам. Затирание значений переменных идёт после закрытия кавычек, а
// обрезка — последней: обрезанное значение переменной уже не нашлось бы.
func psqlFailure(stderr string, values map[string]string) string {
	var lines []string
	for _, line := range strings.Split(stderr, "\n") {
		line = psqlSourcePrefix.ReplaceAllString(strings.TrimSpace(line), "")
		if line == "" || isPsqlContinuation(line) {
			continue
		}
		lines = append(lines, line)
	}

	reason := ""
	for _, line := range lines {
		if at := psqlSeverityIndex(line); at >= 0 {
			reason = line[at:]
			break
		}
	}
	if reason == "" {
		for i := len(lines) - 1; i >= 0; i-- {
			if !strings.Contains(lines[i], "NOTICE:") && !strings.Contains(lines[i], "WARNING:") &&
				!strings.Contains(lines[i], "INFO:") {
				reason = lines[i]
				break
			}
		}
	}
	if reason == "" {
		return ""
	}

	return cutAtRune(redactSecrets(maskQuotedValues(reason), values), psqlFailureMaxBytes)
}

func isPsqlContinuation(line string) bool {
	for _, prefix := range psqlContinuations {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// psqlSeverityIndex — где в строке начинается ERROR: или FATAL:.
//
// Не обязательно в начале: отказ подключения psql печатает как
// `psql: error: connection to server … failed: FATAL:  …`, и причина — после
// адреса сокета.
func psqlSeverityIndex(line string) int {
	at := -1
	for _, token := range []string{"ERROR:", "FATAL:"} {
		if i := strings.Index(line, token); i >= 0 && (at < 0 || i < at) {
			at = i
		}
	}
	return at
}

// maskQuotedValues закрывает содержимое кавычек, кроме имён объектов.
//
// Значение закрывается до ПОСЛЕДНЕЙ кавычки строки, а не до ближайшей:
// PostgreSQL вставляет значение в текст как есть и кавычки внутри не
// экранирует. Разбор по парам на `"12"ivan@example.com"` выпустил бы хвост
// значения наружу. Цена — имя объекта, стоящее в строке после значения,
// закроется вместе с ним; в сообщениях PostgreSQL такого порядка нет.
func maskQuotedValues(s string) string {
	var b strings.Builder
	for {
		open := strings.IndexByte(s, '"')
		if open < 0 {
			b.WriteString(s)
			return b.String()
		}
		b.WriteString(s[:open])
		rest := s[open+1:]

		if quotesObjectName(s[:open]) {
			if end := strings.IndexByte(rest, '"'); end >= 0 {
				b.WriteString(s[open : open+end+2])
				s = rest[end+1:]
				continue
			}
		}

		b.WriteString(`"` + redactedMarker + `"`)
		end := strings.LastIndexByte(rest, '"')
		if end < 0 {
			return b.String()
		}
		s = rest[end+1:]
	}
}

// quotesObjectName — стоит ли перед кавычкой слово из quotedNameWords, отделённое
// пробелом с обеих сторон. `integer: "…"` и `user: "…"` (значение перечисления
// с таким именем) именем не считаются: двоеточие — признак значения.
func quotesObjectName(before string) bool {
	word, ok := strings.CutSuffix(before, " ")
	if !ok {
		return false
	}
	start := len(word)
	for start > 0 && word[start-1] >= 'a' && word[start-1] <= 'z' {
		start--
	}
	if start == 0 || word[start-1] != ' ' {
		return false
	}
	return quotedNameWords[word[start:]]
}

// cutAtRune обрезает текст до max байт, не разрывая руну, и помечает обрезку.
// truncateRunes из threat.go считает символы, а предел отчёта — в байтах.
func cutAtRune(s string, max int) string {
	if len(s) <= max {
		return s
	}
	const ellipsis = "…"
	cut := max - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}
