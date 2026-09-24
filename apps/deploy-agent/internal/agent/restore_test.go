package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// --------------------------------------------------------------------------
// Восстановление из копии: что именно возвращается (задача 8.2)
// --------------------------------------------------------------------------
//
// Тесты в export_test.go проверяют отказы НА ВХОДЕ. Здесь — требования к самой
// операции, без настоящего docker, но через настоящий код агента. Вернулись ли
// данные на самом деле, поддельный docker сказать не может: psql у него ничего
// не вливает. Это проверяет restore_docker_test.go против настоящего Docker
// (тег dockersmoke).
//
// ШОВ — ПОДДЕЛЬНЫЙ `docker` В PATH, А НЕ ПОЛЕ С ФУНКЦИЕЙ. newDockerCmd и
// restoreVolume ищут двоичный файл по PATH, а dockerEnv() пробрасывает PATH
// дочернему процессу. Значит подменить docker можно, не заводя в боевом коде
// ни одного шва ради теста (см. комментарий к runStreaming), и проверка не
// зависит от того, как исправление разложит операцию по функциям.
//
// Требования общие для любого варианта исправления:
//   - набор с `db-<сервис>.sql` возвращает базу ИЗ ДАМПА: архив тома снят с
//     работающего Postgres и согласованным снимком не является;
//   - здоровья ждём столько же, сколько выкат (apply_spec.waitTimeoutSeconds);
//   - сорвавшееся восстановление не поднимается самовосстановлением на
//     смешанных данных;
//   - потерянный отчёт не повторяет разрушительную операцию второй раз.

// fakeDockerCall — один вызов поддельного docker: аргументы и то, что пришло
// на stdin. stdin нужен, чтобы увидеть дамп, влитый потоком в psql.
type fakeDockerCall struct {
	Args  []string
	Stdin []byte
}

func (c fakeDockerCall) line() string { return strings.Join(c.Args, " ") }

func (c fakeDockerCall) hasArg(arg string) bool {
	for _, a := range c.Args {
		if a == arg {
			return true
		}
	}
	return false
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// installFakeDocker кладёт в PATH поддельный docker и возвращает чтение журнала
// его вызовов.
//
// failAfterDown — подстрока аргументов, на которой docker откажет, но ТОЛЬКО
// после того, как стек уже снимали (`down`). Отказ до снятия приложение не
// трогает, и проверять на нём поведение «после сбоя посреди восстановления»
// бессмысленно: хорошее исправление вправе проверять архивы до `down`.
//
// Каталог журнала вшит в текст скрипта, а не передан переменной окружения:
// dockerEnv() отрезает дочернему процессу всё, кроме PATH, HOME и
// DOCKER_CONFIG.
//
// На три вопроса docker отвечает правдоподобно, а не пустотой: состав
// сервисов (`config --services`), нормализованная модель (`config … --format
// json`) и состояние контейнеров (`ps --all`). Их задают поиск тома базы по
// описанию из набора и проверка устойчивости после подъёма. Пустой ответ
// роняет восстановление отказом разбора — раньше, чем тест дойдёт до того, что
// проверяет. Модель — стек n8n: том базы в каталоге данных Postgres, том
// приложения рядом.
func installFakeDocker(t *testing.T, failAfterDown string) func() []fakeDockerCall {
	t.Helper()
	return installFakeDockerModel(t, failAfterDown, fakeDockerN8nModel)
}

// fakeDockerN8nModel — нормализованная модель стека n8n, которой по умолчанию
// отвечает поддельный docker.
const fakeDockerN8nModel = `{"services":{` +
	`"db":{"volumes":[{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data"}]},` +
	`"app":{"volumes":[{"type":"volume","source":"app-data","target":"/home/node/.n8n"}]}},` +
	`"volumes":{"db-data":{},"app-data":{}}}`

// installFakeDockerModel — то же с заданной моделью: ей поддельный docker
// отвечает на `config … --format json`.
func installFakeDockerModel(t *testing.T, failAfterDown, model string) func() []fakeDockerCall {
	t.Helper()

	bin := t.TempDir()
	logDir := t.TempDir()

	script := "#!/bin/sh\n" +
		"log=" + shellQuote(logDir) + "\n" +
		"fail=" + shellQuote(failAfterDown) + "\n" +
		"model=" + shellQuote(model) + "\n" +
		`n=$(cat "$log/count" 2>/dev/null || echo 0)` + "\n" +
		`n=$((n + 1))` + "\n" +
		`echo "$n" > "$log/count"` + "\n" +
		`for a in "$@"; do printf '%s\000' "$a"; done > "$log/$n.args"` + "\n" +
		`cat > "$log/$n.stdin"` + "\n" +
		`for a in "$@"; do [ "$a" = down ] && : > "$log/down-seen"; done` + "\n" +
		`if [ -n "$fail" ] && [ -f "$log/down-seen" ]; then` + "\n" +
		`  case "$*" in *"$fail"*) echo "поддельный отказ docker" >&2; exit 1;; esac` + "\n" +
		`fi` + "\n" +
		`case " $* " in` + "\n" +
		`  *" config "*"--services "*) printf 'db\napp\n';;` + "\n" +
		`  *" config "*"--format json "*) printf '%s\n' "$model";;` + "\n" +
		`  *" ps --all "*) printf 'db\trunning\thealthy\t0\napp\trunning\t\t0\n';;` + "\n" +
		`esac` + "\n" +
		"exit 0\n"

	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	return func() []fakeDockerCall {
		raw, err := os.ReadFile(filepath.Join(logDir, "count"))
		if err != nil {
			return nil
		}
		n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		calls := make([]fakeDockerCall, 0, n)
		for i := 1; i <= n; i++ {
			argsRaw, _ := os.ReadFile(filepath.Join(logDir, strconv.Itoa(i)+".args"))
			stdin, _ := os.ReadFile(filepath.Join(logDir, strconv.Itoa(i)+".stdin"))
			args := strings.Split(string(argsRaw), "\x00")
			if len(args) > 0 && args[len(args)-1] == "" {
				args = args[:len(args)-1]
			}
			calls = append(calls, fakeDockerCall{Args: args, Stdin: stdin})
		}
		return calls
	}
}

func describeCalls(calls []fakeDockerCall) string {
	var b strings.Builder
	for i, c := range calls {
		b.WriteString("  ")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(": docker ")
		b.WriteString(c.line())
		if len(c.Stdin) > 0 {
			b.WriteString("  <stdin ")
			b.WriteString(strconv.Itoa(len(c.Stdin)))
			b.WriteString(" байт>")
		}
		b.WriteString("\n")
	}
	return b.String()
}

const restoreTestSet = "20260910-120000"

// writeRestoreFixture раскладывает на диске то, что застаёт восстановление:
// каталог работающего приложения и набор копий в формате CreateBackup.
func writeRestoreFixture(t *testing.T, p Paths, slug string, setFiles map[string]string) {
	t.Helper()

	appDir := p.appDir(slug)
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"docker-compose.yml": "# описание текущего релиза\nservices: {}\n",
		".env":               "APP_SLUG='" + slug + "'\n",
	} {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	setDir := filepath.Join(p.backupsDir(slug), restoreTestSet)
	if err := os.MkdirAll(setDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"docker-compose.yml": "# описание из копии\nservices: {}\n",
		".env":               "APP_SLUG='" + slug + "'\n",
	}
	for name, content := range setFiles {
		files[name] = content
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(setDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Набор, в котором есть согласованный дамп, обязан вернуть базу ИЗ НЕГО.
//
// Сегодня RestoreBackup берёт из набора только `vol-*.tar.gz`: том базы
// возвращается пофайловой копией, снятой с работающего Postgres, а
// `db-<сервис>.sql` не читается вовсе. У приложения, чья база объявлена в
// `postgres`, а том — нет, «удачное» восстановление оставляет базу прежней.
//
// Проверяется исход, а не способ: дамп дошёл до psql (или pg_restore) потоком
// либо по имени файла, в объявленную в задании базу, и ДО последнего подъёма
// стека — иначе приложение успеет стартовать на старых данных.
func TestRunTaskRestoreAppliesDatabaseDump(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}

	dump := "-- дамп из копии\nCREATE TABLE marker_from_backup (id int);\n"
	writeRestoreFixture(t, p, "n8n", map[string]string{
		"db-db.sql":           dump,
		"vol-db-data.tar.gz":  "архив тома базы, снятый с работающего Postgres",
		"vol-app-data.tar.gz": "архив тома приложения",
	})
	apps := []DesiredApp{{
		Slug: "n8n",
		BackupSpec: BackupSpec{
			Postgres: []PostgresBackup{{Service: "db", User: "appuser", Database: "appdb"}},
			Volumes:  []string{"db-data", "app-data"},
		},
		ApplySpec: ApplySpec{StableChecks: 1},
	}}

	got, err := runRestoreTask(t, p, apps, restoreTestSet)
	if err != nil {
		t.Fatalf("восстановление упало: %v (отчёт: %q)\nвызовы:\n%s", err, got.Error, describeCalls(calls()))
	}

	log := calls()
	applied := -1
	for i, c := range log {
		line := c.line()
		if !strings.Contains(line, "psql") && !strings.Contains(line, "pg_restore") {
			continue
		}
		if string(c.Stdin) != dump && !strings.Contains(line, "db-db.sql") {
			continue
		}
		if !strings.Contains(line, "appdb") {
			t.Errorf("дамп влит не в объявленную базу appdb: docker %s", line)
		}
		applied = i
	}
	if applied < 0 {
		t.Fatalf("дамп db-db.sql из набора не влит в базу — она осталась прежней или "+
			"вернулась несогласованной пофайловой копией.\nвызовы docker:\n%s", describeCalls(log))
	}

	lastUp := -1
	for i, c := range log {
		if c.hasArg("up") {
			lastUp = i
		}
	}
	if lastUp < applied {
		t.Errorf("стек поднят до вливания дампа (подъём на шаге %d, дамп на шаге %d):\n%s",
			lastUp, applied, describeCalls(log))
	}
}

// Здоровья после восстановления ждём столько же, сколько после выката.
//
// Выкат берёт срок из шаблона (apply_spec.waitTimeoutSeconds, у Supabase —
// 900 с), восстановление зашило 180. Стек, которому на старт нужно пять минут,
// получает «не поднялся после отката», хотя поднялся бы: отчёт врёт, а
// восстановление выглядит сломанным там, где сломан только срок.
func TestRunTaskRestoreWaitsAsLongAsDeploy(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}

	writeRestoreFixture(t, p, "n8n", map[string]string{
		"vol-app-data.tar.gz": "архив тома приложения",
	})
	apps := []DesiredApp{{
		Slug:       "n8n",
		BackupSpec: BackupSpec{Volumes: []string{"app-data"}},
		ApplySpec:  ApplySpec{WaitTimeoutSeconds: 900, StableChecks: 1},
	}}

	if _, err := runRestoreTask(t, p, apps, restoreTestSet); err != nil {
		t.Fatalf("восстановление упало: %v", err)
	}

	log := calls()
	var timeouts []string
	for _, c := range log {
		for i, a := range c.Args {
			switch {
			case a == "--wait-timeout" && i+1 < len(c.Args):
				timeouts = append(timeouts, c.Args[i+1])
			case strings.HasPrefix(a, "--wait-timeout="):
				timeouts = append(timeouts, strings.TrimPrefix(a, "--wait-timeout="))
			}
		}
	}
	if len(timeouts) == 0 {
		t.Fatalf("подъём после восстановления не ждёт здоровья вовсе:\n%s", describeCalls(log))
	}
	for _, v := range timeouts {
		if v != "900" {
			t.Errorf("срок ожидания здоровья %s с, а шаблон приложения требует 900:\n%s", v, describeCalls(log))
		}
	}
}

// Сорвавшееся восстановление не поднимается самовосстановлением.
//
// Сбой после `down` оставляет тома наполовину из копии, наполовину прежними.
// Следующий такт видит стек без контейнеров, и recover.go делает `up -d` — до
// пяти попыток. Приложение поднимается на смешанных данных и выглядит
// работающим; вернуть прежнее содержимое очищенных томов уже нечем.
func TestRecoveryDoesNotRaiseStackAfterFailedRestore(t *testing.T) {
	calls := installFakeDocker(t, "vol-app-data.tar.gz")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}

	writeRestoreFixture(t, p, "n8n", map[string]string{
		"vol-app-data.tar.gz": "архив тома приложения",
	})
	apps := []DesiredApp{{Slug: "n8n", BackupSpec: BackupSpec{Volumes: []string{"app-data"}}}}

	// Приложение было развёрнуто и здорово до нажатия «Восстановить».
	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		"n8n": {ReleaseID: "release-1", Status: "healthy"},
	}}); err != nil {
		t.Fatal(err)
	}

	got, err := runRestoreTask(t, p, apps, restoreTestSet)
	if err == nil || got.Error == "" {
		t.Fatalf("поддельный отказ распаковки не сорвал восстановление: err=%v, отчёт=%q\n%s",
			err, got.Error, describeCalls(calls()))
	}
	before := len(calls())

	// Следующий такт: опрос здоровья видит снятый стек.
	if err := RecoverUnhealthy(context.Background(), p, apps,
		[]AppHealth{{Slug: "n8n", Status: HealthDown}}); err != nil {
		t.Fatalf("самовосстановление упало: %v", err)
	}

	for _, c := range calls()[before:] {
		if c.hasArg("up") || c.hasArg("start") {
			t.Errorf("самовосстановление подняло стек после сорвавшегося восстановления — "+
				"на смешанных данных: docker %s", c.line())
		}
	}
}

// Потерянный отчёт не повторяет восстановление.
//
// Отметка о выполненном задании пишется только после принятого отчёта. Отчёт
// не доехал — задание остаётся pending, и следующий такт снова гасит стек и
// перезаписывает тома: всё, что приложение записало между двумя прогонами,
// теряется. Повторить надо ОТЧЁТ, а не операцию.
func TestRunTaskRestoreNotRepeatedWhenReportLost(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}

	writeRestoreFixture(t, p, "n8n", map[string]string{
		"vol-app-data.tar.gz": "архив тома приложения",
	})
	apps := []DesiredApp{{
		Slug:       "n8n",
		BackupSpec: BackupSpec{Volumes: []string{"app-data"}},
		ApplySpec:  ApplySpec{StableChecks: 1},
	}}

	var requests atomic.Int32
	var lastReport restoreReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if requests.Add(1) == 1 {
			// Первый отчёт теряется: сеть, отказ ручки, перезапуск платформы.
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.Unmarshal(raw, &lastReport)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(srv.Close)

	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(srv.URL, "test")
	task := HostTask{ID: "task-1", Kind: "restore", Project: "n8n", BackupSet: restoreTestSet}

	if err := RunTask(t.Context(), client, id, p, task, apps, nil); err == nil {
		t.Fatal("отчёт не доехал, а задание считается закрытым")
	}
	// Такт спустя платформа выдаёт то же задание.
	if err := RunTask(t.Context(), client, id, p, task, apps, nil); err != nil {
		t.Fatalf("повторная выдача задания упала: %v", err)
	}

	downs := 0
	for _, c := range calls() {
		if c.hasArg("down") {
			downs++
		}
	}
	if downs != 1 {
		t.Errorf("стек гасился %d раз(а) на одно задание — восстановление повторено целиком "+
			"и стёрло записанное между прогонами:\n%s", downs, describeCalls(calls()))
	}
	if requests.Load() < 2 || lastReport.Error != "" || lastReport.Result.Set != restoreTestSet {
		t.Errorf("исход первого прогона так и не доехал до платформы: запросов %d, отчёт %+v",
			requests.Load(), lastReport)
	}
}
