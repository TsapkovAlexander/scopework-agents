package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
)

// --------------------------------------------------------------------------
// Набор копий проходит политику compose до остановки стека (ADR-0092, решение 14)
// --------------------------------------------------------------------------
//
// Восстановление поднимает compose и .env из набора, а набор — файлы с диска
// хоста: их мог снять автооткат с отвергнутого описания (запись в applyOne идёт
// до проверки) или положить кто угодно с доступом к каталогу копий. Без
// проверки это второй путь поднять на хосте то, что выкат отверг бы.
//
// Отказ обязан прийти ДО флага восстановления и `down`: прежний стек работает,
// его файлы на диске не тронуты, тома не очищены.

// restoreGuardModel — модель набора, которую выкат отверг бы: privileged.
const restoreGuardModel = `{"services":{"app":{"image":"n8nio/n8n","privileged":true,` +
	`"volumes":[{"type":"volume","source":"app-data","target":"/home/node/.n8n"}]}},` +
	`"volumes":{"app-data":{}}}`

func restoreGuardSetDir(p Paths) string {
	return filepath.Join(p.backupsDir("n8n"), restoreTestSet)
}

// appFilesSnapshot — файлы стека в каталоге приложения, как их застало
// восстановление.
func appFilesSnapshot(t *testing.T, p Paths) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{"docker-compose.yml", ".env"} {
		raw, err := os.ReadFile(filepath.Join(p.appDir("n8n"), name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(raw)
	}
	return out
}

// assertStackUntouched — отказ пришёл до того, как стек тронули: ни `down`, ни
// подъёма, ни очистки тома, файлы стека прежние, флага нет.
func assertStackUntouched(t *testing.T, p Paths, calls []fakeDockerCall, before map[string]string) {
	t.Helper()
	for _, c := range calls {
		last := ""
		if len(c.Args) > 0 {
			last = c.Args[len(c.Args)-1]
		}
		if c.hasArg("down") || c.hasArg("up") || (c.hasArg("run") && c.hasArg("--rm")) ||
			strings.Contains(last, "-delete") {
			t.Errorf("стек тронут до отказа: docker %s\nвызовы:\n%s", c.line(), describeCalls(calls))
		}
	}
	after := appFilesSnapshot(t, p)
	for name, content := range before {
		if after[name] != content {
			t.Errorf("%s каталога приложения переписан до отказа: было %q, стало %q", name, content, after[name])
		}
	}
	if hasRestoreFlag(p, "n8n") {
		t.Error("флаг восстановления поставлен, хотя стек не трогали")
	}
}

func TestRestoreRefusesSetOutsidePolicy(t *testing.T) {
	calls := installFakeDockerModel(t, "", restoreGuardModel)
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	before := appFilesSnapshot(t, p)

	err := RestoreBackup(context.Background(), p, volumesOnlyApp(), restoreGuardSetDir(p))
	if err == nil {
		t.Fatalf("набор с privileged принят:\n%s", describeCalls(calls()))
	}
	for _, want := range []string{restoreTestSet, "отклонено", "privileged", "стек не останавливался"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в отказе нет %q: %v", want, err)
		}
	}
	assertStackUntouched(t, p, calls(), before)
}

// Отказ задания доезжает до платформы с причиной и закрывает задание: иначе
// оно висело бы в pending, а агент гасил бы стек на каждой выдаче.
func TestRunTaskRestoreOutsidePolicyReportsAndKeepsStack(t *testing.T) {
	calls := installFakeDockerModel(t, "", restoreGuardModel)
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	before := appFilesSnapshot(t, p)

	got, err := runRestoreTask(t, p, []DesiredApp{volumesOnlyApp()}, restoreTestSet)
	if err == nil {
		t.Fatalf("задание с набором вне политики выполнено:\n%s", describeCalls(calls()))
	}
	if got.Error == "" || !strings.Contains(got.Error, "privileged") {
		t.Errorf("платформа не узнала, какое правило нарушено: %q", got.Error)
	}
	mark, raw := readTaskMark(t, p)
	if _, left := mark["unreported"]; left || mark["task_id"] != "task-1" {
		t.Errorf("отказ не закрыл задание: %s", raw)
	}
	assertStackUntouched(t, p, calls(), before)
}

// env_file нормализация стирает: ссылку на чужой .env видно только в тексте
// compose набора. Модель при этом чистая.
func TestRestoreRefusesEnvFileEscapeInSet(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{
		"vol-app-data.tar.gz": "архив",
		"docker-compose.yml":  "services:\n  app:\n    image: n8nio/n8n\n    env_file: /opt/other/.env\n",
	})
	before := appFilesSnapshot(t, p)

	err := RestoreBackup(context.Background(), p, volumesOnlyApp(), restoreGuardSetDir(p))
	if err == nil || !strings.Contains(err.Error(), "env_file") {
		t.Fatalf("ссылка на чужой .env в наборе не отвергнута: %v\n%s", err, describeCalls(calls()))
	}
	assertStackUntouched(t, p, calls(), before)
}

// .env набора обязан быть тем, что агент сам пишет: APP_SLUG — своего
// приложения, ключей compose и docker нет. Иначе имя проекта или файл стека
// уходят мимо проверенного, а `up --remove-orphans` сносит контейнеры соседа.
func TestRestoreRefusesSetEnvOutsideRenderRule(t *testing.T) {
	cases := map[string]struct {
		env  string
		want string
	}{
		"COMPOSE_PROJECT_NAME": {env: "APP_SLUG='n8n'\nCOMPOSE_PROJECT_NAME=x\n", want: "COMPOSE_PROJECT_NAME"},
		"DOCKER_HOST":          {env: "APP_SLUG='n8n'\nDOCKER_HOST=tcp://h:2375\n", want: "DOCKER_HOST"},
		"чужой APP_SLUG":       {env: "APP_SLUG='other'\n", want: "APP_SLUG"},
		"без APP_SLUG":         {env: "APP_DOMAIN='n8n.example.com'\n", want: "APP_SLUG"},
		// Разбор агента видит здесь ключ `export APP_SLUG`, а compose — APP_SLUG.
		"export APP_SLUG": {env: "APP_SLUG='n8n'\nexport APP_SLUG=other\n", want: "export APP_SLUG"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := installFakeDocker(t, "")
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			writeRestoreFixture(t, p, "n8n", map[string]string{
				"vol-app-data.tar.gz": "архив",
				".env":                tc.env,
			})
			before := appFilesSnapshot(t, p)

			err := RestoreBackup(context.Background(), p, volumesOnlyApp(), restoreGuardSetDir(p))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf(".env набора вне правила агента не отвергнут (ждали %q): %v\n%s",
					tc.want, err, describeCalls(calls()))
			}
			assertStackUntouched(t, p, calls(), before)
		})
	}
}

// Без одного из файлов поднялся бы прежний с диска — тот, которого проверка
// набора не видела. Ссылка вместо файла — то же: проверили бы одно, а
// записали бы то, на что она указывает в момент чтения.
func TestRestoreRefusesSetWithoutComposeOrEnv(t *testing.T) {
	for _, name := range []string{"docker-compose.yml", ".env"} {
		for _, kind := range []string{"нет", "ссылка"} {
			t.Run(name+" "+kind, func(t *testing.T) {
				calls := installFakeDocker(t, "")
				p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
				writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
				setFile := filepath.Join(restoreGuardSetDir(p), name)
				if err := os.Remove(setFile); err != nil {
					t.Fatal(err)
				}
				if kind == "ссылка" {
					if err := os.Symlink(filepath.Join(p.appDir("n8n"), name), setFile); err != nil {
						t.Fatal(err)
					}
				}
				before := appFilesSnapshot(t, p)

				err := RestoreBackup(context.Background(), p, volumesOnlyApp(), restoreGuardSetDir(p))
				if err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("набор, где %s — %s, принят: %v\n%s", name, kind, err, describeCalls(calls()))
				}
				assertStackUntouched(t, p, calls(), before)
			})
		}
	}
}

// Файлы набора ложатся в каталог приложения, поэтому и нормализуются от него:
// относительный bind `./data` в наборе — это `<каталог приложения>/data` после
// восстановления, а не каталог копии. Подстановка переменных включена — как на
// подъёме, иначе проверялось бы не то, что поднимется.
func TestRestoreNormalizesSetAgainstAppDir(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	setDir := restoreGuardSetDir(p)

	if err := RestoreBackup(context.Background(), p, volumesOnlyApp(), setDir); err != nil {
		t.Fatalf("восстановление упало: %v\n%s", err, describeCalls(calls()))
	}
	log := calls()

	argAfter := func(c fakeDockerCall, flag string) string {
		for i, a := range c.Args {
			if a == flag && i+1 < len(c.Args) {
				return c.Args[i+1]
			}
		}
		return ""
	}
	checked := firstCall(log, func(c fakeDockerCall) bool {
		return c.hasArg("config") && !c.hasArg("--no-interpolate") &&
			argAfter(c, "--project-directory") == p.appDir("n8n") &&
			argAfter(c, "-f") == filepath.Join(setDir, "docker-compose.yml") &&
			argAfter(c, "--env-file") == filepath.Join(setDir, ".env")
	})
	down := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("down") })
	if checked < 0 || down < 0 || checked > down {
		t.Fatalf("набор не нормализован от каталога приложения до остановки стека (проверка %d, down %d):\n%s",
			checked, down, describeCalls(log))
	}
}

// Набор в пределах политики восстанавливается как раньше.
func TestRestoreWithinPolicyProceeds(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})

	if err := RestoreBackup(context.Background(), p, volumesOnlyApp(), restoreGuardSetDir(p)); err != nil {
		t.Fatalf("набор в пределах политики не восстановлен: %v\n%s", err, describeCalls(calls()))
	}
	log := calls()
	down := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("down") })
	lastUp := -1
	for i, c := range log {
		if c.hasArg("up") {
			lastUp = i
		}
	}
	if down < 0 || lastUp < down {
		t.Fatalf("стек не остановлен и не поднят (down %d, up %d):\n%s", down, lastUp, describeCalls(log))
	}
	compose, err := os.ReadFile(filepath.Join(p.appDir("n8n"), "docker-compose.yml"))
	if err != nil || !strings.Contains(string(compose), "описание из копии") {
		t.Errorf("описание стека не возвращено из набора: %q, %v", compose, err)
	}
}

// --------------------------------------------------------------------------
// Грант при восстановлении — только к тем же байтам compose (ADR-0092, решения 11 и 14)
// --------------------------------------------------------------------------
//
// Послабление подписано корнем к sha256 байтов compose приложения. Набор копий
// с другим описанием этому гранту не принадлежит: иначе грант на порт 25 для
// шаблона почты открывал бы тот же порт любому набору, который выберет задание
// восстановления. Совпали байты — это то самое описание, и отказ ему был бы
// регрессом: стек с грантом не восстанавливался бы вовсе.

// restoreGrantModel — стек n8n с прямым портом 25 у app: без послабления его
// отбивает правило ports.
const restoreGrantModel = `{"services":{` +
	`"db":{"volumes":[{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data"}]},` +
	`"app":{"ports":[{"mode":"ingress","target":25,"published":"25","protocol":"tcp"}],` +
	`"volumes":[{"type":"volume","source":"app-data","target":"/home/node/.n8n"}]}},` +
	`"volumes":{"db-data":{},"app-data":{}}}`

// restoreGrantCompose — байты compose набора; к ним выдан грант.
const restoreGrantCompose = "# описание из копии\nservices:\n  app:\n    ports:\n      - \"25:25\"\n"

func TestRestoreGrantAppliesOnlyToSameCompose(t *testing.T) {
	cases := []struct {
		name       string
		sourceType string
		compose    string
		wantRefuse bool
	}{
		{"те же байты", "template", restoreGrantCompose, false},
		{"другие байты", "template", restoreGrantCompose + "# правка\n", true},
		// Описание git-приложения читается из репозитория, а не из подписанных
		// байтов: совпадение строки ничего о нём не говорит.
		{"из git", "git", restoreGrantCompose, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := installFakeDockerModel(t, "", restoreGrantModel)
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			writeRestoreFixture(t, p, "n8n", map[string]string{
				"vol-app-data.tar.gz": "архив",
				"docker-compose.yml":  restoreGrantCompose,
			})
			app := volumesOnlyApp()
			app.SourceType = tc.sourceType
			app.Compose = tc.compose
			app.Allowances = []composeguard.Allowance{
				{Kind: composeguard.AllowPublishPort, Service: "app", Port: 25, Protocol: "tcp"},
			}
			before := appFilesSnapshot(t, p)

			err := RestoreBackup(context.Background(), p, app, restoreGuardSetDir(p))
			log := calls()
			if tc.wantRefuse {
				if err == nil || !strings.Contains(err.Error(), "отклонено") || !strings.Contains(err.Error(), "ports") {
					t.Fatalf("грант применён к набору, которому не принадлежит: %v\n%s", err, describeCalls(log))
				}
				assertStackUntouched(t, p, log, before)
				return
			}
			if err != nil && strings.Contains(err.Error(), "отклонено") {
				t.Fatalf("набор с теми же байтами compose отвергнут, хотя грант его: %v", err)
			}
			if firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("down") }) < 0 {
				t.Fatalf("восстановление не дошло до остановки стека: %v\n%s", err, describeCalls(log))
			}
		})
	}
}
