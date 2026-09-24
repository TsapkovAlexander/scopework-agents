package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// --------------------------------------------------------------------------
// Флаг «идёт восстановление» (ADR-0063, решение 6)
// --------------------------------------------------------------------------
//
// Флаг — единственное, что отделяет «стек лежит, потому что сорвалось
// восстановление» от «стек упал сам». Ошибка в сторону «флага нет» поднимает
// приложение на смешанных томах, поэтому при любом сомнении флаг считается
// поставленным.

func TestRestoreFlagSetThenCleared(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}

	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatalf("флаг не поставлен: %v", err)
	}
	if !hasRestoreFlag(p, "n8n") {
		t.Fatal("поставленный флаг не виден")
	}

	if err := clearRestoreFlag(p, "n8n"); err != nil {
		t.Fatalf("флаг не снят: %v", err)
	}
	if hasRestoreFlag(p, "n8n") {
		t.Fatal("снятый флаг всё ещё виден")
	}
}

// Флаг одного приложения не задевает соседнее на том же хосте.
func TestRestoreFlagIsPerApp(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}

	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}
	if hasRestoreFlag(p, "supabase") {
		t.Fatal("флаг n8n остановил самовосстановление соседнего приложения")
	}
}

// Первый запуск и обычная жизнь приложения: файла нет — флага нет.
func TestRestoreFlagAbsentWithoutFile(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	if hasRestoreFlag(p, "n8n") {
		t.Fatal("флаг найден там, где его никто не ставил")
	}
}

// Битое содержимое — не повод поднять стек: по нему нельзя понять, чем
// кончилось восстановление.
func TestRestoreFlagDamagedContentStillCounts(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}

	for name, content := range map[string]string{
		"не JSON":      "{обрыв",
		"пустой набор": `{"set":""}`,
		"пустой файл":  "",
	} {
		if err := os.WriteFile(restoreFlagPath(p, "n8n"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if !hasRestoreFlag(p, "n8n") {
			t.Errorf("%s: флаг не признан — самовосстановление подняло бы смешанные тома", name)
		}
	}
}

// Ошибка чтения, кроме «файла нет», тоже сомнение. Каталог состояния на месте
// файла — самый простой способ её получить без прав root.
func TestRestoreFlagReadErrorCounts(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Paths{StateDir: notDir}

	if !hasRestoreFlag(p, "n8n") {
		t.Fatal("ошибка чтения флага принята за «флага нет»")
	}
}

// Каталог состояния лежит рядом с ключом агента: права шире 0600 у файла и
// 0700 у каталога расширять незачем.
func TestRestoreFlagFileMode(t *testing.T) {
	p := Paths{StateDir: filepath.Join(t.TempDir(), "state")}

	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(restoreFlagPath(p, "n8n"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("права флага %o, ожидали 600", perm)
	}
	dir, err := os.Stat(p.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dir.Mode().Perm(); perm != 0o700 {
		t.Errorf("права каталога состояния %o, ожидали 700", perm)
	}
}

// Снятие флага зовут и удачный выкат, и удачное восстановление, — в том числе
// когда флага не было. Отказ здесь превратил бы удачу в ошибку.
func TestRestoreFlagClearWithoutFile(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	if err := clearRestoreFlag(p, "n8n"); err != nil {
		t.Fatalf("снятие отсутствующего флага вернуло ошибку: %v", err)
	}
}

// Slug уходит в путь на диске. Запись и снятие под недопустимым slug
// отказывают, чтение к диску не ходит: такой флаг не мог быть поставлен.
func TestRestoreFlagRejectsUnsafeSlug(t *testing.T) {
	// Каталог состояния — файл: любое обращение к диску дало бы ошибку
	// чтения, а она означает «флаг есть».
	notDir := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := Paths{StateDir: notDir}

	for _, slug := range []string{"../../etc", "..", "", "ПРОЕКТ", "app/../../root"} {
		if err := setRestoreFlag(p, slug, restoreTestSet); err == nil {
			t.Errorf("флаг поставлен под slug %q", slug)
		}
		if err := clearRestoreFlag(p, slug); err == nil {
			t.Errorf("флаг снят под slug %q", slug)
		}
		if hasRestoreFlag(p, slug) {
			t.Errorf("чтение флага под slug %q сходило на диск", slug)
		}
	}
}

// Флаг обязан доезжать до решения самовосстановления: чистая функция без
// чтения файла защитила бы только тесты.
func TestRestoreFlagStopsRecoverUnhealthy(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	apps := []DesiredApp{{Slug: "n8n", Desired: "present"}}

	// Без каталога стека `up` падает на смене каталога раньше, чем запустится
	// docker, — и тест зеленел бы при самовосстановлении, которое флаг не
	// читает.
	if err := os.MkdirAll(p.appDir("n8n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		"n8n": {ReleaseID: "release-1", Status: "healthy"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}

	if err := RecoverUnhealthy(context.Background(), p, apps,
		[]AppHealth{{Slug: "n8n", Status: HealthDown}}); err != nil {
		t.Fatalf("самовосстановление упало: %v", err)
	}
	if log := calls(); len(log) != 0 {
		t.Fatalf("при флаге восстановления агент тронул стек:\n%s", describeCalls(log))
	}
}

// captureStderr — то, что агент напечатал в журнал за время f.
//
// Подмена os.Stderr безопасна: в пакете нет ни одного t.Parallel, тесты идут
// по одному.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w

	read := make(chan string, 1)
	go func() {
		raw, _ := io.ReadAll(r)
		read <- string(raw)
	}()

	f()

	os.Stderr = saved
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out := <-read
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Стек, лежащий из-за сорвавшегося восстановления, говорит об этом в журнал.
//
// Это единственная причина отказа самовосстановления, которую видно снаружи:
// лежащее приложение с флагом неотличимо от забытого, а человек на хосте
// первым делом читает журнал агента. Прочие причины молчат намеренно — такт
// идёт раз в минуту.
func TestRestoreFlagReasonReachesLog(t *testing.T) {
	installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	apps := []DesiredApp{{Slug: "n8n", Desired: "present"}}
	if err := os.MkdirAll(p.appDir("n8n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveApplied(p, AppliedState{Apps: map[string]AppliedRecord{
		"n8n": {ReleaseID: "release-1", Status: "healthy"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}

	out := captureStderr(t, func() {
		if err := RecoverUnhealthy(context.Background(), p, apps,
			[]AppHealth{{Slug: "n8n", Status: HealthDown}}); err != nil {
			t.Errorf("самовосстановление упало: %v", err)
		}
	})
	if !strings.Contains(out, "n8n") || !strings.Contains(out, "восстановление из копии не завершилось") {
		t.Errorf("лежащий под флагом стек молчит в журнале: %q", out)
	}

	// Здоровое приложение без флага молчит: строка в минуту на каждое
	// приложение хоста утопила бы в журнале настоящую причину аварии.
	if err := clearRestoreFlag(p, "n8n"); err != nil {
		t.Fatal(err)
	}
	out = captureStderr(t, func() {
		if err := RecoverUnhealthy(context.Background(), p, apps,
			[]AppHealth{{Slug: "n8n", Status: HealthHealthy}}); err != nil {
			t.Errorf("самовосстановление упало: %v", err)
		}
	})
	if out != "" {
		t.Errorf("здоровое приложение печатает причину каждый такт: %q", out)
	}
}

// --------------------------------------------------------------------------
// Том базы — по описанию стека из набора (ADR-0063, решение 2)
// --------------------------------------------------------------------------
//
// Том базы очищается и не распаковывается: базу возвращает дамп. Ошибка связи
// «том — база» стоит очистки не того тома, поэтому всё, кроме однозначного
// случая, — отказ с названием случая, до остановки стека.

func TestDatabaseVolumeFromComposeModel(t *testing.T) {
	pg := PostgresBackup{Service: "db", User: "n8n", Database: "n8n"}
	spec := BackupSpec{Postgres: []PostgresBackup{pg}, Volumes: []string{"db-data", "app-data"}}

	// services — содержимое ключа services нормализованной модели.
	cases := []struct {
		name     string
		services string
		want     string
		// errHas — чем текст отказа называет случай; сервис проверяется всегда.
		errHas string
	}{
		{
			name: "том в каталоге данных",
			services: `{"db":{"volumes":[
				{"type":"bind","source":"/srv/init","target":"/docker-entrypoint-initdb.d"},
				{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data"}]},
				"app":{"volumes":[{"type":"volume","source":"app-data","target":"/home/node/.n8n"}]}}`,
			want: "db-data",
		},
		{
			name: "путь каталога со слешем на конце",
			services: `{"db":{"volumes":[
				{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data/"}]}}`,
			want: "db-data",
		},
		{
			// Каталог данных объявлен и у соседа: связь берётся у сервиса
			// базы, а не у первого попавшегося сервиса с таким монтированием.
			name: "тот же каталог данных у соседнего сервиса",
			services: `{"db":{"volumes":[
				{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data"}]},
				"replica":{"volumes":[
				{"type":"volume","source":"app-data","target":"/var/lib/postgresql/data"}]}}`,
			want: "db-data",
		},
		{
			name:     "сервиса нет",
			services: `{"app":{"volumes":[{"type":"volume","source":"app-data","target":"/home/node/.n8n"}]}}`,
			errHas:   "не найден",
		},
		{
			name:     "у сервиса нет монтирований",
			services: `{"db":{"image":"postgres:16"}}`,
			errHas:   "нет списка монтирований",
		},
		{
			name:     "монтирования не списком",
			services: `{"db":{"volumes":{"db-data":"/var/lib/postgresql/data"}}}`,
			errHas:   "нет списка монтирований",
		},
		{
			name: "каталог данных глубже: PGDATA в подкаталоге",
			services: `{"db":{"volumes":[
				{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data/pgdata"}]}}`,
			errHas: "нет монтирования в /var/lib/postgresql/data",
		},
		{
			name: "каталог данных с хоста",
			services: `{"db":{"volumes":[
				{"type":"bind","source":"/srv/pg","target":"/var/lib/postgresql/data"}]}}`,
			errHas: "bind",
		},
		{
			name: "каталог данных в памяти",
			services: `{"db":{"volumes":[
				{"type":"tmpfs","target":"/var/lib/postgresql/data"}]}}`,
			errHas: "не томом docker",
		},
		{
			name:     "запись строкой",
			services: `{"db":{"volumes":["db-data:/var/lib/postgresql/data"]}}`,
			errHas:   "строкой",
		},
		{
			name: "том не объявлен в backup_spec",
			services: `{"db":{"volumes":[
				{"type":"volume","source":"pg-data","target":"/var/lib/postgresql/data"}]}}`,
			errHas: "не объявлен",
		},
		{
			name: "имя тома из переменной",
			services: `{"db":{"volumes":[
				{"type":"volume","source":"${PG_VOLUME_SECRET_NAME}","target":"/var/lib/postgresql/data"}]}}`,
			errHas: "без допустимого имени",
		},
		{
			name: "анонимный том",
			services: `{"db":{"volumes":[
				{"type":"volume","target":"/var/lib/postgresql/data"}]}}`,
			errHas: "без допустимого имени",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model, err := parseComposeModel([]byte(`{"services":` + tc.services + `}`))
			if err != nil {
				t.Fatalf("модель фикстуры не разобрана: %v", err)
			}

			got, err := databaseVolume(model, spec, pg)
			if tc.errHas == "" {
				if err != nil || got != tc.want {
					t.Fatalf("ожидали том %q, получили %q, ошибка: %v", tc.want, got, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("неоднозначная связь тома с базой принята: том %q — его бы очистили", got)
			}
			if !strings.Contains(err.Error(), tc.errHas) || !strings.Contains(err.Error(), "базы db") {
				t.Errorf("отказ не называет случай (%q) и сервис: %v", tc.errHas, err)
			}
			for _, value := range []string{"PG_VOLUME_SECRET_NAME", "pg-data", "/srv/pg"} {
				if strings.Contains(err.Error(), value) {
					t.Errorf("в отказ попало значение из описания стека %q: %v", value, err)
				}
			}
		})
	}
}

// Модель снимается с КАТАЛОГА НАБОРА, а не с каталога работающего приложения:
// стек вернётся описанием из копии, и ключи томов у релизов могут разниться.
func TestDatabaseVolumeFromSetModel(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", nil)
	setDir := filepath.Join(p.backupsDir("n8n"), restoreTestSet)

	model, err := composeModelOfSet(context.Background(), setDir)
	if err != nil {
		t.Fatalf("модель набора не снята: %v\n%s", err, describeCalls(calls()))
	}
	pg := PostgresBackup{Service: "db", User: "n8n", Database: "n8n"}
	vol, err := databaseVolume(model, BackupSpec{Postgres: []PostgresBackup{pg}, Volumes: []string{"db-data"}}, pg)
	if err != nil || vol != "db-data" {
		t.Fatalf("том базы по модели набора: %q, %v", vol, err)
	}

	log := calls()
	if len(log) != 1 || !log[0].hasArg("config") || !log[0].hasArg(filepath.Join(setDir, ".env")) {
		t.Fatalf("модель снята не с набора копий:\n%s", describeCalls(log))
	}
}

// --------------------------------------------------------------------------
// Образ базы, на котором дамп не ложится (ADR-0063, решение 9)
// --------------------------------------------------------------------------
//
// Восстановление, которое заведомо сорвётся на psql, обязано отказать до
// `down`: после него это уже простой с очищенными томами.

func TestDatabaseImageRefusal(t *testing.T) {
	pg := PostgresBackup{Service: "db", User: "supabase_admin", Database: "postgres"}
	cases := []struct {
		name   string
		image  string
		refuse bool
	}{
		{
			name:   "supabase/postgres с тегом и дайджестом",
			image:  "supabase/postgres:17.6.1.136@sha256:f371b5f3f2ac0a05703f33d6e6134515fb2498cab708fb948a0aeb7481467c00",
			refuse: true,
		},
		{
			name:   "supabase/postgres из другого реестра",
			image:  "public.ecr.aws/supabase/postgres:15.8.1.085",
			refuse: true,
		},
		{name: "postgres шаблона n8n", image: "postgres:16.6-alpine"},
		{
			name:  "postgres шаблона n8n с дайджестом",
			image: "postgres:16.6-alpine@sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model, err := parseComposeModel([]byte(`{"services":{"db":{"image":"` + tc.image + `"}}}`))
			if err != nil {
				t.Fatalf("модель фикстуры не разобрана: %v", err)
			}

			err = databaseImageRefusal(model, pg)
			if !tc.refuse {
				if err != nil {
					t.Fatalf("восстановление на %s отвергнуто: %v", tc.image, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("восстановление на %s не отвергнуто — дамп сорвётся уже после down", tc.image)
			}
			for _, want := range []string{"Supabase", "не поддерживается", "не останавливался", "не тронуты"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("в отказе нет %q: %v", want, err)
				}
			}
			// Текст проходит затирание на выходе RestoreBackup, а `supabase` —
			// значение DASHBOARD_USERNAME по умолчанию у шаблона.
			redacted := redactSecrets(err.Error(), map[string]string{"DASHBOARD_USERNAME": "supabase"})
			if !strings.Contains(redacted, "Supabase") {
				t.Errorf("затирание съело название образа: %s", redacted)
			}
		})
	}
}

// --------------------------------------------------------------------------
// Отказ psql — одной строкой и без данных клиента (ADR-0063, решение 8)
// --------------------------------------------------------------------------
//
// Отчёт о восстановлении ложится в журнал, который читает любой участник
// проекта. В выводе psql рядом с причиной лежат строки данных: у COPY — в
// CONTEXT, у нарушения ключа — в DETAIL, у неверного значения — в самой
// строке ERROR.

func TestPsqlFailureText(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		values map[string]string
		want   string
		// leaks — чего в результате быть не должно ни при каком исходе.
		leaks []string
	}{
		{
			name: "строка данных COPY в CONTEXT",
			stderr: "psql:<stdin>:48: ERROR:  extra data after last expected column\n" +
				"CONTEXT:  COPY orders, line 3: \"3\tИван Петров\tivan@example.com\t+79991234567\"\n",
			want:  "ERROR:  extra data after last expected column",
			leaks: []string{"Иван", "ivan@example.com", "+7999", "COPY orders"},
		},
		{
			name: "ключ в DETAIL",
			stderr: "psql:<stdin>:112: ERROR:  duplicate key value violates unique constraint \"users_email_key\"\n" +
				"DETAIL:  Key (email)=(x@y.ru) already exists.\n" +
				"CONTEXT:  COPY users, line 2\n",
			want:  "ERROR:  duplicate key value violates unique constraint \"users_email_key\"",
			leaks: []string{"x@y.ru", "Key (email)"},
		},
		{
			name:   "значение клиента в строке ERROR",
			stderr: "psql:<stdin>:48: ERROR:  invalid input syntax for type integer: \"ivan@example.com\"\n",
			want:   "ERROR:  invalid input syntax for type integer: \"***\"",
			leaks:  []string{"ivan@example.com"},
		},
		{
			name:   "значение вне диапазона",
			stderr: "psql:<stdin>:48: ERROR:  value \"99999999999\" is out of range for type integer\n",
			want:   "ERROR:  value \"***\" is out of range for type integer",
			leaks:  []string{"99999999999"},
		},
		{
			// Кавычки внутри значения psql не экранирует: разбор по парам
			// выпустил бы хвост значения наружу.
			name:   "кавычка внутри значения",
			stderr: "psql:<stdin>:48: ERROR:  invalid input syntax for type integer: \"12\"ivan@example.com\"\n",
			want:   "ERROR:  invalid input syntax for type integer: \"***\"",
			leaks:  []string{"ivan@example.com"},
		},
		{
			// Слово из списка имён, но с двоеточием: это значение перечисления.
			name:   "значение перечисления с именем user",
			stderr: "psql:<stdin>:48: ERROR:  invalid input value for enum user: \"ivan@example.com\"\n",
			want:   "ERROR:  invalid input value for enum user: \"***\"",
			leaks:  []string{"ivan@example.com"},
		},
		{
			name: "имя объекта сохранено, текст запроса — нет",
			stderr: "psql:<stdin>:7: ERROR:  relation \"public.orders\" does not exist\n" +
				"LINE 1: INSERT INTO public.orders VALUES (1, 'ivan@example.com');\n" +
				"                    ^\n",
			want:  "ERROR:  relation \"public.orders\" does not exist",
			leaks: []string{"ivan@example.com", "LINE"},
		},
		{
			name: "два имени объекта в одной строке",
			stderr: "psql:<stdin>:90: ERROR:  null value in column \"email\" of relation \"users\" " +
				"violates not-null constraint\nDETAIL:  Failing row contains (7, null, Иван).\n",
			want:  "ERROR:  null value in column \"email\" of relation \"users\" violates not-null constraint",
			leaks: []string{"Иван", "Failing row"},
		},
		{
			name:   "значение переменной затёрто",
			stderr: "psql:<stdin>:1: ERROR:  role \"svc_S3cr3tR0leName\" does not exist\n",
			values: map[string]string{"DB_ROLE": "svc_S3cr3tR0leName"},
			want:   "ERROR:  role \"***\" does not exist",
			leaks:  []string{"S3cr3tR0leName"},
		},
		{
			name: "FATAL при подключении",
			stderr: "psql: error: connection to server on socket \"/var/run/postgresql/.s.PGSQL.5432\" failed: " +
				"FATAL:  database \"appdb\" does not exist\n",
			want: "FATAL:  database \"appdb\" does not exist",
		},
		{
			name: "NOTICE до ошибки",
			stderr: "psql:<stdin>:3: NOTICE:  table \"orders\" does not exist, skipping\n" +
				"psql:<stdin>:4: NOTICE:  extension \"pgcrypto\" already exists, skipping\n" +
				"psql:<stdin>:9: ERROR:  permission denied for schema public\n",
			want: "ERROR:  permission denied for schema public",
		},
		{
			name: "ERROR внутри DETAIL не выбирается",
			stderr: "DETAIL:  Key (note)=(ERROR: ivan@example.com) already exists.\n" +
				"psql:<stdin>:5: ERROR:  duplicate key value violates unique constraint \"notes_pkey\"\n",
			want:  "ERROR:  duplicate key value violates unique constraint \"notes_pkey\"",
			leaks: []string{"ivan@example.com"},
		},
		{
			name: "отказал docker, а не psql",
			stderr: "psql:<stdin>:3: NOTICE:  table \"orders\" does not exist, skipping\n" +
				"Error response from daemon: container n8n-db-1 is not running\n\n",
			want: "Error response from daemon: container n8n-db-1 is not running",
		},
		{
			name:   "отказ compose с кавычками",
			stderr: "service \"db\" is not running\n",
			want:   "service \"***\" is not running",
		},
		{
			name: "только служебные строки",
			stderr: "psql:<stdin>:3: NOTICE:  table \"orders\" does not exist, skipping\n" +
				"CONTEXT:  COPY orders, line 3: \"ivan@example.com\"\n",
			want:  "",
			leaks: []string{"ivan@example.com"},
		},
		{
			name:   "пусто",
			stderr: "",
			want:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := psqlFailure(tc.stderr, tc.values)
			if got != tc.want {
				t.Errorf("текст отказа:\n got = %q\nwant = %q", got, tc.want)
			}
			for _, leak := range tc.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("в отчёт попало %q: %q", leak, got)
				}
			}
		})
	}
}

// Отчёт ограничен по длине, и обрезка не рвёт букву: полруны кириллицы — это
// битая строка в JSON отчёта и в журнале.
func TestPsqlFailureTruncatesOnRune(t *testing.T) {
	// «ERROR:  » — 8 байт, дальше буквы по 2: срез по байтам без оглядки на
	// руны пришёлся бы на середину буквы.
	stderr := "psql:<stdin>:5: ERROR:  " + strings.Repeat("я", 150) + "\n"

	got := psqlFailure(stderr, nil)

	if len(got) > 200 || len(got) < 195 {
		t.Errorf("длина текста %d байт, ожидали чуть меньше 200", len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("обрезка разорвала руну: %q", got)
	}
	if !strings.HasPrefix(got, "ERROR:  яяя") || !strings.HasSuffix(got, "…") {
		t.Errorf("обрезано не с конца или без многоточия: %q", got)
	}

	short := "psql:<stdin>:5: ERROR:  ошибка\n"
	if got := psqlFailure(short, nil); got != "ERROR:  ошибка" {
		t.Errorf("короткий текст изменён: %q", got)
	}
}

// --------------------------------------------------------------------------
// Набор копий проверяется до остановки стека (ADR-0063, решения 1 и 3)
// --------------------------------------------------------------------------
//
// Всё, что можно проверить, не трогая стек, проверяется раньше `down`: отказ,
// найденный после, — уже простой с очищенными томами.

var restoreSetDB = PostgresBackup{Service: "db", User: "n8n", Database: "appdb"}

func TestCheckRestoreSetListsVolumeArchives(t *testing.T) {
	dir := writeSet(t, map[string]string{
		"docker-compose.yml":  "services: {}\n",
		".env":                "APP_SLUG='n8n'\n",
		"db-db.sql":           "-- дамп\n",
		"vol-db-data.tar.gz":  "архив",
		"vol-app-data.tar.gz": "архив",
		"заметка.txt":         "не часть набора",
	})
	spec := BackupSpec{Postgres: []PostgresBackup{restoreSetDB}, Volumes: []string{"db-data", "app-data"}}

	archives, err := checkRestoreSet(dir, spec)
	if err != nil {
		t.Fatalf("годный набор отвергнут: %v", err)
	}
	if strings.Join(archives, ",") != "vol-app-data.tar.gz,vol-db-data.tar.gz" {
		t.Fatalf("архивы томов: %q", archives)
	}
}

// Приложение без базы в backup_spec возвращается только томами, как раньше.
func TestCheckRestoreSetVolumesOnly(t *testing.T) {
	dir := writeSet(t, map[string]string{"vol-app-data.tar.gz": "архив"})

	archives, err := checkRestoreSet(dir, BackupSpec{Volumes: []string{"app-data"}})
	if err != nil || len(archives) != 1 {
		t.Fatalf("набор из одних томов: %q, %v", archives, err)
	}
}

// Имя архива уходит в команду оболочки внутри контейнера.
func TestCheckRestoreSetRejectsBadVolumeName(t *testing.T) {
	for _, name := range []string{"vol-$(reboot).tar.gz", "vol-.hidden.tar.gz", "vol-.tar.gz", "vol-a b.tar.gz"} {
		dir := writeSet(t, map[string]string{name: "архив"})

		_, err := checkRestoreSet(dir, BackupSpec{Volumes: []string{"app-data"}})
		if err == nil || !strings.Contains(err.Error(), "недопустимое имя тома в наборе копий") {
			t.Errorf("архив %q принят: %v", name, err)
		}
	}
}

// Объявленная база без годного дампа — отказ до `down`: иначе «удачное»
// восстановление вернуло бы базу пофайловой копией тома или не вернуло вовсе.
func TestCheckRestoreSetRequiresDump(t *testing.T) {
	spec := BackupSpec{Postgres: []PostgresBackup{restoreSetDB}, Volumes: []string{"db-data"}}

	cases := map[string]func(t *testing.T, dir string){
		"файла нет": func(t *testing.T, dir string) {},
		"файл пуст": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "db-db.sql"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"каталог вместо файла": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "db-db.sql"), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"ссылка вместо файла": func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "чужой.sql")
			if err := os.WriteFile(target, []byte("-- не из набора\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, "db-db.sql")); err != nil {
				t.Fatal(err)
			}
		},
	}

	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeSet(t, map[string]string{"vol-db-data.tar.gz": "архив"})
			prepare(t, dir)

			_, err := checkRestoreSet(dir, spec)
			if err == nil {
				t.Fatal("набор без годного дампа принят")
			}
			if !strings.Contains(err.Error(), "appdb") || !strings.Contains(err.Error(), "db-db.sql") {
				t.Errorf("отказ не называет базу и файл: %v", err)
			}
		})
	}
}

// Дамп в наборе есть, а база в backup_spec не объявлена: релиз мог потерять
// описание копии при правке переменных или домена. Молча вернуть базу
// пофайловой копией тома нельзя.
func TestCheckRestoreSetRefusesDumpWithoutDeclaredDatabase(t *testing.T) {
	dir := writeSet(t, map[string]string{
		"db-db.sql":           "-- дамп\n",
		"vol-db-data.tar.gz":  "архив",
		"vol-app-data.tar.gz": "архив",
	})

	_, err := checkRestoreSet(dir, BackupSpec{Volumes: []string{"db-data", "app-data"}})
	if err == nil {
		t.Fatal("набор с дампом восстановлен бы одними томами")
	}
	if !strings.Contains(err.Error(), "дамп") || !strings.Contains(err.Error(), "не объявлена") {
		t.Errorf("отказ не объясняет случай: %v", err)
	}
}

func TestCheckRestoreSetUnreadableSet(t *testing.T) {
	_, err := checkRestoreSet(filepath.Join(t.TempDir(), "нет"), BackupSpec{Volumes: []string{"app-data"}})
	if err == nil || !strings.Contains(err.Error(), "набор копий недоступен") {
		t.Fatalf("отсутствующий набор: %v", err)
	}
}

// Сервис базы входит в путь к дампу: `..` в нём вывело бы чтение за набор.
func TestCheckRestoreSetValidatesSpec(t *testing.T) {
	dir := writeSet(t, nil)
	spec := BackupSpec{Postgres: []PostgresBackup{{Service: "../../../etc/passwd", User: "n8n", Database: "appdb"}}}

	if _, err := checkRestoreSet(dir, spec); err == nil {
		t.Fatal("сервис базы с `..` принят в путь к дампу")
	}
}

// Архив читается целиком внутри контейнера: том смонтирован только на чтение,
// список файлов уходит в /dev/null и в память агента не попадает.
func TestVerifyVolumeArchive(t *testing.T) {
	calls := installFakeDocker(t, "")
	dir := writeSet(t, map[string]string{"vol-app-data.tar.gz": "архив"})

	if err := verifyVolumeArchive(context.Background(), dir, "vol-app-data.tar.gz"); err != nil {
		t.Fatalf("проверка архива упала: %v", err)
	}
	log := calls()
	if len(log) != 1 || !log[0].hasArg("run") || !log[0].hasArg(dir+":/from:ro") ||
		log[0].Args[len(log[0].Args)-1] != "tar tzf /from/vol-app-data.tar.gz > /dev/null" {
		t.Fatalf("архив проверяется не так:\n%s", describeCalls(log))
	}

	for _, name := range []string{"vol-$(reboot).tar.gz", "vol-a;b.tar.gz", "db-db.sql"} {
		if err := verifyVolumeArchive(context.Background(), dir, name); err == nil {
			t.Errorf("имя %q ушло в команду оболочки", name)
		}
	}
	if n := len(calls()); n != 1 {
		t.Errorf("недопустимое имя дошло до docker: вызовов %d", n)
	}
}

// Буфер stderr psql держит хвост. Строка, обрезанная спереди, могла начаться
// посреди значения клиента, а её начало — DETAIL: или CONTEXT: — потеряно.
func TestPsqlStderrTailDropsCutLine(t *testing.T) {
	cut := `mail.ru" ERROR: x` + "\n" + "ERROR:  syntax error\n"
	if got := fromFirstFullLine(cut, len(cut)); got != "ERROR:  syntax error\n" {
		t.Errorf("обрезанная первая строка осталась: %q", got)
	}
	if got := fromFirstFullLine(cut, len(cut)+1); got != cut {
		t.Errorf("необрезанный вывод изменён: %q", got)
	}
	if got := fromFirstFullLine("ivan@example.com без перевода строки", 10); got != "" {
		t.Errorf("обрывок без целой строки не отброшен: %q", got)
	}
}

// --------------------------------------------------------------------------
// RestoreBackup: база из дампа в пустой том (ADR-0063, решение 1)
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Поддельный docker с особыми ответами
// --------------------------------------------------------------------------
//
// ОБЁРТКА ПОВЕРХ ХАРНЕССА из restore_test.go, а не второй поддельный docker:
// журнал вызовов у них общий, и describeCalls с firstCall читают его как
// прежде. Два скрипта, пишущих журнал каждый по-своему, разошлись бы форматом
// на первой же правке.
//
// Обёртка зовёт скрипт харнесса теми же аргументами и с тем же stdin — тот
// ведёт журнал и правдоподобно отвечает на config и ps, — а поверх кладёт то,
// чего у харнесса нет: свою модель стека и свой `ps --all`, отказ psql с
// данными клиента в stderr, снимок описания стека на подъёме базы и `up`,
// висящий до снятия маркера.

// fakeDockerRules — особые ответы. Пустое поле означает «как у харнесса».
type fakeDockerRules struct {
	// model — ответ на `config … --format json` вместо модели харнесса: её
	// задают тесты, где решение принимается по описанию стека из набора.
	model string
	// psqlStderr — что psql печатает в stderr, выходя с кодом 3.
	psqlStderr string
	// psAll — ответ на `ps --all` вместо ответа харнесса: им задаётся стек,
	// который поднялся и не устоял.
	psAll string
}

// fakeDockerRig — журнал вызовов и каталог, через который тест говорит с
// поддельным docker: маркеры и снимки файлов.
type fakeDockerRig struct {
	calls func() []fakeDockerCall
	dir   string
}

// fakeDockerUpWait — предел ожидания начала `up`. Нужен только чтобы тест не
// повис навсегда, если до `up` дело вообще не дошло.
const fakeDockerUpWait = 10 * time.Second

func installFakeDockerRules(t *testing.T, rules fakeDockerRules) fakeDockerRig {
	t.Helper()

	calls := installFakeDocker(t, "")
	harness, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}

	bin := t.TempDir()
	aux := t.TempDir()

	// Ответ харнесса на переопределённый вопрос подавляется: два ответа в один
	// поток склеились бы, и модель перестала бы разбираться вовсе.
	script := "#!/bin/sh\n" +
		"harness=" + shellQuote(harness) + "\n" +
		"aux=" + shellQuote(aux) + "\n" +
		"model=" + shellQuote(rules.model) + "\n" +
		"psqlerr=" + shellQuote(rules.psqlStderr) + "\n" +
		"psall=" + shellQuote(rules.psAll) + "\n" +
		`mine=''` + "\n" +
		`case " $* " in` + "\n" +
		`  *" config "*"--format json "*) [ -n "$model" ] && mine=model;;` + "\n" +
		`  *" ps --all "*) [ -n "$psall" ] && mine=ps;;` + "\n" +
		`esac` + "\n" +
		`if [ -n "$mine" ]; then "$harness" "$@" > /dev/null; else "$harness" "$@"; fi` + "\n" +
		`case "$mine" in` + "\n" +
		`  model) printf '%s\n' "$model";;` + "\n" +
		`  ps) printf '%s' "$psall";;` + "\n" +
		`esac` + "\n" +
		`up=''; db=''; psql=''` + "\n" +
		`for a in "$@"; do case "$a" in up) up=1;; db) db=1;; psql) psql=1;; esac; done` + "\n" +
		// Каталог запуска — каталог приложения (newDockerCmd), и на подъёме
		// базы описание стека в нём обязано быть уже из копии.
		`if [ -n "$up" ] && [ -n "$db" ]; then` + "\n" +
		`  cp docker-compose.yml "$aux/up-db-compose.yml" 2>/dev/null` + "\n" +
		`  cp .env "$aux/up-db.env" 2>/dev/null` + "\n" +
		`fi` + "\n" +
		`if [ -n "$psql" ] && [ -n "$psqlerr" ]; then printf '%s' "$psqlerr" >&2; exit 3; fi` + "\n" +
		// Остановка агента посреди восстановления: `up` докладывает о старте и
		// виснет, пока тест не снимет маркер. Умирает он от сигнала всей
		// группе процессов, который ставит newDockerCmd.
		`if [ -n "$up" ] && [ -f "$aux/block-up" ]; then : > "$aux/up-started"; exec sleep 30; fi` + "\n" +
		"exit 0\n"

	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	return fakeDockerRig{calls: calls, dir: aux}
}

// blockUp заставляет `up` виснуть до unblockUp.
func (f fakeDockerRig) blockUp(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "block-up"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f fakeDockerRig) unblockUp(t *testing.T) {
	t.Helper()
	if err := os.Remove(filepath.Join(f.dir, "block-up")); err != nil {
		t.Fatal(err)
	}
}

// waitUpStarted ждёт доклада о начале `up`. Без t: зовут из горутины, где
// t.Fatal запрещён, — исход возвращается значением.
func (f fakeDockerRig) waitUpStarted() bool {
	deadline := time.Now().Add(fakeDockerUpWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(f.dir, "up-started")); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// upSnapshot — файл каталога приложения, снятый на подъёме базы.
func (f fakeDockerRig) upSnapshot(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		t.Fatalf("снимок %s на подъёме базы не снят: %v", name, err)
	}
	return string(raw)
}

// firstCall — номер первого вызова docker, подходящего под условие, или -1.
func firstCall(log []fakeDockerCall, match func(fakeDockerCall) bool) int {
	for i, c := range log {
		if match(c) {
			return i
		}
	}
	return -1
}

func restoreDatabaseApp() DesiredApp {
	return DesiredApp{
		Slug: "n8n",
		BackupSpec: BackupSpec{
			Postgres: []PostgresBackup{{Service: "db", User: "n8n", Database: "appdb"}},
			Volumes:  []string{"db-data", "app-data"},
		},
		ApplySpec: ApplySpec{WaitTimeoutSeconds: 600, StableChecks: 1},
	}
}

// Порядок операции и есть её смысл: проверки — до `down`, описание стека — до
// данных, том базы очищается без распаковки, дамп — в готовую по TCP базу и до
// подъёма всего стека.
func TestRestoreBackupDumpIntoClearedDatabaseVolume(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	dump := "-- дамп из копии\nCREATE TABLE marker (id int);\n"
	writeRestoreFixture(t, p, "n8n", map[string]string{
		"db-db.sql":           dump,
		"vol-db-data.tar.gz":  "пофайловая копия работающей базы",
		"vol-app-data.tar.gz": "архив тома приложения",
	})
	setDir := filepath.Join(p.backupsDir("n8n"), restoreTestSet)
	appEnv := filepath.Join(p.appDir("n8n"), ".env")

	if err := RestoreBackup(context.Background(), p, restoreDatabaseApp(), setDir); err != nil {
		t.Fatalf("восстановление упало: %v\n%s", err, describeCalls(calls()))
	}
	log := calls()
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf(format+"\nвызовы docker:\n%s", append(args, describeCalls(log))...)
	}

	down := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("down") })
	verified := firstCall(log, func(c fakeDockerCall) bool {
		return strings.Contains(c.line(), "tar tzf /from/vol-app-data.tar.gz")
	})
	if down < 0 || verified < 0 || verified > down {
		fail("архив тома приложения не проверен до остановки стека (проверка %d, down %d)", verified, down)
	}
	if i := firstCall(log, func(c fakeDockerCall) bool { return strings.Contains(c.line(), "vol-db-data.tar.gz") }); i >= 0 {
		fail("архив тома базы тронут на шаге %d — базу возвращает дамп", i)
	}

	cleared := firstCall(log, func(c fakeDockerCall) bool {
		return c.hasArg("n8n_db-data:/to") && c.Args[len(c.Args)-1] == "find /to -mindepth 1 -delete"
	})
	unpacked := firstCall(log, func(c fakeDockerCall) bool {
		return strings.Contains(c.line(), "tar xzf /from/vol-app-data.tar.gz")
	})
	if cleared < down || unpacked < down {
		fail("том базы не очищен (%d) или том приложения не распакован (%d) после down", cleared, unpacked)
	}

	upDB := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("up") && c.hasArg("db") })
	ready := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("pg_isready") && c.hasArg("127.0.0.1") })
	psql := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("psql") })
	if upDB < cleared || ready < upDB || psql < ready {
		fail("база поднята (%d), проверена по TCP (%d) и получила дамп (%d) не по порядку", upDB, ready, psql)
	}
	if psql >= 0 {
		c := log[psql]
		for _, arg := range []string{"-X", "ON_ERROR_STOP=1", "VERBOSITY=terse", "--single-transaction", "appdb", appEnv} {
			if !c.hasArg(arg) {
				fail("у psql нет %q", arg)
			}
		}
		if string(c.Stdin) != dump {
			fail("в psql ушёл не дамп из набора: %d байт", len(c.Stdin))
		}
	}

	lastUp := -1
	for i, c := range log {
		if c.hasArg("up") {
			lastUp = i
			if !c.hasArg("600") {
				fail("подъём на шаге %d ждёт не столько, сколько выкат (600 с)", i)
			}
		}
	}
	if lastUp <= psql || !log[lastUp].hasArg("--remove-orphans") {
		fail("весь стек не поднят после дампа (подъём %d, дамп %d)", lastUp, psql)
	}

	for _, c := range log {
		if c.hasArg("up") || c.hasArg("exec") {
			if !c.hasArg(appEnv) {
				fail("стек запущен не из каталога приложения: docker %s", c.line())
			}
		}
	}
	compose, err := os.ReadFile(filepath.Join(p.appDir("n8n"), "docker-compose.yml"))
	if err != nil || !strings.Contains(string(compose), "описание из копии") {
		t.Errorf("описание стека не возвращено из набора: %q, %v", compose, err)
	}
	if hasRestoreFlag(p, "n8n") {
		t.Error("флаг восстановления остался после удачного восстановления")
	}
}

// Описание стека — из копии ДО того, как база впервые стартует на пустом
// каталоге данных.
//
// Init-скрипты образа выполняются один раз, на пустом каталоге, и читают из
// .env пароли ролей. Обновление могло сменить мажор образа базы или эти
// переменные: стартовав на описании текущего релиза, база инициализировалась бы
// одним образом, а финальный `up` поднял бы другой — на чужом мажоре каталога
// данных, и стек остался бы лежать под флагом (ADR-0063).
func TestRestoreBackupStartsDatabaseOnSetDescription(t *testing.T) {
	const setMark = "APP_MARK='из копии'"
	fd := installFakeDockerRules(t, fakeDockerRules{})
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{
		"db-db.sql":           "-- дамп\n",
		"vol-app-data.tar.gz": "архив тома приложения",
		// Умолчание фикстуры перекрывается: .env копии обязан отличаться от
		// .env работающего релиза, иначе проверка ничего не значит.
		".env": "APP_SLUG='n8n'\n" + setMark + "\n",
	})

	if err := RestoreBackup(context.Background(), p, restoreDatabaseApp(),
		filepath.Join(p.backupsDir("n8n"), restoreTestSet)); err != nil {
		t.Fatalf("восстановление упало: %v\n%s", err, describeCalls(fd.calls()))
	}

	if got := fd.upSnapshot(t, "up-db-compose.yml"); !strings.Contains(got, "описание из копии") {
		t.Errorf("база поднята на описании стека не из копии: %q", got)
	}
	if got := fd.upSnapshot(t, "up-db.env"); !strings.Contains(got, setMark) {
		t.Errorf("база поднята с переменными не из копии: %q", got)
	}
}

// Всё, что можно проверить, — до `down`: отказ после него уже простой.
func TestRestoreBackupRefusesBeforeDown(t *testing.T) {
	// Модель набора со стеком Supabase: том каталога данных объявлен как надо,
	// чтобы отказ пришёл по образу базы, а не по ненайденному тому.
	const supabaseModel = `{"services":{` +
		`"db":{"image":"supabase/postgres:17.6.1.136",` +
		`"volumes":[{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data"}]},` +
		`"app":{"volumes":[{"type":"volume","source":"app-data","target":"/home/node/.n8n"}]}},` +
		`"volumes":{"db-data":{},"app-data":{}}}`

	cases := map[string]struct {
		files map[string]string
		spec  BackupSpec
		// model — описание стека из набора, если случай решается по нему.
		// Пусто — отвечает харнесс.
		model string
		// want — что обязано быть названо в отказе.
		want string
	}{
		"нет дампа объявленной базы": {
			files: map[string]string{"vol-db-data.tar.gz": "архив"},
			spec:  restoreDatabaseApp().BackupSpec,
		},
		"том базы не объявлен": {
			files: map[string]string{"db-db.sql": "-- дамп\n", "vol-app-data.tar.gz": "архив"},
			spec: BackupSpec{
				Postgres: restoreDatabaseApp().BackupSpec.Postgres,
				Volumes:  []string{"app-data"},
			},
		},
		"дамп без объявленной базы": {
			files: map[string]string{"db-db.sql": "-- дамп\n", "vol-db-data.tar.gz": "архив"},
			spec:  BackupSpec{Volumes: []string{"db-data"}},
		},
		// Набор годный: дело не в нём, а в образе базы, на который дамп не
		// ложится (ADR-0063, решение 9). Живую базу тут стирать нечем.
		"образ базы Supabase": {
			files: map[string]string{"db-db.sql": "-- дамп\n", "vol-app-data.tar.gz": "архив"},
			spec:  restoreDatabaseApp().BackupSpec,
			model: supabaseModel,
			want:  "Supabase",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			calls := installFakeDockerRules(t, fakeDockerRules{model: tc.model}).calls
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			writeRestoreFixture(t, p, "n8n", tc.files)
			app := DesiredApp{Slug: "n8n", BackupSpec: tc.spec}

			err := RestoreBackup(context.Background(), p, app, filepath.Join(p.backupsDir("n8n"), restoreTestSet))
			if err == nil {
				t.Fatal("негодный набор принят")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("отказ не называет причину %q: %v", tc.want, err)
			}
			if i := firstCall(calls(), func(c fakeDockerCall) bool { return c.hasArg("down") }); i >= 0 {
				t.Errorf("стек остановлен до отказа: %v\n%s", err, describeCalls(calls()))
			}
			// Очистка тома так же необратима, как `down`: вернуть содержимое
			// после неё нечем.
			if i := firstCall(calls(), func(c fakeDockerCall) bool {
				return len(c.Args) > 0 && strings.Contains(c.Args[len(c.Args)-1], "-delete")
			}); i >= 0 {
				t.Errorf("том очищен до отказа: %v\n%s", err, describeCalls(calls()))
			}
			if hasRestoreFlag(p, "n8n") {
				t.Error("флаг поставлен, хотя стек не трогали")
			}
		})
	}
}

// Дамп не лёг — стек не поднимается, флаг остаётся, а значение переменной
// приложения из хвоста docker в текст отказа не попадает. Что до отчёта
// доезжает одна строка причины psql, проверяет тест ниже.
func TestRestoreBackupDumpFailureKeepsStackDown(t *testing.T) {
	calls := installFakeDocker(t, "psql")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{
		"db-db.sql":           "-- дамп\n",
		"vol-app-data.tar.gz": "архив тома приложения",
	})
	app := restoreDatabaseApp()
	// Значение переменной совпадает с тем, что поддельный docker пишет в stderr.
	app.Env = map[string]string{"LEAKY": "поддельный отказ docker"}

	err := RestoreBackup(context.Background(), p, app, filepath.Join(p.backupsDir("n8n"), restoreTestSet))
	if err == nil {
		t.Fatalf("отказ psql не сорвал восстановление\n%s", describeCalls(calls()))
	}
	if !strings.Contains(err.Error(), "дамп базы appdb не влит") {
		t.Errorf("отказ не называет базу: %v", err)
	}
	if strings.Contains(err.Error(), "поддельный отказ docker") {
		t.Errorf("значение переменной доехало до текста отказа: %v", err)
	}
	if !hasRestoreFlag(p, "n8n") {
		t.Error("флаг снят после сорвавшегося восстановления")
	}

	log := calls()
	psql := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("psql") })
	if psql < 0 {
		t.Fatalf("до psql восстановление не дошло: %v\n%s", err, describeCalls(log))
	}
	for _, c := range log[psql+1:] {
		if c.hasArg("up") {
			t.Errorf("стек поднят после отказа дампа: docker %s", c.line())
		}
	}
}

// До отчёта доезжает ОДНА строка причины, и значение клиента в ней закрыто.
//
// Отчёт ложится в deploy_app_restores, который читает любой участник проекта, а
// psql печатает значение клиента трижды: в самой строке ERROR, в DETAIL и в
// CONTEXT (ADR-0063, решение 8). Поддельный psql печатает все три, а вторым
// случаем — строку длиннее буфера хвоста stderr.
func TestRestoreBackupDumpFailureHidesClientData(t *testing.T) {
	const leaked = "ivan@example.com"

	cases := map[string]struct {
		stderr string
		// want — что обязано быть в отказе; запрещённое одно на все случаи.
		want []string
	}{
		"ERROR, DETAIL и CONTEXT": {
			stderr: `psql:<stdin>:12: ERROR:  invalid input syntax for type integer: "` + leaked + `"` + "\n" +
				`DETAIL:  Key (email)=(` + leaked + `) already exists.` + "\n" +
				`CONTEXT:  COPY users, line 1, column id: "` + leaked + `"` + "\n",
			want: []string{"ERROR:", `"***"`},
		},
		// Строка ERROR длиннее буфера: в памяти агента остаётся её середина —
		// значение клиента без начала строки и без открывающей кавычки.
		// Закрывать в таком обрывке нечего, поэтому он отбрасывается целиком, и
		// в отказ идёт запасной текст.
		"строка длиннее буфера хвоста stderr": {
			stderr: `psql:<stdin>:12: ERROR:  invalid input syntax for type integer: "` +
				strings.Repeat(leaked+" ", 5000) + `"` + "\n",
			want: []string{"psql завершился с ошибкой"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fd := installFakeDockerRules(t, fakeDockerRules{psqlStderr: tc.stderr})
			p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
			writeRestoreFixture(t, p, "n8n", map[string]string{
				"db-db.sql":           "-- дамп\n",
				"vol-app-data.tar.gz": "архив тома приложения",
			})

			err := RestoreBackup(context.Background(), p, restoreDatabaseApp(),
				filepath.Join(p.backupsDir("n8n"), restoreTestSet))
			if err == nil {
				t.Fatalf("отказ psql не сорвал восстановление\n%s", describeCalls(fd.calls()))
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("в отказе нет %q: %v", want, err)
				}
			}
			// DETAIL и CONTEXT не просто содержат значение — они и есть строки
			// с данными клиента, поэтому в отчёт не идут целиком.
			for _, forbidden := range []string{leaked, "DETAIL", "CONTEXT"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Errorf("в отказ попало %q, а его читает любой участник проекта: %v", forbidden, err)
				}
			}
		})
	}
}

// Поднялся — не значит устоял: проверка устойчивости идёт и после отката.
//
// Сервис без healthcheck считается готовым в момент старта, и `up --wait`
// возвращается успехом для контейнера, который упадёт через две секунды. Стек,
// перезапускающийся по кругу на вернувшихся данных, — это неудача
// восстановления, а не его конец: флаг остаётся, самовосстановление не трогает.
func TestRestoreBackupUnstableStackKeepsFlag(t *testing.T) {
	fd := installFakeDockerRules(t, fakeDockerRules{
		psAll: "db\trunning\thealthy\t0\napp\trestarting\t\t1\n",
	})
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})

	err := RestoreBackup(context.Background(), p, volumesOnlyApp(),
		filepath.Join(p.backupsDir("n8n"), restoreTestSet))
	if err == nil || !strings.Contains(err.Error(), "не устоял") {
		t.Fatalf("перезапускающийся стек принят за восстановленный: %v\n%s", err, describeCalls(fd.calls()))
	}
	if !hasRestoreFlag(p, "n8n") {
		t.Error("флаг снят после стека, который не устоял")
	}
}

// --------------------------------------------------------------------------
// Отметка задания восстановления в две фазы (ADR-0063, решение 7)
// --------------------------------------------------------------------------
//
// Повторная выдача задания повторяет ОТЧЁТ, а не операцию: второй `down` и
// перезапись томов стёрли бы то, что приложение записало между прогонами.

// platformStub — поддельная платформа. Первые failFirst запросов теряются;
// возвращает клиент и чтение принятых отчётов и числа всех запросов.
func platformStub(t *testing.T, failFirst int) (*Client, func() ([]restoreReport, int)) {
	t.Helper()

	var mu sync.Mutex
	var accepted []restoreReport
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		requests++
		if requests <= failFirst {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		var report restoreReport
		if err := json.Unmarshal(raw, &report); err != nil {
			t.Errorf("отчёт агента не разбирается: %v", err)
		}
		accepted = append(accepted, report)
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	t.Cleanup(srv.Close)

	return NewClient(srv.URL, "test"), func() ([]restoreReport, int) {
		mu.Lock()
		defer mu.Unlock()
		return append([]restoreReport(nil), accepted...), requests
	}
}

func restoreTask() HostTask {
	return HostTask{ID: "task-1", Kind: "restore", Project: "n8n", BackupSet: restoreTestSet}
}

func volumesOnlyApp() DesiredApp {
	return DesiredApp{
		Slug:       "n8n",
		BackupSpec: BackupSpec{Volumes: []string{"app-data"}},
		ApplySpec:  ApplySpec{StableChecks: 1},
	}
}

func writeTaskMark(t *testing.T, p Paths, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.StateDir, "task.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readTaskMark читает task.json картой: тест проверяет формат на диске, а не
// структуру в коде.
func readTaskMark(t *testing.T, p Paths) (map[string]any, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(p.StateDir, "task.json"))
	if err != nil {
		t.Fatalf("task.json не читается: %v", err)
	}
	var mark map[string]any
	if err := json.Unmarshal(raw, &mark); err != nil {
		t.Fatalf("task.json не разбирается: %v: %s", err, raw)
	}
	return mark, string(raw)
}

// Агент прежней версии писал `{"task_id"}` только после принятого отчёта.
func TestTaskMarkOldFormatMeansReported(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	writeTaskMark(t, p, `{"task_id":"task-1"}`)
	client, reports := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	if err := RunTask(t.Context(), client, id, p, restoreTask(), []DesiredApp{volumesOnlyApp()}, nil); err != nil {
		t.Fatalf("закрытое задание вернуло ошибку: %v", err)
	}
	if log := calls(); len(log) != 0 {
		t.Errorf("закрытое задание тронуло стек:\n%s", describeCalls(log))
	}
	if _, requests := reports(); requests != 0 {
		t.Errorf("по закрытому заданию ушло запросов: %d", requests)
	}
}

// Исход на диске, отчёт не доехал: такт спустя уходит только отчёт — с тем,
// что было записано, и без docker.
func TestTaskMarkResendsUnreportedRestore(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeTaskMark(t, p, `{"task_id":"task-0","unreported":`+
		`{"task_id":"task-1","set":"20260910-120000","ms":4321,"error":"стек не поднялся после отката: ***"}}`)
	client, reports := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Приложения в желаемом состоянии уже может не быть: исход от этого не
	// меняется, и доставить его всё равно нужно.
	if err := RunTask(t.Context(), client, id, p, restoreTask(), nil, nil); err != nil {
		t.Fatalf("повторная доставка отчёта упала: %v", err)
	}

	accepted, requests := reports()
	if requests != 1 || len(accepted) != 1 {
		t.Fatalf("запросов %d, принято %d — ожидали ровно один отчёт", requests, len(accepted))
	}
	got := accepted[0]
	if got.TaskID != "task-1" || got.Result.Set != restoreTestSet || got.Result.MS != 4321 ||
		got.Error != "стек не поднялся после отката: ***" {
		t.Errorf("переотправлен не записанный исход: %+v", got)
	}
	if log := calls(); len(log) != 0 {
		t.Errorf("переотправка отчёта повторила операцию:\n%s", describeCalls(log))
	}
	mark, raw := readTaskMark(t, p)
	if _, left := mark["unreported"]; left || mark["task_id"] != "task-1" {
		t.Errorf("после доставки отметка не закрыта: %s", raw)
	}
}

// Неотправленный исход ПРОШЛОГО задания не закрывает новое.
//
// Повтор отчёта сверяет task_id: без сверки нажатие «восстановить» второй раз
// вернуло бы владельцу исход первого нажатия, а операция не пошла бы вовсе —
// приложение осталось бы на прежних данных с отчётом «восстановлено».
func TestTaskMarkUnreportedFromOtherTaskNotResent(t *testing.T) {
	fd := installFakeDockerRules(t, fakeDockerRules{})
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	writeTaskMark(t, p, `{"task_id":"task-0","unreported":`+
		`{"task_id":"task-1","set":"20260910-120000","ms":4321,"error":"старый исход"}}`)
	client, reports := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	task := HostTask{ID: "task-2", Kind: "restore", Project: "n8n", BackupSet: restoreTestSet}
	if err := RunTask(t.Context(), client, id, p, task, []DesiredApp{volumesOnlyApp()}, nil); err != nil {
		t.Fatalf("новое задание упало: %v\n%s", err, describeCalls(fd.calls()))
	}

	log := fd.calls()
	if i := firstCall(log, func(c fakeDockerCall) bool { return c.hasArg("down") }); i < 0 {
		t.Errorf("новое задание закрыто чужим исходом, восстановление не пошло:\n%s", describeCalls(log))
	}
	accepted, _ := reports()
	if len(accepted) != 1 {
		t.Fatalf("отчётов %d, ожидали один: %+v", len(accepted), accepted)
	}
	if got := accepted[0]; got.TaskID != "task-2" || got.Error != "" {
		t.Errorf("платформе ушёл не исход задания task-2: %+v", got)
	}
	if mark, raw := readTaskMark(t, p); mark["task_id"] != "task-2" {
		t.Errorf("новое задание не закрыто своей отметкой: %s", raw)
	}
}

// Отчёт потерян — исход лежит на диске, и в нём нет значений переменных.
func TestTaskMarkKeepsUnreportedWhenReportLost(t *testing.T) {
	installFakeDocker(t, "vol-app-data.tar.gz")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	app := volumesOnlyApp()
	// Значение совпадает с тем, что поддельный docker пишет в stderr отказа.
	app.Env = map[string]string{"LEAKY": "поддельный отказ docker"}
	client, _ := platformStub(t, 1)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	if err := RunTask(t.Context(), client, id, p, restoreTask(), []DesiredApp{app}, nil); err == nil {
		t.Fatal("отчёт не доехал, а задание считается закрытым")
	}

	mark, raw := readTaskMark(t, p)
	unreported, ok := mark["unreported"].(map[string]any)
	if !ok || unreported["task_id"] != "task-1" || unreported["set"] != restoreTestSet ||
		unreported["error"] == "" {
		t.Fatalf("исход восстановления не записан до отчёта: %s", raw)
	}
	if strings.Contains(raw, "поддельный отказ docker") {
		t.Errorf("в task.json попало значение переменной приложения: %s", raw)
	}
}

// Упавшее восстановление, чей отказ платформа приняла, не повторяется: без
// нового нажатия владельца разрушительная операция второй раз не идёт.
func TestTaskMarkFailedRestoreNotRepeated(t *testing.T) {
	calls := installFakeDocker(t, "vol-app-data.tar.gz")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	client, reports := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	apps := []DesiredApp{volumesOnlyApp()}

	if err := RunTask(t.Context(), client, id, p, restoreTask(), apps, nil); err == nil {
		t.Fatal("поддельный отказ распаковки не сорвал восстановление")
	}
	before := len(calls())

	if err := RunTask(t.Context(), client, id, p, restoreTask(), apps, nil); err != nil {
		t.Fatalf("повторная выдача закрытого задания вернула ошибку: %v", err)
	}
	if after := len(calls()); after != before {
		t.Errorf("упавшее восстановление повторено: вызовов docker %d → %d\n%s",
			before, after, describeCalls(calls()))
	}
	if accepted, _ := reports(); len(accepted) != 1 {
		t.Errorf("отчётов о задании %d, ожидали один", len(accepted))
	}
}

// Остановка агента посреди восстановления — не исход операции.
//
// SIGTERM убивает docker вместе с группой процессов, и RestoreBackup
// возвращает отказ погашенного стека. Записанный фазой 1, он закрыл бы задание
// ложным отказом: после запуска агент дослал бы его платформе, а флаг держал бы
// стек лежащим — до нового нажатия владельца, которого никто не ждёт. Поэтому
// прерванный прогон не записывается, не отчитывается и идёт с начала
// (ADR-0063, решение 6).
func TestRunTaskRestoreCancelledByShutdownRepeatsFromStart(t *testing.T) {
	fd := installFakeDockerRules(t, fakeDockerRules{})
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", map[string]string{"vol-app-data.tar.gz": "архив"})
	client, reports := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	apps := []DesiredApp{volumesOnlyApp()}

	// Отмена приходит ровно тогда, когда стек уже погашен, а `up` начался:
	// ждём доклада поддельного docker, а не таймера — по таймеру тест то ловил
	// бы этот момент, то нет.
	fd.blockUp(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := make(chan bool, 1)
	go func() {
		up := fd.waitUpStarted()
		cancel()
		reached <- up
	}()

	err = RunTask(ctx, client, id, p, restoreTask(), apps, nil)
	if !<-reached {
		t.Fatalf("поддельный docker не доложил о начале `up`: отмена пришла не посреди восстановления\n%s",
			describeCalls(fd.calls()))
	}
	if err == nil {
		t.Fatalf("прерванное восстановление объявлено удавшимся\n%s", describeCalls(fd.calls()))
	}
	if _, statErr := os.Stat(filepath.Join(p.StateDir, "task.json")); statErr == nil {
		mark, raw := readTaskMark(t, p)
		if _, recorded := mark["unreported"]; recorded {
			t.Errorf("отказ убитого остановкой агента docker записан исходом задания: %s", raw)
		}
	}
	if accepted, requests := reports(); len(accepted) != 0 || requests != 0 {
		t.Errorf("прерванный прогон отчитался платформе: запросов %d, принято %+v", requests, accepted)
	}
	if !hasRestoreFlag(p, "n8n") {
		t.Fatal("флаг снят после прерванного восстановления: самовосстановление подняло бы смешанные тома")
	}

	// Запуск агента: платформа выдаёт то же задание, флаг ещё стоит.
	fd.unblockUp(t)
	before := len(fd.calls())
	if err := RunTask(t.Context(), client, id, p, restoreTask(), apps, nil); err != nil {
		t.Fatalf("прогон после запуска агента упал: %v\n%s", err, describeCalls(fd.calls()))
	}
	log := fd.calls()
	if i := firstCall(log[before:], func(c fakeDockerCall) bool { return c.hasArg("down") }); i < 0 {
		t.Errorf("после запуска агента восстановление не пошло с начала: нового `down` нет\n%s",
			describeCalls(log))
	}
	accepted, _ := reports()
	if len(accepted) != 1 {
		t.Fatalf("отчётов о задании %d, ожидали один: %+v", len(accepted), accepted)
	}
	if got := accepted[0]; got.TaskID != "task-1" || got.Error != "" || got.Result.Set != restoreTestSet {
		t.Errorf("платформе ушёл не успех прогона с начала: %+v", got)
	}
	if hasRestoreFlag(p, "n8n") {
		t.Error("флаг остался после удачного восстановления")
	}
	mark, raw := readTaskMark(t, p)
	if _, left := mark["unreported"]; left || mark["task_id"] != "task-1" {
		t.Errorf("после удачного прогона отметка не закрыта: %s", raw)
	}
}

// Неотправленный отчёт восстановления не пропадает оттого, что между тактами
// прошло задание другого вида.
func TestTaskMarkOtherTaskKeepsUnreported(t *testing.T) {
	installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", nil)
	writeTaskMark(t, p, `{"task_id":"task-0","unreported":{"task_id":"task-1","set":"20260910-120000","ms":1,"error":""}}`)
	client, _ := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	backup := HostTask{ID: "task-2", Kind: "backup", Project: "n8n"}
	if err := RunTask(t.Context(), client, id, p, backup, []DesiredApp{volumesOnlyApp()}, nil); err != nil {
		t.Fatalf("плановая копия упала: %v", err)
	}

	mark, raw := readTaskMark(t, p)
	unreported, ok := mark["unreported"].(map[string]any)
	if mark["task_id"] != "task-2" || !ok || unreported["task_id"] != "task-1" {
		t.Errorf("отметка копии выбросила неотправленный отчёт восстановления: %s", raw)
	}
}

// --------------------------------------------------------------------------
// Копия при сорвавшемся восстановлении (решение оркестратора 3)
// --------------------------------------------------------------------------

// Копия со стека в несогласованном состоянии вытеснила бы годную при ротации.
func TestRunTaskBackupRefusedDuringRestore(t *testing.T) {
	calls := installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	writeRestoreFixture(t, p, "n8n", nil)
	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}
	client, reports := platformStub(t, 0)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	backup := HostTask{ID: "task-2", Kind: "backup", Project: "n8n"}
	if err := RunTask(t.Context(), client, id, p, backup, []DesiredApp{volumesOnlyApp()}, nil); err == nil {
		t.Fatal("копия снята при сорвавшемся восстановлении")
	}

	accepted, _ := reports()
	if len(accepted) != 1 || !strings.Contains(accepted[0].Error, "восстановление из копии не завершилось") {
		t.Fatalf("платформа не узнала причину отказа: %+v", accepted)
	}
	if len(accepted[0].Error) > 500 {
		t.Errorf("текст отказа длиннее предела отчёта (500 байт) и будет обрезан: %d", len(accepted[0].Error))
	}
	if log := calls(); len(log) != 0 {
		t.Errorf("при отказе копии агент тронул docker:\n%s", describeCalls(log))
	}
	if _, err := os.Stat(filepath.Join(p.StateDir, "task.json")); err == nil {
		t.Error("отказ копии закрыл задание отметкой")
	}
}

// --------------------------------------------------------------------------
// Флаг снимает удачный выкат (ADR-0063, решение 6)
// --------------------------------------------------------------------------

func restoreFlagApplyApp(compose string) DesiredApp {
	return DesiredApp{
		Slug:      "n8n",
		Desired:   "present",
		ReleaseID: "release-2",
		Compose:   compose,
		ApplySpec: ApplySpec{StableChecks: 1},
	}
}

// Иначе самовосстановление навсегда осталось бы выключенным у работающего
// приложения.
func TestApplyHealthyClearsRestoreFlag(t *testing.T) {
	installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}

	results := Apply(context.Background(), p, []DesiredApp{restoreFlagApplyApp("services: {}\n")}, nil)
	if len(results) != 1 || results[0].Status != "healthy" {
		t.Fatalf("выкат не дошёл до healthy: %+v", results)
	}
	if hasRestoreFlag(p, "n8n") {
		t.Error("удачный выкат не снял флаг восстановления")
	}
}

// Неудачный выкат флаг не снимает: стек так и не пришёл в рабочее состояние.
func TestApplyFailedKeepsRestoreFlag(t *testing.T) {
	installFakeDocker(t, "")
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	if err := setRestoreFlag(p, "n8n", restoreTestSet); err != nil {
		t.Fatal(err)
	}

	// Пустое описание стека — самый короткий путь к failed без docker.
	results := Apply(context.Background(), p, []DesiredApp{restoreFlagApplyApp("")}, nil)
	if len(results) != 1 || results[0].Status != "failed" {
		t.Fatalf("выкат не упал: %+v", results)
	}
	if !hasRestoreFlag(p, "n8n") {
		t.Error("неудачный выкат снял флаг восстановления")
	}
}
