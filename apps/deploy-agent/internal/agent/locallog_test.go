package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Локальный журнал команд (ADR-0095, п. 9). Опора — сам файл на сервере:
// платформа, которая лжёт в своём журнале, солжёт и на экране сверки. Поэтому
// здесь проверяется то, на что владелец сервера будет полагаться без нас:
// цепочка ловит подмену и удаление, записанное не переписывается, секретов в
// строках нет, хеши сходятся с журналом платформы.

func openTestJournal(t *testing.T, path string, out *bytes.Buffer) *Journal {
	t.Helper()
	j := OpenJournal(path, out, "2.2.0")
	j.now = func() time.Time { return time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC) }
	if j.Err() != "" {
		t.Fatalf("журнал не открылся: %s", j.Err())
	}
	return j
}

func journalLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
}

func fillJournal(t *testing.T, j *Journal, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		hash := sha256Hex(string(rune('a' + i)))
		if _, err := j.Receive(JournalKindHostTask, hash, map[string]any{"i": i}, DecisionAccepted, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func TestJournalChainVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	var out bytes.Buffer
	j := openTestJournal(t, path, &out)
	fillJournal(t, j, 5)

	if _, err := VerifyJournal(path); err != nil {
		t.Fatalf("целая цепочка не прошла проверку: %v", err)
	}
	lines := journalLines(t, path)
	if len(lines) != 6 {
		t.Fatalf("строк %d, ожидалось genesis + 5", len(lines))
	}
	var first JournalEntry
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first.Type != "genesis" || first.Seq != 1 || first.Prev != "" {
		t.Fatalf("первая строка не genesis: %s", lines[0])
	}
	// Порядок ключей фиксирован: цепочку проверяют и sha256sum с jq, без нас.
	if !strings.HasPrefix(lines[1], `{"v":1,"seq":2,"at":"2026-09-23T10:00:00Z","type":"receive","kind":"host_task","hash":"`) ||
		!strings.Contains(lines[1], `,"summary":{"i":0},"decision":"accepted","reason":"","prev":"`+sha256Hex(lines[0])+`"}`) {
		t.Fatalf("строка не в фиксированном порядке ключей: %s", lines[1])
	}
	// Второй экземпляр — в stdout, то есть в journald, который пишет root.
	if out.String() != strings.Join(lines, "\n")+"\n" {
		t.Fatalf("в stdout ушло не то, что в файл:\n%s", out.String())
	}
}

func TestJournalEditedLineReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	fillJournal(t, j, 5)

	lines := journalLines(t, path)
	// Подмена решения в третьей строке — ровно то, что сделал бы тот, кто
	// хочет спрятать исполненную команду.
	lines[2] = strings.Replace(lines[2], `"decision":"accepted"`, `"decision":"refused"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var broken *JournalBreak
	if _, err := VerifyJournal(path); !errors.As(err, &broken) || broken.Line != 3 {
		t.Fatalf("правка строки 3 не опознана: %v", err)
	}
}

func TestJournalDeletedLineReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	fillJournal(t, j, 5)

	lines := journalLines(t, path)
	kept := append(append([]string{}, lines[:3]...), lines[4:]...)
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var broken *JournalBreak
	if _, err := VerifyJournal(path); !errors.As(err, &broken) || broken.Line != 4 {
		t.Fatalf("удаление строки 4 не опознано: %v", err)
	}

	// Пустой журнал после первого запуска агента — усечение, а не «цело».
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJournal(path); !errors.As(err, &broken) || broken.Line != 1 {
		t.Fatalf("пустой журнал признан целым: %v", err)
	}

	// Не читается — не «сломан»: это другой исход и другой код выхода.
	if _, err := VerifyJournal(filepath.Join(t.TempDir(), "nope.log")); err == nil || errors.As(err, &broken) {
		t.Fatalf("отсутствующий файл: %v", err)
	}
}

func TestJournalNeverRewritesWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	var before []byte
	for i := 0; i < 10; i++ {
		if _, err := j.Receive(JournalKindHostTask, sha256Hex(fmt.Sprint(i)), nil, DecisionAccepted, ""); err != nil {
			t.Fatal(err)
		}
		now, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(now, before) {
			t.Fatalf("после дописывания %d изменились прежние байты", i+1)
		}
		before = now
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права журнала %v, ожидалось 0600", info.Mode().Perm())
	}
}

func TestJournalDedupSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	h1, h2 := sha256Hex("one"), sha256Hex("two")

	if wrote, _ := j.Receive(JournalKindDesiredState, h1, nil, DecisionRefused, "режим наблюдения"); !wrote {
		t.Fatal("первая выдача не записана")
	}
	if wrote, _ := j.Receive(JournalKindDesiredState, h1, nil, DecisionRefused, "режим наблюдения"); wrote {
		t.Fatal("та же выдача записана второй раз — журнал утонет в одинаковых строках")
	}

	// Перезапуск: голова и последнее по виду читаются из файла.
	j = openTestJournal(t, path, &bytes.Buffer{})
	if wrote, _ := j.Receive(JournalKindDesiredState, h1, nil, DecisionRefused, "режим наблюдения"); wrote {
		t.Fatal("после перезапуска повтор той же выдачи записан")
	}
	// То же состояние, но исполненное после включения deploy, — новая строка:
	// иначе журнал не показал бы, что его применили.
	if wrote, _ := j.Receive(JournalKindDesiredState, h1, nil, DecisionAccepted, ""); !wrote {
		t.Fatal("смена решения по той же команде не записана")
	}
	if wrote, _ := j.Receive(JournalKindDesiredState, h2, nil, DecisionAccepted, ""); !wrote {
		t.Fatal("новая команда не записана")
	}
	if wrote, _ := j.Receive(JournalKindHostTask, h2, nil, DecisionAccepted, ""); !wrote {
		t.Fatal("тот же хеш другого вида не записан")
	}
	if _, err := VerifyJournal(path); err != nil {
		t.Fatalf("цепочка через перезапуск: %v", err)
	}
	if head := j.Head(); head.Seq != 5 || head.Hash != sha256Hex(journalLines(t, path)[4]) {
		t.Fatalf("голова %+v", head)
	}
}

func TestJournalPolicyLineOnFileChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})

	absent := LocalPolicy{State: PolicyAbsent}
	observe := ParsePolicy([]byte("version=1\n"))
	observe.Sha256 = sha256Hex("version=1\n")
	deploy := ParsePolicy([]byte("version=1\nmode=deploy\n"))
	deploy.Sha256 = sha256Hex("version=1\nmode=deploy\n")

	steps := []struct {
		policy LocalPolicy
		want   bool
	}{
		{absent, false}, // файла не было и нет — писать нечего
		{observe, true},
		{observe, false},
		{deploy, true}, // «когда включили исполнение» видно из журнала
		{absent, true},
	}
	for i, step := range steps {
		wrote, err := j.NotePolicy(step.policy)
		if err != nil || wrote != step.want {
			t.Fatalf("шаг %d: записано=%v (%v), ожидалось %v", i, wrote, err, step.want)
		}
	}
	j = openTestJournal(t, path, &bytes.Buffer{})
	if wrote, _ := j.NotePolicy(absent); wrote {
		t.Fatal("после перезапуска та же политика записана повторно")
	}
	lines := journalLines(t, path)
	if !strings.Contains(lines[2], `"type":"policy"`) || !strings.Contains(lines[2], `"hash":"`+deploy.Sha256+`"`) {
		t.Fatalf("строка политики: %s", lines[2])
	}
}

// Сводка — имена приложений и переменных, без значений (ADR-0085): журнал с
// секретами клиента стоил бы дороже, чем его отсутствие.
func TestJournalSummaryHasNoSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	secrets := []string{"pg-password-value", "-----BEGIN OPENSSH PRIVATE KEY-----", "ghs_installation_token",
		"registry-token-value", "s3-secret-key-value", "build-arg-value"}
	state := DesiredState{
		Apps: []DesiredApp{{
			Slug: "shop", Desired: "present", ReleaseID: "r1", SourceType: "git",
			Env:       map[string]string{"DB_PASSWORD": secrets[0], "PUBLIC_URL": "https://shop.example.test"},
			BuildArgs: map[string]string{"NEXT_PUBLIC_KEY": secrets[5]},
			GitKey:    secrets[1], GitToken: secrets[2],
		}},
		Registries:    []RegistryCredential{{Registry: "registry.example.test", Username: "ci", Token: secrets[3]}},
		ObjectStorage: &ObjectStorageSpec{SecretKey: secrets[4]},
	}
	if _, err := j.Receive(JournalKindDesiredState, sha256Hex("x"), DesiredStateSummary(state), DecisionAccepted, ""); err != nil {
		t.Fatal(err)
	}
	task := HostTask{ID: "t1", Kind: "backup", Project: "shop"}
	if _, err := j.Receive(JournalKindHostTask, sha256Hex("y"), HostTaskSummary(task), DecisionRefused, "режим наблюдения"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, secret := range secrets {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("значение %q попало в журнал:\n%s", secret, raw)
		}
	}
	for _, name := range []string{"DB_PASSWORD", "PUBLIC_URL", "registry.example.test", `"hasGitKey":true`, `"taskId":"t1"`} {
		if !strings.Contains(string(raw), name) {
			t.Fatalf("в сводке нет %q — по журналу не понять, что пришло:\n%s", name, raw)
		}
	}
}

// Хеш команды тот же, что у платформы (ADR-0085): sha256 сырых байтов ответа,
// а не пересборки — Go экранирует <, > и & иначе, чем JSON.stringify.
func TestCommandHashFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..",
		"packages", "deploy-core", "fixtures", "command-hash.json"))
	if err != nil {
		t.Fatalf("фикстура хешей не читается: %v", err)
	}
	var fx struct {
		StateKeys []string `json:"stateKeys"`
		Cases     []struct {
			Name             string  `json:"name"`
			Response         string  `json:"response"`
			DesiredStateHash *string `json:"desiredStateHash"`
			HostTaskHash     *string `json:"hostTaskHash"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) == 0 {
		t.Fatal("случаев в фикстуре нет — проверка не проведена")
	}
	if strings.Join(fx.StateKeys, ",") != strings.Join(desiredStateKeys, ",") {
		t.Fatalf("порядок ключей состояния агента %v, в фикстуре %v", desiredStateKeys, fx.StateKeys)
	}
	escaped := false
	for _, tc := range fx.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got := CommandHashes([]byte(tc.Response))
			want := func(p *string) string {
				if p == nil {
					return ""
				}
				return *p
			}
			if got.State != want(tc.DesiredStateHash) {
				t.Fatalf("хеш состояния %q, ожидался %q", got.State, want(tc.DesiredStateHash))
			}
			if got.Task != want(tc.HostTaskHash) {
				t.Fatalf("хеш задания %q, ожидался %q", got.Task, want(tc.HostTaskHash))
			}
		})
		if strings.ContainsAny(tc.Response, "<&") {
			escaped = true
		}
	}
	if !escaped {
		t.Fatal("в фикстуре нет < и & — расхождение с пересборкой не проверяется")
	}
}

func TestJournalReportCarriesHeadAndRecent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	fillJournal(t, j, 25)

	report := j.Report()
	if report.Head != j.Head() || len(report.Entries) != 20 {
		t.Fatalf("доклад: голова %+v, записей %d", report.Head, len(report.Entries))
	}
	if first, last := report.Entries[0], report.Entries[19]; first.Seq != 7 || last.Seq != 26 {
		t.Fatalf("в докладе не последние записи: %d…%d", first.Seq, last.Seq)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), `"summary"`) || strings.Contains(string(raw), `"prev"`) {
		t.Fatalf("в докладе лишнее: %s", raw)
	}

	// Перезапуск: последние записи восстанавливаются из файла.
	again := openTestJournal(t, path, &bytes.Buffer{}).Report()
	if again.Head != report.Head || len(again.Entries) != 20 || again.Entries[0].Seq != 7 {
		t.Fatalf("после перезапуска доклад %+v", again.Head)
	}
}

func TestJournalShowSince(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	fillJournal(t, j, 3)

	var out bytes.Buffer
	if err := ShowJournal(path, 3, &out); err != nil {
		t.Fatal(err)
	}
	lines := journalLines(t, path)
	if out.String() != lines[2]+"\n"+lines[3]+"\n" {
		t.Fatalf("show --since 3:\n%s", out.String())
	}
}

// Атрибут «только дописывание» (chattr +a) — то, что делает журнал опорой:
// без него пользователь агента перепишет файл. Флаги файла подменяются: на
// машине прогона атрибута не поставить.
func TestJournalAppendOnlyReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.log")
	j := openTestJournal(t, path, &bytes.Buffer{})
	prev := journalFileFlags
	t.Cleanup(func() { journalFileFlags = prev })

	cases := []struct {
		name  string
		flags uint32
		err   error
		want  string
	}{
		{"атрибут стоит", fsAppendFL | 0x00080000, nil, `"appendOnly":true`},
		{"атрибута нет", 0x00080000, nil, `"appendOnly":false`},
		{"определить нельзя", 0, errors.New("inappropriate ioctl for device"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			journalFileFlags = func(string) (uint32, error) { return tc.flags, tc.err }
			raw, err := json.Marshal(j.Report())
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if strings.Contains(string(raw), "appendOnly") {
					t.Fatalf("неизвестное доложено как известное: %s", raw)
				}
				return
			}
			if !strings.Contains(string(raw), tc.want) {
				t.Fatalf("доклад %s, ожидалось %s", raw, tc.want)
			}
		})
	}
}
