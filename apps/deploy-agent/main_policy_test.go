package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Политика хоста в такте целиком (ADR-0095, п. 2 и 6): настоящий tick,
// настоящий клиент, фейк платформы и поддельный docker, записывающий каждый
// вызов. Свойство «observe не исполняет ничего» здесь проверяется не на
// функции решения, а на том, что агент сделал с диском, демоном и платформой.

// installRecordingDocker кладёт в PATH docker, который записывает свои
// аргументы и отказывает, и пустой ss. Возвращает путь записи вызовов.
//
// Список контейнеров отвечает пустым успехом: без него уборка останавливается
// на осмотре и до `compose down` не доходит — а именно его и надо увидеть.
func installRecordingDocker(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	calls := filepath.Join(t.TempDir(), "docker-calls.log")
	docker := "#!/bin/sh\n" +
		`printf '%s\n' "$*" >> '` + calls + "'\n" +
		`case " $* " in *" ps --all --filter "*) exit 0;; esac` + "\n" +
		"exit 1\n"
	for name, body := range map[string]string{"docker": docker, "ss": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	// Второй рубеж: даже настоящий docker, окажись он первым в PATH, не
	// дотянется до демона машины прогона.
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(bin, "no-daemon.sock"))
	return calls
}

// dockerCalls — записанные вызовы docker, по строке на вызов.
func dockerCalls(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

// writingDockerCalls — вызовы, которые меняют хост или демон.
func writingDockerCalls(calls []string) []string {
	writing := map[string]bool{
		"up": true, "down": true, "rm": true, "exec": true, "login": true, "pull": true,
		"build": true, "run": true, "start": true, "stop": true, "restart": true, "kill": true,
		"create": true, "cp": true,
	}
	var out []string
	for _, call := range calls {
		for _, arg := range strings.Fields(call) {
			if writing[arg] {
				out = append(out, call)
				break
			}
		}
	}
	return out
}

func withPolicyFile(t *testing.T, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent-policy.conf")
	if text != "" {
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prev := agent.PolicyPath
	agent.PolicyPath = path
	t.Cleanup(func() { agent.PolicyPath = prev })
}

// withHostControl ставит контроллер такта так, как это делает cmdRun, и
// снимает его после теста.
func withHostControl(t *testing.T, l *localControl) {
	t.Helper()
	prev := hostControl
	hostControl = l
	t.Cleanup(func() { hostControl = prev })
}

// platformFake — платформа, которая запоминает запросы агента, а в момент
// отчёта о задании читает локальный журнал: так видно, что receive лёг ДО
// побочного действия.
type platformFake struct {
	mu          sync.Mutex
	paths       []string
	taskReports []map[string]any
	journalSeen []string
	downloads   atomic.Int64
}

func newPlatformFake(t *testing.T, journalPath, tickResponse string) (*httptest.Server, *platformFake) {
	t.Helper()
	fake := &platformFake{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		fake.mu.Lock()
		fake.paths = append(fake.paths, r.URL.Path)
		fake.mu.Unlock()
		switch r.URL.Path {
		case "/api/deploy/agent/migration":
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			journal, _ := os.ReadFile(journalPath)
			fake.mu.Lock()
			fake.taskReports = append(fake.taskReports, body)
			fake.journalSeen = append(fake.journalSeen, string(journal))
			fake.mu.Unlock()
		case "/api/deploy/agent-binary":
			fake.downloads.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		case "/api/deploy/agent/tick":
			_, _ = w.Write([]byte(tickResponse))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, fake
}

func (f *platformFake) called(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.paths {
		if p == path {
			n++
		}
	}
	return n
}

// policyHost — хост, на котором агент уже развернул shop: каталог, файлы и
// отметки применения, как после выката в режиме deploy.
type policyHost struct {
	paths   agent.Paths
	applied []byte
	journal string
}

func newPolicyHost(t *testing.T) policyHost {
	t.Helper()
	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	const compose = "services:\n  app:\n    image: nginx\n"
	const env = "DB_PASSWORD='host-secret-value'\n"
	dir := filepath.Join(paths.WorkDir, "apps", "shop")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"docker-compose.yml": compose, ".env": env} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	applied := []byte(`{"apps":{"shop":{"release_id":"release-1","config_hash":"x","status":"healthy",` +
		`"compose_sha256":"` + hexSha256(compose) + `","env_sha256":"` + hexSha256(env) + `"}}}`)
	if err := os.WriteFile(filepath.Join(paths.StateDir, "applied.json"), applied, 0o600); err != nil {
		t.Fatal(err)
	}
	return policyHost{paths: paths, applied: applied, journal: filepath.Join(paths.StateDir, "journal.log")}
}

// observedResponse — ответ платформы, которая хочет всего сразу: новый релиз
// shop, новое приложение blog, ключ хранилища, копию и осмотр.
const observedResponse = `{"hostId":"h1","targetAgentVersion":"","inventoryRequestedAt":"2026-09-23T10:00:00Z",` +
	`"task":{"id":"task-1","kind":"backup","project":"shop","dir":"","volume":"","backupSet":""},` +
	`"apps":[{"slug":"shop","desired":"present","releaseId":"release-2","compose":"services:\n  app:\n    image: nginx:2\n","env":{"DB_PASSWORD":"platform-secret-value"}},` +
	`{"slug":"blog","desired":"present","releaseId":"release-3","compose":"services:\n  app:\n    image: nginx\n"}],` +
	`"registries":[{"registry":"registry.example.test","username":"ci","token":"registry-secret-value"}],` +
	`"denyIps":[],"platformSubdomainBase":null,` +
	`"objectStorage":{"endpoint":"https://s3.example.test","bucket":"b","accessKeyId":"k","secretAccessKey":"s3-secret-value","keyFingerprint":"f"},` +
	`"nextPollSeconds":60}`

// tickUnderPolicy — один такт с ответом raw так, как его отдал бы cmdRun.
func tickUnderPolicy(t *testing.T, host policyHost, client *agent.Client, raw string, gate *agent.ReportGate) (agent.TickRequest, tickDelivery, *localControl) {
	t.Helper()
	var resp agent.TickResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatal(err)
	}
	resp.Raw = json.RawMessage(raw)
	local := &localControl{
		journal: agent.OpenJournal(host.journal, io.Discard, "test"),
		raw:     resp.Raw,
		trust:   agent.NewTrustReport(""),
	}
	withHostControl(t, local)
	var heartbeat atomic.Pointer[agent.HeartbeatResponse]
	heartbeat.Store(&resp.HeartbeatResponse)
	var proxyError atomic.Pointer[string]
	report, delivery := tick(t.Context(), client, testIdentity(t), host.paths, agent.ProxyOptions{},
		resp.DesiredState, haveDesiredState(resp), false, &proxyError, &heartbeat, gate,
		agent.LoadReportQueue(host.paths), false)
	return report, delivery, local
}

func TestObservePolicyExecutesNothing(t *testing.T) {
	calls := installRecordingDocker(t)
	withPolicyFile(t, "version=1\nmode=observe\n")
	host := newPolicyHost(t)
	srv, platform := newPlatformFake(t, host.journal, `{}`)

	report, _, _ := tickUnderPolicy(t, host, agent.NewClient(srv.URL, "test"), observedResponse, agent.NewReportGate())

	// Хост не тронут: ни нового стека, ни прокси, ни отметок применения.
	entries, err := os.ReadDir(filepath.Join(host.paths.WorkDir, "apps"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "shop" {
		t.Fatalf("в WorkDir/apps появилось лишнее: %v, %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(host.paths.WorkDir, "proxy")); !os.IsNotExist(err) {
		t.Fatalf("в observe настроен прокси: %v", err)
	}
	if now, _ := os.ReadFile(filepath.Join(host.paths.StateDir, "applied.json")); !bytes.Equal(now, host.applied) {
		t.Fatalf("applied.json изменился:\n%s", now)
	}
	if _, err := os.Stat(filepath.Join(host.paths.StateDir, "storage-key.json")); !os.IsNotExist(err) {
		t.Fatalf("в observe ключ хранилища лёг на диск: %v", err)
	}
	if report.Storage != nil || report.StorageKeyAck != "" {
		t.Fatalf("в observe проба или подтверждение ключа хранилища: %+v %q", report.Storage, report.StorageKeyAck)
	}

	// Демон слышал только чтение. «Вызовов нет» — не «пишущих нет»: здоровье
	// уже развёрнутого shop опрашивается и в наблюдении.
	recorded := dockerCalls(t, calls)
	if len(recorded) == 0 {
		t.Fatal("docker не вызывался вовсе — проверять нечего")
	}
	if writing := writingDockerCalls(recorded); len(writing) > 0 {
		t.Fatalf("в observe пишущие вызовы docker: %v", writing)
	}
	if !strings.Contains(strings.Join(recorded, "\n"), "ps --all") {
		t.Fatalf("здоровье развёрнутого shop не опрошено: %v", recorded)
	}

	// Платформа получила отказ задания и ничего больше.
	if n := platform.called("/api/deploy/agent/migration"); n != 1 {
		t.Fatalf("отчётов о задании %d, ожидался один отказ", n)
	}
	for _, path := range []string{"/api/deploy/agent/report", "/api/deploy/agent/inventory", "/api/deploy/agent/registry-login"} {
		if n := platform.called(path); n != 0 {
			t.Fatalf("в observe запрос %s (%d)", path, n)
		}
	}
	if msg, _ := platform.taskReports[0]["error"].(string); !strings.Contains(msg, "политика сервера — режим наблюдения") {
		t.Fatalf("отказ без причины: %+v", platform.taskReports[0])
	}

	// receive лёг ДО отчёта — платформа при отчёте уже видит его в файле.
	hashes := agent.CommandHashes([]byte(observedResponse))
	if seen := platform.journalSeen[0]; !strings.Contains(seen, `"type":"receive","kind":"host_task","hash":"`+hashes.Task+`"`) ||
		!strings.Contains(seen, `"decision":"refused","reason":"режим наблюдения"`) {
		t.Fatalf("к моменту отчёта в журнале нет receive с отказом:\n%s", seen)
	}
	journal, _ := os.ReadFile(host.journal)
	if !strings.Contains(string(journal), `"type":"receive","kind":"desired_state","hash":"`+hashes.State+`"`) {
		t.Fatalf("приход состояния не записан:\n%s", journal)
	}
	if !strings.Contains(string(journal), `"type":"policy"`) {
		t.Fatalf("строки политики нет:\n%s", journal)
	}
	for _, secret := range []string{"platform-secret-value", "registry-secret-value", "s3-secret-value", "host-secret-value"} {
		if strings.Contains(string(journal), secret) {
			t.Fatalf("секрет %q в журнале", secret)
		}
	}
	if _, err := agent.VerifyJournal(host.journal); err != nil {
		t.Fatalf("журнал после такта: %v", err)
	}
	if report.LocalPolicy == nil || report.LocalPolicy.Mode != "observe" || !report.LocalPolicy.Present {
		t.Fatalf("политика не доложена: %+v", report.LocalPolicy)
	}
}

// Доклад такта — ровно ключи контракта (К3, К4): лишний ключ разбор платформы
// считает мусором и закрывает всё.
func TestTickReportCarriesPolicyJournalTrust(t *testing.T) {
	installRecordingDocker(t)
	withPolicyFile(t, "version=1\nmode=observe\n")
	host := newPolicyHost(t)
	srv, _ := newPlatformFake(t, host.journal, `{}`)
	client := agent.NewClient(srv.URL, "test")
	gate := agent.NewReportGate()

	report, delivery, local := tickUnderPolicy(t, host, client, observedResponse, gate)
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	keysOf := func(name string) []string {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(body[name], &m); err != nil {
			t.Fatalf("%s не объект: %s", name, body[name])
		}
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	if got := strings.Join(keysOf("localPolicy"), ","); got !=
		"commands,containerLogs,deployAgentUpdates,deployAgentUpdatesEffective,mode,monitorAgentUpdates,present,protected,sha256" {
		t.Fatalf("ключи localPolicy: %s", got)
	}
	if got := strings.Join(keysOf("trust"), ","); got != "proxyVersion,releaseKeys,stateRoots" {
		t.Fatalf("ключи trust: %s", got)
	}
	if got := strings.Join(keysOf("localJournal"), ","); got != "entries,head" {
		t.Fatalf("ключи localJournal: %s", got)
	}

	// Журнал уезжает только при смене головы: доставленный доклад со той же
	// головой второй раз не шлётся.
	legacy := false
	resp, err := exchange(t.Context(), client, testIdentity(t), report, delivery, gate,
		agent.LoadReportQueue(host.paths), &legacy)
	if err != nil {
		t.Fatal(err)
	}
	local.received(resp, gate, legacy)
	var again agent.TickRequest
	local.addJournalReport(&again, gate)
	if again.LocalJournal != nil {
		t.Fatal("доклад журнала с прежней головой ушёл повторно")
	}
	if _, err := local.journal.Receive(agent.JournalKindHostTask, hexSha256("next"), nil, agent.DecisionAccepted, ""); err != nil {
		t.Fatal(err)
	}
	local.addJournalReport(&again, gate)
	if again.LocalJournal == nil || again.LocalJournal.Head != local.journal.Head() {
		t.Fatalf("новая голова журнала не доложена: %+v", again.LocalJournal)
	}
}

// Ответ без apps — состояния нет (ADR-0095, п. 6): ни уборки, ни прокси.
// "apps":[] — законное «снять всё», и для старой платформы, которая всегда
// шлёт apps массивом, поведение прежнее.
func TestResponseWithoutAppsKeepsStacks(t *testing.T) {
	cases := []struct {
		name      string
		response  string
		haveState bool
	}{
		{"ответ без apps", `{"stateWithheld":"policy","task":null}`, false},
		{"apps: null", `{"apps":null}`, false},
		{"apps: [] — снять всё", `{"apps":[]}`, true},
		{"старая платформа со списком", `{"apps":[{"slug":"shop","desired":"present"}],"registries":[]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.response))
			}))
			defer srv.Close()
			resp, err := agent.NewClient(srv.URL, "test").Tick(t.Context(), testIdentity(t), agent.TickRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if got := haveDesiredState(resp); got != tc.haveState {
				t.Fatalf("haveState = %v, ожидалось %v", got, tc.haveState)
			}
			if string(resp.Raw) != tc.response {
				t.Fatalf("сырой ответ %q", resp.Raw)
			}
		})
	}

	// Без файла политики: ответ без apps стеки не снимает, "apps":[] — снимает.
	for _, tc := range []struct {
		response string
		wantDown bool
	}{
		{`{"stateWithheld":"policy","task":null}`, false},
		{`{"apps":[]}`, true},
	} {
		calls := installRecordingDocker(t)
		withPolicyFile(t, "")
		host := newPolicyHost(t)
		srv, _ := newPlatformFake(t, host.journal, `{}`)
		tickUnderPolicy(t, host, agent.NewClient(srv.URL, "test"), tc.response, agent.NewReportGate())

		down := false
		for _, call := range dockerCalls(t, calls) {
			if strings.Contains(call, " down") {
				down = true
			}
		}
		if down != tc.wantDown {
			t.Fatalf("%s: compose down=%v, ожидалось %v; вызовы %v", tc.response, down, tc.wantDown, dockerCalls(t, calls))
		}
	}
}

func TestDeployWithoutBackupRefusesBackup(t *testing.T) {
	calls := installRecordingDocker(t)
	withPolicyFile(t, "version=1\nmode=deploy\ncommands=inventory,restore\n")
	host := newPolicyHost(t)
	srv, platform := newPlatformFake(t, host.journal, `{}`)

	tickUnderPolicy(t, host, agent.NewClient(srv.URL, "test"), observedResponse, agent.NewReportGate())

	if n := platform.called("/api/deploy/agent/migration"); n != 1 {
		t.Fatalf("отчётов о задании %d", n)
	}
	if msg, _ := platform.taskReports[0]["error"].(string); !strings.Contains(msg, "вид «backup» не в списке commands") {
		t.Fatalf("отказ backup: %+v", platform.taskReports[0])
	}
	// apply вне списка — состояние принято, но не применено.
	if writing := writingDockerCalls(dockerCalls(t, calls)); len(writing) > 0 {
		t.Fatalf("без apply в списке пишущие вызовы docker: %v", writing)
	}
	journal, _ := os.ReadFile(host.journal)
	if !strings.Contains(string(journal), `"decision":"refused","reason":"вид «apply» не в списке commands"`) {
		t.Fatalf("отказ в применении не записан:\n%s", journal)
	}
}

// Самообновление под политикой (ADR-0095, п. 3): где политика не пускает,
// загрузка не начинается вовсе — фейк считает запросы к agent-binary.
func TestSelfUpdateStepHonoursPolicy(t *testing.T) {
	prev := Version
	Version = "2.2.0"
	t.Cleanup(func() { Version = prev })

	cases := []struct {
		name      string
		policy    string
		downloads int64
		decision  string
	}{
		{"manual", "version=1\nmode=deploy\ndeploy_agent_updates=manual\n", 0, "refused"},
		{"observe + auto без ключа выпуска", "version=1\ndeploy_agent_updates=auto\n", 0, "refused"},
		{"закреплена другая версия", "version=1\nmode=deploy\ndeploy_agent_updates=pinned 3.0.0\n", 0, "refused"},
		// Без вшитого ключа номер версии ничего не доказывает: пин — как manual.
		{"закреплена эта версия, ключа выпуска нет", "version=1\nmode=deploy\ndeploy_agent_updates=pinned 9.9.9\n", 0, "refused"},
		{"auto в deploy со всеми видами", "version=1\nmode=deploy\ndeploy_agent_updates=auto\n", 1, "accepted"},
		{"файла нет — как раньше", "", 1, "accepted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPolicyFile(t, tc.policy)
			host := newPolicyHost(t)
			srv, platform := newPlatformFake(t, host.journal, `{}`)
			local := &localControl{
				journal: agent.OpenJournal(host.journal, io.Discard, "test"),
				policy:  agent.LoadLocalPolicy(),
			}
			hb := agent.HeartbeatResponse{
				TargetAgentVersion: "9.9.9",
				TargetAgentSha256:  agent.AgentSha256ByArch{Amd64: hexSha256("x"), Arm64: hexSha256("x")},
			}
			if _, ok := local.selfUpdate(t.Context(), agent.NewClient(srv.URL, "test"), host.paths, hb); ok {
				t.Fatal("обновление «установлено» при отказе загрузки")
			}
			if got := platform.downloads.Load(); got != tc.downloads {
				t.Fatalf("загрузок бинаря %d, ожидалось %d", got, tc.downloads)
			}
			journal, _ := os.ReadFile(host.journal)
			if !strings.Contains(string(journal), `"type":"receive","kind":"self_update"`) ||
				!strings.Contains(string(journal), `"decision":"`+tc.decision+`"`) {
				t.Fatalf("решение о самообновлении не записано:\n%s", journal)
			}
		})
	}
}

// Разрешённое задание исполняется, и его приход лёг в журнал раньше, чем
// исполнение дошло до платформы. Копия shop без описания в шаблоне — «нечего
// резервировать»: настоящий путь RunTask без docker.
func TestDeployRunsListedTaskAfterReceive(t *testing.T) {
	installRecordingDocker(t)
	withPolicyFile(t, "version=1\nmode=deploy\ncommands=backup\n")
	host := newPolicyHost(t)
	srv, platform := newPlatformFake(t, host.journal, `{}`)

	tickUnderPolicy(t, host, agent.NewClient(srv.URL, "test"), observedResponse, agent.NewReportGate())

	if n := platform.called("/api/deploy/agent/migration"); n != 1 {
		t.Fatalf("отчётов о задании %d", n)
	}
	if msg, _ := platform.taskReports[0]["error"].(string); strings.Contains(msg, "политика сервера") ||
		!strings.Contains(msg, "нечего резервировать") {
		t.Fatalf("задание из списка не исполнено: %+v", platform.taskReports[0])
	}
	hash := agent.CommandHashes([]byte(observedResponse)).Task
	if seen := platform.journalSeen[0]; !strings.Contains(seen,
		`"type":"receive","kind":"host_task","hash":"`+hash+`"`) || !strings.Contains(seen, `"decision":"accepted"`) {
		t.Fatalf("к моменту исполнения прихода задания в журнале нет:\n%s", seen)
	}
	journal, _ := os.ReadFile(host.journal)
	if !strings.Contains(string(journal), `"type":"result","kind":"host_task","hash":"`+hash+`","summary":{"ok":true}`) {
		t.Fatalf("исход задания не записан:\n%s", journal)
	}
}

// Без контроллера нет журнала, но политика действует: забытый контроллер не
// превращает observe в «можно всё».
func TestTickWithoutControllerStillHonoursPolicy(t *testing.T) {
	calls := installRecordingDocker(t)
	withPolicyFile(t, "version=1\nmode=observe\n")
	withHostControl(t, nil)
	host := newPolicyHost(t)
	srv, platform := newPlatformFake(t, host.journal, `{}`)

	var resp agent.TickResponse
	if err := json.Unmarshal([]byte(observedResponse), &resp); err != nil {
		t.Fatal(err)
	}
	var heartbeat atomic.Pointer[agent.HeartbeatResponse]
	heartbeat.Store(&resp.HeartbeatResponse)
	var proxyError atomic.Pointer[string]
	tick(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), host.paths, agent.ProxyOptions{},
		resp.DesiredState, true, false, &proxyError, &heartbeat, agent.NewReportGate(),
		agent.LoadReportQueue(host.paths), false)

	if entries, _ := os.ReadDir(filepath.Join(host.paths.WorkDir, "apps")); len(entries) != 1 {
		t.Fatalf("без контроллера состояние применено: %v", entries)
	}
	if writing := writingDockerCalls(dockerCalls(t, calls)); len(writing) > 0 {
		t.Fatalf("без контроллера пишущие вызовы docker: %v", writing)
	}
	if len(platform.taskReports) != 1 {
		t.Fatalf("отчётов о задании %d, ожидался один отказ", len(platform.taskReports))
	}
	if msg, _ := platform.taskReports[0]["error"].(string); !strings.Contains(msg, "режим наблюдения") {
		t.Fatalf("без контроллера задание не отклонено: %+v", platform.taskReports)
	}
}

// deploy → observe → deploy с тем же состоянием S (ADR-0095, п. 9): платформа
// пишет S «отправлено», затем «не отправлено», затем S «отправлено» заново.
// Хост обязан записать второй приход S строкой: иначе сверка покажет вторую
// отправку платформы без пары — ложный признак подмены.
func TestStateReceivedAgainAfterWithheld(t *testing.T) {
	host := newPolicyHost(t)
	local := &localControl{
		journal: agent.OpenJournal(host.journal, io.Discard, "test"),
		trust:   agent.NewTrustReport(""),
	}
	const withState = `{"hostId":"h1","apps":[{"slug":"shop","desired":"present","releaseId":"release-1"}],"registries":[]}`
	const withheld = `{"hostId":"h1","stateWithheld":"policy","task":null}`

	step := func(policy, raw string) bool {
		t.Helper()
		withPolicyFile(t, policy)
		var resp agent.TickResponse
		if err := json.Unmarshal([]byte(raw), &resp); err != nil {
			t.Fatal(err)
		}
		resp.Raw = json.RawMessage(raw)
		local.received(resp, agent.NewReportGate(), true)
		var report agent.TickRequest
		local.beginTick(&report, nil, resp.DesiredState, haveDesiredState(resp))
		return local.stateFresh
	}

	if !step("version=1\nmode=deploy\n", withState) {
		t.Fatal("первый приход S не записан")
	}
	step("version=1\nmode=observe\n", withheld)
	if !step("version=1\nmode=deploy\n", withState) {
		t.Fatal("S после «не отправлено» не записан заново — платформа запишет, хост нет")
	}

	raw, err := os.ReadFile(host.journal)
	if err != nil {
		t.Fatal(err)
	}
	stateHash := agent.CommandHashes([]byte(withState)).State
	receives := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e agent.JournalEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.Type == "receive" &&
			e.Kind == agent.JournalKindDesiredState && e.Hash == stateHash {
			receives++
		}
	}
	if receives != 2 {
		t.Fatalf("строк прихода S %d, ожидалось 2 — как у платформы:\n%s", receives, raw)
	}
}
