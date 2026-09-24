package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/internal/agent"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Агент с корнями подписи состояния в цикле такта (ADR-0093, решения 2 и 4).
//
// Отказ проверки — не повод ни падать, ни снимать стеки: состояние, которое не
// принято, не заменяет прежнее, такт при этом доставлен (отметка о жизни,
// курсор журнала), а итог проверки уходит следующим тактом. Цикл cmdRun
// бесконечен и тянет docker, поэтому здесь он собран из тех же функций, что
// зовёт он сам: tick, exchange и adoptState.

// signingKey — ключ из seed: литералов ключей в репозитории нет, гейт секретов
// читает историю.
func signingKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("deploy-agent/main-signing-test/" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signingPub(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

type signingWorld struct {
	root, work, foreign ed25519.PrivateKey
	id                  agent.Identity
}

func newSigningWorld(t *testing.T) signingWorld {
	t.Helper()
	return signingWorld{
		root:    signingKey("root"),
		work:    signingKey("work"),
		foreign: signingKey("foreign"),
		id:      testIdentity(t),
	}
}

func (w signingWorld) roots() string { return signingPub(w.root) }

// Часы клиента в пакете main не подменить — сертификаты выпускаются вокруг
// настоящего «сейчас».
func (w signingWorld) cert(t *testing.T, notBefore, notAfter time.Time) signenv.Envelope {
	t.Helper()
	env, err := hoststate.IssueCertificate(w.root, 8, w.work.Public().(ed25519.PublicKey), notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (w signingWorld) validCert(t *testing.T) signenv.Envelope {
	now := time.Now()
	return w.cert(t, now.Add(-time.Hour), now.Add(24*time.Hour))
}

// signingShopState — одно приложение из каталога. Проверка стабильности в один
// заход: применение с поддельным docker не ждёт пятнадцать секунд.
const signingShopState = `{"apps":[{"slug":"shop","sourceType":"template",` +
	`"compose":"services:\n  app:\n    image: nginx\n","env":{"MODE":"prod"},` +
	`"desired":"present","releaseId":"r1","applySpec":{"stableChecks":1}}],` +
	`"registries":[],"denyIps":[]}`

// bundle — поле signedState ответа: состояние подписано key под сертификатом cert.
func (w signingWorld) bundle(t *testing.T, key ed25519.PrivateKey, seq int64, cert signenv.Envelope) string {
	t.Helper()
	env, err := hoststate.SignState(key, hoststate.HostState{
		HostID:           "11111111-2222-4333-8444-555555555555",
		AgentFingerprint: w.id.Fingerprint(),
		Seq:              seq,
		IssuedAt:         time.Now(),
		State:            json.RawMessage(signingShopState),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"content": hoststate.ContentV0,
		"bundle":  map[string]any{"envelope": env, "certificate": cert},
		"secrets": map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// signedTick — ответ такта с пакетом. hostId метит ответ: по нему видно, какой
// из них лёг в отметку о жизни.
func signedTick(marker, signed string) string {
	return `{"hostId":"` + marker + `","signedState":` + signed + `}`
}

// tickPlatform отвечает на такты по очереди (последний ответ повторяется) и
// запоминает их тела. Прочие ручки — отчёты о релизах — получают `{}`.
type tickPlatform struct {
	mu        sync.Mutex
	responses []string
	bodies    []map[string]json.RawMessage
}

func newTickPlatform(t *testing.T, responses ...string) (*tickPlatform, *agent.Client) {
	t.Helper()
	p := &tickPlatform{responses: responses}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/api/deploy/agent/tick" {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		var body map[string]json.RawMessage
		_ = json.Unmarshal(raw, &body)
		p.mu.Lock()
		resp := p.responses[min(len(p.bodies), len(p.responses)-1)]
		p.bodies = append(p.bodies, body)
		p.mu.Unlock()
		_, _ = io.WriteString(w, resp)
	}))
	t.Cleanup(srv.Close)
	return p, agent.NewClient(srv.URL, "test")
}

func (p *tickPlatform) signing(t *testing.T, i int) *agent.SigningReport {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= len(p.bodies) {
		t.Fatalf("тактов ушло %d, нужен №%d", len(p.bodies), i+1)
	}
	raw, ok := p.bodies[i]["signing"]
	if !ok {
		return nil
	}
	var s agent.SigningReport
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("signing такта №%d: %v", i+1, err)
	}
	return &s
}

// installSigningDocker кладёт в PATH поддельные docker и ss. Каждый вызов
// docker пишется в журнал: снятие стека видно по `down`.
//
// Список контейнеров пуст, а не выдуман: уборка осматривает контейнеры до
// `down`, и неразборчивый ответ на этом шаге остановил бы её раньше снятия —
// тест тогда не увидел бы снятого стека и при поломке.
func installSigningDocker(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "docker.log")
	docker := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> '" + log + "'\n" +
		`case "$1" in` + "\n" +
		"  ps) exit 0;;\n" +
		"  inspect) printf '[]\\n'; exit 0;;\n" +
		"esac\n" +
		`case " $* " in` + "\n" +
		`  *" config "*"--services "*) printf 'app\n';;` + "\n" +
		`  *" ps --all "*) printf 'app\trunning\t\t0\n';;` + "\n" +
		"esac\n" +
		"exit 0\n"
	for name, script := range map[string]string{"docker": docker, "ss": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func dockerDowns(t *testing.T, log string) []string {
	t.Helper()
	raw, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var downs []string
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.Contains(" "+line+" ", " down ") {
			downs = append(downs, line)
		}
	}
	return downs
}

// seedStacks — стек, оставленный прежним запуском агента: каталог с описанием
// и отметка в applied.json.
func seedStacks(t *testing.T, paths agent.Paths) {
	t.Helper()
	dir := filepath.Join(paths.WorkDir, "apps", "shop")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  app:\n    image: nginx\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_SLUG='shop'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applied := `{"apps":{"shop":{"release_id":"r0","config_hash":"x","status":"healthy"}}}`
	if err := os.WriteFile(filepath.Join(paths.StateDir, "applied.json"), []byte(applied), 0o600); err != nil {
		t.Fatal(err)
	}
}

// stackSnapshot — всё, по чему видно снятие стека: файлы WorkDir/apps и
// applied.json.
func stackSnapshot(t *testing.T, paths agent.Paths) map[string]string {
	t.Helper()
	out := map[string]string{}
	root := filepath.Join(paths.WorkDir, "apps")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			out["apps/"+rel+"/"] = ""
			return nil
		}
		raw, err := os.ReadFile(path)
		out["apps/"+rel] = string(raw)
		return err
	})
	if err != nil {
		t.Fatalf("каталог стеков: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(paths.StateDir, "applied.json"))
	if err != nil {
		t.Fatalf("applied.json: %v", err)
	}
	out["applied.json"] = string(raw)
	return out
}

func sameSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// writeAccessLine — одна строка журнала прокси к следующему сбору окна.
func writeAccessLine(t *testing.T, paths agent.Paths) {
	t.Helper()
	logs := filepath.Join(paths.WorkDir, "proxy", "logs")
	if err := os.MkdirAll(logs, 0o750); err != nil {
		t.Fatal(err)
	}
	line := `{"logger":"http.log.access.log0","status":200,"size":1,"request":{"host":"shop.example.com","uri":"/","remote_ip":"1.1.1.1"}}` + "\n"
	f, err := os.OpenFile(filepath.Join(logs, "access.json"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatal(err)
	}
}

// signingLoop — тело цикла cmdRun между тактом и разбором ошибки.
type signingLoop struct {
	client    *agent.Client
	id        agent.Identity
	paths     agent.Paths
	gate      *agent.ReportGate
	queue     *agent.ReportQueue
	proxy     atomic.Pointer[string]
	heartbeat atomic.Pointer[agent.HeartbeatResponse]
	state     agent.DesiredState
	haveState bool
	legacy    bool
}

func newSigningLoop(client *agent.Client, id agent.Identity, paths agent.Paths) *signingLoop {
	// Как в cmdRun: без каталога защёлок агент с корнями не примет ничего.
	client.UseStateDir(paths.StateDir)
	return &signingLoop{
		client: client,
		id:     id,
		paths:  paths,
		gate:   agent.NewReportGate(),
		queue:  agent.LoadReportQueue(paths),
	}
}

func (l *signingLoop) cycle(t *testing.T) error {
	t.Helper()
	report, delivery := tick(t.Context(), l.client, l.id, l.paths, agent.ProxyOptions{}, l.state,
		l.haveState, false, &l.proxy, &l.heartbeat, l.gate, l.queue, l.legacy)
	resp, err := exchange(t.Context(), l.client, l.id, report, delivery, l.gate, l.queue, &l.legacy)
	// Отметка о жизни — та же строка, что в cmdRun.
	if err == nil && !l.legacy {
		l.heartbeat.Store(&resp.HeartbeatResponse)
	}
	l.state, l.haveState = adoptState(l.state, l.haveState, resp, err)
	return err
}

// Отказ проверки любого рода: агент жив, стеки на месте, такт доставлен, а
// итог проверки уходит следующим тактом.
func TestTickSigningRefusalKeepsAgentAlive(t *testing.T) {
	w := newSigningWorld(t)
	now := time.Now()
	accepted := signedTick("accepted", w.bundle(t, w.work, 5, w.validCert(t)))

	cases := []struct {
		name string
		// roots — значение сборки; битое — отказ с первого же ответа.
		roots string
		// before — ответы, принятые до отказа. Пусто — агент стартовал пустым.
		before  []string
		refusal string
		status  string
		reason  hoststate.Reason
		seq     int64
		last    int64
	}{
		{
			name:    "foreign_key",
			roots:   w.roots(),
			before:  []string{accepted},
			refusal: signedTick("refusal", w.bundle(t, w.foreign, 6, w.validCert(t))),
			// Подпись не сходится раньше разбора нагрузки: номера в докладе нет.
			status: "refused", reason: hoststate.ReasonSignatureInvalid, seq: 0, last: 5,
		},
		{
			name:    "seq_rollback",
			roots:   w.roots(),
			before:  []string{accepted},
			refusal: signedTick("refusal", w.bundle(t, w.work, 3, w.validCert(t))),
			status:  "refused", reason: hoststate.ReasonSeqRollback, seq: 3, last: 5,
		},
		{
			name:   "expired_cert",
			roots:  w.roots(),
			before: []string{accepted},
			refusal: signedTick("refusal", w.bundle(t, w.work, 6,
				w.cert(t, now.Add(-48*time.Hour), now.Add(-time.Hour)))),
			status: "refused", reason: hoststate.ReasonCertExpired, seq: 0, last: 5,
		},
		{
			// Честный пакет, но корни сборки нечитаемы: не применяется ничего.
			name:    "invalid_roots",
			roots:   w.roots() + ",%%%",
			refusal: signedTick("refusal", w.bundle(t, w.work, 5, w.validCert(t))),
			status:  "refused", reason: hoststate.ReasonTrustRootsInvalid, seq: 0, last: 0,
		},
		{
			// Пустой список без пакета — не «снять всё».
			name:    "no_bundle",
			roots:   w.roots(),
			before:  []string{accepted},
			refusal: `{"hostId":"refusal","apps":[]}`,
			status:  "held", reason: hoststate.ReasonNoBundle, seq: 0, last: 5,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(agent.SetTrustedStateRootsForTest(tc.roots))
			log := installSigningDocker(t)
			paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
			seedStacks(t, paths)

			responses := append(append([]string{}, tc.before...), tc.refusal, `{"hostId":"after"}`)
			platform, client := newTickPlatform(t, responses...)
			loop := newSigningLoop(client, w.id, paths)

			for i := range tc.before {
				if err := loop.cycle(t); err != nil {
					t.Fatalf("такт №%d: %v", i+1, err)
				}
			}
			if len(tc.before) > 0 && (!loop.haveState || len(loop.state.Apps) != 1) {
				t.Fatalf("подписанное состояние не принято: %+v", loop.state)
			}

			// Такт, ответом на который приходит отказ. Строка журнала — к
			// нему: отказ проверки не должен сделать такт недоставленным.
			writeAccessLine(t, paths)
			if err := loop.cycle(t); err != nil {
				t.Fatalf("отказ проверки стал ошибкой такта: %v", err)
			}
			if hb := loop.heartbeat.Load(); hb == nil || hb.HostID != "refusal" {
				t.Fatalf("отметка о жизни не из ответа с отказом: %+v", hb)
			}
			if again, err := agent.CollectTrafficWindow(paths); err != nil || len(again.Items) != 0 {
				t.Fatalf("курсор журнала не сдвинут после такта с отказом: %+v, %v", again.Items, err)
			}
			if len(tc.before) > 0 {
				if !loop.haveState || len(loop.state.Apps) != 1 || loop.state.Apps[0].Slug != "shop" {
					t.Errorf("после отказа состояние не прежнее: %+v", loop.state)
				}
			} else if loop.haveState {
				t.Errorf("непринятое состояние стало первым: %+v", loop.state)
			}
			stacks := stackSnapshot(t, paths)
			downs := len(dockerDowns(t, log))

			if err := loop.cycle(t); err != nil {
				t.Fatalf("такт после отказа: %v", err)
			}
			s := platform.signing(t, len(tc.before)+1)
			if s == nil {
				t.Fatal("такт после отказа ушёл без signing")
			}
			if s.Status != tc.status || s.Reason != string(tc.reason) || s.Seq != tc.seq || s.LastAcceptedSeq != tc.last {
				t.Fatalf("signing %+v, ожидалось %s/%s seq %d, принятый %d", *s, tc.status, tc.reason, tc.seq, tc.last)
			}
			if got := stackSnapshot(t, paths); !sameSnapshot(got, stacks) {
				t.Fatalf("стеки изменились после отказа:\nбыло  %v\nстало %v", stacks, got)
			}
			if got := dockerDowns(t, log); len(got) != downs {
				t.Fatalf("после отказа снимались стеки: %v", got[downs:])
			}
			if _, err := os.Stat(filepath.Join(paths.WorkDir, "apps", "shop", "docker-compose.yml")); err != nil {
				t.Fatalf("стек shop снят: %v", err)
			}
		})
	}
}

// Самый опасный случай — сразу после рестарта: агент с корнями ещё не принял
// ни одного состояния, а платформа отвечает пустым списком без пакета. Прежде
// любой ответ без ошибки становился состоянием, и первый же такт снял бы все
// стеки хоста.
func TestTickWithoutBundleKeepsStacks(t *testing.T) {
	w := newSigningWorld(t)
	t.Cleanup(agent.SetTrustedStateRootsForTest(w.roots()))
	log := installSigningDocker(t)
	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	seedStacks(t, paths)
	before := stackSnapshot(t, paths)

	platform, client := newTickPlatform(t, `{"hostId":"h","apps":[],"nextPollSeconds":5}`)
	loop := newSigningLoop(client, w.id, paths)

	for i := 0; i < 2; i++ {
		if err := loop.cycle(t); err != nil {
			t.Fatalf("такт №%d: %v", i+1, err)
		}
	}
	if loop.haveState {
		t.Errorf("ответ без пакета стал состоянием: %+v", loop.state)
	}
	if got := stackSnapshot(t, paths); !sameSnapshot(got, before) {
		t.Fatalf("стеки изменились:\nбыло  %v\nстало %v", before, got)
	}
	if downs := dockerDowns(t, log); len(downs) != 0 {
		t.Fatalf("снимались стеки: %v", downs)
	}
	if s := platform.signing(t, 1); s == nil || s.Status != "held" || s.Reason != string(hoststate.ReasonNoBundle) {
		t.Fatalf("второй такт докладывает %+v, ожидалось held/no_bundle", s)
	}
}

// captureOutput — stdout и stderr вызова.
func captureOutput(t *testing.T, fn func()) (string, string) {
	t.Helper()
	read := func(r *os.File, into *string, done chan<- struct{}) {
		raw, _ := io.ReadAll(r)
		*into = string(raw)
		close(done)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr string
	outDone, errDone := make(chan struct{}), make(chan struct{})
	go read(outR, &stdout, outDone)
	go read(errR, &stderr, errDone)

	prevOut, prevErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() {
		os.Stdout, os.Stderr = prevOut, prevErr
	}()
	fn()
	os.Stdout, os.Stderr = prevOut, prevErr
	_ = outW.Close()
	_ = errW.Close()
	<-outDone
	<-errDone
	return stdout, stderr
}

// При старте агент говорит вслух, проверяет ли он подпись состояния. Битые
// корни — не причина выходить: агент продолжает такты и докладывает отказ.
func TestRunAnnouncesStateRoots(t *testing.T) {
	w := newSigningWorld(t)
	cases := []struct {
		name, roots, stdout, stderr string
	}{
		{"корни есть", w.roots() + "," + signingPub(w.foreign), "подпись состояния проверяется: корней 2", ""},
		{"корней нет", "", "", "подпись состояния НЕ проверяется"},
		{"корни битые", w.roots() + ",%%%", "", "нечитаемы: корень 2: не base64. Никакое желаемое состояние применяться не будет"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(agent.SetTrustedStateRootsForTest(tc.roots))
			var runErr error
			// Пустой адрес: cmdRun выходит на проверке адреса, сразу после
			// объявлений о доверии, не доходя до цикла.
			stdout, stderr := captureOutput(t, func() { runErr = cmdRun([]string{"--url", ""}) })
			if runErr == nil {
				t.Fatal("cmdRun с пустым адресом не вернул ошибку — тест дошёл бы до цикла")
			}
			if tc.stdout != "" && !strings.Contains(stdout, tc.stdout) {
				t.Fatalf("stdout %q без %q", stdout, tc.stdout)
			}
			if tc.stderr != "" && !strings.Contains(stderr, tc.stderr) {
				t.Fatalf("stderr %q без %q", stderr, tc.stderr)
			}
			if tc.stdout == "" && strings.Contains(stdout, "подпись состояния проверяется") {
				t.Fatalf("агент без исправных корней объявил проверку: %q", stdout)
			}
		})
	}
}

// Переходный режим (ADR-0093, решение 5; план Г, раздел 8): правило приёма
// зашито в сборку. Без корней агент 2.2.0 обязан вести себя как прежний, с
// корнями — не принять неподписанное ни одним путём, которым состояние
// попадает в цикл: такт, запасной /state и первый такт после рестарта.

// unsignedShopTick — прежний ответ такта: состояние плоскими полями.
var unsignedShopTick = `{"hostId":"unsigned",` + signingShopState[1:]

// newLegacyPlatform — платформа, откатанная до шести ручек: такта не знает
// (404), состояние отдаёт /state по очереди ответов.
func newLegacyPlatform(t *testing.T, states ...string) *agent.Client {
	t.Helper()
	var mu sync.Mutex
	served := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/api/deploy/agent/tick":
			http.NotFound(w, r)
			return
		case "/api/deploy/agent/state":
			mu.Lock()
			resp := states[min(served, len(states)-1)]
			served++
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)
	return agent.NewClient(srv.URL, "test")
}

func (l *signingLoop) mustCycle(t *testing.T, step string) {
	t.Helper()
	if err := l.cycle(t); err != nil {
		t.Fatalf("%s: %v", step, err)
	}
}

func (l *signingLoop) assertShop(t *testing.T, step string) {
	t.Helper()
	if !l.haveState || len(l.state.Apps) != 1 || l.state.Apps[0].Slug != "shop" {
		t.Fatalf("%s: состояние не принято: haveState=%v %+v", step, l.haveState, l.state)
	}
}

func (l *signingLoop) assertNoState(t *testing.T, step string) {
	t.Helper()
	if l.haveState {
		t.Fatalf("%s: неподписанное стало состоянием агента с корнями: %+v", step, l.state)
	}
}

func TestTransitionNoRootsAppliesUnsigned(t *testing.T) {
	w := newSigningWorld(t)
	t.Cleanup(agent.SetTrustedStateRootsForTest(""))

	t.Run("такт", func(t *testing.T) {
		installSigningDocker(t)
		paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
		platform, client := newTickPlatform(t, unsignedShopTick)
		loop := newSigningLoop(client, w.id, paths)
		loop.mustCycle(t, "такт")
		loop.assertShop(t, "неподписанное без корней")
		// Доклада о подписи агент без корней не шлёт: платформе нечего
		// показывать на карточке, пока проверки нет.
		loop.mustCycle(t, "второй такт")
		if s := platform.signing(t, 1); s != nil {
			t.Fatalf("агент без корней докладывает подпись: %+v", *s)
		}
	})

	t.Run("/state", func(t *testing.T) {
		installSigningDocker(t)
		paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
		loop := newSigningLoop(newLegacyPlatform(t, signingShopState), w.id, paths)
		loop.mustCycle(t, "такт через /state")
		if !loop.legacy {
			t.Fatal("404 на такт не перевёл агента на прежние ручки")
		}
		loop.assertShop(t, "неподписанное с /state без корней")
	})
}

func TestTransitionRootsAcceptOnlySigned(t *testing.T) {
	w := newSigningWorld(t)
	t.Cleanup(agent.SetTrustedStateRootsForTest(w.roots()))
	signed := func(seq int64) string { return w.bundle(t, w.work, seq, w.validCert(t)) }

	t.Run("такт", func(t *testing.T) {
		installSigningDocker(t)
		paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
		_, client := newTickPlatform(t, unsignedShopTick, signedTick("signed", signed(5)))
		loop := newSigningLoop(client, w.id, paths)
		loop.mustCycle(t, "неподписанный такт")
		loop.assertNoState(t, "такт")
		// Контроль: тот же цикл подписанное принимает — отказ выше не от
		// сломанной сборки теста.
		loop.mustCycle(t, "подписанный такт")
		loop.assertShop(t, "подписанное в такте")
	})

	t.Run("/state", func(t *testing.T) {
		installSigningDocker(t)
		paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
		client := newLegacyPlatform(t, signingShopState, `{"signedState":`+signed(5)+`}`)
		loop := newSigningLoop(client, w.id, paths)
		loop.mustCycle(t, "неподписанный /state")
		if !loop.legacy {
			t.Fatal("404 на такт не перевёл агента на прежние ручки")
		}
		loop.assertNoState(t, "/state")
		loop.mustCycle(t, "подписанный /state")
		loop.assertShop(t, "подписанное с /state")
	})

	t.Run("рестарт", func(t *testing.T) {
		installSigningDocker(t)
		paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
		// Повтор — тот же пакет побайтно. Пакет того же номера с другой
		// нагрузкой (другое issuedAt) — не повтор, а подмена, и отказ ему
		// верный: пересобирать его здесь значило бы проверять не то.
		five := signed(5)
		_, before := newTickPlatform(t, signedTick("signed", five))
		first := newSigningLoop(before, w.id, paths)
		first.mustCycle(t, "до рестарта")
		first.assertShop(t, "до рестарта")

		// Новый процесс: пустая память, тот же каталог состояния. Защёлка
		// на диске — единственное, что помнит принятый номер.
		_, after := newTickPlatform(t,
			unsignedShopTick,
			signedTick("rollback", signed(4)),
			signedTick("redelivery", five))
		loop := newSigningLoop(after, w.id, paths)
		loop.mustCycle(t, "неподписанный после рестарта")
		loop.assertNoState(t, "неподписанное после рестарта")
		loop.mustCycle(t, "меньший номер после рестарта")
		loop.assertNoState(t, "откат номера после рестарта")
		loop.mustCycle(t, "повтор того же номера")
		loop.assertShop(t, "повтор принятого пакета после рестарта")
	})
}
