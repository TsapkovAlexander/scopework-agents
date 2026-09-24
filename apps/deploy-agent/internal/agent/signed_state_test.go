package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Приём подписанного состояния в клиенте (ADR-0093, решения 4–7).
//
// Проверка стоит в Client.Tick и Client.DesiredState, а не в main.go: так у
// такта и у запасного /state одно правило, и ни один путь не применит
// неподписанное у агента с корнями. Отказ — не ошибка доставки: ошибка
// сделала бы такт недоставленным, а успех с пустым состоянием снёс бы стеки.

type stateWorld struct {
	root, root2, work, foreign ed25519.PrivateKey
	id                         Identity
	now                        time.Time
	hostID                     string
}

func newStateWorld(t *testing.T) stateWorld {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return stateWorld{
		root:    testSeedKey("root-a"),
		root2:   testSeedKey("root-b"),
		work:    testSeedKey("work"),
		foreign: testSeedKey("foreign"),
		id:      id,
		now:     mustParseTime(t, "2026-09-17T12:00:00Z"),
		hostID:  "11111111-2222-4333-8444-555555555555",
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (w stateWorld) rootsRaw() string { return testPubB64(w.root) + "," + testPubB64(w.root2) }

func useStateRoots(t *testing.T, raw string) {
	t.Helper()
	t.Cleanup(SetTrustedStateRootsForTest(raw))
}

func (w stateWorld) certBy(t *testing.T, root ed25519.PrivateKey, serial int64, notAfter string) signenv.Envelope {
	t.Helper()
	env, err := hoststate.IssueCertificate(root, serial, w.work.Public().(ed25519.PublicKey),
		mustParseTime(t, "2026-09-01T00:00:00Z"), mustParseTime(t, notAfter))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (w stateWorld) cert(t *testing.T) signenv.Envelope {
	return w.certBy(t, w.root, 8, "2026-10-01T00:00:00Z")
}

// shopState — желаемое состояние без значений секретов: одно приложение из
// каталога, пароль базы едет рядом с пакетом.
const shopState = `{"apps":[{"slug":"shop","domain":"shop.example.com","sourceType":"template",` +
	`"compose":"services:\n  app:\n    image: nginx\n","env":{"MODE":"prod"},"desired":"present","releaseId":"r1"}],` +
	`"registries":[],"denyIps":[]}`

const shopSecretRef = "app/shop/env/DB_PASSWORD"

func shopSecrets() map[string]string {
	return map[string]string{shopSecretRef: "test-only-db-password"}
}

func (w stateWorld) signStateAs(t *testing.T, key ed25519.PrivateKey, seq int64, state string, refs []string, grants ...signenv.Envelope) signenv.Envelope {
	t.Helper()
	raw := make([]json.RawMessage, 0, len(grants))
	for _, g := range grants {
		b, err := json.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b)
	}
	env, err := hoststate.SignState(key, hoststate.HostState{
		HostID:           w.hostID,
		AgentFingerprint: w.id.Fingerprint(),
		Seq:              seq,
		IssuedAt:         mustParseTime(t, "2026-09-17T11:59:00Z"),
		State:            json.RawMessage(state),
		Secrets:          refs,
		Grants:           raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// signedStateField — поле signedState ответа платформы.
func signedStateField(t *testing.T, content string, env, cert signenv.Envelope, secrets map[string]string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"content": content,
		"bundle":  map[string]any{"envelope": env, "certificate": cert},
		"secrets": secrets,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// shopBundle — честный пакет с номером seq.
func (w stateWorld) shopBundle(t *testing.T, seq int64) string {
	t.Helper()
	return signedStateField(t, hoststate.ContentV0,
		w.signStateAs(t, w.work, seq, shopState, []string{shopSecretRef}), w.cert(t), shopSecrets())
}

// signedResponse — ответ такта агенту с корнями. Плоские поля рядом с пакетом
// нарочно: агент с корнями обязан их не видеть.
func signedResponse(signed string) string {
	return `{"hostId":"h","nextPollSeconds":7,"apps":[{"slug":"evil","compose":"x"}],"denyIps":["0.0.0.0/0"],` +
		`"signedState":` + signed + `}`
}

const flatShopResponse = `{"hostId":"h","nextPollSeconds":7,"apps":[{"slug":"shop","compose":"services: {}\n"}],` +
	`"registries":[{"registry":"ghcr.io","username":"u","token":"t"}],"denyIps":["192.0.2.1"],` +
	`"platformSubdomainBase":"example.com","objectStorage":{"bucket":"b"}}`

// fakePlatform отвечает по очереди заданными телами (последнее повторяется) и
// запоминает тела запросов.
type fakePlatform struct {
	mu        sync.Mutex
	responses []string
	requests  []recordedRequest
}

type recordedRequest struct {
	path string
	body map[string]json.RawMessage
	raw  string
}

func newFakePlatform(t *testing.T, responses ...string) (*fakePlatform, string) {
	t.Helper()
	p := &fakePlatform{responses: responses}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]json.RawMessage
		_ = json.Unmarshal(raw, &body)
		p.mu.Lock()
		p.requests = append(p.requests, recordedRequest{path: r.URL.Path, body: body, raw: string(raw)})
		resp := p.responses[0]
		if len(p.responses) > 1 {
			p.responses = p.responses[1:]
		}
		p.mu.Unlock()
		rw.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(rw, resp)
	}))
	t.Cleanup(srv.Close)
	return p, srv.URL
}

func (p *fakePlatform) request(t *testing.T, i int) recordedRequest {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if i >= len(p.requests) {
		t.Fatalf("запросов %d, нужен №%d", len(p.requests), i+1)
	}
	return p.requests[i]
}

func (p *fakePlatform) push(responses ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.responses = responses
}

func (w stateWorld) client(url, stateDir string) *Client {
	c := NewClient(url, "test")
	if stateDir != "" {
		c.UseStateDir(stateDir)
	}
	c.now = func() time.Time { return w.now }
	return c
}

func (w stateWorld) tick(t *testing.T, c *Client) TickResponse {
	t.Helper()
	resp, err := c.Tick(context.Background(), w.id, TickRequest{AgentVersion: "test"})
	if err != nil {
		t.Fatalf("отказ проверки стал ошибкой такта: %v", err)
	}
	return resp
}

// signingOf — доклад signing из запроса; nil — поля нет.
func signingOf(t *testing.T, r recordedRequest) *SigningReport {
	t.Helper()
	raw, ok := r.body["signing"]
	if !ok {
		return nil
	}
	var s SigningReport
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("signing не разбирается: %v (%s)", err, raw)
	}
	return &s
}

// expectNotApplied — состояние не принято и пусто целиком: плоские поля
// ответа агенту с корнями не достаются ни при каком исходе.
func expectNotApplied(t *testing.T, st DesiredState) {
	t.Helper()
	if st.Accepted {
		t.Fatal("состояние принято")
	}
	if st.Apps != nil || st.Registries != nil || st.DenyIPs != nil || st.PlatformSubdomainBase != "" || st.ObjectStorage != nil {
		t.Fatalf("непринятое состояние не обнулено: %+v", st)
	}
}

// refusedOnNextTick — итог проверки уезжает следующим тактом.
func (w stateWorld) refusedOnNextTick(t *testing.T, c *Client, p *fakePlatform, status string, reason hoststate.Reason) *SigningReport {
	t.Helper()
	w.tick(t, c)
	p.mu.Lock()
	last := p.requests[len(p.requests)-1]
	p.mu.Unlock()
	s := signingOf(t, last)
	if s == nil {
		t.Fatal("в следующем такте нет signing")
	}
	if s.Status != status || s.Reason != string(reason) {
		t.Fatalf("signing %s/%s, ожидалось %s/%s", s.Status, s.Reason, status, reason)
	}
	return s
}

func latchExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, stateLatchFile))
	return err == nil
}

func TestClientTickNoRootsAppliesUnsigned(t *testing.T) {
	useStateRoots(t, "")
	w := newStateWorld(t)
	p, url := newFakePlatform(t, flatShopResponse)
	dir := t.TempDir()
	c := w.client(url, dir)

	resp := w.tick(t, c)
	if !resp.DesiredState.Accepted {
		t.Fatal("агент без корней не принял неподписанное состояние")
	}
	if len(resp.Apps) != 1 || resp.Apps[0].Slug != "shop" || len(resp.DenyIPs) != 1 {
		t.Fatalf("состояние разобрано не так: %+v", resp.DesiredState)
	}

	w.tick(t, c)
	for i := range 2 {
		if s := signingOf(t, p.request(t, i)); s != nil {
			t.Fatalf("агент без корней докладывает signing: %+v", s)
		}
	}
	if latchExists(dir) {
		t.Fatal("агент без корней завёл файл защёлок")
	}
}

// Пакет в ответе агенту без корней игнорируется: проверять его нечем, а
// «принять подписанное без проверки» — хуже, чем принять плоское.
func TestClientTickNoRootsIgnoresSignedState(t *testing.T) {
	useStateRoots(t, "")
	w := newStateWorld(t)
	_, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))

	resp := w.tick(t, w.client(url, t.TempDir()))
	if !resp.DesiredState.Accepted || len(resp.Apps) != 1 || resp.Apps[0].Slug != "evil" {
		t.Fatalf("агент без корней применил не плоские поля: %+v", resp.DesiredState)
	}
}

// Ответ без apps — не «снять всё»: старая или сломанная платформа, и
// заменять им состояние нельзя.
func TestClientTickNoRootsWithoutAppsNotAccepted(t *testing.T) {
	useStateRoots(t, "")
	w := newStateWorld(t)
	_, url := newFakePlatform(t, `{"hostId":"h","nextPollSeconds":7}`, `{"apps":[]}`)
	c := w.client(url, t.TempDir())

	if resp := w.tick(t, c); resp.DesiredState.Accepted {
		t.Fatal("ответ без apps принят как состояние")
	}
	if resp := w.tick(t, c); !resp.DesiredState.Accepted || resp.Apps == nil {
		t.Fatal("явный пустой список не принят")
	}
}

func TestClientTickRootsRefuseUnsignedResponse(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	cases := []struct {
		name     string
		response string
		reason   hoststate.Reason
	}{
		{"плоский ответ", flatShopResponse, hoststate.ReasonNoBundle},
		{"пустой список без пакета", `{"apps":[]}`, hoststate.ReasonNoBundle},
		{"подписант недоступен", `{"apps":[],"stateWithheld":"signer_unavailable"}`, hoststate.ReasonSignerUnavailable},
		{"подписант отказал", `{"stateWithheld":"signer_refused"}`, hoststate.ReasonSignerRefused},
		{"подписант не настроен", `{"stateWithheld":"signer_not_configured"}`, hoststate.ReasonSignerNotConfigured},
		{"протокол несовместим", `{"stateWithheld":"protocol_incompatible"}`, hoststate.ReasonProtocolIncompatible},
		{"незнакомая причина", `{"stateWithheld":"DROP TABLE"}`, hoststate.ReasonNoBundle},
		{"пакет null", `{"apps":[],"signedState":null}`, hoststate.ReasonNoBundle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, url := newFakePlatform(t, tc.response)
			dir := t.TempDir()
			c := w.client(url, dir)
			resp := w.tick(t, c)
			expectNotApplied(t, resp.DesiredState)
			s := w.refusedOnNextTick(t, c, p, "held", tc.reason)
			if s.Seq != 0 || s.LastAcceptedSeq != 0 {
				t.Fatalf("удержание без пакета докладывает номера: %+v", s)
			}
			if latchExists(dir) {
				t.Fatal("удержание оставило файл защёлок")
			}
		})
	}
}

func TestClientTickRootsAcceptSignedBundle(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	p, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
	dir := t.TempDir()
	c := w.client(url, dir)

	resp := w.tick(t, c)
	st := resp.DesiredState
	if !st.Accepted {
		t.Fatal("честный пакет не принят")
	}
	if len(st.Apps) != 1 || st.Apps[0].Slug != "shop" {
		t.Fatalf("применены не подписанные приложения: %+v", st.Apps)
	}
	if st.Apps[0].Env["DB_PASSWORD"] != "test-only-db-password" || st.Apps[0].Env["MODE"] != "prod" {
		t.Fatalf("секрет не подставлен в env: %v", st.Apps[0].Env)
	}
	if len(st.DenyIPs) != 0 {
		t.Fatalf("плоские denyIps ответа попали в состояние: %v", st.DenyIPs)
	}
	if resp.NextPollSeconds != 7 || resp.HostID != "h" {
		t.Fatal("остальные поля такта потеряны")
	}

	latch, err := loadStateLatch(dir, w.id.Fingerprint())
	if err != nil || latch.Seq != 5 || latch.MaxCertSerial != 8 {
		t.Fatalf("защёлка после приёма %+v (%v)", latch, err)
	}

	s := w.refusedOnNextTick(t, c, p, "accepted", "")
	if s.Seq != 5 || s.LastAcceptedSeq != 5 {
		t.Fatalf("доклад принятого: %+v", s)
	}
	if strings.Contains(string(p.request(t, 1).body["signing"]), "reason") {
		t.Fatalf("у принятого есть reason: %s", p.request(t, 1).body["signing"])
	}
}

func TestClientTickInvalidRootsRefuseAll(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw()+",not-a-key")
	p, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
	dir := t.TempDir()
	c := w.client(url, dir)

	resp := w.tick(t, c)
	expectNotApplied(t, resp.DesiredState)
	if latchExists(dir) {
		t.Fatal("при битых корнях записана защёлка")
	}
	if got := string(p.request(t, 0).body["protocol"]); !strings.Contains(got, `"envelopes":[]`) {
		t.Fatalf("с битыми корнями агент объявляет обёртки: %s", got)
	}
	w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonTrustRootsInvalid)

	// Плоский ответ — тоже не применяется.
	p.push(flatShopResponse)
	expectNotApplied(t, w.tick(t, c).DesiredState)
}

func TestClientTickLatchUnreadableRefuses(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())

	t.Run("испорченный файл", func(t *testing.T) {
		p, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
		dir := t.TempDir()
		path := filepath.Join(dir, stateLatchFile)
		if err := os.WriteFile(path, []byte("{испорчен"), 0o600); err != nil {
			t.Fatal(err)
		}
		c := w.client(url, dir)
		expectNotApplied(t, w.tick(t, c).DesiredState)
		w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonLatchUnreadable)
		if raw, _ := os.ReadFile(path); string(raw) != "{испорчен" {
			t.Fatalf("испорченный файл перезаписан: %q", raw)
		}
	})

	// Каталог состояния не задан, а корни есть: принимать без защёлок —
	// значит принимать повтор старого пакета.
	t.Run("каталог не задан", func(t *testing.T) {
		p, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
		c := w.client(url, "")
		expectNotApplied(t, w.tick(t, c).DesiredState)
		w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonLatchUnreadable)
	})
}

func TestClientTickLatchWriteFailedRefuses(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	p, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
	dir := t.TempDir()
	c := w.client(url, dir)

	prev := latchSync
	latchSync = func(*os.File) error { return os.ErrPermission }
	t.Cleanup(func() { latchSync = prev })

	expectNotApplied(t, w.tick(t, c).DesiredState)
	w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonLatchWriteFailed)
}

// Рестарт агента: защёлки на диске, повтор того же пакета принимается, меньший
// номер — нет (ADR-0093, решение 5).
func TestClientTickRestartRedeliverySameSeq(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	dir := t.TempDir()
	same := signedResponse(w.shopBundle(t, 5))

	_, url := newFakePlatform(t, same)
	if !w.tick(t, w.client(url, dir)).DesiredState.Accepted {
		t.Fatal("первый приём не прошёл")
	}

	// Новый процесс с тем же каталогом.
	p, url2 := newFakePlatform(t, same)
	c := w.client(url2, dir)
	if !w.tick(t, c).DesiredState.Accepted {
		t.Fatal("повтор того же пакета после рестарта отвергнут")
	}

	p.push(signedResponse(w.shopBundle(t, 4)))
	expectNotApplied(t, w.tick(t, c).DesiredState)
	p.push(same)
	s := w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonSeqRollback)
	if s.Seq != 4 || s.LastAcceptedSeq != 5 {
		t.Fatalf("доклад отката: %+v", s)
	}

	// Тот же номер с другими байтами — тоже откат.
	other := strings.Replace(shopState, `"MODE":"prod"`, `"MODE":"dev"`, 1)
	p.push(signedResponse(signedStateField(t, hoststate.ContentV0,
		w.signStateAs(t, w.work, 5, other, []string{shopSecretRef}), w.cert(t), shopSecrets())))
	expectNotApplied(t, w.tick(t, c).DesiredState)
	latch, err := loadStateLatch(dir, w.id.Fingerprint())
	if err != nil || latch.Seq != 5 {
		t.Fatalf("отказ сдвинул защёлку: %+v (%v)", latch, err)
	}
}

// Отказ — не ошибка: такт доставлен, отметка о жизни и интервал приехали.
func TestClientTickRefusalIsNotError(t *testing.T) {
	w := newStateWorld(t)
	responses := map[string]string{
		"без пакета":   flatShopResponse,
		"чужой ключ":   signedResponse(signedStateField(t, hoststate.ContentV0, w.signStateAs(t, w.foreign, 5, shopState, []string{shopSecretRef}), w.cert(t), shopSecrets())),
		"битый пакет":  signedResponse(`{"content":"host-state/0","bundle":{"envelope":1},"secrets":{}}`),
		"пакет строка": signedResponse(`"x"`),
	}
	for _, roots := range []string{w.rootsRaw(), "битые"} {
		useStateRoots(t, roots)
		for name, body := range responses {
			t.Run(name, func(t *testing.T) {
				_, url := newFakePlatform(t, body)
				resp, err := w.client(url, t.TempDir()).Tick(context.Background(), w.id, TickRequest{})
				if err != nil {
					t.Fatalf("отказ вернулся ошибкой: %v", err)
				}
				expectNotApplied(t, resp.DesiredState)
				if resp.NextPollSeconds != 7 || resp.HostID != "h" {
					t.Fatalf("поля такта потеряны при отказе: %+v", resp.HeartbeatResponse)
				}
			})
		}
	}
}

func TestClientDesiredStateLegacyRootsRefuseUnsigned(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	p, url := newFakePlatform(t, flatShopResponse)
	c := w.client(url, t.TempDir())

	st, err := c.DesiredState(context.Background(), w.id)
	if err != nil {
		t.Fatalf("отказ стал ошибкой /state: %v", err)
	}
	expectNotApplied(t, st)

	req := p.request(t, 0)
	if req.path != "/api/deploy/agent/state" {
		t.Fatalf("путь %s", req.path)
	}
	if !strings.Contains(string(req.body["protocol"]), `"envelopes":["dsse-ed25519/1"]`) {
		t.Fatalf("/state без объявления протокола: %s", req.raw)
	}

	if _, err := c.DesiredState(context.Background(), w.id); err != nil {
		t.Fatal(err)
	}
	if s := signingOf(t, p.request(t, 1)); s == nil || s.Status != "held" || s.Reason != "no_bundle" {
		t.Fatalf("/state не доложил итог прошлого запроса: %+v", s)
	}
}

func TestClientDesiredStateLegacyRootsAcceptSigned(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	_, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
	dir := t.TempDir()

	st, err := w.client(url, dir).DesiredState(context.Background(), w.id)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Accepted || len(st.Apps) != 1 || st.Apps[0].Slug != "shop" {
		t.Fatalf("подписанное на /state не принято: %+v", st)
	}
	if latch, _ := loadStateLatch(dir, w.id.Fingerprint()); latch.Seq != 5 {
		t.Fatalf("защёлка после /state: %+v", latch)
	}
}

func TestClientTickReportsSigningNextTick(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	p, url := newFakePlatform(t,
		signedResponse(w.shopBundle(t, 5)),
		signedResponse(w.shopBundle(t, 3)),
		`{"stateWithheld":"signer_unavailable"}`,
	)
	c := w.client(url, t.TempDir())

	for range 4 {
		w.tick(t, c)
	}
	if s := signingOf(t, p.request(t, 0)); s != nil {
		t.Fatalf("до первого итога signing уже есть: %+v", s)
	}
	want := []SigningReport{
		{Status: "accepted", Seq: 5, LastAcceptedSeq: 5},
		{Status: "refused", Reason: "seq_rollback", Seq: 3, LastAcceptedSeq: 5},
		// Удержание докладывает последний принятый номер: им подписант
		// восстанавливает своё хранилище.
		{Status: "held", Reason: "signer_unavailable", Seq: 0, LastAcceptedSeq: 5},
	}
	for i, exp := range want {
		got := signingOf(t, p.request(t, i+1))
		if got == nil {
			t.Fatalf("такт %d без signing", i+2)
		}
		exp.At = "2026-09-17T12:00:00Z"
		if *got != exp {
			t.Errorf("такт %d: signing %+v, ожидалось %+v", i+2, *got, exp)
		}
	}
}

// Пакет в base64 на треть больше состояния — потолок поднят до 4 МиБ, а
// ответ сверх него — явная ошибка, а не обрезанный JSON.
func TestClientResponseCeiling(t *testing.T) {
	useStateRoots(t, "")
	w := newStateWorld(t)
	body := func(size int) string {
		head, tail := `{"hostId":"`, `","apps":[]}`
		return head + strings.Repeat("a", size-len(head)-len(tail)) + tail
	}

	_, url := newFakePlatform(t, body(4<<20))
	resp, err := w.client(url, "").Tick(context.Background(), w.id, TickRequest{})
	if err != nil {
		t.Fatalf("ответ ровно 4 МиБ отвергнут: %v", err)
	}
	if !resp.DesiredState.Accepted {
		t.Fatal("ответ ровно 4 МиБ разобран не целиком")
	}

	_, url = newFakePlatform(t, body(4<<20+1))
	if _, err := w.client(url, "").Tick(context.Background(), w.id, TickRequest{}); err == nil || !strings.Contains(err.Error(), "больше потолка") {
		t.Fatalf("ответ сверх потолка: %v", err)
	}
}

func TestClientTickDeclaresProtocol(t *testing.T) {
	w := newStateWorld(t)
	cases := []struct {
		roots string
		want  string
	}{
		{w.rootsRaw(), `{"content":["host-state/0"],"envelopes":["dsse-ed25519/1"]}`},
		{"", `{"content":["host-state/0"],"envelopes":[]}`},
	}
	for _, tc := range cases {
		useStateRoots(t, tc.roots)
		p, url := newFakePlatform(t, `{"apps":[]}`)
		c := w.client(url, t.TempDir())
		w.tick(t, c)
		if _, err := c.DesiredState(context.Background(), w.id); err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if got := string(p.request(t, i).body["protocol"]); got != tc.want {
				t.Errorf("корни %q, запрос %s: protocol %s, ожидалось %s", tc.roots, p.request(t, i).path, got, tc.want)
			}
		}
	}
}

// Содержимое новее агента — отказ целиком, прежнее состояние (ADR-0093,
// решение 6).
func TestClientTickRefusesNewerContent(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	newerType, _ := hoststate.PayloadTypeFor("host-state/1")
	honest := w.signStateAs(t, w.work, 5, shopState, []string{shopSecretRef})
	parsed, err := signenv.Parse([]byte(mustJSON(t, honest)))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"content host-state/1": signedStateField(t, "host-state/1", honest, w.cert(t), shopSecrets()),
		"payloadType v=1": signedStateField(t, hoststate.ContentV0,
			signenv.Sign(w.work, newerType, parsed.Payload), w.cert(t), shopSecrets()),
		"незнакомое поле рядом с пакетом": strings.Replace(w.shopBundle(t, 5), `"content"`, `"manifest":{},"content"`, 1),
	}
	for name, signed := range cases {
		t.Run(name, func(t *testing.T) {
			p, url := newFakePlatform(t, signedResponse(signed))
			dir := t.TempDir()
			c := w.client(url, dir)
			expectNotApplied(t, w.tick(t, c).DesiredState)
			w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonUnsupportedContent)
			if latchExists(dir) {
				t.Fatal("отвергнутый пакет оставил защёлку")
			}
		})
	}
}

// Метка content подписью не покрыта: пакет чужого корня с незнакомой меткой
// отвергается как чужой, а не как «содержимое новее агента» — сертификат
// проверяется первым (ADR-0092, решение 4).
func TestClientTickCertCheckedBeforeContentLabel(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	signed := signedStateField(t, "host-state/9",
		w.signStateAs(t, w.work, 5, shopState, []string{shopSecretRef}),
		w.certBy(t, w.foreign, 8, "2026-10-01T00:00:00Z"), shopSecrets())
	p, url := newFakePlatform(t, signedResponse(signed))
	dir := t.TempDir()
	c := w.client(url, dir)
	expectNotApplied(t, w.tick(t, c).DesiredState)
	w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonCertNotFromRoot)
	if latchExists(dir) {
		t.Fatal("отвергнутый пакет оставил защёлку")
	}
}

func TestClientTickRefusesUnknownStateField(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	cases := []struct {
		name   string
		state  string
		reason hoststate.Reason
	}{
		{"поле приложения", strings.Replace(shopState, `"slug":"shop"`, `"slug":"shop","sidecar":true`, 1), hoststate.ReasonUnsupportedContent},
		{"поле состояния", strings.Replace(shopState, `"denyIps":[]`, `"denyIps":[],"manifest":{}`, 1), hoststate.ReasonUnsupportedContent},
		// Послабление не едет полем приложения: только грантом корня.
		{"allowances в приложении", strings.Replace(shopState, `"slug":"shop"`, `"slug":"shop","allowances":[]`, 1), hoststate.ReasonUnsupportedContent},
		{"неверный тип", strings.Replace(shopState, `"denyIps":[]`, `"denyIps":"all"`, 1), hoststate.ReasonStateMalformed},
		// Снять всё можно только подписанным пустым списком: отсутствие
		// списка неотличимо от сбоя сборки состояния.
		{"нет apps", `{"registries":[],"denyIps":[]}`, hoststate.ReasonStateMalformed},
		{"apps null", `{"apps":null,"registries":[]}`, hoststate.ReasonStateMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refs := []string{}
			if strings.Contains(tc.state, `"slug":"shop"`) {
				refs = []string{shopSecretRef}
			}
			secrets := map[string]string{}
			if len(refs) > 0 {
				secrets = shopSecrets()
			}
			signed := signedStateField(t, hoststate.ContentV0,
				w.signStateAs(t, w.work, 5, tc.state, refs), w.cert(t), secrets)
			p, url := newFakePlatform(t, signedResponse(signed))
			dir := t.TempDir()
			c := w.client(url, dir)
			expectNotApplied(t, w.tick(t, c).DesiredState)
			w.refusedOnNextTick(t, c, p, "refused", tc.reason)
			if latchExists(dir) {
				t.Fatal("пакет с неразобранным состоянием оставил защёлку")
			}
		})
	}
}

func TestClientTickRefusesForeignKey(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	cases := []struct {
		name   string
		signed string
		reason hoststate.Reason
	}{
		{"сертификат от чужого корня", signedStateField(t, hoststate.ContentV0,
			w.signStateAs(t, w.work, 5, shopState, []string{shopSecretRef}),
			w.certBy(t, w.foreign, 8, "2026-10-01T00:00:00Z"), shopSecrets()), hoststate.ReasonCertNotFromRoot},
		{"состояние чужим ключом", signedStateField(t, hoststate.ContentV0,
			w.signStateAs(t, w.foreign, 5, shopState, []string{shopSecretRef}), w.cert(t), shopSecrets()), hoststate.ReasonSignatureInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, url := newFakePlatform(t, signedResponse(tc.signed))
			dir := t.TempDir()
			c := w.client(url, dir)
			expectNotApplied(t, w.tick(t, c).DesiredState)
			w.refusedOnNextTick(t, c, p, "refused", tc.reason)
			if latchExists(dir) {
				t.Fatal("отвергнутый пакет оставил защёлку")
			}
		})
	}
}

func TestClientTickRefusesExpiredCert(t *testing.T) {
	w := newStateWorld(t)
	useStateRoots(t, w.rootsRaw())
	p, url := newFakePlatform(t, signedResponse(w.shopBundle(t, 5)))
	c := w.client(url, t.TempDir())
	c.now = func() time.Time { return mustParseTime(t, "2026-10-01T00:00:01Z") }

	expectNotApplied(t, w.tick(t, c).DesiredState)
	s := w.refusedOnNextTick(t, c, p, "refused", hoststate.ReasonCertExpired)
	if s.At != "2026-10-01T00:00:01Z" {
		t.Fatalf("момент доклада %q — не часы клиента", s.At)
	}
}
