package hoststate_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Мир проверки: ключи и время. Приватные ключи выводятся здесь из
// фиксированных байтов при каждом прогоне и не лежат ни в одном файле — в
// фикстурах только публичные половины.
type world struct {
	root, root2, work, foreign, agent ed25519.PrivateKey
	fingerprint                       string
	now                               time.Time
	hostID                            string
}

// keyFrom — ключ Ed25519 из 32 исходных байтов first, first+1, … Ключ агента
// (first = 0x01) — тот же, что в agent-signature.json: отпечаток пакета
// обязан совпасть с эталоном подписи запросов.
func keyFrom(first byte) ed25519.PrivateKey {
	b := make([]byte, ed25519.SeedSize)
	for i := range b {
		b[i] = first + byte(i)
	}
	return ed25519.NewKeyFromSeed(b)
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func newWorld() world {
	agent := keyFrom(0x01)
	// Отпечаток агента — от base64-строки ключа, как в agent-signature.json.
	sum := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(pub(agent))))
	return world{
		root:        keyFrom(0x21),
		root2:       keyFrom(0x81),
		work:        keyFrom(0x41),
		foreign:     keyFrom(0x61),
		agent:       agent,
		fingerprint: hex.EncodeToString(sum[:]),
		now:         mustTime("2026-09-17T12:00:00Z"),
		hostID:      "11111111-2222-4333-8444-555555555555",
	}
}

// Сертификат мира: serial 8 при защёлке 7 — так принятый пакет заодно
// показывает подъём защёлки serial. Срок — 30 дней, по умолчанию церемонии.
const (
	certSerial  = 8
	latchSerial = 7
)

var (
	certNotBefore = mustTime("2026-09-01T00:00:00Z")
	certNotAfter  = mustTime("2026-10-01T00:00:00Z")
)

// mailCompose — compose приложения, к которому корень выдаёт грант: шаблону
// почты нужен прямой порт 25.
const mailCompose = "name: ${APP_SLUG}\nservices:\n  smtp:\n    image: example/mail:1\n    ports:\n      - \"25:25\"\n"

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func (w world) verifier() hoststate.Verifier {
	return hoststate.Verifier{
		Roots:            []ed25519.PublicKey{pub(w.root), pub(w.root2)},
		AgentFingerprint: w.fingerprint,
		Now:              func() time.Time { return w.now },
	}
}

func (w world) verifierAt(now time.Time) hoststate.Verifier {
	v := w.verifier()
	v.Now = func() time.Time { return now }
	return v
}

// latch — агент, уже принявший пакет seq 4 под сертификатом serial 7.
func (w world) latch(t testing.TB) hoststate.Latch {
	t.Helper()
	return hoststate.Latch{
		AgentFingerprint: w.fingerprint,
		Seq:              4,
		PayloadSHA256:    sha(payloadOf(t, w.signState(t, w.hostState(4)))),
		MaxCertSerial:    latchSerial,
	}
}

// certPayload — сертификат полями, чтобы тест мог испортить любое из них мимо
// проверок IssueCertificate.
func (w world) certPayload() map[string]any {
	return map[string]any{
		"v":         1,
		"serial":    certSerial,
		"keyId":     signenv.KeyID(pub(w.work)),
		"publicKey": base64.StdEncoding.EncodeToString(pub(w.work)),
		"notBefore": "2026-09-01T00:00:00Z",
		"notAfter":  "2026-10-01T00:00:00Z",
		"purposes":  []string{"host-state"},
	}
}

func (w world) cert(t testing.TB) signenv.Envelope {
	t.Helper()
	env, err := hoststate.IssueCertificate(w.root, certSerial, pub(w.work), certNotBefore, certNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// signedCert — сертификат, собранный вручную и подписанный ключом signer (nil
// — основной корень) как сертификат.
func (w world) signedCert(t testing.TB, signer ed25519.PrivateKey, mutate func(map[string]any)) signenv.Envelope {
	t.Helper()
	c := w.certPayload()
	if mutate != nil {
		mutate(c)
	}
	if signer == nil {
		signer = w.root
	}
	return signenv.Sign(signer, hoststate.PayloadTypeCert, marshalCompact(t, c))
}

// stateJSON — желаемое состояние без значений секретов: по приложению на
// каждый вид ссылки, реестр и хранилище копий.
func stateJSON() json.RawMessage {
	compose, _ := json.Marshal(mailCompose) // у строки ошибки маршалинга не бывает
	return json.RawMessage(`{"apps":[` +
		`{"slug":"backend","sourceType":"git","compose":"","env":{"NODE_ENV":"production"},"gitKey":null,"gitToken":null},` +
		`{"slug":"site","sourceType":"git","compose":"","env":{},"gitKey":null,"gitToken":null},` +
		`{"slug":"mail","sourceType":"template","compose":` + string(compose) + `,"env":{"MAIL_DOMAIN":"mail.example.com"},"gitKey":null,"gitToken":null}` +
		`],"registries":[{"registry":"ghcr.io","username":"acme-bot","token":""}],"denyIps":[],"platformSubdomainBase":"",` +
		`"objectStorage":{"bucket":"acme-backups","accessKeyId":"test-only-access-key","secretAccessKey":""}}`)
}

// hostState — состояние хоста для подписи. Ссылки нарочно не по порядку:
// выпуск обязан отсортировать их сам.
func (w world) hostState(seq int64) hoststate.HostState {
	return hoststate.HostState{
		HostID:           w.hostID,
		AgentFingerprint: w.fingerprint,
		Seq:              seq,
		IssuedAt:         mustTime("2026-09-17T11:59:00Z"),
		State:            stateJSON(),
		Secrets: []string{
			"registry/ghcr.io/token", "app/mail/env/SMTP_PASSWORD", "objectStorage/secretAccessKey",
			"app/backend/env/DB_PASSWORD", "app/site/gitToken", "app/backend/gitKey",
		},
	}
}

func (w world) secretValues() map[string]string {
	return map[string]string{
		"app/backend/env/DB_PASSWORD":   "test-only-db-password",
		"app/backend/gitKey":            "test-only-git-key",
		"app/mail/env/SMTP_PASSWORD":    "test-only-smtp-password",
		"app/site/gitToken":             "test-only-git-token",
		"objectStorage/secretAccessKey": "test-only-object-storage-secret",
		"registry/ghcr.io/token":        "test-only-registry-token",
	}
}

func (w world) signState(t testing.TB, hs hoststate.HostState) signenv.Envelope {
	t.Helper()
	env, err := hoststate.SignState(w.work, hs)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// bundleJSON — пакет с произвольными членами: тесту нужно собрать и битый.
// Порядок полей — как у hoststate.Bundle.
func bundleJSON(t testing.TB, envelope, cert any) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		Envelope    any `json:"envelope"`
		Certificate any `json:"certificate"`
	}{envelope, cert})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (w world) validBundle(t testing.TB) []byte {
	t.Helper()
	return bundleJSON(t, w.signState(t, w.hostState(5)), w.cert(t))
}

func mailAllowances() []composeguard.Allowance {
	return []composeguard.Allowance{{Kind: composeguard.AllowPublishPort, Service: "smtp", Port: 25, Protocol: "tcp"}}
}

func composeSHA(compose string) string {
	return sha([]byte(compose))
}

// grant — грант корня шаблону почты: порт 25/tcp сервису smtp.
func (w world) grant(t testing.TB) signenv.Envelope {
	t.Helper()
	env, err := hoststate.IssueGrant(w.root, composeSHA(mailCompose), mailAllowances(), "шаблон почты: SMTP на 25/tcp")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// grantPayload — грант полями, чтобы испортить его мимо проверок IssueGrant.
func grantPayload() map[string]any {
	return map[string]any{
		"v":             1,
		"composeSha256": composeSHA(mailCompose),
		"allowances":    []map[string]any{{"kind": "publish_port", "service": "smtp", "port": 25, "protocol": "tcp"}},
		"notes":         "шаблон почты: SMTP на 25/tcp",
	}
}

func (w world) signedGrant(t testing.TB, signer ed25519.PrivateKey, mutate func(map[string]any)) signenv.Envelope {
	t.Helper()
	g := grantPayload()
	if mutate != nil {
		mutate(g)
	}
	if signer == nil {
		signer = w.root
	}
	return signenv.Sign(signer, hoststate.PayloadTypeGrant, marshalCompact(t, g))
}

// bundleWithGrants — пакет seq 5, в теле которого лежат данные гранты. Нагрузка
// собирается вручную и честно подписывается рабочим ключом: SignState
// негодный грант не подпишет, а проверить нужно именно агента.
func (w world) bundleWithGrants(t testing.TB, grants ...signenv.Envelope) []byte {
	t.Helper()
	env := w.resigned(t, hoststate.PayloadTypeHostStateV0, func(m map[string]any) {
		list := make([]any, 0, len(grants))
		for _, g := range grants {
			list = append(list, decodeMap(t, envelopeJSON(t, g)))
		}
		m["body"].(map[string]any)["grants"] = list
	})
	return bundleJSON(t, env, w.cert(t))
}

// resigned — нагрузка пакета seq 5, испорченная и честно переподписанная
// рабочим ключом: подпись верна, отказ обязан прийти от разбора и сверки.
func (w world) resigned(t testing.TB, payloadType string, mutate func(map[string]any)) signenv.Envelope {
	t.Helper()
	m := decodeMap(t, payloadOf(t, w.signState(t, w.hostState(5))))
	mutate(m)
	return signenv.Sign(w.work, payloadType, marshalCompact(t, m))
}

func envelopeJSON(t testing.TB, env signenv.Envelope) []byte {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// payloadOf — байты нагрузки конверта.
func payloadOf(t testing.TB, env signenv.Envelope) []byte {
	t.Helper()
	p, err := signenv.Parse(envelopeJSON(t, env))
	if err != nil {
		t.Fatal(err)
	}
	return p.Payload
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func decodeMap(t testing.TB, raw []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func marshalCompact(t testing.TB, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

func marshalIndent(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// expectRefused — отказ с нужной причиной, и защёлка не сдвинулась ни на
// одно поле: иначе отказанный пакет оставил бы след на диске агента.
func expectRefused(t *testing.T, name string, got hoststate.Result, want hoststate.Reason, prev hoststate.Latch) {
	t.Helper()
	if got.Reason != want {
		t.Errorf("%s: причина %q (%s), ожидалась %q", name, got.Reason, got.Detail, want)
	}
	if got.Next != prev {
		t.Errorf("%s: отказ сдвинул защёлку: %+v, было %+v", name, got.Next, prev)
	}
	if got.State != nil || got.AllowancesByCompose != nil {
		t.Errorf("%s: у отказа есть собранное состояние или послабления", name)
	}
}

func expectAccepted(t *testing.T, name string, got hoststate.Result) {
	t.Helper()
	if got.Reason != "" {
		t.Fatalf("%s: отказ %q (%s)", name, got.Reason, got.Detail)
	}
}
