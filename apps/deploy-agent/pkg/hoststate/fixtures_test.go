package hoststate_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Фикстуры межъязыкового контракта подписи (ADR-0092, ADR-0093).
//
// Файлы генерирует этот тест: UPDATE_SIGNING_FIXTURES=1 записывает, без
// переменной — сверяет побайтно. Ключи выводятся из фиксированных байтов,
// Ed25519 детерминирован, часы зафиксированы, поэтому повторная генерация даёт
// те же байты. Разошлось без правки контракта — значит изменился формат, и это
// повод остановиться, а не перегенерировать: по этим файлам проверяют себя
// агент, подписант и web.
//
// От кода агента пакет не зависит: строгий разбор собранного состояния в
// DesiredState — контрактный тест агента, здесь сравнение идёт на уровне JSON.

const updateFixturesEnv = "UPDATE_SIGNING_FIXTURES"

func fixturesDir() string {
	return filepath.Join("..", "..", "..", "..", "packages", "deploy-core", "fixtures")
}

// splitRefs — какие значения desired-state.json web выносит из подписи:
// переменная окружения, ключ и токен репозитория, ключ хранилища копий, токен
// реестра.
var splitRefs = []string{
	"app/backend/gitKey",
	"app/sigma-supabase/env/POSTGRES_PASSWORD",
	"app/site/gitToken",
	"app/supabase/env/JWT_SECRET",
	"objectStorage/secretAccessKey",
	"registry/ghcr.io/token",
}

// tickRefs — те же ссылки без ключа репозитория backend. Его значение в
// desired-state.json — строка с маркером приватного ключа, и в каталоге
// фикстур она лежит ровно в двух файлах (эталон и signed-state-split.json).
// Агенту всё равно, какие поля вынесены: он сверяет набор ссылок с
// подписанным, а какие поля режет web, закрепляет signed-state-split.json.
var tickRefs = []string{
	"app/sigma-supabase/env/POSTGRES_PASSWORD",
	"app/site/gitToken",
	"app/supabase/env/JWT_SECRET",
	"objectStorage/secretAccessKey",
	"registry/ghcr.io/token",
}

func TestSigningFixtures(t *testing.T) {
	w := newWorld()

	// Отпечаток агента обязан совпасть с эталоном подписи запросов: тот же
	// ключ, та же формула.
	sig := loadJSONMap(t, filepath.Join(fixturesDir(), "agent-signature.json"))
	if sig["fingerprint"] != w.fingerprint {
		t.Fatalf("отпечаток агента разошёлся с agent-signature.json: %s", w.fingerprint)
	}
	desired := loadJSONMap(t, filepath.Join(fixturesDir(), "desired-state.json"))

	bundles := buildSignedBundles(t, w)
	negotiation := buildNegotiation()
	split := buildSplit(t, desired)
	signerAPI := buildSignerAPI(t, w, split)
	tick := buildTickResponse(t, w, desired)

	checkSignedBundles(t, bundles)
	checkNegotiation(t, negotiation)
	checkSplit(t, split, desired)
	checkSignerAPI(t, w, signerAPI, split, desired)
	checkTickResponse(t, tick, desired)

	files := map[string][]byte{
		"signed-bundles.json":       encodeFixture(t, bundles),
		"protocol-negotiation.json": encodeFixture(t, negotiation),
		"signed-state-split.json":   encodeFixture(t, split),
		"signer-api.json":           encodeFixture(t, signerAPI),
		"tick-response-signed.json": encodeFixture(t, tick),
	}
	for name, content := range files {
		// Те же запреты, что у гейта каталога: только публичные ключи и
		// единственная копия тестовой строки ключа репозитория.
		if bytes.Contains(content, []byte("PRIVATE KEY")) && name != "signed-state-split.json" {
			t.Errorf("%s: маркер приватного ключа", name)
		}
		if bytes.Contains(content, []byte("seed")) {
			t.Errorf("%s: слово seed запрещено в каталоге фикстур", name)
		}
	}

	update := os.Getenv(updateFixturesEnv) == "1"
	for name, want := range files {
		path := filepath.Join(fixturesDir(), name)
		if update {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("нет фикстуры %s (сгенерировать: %s=1 go test -run TestSigningFixtures ./pkg/hoststate/): %v", name, updateFixturesEnv, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("фикстура %s разошлась с генератором: контракт подписи изменился — "+
				"правка идёт синхронно в агент, подписант и web, а не перегенерацией", name)
		}
	}
}

func loadJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не найден %s: %v", path, err)
	}
	return decodeMap(t, raw)
}

func encodeFixture(t *testing.T, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func rootPublicKeys(w world) []string {
	return []string{base64.StdEncoding.EncodeToString(pub(w.root)), base64.StdEncoding.EncodeToString(pub(w.root2))}
}

// verifierFrom — проверка, собранная только из того, что лежит в фикстуре:
// так же её соберёт агент или web по файлу.
func verifierFrom(t *testing.T, roots []string, now, fingerprint string) hoststate.Verifier {
	t.Helper()
	v := hoststate.Verifier{AgentFingerprint: fingerprint}
	for _, k := range roots {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			t.Fatal(err)
		}
		v.Roots = append(v.Roots, ed25519.PublicKey(raw))
	}
	at := mustTime(now)
	v.Now = func() time.Time { return at }
	return v
}

func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	return reflect.DeepEqual(x, y)
}

func cloneValues(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ── signed-bundles.json ──────────────────────────────────────────────────────

type fixtureValid struct {
	Bundle              json.RawMessage                     `json:"bundle"`
	Secrets             map[string]string                   `json:"secrets"`
	State               json.RawMessage                     `json:"state"`
	AllowancesByCompose map[string][]composeguard.Allowance `json:"allowancesByCompose"`
	Next                hoststate.Latch                     `json:"next"`
}

type fixtureRejected struct {
	Name    string            `json:"name"`
	Bundle  json.RawMessage   `json:"bundle"`
	Secrets map[string]string `json:"secrets"`
	Reason  hoststate.Reason  `json:"reason"`
}

type signedBundlesFixture struct {
	RootPublicKeys   []string          `json:"rootPublicKeys"`
	Now              string            `json:"now"`
	AgentFingerprint string            `json:"agentFingerprint"`
	Latch            hoststate.Latch   `json:"latch"`
	Valid            fixtureValid      `json:"valid"`
	Rejected         []fixtureRejected `json:"rejected"`
}

func buildSignedBundles(t *testing.T, w world) signedBundlesFixture {
	t.Helper()
	v0 := hoststate.PayloadTypeHostStateV0
	v1, _ := hoststate.PayloadTypeFor("host-state/1")
	cert := w.cert(t)
	grant := w.grant(t)

	hs := w.hostState(5)
	hs.Grants = []json.RawMessage{envelopeJSON(t, grant)}
	valid := w.signState(t, hs)
	validPayload := payloadOf(t, valid)
	body := func(m map[string]any) map[string]any { return m["body"].(map[string]any) }

	withEnv := func(env signenv.Envelope) json.RawMessage { return bundleJSON(t, env, cert) }
	withCert := func(c any) json.RawMessage { return bundleJSON(t, valid, c) }
	// resign — нагрузка годного пакета, испорченная и честно переподписанная
	// рабочим ключом: отказ обязан прийти от разбора и сверки, не от подписи.
	resign := func(payloadType string, mutate func(map[string]any)) signenv.Envelope {
		m := decodeMap(t, validPayload)
		mutate(m)
		return signenv.Sign(w.work, payloadType, marshalCompact(t, m))
	}
	withGrant := func(g signenv.Envelope) json.RawMessage {
		return withEnv(resign(v0, func(m map[string]any) {
			body(m)["grants"] = []any{decodeMap(t, envelopeJSON(t, g))}
		}))
	}
	withValues := func(mutate func(map[string]string)) map[string]string {
		out := w.secretValues()
		mutate(out)
		return out
	}

	twoSigs := valid
	twoSigs.Signatures = []signenv.Signature{valid.Signatures[0], valid.Signatures[0]}

	tampered := valid
	flipped := append([]byte(nil), validPayload...)
	i := bytes.Index(flipped, []byte(`"seq":5`)) + len(`"seq":`)
	flipped[i] = '6'
	tampered.Payload = base64.StdEncoding.EncodeToString(flipped)

	reserialized := signenv.Sign(w.work, v0, marshalIndent(t, decodeMap(t, validPayload)))
	reserialized.Payload = valid.Payload

	// Подмена типа документа: байты, честно подписанные корнем под одним
	// типом, выданы за другой (PAE).
	certAsGrantSigned := signenv.Sign(w.root, hoststate.PayloadTypeGrant, payloadOf(t, cert))
	certAsGrantSigned.PayloadType = hoststate.PayloadTypeCert
	grantAsCertSigned := signenv.Sign(w.root, hoststate.PayloadTypeCert, payloadOf(t, grant))
	grantAsCertSigned.PayloadType = hoststate.PayloadTypeGrant

	sameSeqOther := w.hostState(4)
	sameSeqOther.IssuedAt = sameSeqOther.IssuedAt.Add(time.Second)

	rejected := []fixtureRejected{
		{Name: "bundle-extra-field", Bundle: json.RawMessage(strings.Replace(string(withEnv(valid)), `{"envelope"`, `{"manifest":{},"envelope"`, 1)), Reason: hoststate.ReasonEnvelopeMalformed},
		{Name: "bundle-without-certificate", Bundle: bundleJSON(t, valid, nil), Reason: hoststate.ReasonEnvelopeMalformed},
		{Name: "envelope-two-signatures", Bundle: withEnv(twoSigs), Reason: hoststate.ReasonEnvelopeMalformed},
		{Name: "cert-not-from-root", Bundle: withCert(w.signedCert(t, w.foreign, nil)), Reason: hoststate.ReasonCertNotFromRoot},
		{Name: "cert-signed-by-work-key", Bundle: withCert(w.signedCert(t, w.work, nil)), Reason: hoststate.ReasonCertNotFromRoot},
		{Name: "cert-payload-type-swapped", Bundle: withCert(certAsGrantSigned), Reason: hoststate.ReasonCertNotFromRoot},
		{Name: "grant-presented-as-certificate", Bundle: withCert(grant), Reason: hoststate.ReasonCertInvalid},
		{Name: "cert-key-id-mismatch", Bundle: withCert(w.signedCert(t, nil, func(c map[string]any) { c["keyId"] = signenv.KeyID(pub(w.foreign)) })), Reason: hoststate.ReasonCertInvalid},
		{Name: "cert-validity-over-45-days", Bundle: withCert(w.signedCert(t, nil, func(c map[string]any) { c["notAfter"] = "2026-10-16T00:00:01Z" })), Reason: hoststate.ReasonCertValidityTooLong},
		{Name: "cert-not-before-beyond-skew", Bundle: withCert(w.signedCert(t, nil, func(c map[string]any) { c["notBefore"] = "2026-09-17T12:05:01Z" })), Reason: hoststate.ReasonCertNotYetValid},
		{Name: "cert-expired", Bundle: withCert(w.signedCert(t, nil, func(c map[string]any) {
			c["notBefore"] = "2026-08-20T00:00:00Z"
			c["notAfter"] = "2026-09-17T11:59:59Z"
		})), Reason: hoststate.ReasonCertExpired},
		{Name: "cert-wrong-purpose", Bundle: withCert(w.signedCert(t, nil, func(c map[string]any) { c["purposes"] = []string{"catalog-template"} })), Reason: hoststate.ReasonCertPurpose},
		{Name: "cert-superseded", Bundle: withCert(w.signedCert(t, nil, func(c map[string]any) { c["serial"] = latchSerial - 1 })), Reason: hoststate.ReasonCertSuperseded},
		{Name: "payload-byte-tampered", Bundle: withEnv(tampered), Reason: hoststate.ReasonSignatureInvalid},
		{Name: "signature-over-reserialized-json", Bundle: withEnv(reserialized), Reason: hoststate.ReasonSignatureInvalid},
		{Name: "envelope-signed-by-foreign-key", Bundle: withEnv(signenv.Sign(w.foreign, v0, validPayload)), Reason: hoststate.ReasonSignatureInvalid},
		{Name: "content-host-state-v1", Bundle: withEnv(resign(v1, func(map[string]any) {})), Reason: hoststate.ReasonUnsupportedContent},
		{Name: "payload-extra-field", Bundle: withEnv(resign(v0, func(m map[string]any) { m["expiresAt"] = "2026-10-01T00:00:00Z" })), Reason: hoststate.ReasonUnsupportedContent},
		{Name: "body-extra-field", Bundle: withEnv(resign(v0, func(m map[string]any) { body(m)["manifest"] = map[string]any{} })), Reason: hoststate.ReasonUnsupportedContent},
		{Name: "payload-trailing-data", Bundle: withEnv(signenv.Sign(w.work, v0, append(append([]byte(nil), validPayload...), " {}"...))), Reason: hoststate.ReasonPayloadMalformed},
		{Name: "payload-seq-zero", Bundle: withEnv(resign(v0, func(m map[string]any) { m["seq"] = 0 })), Reason: hoststate.ReasonPayloadMalformed},
		{Name: "body-without-grants", Bundle: withEnv(resign(v0, func(m map[string]any) { delete(body(m), "grants") })), Reason: hoststate.ReasonPayloadMalformed},
		{Name: "body-secrets-unsorted", Bundle: withEnv(resign(v0, func(m map[string]any) {
			s := body(m)["secrets"].([]any)
			s[0], s[1] = s[1], s[0]
		})), Reason: hoststate.ReasonPayloadMalformed},
		{Name: "fingerprint-mismatch", Bundle: withEnv(resign(v0, func(m map[string]any) { m["agentFingerprint"] = strings.Repeat("ab", 32) })), Reason: hoststate.ReasonFingerprintMismatch},
		{Name: "seq-lower-than-latch", Bundle: withEnv(w.signState(t, w.hostState(3))), Reason: hoststate.ReasonSeqRollback},
		{Name: "seq-equal-other-bytes", Bundle: withEnv(w.signState(t, sameSeqOther)), Reason: hoststate.ReasonSeqRollback},
		{Name: "grant-signed-by-work-key", Bundle: withGrant(w.signedGrant(t, w.work, nil)), Reason: hoststate.ReasonGrantInvalid},
		{Name: "grant-payload-type-swapped", Bundle: withGrant(grantAsCertSigned), Reason: hoststate.ReasonGrantInvalid},
		{Name: "certificate-presented-as-grant", Bundle: withGrant(cert), Reason: hoststate.ReasonGrantInvalid},
		{Name: "grant-unknown-kind", Bundle: withGrant(w.signedGrant(t, nil, func(g map[string]any) {
			g["allowances"] = []map[string]any{{"kind": "cap_add", "service": "smtp", "port": 25, "protocol": "tcp"}}
		})), Reason: hoststate.ReasonGrantInvalid},
		{Name: "grant-bad-digest", Bundle: withGrant(w.signedGrant(t, nil, func(g map[string]any) { g["composeSha256"] = "abc" })), Reason: hoststate.ReasonGrantInvalid},
		{Name: "secrets-value-missing", Bundle: withEnv(valid), Secrets: withValues(func(m map[string]string) { delete(m, "app/site/gitToken") }), Reason: hoststate.ReasonSecretsMismatch},
		{Name: "secrets-value-extra", Bundle: withEnv(valid), Secrets: withValues(func(m map[string]string) { m["app/site/env/INJECTED"] = "test-only-injected" }), Reason: hoststate.ReasonSecretsMismatch},
	}
	for i := range rejected {
		if rejected[i].Secrets == nil {
			rejected[i].Secrets = w.secretValues()
		}
	}

	f := signedBundlesFixture{
		RootPublicKeys:   rootPublicKeys(w),
		Now:              w.now.Format(time.RFC3339),
		AgentFingerprint: w.fingerprint,
		Latch:            w.latch(t),
		Rejected:         rejected,
	}
	res := verifierFrom(t, f.RootPublicKeys, f.Now, f.AgentFingerprint).Verify(f.Latch, hoststate.Input{Bundle: withEnv(valid), Secrets: w.secretValues()})
	expectAccepted(t, "signed-bundles valid", res)
	f.Valid = fixtureValid{
		Bundle:              withEnv(valid),
		Secrets:             w.secretValues(),
		State:               res.State,
		AllowancesByCompose: res.AllowancesByCompose,
		Next:                res.Next,
	}
	return f
}

func checkSignedBundles(t *testing.T, f signedBundlesFixture) {
	t.Helper()
	v := verifierFrom(t, f.RootPublicKeys, f.Now, f.AgentFingerprint)

	res := v.Verify(f.Latch, hoststate.Input{Bundle: f.Valid.Bundle, Secrets: f.Valid.Secrets})
	expectAccepted(t, "valid", res)
	if res.Next != f.Valid.Next || !reflect.DeepEqual(res.AllowancesByCompose, f.Valid.AllowancesByCompose) {
		t.Errorf("valid: защёлка %+v, послабления %+v", res.Next, res.AllowancesByCompose)
	}
	if res.Next.MaxCertSerial <= f.Latch.MaxCertSerial {
		t.Errorf("valid не показывает подъём защёлки serial: %+v", res.Next)
	}
	if len(f.Valid.AllowancesByCompose) == 0 {
		t.Error("valid без гранта: сопоставление по digest не закреплено")
	}

	seen := map[hoststate.Reason]bool{}
	for _, c := range f.Rejected {
		r := v.Verify(f.Latch, hoststate.Input{Bundle: c.Bundle, Secrets: c.Secrets})
		expectRefused(t, c.Name, r, c.Reason, f.Latch)
		seen[c.Reason] = true
	}
	// Каждый код, который выдаёт Verify, обязан иметь случай в фикстуре:
	// web учится показывать причины по этому файлу.
	for _, reason := range []hoststate.Reason{
		hoststate.ReasonEnvelopeMalformed, hoststate.ReasonSignatureInvalid, hoststate.ReasonCertInvalid,
		hoststate.ReasonCertNotFromRoot, hoststate.ReasonCertNotYetValid, hoststate.ReasonCertExpired,
		hoststate.ReasonCertValidityTooLong, hoststate.ReasonCertPurpose, hoststate.ReasonCertSuperseded,
		hoststate.ReasonUnsupportedContent, hoststate.ReasonPayloadMalformed, hoststate.ReasonFingerprintMismatch,
		hoststate.ReasonSeqRollback, hoststate.ReasonSecretsMismatch, hoststate.ReasonGrantInvalid,
	} {
		if !seen[reason] {
			t.Errorf("в rejected нет случая с причиной %s", reason)
		}
	}
}

// ── protocol-negotiation.json ────────────────────────────────────────────────

type negotiationCase struct {
	Name     string              `json:"name"`
	Declared *hoststate.Protocol `json:"declared"`
	Expected *hoststate.Choice   `json:"expected"`
	Legacy   bool                `json:"legacy"`
}

type negotiationFixture struct {
	Platform hoststate.Protocol `json:"platform"`
	Cases    []negotiationCase  `json:"cases"`
}

// Ожидания выписаны руками, а не посчитаны Negotiate: иначе фикстура
// закрепила бы любую ошибку выбора.
func buildNegotiation() negotiationFixture {
	proto := func(content, envelopes []string) *hoststate.Protocol {
		return &hoststate.Protocol{Content: content, Envelopes: envelopes}
	}
	choice := func(envelope, content string) *hoststate.Choice {
		return &hoststate.Choice{Envelope: envelope, Content: content}
	}
	dsse := []string{hoststate.EnvelopeDSSE}
	return negotiationFixture{
		// Платформа условная, с host-state/1: без второй версии выбор
		// «наибольшей из пересечения» нечем проверить.
		Platform: hoststate.Protocol{Content: []string{"host-state/0", "host-state/1"}, Envelopes: dsse},
		Cases: []negotiationCase{
			{Name: "legacy-agent-without-declaration", Declared: nil, Expected: choice("", "host-state/0"), Legacy: true},
			// Агент без корней: обёртки нет, общее содержимое — только
			// неподписанное host-state/0 (ADR-0093, решение 3).
			{Name: "agent-without-roots", Declared: proto([]string{"host-state/0"}, []string{}), Expected: choice("", "host-state/0")},
			{Name: "current-agent", Declared: proto([]string{"host-state/0"}, dsse), Expected: choice("dsse-ed25519/1", "host-state/0")},
			{Name: "agent-with-both-versions-gets-highest", Declared: proto([]string{"host-state/1", "host-state/0"}, dsse), Expected: choice("dsse-ed25519/1", "host-state/1")},
			{Name: "agent-newer-than-platform", Declared: proto([]string{"host-state/0", "host-state/1", "host-state/2"}, dsse), Expected: choice("dsse-ed25519/1", "host-state/1")},
			{Name: "agent-only-unknown-content", Declared: proto([]string{"host-state/7"}, dsse), Expected: nil},
			{Name: "agent-unknown-envelope", Declared: proto([]string{"host-state/0"}, []string{"dsse-ed25519/2"}), Expected: choice("", "host-state/0")},
			{Name: "empty-declaration", Declared: proto([]string{}, []string{}), Expected: nil},
			{Name: "leading-zero-is-not-a-version", Declared: proto([]string{"host-state/01"}, dsse), Expected: nil},
			{Name: "malformed-versions-ignored", Declared: proto([]string{"host-state", "host-state/x", "host-state/01", "host-state/0"}, []string{"dsse-ed25519"}), Expected: choice("", "host-state/0")},
		},
	}
}

func checkNegotiation(t *testing.T, f negotiationFixture) {
	t.Helper()
	for _, c := range f.Cases {
		got, legacy := hoststate.Negotiate(c.Declared, f.Platform)
		var gotPtr *hoststate.Choice
		if got.Content != "" {
			gotPtr = &got
		}
		if legacy != c.Legacy || !reflect.DeepEqual(gotPtr, c.Expected) {
			t.Errorf("%s: выбрано %+v legacy=%v", c.Name, gotPtr, legacy)
		}
	}
}

// ── signed-state-split.json ──────────────────────────────────────────────────

type splitFixture struct {
	Payload      json.RawMessage   `json:"payload"`
	SecretValues map[string]string `json:"secretValues"`
	State        json.RawMessage   `json:"state"`
	Secrets      []string          `json:"secrets"`
	Values       map[string]string `json:"values"`
}

// redact забирает значения секретов из состояния по правилам разреза: env —
// ключа нет, ключ и токен репозитория — null, токен реестра и ключ хранилища —
// пустая строка. Возвращает состояние без значений и карту «ссылка → значение».
func redact(t *testing.T, state map[string]any, refs []string) (json.RawMessage, map[string]string) {
	t.Helper()
	redacted := decodeMap(t, marshalCompact(t, state))
	values := map[string]string{}
	find := func(ref, list, field, value string) map[string]any {
		items, _ := redacted[list].([]any)
		for _, it := range items {
			if obj := it.(map[string]any); obj[field] == value {
				return obj
			}
		}
		t.Fatalf("%s: нет цели", ref)
		return nil
	}
	for _, ref := range refs {
		parts := strings.Split(ref, "/")
		switch {
		case parts[0] == "app" && parts[2] == "env":
			env := find(ref, "apps", "slug", parts[1])["env"].(map[string]any)
			values[ref] = env[parts[3]].(string)
			delete(env, parts[3])
		case parts[0] == "app":
			app := find(ref, "apps", "slug", parts[1])
			values[ref] = app[parts[2]].(string)
			app[parts[2]] = nil
		case parts[0] == "registry":
			reg := find(ref, "registries", "registry", parts[1])
			values[ref] = reg["token"].(string)
			reg["token"] = ""
		default:
			storage := redacted["objectStorage"].(map[string]any)
			values[ref] = storage["secretAccessKey"].(string)
			storage["secretAccessKey"] = ""
		}
	}
	return marshalCompact(t, redacted), values
}

func buildSplit(t *testing.T, desired map[string]any) splitFixture {
	t.Helper()
	state, values := redact(t, desired, splitRefs)
	secrets := append([]string(nil), splitRefs...)
	sort.Strings(secrets)
	return splitFixture{
		Payload:      marshalCompact(t, desired),
		SecretValues: values,
		State:        state,
		Secrets:      secrets,
		Values:       cloneValues(values),
	}
}

func checkSplit(t *testing.T, f splitFixture, desired map[string]any) {
	t.Helper()
	if !sameJSON(t, f.Payload, marshalCompact(t, desired)) {
		t.Error("split: payload не равен desired-state.json")
	}
	assembled, err := hoststate.AssembleStateV0(f.State, f.Secrets, f.Values)
	if err != nil {
		t.Fatalf("split: не собирается: %v", err)
	}
	if !sameJSON(t, assembled, f.Payload) {
		t.Errorf("split: собранное не равно payload:\n%s", assembled)
	}
	if !reflect.DeepEqual(f.Values, f.SecretValues) || !hoststate.SecretValuesMatch(f.Secrets, f.Values) || !sort.StringsAreSorted(f.Secrets) {
		t.Error("split: набор ссылок и значений не сходится")
	}
}

// ── signer-api.json ──────────────────────────────────────────────────────────

type signerExchange struct {
	HTTPStatus int                     `json:"httpStatus"`
	Body       *hoststate.SignResponse `json:"body"`
}

type signerResponses struct {
	Signed      signerExchange `json:"signed"`
	Refused     signerExchange `json:"refused"`
	Unavailable signerExchange `json:"unavailable"`
}

type signerAPIFixture struct {
	Request   hoststate.SignRequest `json:"request"`
	Responses signerResponses       `json:"responses"`
	Health    hoststate.Health      `json:"health"`
}

// Запрос несёт состояние из signed-state-split.json: web строит тело из
// разреза, и подписанный ответ собирается агентом обратно в desired-state.json.
func buildSignerAPI(t *testing.T, w world, split splitFixture) signerAPIFixture {
	t.Helper()
	req := hoststate.SignRequest{
		HostID:           w.hostID,
		AgentFingerprint: w.fingerprint,
		Content:          hoststate.ContentV0,
		SeqHint:          4,
		State:            split.State,
		Secrets:          split.Secrets,
		Grants:           []json.RawMessage{},
	}
	// Номер подписанта — max(хранимый, подсказка) + 1; хранимый здесь не
	// больше подсказки.
	env := w.signState(t, hoststate.HostState{
		HostID:           req.HostID,
		AgentFingerprint: req.AgentFingerprint,
		Seq:              req.SeqHint + 1,
		IssuedAt:         mustTime("2026-09-17T11:59:00Z"),
		State:            req.State,
		Secrets:          req.Secrets,
		Grants:           req.Grants,
	})
	signed := &hoststate.SignResponse{
		Status:        hoststate.SignStatusSigned,
		Seq:           req.SeqHint + 1,
		PayloadSHA256: sha(payloadOf(t, env)),
		CertSerial:    certSerial,
		CertNotAfter:  certNotAfter.Format(time.RFC3339),
		Bundle:        hoststate.Bundle{Envelope: env, Certificate: w.cert(t)},
	}
	refused := &hoststate.SignResponse{
		Status: hoststate.SignStatusRefused,
		Reason: "policy_violation",
		Violations: []hoststate.Violation{{
			App:  "sigma-supabase",
			Rule: composeguard.Violation{Service: "app", Reason: "privileged: true снимает почти все ограничения контейнера"}.String(),
		}},
	}
	return signerAPIFixture{
		Request: req,
		Responses: signerResponses{
			Signed:      signerExchange{HTTPStatus: 200, Body: signed},
			Refused:     signerExchange{HTTPStatus: 200, Body: refused},
			Unavailable: signerExchange{HTTPStatus: 503},
		},
		Health: hoststate.Health{OK: true, CertSerial: certSerial, CertNotAfter: certNotAfter.Format(time.RFC3339)},
	}
}

func checkSignerAPI(t *testing.T, w world, f signerAPIFixture, split splitFixture, desired map[string]any) {
	t.Helper()
	if !sameJSON(t, f.Request.State, split.State) || !reflect.DeepEqual(f.Request.Secrets, split.Secrets) || f.Request.Grants == nil {
		t.Error("signer-api: запрос разошёлся с разрезом")
	}
	signed := f.Responses.Signed.Body
	raw, err := json.Marshal(signed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	v := verifierFrom(t, rootPublicKeys(w), w.now.Format(time.RFC3339), f.Request.AgentFingerprint)
	res := v.Verify(w.latch(t), hoststate.Input{Bundle: raw, Secrets: split.Values})
	expectAccepted(t, "signer-api signed", res)
	if res.Seq != signed.Seq || res.PayloadSHA256 != signed.PayloadSHA256 || res.CertSerial != signed.CertSerial {
		t.Errorf("signer-api: поля ответа не совпали с пакетом: %+v", res)
	}
	if !sameJSON(t, res.State, marshalCompact(t, desired)) {
		t.Error("signer-api: подписанное состояние не собирается в desired-state.json")
	}
}

// ── tick-response-signed.json ────────────────────────────────────────────────

type signedStateWire struct {
	Content string            `json:"content"`
	Bundle  hoststate.Bundle  `json:"bundle"`
	Secrets map[string]string `json:"secrets"`
}

type tickResponseWire struct {
	SignedState signedStateWire `json:"signedState"`
}

type tickResponseFixture struct {
	RootPublicKeys   []string         `json:"rootPublicKeys"`
	Now              string           `json:"now"`
	AgentFingerprint string           `json:"agentFingerprint"`
	Response         tickResponseWire `json:"response"`
	LatchAfter       hoststate.Latch  `json:"latchAfter"`
}

// Первый пакет на хосте: защёлки до такта нет, seq 1.
func buildTickResponse(t *testing.T, w world, desired map[string]any) tickResponseFixture {
	t.Helper()
	state, values := redact(t, desired, tickRefs)
	env := w.signState(t, hoststate.HostState{
		HostID:           w.hostID,
		AgentFingerprint: w.fingerprint,
		Seq:              1,
		IssuedAt:         mustTime("2026-09-17T11:59:00Z"),
		State:            state,
		Secrets:          tickRefs,
	})
	f := tickResponseFixture{
		RootPublicKeys:   rootPublicKeys(w),
		Now:              w.now.Format(time.RFC3339),
		AgentFingerprint: w.fingerprint,
		Response: tickResponseWire{SignedState: signedStateWire{
			Content: hoststate.ContentV0,
			Bundle:  hoststate.Bundle{Envelope: env, Certificate: w.cert(t)},
			Secrets: values,
		}},
	}
	raw, err := json.Marshal(f.Response.SignedState.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	res := verifierFrom(t, f.RootPublicKeys, f.Now, f.AgentFingerprint).Verify(hoststate.Latch{}, hoststate.Input{Bundle: raw, Secrets: values})
	expectAccepted(t, "tick-response", res)
	f.LatchAfter = res.Next
	return f
}

func checkTickResponse(t *testing.T, f tickResponseFixture, desired map[string]any) {
	t.Helper()
	signed := f.Response.SignedState
	if signed.Content != hoststate.ContentV0 {
		t.Errorf("tick-response: content %q", signed.Content)
	}
	raw, err := json.Marshal(signed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	res := verifierFrom(t, f.RootPublicKeys, f.Now, f.AgentFingerprint).Verify(hoststate.Latch{}, hoststate.Input{Bundle: raw, Secrets: signed.Secrets})
	expectAccepted(t, "tick-response", res)
	if res.Next != f.LatchAfter {
		t.Errorf("tick-response: защёлка %+v, в фикстуре %+v", res.Next, f.LatchAfter)
	}
	if !sameJSON(t, res.State, marshalCompact(t, desired)) {
		t.Errorf("tick-response: собранное состояние не равно desired-state.json:\n%s", res.State)
	}
}
