package hoststate_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Предел срока — и при выпуске: CLI корня не должен уметь выпустить
// сертификат, который узнаётся битым только отказами на хостах.
func TestIssueCertificateRefusesOver45Days(t *testing.T) {
	w := newWorld()
	if _, err := hoststate.IssueCertificate(w.root, certSerial, pub(w.work), certNotBefore, certNotBefore.Add(45*24*time.Hour+time.Second)); err == nil {
		t.Fatal("выпущен сертификат длиннее 45 дней")
	}
	if _, err := hoststate.IssueCertificate(w.root, certSerial, pub(w.work), certNotBefore, certNotBefore.Add(45*24*time.Hour)); err != nil {
		t.Fatalf("сертификат ровно на 45 дней не выпущен: %v", err)
	}
}

func TestIssueCertificateRefusesInvalid(t *testing.T) {
	w := newWorld()
	cases := map[string]func() error{
		"конец раньше начала": func() error {
			_, err := hoststate.IssueCertificate(w.root, certSerial, pub(w.work), certNotBefore, certNotBefore)
			return err
		},
		"serial 0": func() error {
			_, err := hoststate.IssueCertificate(w.root, 0, pub(w.work), certNotBefore, certNotAfter)
			return err
		},
		"не ключ": func() error {
			_, err := hoststate.IssueCertificate(w.root, certSerial, pub(w.work)[:5], certNotBefore, certNotAfter)
			return err
		},
	}
	for name, run := range cases {
		if run() == nil {
			t.Errorf("%s: выпущено", name)
		}
	}
}

// Формат полей и порядок — контракт: TypeScript и CLI читают эти байты сами.
func TestIssueCertificatePayloadForm(t *testing.T) {
	w := newWorld()
	got := string(payloadOf(t, w.cert(t)))
	want := `{"v":1,"serial":8,"keyId":"` + signenv.KeyID(pub(w.work)) + `","publicKey":"` +
		base64.StdEncoding.EncodeToString(pub(w.work)) +
		`","notBefore":"2026-09-01T00:00:00Z","notAfter":"2026-10-01T00:00:00Z","purposes":["host-state"]}`
	if got != want {
		t.Fatalf("нагрузка сертификата:\n got %s\nwant %s", got, want)
	}
}

func TestSignStateForm(t *testing.T) {
	w := newWorld()
	hs := w.hostState(5)
	m := decodeMap(t, payloadOf(t, w.signState(t, hs)))
	body := m["body"].(map[string]any)
	secrets, _ := json.Marshal(body["secrets"])
	if string(secrets) != `["app/backend/env/DB_PASSWORD","app/backend/gitKey","app/mail/env/SMTP_PASSWORD","app/site/gitToken","objectStorage/secretAccessKey","registry/ghcr.io/token"]` {
		t.Fatalf("secrets не отсортированы: %s", secrets)
	}
	if hs.Secrets[0] != "registry/ghcr.io/token" {
		t.Fatal("выпуск переставил срез вызывающего")
	}
	// Грантов нет — пустой список, а не null: строгий разбор агента требует поле.
	if grants, _ := json.Marshal(body["grants"]); string(grants) != `[]` {
		t.Fatalf("grants без грантов: %s", grants)
	}
	for _, k := range []string{"hostId", "agentFingerprint", "seq", "issuedAt", "body"} {
		if _, ok := m[k]; !ok {
			t.Errorf("нет поля %s", k)
		}
	}
	if len(m) != 5 {
		t.Fatalf("лишние поля нагрузки: %v", m)
	}
}

func TestSignStateRefusesInvalid(t *testing.T) {
	w := newWorld()
	grantV2 := w.signedGrant(t, nil, func(g map[string]any) { g["v"] = 2 })
	bad := map[string]func(*hoststate.HostState){
		"seq 0":           func(h *hoststate.HostState) { h.Seq = 0 },
		"hostId":          func(h *hoststate.HostState) { h.HostID = "x" },
		"отпечаток":       func(h *hoststate.HostState) { h.AgentFingerprint = "abc" },
		"повтор секрета":  func(h *hoststate.HostState) { h.Secrets = []string{"app/backend/gitKey", "app/backend/gitKey"} },
		"плохая ссылка":   func(h *hoststate.HostState) { h.Secrets = []string{"host/root"} },
		"state не объект": func(h *hoststate.HostState) { h.State = json.RawMessage(`[]`) },
		"state не JSON":   func(h *hoststate.HostState) { h.State = json.RawMessage(`{`) },
		"ссылка без цели": func(h *hoststate.HostState) { h.Secrets = []string{"app/nope/gitKey"} },
		"грант не конверт": func(h *hoststate.HostState) {
			h.Grants = []json.RawMessage{json.RawMessage(`{"v":1}`)}
		},
		"сертификат вместо гранта": func(h *hoststate.HostState) {
			h.Grants = []json.RawMessage{envelopeJSON(t, w.cert(t))}
		},
		"грант версии 2": func(h *hoststate.HostState) {
			h.Grants = []json.RawMessage{envelopeJSON(t, grantV2)}
		},
	}
	for name, mutate := range bad {
		h := w.hostState(5)
		mutate(&h)
		if _, err := hoststate.SignState(w.work, h); err == nil {
			t.Errorf("%s: подписано", name)
		}
	}
}

// Пакет, собранный типом Bundle, принимается проверкой: подписант собирает его
// этим типом, агент разбирает своим — формат у них обязан быть один.
func TestBundleTypeRoundTrip(t *testing.T) {
	w := newWorld()
	raw, err := json.Marshal(hoststate.Bundle{Envelope: w.signState(t, w.hostState(5)), Certificate: w.cert(t)})
	if err != nil {
		t.Fatal(err)
	}
	expectAccepted(t, "пакет типа Bundle", w.verifier().Verify(w.latch(t), hoststate.Input{Bundle: raw, Secrets: w.secretValues()}))
	if string(raw[:12]) != `{"envelope":` {
		t.Fatalf("порядок полей пакета: %.40s", raw)
	}
	if m := decodeMap(t, raw); len(m) != 2 {
		t.Fatalf("пакет — ровно {envelope, certificate}: %v", m)
	}
}

// Самопроверка подписанта при старте — та же проверка сертификата, что у
// агента: код отказа отличает «не готов» (срок) от битой настройки.
func TestVerifyCertificateForSigner(t *testing.T) {
	w := newWorld()
	roots := w.verifier().Roots
	cert, key, err := hoststate.VerifyCertificate(envelopeJSON(t, w.cert(t)), roots, w.now)
	if err != nil {
		t.Fatalf("действующий сертификат отвергнут: %v", err)
	}
	if cert.Serial != certSerial || cert.NotAfter != "2026-10-01T00:00:00Z" || !key.Equal(pub(w.work)) {
		t.Fatalf("сертификат: %+v", cert)
	}

	cases := []struct {
		name string
		raw  []byte
		now  time.Time
		want hoststate.Reason
	}{
		{"истёк", envelopeJSON(t, w.cert(t)), certNotAfter.Add(time.Second), hoststate.ReasonCertExpired},
		{"ещё не действует", envelopeJSON(t, w.cert(t)), certNotBefore.Add(-time.Hour), hoststate.ReasonCertNotYetValid},
		{"чужой корень", envelopeJSON(t, w.signedCert(t, w.foreign, nil)), w.now, hoststate.ReasonCertNotFromRoot},
		{"длиннее 45 дней", envelopeJSON(t, w.signedCert(t, nil, func(c map[string]any) { c["notAfter"] = "2026-10-16T00:00:01Z" })), w.now, hoststate.ReasonCertValidityTooLong},
		{"не конверт", []byte(`{}`), w.now, hoststate.ReasonCertInvalid},
	}
	for _, c := range cases {
		_, _, err := hoststate.VerifyCertificate(c.raw, roots, c.now)
		var refusal *hoststate.RefusalError
		if !errors.As(err, &refusal) || refusal.Reason != c.want {
			t.Errorf("%s: %v, ожидался отказ %q", c.name, err, c.want)
		}
	}
}
