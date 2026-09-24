package hoststate_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

// Ответ подписанта — два вида с разным набором полей (ADR-0092, решение 2).
// У подписанного нет reason и violations, у отказа нет пакета: web разбирает
// их по status, и лишнее нулевое поле читалось бы как «пакет есть, пустой».
func TestSignResponseForms(t *testing.T) {
	w := newWorld()
	bundle := hoststate.Bundle{Envelope: w.signState(t, w.hostState(5)), Certificate: w.cert(t)}
	signedResp := hoststate.SignResponse{
		Status: hoststate.SignStatusSigned, Seq: 5, PayloadSHA256: strings.Repeat("a", 64),
		CertSerial: certSerial, CertNotAfter: "2026-10-01T00:00:00Z", Bundle: bundle,
	}
	signed, err := json.Marshal(signedResp)
	if err != nil {
		t.Fatal(err)
	}
	var back hoststate.SignResponse
	if err := json.Unmarshal(signed, &back); err != nil || !reflect.DeepEqual(back, signedResp) {
		t.Fatalf("подписанный ответ не разбирается обратно: %v %+v", err, back)
	}
	prefix := `{"status":"signed","seq":5,"payloadSha256":"` + strings.Repeat("a", 64) + `","certSerial":8,"certNotAfter":"2026-10-01T00:00:00Z","bundle":{"envelope":`
	if !strings.HasPrefix(string(signed), prefix) || len(decodeMap(t, signed)) != 6 {
		t.Fatalf("подписанный ответ: %.200s", signed)
	}

	refused, err := json.Marshal(hoststate.SignResponse{Status: hoststate.SignStatusRefused, Reason: "policy_violation"})
	if err != nil {
		t.Fatal(err)
	}
	// Отказ без нарушений по приложениям — пустой список, а не null.
	if string(refused) != `{"status":"refused","reason":"policy_violation","violations":[]}` {
		t.Fatalf("отказ: %s", refused)
	}
	withViolation, err := json.Marshal(hoststate.SignResponse{
		Status: hoststate.SignStatusRefused, Reason: "policy_violation",
		Violations: []hoststate.Violation{{App: "mail", Rule: "сервис smtp: ports: публикация порта наружу запрещена"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(withViolation) != `{"status":"refused","reason":"policy_violation","violations":[{"app":"mail","rule":"сервис smtp: ports: публикация порта наружу запрещена"}]}` {
		t.Fatalf("отказ с нарушением: %s", withViolation)
	}

	for _, bad := range []hoststate.SignResponse{{}, {Status: "held"}, {Status: hoststate.SignStatusRefused}, {Status: hoststate.SignStatusSigned}} {
		if raw, err := json.Marshal(bad); err == nil {
			t.Errorf("негодный ответ %+v сериализован: %s", bad, raw)
		}
	}
}

// Здоровье подписанта без сертификата: полей сертификата нет вовсе, а не
// нули — сторож отличает «нет сертификата» от «serial 0 истёк».
func TestHealthForm(t *testing.T) {
	ready, _ := json.Marshal(hoststate.Health{OK: true, CertSerial: certSerial, CertNotAfter: "2026-10-01T00:00:00Z"})
	if string(ready) != `{"ok":true,"certSerial":8,"certNotAfter":"2026-10-01T00:00:00Z","expiresSoon":false}` {
		t.Fatalf("готов: %s", ready)
	}
	notReady, _ := json.Marshal(hoststate.Health{Reason: "no_certificate"})
	if string(notReady) != `{"ok":false,"expiresSoon":false,"reason":"no_certificate"}` {
		t.Fatalf("не готов: %s", notReady)
	}
}
