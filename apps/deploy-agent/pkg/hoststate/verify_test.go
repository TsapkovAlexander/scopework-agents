package hoststate_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

func TestVerifyAcceptsValidBundle(t *testing.T) {
	w := newWorld()
	res := w.verifier().Verify(w.latch(t), hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()})
	expectAccepted(t, "валидный пакет", res)

	payload := payloadOf(t, w.signState(t, w.hostState(5)))
	want := hoststate.Latch{AgentFingerprint: w.fingerprint, Seq: 5, PayloadSHA256: sha(payload), MaxCertSerial: certSerial}
	if res.Next != want {
		t.Fatalf("защёлка после приёма: %+v, ожидалась %+v", res.Next, want)
	}
	if res.Seq != 5 || res.PayloadSHA256 != sha(payload) || res.CertSerial != certSerial {
		t.Fatalf("итог: seq %d, sha %s, serial %d", res.Seq, res.PayloadSHA256, res.CertSerial)
	}
	if len(res.AllowancesByCompose) != 0 {
		t.Fatalf("послабления без грантов: %+v", res.AllowancesByCompose)
	}

	var state struct {
		Apps []struct {
			Slug     string            `json:"slug"`
			Env      map[string]string `json:"env"`
			GitKey   *string           `json:"gitKey"`
			GitToken *string           `json:"gitToken"`
		} `json:"apps"`
		Registries []struct {
			Token string `json:"token"`
		} `json:"registries"`
		ObjectStorage struct {
			SecretAccessKey string `json:"secretAccessKey"`
		} `json:"objectStorage"`
	}
	if err := json.Unmarshal(res.State, &state); err != nil {
		t.Fatal(err)
	}
	backend, site, mail := state.Apps[0], state.Apps[1], state.Apps[2]
	if backend.Env["DB_PASSWORD"] != "test-only-db-password" || backend.Env["NODE_ENV"] != "production" ||
		backend.GitKey == nil || *backend.GitKey != "test-only-git-key" || backend.GitToken != nil ||
		site.GitToken == nil || *site.GitToken != "test-only-git-token" ||
		mail.Env["SMTP_PASSWORD"] != "test-only-smtp-password" || mail.Env["MAIL_DOMAIN"] != "mail.example.com" ||
		state.Registries[0].Token != "test-only-registry-token" ||
		state.ObjectStorage.SecretAccessKey != "test-only-object-storage-secret" {
		t.Fatalf("секреты не подставлены: %s", res.State)
	}
}

// Чужой ключ в любом звене цепочки — отказ: сертификат не от вшитого корня и
// состояние, подписанное не ключом сертификата.
func TestVerifyRefusesForeignKey(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	state := w.signState(t, w.hostState(5))
	cases := []struct {
		name   string
		bundle []byte
		want   hoststate.Reason
	}{
		{"сертификат от чужого корня", bundleJSON(t, state, w.signedCert(t, w.foreign, nil)), hoststate.ReasonCertNotFromRoot},
		{"рабочий ключ заверил сам себя", bundleJSON(t, state, w.signedCert(t, w.work, nil)), hoststate.ReasonCertNotFromRoot},
		{"состояние чужим ключом", bundleJSON(t, signenv.Sign(w.foreign, hoststate.PayloadTypeHostStateV0, payloadOf(t, state)), w.cert(t)), hoststate.ReasonSignatureInvalid},
		{"состояние корнем, а не рабочим ключом", bundleJSON(t, signenv.Sign(w.root, hoststate.PayloadTypeHostStateV0, payloadOf(t, state)), w.cert(t)), hoststate.ReasonSignatureInvalid},
	}
	for _, c := range cases {
		expectRefused(t, c.name, w.verifier().Verify(prev, hoststate.Input{Bundle: c.bundle, Secrets: w.secretValues()}), c.want, prev)
	}
}

func TestVerifyRefusesSeqRollback(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	bundle := bundleJSON(t, w.signState(t, w.hostState(3)), w.cert(t))
	res := w.verifier().Verify(prev, hoststate.Input{Bundle: bundle, Secrets: w.secretValues()})
	expectRefused(t, "seq 3 при принятом 4", res, hoststate.ReasonSeqRollback, prev)
	// Номер отказанного пакета нужен докладу платформе.
	if res.Seq != 3 {
		t.Fatalf("seq отказа: %d", res.Seq)
	}
}

// Повторная доставка того же пакета — не отказ: web отдаёт последний пакет,
// пока подписант не выпустил новый, и агент после рестарта получает его снова.
func TestVerifyAcceptsSameSeqSameBytes(t *testing.T) {
	w := newWorld()
	first := w.verifier().Verify(w.latch(t), hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()})
	expectAccepted(t, "первая доставка", first)
	again := w.verifier().Verify(first.Next, hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()})
	expectAccepted(t, "повторная доставка", again)
	if again.Next != first.Next {
		t.Fatalf("повтор сдвинул защёлку: %+v → %+v", first.Next, again.Next)
	}
}

func TestVerifyRefusesSameSeqOtherBytes(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	hs := w.hostState(4)
	hs.IssuedAt = hs.IssuedAt.Add(time.Second)
	bundle := bundleJSON(t, w.signState(t, hs), w.cert(t))
	expectRefused(t, "seq 4 с другими байтами", w.verifier().Verify(prev, hoststate.Input{Bundle: bundle, Secrets: w.secretValues()}), hoststate.ReasonSeqRollback, prev)
}

func TestVerifyRefusesExpiredCert(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	in := hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()}
	expectRefused(t, "секунда после notAfter", w.verifierAt(certNotAfter.Add(time.Second)).Verify(prev, in), hoststate.ReasonCertExpired, prev)
	// Граница включительно: сертификат действует и в самый момент notAfter.
	expectAccepted(t, "ровно notAfter", w.verifierAt(certNotAfter).Verify(prev, in))
}

// Допуск часов — только на notBefore: хост с отстающими часами не должен
// отвергать сертификат, выпущенный минуту назад по часам подписанта.
func TestVerifyRefusesNotBeforeBeyondSkew(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	in := hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()}
	at := certNotBefore.Add(-5*time.Minute - time.Second)
	expectRefused(t, "за 5 мин 1 с до notBefore", w.verifierAt(at).Verify(prev, in), hoststate.ReasonCertNotYetValid, prev)
}

func TestVerifyAcceptsNotBeforeWithinSkew(t *testing.T) {
	w := newWorld()
	in := hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()}
	for _, at := range []time.Time{certNotBefore.Add(-5 * time.Minute), certNotBefore.Add(-time.Minute), certNotBefore} {
		expectAccepted(t, at.Format(time.RFC3339), w.verifierAt(at).Verify(w.latch(t), in))
	}
}

// Предел срока — граница ущерба от украденного рабочего ключа (отзыва нет):
// ошибка церемонии не должна выпустить «вечный» сертификат.
func TestVerifyRefusesCertLongerThan45Days(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	state := w.signState(t, w.hostState(5))
	tooLong := w.signedCert(t, nil, func(c map[string]any) {
		c["notAfter"] = certNotBefore.Add(45*24*time.Hour + time.Second).Format(time.RFC3339)
	})
	expectRefused(t, "45 дней и секунда", w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, tooLong), Secrets: w.secretValues()}), hoststate.ReasonCertValidityTooLong, prev)

	exact, err := hoststate.IssueCertificate(w.root, certSerial, pub(w.work), certNotBefore, certNotBefore.Add(45*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	expectAccepted(t, "ровно 45 дней", w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, exact), Secrets: w.secretValues()}))
}

// Новый сертификат, доехавший до агента, закрывает все с меньшим serial —
// вместо отзыва списком (ADR-0092, решение 8).
func TestVerifyRefusesSupersededSerial(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	state := w.signState(t, w.hostState(5))
	older := w.signedCert(t, nil, func(c map[string]any) { c["serial"] = latchSerial - 1 })
	expectRefused(t, "serial меньше защёлкнутого", w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, older), Secrets: w.secretValues()}), hoststate.ReasonCertSuperseded, prev)

	same := w.signedCert(t, nil, func(c map[string]any) { c["serial"] = latchSerial })
	expectAccepted(t, "serial равен защёлкнутому", w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, same), Secrets: w.secretValues()}))
}

// Защёлка serial поднимается только вместе с принятым пакетом: сертификат,
// пришедший в отвергнутом пакете, ещё ничего не доказал, и поднятая по нему
// защёлка заперла бы агента от действующего сертификата.
func TestVerifyRaisesSerialLatchOnlyOnAccept(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	newer := w.signedCert(t, nil, func(c map[string]any) { c["serial"] = 9 })

	missing := w.secretValues()
	delete(missing, "app/site/gitToken")
	refusals := []struct {
		name   string
		bundle []byte
		values map[string]string
		want   hoststate.Reason
	}{
		{"откат номера", bundleJSON(t, w.signState(t, w.hostState(3)), newer), w.secretValues(), hoststate.ReasonSeqRollback},
		{"набор секретов", bundleJSON(t, w.signState(t, w.hostState(5)), newer), missing, hoststate.ReasonSecretsMismatch},
		{"подпись состояния", bundleJSON(t, signenv.Sign(w.foreign, hoststate.PayloadTypeHostStateV0, payloadOf(t, w.signState(t, w.hostState(5)))), newer), w.secretValues(), hoststate.ReasonSignatureInvalid},
	}
	for _, c := range refusals {
		res := w.verifier().Verify(prev, hoststate.Input{Bundle: c.bundle, Secrets: c.values})
		expectRefused(t, c.name, res, c.want, prev)
		if res.CertSerial != 9 {
			t.Errorf("%s: serial сертификата не доложен: %d", c.name, res.CertSerial)
		}
	}

	accepted := w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, w.signState(t, w.hostState(5)), newer), Secrets: w.secretValues()})
	expectAccepted(t, "пакет с serial 9", accepted)
	if accepted.Next.MaxCertSerial != 9 {
		t.Fatalf("защёлка serial не поднялась: %+v", accepted.Next)
	}
	// Дальше прежний сертификат (serial 8) уже закрыт.
	next := bundleJSON(t, w.signState(t, w.hostState(6)), w.cert(t))
	expectRefused(t, "serial 8 после принятого 9", w.verifier().Verify(accepted.Next, hoststate.Input{Bundle: next, Secrets: w.secretValues()}), hoststate.ReasonCertSuperseded, accepted.Next)
}

// hostId агент не закрепляет (ADR-0092, решение 4): пересоздание хоста на
// платформе при том же ключе агента не должно запирать выкаты.
func TestVerifyAcceptsNewHostIdSameFingerprint(t *testing.T) {
	w := newWorld()
	hs := w.hostState(5)
	hs.HostID = "99999999-2222-4333-8444-555555555555"
	res := w.verifier().Verify(w.latch(t), hoststate.Input{Bundle: bundleJSON(t, w.signState(t, hs), w.cert(t)), Secrets: w.secretValues()})
	expectAccepted(t, "новый hostId", res)
	if res.Next.Seq != 5 || res.Next.AgentFingerprint != w.fingerprint {
		t.Fatalf("защёлка: %+v", res.Next)
	}
}

func TestVerifyRefusesFingerprintMismatch(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	env := w.resigned(t, hoststate.PayloadTypeHostStateV0, func(m map[string]any) { m["agentFingerprint"] = strings.Repeat("ab", 32) })
	expectRefused(t, "пакет чужому агенту", w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, env, w.cert(t)), Secrets: w.secretValues()}), hoststate.ReasonFingerprintMismatch, prev)
}

// Набор значений секретов обязан совпасть с подписанным ровно: лишнее значение
// — то, чего подписант не видел, недостающее — стек без секрета.
func TestVerifyRefusesSecretsMismatch(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	missing := w.secretValues()
	delete(missing, "app/backend/gitKey")
	extra := w.secretValues()
	extra["app/backend/env/EXTRA"] = "test-only-extra"
	for name, values := range map[string]map[string]string{"не хватает": missing, "лишнее": extra, "пусто": nil} {
		res := w.verifier().Verify(prev, hoststate.Input{Bundle: w.validBundle(t), Secrets: values})
		expectRefused(t, name, res, hoststate.ReasonSecretsMismatch, prev)
	}
}

// Незнакомое поле — «содержимое новее агента», а не порча: отказ целиком
// (ADR-0093, решение 6), понятая наполовину нагрузка применилась бы наполовину.
func TestVerifyRefusesUnknownPayloadField(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	body := func(m map[string]any) map[string]any { return m["body"].(map[string]any) }
	cases := map[string]func(map[string]any){
		"поле нагрузки": func(m map[string]any) { m["expiresAt"] = "2026-10-01T00:00:00Z" },
		"поле body":     func(m map[string]any) { body(m)["manifest"] = map[string]any{} },
	}
	for name, mutate := range cases {
		env := w.resigned(t, hoststate.PayloadTypeHostStateV0, mutate)
		expectRefused(t, name, w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, env, w.cert(t)), Secrets: w.secretValues()}), hoststate.ReasonUnsupportedContent, prev)
	}
}

// Защёлка другого отпечатка — след прежней установки агента на этом сервере
// (переустановка — действие root): проверка начинается заново, как без файла.
func TestVerifyLatchOfOtherFingerprintIsFresh(t *testing.T) {
	w := newWorld()
	stale := hoststate.Latch{AgentFingerprint: strings.Repeat("cd", 32), Seq: 100, PayloadSHA256: strings.Repeat("0", 64), MaxCertSerial: 50}
	res := w.verifier().Verify(stale, hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()})
	expectAccepted(t, "защёлка чужого отпечатка", res)
	if res.Next.AgentFingerprint != w.fingerprint || res.Next.Seq != 5 || res.Next.MaxCertSerial != certSerial {
		t.Fatalf("защёлка: %+v", res.Next)
	}
	// Пустая защёлка — первый пакет на хосте.
	expectAccepted(t, "пустая защёлка", w.verifier().Verify(hoststate.Latch{}, hoststate.Input{Bundle: w.validBundle(t), Secrets: w.secretValues()}))
}

// Сертификат от второго вшитого корня принимается: запасной корень вводится
// сразу (ADR-0092, решение 9).
func TestVerifyAcceptsCertFromSecondRoot(t *testing.T) {
	w := newWorld()
	bundle := bundleJSON(t, w.signState(t, w.hostState(5)), w.signedCert(t, w.root2, nil))
	expectAccepted(t, "второй корень", w.verifier().Verify(w.latch(t), hoststate.Input{Bundle: bundle, Secrets: w.secretValues()}))
}

func TestVerifyEnvelopeAndSignature(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	cert := w.cert(t)
	good := w.signState(t, w.hostState(5))

	twoSigs := good
	twoSigs.Signatures = append([]signenv.Signature{}, good.Signatures[0], good.Signatures[0])

	tampered := good
	p := payloadOf(t, good)
	flipped := append([]byte(nil), p...)
	i := bytes.Index(flipped, []byte(`"seq":5`)) + len(`"seq":`)
	flipped[i] = '6'
	tampered.Payload = base64.StdEncoding.EncodeToString(flipped)

	// Подписан пересериализованный JSON, доставлены исходные байты: по смыслу
	// то же самое, по байтам — нет.
	reser := signenv.Sign(w.work, hoststate.PayloadTypeHostStateV0, marshalIndent(t, decodeMap(t, p)))
	reser.Payload = good.Payload

	cases := []struct {
		name   string
		bundle []byte
		want   hoststate.Reason
	}{
		{"не JSON", []byte(`{`), hoststate.ReasonEnvelopeMalformed},
		{"лишнее поле пакета", []byte(strings.Replace(string(bundleJSON(t, good, cert)), `{"envelope"`, `{"x":1,"envelope"`, 1)), hoststate.ReasonEnvelopeMalformed},
		{"нет сертификата", bundleJSON(t, good, nil), hoststate.ReasonEnvelopeMalformed},
		{"нет конверта", bundleJSON(t, nil, cert), hoststate.ReasonEnvelopeMalformed},
		{"две подписи", bundleJSON(t, twoSigs, cert), hoststate.ReasonEnvelopeMalformed},
		{"подменённый байт", bundleJSON(t, tampered, cert), hoststate.ReasonSignatureInvalid},
		{"пересериализованный JSON", bundleJSON(t, reser, cert), hoststate.ReasonSignatureInvalid},
	}
	for _, c := range cases {
		expectRefused(t, c.name, w.verifier().Verify(prev, hoststate.Input{Bundle: c.bundle, Secrets: w.secretValues()}), c.want, prev)
	}
}

func TestVerifyCertificate(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	state := w.signState(t, w.hostState(5))
	cases := []struct {
		name string
		cert signenv.Envelope
		want hoststate.Reason
	}{
		{"keyId не от publicKey", w.signedCert(t, nil, func(c map[string]any) { c["keyId"] = signenv.KeyID(pub(w.foreign)) }), hoststate.ReasonCertInvalid},
		{"notAfter раньше notBefore", w.signedCert(t, nil, func(c map[string]any) { c["notAfter"] = "2026-08-01T00:00:00Z" }), hoststate.ReasonCertInvalid},
		{"не UTC", w.signedCert(t, nil, func(c map[string]any) { c["notBefore"] = "2026-09-01T03:00:00+03:00" }), hoststate.ReasonCertInvalid},
		{"лишнее поле", w.signedCert(t, nil, func(c map[string]any) { c["extra"] = true }), hoststate.ReasonCertInvalid},
		{"версия 2", w.signedCert(t, nil, func(c map[string]any) { c["v"] = 2 }), hoststate.ReasonCertInvalid},
		{"serial 0", w.signedCert(t, nil, func(c map[string]any) { c["serial"] = 0 }), hoststate.ReasonCertInvalid},
		{"нет purposes", w.signedCert(t, nil, func(c map[string]any) { delete(c, "purposes") }), hoststate.ReasonCertInvalid},
		{"грант вместо сертификата", w.grant(t), hoststate.ReasonCertInvalid},
		{"просрочен", w.signedCert(t, nil, func(c map[string]any) {
			c["notBefore"] = "2026-08-20T00:00:00Z"
			c["notAfter"] = "2026-09-17T11:59:59Z"
		}), hoststate.ReasonCertExpired},
		{"ещё не действует", w.signedCert(t, nil, func(c map[string]any) { c["notBefore"] = "2026-09-17T12:05:01Z" }), hoststate.ReasonCertNotYetValid},
		{"не для состояния", w.signedCert(t, nil, func(c map[string]any) { c["purposes"] = []string{"catalog-template"} }), hoststate.ReasonCertPurpose},
	}
	for _, c := range cases {
		res := w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, c.cert), Secrets: w.secretValues()})
		expectRefused(t, c.name, res, c.want, prev)
	}
}

func TestVerifyPayload(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	cert := w.cert(t)
	v0 := hoststate.PayloadTypeHostStateV0
	v1, _ := hoststate.PayloadTypeFor("host-state/1")
	body := func(m map[string]any) map[string]any { return m["body"].(map[string]any) }

	trailing := signenv.Sign(w.work, v0, append(payloadOf(t, w.signState(t, w.hostState(5))), []byte(` {}`)...))

	cases := []struct {
		name string
		env  signenv.Envelope
		want hoststate.Reason
	}{
		{"host-state/1", w.resigned(t, v1, func(map[string]any) {}), hoststate.ReasonUnsupportedContent},
		{"незнакомый тип", w.resigned(t, "application/json", func(map[string]any) {}), hoststate.ReasonUnsupportedContent},
		{"данные после JSON", trailing, hoststate.ReasonPayloadMalformed},
		{"нет body", w.resigned(t, v0, func(m map[string]any) { delete(m, "body") }), hoststate.ReasonPayloadMalformed},
		{"нет grants", w.resigned(t, v0, func(m map[string]any) { delete(body(m), "grants") }), hoststate.ReasonPayloadMalformed},
		{"grants null", w.resigned(t, v0, func(m map[string]any) { body(m)["grants"] = nil }), hoststate.ReasonPayloadMalformed},
		{"seq 0", w.resigned(t, v0, func(m map[string]any) { m["seq"] = 0 }), hoststate.ReasonPayloadMalformed},
		{"seq строкой", w.resigned(t, v0, func(m map[string]any) { m["seq"] = "5" }), hoststate.ReasonPayloadMalformed},
		{"hostId не uuid", w.resigned(t, v0, func(m map[string]any) { m["hostId"] = "host-1" }), hoststate.ReasonPayloadMalformed},
		{"issuedAt не UTC", w.resigned(t, v0, func(m map[string]any) { m["issuedAt"] = "2026-09-17T14:59:00+03:00" }), hoststate.ReasonPayloadMalformed},
		{"state не объект", w.resigned(t, v0, func(m map[string]any) { body(m)["state"] = nil }), hoststate.ReasonPayloadMalformed},
		{"secrets не по порядку", w.resigned(t, v0, func(m map[string]any) {
			s := body(m)["secrets"].([]any)
			s[0], s[1] = s[1], s[0]
		}), hoststate.ReasonPayloadMalformed},
		{"повтор в secrets", w.resigned(t, v0, func(m map[string]any) {
			body(m)["secrets"] = []string{"app/backend/gitKey", "app/backend/gitKey"}
		}), hoststate.ReasonPayloadMalformed},
		{"неизвестная ссылка", w.resigned(t, v0, func(m map[string]any) {
			body(m)["secrets"] = []string{"app/backend/env/DB_PASSWORD", "host/rootPassword"}
		}), hoststate.ReasonPayloadMalformed},
		{"старый seq", w.resigned(t, v0, func(m map[string]any) { m["seq"] = 3 }), hoststate.ReasonSeqRollback},
		{"тот же seq, другие байты", w.resigned(t, v0, func(m map[string]any) { m["seq"] = 4 }), hoststate.ReasonSeqRollback},
	}
	for _, c := range cases {
		res := w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, c.env, cert), Secrets: w.secretValues()})
		expectRefused(t, c.name, res, c.want, prev)
	}
}

// Ссылка, которой не на что указать, — подписанная, но несобираемая нагрузка:
// применить её частично нельзя.
func TestVerifyRefWithoutTarget(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	// SignState такую ссылку не подпишет, поэтому нагрузка собрана вручную.
	env := w.resigned(t, hoststate.PayloadTypeHostStateV0, func(m map[string]any) {
		m["body"].(map[string]any)["secrets"] = []string{"app/frontend/gitToken"}
	})
	res := w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, env, w.cert(t)), Secrets: map[string]string{"app/frontend/gitToken": "x"}})
	expectRefused(t, "ссылка на несуществующее приложение", res, hoststate.ReasonPayloadMalformed, prev)
}
