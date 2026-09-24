package hoststate_test

import (
	"crypto/ed25519"
	"reflect"
	"strings"
	"testing"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
	"tracedocs.ru/deploy-agent/pkg/signenv"
)

// Грант подписывает только корень: рабочий ключ живёт на подписанте, и
// послабление его подписью значило бы, что взломанный подписант сам себе
// расширяет политику.
func TestVerifyRefusesGrantNotFromRoot(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	for name, signer := range map[string]ed25519.PrivateKey{"рабочий ключ": w.work, "чужой ключ": w.foreign} {
		bundle := w.bundleWithGrants(t, w.signedGrant(t, signer, nil))
		expectRefused(t, name, w.verifier().Verify(prev, hoststate.Input{Bundle: bundle, Secrets: w.secretValues()}), hoststate.ReasonGrantInvalid, prev)
	}
}

// Словарь послаблений закрыт в коде: незнакомый вид — ошибка гранта, а не
// «неизвестно, значит можно». Негодный грант отвергает пакет целиком.
func TestVerifyRefusesGrantUnknownKind(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	cases := map[string]func(map[string]any){
		"вид cap_add": func(g map[string]any) {
			g["allowances"] = []map[string]any{{"kind": "cap_add", "service": "smtp", "port": 25, "protocol": "tcp"}}
		},
		"порт 0": func(g map[string]any) {
			g["allowances"] = []map[string]any{{"kind": "publish_port", "service": "smtp", "port": 0, "protocol": "tcp"}}
		},
		"протокол sctp": func(g map[string]any) {
			g["allowances"] = []map[string]any{{"kind": "publish_port", "service": "smtp", "port": 25, "protocol": "sctp"}}
		},
		"лишнее поле послабления": func(g map[string]any) {
			g["allowances"] = []map[string]any{{"kind": "publish_port", "service": "smtp", "port": 25, "protocol": "tcp", "hostIp": "0.0.0.0"}}
		},
	}
	for name, mutate := range cases {
		bundle := w.bundleWithGrants(t, w.grant(t), w.signedGrant(t, nil, mutate))
		expectRefused(t, name, w.verifier().Verify(prev, hoststate.Input{Bundle: bundle, Secrets: w.secretValues()}), hoststate.ReasonGrantInvalid, prev)
	}
}

func TestVerifyRefusesGrantBadDigest(t *testing.T) {
	w := newWorld()
	prev := w.latch(t)
	for _, digest := range []string{"", "abc", strings.ToUpper(composeSHA(mailCompose)), composeSHA(mailCompose) + "00", strings.Repeat("g", 64)} {
		g := w.signedGrant(t, nil, func(g map[string]any) { g["composeSha256"] = digest })
		bundle := w.bundleWithGrants(t, g)
		expectRefused(t, "digest "+digest, w.verifier().Verify(prev, hoststate.Input{Bundle: bundle, Secrets: w.secretValues()}), hoststate.ReasonGrantInvalid, prev)
	}
}

// Послабление привязано к digest точных байтов compose; агент берёт его по
// sha256 compose приложения, и чужой compose гранта не получает.
func TestVerifyMapsGrantByComposeSha(t *testing.T) {
	w := newWorld()
	other := composeSHA("name: other\n")
	otherAllowances := []composeguard.Allowance{{Kind: composeguard.AllowPublishPort, Service: "turn", Port: 3478, Protocol: "udp"}}
	otherGrant, err := hoststate.IssueGrant(w.root2, other, otherAllowances, "")
	if err != nil {
		t.Fatal(err)
	}
	res := w.verifier().Verify(w.latch(t), hoststate.Input{Bundle: w.bundleWithGrants(t, w.grant(t), otherGrant), Secrets: w.secretValues()})
	expectAccepted(t, "пакет с грантами", res)
	want := map[string][]composeguard.Allowance{composeSHA(mailCompose): mailAllowances(), other: otherAllowances}
	if !reflect.DeepEqual(res.AllowancesByCompose, want) {
		t.Fatalf("послабления по digest: %+v", res.AllowancesByCompose)
	}
	if _, ok := res.AllowancesByCompose[composeSHA(mailCompose+" ")]; ok {
		t.Fatal("послабление нашлось по другим байтам compose")
	}
}

// Выпущенный грант проходит проверку корнями, и нагрузка его — ровно
// {v, composeSha256, allowances, notes}.
func TestIssueGrantRoundTrip(t *testing.T) {
	w := newWorld()
	env := w.grant(t)
	want := `{"v":1,"composeSha256":"` + composeSHA(mailCompose) +
		`","allowances":[{"kind":"publish_port","service":"smtp","port":25,"protocol":"tcp"}],"notes":"шаблон почты: SMTP на 25/tcp"}`
	if got := string(payloadOf(t, env)); got != want {
		t.Fatalf("нагрузка гранта:\n got %s\nwant %s", got, want)
	}
	g, err := hoststate.VerifyGrant(envelopeJSON(t, env), w.verifier().Roots)
	if err != nil {
		t.Fatal(err)
	}
	if g.V != 1 || g.ComposeSHA256 != composeSHA(mailCompose) || !reflect.DeepEqual(g.Allowances, mailAllowances()) {
		t.Fatalf("грант: %+v", g)
	}

	refused := map[string]func() error{
		"плохой digest": func() error {
			_, err := hoststate.IssueGrant(w.root, "abc", mailAllowances(), "")
			return err
		},
		"без послаблений": func() error {
			_, err := hoststate.IssueGrant(w.root, composeSHA(mailCompose), nil, "")
			return err
		},
		"незнакомый вид": func() error {
			_, err := hoststate.IssueGrant(w.root, composeSHA(mailCompose), []composeguard.Allowance{{Kind: "cap_add", Service: "smtp", Port: 25, Protocol: "tcp"}}, "")
			return err
		},
	}
	for name, run := range refused {
		if run() == nil {
			t.Errorf("%s: выпущено", name)
		}
	}
}

func TestVerifyGrantIsStrict(t *testing.T) {
	w := newWorld()
	roots := w.verifier().Roots
	good := envelopeJSON(t, w.grant(t))
	cases := map[string][]byte{
		"версия 2":           envelopeJSON(t, w.signedGrant(t, nil, func(g map[string]any) { g["v"] = 2 })),
		"лишнее поле":        envelopeJSON(t, w.signedGrant(t, nil, func(g map[string]any) { g["expiresAt"] = "2026-10-01T00:00:00Z" })),
		"пустые послабления": envelopeJSON(t, w.signedGrant(t, nil, func(g map[string]any) { g["allowances"] = []any{} })),
		"нет послаблений":    envelopeJSON(t, w.signedGrant(t, nil, func(g map[string]any) { delete(g, "allowances") })),
		"данные после JSON": envelopeJSON(t, signenv.Sign(w.root, hoststate.PayloadTypeGrant,
			append(payloadOf(t, w.grant(t)), []byte(` {}`)...))),
		"не конверт": []byte(`{"v":1}`),
	}
	for name, raw := range cases {
		if _, err := hoststate.VerifyGrant(raw, roots); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
	if _, err := hoststate.VerifyGrant(good, roots); err != nil {
		t.Fatalf("годный грант отвергнут: %v", err)
	}
	if _, err := hoststate.VerifyGrant(good, nil); err == nil {
		t.Fatal("грант принят без корней")
	}
}

// Корень подписывает два вида документов — сертификаты и гранты, — поэтому тип
// обязан входить в подписанные байты (PAE). Иначе документ одного вида,
// честно подписанный корнем, выдаётся за другой сменой одного поля конверта.
//
// Чтобы подмена была честной, нагрузка годится для того вида, за который её
// выдают: байты гранта, подписанные корнем с типом сертификата, выдаются за
// грант, и наоборот. Без PAE подпись после смены payloadType осталась бы
// верной, и документ прошёл бы.
func TestPayloadTypeBindsDocumentKind(t *testing.T) {
	w := newWorld()
	roots := w.verifier().Roots
	prev := w.latch(t)
	grantBytes := payloadOf(t, w.grant(t))
	certBytes := payloadOf(t, w.cert(t))

	// Сертификат, выданный за грант.
	asGrant := signenv.Sign(w.root, hoststate.PayloadTypeCert, grantBytes)
	asGrant.PayloadType = hoststate.PayloadTypeGrant
	if _, err := hoststate.VerifyGrant(envelopeJSON(t, asGrant), roots); err == nil {
		t.Fatal("подпись сертификата прошла как подпись гранта")
	}
	expectRefused(t, "сертификат, выданный за грант, в пакете",
		w.verifier().Verify(prev, hoststate.Input{Bundle: w.bundleWithGrants(t, asGrant), Secrets: w.secretValues()}),
		hoststate.ReasonGrantInvalid, prev)

	// Грант, выданный за сертификат.
	asCert := signenv.Sign(w.root, hoststate.PayloadTypeGrant, certBytes)
	asCert.PayloadType = hoststate.PayloadTypeCert
	if _, _, err := hoststate.VerifyCertificate(envelopeJSON(t, asCert), roots, w.now); err == nil {
		t.Fatal("подпись гранта прошла как подпись сертификата")
	}
	state := w.signState(t, w.hostState(5))
	expectRefused(t, "грант, выданный за сертификат, в пакете",
		w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, asCert), Secrets: w.secretValues()}),
		hoststate.ReasonCertNotFromRoot, prev)

	// Контроль: те же байты под своим типом проходят — отказ выше дала именно
	// подмена типа, а не содержимое.
	if _, err := hoststate.VerifyGrant(envelopeJSON(t, signenv.Sign(w.root, hoststate.PayloadTypeGrant, grantBytes)), roots); err != nil {
		t.Fatalf("контроль гранта: %v", err)
	}
	if _, _, err := hoststate.VerifyCertificate(envelopeJSON(t, signenv.Sign(w.root, hoststate.PayloadTypeCert, certBytes)), roots, w.now); err != nil {
		t.Fatalf("контроль сертификата: %v", err)
	}

	// Без подмены типа документ не на своём месте отвергается по типу.
	if _, err := hoststate.VerifyGrant(envelopeJSON(t, w.cert(t)), roots); err == nil {
		t.Fatal("сертификат принят как грант")
	}
	expectRefused(t, "грант на месте сертификата",
		w.verifier().Verify(prev, hoststate.Input{Bundle: bundleJSON(t, state, w.grant(t)), Secrets: w.secretValues()}),
		hoststate.ReasonCertInvalid, prev)
}
