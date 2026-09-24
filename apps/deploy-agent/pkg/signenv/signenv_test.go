package signenv

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func seedKey(first byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = first + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func marshal(t *testing.T, e Envelope) []byte {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Формат PAE — из спецификации DSSE; длины в байтах, а не в символах: тип с
// кириллицей обязан давать длину UTF-8, иначе TS и Go разойдутся на первом же
// не-ASCII.
func TestPAEMatchesSpec(t *testing.T) {
	got := PAE("application/example", []byte("hello world"))
	want := "DSSEv1 19 application/example 11 hello world"
	if string(got) != want {
		t.Fatalf("PAE = %q, ожидалось %q", got, want)
	}
	if got := PAE("тип", []byte{}); string(got) != "DSSEv1 6 тип 0 " {
		t.Fatalf("длина типа посчитана не в байтах: %q", got)
	}
}

func TestKeyIDIsSHA256OfRawPublicKey(t *testing.T) {
	pub := seedKey(0x21).Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	if got := KeyID(pub); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("keyid = %s", got)
	}
}

func TestSignParseVerifyRoundTrip(t *testing.T) {
	priv := seedKey(0x41)
	payload := []byte(`{"a":1}`)
	raw := marshal(t, Sign(priv, "t/x", payload))

	p, err := Parse(raw)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if p.PayloadType != "t/x" || !bytes.Equal(p.Payload, payload) {
		t.Fatalf("разобрано не то: %+v", p)
	}
	if !p.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("своя подпись не проверилась")
	}
	if p.Verify(seedKey(0x61).Public().(ed25519.PublicKey)) {
		t.Fatal("подпись проверилась чужим ключом")
	}
}

// Подпись над байтами, а не над смыслом: тот же JSON с другим пробелом — это
// другие байты, и подпись обязана не пройти.
func TestVerifyRejectsReserializedPayload(t *testing.T) {
	priv := seedKey(0x41)
	env := Sign(priv, "t/x", []byte(`{"a": 1}`))
	env.Payload = base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))
	p, err := Parse(marshal(t, env))
	if err != nil {
		t.Fatal(err)
	}
	if p.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("подпись прошла над пересериализованной нагрузкой")
	}
}

func TestVerifyRejectsFlippedByte(t *testing.T) {
	priv := seedKey(0x41)
	payload := []byte(`{"seq":5}`)
	env := Sign(priv, "t/x", payload)
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-2] = '6'
	env.Payload = base64.StdEncoding.EncodeToString(tampered)
	p, err := Parse(marshal(t, env))
	if err != nil {
		t.Fatal(err)
	}
	if p.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("подменённый байт не замечен")
	}
}

// Тип входит в PAE: подпись сертификата не должна проходить как подпись
// состояния с теми же байтами.
func TestVerifyBindsPayloadType(t *testing.T) {
	priv := seedKey(0x41)
	env := Sign(priv, "t/cert", []byte(`{}`))
	env.PayloadType = "t/state"
	p, err := Parse(marshal(t, env))
	if err != nil {
		t.Fatal(err)
	}
	if p.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("подпись перенеслась на другой тип")
	}
}

// keyid чужого ключа при верной подписи — тоже отказ: по keyid агент выбирает
// ключ, и расхождение означает, что конверт собран не тем, кем назван.
func TestVerifyRequiresMatchingKeyID(t *testing.T) {
	priv := seedKey(0x41)
	env := Sign(priv, "t/x", []byte(`{}`))
	env.Signatures[0].KeyID = KeyID(seedKey(0x61).Public().(ed25519.PublicKey))
	p, err := Parse(marshal(t, env))
	if err != nil {
		t.Fatal(err)
	}
	if p.Verify(priv.Public().(ed25519.PublicKey)) {
		t.Fatal("подпись прошла с чужим keyid")
	}
}

func TestParseIsStrict(t *testing.T) {
	priv := seedKey(0x41)
	good := Sign(priv, "t/x", []byte(`{}`))
	two := good
	two.Signatures = append([]Signature{}, good.Signatures[0], good.Signatures[0])
	none := good
	none.Signatures = []Signature{}

	cases := map[string]string{
		"две подписи":        string(marshal(t, two)),
		"ни одной подписи":   string(marshal(t, none)),
		"не JSON":            `nope`,
		"null":               `null`,
		"лишнее поле":        strings.Replace(string(marshal(t, good)), `{"payloadType"`, `{"x":1,"payloadType"`, 1),
		"лишнее в подписи":   strings.Replace(string(marshal(t, good)), `{"keyid"`, `{"x":1,"keyid"`, 1),
		"данные после JSON":  string(marshal(t, good)) + `{}`,
		"payload не base64":  strings.Replace(string(marshal(t, good)), `"payload":"`, `"payload":"!`, 1),
		"sig не base64":      strings.Replace(string(marshal(t, good)), `"sig":"`, `"sig":"!`, 1),
		"пустой тип":         strings.Replace(string(marshal(t, good)), `"payloadType":"t/x"`, `"payloadType":""`, 1),
		"keyid не hex":       strings.Replace(string(marshal(t, good)), `"keyid":"`, `"keyid":"Z`, 1),
		"подпись не 64 байт": strings.Replace(string(marshal(t, good)), good.Signatures[0].Sig, "AAAA", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if _, err := Parse(marshal(t, good)); err != nil {
		t.Fatalf("правильный конверт отвергнут: %v", err)
	}
}

func TestDecodeStrict(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	if err := DecodeStrict([]byte(`{"a":1}`), &v); err != nil || v.A != 1 {
		t.Fatalf("обычный JSON: %v", err)
	}
	for _, raw := range []string{`{"a":1,"b":2}`, `{"a":1} {}`, `{"a":1}x`, `{"a":"1"}`} {
		if err := DecodeStrict([]byte(raw), &v); err == nil {
			t.Errorf("%s: принято", raw)
		}
	}
}
