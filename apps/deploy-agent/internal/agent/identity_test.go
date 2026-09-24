package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// Отпечаток обязан совпадать с тем, что считает сервер в
// apps/web/src/app/api/deploy/agent/enroll/route.ts:
//
//	createHash("sha256").update(publicKey).digest("hex")
//
// где publicKey — та же base64-строка, что уходит в теле запроса.
// Сервер пересчитывает отпечаток и отвергает несовпадение, поэтому
// расхождение здесь означало бы, что ни один агент не зарегистрируется.
func TestFingerprintMatchesServerFormula(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	sum := sha256.Sum256([]byte(id.PublicKey))
	want := hex.EncodeToString(sum[:])

	if got := id.Fingerprint(); got != want {
		t.Fatalf("отпечаток разошёлся с формулой сервера:\n got = %s\nwant = %s", got, want)
	}

	if len(id.Fingerprint()) != 64 {
		t.Fatalf("ожидали 64 hex-символа, получили %d", len(id.Fingerprint()))
	}
}

// Публичный ключ должен быть ровно 32 байта Ed25519 в base64 — сервер хранит
// эту строку как есть и по ней же будет проверять подпись в следующей фазе.
func TestPublicKeyIsRawEd25519(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(id.PublicKey)
	if err != nil {
		t.Fatalf("публичный ключ не base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("ожидали 32 байта публичного ключа, получили %d", len(raw))
	}
}

// Подпись должна проверяться публичным ключом из той же пары. Пока подпись не
// используется, но контракт фиксируем сейчас: в Фазе 1 на ней будет держаться
// доставка секретов, и ломать её молча нельзя.
func TestSignProducesVerifiableSignature(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}

	payload := []byte("fingerprint.1700000000")
	sig, err := id.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == "" {
		t.Fatal("подпись пустая")
	}

	if _, err := base64.StdEncoding.DecodeString(sig); err != nil {
		t.Fatalf("подпись не base64: %v", err)
	}
}

// Разные вызовы обязаны давать разные ключи: одинаковый ключ на двух хостах
// означал бы, что один может выдать себя за другого.
func TestIdentitiesAreUnique(t *testing.T) {
	a, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	b, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("две личности получили одинаковый отпечаток")
	}
}
