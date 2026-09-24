package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Эталон контракта подписи, общий с TypeScript-стороной.
//
// Go и BFF знают формат подписи раздельно, и разойтись они могут молча:
// сборка пройдёт, тесты каждой стороны пройдут, а в бою агент перестанет
// получать желаемое состояние, потому что сервер отвергнет его подпись.
// Поэтому обе стороны проверяются против одного файла.
//
// Тот же файл проверяет scripts/check-agent-signature-contract.ts.
// Если этот тест упал — контракт изменился, и правку нужно вносить синхронно
// в обе стороны, а не подгонять эталон под новый результат.
type signatureFixture struct {
	PublicKey   string `json:"publicKey"`
	Fingerprint string `json:"fingerprint"`
	Timestamp   string `json:"timestamp"`
	Body        string `json:"body"`
	Signature   string `json:"signature"`
	Method      string `json:"method"`
	Path        string `json:"path"`
}

func loadFixture(t *testing.T) signatureFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "packages", "deploy-core", "fixtures", "agent-signature.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не найден эталон %s: %v", path, err)
	}
	var f signatureFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("эталон повреждён: %v", err)
	}
	return f
}

// Отпечаток обязан считаться из публичного ключа той же формулой, что на сервере.
func TestFixtureFingerprintFormula(t *testing.T) {
	f := loadFixture(t)
	sum := sha256.Sum256([]byte(f.PublicKey))
	if got := hex.EncodeToString(sum[:]); got != f.Fingerprint {
		t.Fatalf("отпечаток разошёлся:\n got = %s\nwant = %s", got, f.Fingerprint)
	}
}

// Подпись из эталона обязана проверяться публичным ключом из эталона.
func TestFixtureSignatureVerifies(t *testing.T) {
	f := loadFixture(t)

	pub, err := base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil {
		t.Fatalf("публичный ключ не base64: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		t.Fatalf("подпись не base64: %v", err)
	}

	bodySum := sha256.Sum256([]byte(f.Body))
	message := f.Method + "." + f.Path + "." + f.Fingerprint + "." +
		f.Timestamp + "." + hex.EncodeToString(bodySum[:])

	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		t.Fatal("подпись эталона не проверяется — контракт разошёлся")
	}
}

// Подменённое тело обязано отвергаться: иначе живая подпись позволяла бы
// подсунуть другую полезную нагрузку.
func TestFixtureRejectsTamperedBody(t *testing.T) {
	f := loadFixture(t)

	pub, _ := base64.StdEncoding.DecodeString(f.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(f.Signature)

	tampered := sha256.Sum256([]byte(f.Body + " "))
	message := f.Method + "." + f.Path + "." + f.Fingerprint + "." +
		f.Timestamp + "." + hex.EncodeToString(tampered[:])

	if ed25519.Verify(ed25519.PublicKey(pub), []byte(message), sig) {
		t.Fatal("подпись принята для подменённого тела")
	}
}
