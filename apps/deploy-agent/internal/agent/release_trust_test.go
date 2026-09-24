package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func withKeys(t *testing.T, keys ...ed25519.PublicKey) {
	t.Helper()
	prev := trustedKeysRaw
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, base64.StdEncoding.EncodeToString(k))
	}
	trustedKeysRaw = join(parts, ",")
	t.Cleanup(func() { trustedKeysRaw = prev })
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

func TestSignatureAcceptedByTrustedKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	withKeys(t, pub)

	msg := ReleaseBinaryMessage("2.1.0", "ABC123", "amd64")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	if err := VerifyReleaseSignature(msg, sig); err != nil {
		t.Fatalf("своя подпись отклонена: %v", err)
	}
}

// Ровно то, ради чего подпись и нужна: платформа, которой завладели, отдаёт
// свой бинарь и свою сумму — но подписать чужим ключом не может.
func TestSignatureFromForeignKeyRefused(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
	withKeys(t, pub)

	msg := ReleaseBinaryMessage("2.1.0", "ABC123", "amd64")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(foreignPriv, msg))
	if err := VerifyReleaseSignature(msg, sig); err == nil {
		t.Fatal("подпись чужим ключом принята")
	}
}

func TestSignatureOverOtherVersionRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	withKeys(t, pub)

	// Подпись СТАРОЙ версии не годится для новой и наоборот: версия входит в
	// сообщение, иначе подпись старого бинаря разрешала бы откат.
	signed := ReleaseBinaryMessage("2.0.0", "ABC123", "amd64")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signed))

	other := ReleaseBinaryMessage("2.1.0", "ABC123", "amd64")
	if err := VerifyReleaseSignature(other, sig); err == nil {
		t.Fatal("подпись другой версии принята")
	}
}

func TestTwoKeysLiveTogether(t *testing.T) {
	// Смена ключа переживается только так: обе подписи принимаются, пока старый
	// ключ не снимут следующей версией.
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	withKeys(t, oldPub, newPub)

	msg := ReleaseBinaryMessage("2.1.0", "ABC123", "amd64")
	for name, priv := range map[string]ed25519.PrivateKey{"старый": oldPriv, "новый": newPriv} {
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
		if err := VerifyReleaseSignature(msg, sig); err != nil {
			t.Fatalf("%s ключ отклонён: %v", name, err)
		}
	}
}

// Состояние на сегодня: ключ ещё не выпущен. Агент работает как раньше — иначе
// накат сломал бы всех работающих агентов в день, когда подписывать нечем.
func TestNoKeysMeansNoCheck(t *testing.T) {
	withKeys(t)
	if ReleaseSignatureRequired() {
		t.Fatal("без ключей проверка объявлена обязательной")
	}
	if err := VerifyReleaseSignature([]byte("что угодно"), ""); err != nil {
		t.Fatalf("без ключей проверка отказала: %v", err)
	}
}

// Битый ключ в сборке — ошибка выпуска, и самообновление отказывает целиком.
// Молчаливый пропуск значил бы работу на оставшихся ключах так, будто сборка
// исправна, а при единственном битом — вовсе без проверки подписи.
func TestBrokenKeyInBuildRefusesVerification(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good := base64.StdEncoding.EncodeToString(pub)
	msg := ReleaseBinaryMessage("2.3.0", "ABC123", "amd64")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	prev := trustedKeysRaw
	t.Cleanup(func() { trustedKeysRaw = prev })

	for name, raw := range map[string]string{
		"годный и не base64":   good + ",не-base64",
		"годный и не 32 байта": good + ",AAAA",
		"только битый":         "AAAA",
	} {
		t.Run(name, func(t *testing.T) {
			trustedKeysRaw = raw
			if !ReleaseSignatureRequired() {
				t.Fatal("при битом ключе проверка подписи объявлена ненужной")
			}
			if ReleaseKeysError() == nil {
				t.Fatal("битый ключ не опознан")
			}
			if err := VerifyReleaseSignature(msg, sig); err == nil || !strings.Contains(err.Error(), "испорчены") {
				t.Fatalf("подпись годным ключом принята при битом соседе: %v", err)
			}
		})
	}

	// Пустые элементы списка — не ключи и не порча.
	trustedKeysRaw = good + ",,"
	if err := ReleaseKeysError(); err != nil {
		t.Fatalf("пустой элемент списка принят за битый ключ: %v", err)
	}
	if err := VerifyReleaseSignature(msg, sig); err != nil {
		t.Fatalf("своя подпись отклонена: %v", err)
	}
}

// Отпечаток — первые 16 hex sha256 сырых 32 байт ключа: его печатает
// `version --trust`, и его же владелец сверяет с опубликованным.
func TestKeyFingerprint(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sum := sha256.Sum256(pub)
	if got, want := KeyFingerprint(pub), hex.EncodeToString(sum[:])[:16]; got != want {
		t.Fatalf("отпечаток %q, ожидался %q", got, want)
	}
}

// Доклад доверия: массивы — всегда массивы, иначе платформа не отличит «ключей
// нет» от «поле не прислали».
func TestTrustReportShape(t *testing.T) {
	withKeys(t)
	raw, err := json.Marshal(NewTrustReport(""))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"releaseKeys":[],"stateRoots":[],"proxyVersion":""}` {
		t.Fatalf("доклад доверия без ключей: %s", raw)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	withKeys(t, pub)
	report := NewTrustReport("2.1.0")
	if len(report.ReleaseKeys) != 1 || report.ReleaseKeys[0] != KeyFingerprint(pub) || report.ProxyVersion != "2.1.0" {
		t.Fatalf("доклад доверия: %+v", report)
	}

	root, _, _ := ed25519.GenerateKey(rand.Reader)
	restore := SetTrustedStateRootsForTest(base64.StdEncoding.EncodeToString(root))
	defer restore()
	report = NewTrustReport("")
	if len(report.StateRoots) != 1 || report.StateRoots[0] != KeyFingerprint(root) {
		t.Fatalf("доклад доверия с корнем состояния: %+v", report)
	}
}
