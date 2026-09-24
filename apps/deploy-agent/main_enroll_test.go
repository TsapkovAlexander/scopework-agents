package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Отложенный ключ переиспользуется ТОЛЬКО той же попыткой.
//
// Он существует ради одного случая: ответ на регистрацию потерялся, и повтор
// тем же токеном должен доехать. Без привязки он переживал и другой сценарий:
// попытка провалилась, человек удалил хост, создал новый и взял новую команду —
// а агент повторял со старым ключом и получал «отпечаток уже занят» при
// исправном токене, без единой подсказки, что лечится это удалением файла.
func TestPendingIdentityBoundToAttempt(t *testing.T) {
	dir := t.TempDir()
	const url = "https://scopework.ru"

	first, reused, err := loadOrCreateIdentity(dir, enrollBinding("tdx_one", url))
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Fatal("первая попытка считает ключ переиспользованным")
	}

	// Тот же токен — тот же ключ: ради этого всё и сделано.
	again, reused, err := loadOrCreateIdentity(dir, enrollBinding("tdx_one", url))
	if err != nil {
		t.Fatal(err)
	}
	if !reused || again.PublicKey != first.PublicKey {
		t.Fatalf("повтор тем же токеном не переиспользовал ключ (reused=%v)", reused)
	}

	// Другой токен — новый ключ.
	other, reused, err := loadOrCreateIdentity(dir, enrollBinding("tdx_two", url))
	if err != nil {
		t.Fatal(err)
	}
	if reused || other.PublicKey == first.PublicKey {
		t.Fatalf("другой токен переиспользовал прежний ключ (reused=%v)", reused)
	}

	// Другой адрес платформы — тоже другая попытка.
	elsewhere, reused, err := loadOrCreateIdentity(dir, enrollBinding("tdx_two", "https://other.example"))
	if err != nil {
		t.Fatal(err)
	}
	if reused || elsewhere.PublicKey == other.PublicKey {
		t.Fatalf("смена адреса платформы переиспользовала ключ (reused=%v)", reused)
	}

	// Приватный ключ на диске лежит доступным только root.
	info, err := os.Stat(filepath.Join(dir, "identity.pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("права отложенного ключа %v, ожидались 0600", info.Mode().Perm())
	}
}
