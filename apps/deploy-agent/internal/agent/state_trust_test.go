package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// testSeedKey — ключ Ed25519 из метки: ни ключей, ни seed литералами в файле
// нет, и гейт секретов по истории репозитория им не спотыкается.
func testSeedKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("deploy-agent/state-trust-test/" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func testPubB64(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

func TestStateRootsEmptyMeansNone(t *testing.T) {
	roots, err := parseStateRoots("")
	if err != nil || roots != nil {
		t.Fatalf("пустое значение: корни %v, ошибка %v — ожидалось «корней нет»", roots, err)
	}

	restore := SetTrustedStateRootsForTest("")
	defer restore()
	if got := TrustedStateRoots(); got != nil {
		t.Fatalf("TrustedStateRoots без корней = %v, ожидался nil", got)
	}
	roots, invalid := StateRootsStatus()
	if roots != nil || invalid != nil {
		t.Fatalf("статус без корней: %v, %v", roots, invalid)
	}
}

// Битый ключ не пропускается, как в release_trust.go, а роняет весь список:
// ошибка сборки не должна тихо стать «проверок нет» или «проверяем меньшим
// набором, чем задумано» (ADR-0093, решение 2).
func TestStateRootsOneBadFailsAll(t *testing.T) {
	good := testPubB64(testSeedKey("root-a"))
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	cases := map[string]string{
		"не base64":           good + ",not-base64!",
		"не 32 байта":         good + "," + short,
		"пустой элемент":      good + ",",
		"пустой в середине":   good + ",," + good,
		"пробел вокруг ключа": good + ", " + good,
		"только запятая":      ",",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			roots, err := parseStateRoots(raw)
			if err == nil {
				t.Fatalf("значение %q принято: %d корней", raw, len(roots))
			}
			if roots != nil {
				t.Fatalf("при ошибке вернулись корни: %v", roots)
			}

			restore := SetTrustedStateRootsForTest(raw)
			defer restore()
			if got := TrustedStateRoots(); got != nil {
				t.Fatalf("TrustedStateRoots при битом значении = %v, ожидался nil", got)
			}
			got, invalid := StateRootsStatus()
			if got != nil || invalid == nil {
				t.Fatalf("статус битых корней: %v, %v", got, invalid)
			}
		})
	}
}

func TestStateRootsParsesTwo(t *testing.T) {
	a, b := testSeedKey("root-a"), testSeedKey("root-b")
	raw := testPubB64(b) + "," + testPubB64(a)

	roots, err := parseStateRoots(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 {
		t.Fatalf("корней %d, ожидалось 2", len(roots))
	}
	if !roots[0].Equal(b.Public()) || !roots[1].Equal(a.Public()) {
		t.Fatal("корни разобраны не те")
	}

	restore := SetTrustedStateRootsForTest(raw)
	if len(TrustedStateRoots()) != 2 {
		t.Fatal("TrustedStateRoots не видит подставленные корни")
	}
	restore()
	if trustedStateRootsRaw != "" {
		t.Fatalf("restore не вернул значение сборки: %q", trustedStateRootsRaw)
	}
}

// Файлы корней кладёт штаб К и склеивает их при сборке по имени через
// запятую. Здесь проверяется, что то, что он склеит, агент разберёт.
func TestStateRootsBuildFiles(t *testing.T) {
	dir := filepath.Join("..", "..", "trust", "state")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("каталог корней не создан, формат не проверен")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		// Каталог со своим README заводит сборка, а корни кладёт человек после
		// церемонии ADR-0082: до неё проверять нечего.
		t.Skipf("в %s ещё нет ни одного .pub, формат не проверен", dir)
	}
	sort.Strings(files)
	parts := make([]string, 0, len(files))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// Перевод строки в конце файла допустим — сборка его срезает.
		one := string(bytes.TrimRight(raw, "\r\n"))
		if _, err := parseStateRoots(one); err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
		}
		parts = append(parts, one)
	}
	roots, err := parseStateRoots(strings.Join(parts, ","))
	if err != nil {
		t.Fatalf("склейка файлов не разбирается: %v", err)
	}
	if len(roots) != len(files) {
		t.Fatalf("корней %d при файлах %d", len(roots), len(files))
	}
}
