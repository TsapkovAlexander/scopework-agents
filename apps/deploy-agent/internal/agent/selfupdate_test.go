package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Самообновление агента. Ошибка здесь стоит дорого в обе стороны: не
// обновившийся агент молча игнорирует новые возможности (боевой случай —
// защита домена паролем «включилась», а домен остался открытым), а
// обновившийся на битый бинарь кладёт весь хост без удалённого доступа.

// Версии здесь настоящие (MAJOR.MINOR.PATCH), а не метки «abc»/«def»: с
// 18.09.2026 форма версии значима — откат запрещён, и нечитаемая метка сама по
// себе означает «не обновляться» (задача С1.3).
func TestShouldSelfUpdate(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name    string
		current string
		target  string
		sha     string
		marker  *updateMarker
		want    bool
	}{
		{"версии совпадают — обновляться не на что", "2.0.0", "2.0.0", "d0c0ffee", nil, false},
		{"цель пуста — платформа собрана без версии", "2.0.0", "", "d0c0ffee", nil, false},
		{"цель без суммы — проверять нечем, не обновляемся", "2.0.0", "2.1.0", "", nil, false},
		{"版本 отличается и сумма есть — обновляемся", "2.0.0", "2.1.0", "d0c0ffee", nil, true},
		{
			// Экран от бесконечного exec-цикла: если после подмены бинаря
			// версия так и не совпала с целью (кривая сборка платформы —
			// сумма от одного бинаря, ldflags от другого), вторая попытка на
			// ту же цель раньше чем через час запрещена.
			"недавняя неудачная попытка на ту же цель — пропуск",
			"2.0.0", "2.1.0", "d0c0ffee",
			&updateMarker{Target: "2.1.0", At: now.Add(-10 * time.Minute)},
			false,
		},
		{
			"старая попытка на ту же цель — можно снова",
			"2.0.0", "2.1.0", "d0c0ffee",
			&updateMarker{Target: "2.1.0", At: now.Add(-2 * time.Hour)},
			true,
		},
		{
			"попытка была на другую цель — не мешает",
			"2.0.0", "2.1.0", "d0c0ffee",
			&updateMarker{Target: "old", At: now.Add(-time.Minute)},
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSelfUpdate(tc.current, tc.target, tc.sha, tc.marker, now)
			if got != tc.want {
				t.Fatalf("shouldSelfUpdate = %v, ожидалось %v", got, tc.want)
			}
		})
	}
}

func TestVerifyAgentBinary(t *testing.T) {
	dir := t.TempDir()

	// Валидный «бинарь»: ELF-магия и совпадающая сумма.
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("payload")...)
	sum := sha256.Sum256(elf)
	path := filepath.Join(dir, "candidate")
	if err := os.WriteFile(path, elf, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := verifyAgentBinary(path, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("валидный бинарь отвергнут: %v", err)
	}

	// Чужая сумма — отказ: бинарь мог подменить любой, кто контролирует сеть
	// до платформы; сумма приезжает в подписанном TLS-ответе heartbeat.
	if err := verifyAgentBinary(path, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("бинарь с чужой суммой принят")
	}

	// Не-ELF (например, HTML-страница ошибки от прокси) — отказ до всякой
	// суммы: заменить агента страницей 502 значит убить хост.
	html := []byte("<html>502 Bad Gateway</html>")
	htmlSum := sha256.Sum256(html)
	htmlPath := filepath.Join(dir, "error-page")
	if err := os.WriteFile(htmlPath, html, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyAgentBinary(htmlPath, hex.EncodeToString(htmlSum[:])); err == nil {
		t.Fatal("не-ELF принят как бинарь агента")
	}

	// Пустой файл — отказ.
	emptyPath := filepath.Join(dir, "empty")
	if err := os.WriteFile(emptyPath, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	emptySum := sha256.Sum256(nil)
	if err := verifyAgentBinary(emptyPath, hex.EncodeToString(emptySum[:])); err == nil {
		t.Fatal("пустой файл принят как бинарь агента")
	}
}

func TestUpdateMarkerRoundTrip(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}

	if m := readUpdateMarker(p); m != nil {
		t.Fatalf("маркера ещё нет, а прочиталось: %+v", m)
	}

	if err := writeUpdateMarker(p, "target-sha"); err != nil {
		t.Fatal(err)
	}
	m := readUpdateMarker(p)
	if m == nil || m.Target != "target-sha" {
		t.Fatalf("маркер не прочитался: %+v", m)
	}

	// Успешное обновление стирает маркер: версия совпала с целью.
	ClearUpdateMarker(p, "target-sha")
	if m := readUpdateMarker(p); m != nil {
		t.Fatalf("маркер должен быть стёрт, а прочиталось: %+v", m)
	}
}

func TestClearUpdateMarkerKeepsForeignTarget(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}

	if err := writeUpdateMarker(p, "target-a"); err != nil {
		t.Fatal(err)
	}
	// Мы стали версией B, а неудачная попытка была на цель A: маркер обязан
	// пережить старт, иначе защита от цикла на цели A обнулится.
	ClearUpdateMarker(p, "target-b")
	if m := readUpdateMarker(p); m == nil || m.Target != "target-a" {
		t.Fatalf("маркер чужой цели стёрт: %+v", m)
	}
}

func TestReplaceAgentBinaryIsAtomic(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "agent")
	if err := os.WriteFile(current, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}

	elf := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("new-binary")...)
	if err := replaceAgentBinary(current, elf); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(elf) {
		t.Fatalf("бинарь не заменён: %q", got)
	}

	info, err := os.Stat(current)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("права бинаря %v, ожидалось 0755", info.Mode().Perm())
	}

	// Временных файлов после замены не остаётся.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("в каталоге лишние файлы: %v", entries)
	}
}

// Подпись выпуска на всём пути самообновления (ADR-0082, задача С1.3):
// скачивание с платформы, сумма, подпись, подмена файла. Ключ подставляется в
// сборочную переменную тестом, бинарь пишется во временный файл вместо
// собственного.
func TestSelfUpdateReleaseSignature(t *testing.T) {
	pub, own, _ := ed25519.GenerateKey(rand.Reader)
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	withKeys(t, pub)

	content := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("agent 2.3.0")...)
	digest := sha256.Sum256(content)
	sum := hex.EncodeToString(digest[:])
	sign := func(key ed25519.PrivateKey, version string) string {
		return base64.StdEncoding.EncodeToString(ed25519.Sign(key, ReleaseBinaryMessage(version, sum, runtime.GOARCH)))
	}

	cases := []struct {
		name      string
		signature string
		want      bool
	}{
		{"без подписи при вшитом ключе — отказ", "", false},
		{"подписан чужим ключом — отказ", sign(foreign, "2.3.0"), false},
		{"подписан своим для другой версии — отказ", sign(own, "2.2.9"), false},
		{"подписан своим для этой версии — принят", sign(own, "2.3.0"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/deploy/agent-binary" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if tc.signature != "" {
					w.Header().Set("X-Release-Signature", tc.signature)
				}
				_, _ = w.Write(content)
			}))
			defer srv.Close()

			bin := filepath.Join(t.TempDir(), "tracedocs-deploy-agent")
			if err := os.WriteFile(bin, []byte("old"), 0o755); err != nil {
				t.Fatal(err)
			}
			prev := agentExecutable
			agentExecutable = func() (string, error) { return bin, nil }
			t.Cleanup(func() { agentExecutable = prev })

			p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
			hb := HeartbeatResponse{
				TargetAgentVersion: "2.3.0",
				TargetAgentSha256:  AgentSha256ByArch{Amd64: sum, Arm64: sum},
			}
			path, ok := PrepareSelfUpdate(t.Context(), NewClient(srv.URL, "2.2.0"), p, hb, "2.2.0")
			if ok != tc.want {
				t.Fatalf("PrepareSelfUpdate = %v, ожидалось %v", ok, tc.want)
			}
			got, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want {
				if path != bin || string(got) != string(content) {
					t.Fatalf("принятый бинарь не подменён: %q → %q", path, got)
				}
				return
			}
			if string(got) != "old" {
				t.Fatalf("отвергнутый бинарь всё равно встал на место: %q", got)
			}
		})
	}
}

// Один годный ключ и один битый — самообновление отклонено ДО загрузки, бинарь
// не подменён, хотя выпуск подписан годным ключом: сборка с испорченным
// списком ключей — ошибка выпуска, и работать на остатке нельзя.
func TestSelfUpdateRefusedOnBrokenReleaseKey(t *testing.T) {
	pub, own, _ := ed25519.GenerateKey(rand.Reader)
	prevKeys := trustedKeysRaw
	trustedKeysRaw = base64.StdEncoding.EncodeToString(pub) + ",не-base64"
	t.Cleanup(func() { trustedKeysRaw = prevKeys })

	content := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("agent 2.3.0")...)
	digest := sha256.Sum256(content)
	sum := hex.EncodeToString(digest[:])
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(own, ReleaseBinaryMessage("2.3.0", sum, runtime.GOARCH)))

	downloads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads++
		w.Header().Set("X-Release-Signature", signature)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	bin := filepath.Join(t.TempDir(), "tracedocs-deploy-agent")
	if err := os.WriteFile(bin, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	prevExe := agentExecutable
	agentExecutable = func() (string, error) { return bin, nil }
	t.Cleanup(func() { agentExecutable = prevExe })

	hb := HeartbeatResponse{TargetAgentVersion: "2.3.0", TargetAgentSha256: AgentSha256ByArch{Amd64: sum, Arm64: sum}}
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	if _, ok := PrepareSelfUpdate(t.Context(), NewClient(srv.URL, "2.2.0"), p, hb, "2.2.0"); ok {
		t.Fatal("самообновление принято при битом ключе в сборке")
	}
	if got, _ := os.ReadFile(bin); string(got) != "old" {
		t.Fatalf("бинарь подменён: %q", got)
	}
	if downloads != 0 {
		t.Fatalf("загрузок %d — отказ должен быть до загрузки", downloads)
	}
}
