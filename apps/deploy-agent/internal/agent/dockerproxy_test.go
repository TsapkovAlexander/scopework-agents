package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var proxyRoots = []string{"/opt/tracedocs/deploy"}

func TestDockerProxyOtbivaetPrivilegii(t *testing.T) {
	// Каждый случай — способ получить root на хосте через сокет демона.
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "privileged",
			body: `{"Image":"nginx","HostConfig":{"Privileged":true}}`,
			want: "Privileged",
		},
		{
			name: "корень хоста в томе",
			body: `{"Image":"nginx","HostConfig":{"Binds":["/:/host:rw"]}}`,
			want: "вне рабочих каталогов",
		},
		{
			name: "сокет докера в томе",
			body: `{"Image":"nginx","HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock"]}}`,
			want: "сокет Docker",
		},
		{
			name: "сокет докера через Mounts",
			body: `{"Image":"nginx","HostConfig":{"Mounts":[{"Type":"bind","Source":"/run/docker.sock","Target":"/x"}]}}`,
			want: "сокет Docker",
		},
		{
			name: "cap_add",
			body: `{"Image":"nginx","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
			want: "CapAdd",
		},
		{
			name: "устройство хоста",
			body: `{"Image":"nginx","HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`,
			want: "Devices",
		},
		{
			name: "правила cgroup на устройства",
			body: `{"Image":"nginx","HostConfig":{"DeviceCgroupRules":["b 254:0 rwm"]}}`,
			want: "DeviceCgroupRules",
		},
		{
			name: "pid хоста",
			body: `{"Image":"nginx","HostConfig":{"PidMode":"host"}}`,
			want: "PidMode",
		},
		{
			name: "сеть хоста",
			body: `{"Image":"nginx","HostConfig":{"NetworkMode":"host"}}`,
			want: "NetworkMode",
		},
		{
			name: "вход в чужой контейнер",
			body: `{"Image":"nginx","HostConfig":{"IpcMode":"container:db"}}`,
			want: "чужого контейнера",
		},
		{
			name: "снятие профиля изоляции",
			body: `{"Image":"nginx","HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}`,
			want: "unconfined",
		},
		{
			name: "параметр ядра хоста",
			body: `{"Image":"nginx","HostConfig":{"Sysctls":{"kernel.shm_rmid_forced":"1"}}}`,
			want: "kernel.shm_rmid_forced",
		},
		{
			name: "чужой cgroup",
			body: `{"Image":"nginx","HostConfig":{"CgroupParent":"/"}}`,
			want: "CgroupParent",
		},
		{
			name: "нечитаемое тело",
			body: `не json`,
			want: "не разбирается",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(tc.body), proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил привилегию: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

func TestDockerProxyPuskaetObychnyeStekiIVyzovy(t *testing.T) {
	// Обратная сторона: запрет, отбивающий работу агента, так же бесполезен,
	// как и разрешение. Здесь — то, что агент делает каждый такт.
	allowed := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"опрос демона", "GET", "/_ping", ""},
		{"список контейнеров", "GET", "/v1.44/containers/json", ""},
		{"журнал контейнера", "GET", "/v1.44/containers/app-web-1/logs", ""},
		{"обычный контейнер", "POST", "/v1.44/containers/create",
			`{"Image":"nginx","HostConfig":{"Binds":["app_data:/data"],"NetworkMode":"app_default","RestartPolicy":{"Name":"unless-stopped"}}}`},
		{"том приложения", "POST", "/v1.44/containers/create",
			`{"Image":"nginx","HostConfig":{"Binds":["/opt/tracedocs/deploy/apps/site/data:/data:rw"]}}`},
		{"запуск", "POST", "/v1.44/containers/app-web-1/start", ""},
		{"снятие копии базы", "POST", "/v1.44/containers/app-db-1/exec", `{"Cmd":["pg_dump"],"AttachStdout":true}`},
		{"сборка образа", "POST", "/v1.44/build", ""}, // путь без query: хендлер сверяет r.URL.Path
		{"сессия buildkit", "POST", "/session", ""},
		{"загрузка образа", "POST", "/v1.44/images/create", ""},
		{"сеть compose", "POST", "/v1.44/networks/create", `{"Name":"app_default","Driver":"bridge"}`},
		{"именованный том", "POST", "/v1.44/volumes/create", `{"Name":"app_data","Driver":"local"}`},
		{"удаление контейнера", "DELETE", "/v1.44/containers/app-web-1", ""},
	}

	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy(tc.method, tc.path, []byte(tc.body), proxyRoots)
			if !got.Allowed {
				t.Fatalf("прокси отбил штатную работу агента: %s", got.Reason)
			}
		})
	}
}

func TestDockerProxyOtbivaetVyzovyVneSpiska(t *testing.T) {
	// Белый список: всё, чего в нём нет, отбивается — включая вызовы, которые
	// сегодня выглядят безобидно.
	denied := []struct{ method, path string }{
		{"GET", "/secrets"},
		{"POST", "/swarm/init"},
		{"POST", "/plugins/pull"},
		{"POST", "/containers/app-web-1/update"},
		{"POST", "/commit"},
		{"GET", "/containers/app-web-1/archive"},
		{"PUT", "/containers/app-web-1/archive"},
		{"POST", "/services/create"},
	}
	for _, tc := range denied {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			got := decideDockerProxy(tc.method, tc.path, nil, proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил вызов вне списка: %s %s", tc.method, tc.path)
			}
		})
	}
}

func TestDockerProxyTomSDriverOptsNeOtkryvaetHost(t *testing.T) {
	// Том с драйвером local и опцией device — привязка каталога хоста, которая
	// в compose выглядит обычным именованным томом. Без этой проверки запрет
	// привязок обходился бы одним объявлением тома.
	got := decideDockerProxy("POST", "/v1.44/volumes/create",
		[]byte(`{"Name":"sneaky","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/"}}`), proxyRoots)
	if got.Allowed {
		t.Fatal("прокси пропустил том, смонтированный из корня хоста")
	}

	ok := decideDockerProxy("POST", "/v1.44/volumes/create",
		[]byte(`{"Name":"data","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/opt/tracedocs/deploy/apps/site/data"}}`), proxyRoots)
	if !ok.Allowed {
		t.Fatalf("прокси отбил том внутри каталога агента: %s", ok.Reason)
	}
}

func TestDockerProxyPrivilegirovannyjExecOtbit(t *testing.T) {
	got := decideDockerProxy("POST", "/v1.44/containers/app-db-1/exec",
		[]byte(`{"Cmd":["sh"],"Privileged":true}`), proxyRoots)
	if got.Allowed {
		t.Fatal("прокси пропустил привилегированный exec")
	}
}

// TestDockerProxySkvoznoj — прокси целиком: настоящий сокет, настоящий HTTP.
//
// Проверка по единицам решений не поймала бы ошибку в связке: что тело дошло
// до демона нетронутым, что отказ возвращается кодом 403, а не молча, что
// ответ демона доезжает до клиента.
func TestDockerProxySkvoznoj(t *testing.T) {
	dir := t.TempDir()
	upstreamPath := filepath.Join(dir, "docker.sock")
	proxyPath := filepath.Join(dir, "proxy.sock")

	// Фиктивный демон: отвечает тем, что получил.
	upstream, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatalf("сокет демона: %v", err)
	}
	defer upstream.Close()
	go func() {
		_ = http.Serve(upstream, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"path": r.URL.Path,
				"body": string(body),
			})
		}))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		err := RunDockerProxy(ctx, DockerProxyOptions{
			UpstreamSocket:   upstreamPath,
			ListenSocket:     proxyPath,
			AllowedBindRoots: proxyRoots,
			SocketUID:        -1,
			SocketGID:        -1,
			// Файл политики машины прогона не должен решать исход теста.
			PolicyPath: filepath.Join(dir, "no-policy.conf"),
		})
		if err != nil && ctx.Err() == nil {
			t.Errorf("прокси упал: %v", err)
		}
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", proxyPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	// Ждём, пока прокси займёт сокет.
	var lastErr error
	for i := 0; i < 100; i++ {
		resp, err := client.Get("http://docker/_ping")
		if err == nil {
			resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("прокси не поднялся: %v", lastErr)
	}

	// Штатный запрос доходит до демона вместе с телом.
	good := `{"Image":"nginx","HostConfig":{"Binds":["app_data:/data"]}}`
	resp, err := client.Post("http://docker/v1.44/containers/create", "application/json", strings.NewReader(good))
	if err != nil {
		t.Fatalf("запрос через прокси: %v", err)
	}
	var echoed map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&echoed)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("штатный запрос отбит: код %d", resp.StatusCode)
	}
	if echoed["body"] != good {
		t.Fatalf("тело дошло до демона изменённым: %q", echoed["body"])
	}

	// Привилегия отбивается, и до демона не доходит вовсе.
	bad := `{"Image":"nginx","HostConfig":{"Privileged":true}}`
	resp, err = client.Post("http://docker/v1.44/containers/create", "application/json", strings.NewReader(bad))
	if err != nil {
		t.Fatalf("запрос через прокси: %v", err)
	}
	payload, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("привилегированный контейнер получил код %d вместо 403", resp.StatusCode)
	}
	if !strings.Contains(string(payload), "Privileged") {
		t.Fatalf("отказ не называет причину: %s", payload)
	}
}

func TestDockerProxyTrebuetKatalogovDlyaPrivyazok(t *testing.T) {
	// Пустой список каталогов — это «проверка не настроена», а не «монтировать
	// нечего»: прокси обязан отказаться подниматься, а не тихо запретить всё.
	err := RunDockerProxy(context.Background(), DockerProxyOptions{
		UpstreamSocket: "/var/run/docker.sock",
		ListenSocket:   filepath.Join(t.TempDir(), "p.sock"),
	})
	if err == nil {
		t.Fatal("прокси поднялся без списка разрешённых каталогов")
	}
	if !strings.Contains(err.Error(), "каталог") {
		t.Fatalf("причина отказа непонятна: %v", err)
	}
}

func TestBindSourceRazbiraetsyaSleva(t *testing.T) {
	// Путь хоста может содержать двоеточие; разбор справа отдал бы под
	// источник кусок цели и пропустил бы привязку корня.
	cases := map[string]string{
		"/opt/a:b/data:/data:ro": "/opt/a",
		"named_volume:/data":     "named_volume",
		"/:/host":                "/",
		"anonymous":              "",
	}
	for bind, want := range cases {
		if got := bindSource(bind); got != want {
			t.Fatalf("%s: источник %q, ожидался %q", bind, got, want)
		}
	}
	_ = fmt.Sprint()
}

// Прокси под политикой сервера (ADR-0095, п. 5). Прокси — root-бинарь, который
// агент не обновляет и не переписывает: даже подменённый бинарь агента в
// observe не поднимет и не остановит ни одного контейнера, потому что демон
// за прокси слышит только чтение.

// policyProxy — прокси с фиктивным демоном, отвечающим 200 на всё, что дошло.
func policyProxy(t *testing.T, policyPath string) http.Handler {
	t.Helper()
	// Короткий путь: у unix-сокета предел длины, и каталог теста на macOS в
	// него не влезает.
	dir, err := os.MkdirTemp("", "dpx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	upstreamPath := filepath.Join(dir, "d.sock")
	upstream, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatalf("сокет демона: %v", err)
	}
	t.Cleanup(func() { upstream.Close() })
	go func() {
		_ = http.Serve(upstream, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"reached":true}`)
		}))
	}()
	return newDockerProxyHandler(DockerProxyOptions{
		UpstreamSocket:   upstreamPath,
		AllowedBindRoots: proxyRoots,
		PolicyPath:       policyPath,
		Logf:             func(string, ...any) {},
	})
}

func proxyCall(t *testing.T, h http.Handler, method, path, body string, header http.Header) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, "http://docker"+path, strings.NewReader(body))
	for k, v := range header {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func writePolicy(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

const benignCreate = `{"Image":"nginx","HostConfig":{"Binds":["app_data:/data"]}}`

func TestDockerProxyObservePassesOnlyReads(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "agent-policy.conf")
	writePolicy(t, policyPath, "version=1\nmode=observe\ncommands=inventory\n")
	h := policyProxy(t, policyPath)

	code, body := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil)
	if code != http.StatusForbidden || !strings.Contains(body, "политика сервера: режим наблюдения") {
		t.Fatalf("POST /containers/create в observe: %d %s", code, body)
	}
	if code, body := proxyCall(t, h, "GET", "/v1.44/containers/json", "", nil); code != http.StatusOK || !strings.Contains(body, "reached") {
		t.Fatalf("GET /containers/json в observe не прошёл: %d %s", code, body)
	}
	denied := []struct{ method, path string }{
		{"POST", "/v1.44/containers/app-web-1/start"},
		{"POST", "/v1.44/containers/app-web-1/stop"},
		{"DELETE", "/v1.44/containers/app-web-1"},
		{"POST", "/v1.44/containers/app-db-1/exec"},
		{"POST", "/v1.44/images/create"},
		{"POST", "/v1.44/build"},
		{"POST", "/v1.44/volumes/create"},
		// Чтение вне белого списка — не шире прежнего: пересечение, а не замена.
		{"GET", "/v1.44/secrets"},
		{"GET", "/v1.44/containers/app-web-1/archive"},
	}
	for _, tc := range denied {
		if code, _ := proxyCall(t, h, tc.method, tc.path, "{}", nil); code != http.StatusForbidden {
			t.Fatalf("%s %s в observe: код %d", tc.method, tc.path, code)
		}
	}
	// Подключение к потоку контейнера — это ввод в него, а не чтение.
	upgrade := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"tcp"}}
	if code, _ := proxyCall(t, h, "GET", "/v1.44/containers/app-web-1/logs", "", upgrade); code != http.StatusForbidden {
		t.Fatalf("GET с Upgrade в observe: код %d", code)
	}
}

func TestDockerProxyDeployKeepsWhitelist(t *testing.T) {
	for name, text := range map[string]string{
		"deploy":    "version=1\nmode=deploy\n",
		"файла нет": "",
	} {
		t.Run(name, func(t *testing.T) {
			policyPath := filepath.Join(t.TempDir(), "agent-policy.conf")
			if text != "" {
				writePolicy(t, policyPath, text)
			}
			h := policyProxy(t, policyPath)
			if code, body := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != http.StatusOK {
				t.Fatalf("штатный create отбит: %d %s", code, body)
			}
			// Прежние запреты на месте.
			if code, _ := proxyCall(t, h, "POST", "/v1.44/containers/create",
				`{"Image":"nginx","HostConfig":{"Privileged":true}}`, nil); code != http.StatusForbidden {
				t.Fatalf("привилегия прошла: %d", code)
			}
		})
	}
}

// Негодный файл закрывает всё — и у прокси тоже: владелец писал его, чтобы
// ограничить, и опечатка не должна открывать демона.
func TestDockerProxyInvalidPolicyIsObserve(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "agent-policy.conf")
	writePolicy(t, policyPath, "mode=deploy\n") // нет version
	h := policyProxy(t, policyPath)
	if code, body := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != http.StatusForbidden ||
		!strings.Contains(body, "политика сервера: режим наблюдения") {
		t.Fatalf("негодный файл не закрыл запись: %d %s", code, body)
	}
}

// Правка файла действует без перезапуска прокси: он перечитывает файл, когда
// у того сменились время изменения или размер.
func TestDockerProxyRereadsPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "agent-policy.conf")
	writePolicy(t, policyPath, "version=1\nmode=observe\n")
	h := policyProxy(t, policyPath)
	steps := []struct {
		text string
		want int
	}{
		{"", http.StatusForbidden},
		{"version=1\nmode=deploy\ncommands=apply\n", http.StatusOK},
		{"version=1\nmode=observe\n", http.StatusForbidden},
	}
	for i, step := range steps {
		if step.text != "" {
			writePolicy(t, policyPath, step.text)
		}
		if code, _ := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != step.want {
			t.Fatalf("шаг %d: код %d, ожидался %d", i, code, step.want)
		}
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if code, _ := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != http.StatusOK {
		t.Fatalf("файл убран — прежний белый список, а код %d", code)
	}
}

// Висячая ссылка на месте файла политики — негодный файл, а не «файла нет»:
// прокси обязан закрыть запись, и открыть её снова, когда ссылку уберут.
func TestDockerProxyDanglingPolicyLinkIsObserve(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "agent-policy.conf")
	h := policyProxy(t, policyPath)

	if code, _ := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != http.StatusOK {
		t.Fatalf("файла нет — прежний список, а код %d", code)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere.conf"), policyPath); err != nil {
		t.Fatal(err)
	}
	if code, _ := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != http.StatusForbidden {
		t.Fatalf("висячая ссылка открыла запись: код %d", code)
	}
	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	if code, _ := proxyCall(t, h, "POST", "/v1.44/containers/create", benignCreate, nil); code != http.StatusOK {
		t.Fatalf("ссылку убрали — прежний список, а код %d", code)
	}
}
