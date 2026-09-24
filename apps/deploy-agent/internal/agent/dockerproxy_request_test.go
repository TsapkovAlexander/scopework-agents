package agent

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Старые версии API Docker и тело у `start`.
//
// На демонах v20.10–v24 `POST /v1.23/containers/{id}/start` применяет ТЕЛО как
// HostConfig: Binds, Privileged — всё, что прокси отбивает в `create`, приезжает
// вторым вызовом, который прокси раньше пропускал не глядя. Отсюда два рубежа, и
// каждый проверен отдельно: префикс версии ниже 1.24 и непустое тело `start`.

// noPolicyProxy — прокси в режиме развёртывания: файла политики нет.
func noPolicyProxy(t *testing.T) http.Handler {
	t.Helper()
	return policyProxy(t, filepath.Join(t.TempDir(), "agent-policy.conf"))
}

func TestDockerProxyStaryjAPIOtbit(t *testing.T) {
	h := noPolicyProxy(t)
	cases := []struct {
		name, method, path, body string
	}{
		{"1.23 start с HostConfig в теле", "POST", "/v1.23/containers/x/start", `{"Binds":["/:/h"]}`},
		{"1.23 start без тела", "POST", "/v1.23/containers/x/start", ""},
		{"1.23 чтение", "GET", "/v1.23/containers/json", ""},
		{"1.9: сравнение числами, не строками", "POST", "/v1.9/containers/x/start", ""},
		{"1.0", "GET", "/v1.0/containers/json", ""},
		{"0.99", "GET", "/v0.99/containers/json", ""},
		// Разбор строгий: всё, что демон примет за версию, а прокси понял бы иначе.
		{"ведущий ноль", "GET", "/v01.30/containers/json", ""},
		{"ведущий ноль в минорной", "GET", "/v1.030/containers/json", ""},
		{"три части", "POST", "/v1.23.1/containers/x/start", ""},
		{"одна часть", "POST", "/v1/containers/x/start", ""},
		{"без минорной", "POST", "/v1./containers/x/start", ""},
		{"без мажорной", "POST", "/v.23/containers/x/start", ""},
		{"заглавная V", "POST", "/V1.23/containers/x/start", ""},
		{"заглавная V новой версии", "GET", "/V1.43/containers/json", ""},
		{"переполнение числа", "GET", "/v99999999999999999999.1/containers/json", ""},
		// Нормализация пути: прокси и демон обязаны увидеть один и тот же путь.
		{"двойной слэш в начале", "POST", "//v1.23/containers/x/start", ""},
		{"двойной слэш после версии", "POST", "/v1.43//containers/x/start", ""},
		{"двойной слэш внутри", "GET", "/v1.43/containers//json", ""},
		{"точка-точка к старой версии", "POST", "/v1.43/../v1.23/containers/x/start", ""},
		{"точка", "POST", "/v1.43/./containers/x/start", ""},
		{"хвостовой слэш", "POST", "/v1.43/containers/x/start/", ""},
		// `.+` в правиле образов пропустил бы `..`, а демон свернул бы путь в чужой вызов.
		{"точка-точка из правила образов", "DELETE", "/v1.43/images/../containers/x", ""},
		{"закодированный слэш после версии", "POST", "/v1.23%2Fcontainers/x/start", ""},
		{"закодированный слэш внутри", "POST", "/v1.43/containers%2Fx/start", ""},
		{"закодированный слэш в нижнем регистре", "POST", "/v1.43/containers/x%2fstart", ""},
		{"закодированная буква версии", "POST", "/%76%31.23/containers/x/start", ""},
		{"закодированная буква новой версии", "GET", "/%761.43/containers/json", ""},
		{"закодированная точка-точка", "POST", "/v1.43/%2e%2e/v1.23/containers/x/start", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := proxyCall(t, h, tc.method, tc.path, tc.body, nil)
			if code != http.StatusForbidden {
				t.Fatalf("%s %s: код %d вместо 403 (%s)", tc.method, tc.path, code, body)
			}
			if strings.Contains(body, "reached") {
				t.Fatalf("%s %s дошёл до демона", tc.method, tc.path)
			}
		})
	}
}

func TestDockerProxyStartSTelomOtbit(t *testing.T) {
	h := noPolicyProxy(t)
	cases := []struct {
		name, path, body string
	}{
		{"HostConfig в теле", "/v1.43/containers/x/start", `{"Binds":["/:/h"],"Privileged":true}`},
		{"HostConfig без префикса версии", "/containers/x/start", `{"Privileged":true}`},
		// Реальные клиенты агента (docker 29, compose v5) тело у start не шлют
		// вовсе, поэтому исключений нет ни для пустого объекта, ни для null.
		{"пустой объект", "/v1.43/containers/x/start", `{}`},
		{"null", "/v1.43/containers/x/start", `null`},
		{"пробел", "/v1.43/containers/x/start", ` `},
		{"тело больше любого предела", "/v1.43/containers/x/start", strings.Repeat("x", 8<<20)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := proxyCall(t, h, "POST", tc.path, tc.body, nil)
			if code != http.StatusForbidden || !strings.Contains(body, "start") {
				t.Fatalf("POST %s с телом: код %d (%s)", tc.path, code, tail(body, 200))
			}
		})
	}

	// Chunked без Content-Length: длину заранее не знает никто, и демон на
	// старом API читает такое тело как HostConfig.
	req := httptest.NewRequest("POST", "http://docker/v1.43/containers/x/start",
		io.NopCloser(strings.NewReader(`{"Binds":["/:/h"]}`)))
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("chunked-тело у start: код %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestDockerProxyStartBezTelaPuskaet(t *testing.T) {
	h := noPolicyProxy(t)
	for _, path := range []string{
		"/v1.43/containers/x/start",
		"/v1.24/containers/x/start", // граница: 1.24 — первая версия без тела у start
		"/containers/x/start",
		"/v1.43/containers/app-web-1/start?checkpoint=", // параметры запроса не в пути
	} {
		code, body := proxyCall(t, h, "POST", path, "", nil)
		if code != http.StatusOK || !strings.Contains(body, "reached") {
			t.Fatalf("штатный start %s отбит: %d %s", path, code, body)
		}
	}
	// Соседние вызовы тела не лишились: `exec/{id}/start` несёт тело по делу.
	if code, body := proxyCall(t, h, "POST", "/v1.43/exec/abc/start", `{"Detach":false,"Tty":false}`, nil); code != http.StatusOK {
		t.Fatalf("exec start с телом отбит: %d %s", code, body)
	}
	if code, body := proxyCall(t, h, "GET", "/v1.44/containers/json", "", nil); code != http.StatusOK {
		t.Fatalf("новая версия API отбита: %d %s", code, body)
	}
}

// TestDockerProxyStartChunkedSkvoznoj — те же правила на настоящем сокете и
// сыром HTTP: chunked-тело здесь разбирает сервер Go, а не тест.
func TestDockerProxyStartChunkedSkvoznoj(t *testing.T) {
	dir, err := os.MkdirTemp("", "dpx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	upstreamPath := filepath.Join(dir, "d.sock")
	proxyPath := filepath.Join(dir, "p.sock")

	reached := make(chan string, 16)
	upstream, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { upstream.Close() })
	go func() {
		_ = http.Serve(upstream, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			reached <- r.URL.Path + " " + string(body)
			w.WriteHeader(http.StatusNoContent)
		}))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = RunDockerProxy(ctx, DockerProxyOptions{
			UpstreamSocket:   upstreamPath,
			ListenSocket:     proxyPath,
			AllowedBindRoots: proxyRoots,
			SocketUID:        -1,
			SocketGID:        -1,
			PolicyPath:       filepath.Join(dir, "no-policy.conf"),
		})
	}()

	raw := func(request string) int {
		t.Helper()
		var conn net.Conn
		for i := 0; i < 100; i++ {
			if conn, err = net.Dial("unix", proxyPath); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("прокси не поднялся: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("ответ прокси: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	chunked := func(path, body string) string {
		var b strings.Builder
		b.WriteString("POST " + path + " HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
		if body != "" {
			b.WriteString(strconv.FormatInt(int64(len(body)), 16) + "\r\n" + body + "\r\n")
		}
		b.WriteString("0\r\n\r\n")
		return b.String()
	}

	for _, tc := range []struct{ path, body string }{
		{"/v1.43/containers/x/start", `{"Binds":["/:/h"]}`},
		{"/v1.23/containers/x/start", `{"Binds":["/:/h"]}`},
		{"/v1.23/containers/x/start", ""},
	} {
		if code := raw(chunked(tc.path, tc.body)); code != http.StatusForbidden {
			t.Fatalf("chunked POST %s %q: код %d вместо 403", tc.path, tc.body, code)
		}
	}
	select {
	case got := <-reached:
		t.Fatalf("отбитый запрос дошёл до демона: %s", got)
	default:
	}

	// Пустое chunked-тело — это отсутствие тела: до демона доходит без него.
	if code := raw(chunked("/v1.43/containers/x/start", "")); code != http.StatusNoContent {
		t.Fatalf("пустой chunked start: код %d", code)
	}
	if got := <-reached; got != "/v1.43/containers/x/start " {
		t.Fatalf("демон получил %q", got)
	}
}
