package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HTTP-проба приложения. Контейнер без HEALTHCHECK агент считает живым по
// одному факту «процесс запущен» — проба закрывает эту дыру: платформа сама
// спрашивает приложение и узнаёт, отвечает ли оно, а не только запущено ли.

func TestProbeTargetPicksRouteThenFallback(t *testing.T) {
	// Основной опубликованный маршрут важнее конвенции app+InternalPort:
	// у шаблона главный вход может жить на другом сервисе.
	app := DesiredApp{
		Slug:         "supabase",
		Domain:       "db.example.com",
		InternalPort: 8000,
		Routes: []DesiredRoute{
			{Domain: "db.example.com", Service: "kong", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000},
		},
	}
	service, port, ok := probeTarget(app)
	if !ok || service != "kong" || port != 8000 {
		t.Fatalf("цель пробы: %s:%d ok=%v, ожидалось kong:8000", service, port, ok)
	}

	// Старый формат без routes: конвенция app + InternalPort.
	legacy := DesiredApp{Slug: "n8n", Domain: "n8n.example.com", InternalPort: 5678}
	service, port, ok = probeTarget(legacy)
	if !ok || service != "app" || port != 5678 {
		t.Fatalf("цель пробы: %s:%d ok=%v, ожидалось app:5678", service, port, ok)
	}

	// Порт не объявлен — пробовать нечего, и это не отказ.
	if _, _, ok := probeTarget(DesiredApp{Slug: "x"}); ok {
		t.Fatal("проба без порта должна пропускаться")
	}
}

func TestProbeHTTPStatuses(t *testing.T) {
	// Ответ ЛЮБЫМ статусом до 500 означает «приложение живо и отвечает»:
	// 401/403 — это работающая аутентификация, 301 — работающий редирект.
	// 5xx — приложение стоит за своим портом, но обслуживать не может.
	cases := []struct {
		status int
		wantOK bool
	}{
		{200, true},
		{301, true},
		{401, true},
		{404, true},
		{500, false},
		{502, false},
	}

	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
		}))
		result := probeHTTP(context.Background(), srv.URL, "app.example.com", time.Second)
		srv.Close()

		if result.OK != tc.wantOK {
			t.Fatalf("статус %d: ok=%v, ожидалось %v", tc.status, result.OK, tc.wantOK)
		}
		if result.Status != tc.status {
			t.Fatalf("статус %d не донесён: %d", tc.status, result.Status)
		}
	}
}

func TestProbeHTTPSendsHostHeader(t *testing.T) {
	// Приложения за прокси часто маршрутизируют по Host; проба без него
	// получала бы 404 от того же nginx с виртуальными хостами.
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	probeHTTP(context.Background(), srv.URL, "app.example.com", time.Second)
	if gotHost != "app.example.com" {
		t.Fatalf("Host = %q, ожидался app.example.com", gotHost)
	}
}

func TestProbeHTTPDoesNotFollowRedirects(t *testing.T) {
	// Редирект на https://домен ведёт наружу — туда проба ходить не должна:
	// её вопрос «отвечает ли контейнер», а не «работает ли интернет».
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.com/", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	result := probeHTTP(context.Background(), srv.URL, "", time.Second)
	if !result.OK || result.Status != http.StatusMovedPermanently {
		t.Fatalf("редирект должен считаться живым ответом: %+v", result)
	}
}

func TestProbeHTTPTimeoutIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	result := probeHTTP(context.Background(), srv.URL, "", 100*time.Millisecond)
	if result.OK {
		t.Fatal("зависший ответ не должен считаться живым")
	}
	if result.Error == "" {
		t.Fatal("причина отказа должна быть названа")
	}
	// В тексте не должно быть адреса с IP из docker-сети как единственного
	// объяснения — но сам факт ошибки обязателен.
	if !strings.Contains(strings.ToLower(result.Error), "timeout") &&
		!strings.Contains(result.Error, "превы") &&
		!strings.Contains(result.Error, "deadline") {
		t.Logf("текст ошибки: %s", result.Error)
	}
}
