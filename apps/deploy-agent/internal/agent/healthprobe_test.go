package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Проверка опубликованных доменов с хоста: что она докладывает и о чём молчит.
//
// Проверка идёт по пути Caddy → сеть → контейнер, поэтому её отчёт — почти всё,
// что платформа знает о домене. Пока в нём было одно `ok`, отказ выглядел
// одинаково при таймауте, отказе резолва и невыпущенном сертификате.

// selfSignedCert — сертификат для проверки разбора: доверия к нему нет, срок
// задаётся аргументом.
func selfSignedCert(t *testing.T, host string, notAfter time.Time) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestProbeDomainReportsErrorText(t *testing.T) {
	client := &http.Client{Timeout: 500 * time.Millisecond}

	// Адрес, которого нет: соединение не состоится, и причина обязана доехать.
	res := probeDomain(context.Background(), client, "domain.invalid.example")

	if res.OK {
		t.Fatal("недоступный домен признан живым")
	}
	if res.Error == "" {
		t.Fatal("причина отказа потеряна — по голому ok:false разбирать нечего")
	}
	if res.StatusCode != nil || res.LatencyMs != nil {
		t.Fatalf("у несостоявшегося запроса появились статус/задержка: %+v", res)
	}
}

// Текст ошибки уезжает в снимок мониторинга и оттуда в интерфейс.
func TestShortProbeErrorTrims(t *testing.T) {
	long := errors.New(strings.Repeat("я", maxProbeErrorLen+50))
	if got := shortProbeError(long); len(got) != maxProbeErrorLen {
		t.Fatalf("длина обрезанного текста %d, ожидалась %d", len(got), maxProbeErrorLen)
	}
	if got := shortProbeError(errors.New("  коротко  ")); got != "коротко" {
		t.Fatalf("получено %q", got)
	}
}

// Тело ответа вычитывается: иначе прокси на каждую проверку пишет
// «aborting with incomplete response» — в тот самый лог, куда идут смотреть,
// когда домен не отвечает.
func TestProbeDomainDrainsBody(t *testing.T) {
	var completed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		if _, err := w.Write([]byte("hello")); err != nil {
			return
		}
		// Обработчик дописал ответ целиком и клиент его забрал — при
		// незакрытом чтении сервер зафиксировал бы обрыв.
		completed.Store(true)
	}))
	defer srv.Close()

	res := probeHTTP(context.Background(), srv.URL, "", time.Second)
	if !res.OK {
		t.Fatalf("проба не прошла: %+v", res)
	}
	if !completed.Load() {
		t.Fatal("тело ответа не вычитано — прокси зачтёт это как обрыв")
	}
}

// Приложение вправе отдавать на `/` сколько угодно; проба спрашивает лишь
// «отвечает ли оно» и не должна тянуть с боевого приложения гигабайты.
func TestProbeHTTPBodyReadIsBounded(t *testing.T) {
	var served atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 32<<10)
		for i := 0; i < 64; i++ { // 2 МиБ, если читать всё
			n, err := w.Write(chunk)
			served.Add(int64(n))
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	if res := probeHTTP(context.Background(), srv.URL, "", 5*time.Second); !res.OK {
		t.Fatalf("проба не прошла: %+v", res)
	}
	// Потолок мягкий: сервер успевает записать в буфер сверх лимита, но
	// вычитывать всё до конца проба не обязана.
	if served.Load() > 2<<20 {
		t.Fatalf("прочитано %d байт — потолок чтения не работает", served.Load())
	}
}

func TestCertValidReportsExpiryAndProblems(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

	// Соединения не было — о сертификате сказать нечего, и выдумывать отказ
	// нельзя: причина уже записана в Error.
	var empty HealthCheckResult
	certValid(nil, "app.example.com", now, &empty)
	if empty.TLSError != "" || empty.CertDaysLeft != nil {
		t.Fatalf("без соединения появились выводы о сертификате: %+v", empty)
	}

	// Самоподписанный сертификат — ровно то, что видит браузер как «сайт не
	// открывается», хотя приложение отвечает.
	cert := selfSignedCert(t, "app.example.com", now.Add(30*24*time.Hour))
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	var res HealthCheckResult
	certValid(state, "app.example.com", now, &res)
	if res.TLSError == "" {
		t.Fatal("недоверенный сертификат принят за исправный")
	}
	if res.CertDaysLeft == nil {
		t.Fatal("срок сертификата не определён")
	}
	if *res.CertDaysLeft != 30 {
		t.Fatalf("срок сертификата: %d дней, ожидалось 30", *res.CertDaysLeft)
	}

	// Просроченный: срок отрицательный, и это тоже надо видеть.
	expired := selfSignedCert(t, "app.example.com", now.Add(-48*time.Hour))
	var old HealthCheckResult
	certValid(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{expired}},
		"app.example.com", now, &old)
	if old.CertDaysLeft == nil {
		t.Fatal("срок просроченного сертификата не определён")
	}
	if *old.CertDaysLeft > 0 {
		t.Fatalf("просроченный сертификат показан живым: %d дней", *old.CertDaysLeft)
	}
}

// Имя в сертификате не совпадает с доменом — снаружи это ошибка браузера,
// изнутри приложение отвечает как ни в чём не бывало.
func TestCertValidCatchesWrongName(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	cert := selfSignedCert(t, "other.example.com", now.Add(90*24*time.Hour))

	var res HealthCheckResult
	certValid(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		"app.example.com", now, &res)

	if res.TLSError == "" {
		t.Fatal("сертификат на чужое имя принят за исправный")
	}
}
