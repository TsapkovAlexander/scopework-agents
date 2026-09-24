package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"time"
)

// Проверка доступности опубликованных доменов с самого хоста.
//
// ЗАЧЕМ ЭТО ЗДЕСЬ, А НЕ ВО ВНЕШНЕМ UPTIME. Внешний мониторинг существует для
// случая, когда агента на сервере нет: платформа стучится снаружи и по ответу
// судит, жив ли сайт. Но контейнеры на этом сервере поднимаем МЫ — то есть
// знаем и домены, и сервисы, и порты. Спрашивать у человека, что проверять,
// здесь незачем: список выводится из того, что мы сами и развернули.
//
// ЧТО ЭТА ПРОВЕРКА ДОБАВЛЯЕТ К ДВУМ ОСТАЛЬНЫМ:
//
//   - docker healthcheck видит контейнер и только его. Приложение может быть
//     совершенно здоровым, а домен вести в другой сервис — и это состояние
//     платформа уже дважды ловила на боевых выкатах;
//   - внешний uptime видит путь целиком, но не отличает «сервер лежит» от
//     «маршрут сломан», и молчит, когда сервер вовсе не подключён к нему;
//   - эта проверка идёт с хоста через прокси платформы, то есть по пути
//     Caddy → сеть → контейнер. Она отвечает ровно на вопрос «доходит ли
//     запрос до приложения через опубликованный адрес».
//
// ЦЕНА. Каждая проверка — запрос к боевому приложению раз в такт. На
// большинстве серверов это ничто, но приложение бывает тяжёлым на корневом
// маршруте. Поэтому проверки выключаются владельцем (0237), а сам агент их
// ограничивает: не больше десяти адресов, короткий срок, только заголовки.

// HealthCheckResult — итог одной проверки. Поля совпадают со схемой приёма
// мониторинга (healthCheckResultSchema).
type HealthCheckResult struct {
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	StatusCode *int   `json:"status_code"`
	LatencyMs  *int64 `json:"latency_ms"`
	// Error — почему не ответило. До этого поля отказ выглядел как голое
	// `ok: false`, и разобраться постфактум было нечем: таймаут, обрыв
	// соединения и отказ резолва выглядели одинаково.
	Error string `json:"error,omitempty"`
	// TLSError — почему сертификат не годится. Пусто при исправном
	// сертификате И при отказе соединения (тогда о сертификате сказать
	// нечего — смотреть надо Error).
	//
	// ЗАЧЕМ ОТДЕЛЬНО ОТ OK. Запрос идёт с самого хоста, и проверку сертификата
	// приходится глушить: первые минуты после публикации домена его ещё нет,
	// а сказать «приложение не работает» в этот момент было бы неправдой.
	// Но снаружи невыпущенный или просроченный сертификат — это ровно
	// «сайт не открывается», и молчать о нём нельзя. Поэтому проверяем цепочку
	// сами и докладываем отдельным полем.
	TLSError string `json:"tls_error,omitempty"`
	// CertDaysLeft — сколько дней осталось сертификату. nil — соединение не
	// состоялось либо сертификата нет вовсе.
	CertDaysLeft *int `json:"cert_days_left,omitempty"`
}

// Потолок проверок за такт. Хост с полусотней приложений иначе тратил бы на
// них минуту и превращал такт в обход собственных сайтов.
const maxHealthChecks = 10

// healthProbeTimeout — короткий срок на ответ.
//
// Проверка отвечает на вопрос «доходит ли запрос», а не «быстро ли работает
// приложение». Пять секунд отделяют работающее от неработающего; ждать дольше
// значит задерживать весь такт ради приложения, которое и так уже не отвечает.
const healthProbeTimeout = 5 * time.Second

// CollectHealthChecks опрашивает опубликованные домены.
//
// Адреса выводятся из желаемого состояния: проверяем ровно то, что платформа
// сама и опубликовала. Приложение без домена и остановленное пропускаются —
// проверять там нечего, а отчёт «не отвечает» о намеренно остановленном стеке
// был бы ложной тревогой.
func CollectHealthChecks(ctx context.Context, apps []DesiredApp) []HealthCheckResult {
	client := &http.Client{
		Timeout: healthProbeTimeout,
		// Редирект — нормальный ответ живого приложения (http→https,
		// / → /login). Ходить по нему незачем: нас интересует, что кто-то
		// ответил, а не куда он ведёт.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			// Сертификат может быть ещё не выпущен: Let's Encrypt отвечает не
			// мгновенно, а первые минуты после публикации домена — самые
			// интересные для наблюдения. Отказ по сертификату здесь означал бы
			// «приложение не работает», что неправда.
			//
			// Риска подмены нет: запрос идёт с самого хоста на его же прокси и
			// наружу не выходит; ни секретов, ни тела в нём нет.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	var out []HealthCheckResult
	seen := map[string]bool{}

	for _, app := range apps {
		if !app.ShouldRun() {
			continue
		}
		for _, route := range effectiveRoutes(app) {
			if route.Domain == "" || seen[route.Domain] {
				continue
			}
			seen[route.Domain] = true

			out = append(out, probeDomain(ctx, client, route.Domain))
			if len(out) >= maxHealthChecks {
				return out
			}
		}
	}
	return out
}

func probeDomain(ctx context.Context, client *http.Client, domain string) HealthCheckResult {
	url := "https://" + domain + "/"
	res := HealthCheckResult{URL: url}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return res
	}
	// Представляемся тем же именем, что и остальные проверки платформы: без
	// него собственный запрос попадал бы в счётчик подозрительной активности
	// на сервере, который сам же и проверяет.
	req.Header.Set("User-Agent", "ScopeworkHealth/1.0")

	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// Текст ошибки — то единственное, по чему потом можно отличить
		// «сервер не отвечает» от «имя не разрешилось».
		res.Error = shortProbeError(err)
		return res
	}
	defer resp.Body.Close()

	latency := time.Since(started).Milliseconds()
	res.LatencyMs = &latency
	res.StatusCode = &resp.StatusCode
	// Успехом считаем любой ответ, кроме серверной ошибки. 401 и 404 означают,
	// что приложение живо и отвечает по правилам — а закрытый паролем раздел
	// или отсутствующий корневой маршрут поломкой не являются.
	res.OK = resp.StatusCode < 500

	// Тело вычитываем и выбрасываем: закрытие соединения посреди ответа прокси
	// считает обрывом и пишет «aborting with incomplete response» на каждую
	// проверку, зашумляя лог, куда идут смотреть при отказе домена.
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))

	certValid(resp.TLS, domain, time.Now(), &res)
	return res
}

// certValid дополняет результат состоянием сертификата.
//
// Проверка ручная, потому что клиенту она отключена (InsecureSkipVerify):
// иначе первые минуты после публикации домена, пока Let's Encrypt ещё не
// ответил, проверка кричала бы «приложение не работает».
func certValid(state *tls.ConnectionState, domain string, now time.Time, res *HealthCheckResult) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}

	leaf := state.PeerCertificates[0]
	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	res.CertDaysLeft = &days

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       domain,
		Intermediates: intermediates,
		CurrentTime:   now,
	}); err != nil {
		res.TLSError = shortProbeError(err)
	}
}

// Потолок длины текста ошибки: он уезжает в снимок мониторинга и оттуда в
// интерфейс, а сетевые ошибки Go бывают длиной в абзац.
const maxProbeErrorLen = 200

func shortProbeError(err error) string {
	text := strings.TrimSpace(err.Error())
	if len(text) > maxProbeErrorLen {
		return text[:maxProbeErrorLen]
	}
	return text
}
