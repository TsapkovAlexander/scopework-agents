package agent

import (
	"regexp"
	"strings"
	"testing"
)

// Публикация нескольких сервисов одного приложения под разными доменами.
//
// До этого прокси знал ровно одну цель — `<slug>-app-1`, и Supabase мог отдать
// наружу либо API, либо панель управления, но не то и другое по отдельным
// адресам.

func TestCaddyfileUsesRoutes(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000},
		},
	}}, ProxyOptions{})

	if !strings.Contains(out, "api.example.com {") {
		t.Fatalf("нет блока для домена API:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy supabase-app-1:8000") {
		t.Fatalf("неверная цель для API:\n%s", out)
	}
	if !strings.Contains(out, "studio.example.com {") {
		t.Fatalf("нет блока для домена панели:\n%s", out)
	}
	// Имя контейнера складывается как `<проект>-<сервис>-<номер>`, и сервис
	// берётся из маршрута, а не зашит.
	if !strings.Contains(out, "reverse_proxy supabase-studio-1:3000") {
		t.Fatalf("неверная цель для панели:\n%s", out)
	}
}

// Старый сервер маршрутов не присылает. Агент обязан продолжать работать по
// паре домен+порт, иначе обновление агента погасило бы все сайты.
func TestCaddyfileFallsBackToSingleDomain(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:         "n8n",
		Domain:       "n8n.example.com",
		InternalPort: 5678,
		Desired:      "present",
	}}, ProxyOptions{})

	if !strings.Contains(out, "reverse_proxy n8n-app-1:5678") {
		t.Fatalf("совместимость со старым форматом потеряна:\n%s", out)
	}
}

// Caddy отказывается принимать конфиг с двумя блоками на один адрес — целиком.
// То есть ошибка на сервере, выдавшая один домен двум приложениям, погасила бы
// ВСЕ сайты хоста, а не одно приложение. Поэтому дубликаты отсекаются здесь.
func TestCaddyfileDropsDuplicateDomains(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{
		{Slug: "first", Domain: "shared.example.com", InternalPort: 3000, Desired: "present"},
		{Slug: "second", Domain: "shared.example.com", InternalPort: 4000, Desired: "present"},
	}, ProxyOptions{})

	if countSiteBlocks(out, "shared.example.com") != 1 {
		t.Fatalf("дубликат домена попал в конфиг:\n%s", out)
	}
	// Побеждает первый по порядку сортировки, и он же остаётся единственным.
	if strings.Contains(out, "second-app-1") {
		t.Fatalf("в конфиг попали обе цели одного домена:\n%s", out)
	}
}

func TestCaddyfileDropsDuplicateWithinApp(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "api.example.com", Service: "studio", Port: 3000},
		},
	}}, ProxyOptions{})

	if countSiteBlocks(out, "api.example.com") != 1 {
		t.Fatalf("дубликат внутри приложения попал в конфиг:\n%s", out)
	}
}

// Значения маршрута уезжают в конфиг прокси, то есть это недоверенный вход.
func TestCaddyfileRejectsUnsafeRoute(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "ok.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "ok.example.com", Service: "app", Port: 8000},
			// Имя сервиса с пробелом и скобкой разорвало бы конфиг Caddy.
			{Domain: "bad.example.com", Service: "evil }\n:80 {\n respond", Port: 3000},
			// Домен не по формату.
			{Domain: "не домен", Service: "studio", Port: 3000},
			// Порт вне диапазона.
			{Domain: "port.example.com", Service: "studio", Port: 0},
		},
	}}, ProxyOptions{})

	if strings.Contains(out, "evil") {
		t.Fatalf("небезопасное имя сервиса попало в конфиг:\n%s", out)
	}
	if strings.Contains(out, "bad.example.com") || strings.Contains(out, "port.example.com") {
		t.Fatalf("некорректный маршрут попал в конфиг:\n%s", out)
	}
	// Исправный маршрут при этом обязан остаться: один плохой не должен
	// оставлять приложение без публикации целиком.
	if !strings.Contains(out, "reverse_proxy supabase-app-1:8000") {
		t.Fatalf("исправный маршрут потерян:\n%s", out)
	}
}

// Остановленное приложение наружу не публикуется: маршрут в снятый стек отдавал
// бы ошибку, а Caddy продолжал бы продлевать для него сертификат.
func TestCaddyfileSkipsStoppedApp(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "absent",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000},
		},
	}}, ProxyOptions{})

	if strings.Contains(out, "example.com {") {
		t.Fatalf("остановленное приложение опубликовано:\n%s", out)
	}
}

// Защита маршрута паролем: политика type=basic_auth рендерится блоком
// basic_auth до reverse_proxy. Хеш — bcrypt, его считает сервер; агент только
// проверяет форму значений, потому что они уезжают в конфиг Caddy.
func TestCaddyfileRendersBasicAuth(t *testing.T) {
	const hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "basic_auth", Username: "admin", PasswordHash: hash}}},
		},
	}}, ProxyOptions{})

	// Внутри route: пароль вместе с отказом скрытым путям — два вида проверок,
	// а вне route Caddy поставил бы basic_auth раньше abort, и `/.env` без
	// учётных данных получал бы 401 вместо оборванного соединения.
	if !strings.Contains(out, "\troute {\n") || !strings.Contains(out, "basic_auth {\n\t\t\tadmin "+hash+"\n\t\t}") {
		t.Fatalf("нет блока basic_auth с пользователем и хешем:\n%s", out)
	}
	// Порядок внутри блока сайта: сначала аутентификация, потом проксирование.
	authAt := strings.Index(out, "basic_auth")
	proxyAt := strings.Index(out, "reverse_proxy supabase-studio-1:3000")
	if authAt == -1 || proxyAt == -1 || authAt > proxyAt {
		t.Fatalf("basic_auth не стоит перед reverse_proxy:\n%s", out)
	}
	// Маршрут без политики защиту не получает.
	apiBlock := out[strings.Index(out, "api.example.com {"):strings.Index(out, "studio.example.com {")]
	if strings.Contains(apiBlock, "basic_auth") {
		t.Fatalf("защита попала на маршрут без политики:\n%s", out)
	}
}

// Политика есть, но негодна — маршрут НЕ публикуется вовсе (fail closed).
// Опубликовать админ-панель БЕЗ пароля из-за испорченного хеша — худший из
// возможных исходов; недоступность панели — меньшая цена.
func TestCaddyfileFailClosedOnBadBasicAuth(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			// Имя с пробелом и скобкой разорвало бы конфиг Caddy.
			{Domain: "one.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "basic_auth", Username: "evil }\n:80 {", PasswordHash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"}}},
			// Хеш не bcrypt: Caddy отверг бы конфиг целиком — или, хуже,
			// пропускал бы всех.
			{Domain: "two.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "basic_auth", Username: "admin", PasswordHash: "plaintext-password"}}},
		},
	}}, ProxyOptions{})

	if strings.Contains(out, "one.example.com") || strings.Contains(out, "two.example.com") {
		t.Fatalf("маршрут с негодной политикой опубликован:\n%s", out)
	}
	if strings.Contains(out, "evil") {
		t.Fatalf("небезопасное имя пользователя попало в конфиг:\n%s", out)
	}
	// Исправный маршрут того же приложения обязан остаться.
	if !strings.Contains(out, "reverse_proxy supabase-app-1:8000") {
		t.Fatalf("исправный маршрут потерян:\n%s", out)
	}
}

// Политика неизвестного типа — тоже fail closed. Будущий сервер пришлёт
// forward_auth; старый агент, который его не понимает, обязан НЕ публиковать
// маршрут, а не публиковать его без защиты.
func TestCaddyfileFailClosedOnUnknownPolicy(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "forward_auth"}}},
		},
	}}, ProxyOptions{})

	if strings.Contains(out, "studio.example.com") {
		t.Fatalf("маршрут с неизвестной политикой опубликован без защиты:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy supabase-app-1:8000") {
		t.Fatalf("исправный маршрут потерян:\n%s", out)
	}
}

// Ограничение по списку IP: policy type=ip_allowlist рендерится матчером
// remote_ip с ответом 403 для остальных. Записи проверяет и сервер, но они
// уезжают в конфиг Caddy — агент сверяет форму сам (недоверенный вход).
func TestCaddyfileRendersIpAllowlist(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "ip_allowlist", Cidrs: []string{"203.0.113.7", "10.0.0.0/8", "2001:db8::/32"}}}},
		},
	}}, ProxyOptions{})

	if !strings.Contains(out, "@denied not remote_ip 203.0.113.7 10.0.0.0/8 2001:db8::/32") {
		t.Fatalf("нет матчера remote_ip со списком:\n%s", out)
	}
	if !strings.Contains(out, "respond @denied 403") {
		t.Fatalf("нет ответа 403 для чужих адресов:\n%s", out)
	}
	// Фильтр стоит до проксирования.
	denyAt := strings.Index(out, "respond @denied 403")
	proxyAt := strings.Index(out, "reverse_proxy supabase-studio-1:3000")
	if denyAt == -1 || proxyAt == -1 || denyAt > proxyAt {
		t.Fatalf("фильтр IP не стоит перед reverse_proxy:\n%s", out)
	}
	// Маршрут без политики фильтра не получает.
	apiBlock := out[strings.Index(out, "api.example.com {"):strings.Index(out, "studio.example.com {")]
	if strings.Contains(apiBlock, "remote_ip") {
		t.Fatalf("фильтр попал на маршрут без политики:\n%s", out)
	}
}

// Список IP и пароль живут вместе: фильтр стоит ПЕРВЫМ, чтобы чужой адрес
// не доходил до bcrypt-проверки (она дорогая, и это защита от подбора).
func TestCaddyfileIpAllowlistBeforeBasicAuth(t *testing.T) {
	const hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{
					{Type: "basic_auth", Username: "admin", PasswordHash: hash},
					{Type: "ip_allowlist", Cidrs: []string{"203.0.113.7"}},
				}},
		},
	}}, ProxyOptions{})

	denyAt := strings.Index(out, "respond @denied 403")
	authAt := strings.Index(out, "basic_auth")
	proxyAt := strings.Index(out, "reverse_proxy supabase-studio-1:3000")
	if denyAt == -1 || authAt == -1 || proxyAt == -1 {
		t.Fatalf("не хватает директив:\n%s", out)
	}
	if !(denyAt < authAt && authAt < proxyAt) {
		t.Fatalf("порядок должен быть: фильтр IP → пароль → проксирование:\n%s", out)
	}
}

// Негодная запись списка — маршрут НЕ публикуется (fail closed), как и с
// негодным хешем: разорванный конфиг погасил бы все сайты хоста.
func TestCaddyfileFailClosedOnBadAllowlist(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			// Имя вместо адреса.
			{Domain: "one.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "ip_allowlist", Cidrs: []string{"example.com"}}}},
			// Попытка разорвать конфиг.
			{Domain: "two.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "ip_allowlist", Cidrs: []string{"1.2.3.4 }\n:80 {"}}}},
			// Маска шире допустимой.
			{Domain: "three.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "ip_allowlist", Cidrs: []string{"10.0.0.0/33"}}}},
			// Пустой список: «запереть всех» и «открыть всем» читаются одинаково
			// легко — не угадываем, не публикуем.
			{Domain: "four.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "ip_allowlist"}}},
		},
	}}, ProxyOptions{})

	for _, domain := range []string{"one.example.com", "two.example.com", "three.example.com", "four.example.com"} {
		if strings.Contains(out, domain) {
			t.Fatalf("маршрут %s с негодным списком опубликован:\n%s", domain, out)
		}
	}
	if strings.Contains(out, ":80 {\n respond") {
		t.Fatalf("инъекция из списка попала в конфиг:\n%s", out)
	}
	if !strings.Contains(out, "reverse_proxy supabase-app-1:8000") {
		t.Fatalf("исправный маршрут потерян:\n%s", out)
	}
}

// Отпечаток конфигурации зависит от НАБОРА ОПУБЛИКОВАННЫХ СЕРВИСОВ, но не от
// доменов.
//
// Прежде он не зависел от маршрутов вовсе, и это было верно: они меняли конфиг
// прокси, а не содержимое каталога приложения. Перестало быть верным, когда
// платформа начала готовить описание стека из репозитория: членство в сети
// прокси выводится из маршрутов, то есть попадает в файл. Сервис без маршрута к
// сети не подключается, и добавленный маршрут обязан вызвать переприменение —
// иначе прокси направлен в контейнер, которого в его сети нет, и домен отвечает
// 502 при зелёном приложении.
//
// Смена домена у того же сервиса по-прежнему стек не трогает: членства она не
// меняет, а прокси перечитывает адреса каждый цикл.
func TestConfigHashFollowsPublishedServicesNotDomains(t *testing.T) {
	base := DesiredApp{Slug: "supabase", Compose: "name: x", Env: map[string]string{"A": "1"}}

	withStudio := base
	withStudio.Routes = []DesiredRoute{{Domain: "studio.example.com", Service: "studio", Port: 3000}}

	// Появился опубликованный сервис — стек обязан переприменяться.
	if configHash(base) == configHash(withStudio) {
		t.Error("появление маршрута не приводит к переприменению: сервис не попадёт в сеть прокси")
	}

	// Тот же сервис под другим адресом — переприменять нечего.
	renamed := withStudio
	renamed.Routes = []DesiredRoute{{Domain: "panel.example.com", Service: "studio", Port: 3000}}
	if configHash(withStudio) != configHash(renamed) {
		t.Error("смена домена перезапускает стек — ронять сервис ради смены адреса нельзя")
	}

	// Второй сервис наружу — снова переприменение.
	both := withStudio
	both.Routes = append(append([]DesiredRoute(nil), withStudio.Routes...),
		DesiredRoute{Domain: "api.example.com", Service: "api", Port: 8000})
	if configHash(withStudio) == configHash(both) {
		t.Error("добавление второго опубликованного сервиса не приводит к переприменению")
	}

	// Порядок маршрутов в ответе сервера значения не имеет.
	swapped := both
	swapped.Routes = []DesiredRoute{
		{Domain: "api.example.com", Service: "api", Port: 8000},
		{Domain: "studio.example.com", Service: "studio", Port: 3000},
	}
	if configHash(both) != configHash(swapped) {
		t.Error("перестановка маршрутов меняет отпечаток — стек перезапускался бы на ровном месте")
	}
}

// countSiteBlocks считает блоки, открытые ИМЕННО этим адресом: подсчёт по
// подстроке ловил бы и www-редирект (www.domain содержит domain).
func countSiteBlocks(out, domain string) int {
	count := 0
	for _, line := range strings.Split(out, "\n") {
		if line == domain+" {" {
			count++
		}
	}
	return count
}

// Центральный forward_auth (0188): вход в панель по личности Scopework.
// На хосте — только строки в Caddyfile: subrequest к платформе, кука
// проверяется там. Порядок: фильтр IP → пароль → forward_auth → проксирование
// (дешёвое и локальное раньше сетевого).
func TestCaddyfileRendersForwardAuth(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "forward_auth"}}},
		},
	}}, ProxyOptions{PlatformBaseURL: "https://scopework.ru"})

	for _, want := range []string{
		"forward_auth https://scopework.ru {",
		"uri /api/deploy/access/verify",
		// Без подмены Host subrequest пришёл бы к платформе с чужим именем
		// хоста и не совпал бы ни с одним vhost.
		"header_up Host {upstream_hostport}",
		// Клиентский X-Scopework-User вычищается до проверки, доверенный —
		// переносится из ответа платформы.
		"request_header -X-Scopework-User",
		"copy_headers X-Scopework-User",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("в конфиге нет %q:\n%s", want, out)
		}
	}
	// Очистка заголовка стоит ДО subrequest, subrequest — до проксирования.
	cleanAt := strings.Index(out, "request_header -X-Scopework-User")
	faAt := strings.Index(out, "forward_auth https://")
	proxyAt := strings.Index(out, "reverse_proxy supabase-studio-1:3000")
	if cleanAt == -1 || faAt == -1 || proxyAt == -1 || !(cleanAt < faAt && faAt < proxyAt) {
		t.Fatalf("порядок request_header → forward_auth → reverse_proxy нарушен:\n%s", out)
	}
}

// Все три политики разом: порядок фиксирован route-блоком.
func TestCaddyfileOrdersAllPolicies(t *testing.T) {
	const hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{
					{Type: "forward_auth"},
					{Type: "basic_auth", Username: "admin", PasswordHash: hash},
					{Type: "ip_allowlist", Cidrs: []string{"203.0.113.7"}},
				}},
		},
	}}, ProxyOptions{PlatformBaseURL: "https://scopework.ru"})

	denyAt := strings.Index(out, "respond @denied 403")
	authAt := strings.Index(out, "basic_auth {")
	faAt := strings.Index(out, "forward_auth ")
	proxyAt := strings.Index(out, "reverse_proxy supabase-studio-1:3000")
	if denyAt == -1 || authAt == -1 || faAt == -1 || proxyAt == -1 {
		t.Fatalf("не хватает директив:\n%s", out)
	}
	if !(denyAt < authAt && authAt < faAt && faAt < proxyAt) {
		t.Fatalf("порядок должен быть: IP → пароль → forward_auth → proxy:\n%s", out)
	}
}

// Без адреса платформы forward_auth рендерить не из чего — fail closed.
func TestCaddyfileForwardAuthFailClosedWithoutBase(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "forward_auth"}}},
		},
	}}, ProxyOptions{})

	if strings.Contains(out, "studio.example.com {") {
		t.Fatalf("маршрут с forward_auth опубликован без адреса платформы:\n%s", out)
	}
}

// Блокировка адресов (0204) — хостовая: матчер применяется ко ВСЕМ доменам, а
// не к одному маршруту. Сканер стучится во все сразу, и бан, действующий на
// один домен, не защитил бы ни от чего.
func TestCaddyfileRendersHostDenyList(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000},
		},
	}}, ProxyOptions{DenyIPs: []string{"203.0.113.7", "198.51.100.0/24"}})

	if strings.Count(out, "@banned remote_ip 203.0.113.7 198.51.100.0/24") != 2 {
		t.Fatalf("блокировка применена не ко всем доменам:\n%s", out)
	}
	if strings.Count(out, "respond @banned 403") != 2 {
		t.Fatalf("нет ответа 403 заблокированным:\n%s", out)
	}
	proxyAt := strings.Index(out, "reverse_proxy supabase-app-1:8000")
	banAt := strings.Index(out, "respond @banned 403")
	if banAt == -1 || proxyAt == -1 || banAt > proxyAt {
		t.Fatalf("блокировка не стоит перед проксированием:\n%s", out)
	}
}

// Блокировка стоит ПЕРЕД паролем и forward_auth: смысл бана в том, чтобы
// перестать тратить на источник ресурсы хоста, а bcrypt и сетевой subrequest —
// самые дорогие шаги.
func TestCaddyfileDenyListBeforeAuth(t *testing.T) {
	const hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{
					{Type: "basic_auth", Username: "admin", PasswordHash: hash},
					{Type: "ip_allowlist", Cidrs: []string{"203.0.113.7"}},
				}},
		},
	}}, ProxyOptions{DenyIPs: []string{"198.51.100.14"}})

	banAt := strings.Index(out, "respond @banned 403")
	denyAt := strings.Index(out, "respond @denied 403")
	authAt := strings.Index(out, "basic_auth")
	if banAt == -1 || denyAt == -1 || authAt == -1 {
		t.Fatalf("не хватает директив:\n%s", out)
	}
	if !(banAt < denyAt && denyAt < authAt) {
		t.Fatalf("порядок должен быть: бан → список допущенных → пароль:\n%s", out)
	}
}

// Единственная политика плюс бан — это уже два вида проверок, значит нужен
// route-блок с явным порядком: вне него порядок задаёт Caddy, а не текст.
func TestCaddyfileDenyListWrapsRouteWithSinglePolicy(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{{Type: "ip_allowlist", Cidrs: []string{"203.0.113.7"}}}},
		},
	}}, ProxyOptions{DenyIPs: []string{"198.51.100.14"}})

	if !strings.Contains(out, "route {") {
		t.Fatalf("бан вместе с политикой обязан ехать в route-блоке:\n%s", out)
	}
}

// Негодная запись бана ПРОПУСКАЕТСЯ, а сайт публикуется. Асимметрия с
// политиками маршрута намеренная: не применённая политика оставляет админку
// открытой миру, не применённый бан — оставляет сканер работать ещё цикл.
// Гасить рабочий сайт из-за испорченной строки в списке банов несоразмерно.
func TestCaddyfileSkipsBadDenyEntriesButKeepsSite(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes:  []DesiredRoute{{Domain: "api.example.com", Service: "app", Port: 8000}},
	}}, ProxyOptions{DenyIPs: []string{
		"example.com",      // имя вместо адреса
		"1.2.3.4 }\n:80 {", // попытка разорвать конфиг
		"10.0.0.0/33",      // маска шире допустимой
		"01.2.3.4",         // ведущий ноль
		"203.0.113.7",      // единственная годная
		"203.0.113.7",      // дубль
	}})

	if !strings.Contains(out, "reverse_proxy supabase-app-1:8000") {
		t.Fatalf("сайт погашен из-за негодной записи бана:\n%s", out)
	}
	if !strings.Contains(out, "@banned remote_ip 203.0.113.7\n") {
		t.Fatalf("годная запись не применена или к ней приклеился мусор:\n%s", out)
	}
	if strings.Contains(out, ":80 {\n\t\trespond") || strings.Contains(out, "example.com }") {
		t.Fatalf("инъекция из списка попала в конфиг:\n%s", out)
	}
}

// Кромка отказывает разведке ДО приложения — по имени пути (ADR-0060 §1).
//
// Ни одному легальному клиенту опубликованного приложения не нужен `/.env` или
// `/.git/config`. 10.09.2026 сканер прошёл 844 такими запросами до Next.js и
// получил отрисованную страницу 404. Отказ по пути быстрее любого порога: скан
// на 17 секунд кончается раньше любого окна.
//
// Шаблон записан здесь буквально, а не взят из кода: тест держит ровно тот
// список, который утвердили, и правка списка обязана пройти через него.
const secretPathRegexp = `(?i)(^|/)(\.env([._-][^/]*)?|\.git|\.git-credentials|\.svn|\.hg|\.bzr|\.aws|\.ssh|\.docker|\.kube|\.gnupg|\.htpasswd|\.npmrc|\.pgpass|\.netrc|\.vault-token|\.bash_history|\.zsh_history|\.mysql_history|\.psql_history|\.s3cfg|\.boto|\.pypirc|\.dockercfg)(/|$)`

func secretPathLines(indent string) string {
	return indent + "@secret_path path_regexp " + secretPathRegexp + "\n" + indent + "abort @secret_path\n"
}

func TestCaddyfileAbortsSecretPaths(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "api.example.com", Service: "app", Port: 8000},
			{Domain: "studio.example.com", Service: "studio", Port: 3000},
		},
	}}, ProxyOptions{})

	// Без политик и банов route-блок не нужен: `abort` в штатном порядке Caddy
	// и так стоит раньше reverse_proxy.
	if n := strings.Count(out, secretPathLines("\t")); n != 2 {
		t.Fatalf("отказ секретным путям обязан стоять в каждом сайте приложения, найдено %d:\n%s", n, out)
	}
	for _, target := range []string{"supabase-app-1:8000", "supabase-studio-1:3000"} {
		abortAt := strings.LastIndex(out[:strings.Index(out, "reverse_proxy "+target)], "abort @secret_path")
		siteAt := strings.LastIndex(out[:strings.Index(out, "reverse_proxy "+target)], " {\n\theader Strict")
		if abortAt == -1 || abortAt < siteAt {
			t.Fatalf("у %s отказ секретным путям не стоит перед проксированием:\n%s", target, out)
		}
	}
	// В www-редиректе проксирования нет: путь уедет 308 на основной домен и
	// получит отказ уже там.
	wwwAt := strings.Index(out, "www.api.example.com {")
	if wwwAt == -1 || strings.Contains(out[wwwAt:], "abort") {
		t.Fatalf("отказ попал в www-редирект или www-блока нет:\n%s", out)
	}
}

// Шаблон проверяется поведением, а не только текстом: регулярка вынимается из
// отрендеренного конфига и прогоняется тем же RE2, на котором работает
// path_regexp у Caddy (он написан на Go).
//
// Прежний `/\.` с исключением `/.well-known/*` в корне рвал законные пути
// приложений клиентов: `.well-known` Supabase лежит на глубине, объекты
// Storage и репозитории Gitea законно начинаются с точки.
func TestCaddyfileSecretPathPatternSparesLegitDotSegments(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{})
	m := regexp.MustCompile(`@secret_path path_regexp (\S+)\n`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("матчер секретных путей не найден:\n%s", out)
	}
	re, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("шаблон не компилируется RE2: %v", err)
	}

	for _, path := range []string{"/.env", "/.env.local", "/repo/.env", "/.git/config", "/a/.ssh/id_rsa", "/.ENV"} {
		if !re.MatchString(path) {
			t.Errorf("%s обязан получить обрыв", path)
		}
	}
	for _, path := range []string{
		"/auth/v1/.well-known/jwks.json",
		"/.well-known/acme-challenge/x",
		"/storage/v1/object/public/b/.NET-portal.zip",
		"/o/r/src/.github/workflows/ci.yml",
		"/.gitignore",
		"/.environment-notes",
	} {
		if re.MatchString(path) {
			t.Errorf("%s — законный путь приложения, обрыва быть не должно", path)
		}
	}
}

// С баном и политиками порядок задаёт текст route-блока: забаненный получает
// 403 (по нему видно, что бан действует), секретный путь рвётся раньше bcrypt
// и subrequest платформы — иначе сканер `.env` выжигал бы CPU хоста и дёргал
// платформу на каждый запрос.
func TestCaddyfileSecretPathsAfterBanBeforeAuth(t *testing.T) {
	const hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "studio.example.com",
		Desired: "present",
		Routes: []DesiredRoute{
			{Domain: "studio.example.com", Service: "studio", Port: 3000,
				Policies: []RoutePolicy{
					{Type: "forward_auth"},
					{Type: "basic_auth", Username: "admin", PasswordHash: hash},
					{Type: "ip_allowlist", Cidrs: []string{"203.0.113.7"}},
				}},
		},
	}}, ProxyOptions{PlatformBaseURL: "https://scopework.ru", DenyIPs: []string{"198.51.100.14"}})

	if !strings.Contains(out, secretPathLines("\t\t")) {
		t.Fatalf("отказ секретным путям не отрендерен внутри route:\n%s", out)
	}
	banAt := strings.Index(out, "respond @banned 403")
	secretAt := strings.Index(out, "abort @secret_path")
	denyAt := strings.Index(out, "respond @denied 403")
	authAt := strings.Index(out, "basic_auth {")
	faAt := strings.Index(out, "forward_auth ")
	proxyAt := strings.Index(out, "reverse_proxy supabase-studio-1:3000")
	if !(banAt != -1 && banAt < secretAt && secretAt < denyAt && denyAt < authAt && authAt < faAt && faAt < proxyAt) {
		t.Fatalf("порядок должен быть: бан → секретные пути → список → пароль → forward_auth → proxy:\n%s", out)
	}
}

// Бан без политик — это уже два вида проверок вместе с отказом секретным путям.
// Вне route штатный порядок Caddy ставит `abort` РАНЬШЕ `respond`, и
// забаненный сканер получал бы оборванное соединение вместо 403 — по логу
// нельзя было бы понять, что бан вообще применён.
func TestCaddyfileBanWithSecretPathsUsesRoute(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes:  []DesiredRoute{{Domain: "api.example.com", Service: "app", Port: 8000}},
	}}, ProxyOptions{DenyIPs: []string{"198.51.100.14"}})

	if !strings.Contains(out, "\troute {\n\t\t@banned remote_ip 198.51.100.14\n\t\trespond @banned 403\n"+secretPathLines("\t\t")) {
		t.Fatalf("бан и отказ секретным путям обязаны ехать в route-блоке в этом порядке:\n%s", out)
	}
}

// Заглушка без приложений ничего не проксирует — отказ там не нужен.
func TestCaddyfileStubHasNoSecretPathMatcher(t *testing.T) {
	if out := renderCaddyfile(nil, ProxyOptions{}); strings.Contains(out, "@secret_path") {
		t.Fatalf("матчер секретных путей попал в заглушку:\n%s", out)
	}
}

// Пустой список банов ничего не добавляет в конфиг: хост без блокировок
// обязан рендериться ровно так же, как до появления этой возможности.
func TestCaddyfileWithoutDenyListUnchanged(t *testing.T) {
	app := []DesiredApp{{
		Slug:    "supabase",
		Domain:  "api.example.com",
		Desired: "present",
		Routes:  []DesiredRoute{{Domain: "api.example.com", Service: "app", Port: 8000}},
	}}

	empty := renderCaddyfile(app, ProxyOptions{})
	nilList := renderCaddyfile(app, ProxyOptions{DenyIPs: nil})
	onlyBad := renderCaddyfile(app, ProxyOptions{DenyIPs: []string{"example.com"}})

	if empty != nilList || empty != onlyBad {
		t.Fatalf("конфиг без действующих банов отличается от прежнего:\n%s\n---\n%s", empty, onlyBad)
	}
	if strings.Contains(empty, "@banned") {
		t.Fatalf("матчер бана появился без записей:\n%s", empty)
	}
}
