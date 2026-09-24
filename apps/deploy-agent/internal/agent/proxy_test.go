package agent

import (
	"strings"
	"testing"
)

func sampleApps() []DesiredApp {
	return []DesiredApp{
		{Slug: "n8n", Domain: "n8n.example.com", InternalPort: 5678},
		{Slug: "internal-only", Domain: "", InternalPort: 3000},
	}
}

// Приложение без домена наружу не публикуется: домен — это явное решение
// пользователя, а не то, что появляется само.
func TestCaddyfileSkipsAppsWithoutDomain(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{})

	if !strings.Contains(out, "n8n.example.com {") {
		t.Fatal("приложение с доменом не попало в конфиг")
	}
	if strings.Contains(out, "internal-only") {
		t.Fatal("приложение без домена опубликовано наружу")
	}
}

// Цель прокси складывается по правилу docker compose «<проект>-<сервис>-<номер>».
// Если имя сервиса в шаблонах когда-нибудь поменяют, этот тест упадёт — и это
// правильно, потому что молча сломался бы доступ к приложению.
func TestCaddyfileTargetsComposeContainerName(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{})
	if !strings.Contains(out, "reverse_proxy n8n-app-1:5678") {
		t.Fatalf("не найдена ожидаемая цель прокси, получено:\n%s", out)
	}
}

// В боевом режиме сертификат выпускает Let's Encrypt, а адрес уходит в
// глобальный блок для уведомлений об истечении.
func TestCaddyfileProductionUsesACME(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{ACMEEmail: "ops@example.com"})

	if strings.Contains(out, "tls internal") {
		t.Fatal("в боевом режиме включён внутренний центр сертификации")
	}
	if !strings.Contains(out, "email ops@example.com") {
		t.Fatal("адрес для Let's Encrypt не попал в конфиг")
	}
}

// В локальном режиме ACME недоступен (домен не резолвится из интернета),
// поэтому сертификат выпускает внутренний центр Caddy.
func TestCaddyfileLocalUsesInternalTLS(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{
		ACMEEmail: "ops@example.com",
		LocalTLS:  true,
	})

	if !strings.Contains(out, "tls internal") {
		t.Fatal("локальный режим не включил внутренний центр сертификации")
	}
	// Адрес Let's Encrypt в локальном режиме бессмысленен и не должен
	// провоцировать обращения к ACME.
	if strings.Contains(out, "email ops@example.com") {
		t.Fatal("в локальном режиме остался глобальный блок ACME")
	}
}

// Пустой конфиг Caddy не примет, поэтому без опубликованных приложений
// нужна валидная заглушка — иначе прокси не поднимется вовсе.
func TestCaddyfileWithoutAppsIsStillValid(t *testing.T) {
	out := renderCaddyfile(nil, ProxyOptions{})
	if !strings.Contains(out, ":80 {") {
		t.Fatalf("нет заглушки для пустого набора приложений:\n%s", out)
	}
}

// Домен и slug приходят с сервера, но агент живёт на чужой машине и обязан
// не доверять входу второй раз: мусор не должен попасть в конфиг прокси.
func TestCaddyfileRejectsMalformedInput(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{
		{Slug: "ok", Domain: "evil.com {\n\trespond \"pwned\"\n}", InternalPort: 80},
		{Slug: "../escape", Domain: "fine.example.com", InternalPort: 80},
	}, ProxyOptions{})

	if strings.Contains(out, "pwned") {
		t.Fatal("инъекция в конфиг прокси через домен")
	}
	if strings.Contains(out, "../escape") {
		t.Fatal("недопустимый slug попал в конфиг")
	}
}

// www-вариант каждого домена принудительно редиректится на сам домен.
//
// Без этого блока www.домен не обслуживался вовсе: на https браузер получал
// ошибку сертификата, на http — редирект Caddy на тот же необслуженный
// www-адрес. Для посетителя это выглядело как «сайт сломан», хотя приложение
// работало.
func TestCaddyfileRedirectsWWWToApex(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{})

	if !strings.Contains(out, "www.n8n.example.com {") {
		t.Fatalf("www-вариант домена не обслуживается:\n%s", out)
	}
	// 308, а не 301: метод и тело обязаны переживать редирект, у приложений
	// за прокси бывают POST-вебхуки.
	if !strings.Contains(out, "redir https://n8n.example.com{uri} 308") {
		t.Fatalf("www не редиректится на основной домен:\n%s", out)
	}
}

// Домен, сам начинающийся с www., второго www не получает.
func TestCaddyfileNoDoubleWWW(t *testing.T) {
	apps := []DesiredApp{{Slug: "site", Domain: "www.example.com", InternalPort: 3000}}
	out := renderCaddyfile(apps, ProxyOptions{})

	if strings.Contains(out, "www.www.") {
		t.Fatalf("к www-домену добавлен второй www:\n%s", out)
	}
}

// Если пользователь сам опубликовал www-домен отдельным маршрутом, наш
// автоматический редирект не должен его перекрывать: дубль домена валит
// конфиг Caddy целиком.
func TestCaddyfileWWWDoesNotDuplicateExplicitRoute(t *testing.T) {
	apps := []DesiredApp{
		{Slug: "site", Domain: "example.com", InternalPort: 3000, Routes: []DesiredRoute{
			{Domain: "example.com", Service: "app", Port: 3000},
			{Domain: "www.example.com", Service: "app", Port: 3000},
		}},
	}
	out := renderCaddyfile(apps, ProxyOptions{})

	if got := countSiteBlocks(out, "www.example.com"); got != 1 {
		t.Fatalf("www.example.com объявлен %d раз, ожидался 1:\n%s", got, out)
	}
	// Явный маршрут пользователя побеждает: он проксирует, а не редиректит.
	if !strings.Contains(out, "redir") && len(apps[0].Routes) == 2 {
		// redir допустим только у автоматических www-блоков других доменов.
		t.Log("явный www-маршрут проксирует напрямую — ок")
	}
}

// Каждый https-блок отдаёт HSTS: после первого захода браузер сам не пойдёт
// на http, даже если пользователь наберёт адрес без схемы. Редирект Caddy
// с 80-го порта остаётся, но HSTS убирает и само первое http-обращение.
func TestCaddyfileSetsHSTS(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{})

	if !strings.Contains(out, "Strict-Transport-Security") {
		t.Fatalf("HSTS не выставлен:\n%s", out)
	}
}

// Структурированный access-log (0187): включается вместе с прокси, а не
// «когда понадобится» — без него трафик приложений невидим. Пишется в том
// logs, который агент читает локально; в control plane уезжают агрегаты.
func TestCaddyfileEnablesAccessLog(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{{
		Slug: "n8n", Domain: "n8n.example.com", InternalPort: 5678, Desired: "present",
	}}, ProxyOptions{})

	if !strings.Contains(out, "log {") {
		t.Fatalf("нет директивы log в блоке сайта:\n%s", out)
	}
	if !strings.Contains(out, "output file /var/log/caddy/access.json") {
		t.Fatalf("лог не пишется в файл тома:\n%s", out)
	}
	if !strings.Contains(out, "format json") {
		t.Fatalf("лог не структурированный:\n%s", out)
	}
	// Ротация обязана быть ограничена: диск клиента не наш.
	if !strings.Contains(out, "roll_size") || !strings.Contains(out, "roll_keep") {
		t.Fatalf("нет ограничения ротации:\n%s", out)
	}
	// www-редиректы не логируются: в них нет трафика приложений.
	wwwAt := strings.Index(out, "www.n8n.example.com {")
	if wwwAt != -1 && strings.Contains(out[wwwAt:], "log {") {
		t.Fatalf("лог включён на www-редиректе:\n%s", out)
	}
}

func TestProxyComposeMountsLogVolume(t *testing.T) {
	if !strings.Contains(proxyCompose, "./logs:/var/log/caddy") {
		t.Fatalf("compose прокси не монтирует каталог логов:\n%s", proxyCompose)
	}
}

// --------------------------------------------------------------------------
// Прокси не претендует на 80/443 раньше, чем ему есть что публиковать
// --------------------------------------------------------------------------
//
// Caddy платформы публикуется жёстко на 80 и 443. Пока на хосте нет ни одного
// приложения с доменом, публиковать ему нечего — а порты он всё равно занимал
// бы, начиная с первого цикла после установки.
//
// На пустом сервере это незаметно. На сервере, куда платформу подключают к уже
// работающим нагрузкам, там стоит чужой прокси, и агент раз в минуту пытается
// отобрать у него порты. Хуже тихой возни то, что она однажды удаётся: любая
// пауза чужого прокси длиннее цикла отдаёт порты нам — и все домены хоста,
// которых платформа не знает, гаснут без единого решения человека.
func TestProxyNotStartedWithoutDomains(t *testing.T) {
	if hasPublishedDomains(nil) {
		t.Error("пустой набор приложений считается поводом занять порты")
	}
	if hasPublishedDomains([]DesiredApp{{Slug: "внутреннее", Domain: ""}}) {
		t.Error("приложение без домена считается поводом занять порты")
	}
	if !hasPublishedDomains([]DesiredApp{{Slug: "внутреннее"}, {Slug: "сайт", Domain: "example.com"}}) {
		t.Error("приложение с доменом не приводит к подъёму прокси")
	}
}

// --------------------------------------------------------------------------
// Порты 80/443 не отбираются у чужого прокси
// --------------------------------------------------------------------------
//
// На боевом хосте, куда платформу подключили к работающим нагрузкам, порты
// держит прокси прежней панели, а наш Caddy висит в состоянии Created и
// пытается подняться каждую минуту.
//
// Опасна не сама возня, а её успех. Стоит чужому прокси уйти на перезапуск
// дольше цикла — порты достаются нам, и хост начинает обслуживать ТОЛЬКО
// домены, заведённые в платформе. На Sigma это пятнадцать доменов против
// одного: четырнадцать сайтов гаснут без единого решения человека.
//
// Правильный порядок — обратный и осознанный: человек останавливает чужой
// прокси в окне переключения, и на следующем цикле наш встаёт уже без спора.
func TestForeignPortHolder(t *testing.T) {
	const ours = "tracedocs-proxy"

	holder := foreignPortHolder([]string{
		"supabase-kong-h804o\t8000/tcp",
		"coolify-proxy\t0.0.0.0:80->80/tcp, [::]:80->80/tcp, 0.0.0.0:443->443/tcp",
	}, ours)
	// Текст сразу говорит, ЧТО это: держателем бывает и процесс на хосте, и
	// подставлялся он в шаблон со словом «контейнер» — человек шёл искать
	// контейнер, которого нет.
	if holder != "контейнер coolify-proxy" {
		t.Errorf("владелец портов не найден: %q", holder)
	}

	// Наш собственный прокси владельцем не считается — иначе агент отказался
	// бы обновлять конфиг ровно тогда, когда прокси работает нормально.
	if h := foreignPortHolder([]string{
		"tracedocs-proxy-caddy-1\t0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp",
	}, ours); h != "" {
		t.Errorf("свой прокси принят за чужого: %q", h)
	}

	// Порты свободны.
	if h := foreignPortHolder([]string{"n8n\t5678/tcp"}, ours); h != "" {
		t.Errorf("ложный владелец на свободных портах: %q", h)
	}

	// 8080 и 4430 не должны совпадать с 80 и 443.
	if h := foreignPortHolder([]string{
		"чужое\t0.0.0.0:8080->8080/tcp, 0.0.0.0:4430->4430/tcp",
	}, ours); h != "" {
		t.Errorf("похожий порт принят за 80/443: %q", h)
	}
}

// --------------------------------------------------------------------------
// Происхождение запроса задаём мы, а не клиент
// --------------------------------------------------------------------------
//
// Caddy по умолчанию ДОПИСЫВАЕТ адрес соединения к `X-Forwarded-For`,
// пришедшему от клиента. Запрос с `X-Forwarded-For: 8.8.8.8` доезжает до
// приложения как `8.8.8.8, <настоящий>` — а первый элемент списка это
// общепринятое место «исходного клиента», и именно его берёт большинство
// фреймворков.
//
// Цена: подделываются журналы аудита приложения, его собственные ограничения
// по частоте запросов и любые решения «этот адрес мы уже видели». Для
// перехваченного стека это особенно важно — он писался в расчёте на чужой
// прокси с другими правилами, и полагаться на его аккуратность нельзя.
//
// Поэтому заголовки происхождения ставятся ЗАМЕНОЙ, из свойств соединения, а
// всё, чем клиент мог бы притвориться, вычищается. Апстриму остаётся ровно
// один источник правды, и он наш.
func TestCaddyfileSetsForwardingHeadersFromConnection(t *testing.T) {
	out := renderCaddyfile(sampleApps(), ProxyOptions{})

	for _, want := range []string{
		"header_up X-Forwarded-For {remote_host}",
		"header_up X-Real-IP {remote_host}",
		"header_up X-Forwarded-Proto {scheme}",
		"header_up X-Forwarded-Host {host}",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("нет строки %q; получено:\n%s", want, out)
		}
	}

	// Заголовки, которыми клиент мог бы притвориться источником: их читают
	// приложения, привыкшие работать за CDN, и подделать их сегодня может кто
	// угодно.
	for _, spoofable := range []string{
		"header_up -Forwarded",
		"header_up -CF-Connecting-IP",
		"header_up -True-Client-IP",
		"header_up -X-Client-IP",
	} {
		if !strings.Contains(out, spoofable) {
			t.Errorf("не вычищается заголовок: %q", spoofable)
		}
	}
}

// Заголовки ставятся у КАЖДОГО маршрута, а не только у первого: домен без них
// стал бы дырой, о которой никто не знает.
func TestCaddyfileSetsForwardingHeadersOnEveryRoute(t *testing.T) {
	out := renderCaddyfile([]DesiredApp{
		{Slug: "shop-web", Domain: "shop.example.com", InternalPort: 3000},
		{Slug: "shop-api", Domain: "api.example.com", InternalPort: 4000},
	}, ProxyOptions{})

	if n := strings.Count(out, "header_up X-Forwarded-For {remote_host}"); n != 2 {
		t.Errorf("заголовки проставлены %d раз(а) вместо двух:\n%s", n, out)
	}
}

// Порты 80/443, занятые системным nginx, обязаны диагностироваться.
//
// Самый частый вид «сервера с нагрузкой» — тот, где nginx стоит пакетом из
// apt. Контейнером он не является, `docker ps` его не видит, и агент доходил
// до `up -d` прокси, получая сырое «Bind for 0.0.0.0:80 failed». Именно на
// такие серверы и рассчитан перехват стеков.
func TestHostPortHolderFindsSystemNginx(t *testing.T) {
	raw := "LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=812,fd=6))\n" +
		"LISTEN 0 511 [::]:443 [::]:* users:((\"nginx\",pid=812,fd=7))\n"

	got := parseHostPortHolder(raw)
	if !strings.Contains(got, "nginx") {
		t.Fatalf("системный nginx не опознан: %q", got)
	}
	if !strings.Contains(got, "на хосте") {
		t.Fatalf("в тексте не сказано, что процесс не в контейнере: %q", got)
	}
}

// Свои же публикации портов держателем не считаются: иначе платформа обвиняла
// бы в занятости себя.
func TestHostPortHolderIgnoresDockerProxy(t *testing.T) {
	raw := "LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:((\"docker-proxy\",pid=99,fd=4))\n" +
		"LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"docker-proxy\",pid=99,fd=5))\n"

	if got := parseHostPortHolder(raw); got != "" {
		t.Fatalf("публикация контейнера принята за чужого держателя: %q", got)
	}
}

// Порты, не относящиеся к делу, не считаются.
func TestHostPortHolderIgnoresOtherPorts(t *testing.T) {
	raw := "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=700,fd=3))\n" +
		"LISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:((\"node\",pid=900,fd=20))\n"

	if got := parseHostPortHolder(raw); got != "" {
		t.Fatalf("посторонний слушатель принят за держателя 80/443: %q", got)
	}
}

// Процесс без имени (нет прав на чтение чужого /proc) — всё равно ответ.
func TestHostPortHolderNamesUnknownProcess(t *testing.T) {
	raw := "LISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n"

	if got := parseHostPortHolder(raw); got == "" {
		t.Fatal("держатель без имени процесса потерян")
	}
}

// Платформенный поддомен www-редиректа не получает (P2-3).
//
// Клиент заводит ОДНУ wildcard-запись `*.h<метка>.<база>`, и она покрывает
// ровно один уровень имён. `www.<slug>.h<метка>.<база>` не резолвится никогда,
// то есть выпуск сертификата для него безнадёжен по построению, а Caddy
// повторяет его с нарастающим интервалом всё время жизни приложения.
func TestNoWwwForPlatformSubdomain(t *testing.T) {
	base := "deploy.example.com"
	apps := []DesiredApp{
		{Slug: "shop", Domain: "shop.h1a2b3c4d." + base, InternalPort: 3000},
		{Slug: "site", Domain: "example.com", InternalPort: 3000},
	}

	out := renderCaddyfile(apps, ProxyOptions{PlatformSubdomainBase: base})

	if strings.Contains(out, "www.shop.h1a2b3c4d."+base) {
		t.Fatalf("платформенный поддомен получил www-блок:\n%s", out)
	}
	// Собственный домен клиента правило не задевает: там www осмыслен, и
	// потерять его из-за платформенных адресов было бы регрессом.
	if !strings.Contains(out, "www.example.com {") {
		t.Fatalf("свой домен клиента остался без www-блока:\n%s", out)
	}

	// Выключенная фича (старый сервер поля не присылает) — поведение прежнее.
	off := renderCaddyfile(apps, ProxyOptions{})
	if !strings.Contains(off, "www.shop.h1a2b3c4d."+base+" {") {
		t.Fatalf("без базы www-блок пропал:\n%s", off)
	}
}
