package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
)

// Обратный прокси и сертификаты.
//
// Приложения не публикуют порты наружу — снаружи их видит только Caddy, и он
// же получает сертификаты Let's Encrypt автоматически, по факту появления
// домена в конфиге. Отдельного шага «выпустить сертификат» нет: Caddy делает
// это при первом обращении к имени и продлевает сам.
//
// Почему Caddy, а не Traefik (как в Coolify): для нашей задачи конфиг сводится
// к «домен → контейнер», и Caddy описывает это тремя строками без меток на
// контейнерах и без доступа к docker.sock. Прокси, которому не нужен сокет
// Docker, — это на одну root-эквивалентную точку меньше на хосте клиента.

// EdgeNetwork — общая сеть прокси и приложений. Имя зафиксировано и совпадает
// с тем, что объявлено внешним в шаблонах каталога. Значение — из политики
// compose: единственная внешняя сеть, которую она пропускает, обязана быть той
// же, к которой прокси подключает стеки.
const EdgeNetwork = composeguard.EdgeNetwork

// safeACMEEmail — адрес попадает в конфиг прокси, поэтому проверяется отдельно.
//
// Раньше здесь по ошибке использовалась регулярка имён переменных окружения:
// она не допускает точку, и любой нормальный адрес молча отбраковывался —
// уведомления об истечении сертификата не приходили бы никогда. Полноценная
// валидация email тут не нужна, важно лишь, чтобы строка не могла разорвать
// конфиг: без пробелов, переводов строк и фигурных скобок.
var safeACMEEmail = regexp.MustCompile(`^[^\s{}@]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// Конфиг монтируется КАТАЛОГОМ, а не отдельным файлом. Это не стилистика.
//
// Мы пишем Caddyfile атомарно: временный файл рядом и переименование. У
// переименования новый inode, а bind-mount отдельного файла в Docker привязан
// к inode исходного — контейнер после подмены продолжает видеть СТАРЫЙ файл.
//
// На первом же боевом прогоне это выглядело так: на хосте лежит конфиг с
// доменом, `caddy reload` отрабатывает без ошибок, отметка о загрузке
// записана, а Caddy обслуживает заглушку и пишет в лог «server is listening
// only on the HTTP port, so no automatic HTTPS». Сертификат не выпускался, и
// ни одна проверка на это не указывала.
//
// Монтирование каталога переживает подмену файла внутри него.
const proxyCompose = `name: tracedocs-proxy

services:
  caddy:
    # Тег + дайджест, а не один тег.
    #
    # Установщик прописывает mirror.gcr.io зеркалом реестра, и разрешение
    # «тег → дайджест» делает ЗЕРКАЛО. Скомпрометированное или враждебное
    # зеркало отдало бы под этим тегом что угодно, и docker бы это принял:
    # дайджест он сверяет с тем манифестом, который получил, то есть сам с
    # собой. Явный дайджест снимает вопрос — образ не тот, значит запуск не
    # состоится. Тег оставлен рядом для читаемости.
    image: caddy:2.8-alpine@sha256:af32e97399febea808609119bb21544d0265c58a02836576e32a2d082c262c17
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./conf:/etc/caddy:ro
      # Структурированный access-log (0187): агент читает его ЛОКАЛЬНО и шлёт
      # в платформу только агрегаты — сырой лог с URL и адресами хост не
      # покидает, это данные клиента.
      - ./logs:/var/log/caddy
      - caddy-data:/data
      - caddy-config:/config
    networks:
      - edge
    security_opt:
      - no-new-privileges:true

volumes:
  caddy-data:
  caddy-config:

networks:
  edge:
    external: true
    name: ` + EdgeNetwork + `
`

func (p Paths) proxyDir() string { return filepath.Join(p.WorkDir, "proxy") }

// isPlatformSubdomain — адрес выдан платформой из её собственной зоны.
//
// Сравнение по суффиксу, а не по числу меток: база задаётся окружением
// платформы и бывает любой глубины. Совпадение с самой базой не считается —
// корневой домен платформы никто как приложение не публикует, а если бы
// опубликовал, www для него как раз осмыслен.
func isPlatformSubdomain(domain, base string) bool {
	if base == "" {
		return false
	}
	return strings.HasSuffix(domain, "."+base)
}

// ProxyOptions — настройки обратного прокси.
type ProxyOptions struct {
	// ACMEEmail — адрес для уведомлений Let's Encrypt об истечении сертификата.
	ACMEEmail string
	// PlatformBaseURL — адрес платформы для forward_auth (0188): subrequest
	// проверки доступа уходит туда же, куда агент ходит за состоянием.
	// Пустое значение — маршруты с forward_auth не публикуются (fail closed).
	PlatformBaseURL string
	// LocalTLS переключает выпуск сертификата на собственный центр Caddy.
	//
	// Нужно для прогона на localhost: настоящий ACME требует, чтобы домен
	// резолвился из интернета в этот хост и 80/443 были доступны снаружи.
	// За NAT это невозможно, и без такого режима Caddy будет бесконечно
	// пытаться получить сертификат и падать в ошибку.
	//
	// В бою включать нельзя: браузер такому сертификату не верит.
	LocalTLS bool
	// DenyIPs — заблокированные на хосте адреса и подсети (0204). Список
	// хостовой: он применяется ко ВСЕМ опубликованным доменам, потому что
	// сканер стучится во все сразу, а не в один маршрут.
	DenyIPs []string
	// PlatformSubdomainBase — база платформенных поддоменов (P2-3).
	//
	// Для адреса под ней www-блок не выпускается. Причина не в удобстве:
	// платформенный адрес имеет вид `<slug>.h<метка>.<база>` и держится ОДНОЙ
	// wildcard-записью `*.h<метка>.<база>`, которая покрывает ровно один
	// уровень имён. `www.<slug>.h<метка>.<база>` не резолвится ни при каких
	// условиях, и Caddy повторяет заведомо безнадёжный выпуск сертификата, пока
	// приложение существует.
	//
	// Пустое значение отключает правило целиком: старый сервер поля не
	// присылает, и терять www-редирект для обычных доменов из-за этого нельзя.
	PlatformSubdomainBase string
}

// Потолок записей в блокировке. Сервер держит свой (256 на хост), этот —
// последний рубеж: матчер remote_ip рендерится одной строкой, и её длина
// должна оставаться предсказуемой, что бы ни прислал сервер.
const maxDenyEntries = 512

// sanitizeDenyIPs приводит список блокировки к пригодному для конфига виду.
//
// Негодная запись здесь ПРОПУСКАЕТСЯ, а не отменяет публикацию — в отличие от
// политик маршрута, где неизвестное значение закрывает маршрут целиком (см.
// resolveRoutePolicies). Асимметрия намеренная: цена ошибки разная. Не
// применённая политика оставляет админку открытой миру; не применённый бан
// оставляет сканер работать ещё один цикл. Гасить рабочий сайт клиента из-за
// испорченной записи в списке банов — несоразмерная цена.
func sanitizeDenyIPs(entries []string) []string {
	if len(entries) == 0 {
		return nil
	}
	out := make([]string, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, raw := range entries {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if !validIPListEntry(entry) {
			fmt.Fprintf(os.Stderr, "блокировка: запись %q негодна, пропущена\n", raw)
			continue
		}
		if seen[entry] {
			continue
		}
		seen[entry] = true
		out = append(out, entry)
		if len(out) >= maxDenyEntries {
			fmt.Fprintf(os.Stderr, "блокировка: больше %d записей, лишние отброшены\n", maxDenyEntries)
			break
		}
	}
	return out
}

// hasPublishedDomains — есть ли хоть одно приложение, которое публикуется
// наружу. Приложение без домена доступно только внутри хоста, и прокси для
// него не нужен.
func hasPublishedDomains(apps []DesiredApp) bool {
	for _, app := range apps {
		if strings.TrimSpace(app.Domain) != "" {
			return true
		}
		for _, r := range app.Routes {
			if strings.TrimSpace(r.Domain) != "" {
				return true
			}
		}
	}
	return false
}

// publishedHTTPPorts — публикация 80 или 443 в строке `docker ps`.
//
// Именно `:80->`, а не «содержит 80»: `0.0.0.0:8080->8080/tcp` — это чужой
// сервис на своём порту, и принять его за держателя означало бы навсегда
// отказаться поднимать прокси на хосте, где такой сервис просто есть.
var publishedHTTPPorts = regexp.MustCompile(`:(80|443)->`)

// foreignPortHolder — контейнер НЕ НАШЕГО прокси, занявший 80 или 443.
//
// lines — строки вида "имя\tпорты" из `docker ps`; ourProject — имя
// compose-проекта нашего прокси.
func foreignPortHolder(lines []string, ourProject string) string {
	for _, line := range lines {
		name, ports, found := strings.Cut(strings.TrimSpace(line), "\t")
		if !found || name == "" {
			continue
		}
		if strings.HasPrefix(name, ourProject) {
			continue
		}
		if publishedHTTPPorts.MatchString(ports) {
			return "контейнер " + name
		}
	}
	return ""
}

// proxyPortsHeldBy спрашивает, кто держит 80 и 443, — сперва docker, потом хост.
func proxyPortsHeldBy(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
	cmd.Env = dockerEnv()
	out, err := cmd.Output()
	if err == nil {
		if holder := foreignPortHolder(
			strings.Split(strings.TrimSpace(string(out)), "\n"), proxyProjectName); holder != "" {
			return holder
		}
	}
	// Не смогли спросить docker — не повод отказываться работать: без этой
	// проверки агент жил всё время до сих пор.
	return hostPortHolder(ctx)
}

// hostPortHolder — держатель 80/443 на уровне ХОСТА, а не docker.
//
// Самый частый вид «сервера с нагрузкой» — тот, где nginx или apache стоят
// пакетом из apt. Контейнерами они не являются, `docker ps` их не видит вовсе,
// и агент доходил до `up -d` прокси, получая от docker сырое «Bind for
// 0.0.0.0:80 failed: port is already allocated». Именно на такие серверы и
// рассчитан перехват стеков, то есть это не редкий случай, а целевой.
func hostPortHolder(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, "ss", "-lntpH")
	out, err := cmd.Output()
	if err != nil {
		// ss нет (минимальный образ) — молчим: догадка хуже отсутствия ответа.
		return ""
	}
	return parseHostPortHolder(string(out))
}

// listenerProcess вытаскивает имя процесса из поля users:(("nginx",pid=1,fd=6)).
var listenerProcess = regexp.MustCompile(`users:\(\("([^"]+)"`)

// parseHostPortHolder разбирает вывод `ss -lntpH`.
//
// Свои же слушатели пропускаем: docker-proxy и containerd публикуют порты
// контейнеров, и назвать их держателем значило бы обвинить платформу в том,
// что она сама и сделала. Ветку docker обрабатывает foreignPortHolder выше.
func parseHostPortHolder(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[3]
		port := local[strings.LastIndex(local, ":")+1:]
		if port != "80" && port != "443" {
			continue
		}
		name := ""
		if m := listenerProcess.FindStringSubmatch(line); m != nil {
			name = m[1]
		}
		if name == "docker-proxy" || name == "containerd" || name == "dockerd" {
			continue
		}
		if name == "" {
			name = "неизвестный процесс"
		}
		return name + " (на хосте, не в контейнере)"
	}
	return ""
}

// proxyProjectName — имя compose-проекта прокси платформы (см. proxyCompose).
const proxyProjectName = "tracedocs-proxy"

// EnsureProxy приводит конфиг прокси в соответствие с набором приложений.
//
// Домены собираются из желаемого состояния: приложение без домена наружу не
// публикуется вовсе и остаётся доступным только внутри хоста.
func EnsureProxy(ctx context.Context, p Paths, apps []DesiredApp, opts ProxyOptions) error {
	// Порты 80 и 443 занимаем только тогда, когда есть что публиковать.
	//
	// Прокси публикуется жёстко на 80:80 и 443:443, и раньше поднимался с
	// первого же цикла — до всякого приложения. На пустом сервере это
	// незаметно; на сервере, куда платформу подключают к работающим нагрузкам,
	// порты держит чужой прокси, и агент раз в минуту пытается их отобрать.
	// Опасна не возня, а её успех: любая пауза чужого прокси длиннее цикла
	// отдаёт порты нам, и все домены хоста, которых платформа не знает, гаснут
	// без единого решения человека.
	//
	// Сеть edge тоже создаём только здесь: без приложений она не нужна, а
	// лишняя сеть на хосте с исчерпанными адресными пулами — отдельная беда.
	//
	// Условие именно «прокси ЕЩЁ НЕ поднимали», а не просто «доменов нет».
	// Иначе снятие последнего домена оставляло бы работающий прокси со старым
	// конфигом: сайт продолжал бы обслуживаться после того, как его сняли с
	// публикации, — тихо и ровно до перезапуска контейнера.
	dir := p.proxyDir()
	if !hasPublishedDomains(apps) {
		if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err != nil {
			return nil
		}
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("не удалось создать каталог прокси: %w", err)
	}

	if err := ensureEdgeNetwork(ctx); err != nil {
		return err
	}

	// Конфиг лежит в отдельном подкаталоге: внутрь контейнера монтируется
	// именно он, и compose-файл прокси туда не попадает.
	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0o750); err != nil {
		return fmt.Errorf("не удалось создать каталог конфига прокси: %w", err)
	}

	caddyfile := renderCaddyfile(apps, opts)
	path := filepath.Join(confDir, "Caddyfile")

	// compose прокси пишем безусловно, а не только вместе с Caddyfile: новая
	// версия агента может нести другой образ или лимиты, и на хостах с
	// неизменившимся набором доменов эта правка не доехала бы никогда.
	if err := writeFileAtomic(filepath.Join(dir, "docker-compose.yml"), []byte(proxyCompose), 0o640); err != nil {
		return fmt.Errorf("не удалось записать compose прокси: %w", err)
	}

	if err := writeFileAtomic(path, []byte(caddyfile), 0o640); err != nil {
		return fmt.Errorf("не удалось записать Caddyfile: %w", err)
	}
	// Базовая линия сверки дрейфа (ADR-0078) — отметка ЗАПИСАННОГО, рядом с
	// записью. proxy-loaded.sha256 для неё не годится: при занятых портах или
	// неудачном reload файл уже новый, а та отметка старая.
	want := sha256.Sum256([]byte(caddyfile))
	wantHex := hex.EncodeToString(want[:])
	noteProxyWritten(p, wantHex)

	// Порты 80 и 443 у чужого прокси не отбираем.
	//
	// Конфиг на диске к этому моменту уже обновлён — это дёшево и полезно: в
	// окне переключения наш Caddy встанет сразу с актуальными доменами. А вот
	// поднимать его, пока порты заняты чужим, нельзя, и дело не в бесполезных
	// попытках раз в минуту. Дело в том, что однажды попытка удаётся: стоит
	// чужому прокси уйти на перезапуск дольше цикла — порты достаются нам, и
	// хост начинает обслуживать ТОЛЬКО домены, заведённые в платформе. На
	// боевом сервере это пятнадцать доменов против одного, и решения человека
	// здесь нет вовсе.
	//
	// Порядок переключения обратный и осознанный: человек останавливает чужой
	// прокси, и на следующем цикле наш встаёт уже без спора.
	if holder := proxyPortsHeldBy(ctx); holder != "" {
		return fmt.Errorf(
			"порты 80 и 443 занимает %s — прокси платформы не поднимается. "+
				"Это не сбой: пока чужой прокси работает, забрать у него порты значило бы "+
				"погасить все домены хоста, которых нет в платформе. Остановите его в окне "+
				"переключения, и прокси поднимется сам в течение минуты", holder)
	}

	if err := ensureProxyRunning(ctx, p, dir); err != nil {
		return err
	}

	// Отметку об успешно ЗАГРУЖЕННОМ конфиге держим отдельно от файла.
	//
	// Раньше признаком «применено» был сам Caddyfile на диске: если конфиг
	// совпадал с желаемым, агент выходил рано. Но файл пишется ДО перезагрузки,
	// и стоило reload не удаться (контейнер только что создан и админский API
	// ещё не слушает, Caddy перезапускается), как на следующем цикле файл уже
	// совпадал — и повтор не происходил НИКОГДА. Caddy держал старую
	// конфигурацию до перезапуска контейнера: домен не обслуживался, сертификат
	// не выпускался, а в логах всё выглядело спокойно.
	loadedPath := filepath.Join(p.StateDir, "proxy-loaded.sha256")

	if loaded, err := os.ReadFile(loadedPath); err == nil && string(loaded) == wantHex {
		return nil
	}

	if out, err := dockerCompose(ctx, dir, "exec", "-T", "caddy",
		"caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"); err != nil {
		return fmt.Errorf("не удалось перечитать конфиг прокси: %w: %s", err, tail(out, 400))
	}

	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(loadedPath, []byte(wantHex), 0o600); err != nil {
		// Отметку не записали — на следующем цикле будет лишний reload.
		// Он безопасен, поэтому не считаем это ошибкой применения.
		fmt.Fprintf(os.Stderr, "конфиг прокси загружен, но отметка не сохранена: %v\n", err)
	}
	return nil
}

func ensureProxyRunning(ctx context.Context, p Paths, dir string) error {
	if out, err := dockerCompose(ctx, dir, "up", "-d"); err != nil {
		// Именно этот отказ и был поводом настраивать зеркало: первый боевой
		// прогон встал на 429 при загрузке caddy — то есть платформа не смогла
		// поднять собственный прокси. Подсказка обязана быть здесь в первую
		// очередь.
		return fmt.Errorf("не удалось поднять прокси: %w: %s", err,
			explainPullLimit(ctx, p, tail(out, 600)))
	}
	return nil
}

// DesiredRoute — один опубликованный наружу сервис приложения.
//
// Появился ради стеков, у которых наружу смотрит не одна дверь: у Supabase это
// шлюз API и панель управления, и держать их на одном домене можно, а разделить
// раньше было нечем — модель знала ровно одну пару «домен + порт».
type DesiredRoute struct {
	Domain string `json:"domain"`
	// Service — имя сервиса в compose. Из него складывается имя контейнера.
	Service string `json:"service"`
	Port    int    `json:"port"`
	// Policies — политики доступа на маршруте. Пустой список — маршрут
	// открыт; так живут все маршруты, созданные до этого поля.
	Policies []RoutePolicy `json:"policies"`
}

// RoutePolicy — одна политика доступа опубликованного маршрута.
//
// Агент понимает два типа. "basic_auth" — пара «имя — bcrypt-хеш» для блока
// basic_auth в Caddyfile; хеш считает сервер, пароль открытым текстом на хост
// не приезжает вовсе. "ip_allowlist" — список адресов и подсетей для матчера
// remote_ip: всем остальным отвечается 403.
type RoutePolicy struct {
	Type         string   `json:"type"`
	Username     string   `json:"username,omitempty"`
	PasswordHash string   `json:"passwordHash,omitempty"`
	Cidrs        []string `json:"cidrs,omitempty"`
}

// Имя пользователя и хеш уезжают в конфиг Caddy, то есть это недоверенный
// вход: пробел или скобка разорвали бы конфиг, а Caddy отвергает его целиком —
// гасли бы все сайты хоста.
var safeBasicAuthUser = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var safeBcryptHash = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

// Записи списков IP — тоже недоверенный вход в конфиг Caddy. Символьный фильтр
// отсекает всё, что могло бы разорвать конфиг; разбор адреса делает net.
// Ведущие нули запрещены отдельно: «01.2.3.4» кто-то прочитает как
// восьмеричное, и список будет означать разное для разных читателей.
//
// Проверка общая для списка допущенных (ip_allowlist, 0179) и списка
// заблокированных (0204): форма записи у них одна, расходятся они только в
// том, что делать с негодной записью.
var safeIPListEntry = regexp.MustCompile(`^[0-9a-f:./]{1,64}$`)
var ipListLeadingZero = regexp.MustCompile(`(^|[./])0[0-9]`)

func validIPListEntry(entry string) bool {
	if !safeIPListEntry.MatchString(entry) || ipListLeadingZero.MatchString(entry) {
		return false
	}
	if strings.Contains(entry, "/") {
		_, _, err := net.ParseCIDR(entry)
		return err == nil
	}
	return net.ParseIP(entry) != nil
}

// routeAccess — проверенные политики маршрута, готовые к рендеру.
type routeAccess struct {
	// basicAuth — пары «имя — bcrypt-хеш» для блока basic_auth.
	basicAuth []RoutePolicy
	// allowlist — записи для матчера remote_ip: пускаются только эти адреса.
	allowlist []string
	// forwardAuth — вход по личности Scopework (0188): subrequest платформе.
	forwardAuth bool
}

// kinds — сколько видов политик активно: от этого зависит, нужен ли
// route-блок с явным порядком.
func (a routeAccess) kinds() int {
	n := 0
	if len(a.allowlist) > 0 {
		n++
	}
	if len(a.basicAuth) > 0 {
		n++
	}
	if a.forwardAuth {
		n++
	}
	return n
}

// resolveRoutePolicies проверяет политики маршрута и возвращает применимые.
//
// ok=false — маршрут публиковать НЕЛЬЗЯ. Правило жёсткое: политика есть, но
// негодна или неизвестна агенту — маршрут не публикуется вовсе. Опубликовать
// админ-панель БЕЗ защиты из-за испорченного значения или из-за того, что
// новый сервер прислал политику, которую этот агент ещё не понимает, — худший
// из исходов; недоступность маршрута — меньшая цена.
func resolveRoutePolicies(r DesiredRoute) (access routeAccess, ok bool) {
	for _, p := range r.Policies {
		switch p.Type {
		case "basic_auth":
			if !safeBasicAuthUser.MatchString(p.Username) || !safeBcryptHash.MatchString(p.PasswordHash) {
				return routeAccess{}, false
			}
			access.basicAuth = append(access.basicAuth, p)
		case "ip_allowlist":
			// Пустой список — не «открыто всем» и не «закрыто всем»: обе
			// трактовки одинаково правдоподобны, значит угадывать нельзя.
			if len(p.Cidrs) == 0 || len(p.Cidrs) > 64 {
				return routeAccess{}, false
			}
			for _, entry := range p.Cidrs {
				if !validIPListEntry(entry) {
					return routeAccess{}, false
				}
			}
			access.allowlist = append(access.allowlist, p.Cidrs...)
		case "forward_auth":
			access.forwardAuth = true
		default:
			return routeAccess{}, false
		}
	}
	return access, true
}

// safeServiceName — имя сервиса уезжает в адрес назначения в конфиге Caddy.
// Пробел или скобка в нём разорвали бы конфиг, а Caddy не принимает конфиг
// частично: ошибка в одной строке гасит ВСЕ сайты хоста.
var safeServiceName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)

// effectiveRoutes — маршруты приложения в едином виде.
//
// Пустой список означает старый формат ответа сервера: один домен на сервис
// `app`. Агент обновляется отдельно от сервера, и версия без этой
// совместимости погасила бы все сайты хоста до следующего обновления.
func effectiveRoutes(a DesiredApp) []DesiredRoute {
	if len(a.Routes) > 0 {
		return a.Routes
	}
	if a.Domain == "" {
		return nil
	}
	return []DesiredRoute{{Domain: a.Domain, Service: "app", Port: a.InternalPort}}
}

// renderCaddyfile собирает конфиг из маршрутов приложений.
//
// Имя контейнера складывается по правилу docker compose «<проект>-<сервис>-<номер>».
// Проект задан в шаблоне как ${APP_SLUG}, поэтому цель прокси —
// `<slug>-<сервис>-1`. Эта связка — договорённость между шаблоном и прокси:
// сервис, названный в маршруте, обязан существовать в compose под тем же
// именем.
func renderCaddyfile(apps []DesiredApp, opts ProxyOptions) string {
	var b strings.Builder
	b.WriteString("# Файл создан агентом Scopework. Правки перезаписываются.\n")
	if opts.LocalTLS {
		b.WriteString("# РЕЖИМ ЛОКАЛЬНОГО ПРОГОНА: сертификаты выпускает внутренний\n")
		b.WriteString("# центр Caddy, браузер им не доверяет. В бою так быть не должно.\n")
	}
	b.WriteString("\n")

	denyList := sanitizeDenyIPs(opts.DenyIPs)

	if !opts.LocalTLS && safeACMEEmail.MatchString(opts.ACMEEmail) {
		// Адрес нужен Let's Encrypt для уведомлений об истечении сертификата.
		fmt.Fprintf(&b, "{\n\temail %s\n}\n\n", opts.ACMEEmail)
	}

	type target struct {
		domain    string
		container string
		port      int
		access    routeAccess
	}

	published := make([]target, 0, len(apps))
	for _, a := range apps {
		// Остановленное приложение наружу не публикуем: маршрут в снятый
		// стек отдавал бы ошибку, а Caddy продолжал бы продлевать для него
		// сертификат.
		if !a.ShouldRun() || !safeSlug.MatchString(a.Slug) {
			continue
		}
		for _, r := range effectiveRoutes(a) {
			// Каждое значение проверяется отдельно: один негодный маршрут не
			// повод оставить приложение без публикации целиком.
			if !safeDomain.MatchString(r.Domain) || !safeServiceName.MatchString(r.Service) {
				continue
			}
			if r.Port <= 0 || r.Port > 65535 {
				continue
			}
			access, ok := resolveRoutePolicies(r)
			if !ok {
				// Fail closed: маршрут с политикой, которую агент не может
				// применить, не публикуется. См. resolveRoutePolicies.
				fmt.Fprintf(os.Stderr, "маршрут %s: политика доступа негодна или неизвестна, маршрут не опубликован\n", r.Domain)
				continue
			}
			if access.forwardAuth && opts.PlatformBaseURL == "" {
				// Тот же fail closed: без адреса платформы subrequest слать
				// некуда, а публиковать защищённый маршрут открытым нельзя.
				fmt.Fprintf(os.Stderr, "маршрут %s: forward_auth без адреса платформы, маршрут не опубликован\n", r.Domain)
				continue
			}
			published = append(published, target{
				domain:    r.Domain,
				container: a.Slug + "-" + r.Service + "-1",
				port:      r.Port,
				access:    access,
			})
		}
	}
	sort.Slice(published, func(i, j int) bool {
		if published[i].domain != published[j].domain {
			return published[i].domain < published[j].domain
		}
		return published[i].container < published[j].container
	})

	if len(published) == 0 {
		b.WriteString("# Пока ни одно приложение не опубликовано наружу.\n")
		// Пустой конфиг Caddy не примет, поэтому оставляем заглушку, которая
		// ничего не обслуживает, но даёт валидный файл.
		b.WriteString(":80 {\n\trespond \"tracedocs proxy\" 200\n}\n")
		return b.String()
	}

	// Дубликат домена Caddy не принимает — и отвергает конфиг ЦЕЛИКОМ. То есть
	// ошибка на сервере, выдавшая один домен двум приложениям, погасила бы все
	// сайты хоста, а не одно приложение. Отсекаем здесь: у сервера свои
	// проверки, но цена его ошибки здесь несоразмерна.
	seen := make(map[string]bool, len(published))

	for _, t := range published {
		if seen[t.domain] {
			fmt.Fprintf(os.Stderr, "домен %s объявлен дважды, лишний маршрут пропущен\n", t.domain)
			continue
		}
		seen[t.domain] = true

		fmt.Fprintf(&b, "%s {\n", t.domain)
		if opts.LocalTLS {
			b.WriteString("\ttls internal\n")
		}
		// HSTS: после первого захода браузер сам не пойдёт на http, даже если
		// адрес набрали без схемы. Редирект Caddy с 80-го порта остаётся, но
		// HSTS убирает и само первое http-обращение при повторных визитах.
		// Год, без includeSubDomains: поддомены клиента — не наша зона.
		b.WriteString("\theader Strict-Transport-Security \"max-age=31536000\"\n")
		// Access-log — включается вместе с прокси, а не «когда понадобится»
		// (план, «Наблюдаемость по умолчанию»). Один файл на все сайты: Caddy
		// переиспользует writer, а агрегация всё равно идёт по полю host.
		// Ротация ограничена — диск клиента не наш.
		b.WriteString("\tlog {\n")
		b.WriteString("\t\toutput file /var/log/caddy/access.json {\n")
		b.WriteString("\t\t\troll_size 10MiB\n\t\t\troll_keep 2\n\t\t}\n")
		b.WriteString("\t\tformat json\n")
		b.WriteString("\t}\n")
		hasAuth := len(t.access.basicAuth) > 0
		hasList := len(t.access.allowlist) > 0
		hasDeny := len(denyList) > 0
		denyKinds := 0
		if hasDeny {
			denyKinds = 1
		}
		// Отказ секретным путям стоит в каждом сайте приложения и считается
		// видом проверки наравне с баном: вне route штатный порядок Caddy
		// ставит `abort` раньше `respond`, и забаненный сканер получал бы
		// оборванное соединение вместо 403 — по логу было бы не понять,
		// действует ли бан вообще.
		const secretPathKinds = 1

		// Две и больше политики разом — оборачиваем в route: внутри него
		// директивы выполняются в написанном порядке. Штатный порядок Caddy
		// поставил бы аутентификацию первой, и чужой адрес доходил бы до
		// bcrypt-проверки — дорогой по CPU и потому пригодной для перебора и
		// выжигания ресурсов хоста. Порядок: IP-фильтр (дешёвый) → пароль
		// (локальный CPU) → forward_auth (сетевой subrequest) → проксирование.
		// route-блок нужен при двух и более политиках (явный порядок) и всегда
		// при forward_auth: там важно, чтобы очистка X-Scopework-User и сам
		// subrequest стояли строго до reverse_proxy, а вне route порядок задаёт
		// Caddy, а не текст.
		indent := "\t"
		wrap := t.access.kinds()+denyKinds+secretPathKinds >= 2 || t.access.forwardAuth
		if wrap {
			b.WriteString("\troute {\n")
			indent = "\t\t"
		}
		if hasDeny {
			// Блокировка — самой первой: заблокированный адрес не должен
			// доходить ни до bcrypt-проверки пароля, ни до сетевого
			// subrequest forward_auth. Именно ради этого бан и ставится —
			// перестать тратить на источник ресурсы хоста.
			fmt.Fprintf(&b, "%s@banned remote_ip %s\n", indent, strings.Join(denyList, " "))
			fmt.Fprintf(&b, "%srespond @banned 403\n", indent)
		}
		// Разведка получает отказ по имени пути, а не по порогу (ADR-0060 §1):
		// ни одному легальному клиенту опубликованного приложения не нужен
		// `/.env`, `/.git/config` или `/.ssh/id_rsa`. 10.09.2026 такие запросы
		// доходили до Next.js и получали отрисованную страницу, а скан на 17
		// секунд кончается раньше любого окна реакции.
		//
		// ЯВНЫЙ СПИСОК ИМЁН, а не «любой сегмент с точкой» (secretSegmentPattern).
		// Первая редакция рвала `/\.` с исключением `/.well-known/*` в корне и
		// ломала законные пути приложений клиентов: `.well-known` Supabase лежит
		// на глубине (`/auth/v1/.well-known/jwks.json`), объекты Storage бывают
		// вида `.NET-portal.zip`, Gitea отдаёт `.github/` и `.gitignore`, WebDAV —
		// что угодно. Обрыв ломает приложение молча: в его логах запроса нет.
		//
		// Место — после бана и до всех политик маршрута: забаненный получает
		// 403, а секретный путь не доходит ни до bcrypt, ни до subrequest
		// платформы, ни до приложения. PHP и копии здесь не закрываются: у
		// клиентского приложения они бывают законно, их судит приложение.
		//
		// `abort` рвёт соединение без ответа; Caddy пишет такой запрос в
		// access-лог со статусом 0, и сбор угроз считает его отказом.
		fmt.Fprintf(&b, "%s@secret_path path_regexp %s\n", indent, secretSegmentPattern)
		fmt.Fprintf(&b, "%sabort @secret_path\n", indent)
		if hasList {
			// Матчер пропускает только перечисленные адреса; остальным — 403
			// без тела. Список сверяется с адресом соединения: за CDN это
			// адрес CDN, честная граница описана в интерфейсе.
			fmt.Fprintf(&b, "%s@denied not remote_ip %s\n", indent, strings.Join(t.access.allowlist, " "))
			fmt.Fprintf(&b, "%srespond @denied 403\n", indent)
		}
		if hasAuth {
			// Один блок на все учётные записи: Caddy принимает несколько
			// строк «пользователь хеш» внутри одного basic_auth.
			fmt.Fprintf(&b, "%sbasic_auth {\n", indent)
			for _, cred := range t.access.basicAuth {
				fmt.Fprintf(&b, "%s\t%s %s\n", indent, cred.Username, cred.PasswordHash)
			}
			fmt.Fprintf(&b, "%s}\n", indent)
		}
		if t.access.forwardAuth {
			// Личность, которую приложение может прочитать, задаёт ТОЛЬКО
			// платформа. Входящий от клиента X-Scopework-User вычищаем из
			// запроса до проверки: иначе приложение, доверяющее заголовку,
			// получило бы подделанное посетителем значение. request_header
			// (не header_up) — потому что это уровень сайта, а не reverse_proxy.
			fmt.Fprintf(&b, "%srequest_header -X-Scopework-User\n", indent)
			// Вход по личности Scopework: subrequest платформе, кука
			// проверяется там (0188). Подмена Host обязательна — иначе
			// запрос пришёл бы к платформе с именем защищаемого домена и не
			// совпал бы ни с одним vhost.
			fmt.Fprintf(&b, "%sforward_auth %s {\n", indent, opts.PlatformBaseURL)
			fmt.Fprintf(&b, "%s\turi /api/deploy/access/verify\n", indent)
			fmt.Fprintf(&b, "%s\theader_up Host {upstream_hostport}\n", indent)
			// copy_headers переносит X-Scopework-User из проверенного ответа
			// платформы в запрос к приложению — уже как доверенное значение.
			fmt.Fprintf(&b, "%s\tcopy_headers X-Scopework-User\n", indent)
			fmt.Fprintf(&b, "%s}\n", indent)
		}
		// Происхождение запроса задаём МЫ, а не клиент.
		//
		// По умолчанию Caddy ДОПИСЫВАЕТ адрес соединения к `X-Forwarded-For`,
		// который прислал клиент. Запрос с `X-Forwarded-For: 8.8.8.8` доезжает
		// до приложения как `8.8.8.8, <настоящий>`, а первый элемент списка —
		// общепринятое место «исходного клиента», и именно его берёт
		// большинство фреймворков. Подделываются журналы аудита приложения,
		// его ограничения по частоте и любые решения вида «этот адрес мы уже
		// видели».
		//
		// Здесь заголовки ставятся ЗАМЕНОЙ и из свойств соединения. Для
		// перехваченного стека это существенно вдвойне: он писался под чужой
		// прокси с другими правилами, и полагаться на его аккуратность
		// оснований нет.
		//
		// Честная граница: `{remote_host}` — адрес того, кто открыл соединение
		// с нами. Если перед платформой стоит CDN, это адрес CDN, и другого
		// достоверного источника у нас нет. То же ограничение уже описано для
		// списков разрешённых адресов.
		fmt.Fprintf(&b, "%sreverse_proxy %s:%d {\n", indent, t.container, t.port)
		fmt.Fprintf(&b, "%s\theader_up X-Forwarded-For {remote_host}\n", indent)
		fmt.Fprintf(&b, "%s\theader_up X-Real-IP {remote_host}\n", indent)
		fmt.Fprintf(&b, "%s\theader_up X-Forwarded-Proto {scheme}\n", indent)
		fmt.Fprintf(&b, "%s\theader_up X-Forwarded-Host {host}\n", indent)
		// Всё, чем клиент мог бы притвориться источником. Эти заголовки читают
		// приложения, привыкшие работать за CDN; на нашем прокси их не
		// выставляет никто, значит любое пришедшее значение — подделка.
		for _, spoofable := range []string{
			"Forwarded", "CF-Connecting-IP", "True-Client-IP", "X-Client-IP",
		} {
			fmt.Fprintf(&b, "%s\theader_up -%s\n", indent, spoofable)
		}
		fmt.Fprintf(&b, "%s}\n", indent)
		if wrap {
			b.WriteString("\t}\n")
		}
		b.WriteString("}\n\n")
	}

	// www-вариант каждого домена принудительно редиректится на сам домен.
	//
	// Без этого блока www.домен не обслуживался вовсе: на https браузер
	// получал ошибку сертификата, на http — редирект на тот же необслуженный
	// адрес. Для посетителя «сайт сломан», хотя приложение работает.
	//
	// Сертификат для www Caddy выпускает как для обычного имени; если
	// DNS-записи www у клиента нет, выпуск просто не удастся и Caddy будет
	// повторять его с нарастающим интервалом — остальные домены это не
	// задевает, у каждого свой site-блок.
	//
	// 308, а не 301: метод и тело обязаны переживать редирект — у приложений
	// за прокси бывают POST-вебхуки.
	//
	// Отказа секретным путям здесь нет намеренно: блок ничего не проксирует,
	// `www.домен/.env` получает 308 на основной домен и отказ уже там. Второй
	// матчер дал бы лишнюю копию правила без единого закрытого пути.
	for _, t := range published {
		if strings.HasPrefix(t.domain, "www.") {
			continue
		}
		if isPlatformSubdomain(t.domain, opts.PlatformSubdomainBase) {
			continue
		}
		www := "www." + t.domain
		if seen[www] {
			// Пользователь опубликовал www-домен явно — его маршрут важнее
			// нашего редиректа, а дубль домена валит конфиг Caddy целиком.
			continue
		}
		seen[www] = true

		fmt.Fprintf(&b, "%s {\n", www)
		if opts.LocalTLS {
			b.WriteString("\ttls internal\n")
		}
		fmt.Fprintf(&b, "\tredir https://%s{uri} 308\n}\n\n", t.domain)
	}

	return b.String()
}
