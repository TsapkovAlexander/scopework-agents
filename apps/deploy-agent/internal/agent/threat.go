package agent

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// authSegments — сегменты пути, означающие вход/сессию/учётные данные.
// Сверка идёт по сегментам, а не подстрокой: подстрочный матч записывал в
// брутфорс легитимные 401/403 на путях вроде /api/products/authentic-goods.
// Список синхронизирован с awk-классификатором monitor-agent (monitor-push.sh).
var authSegments = map[string]bool{
	"login": true, "signin": true, "sign-in": true, "auth": true,
	"admin": true, "session": true, "token": true, "password": true,
	"verify-password": true, "verify_password": true,
}

// fileExtensions — расширения, при которых последний сегмент пути — файл, а
// не страница входа (ADR-0060 §4).
//
// 10.09.2026 скан словаря секретов разбудил человека тревогой «брутфорс
// авторизации»: `/auth.json`, `/token.txt`, `/.vault-token`, запрошенные по
// разу, дали 429 общего предела, а в именах нашлись слова входа. PHP в списке
// нет намеренно: `/admin/index.php` — страница входа, и подбор на ней отличает
// концентрация попыток, а не имя.
var fileExtensions = map[string]bool{
	"json": true, "txt": true, "log": true, "yml": true, "yaml": true, "xml": true,
	"ini": true, "conf": true, "cfg": true, "rb": true, "py": true, "bak": true,
	"old": true, "orig": true, "save": true, "swp": true, "sql": true, "sqlite": true,
	"db": true, "pem": true, "key": true, "crt": true, "p12": true, "pfx": true,
	"zip": true, "gz": true, "tgz": true, "tar": true, "rar": true, "7z": true,
	"csv": true,
}

// lastPathExtension — расширение последнего НЕПУСТОГО сегмента: то, что после
// последней точки (у `/login.php.bak` это `bak`).
//
// Непустого — потому что `/auth.json/` тот же файл, что `/auth.json`: слэш в
// конце дописывает сканер, и по пустому последнему сегменту файл выглядел бы
// страницей входа.
func lastPathExtension(path string) string {
	path = strings.TrimRight(path, "/")
	seg := path[strings.LastIndexByte(path, '/')+1:]
	if dot := strings.LastIndexByte(seg, '.'); dot >= 0 {
		return seg[dot+1:]
	}
	return ""
}

// Сверяем и сегмент целиком (/sign-in), и его слова через - _ . (/reset-password).
// Слово, а не подстрока: /api/products/authentic-goods и /api/tokens-usage —
// обычные пути, их 401/403 не брутфорс.
//
// Скрытый сегмент и файловое расширение последнего сегмента снимают признак
// входа целиком: это разведка файлов, а не вход (ADR-0060 §4).
func isSensitiveAuthPath(path string) bool {
	isSep := func(r rune) bool { return r == '-' || r == '_' || r == '.' }
	path = strings.ToLower(path)
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if strings.HasPrefix(seg, ".") {
			return false
		}
	}
	if fileExtensions[lastPathExtension(path)] {
		return false
	}
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if authSegments[seg] {
			return true
		}
		for _, word := range strings.FieldsFunc(seg, isSep) {
			if authSegments[word] {
				return true
			}
		}
	}
	return false
}

// stripQuery убирает query-строку: /reset-password?token=… иначе клал бы токен
// в top_paths и samples, а оттуда — в БД платформы и в текст уведомления.
func stripQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

// staticExtensions — 404 на битой картинке это мусор, а не перебор путей.
var staticExtensions = []string{
	".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
	".css", ".js", ".mjs", ".map",
	".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp4", ".webm", ".mp3", ".pdf", ".zip",
}

// isBackgroundRequest — фоновый запрос браузера, а не действие человека:
// предзагрузка страниц Next.js (`?_rsc=`) и 304 на статику и манифест.
// Правило — isBackgroundRequest в @tracedocs/threat-analytics (classify.ts),
// там же причина; сверяет оконная фикстура.
func isBackgroundRequest(rawPath string, status int) bool {
	if i := strings.IndexByte(rawPath, '?'); i >= 0 {
		q := rawPath[i+1:]
		if strings.HasPrefix(q, "_rsc=") || strings.Contains(q, "&_rsc=") {
			return true
		}
	}
	if status != 304 {
		return false
	}
	return isStaticAsset(rawPath) || strings.HasSuffix(strings.ToLower(stripQuery(rawPath)), ".webmanifest")
}

// talkerScore — запросы адреса с фоновыми четвертью, в четвертях, чтобы не
// считать дробями. Вес — RATE_SPIKE_BACKGROUND_WEIGHT судьи (evaluate.ts):
// выбор по сырому счёту прятал бы бота с 520 запросами за человеком с 600,
// из которых 510 фоновые.
func talkerScore(requests, background int64) int64 {
	return 4*(requests-background) + background
}

func isStaticAsset(path string) bool {
	p := strings.ToLower(stripQuery(path))
	for _, ext := range staticExtensions {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// scannerAgents — сканеры, которые представляются сами. Признак сильнее пути.
var scannerAgents = []string{
	"nikto", "sqlmap", "zgrab", "masscan", "nmap",
	"acunetix", "dirbuster", "gobuster", "wpscan", "nuclei",
}

// ownUAFragments — наши собственные запросы в обе стороны.
//
// Проверки платформы к серверу (uptime, health, аудит) и такт агента
// развёртывания обратно к платформе. Список дословно повторяет
// OWN_UA_FRAGMENTS из packages/threat-analytics/src/classify.ts — расхождение
// ловит golden-тест на общей фикстуре.
var ownUAFragments = []string{
	"scopeworkuptime",
	"scopeworkhealth",
	"scopeworksiteauditbot",
	"scopework-deploy-agent",
	// Прежние имена: на серверах ещё живут агенты и зонды, поставленные до
	// переименования. Убрать их раньше переустановки значит записать
	// собственный трафик в угрозы.
	"tracedocsuptime",
	"tracedocshealth",
	"tracedocssiteauditbot",
	"tracedocs-deploy-agent",
}

func isOwnPlatformUserAgent(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	ua := strings.ToLower(userAgent)
	for _, frag := range ownUAFragments {
		if strings.Contains(ua, frag) {
			return true
		}
	}
	return false
}

func isScannerUserAgent(userAgent string) bool {
	if userAgent == "" {
		return false
	}
	ua := strings.ToLower(userAgent)
	for _, frag := range scannerAgents {
		if strings.Contains(ua, frag) {
			return true
		}
	}
	return false
}

// Фрагменты пути разведки — дословно ENV_PROBE_FRAGMENTS и CMS_SCAN_FRAGMENTS
// из classify.ts. Ищутся в любом месте пути, а не префиксом: `/blog/wp-admin/…`
// — тот же скан WordPress, установленного в подкаталог; префикс записывал его в
// перебор путей, и Go расходился с TS (`includes`).
var (
	envProbeFragments = []string{"/.env", "/.git/", "/wp-config", "/.aws/", "/actuator/"}
	cmsScanFragments  = []string{"/wp-admin", "/wp-login", "/xmlrpc.php", "/phpmyadmin", "/administrator/"}
)

func containsAny(s string, fragments []string) bool {
	for _, f := range fragments {
		if strings.Contains(s, f) {
			return true
		}
	}
	return false
}

// probeExtensions — SECRET_EXT контракта: расширения копий, дампов и ключей.
// `json` и `yml` сюда не входят: SPA законно отдаёт `/config.json`, и 200 на
// нём — не утечка.
var probeExtensions = map[string]bool{
	"bak": true, "old": true, "orig": true, "save": true, "swp": true, "sql": true,
	"sqlite": true, "db": true, "pem": true, "key": true, "p12": true, "pfx": true,
	"env": true,
}

// secretActuatorFragments — эндпоинты Spring Actuator, отдающие секреты. Весь
// `/actuator/` — проба, но `/actuator/health` отвечает 200 законно, и считать
// его отданным секретом значило бы будить человека на каждый мониторинг.
var secretActuatorFragments = []string{"/actuator/env", "/actuator/heapdump", "/actuator/configprops"}

// secretSegmentPattern — явный список имён сегмента, отдать которые законно
// нельзя. Один шаблон на две задачи: по нему кромка Caddy рвёт соединение
// (renderCaddyfile) и по нему же сбор решает, был ли ответ 200 отданным
// секретом. Две копии разошлись бы, и кромка закрывала бы одно, а тревога
// будила бы по другому.
//
// Список, а не «любой сегмент с точкой»: законных путей с точкой у приложений
// клиентов много — `/auth/v1/.well-known/jwks.json` у Supabase, объекты Storage
// вида `.NET-portal.zip`, `.github/` и `.gitignore` в Gitea, WebDAV. Отказ по
// любой точке ломал бы их, а тревога «отдан файл» будила бы на каждом заходе.
const secretSegmentPattern = `(?i)(^|/)(\.env([._-][^/]*)?|\.git|\.git-credentials|\.svn|\.hg|\.bzr|\.aws|\.ssh|\.docker|\.kube|\.gnupg|\.htpasswd|\.npmrc|\.pgpass|\.netrc|\.vault-token|\.bash_history|\.zsh_history|\.mysql_history|\.psql_history|\.s3cfg|\.boto|\.pypirc|\.dockercfg)(/|$)`

var secretSegmentRe = regexp.MustCompile(secretSegmentPattern)

// isProbePath — был ли запрос пробой (поправка А к ADR-0060 §3). Путь — без
// query, в нижнем регистре.
//
// По свойству пути, а не по категории: категория отвечает «кто это», исход —
// «что он получил». Сканер, назвавшийся zgrab, получает категорию scanner_ua,
// и учёт по категории терял его единственный ответ 200 на `/backup.sql`.
// Скрытый сегмент здесь — ЛЮБОЙ, кроме ровно `.well-known`: отказ `.gitignore`
// тоже отказ, а отдан ли секрет, решает уже isSecretPath.
func isProbePath(p string) bool {
	if containsAny(p, envProbeFragments) || containsAny(p, cmsScanFragments) {
		return true
	}
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") && seg != ".well-known" {
			return true
		}
	}
	return probeExtensions[lastPathExtension(p)]
}

// isSecretPath — отдача какого пути означает утечку (поправка Б). Путь — без
// query, в нижнем регистре.
//
// CMS-фрагментов здесь нет: страница входа WordPress, ответившая 200, — не
// секрет, а сайт на WordPress.
func isSecretPath(p string) bool {
	return strings.Contains(p, "/wp-config") ||
		containsAny(p, secretActuatorFragments) ||
		secretSegmentRe.MatchString(p) ||
		probeExtensions[lastPathExtension(p)]
}

// classifyThreatPath — правила без User-Agent (совместимость со старыми вызовами).
func classifyThreatPath(path string, status int) string {
	return classifyThreatLine(path, status, "")
}

// classifyThreatLine — точка правды продублирована из packages/threat-analytics
// (classify.ts); расхождение ловит golden-тест на общей фикстуре.
func classifyThreatLine(path string, status int, userAgent string) string {
	// Свои запросы — не события. ПЕРВЫМ правилом: краулер аудита платформы
	// ходит по путям, которые любое из правил ниже сочло бы разведкой.
	//
	// Без этого агент считал угрозой саму платформу: проверка доступности,
	// бьющая в несуществующий URL, давала сотни «событий перебора путей» в
	// сутки, а обход аудита — на порядок больше. Правило было только в
	// bash-агенте мониторинга; здесь его не было вовсе.
	if isOwnPlatformUserAgent(userAgent) {
		return ""
	}
	if isScannerUserAgent(userAgent) {
		return "scanner_ua"
	}
	p := strings.ToLower(stripQuery(path))
	switch {
	case containsAny(p, envProbeFragments):
		return "env_probe"
	case containsAny(p, cmsScanFragments):
		return "cms_scan"
	}
	if isSensitiveAuthPath(p) {
		if status == 429 {
			return "rate_limited"
		}
		if status == 401 || status == 403 {
			return "auth_brute"
		}
	}
	if status == 404 && !isStaticAsset(p) {
		return "api_fuzz"
	}
	return ""
}

type threatIpAcc struct {
	count      int64
	categories map[string]int64
	// requests — ВСЕ запросы с этого IP, не только подозрительные: без них
	// объёмная атака (флуд 200 OK) не попадала ни в один счётчик.
	requests int64
	// background — из них фоновые (isBackgroundRequest).
	background int64
	// seenFuzz — уникальные 404-пути: битая ссылка на сайте иначе давала
	// сотню «подозрительных событий» вместо одной находки.
	seenFuzz map[string]struct{}
}

// authPairKey — пара (адрес, путь без query) попыток входа.
type authPairKey struct {
	ip   string
	path string
}

// threatAcc — рабочее состояние сбора окна; наружу не уезжает.
type threatAcc struct {
	ips   map[string]*threatIpAcc
	paths map[string]int64
	// authPairs — сколько попыток входа пришлось на пару (адрес, путь).
	// Ограничен maxAuthPairs, см. noteAuthAttempt. Из него же выводятся
	// auth_attempts и auth_paths — второго словаря не заводим.
	authPairs map[authPairKey]int64
}

// Пределы фактов исхода (ADR-0060 §3).
const (
	maxServedProbes = 10
	// maxSameBytesProbes — столько элементов с одинаковым размером ответа
	// держит served_probes. Одинаковый размер у многих проб — общая заглушка
	// приложения; трёх судье хватает, чтобы её опознать, а десять копий
	// вытеснили бы настоящий файл, отданный следом.
	maxSameBytesProbes = 3
	maxAuthAttempts    = 5
	maxAuthPaths       = 5
	maxContentTypeLen  = 100
	// maxAuthPairs — столько же, сколько адресов на домен (maxTrackedIPs).
	// Подбор — это концентрация: настоящий подбор занимает одну пару, и
	// переполнение означает рассеянный шум, у которого первые пять пар
	// значения не меняют. Без предела пятьдесят тысяч строк такта с разными
	// путями держали бы в памяти агента столько же ключей до полукилобайта
	// каждый — на чужом сервере, где память не наша.
	maxAuthPairs = 10000
)

// ThreatWindow matches @tracedocs/threat-analytics threatWindowPayloadSchema.
//
// Версия 2 (ADR-0060 §3) аддитивна: добавлены факты исхода, по которым судья
// на платформе отвечает, отказали ли сканеру и получил ли он что-нибудь. Поля
// уходят всегда, пустые — массивами: `auth_attempts: []` отличает агента v2 от
// v1, для которого судья сохраняет прежние правила.
type ThreatWindow struct {
	SchemaVersion int `json:"schema_version"`
	WindowSec     int `json:"window_sec"`
	Totals        struct {
		Parsed       int64 `json:"parsed"`
		Suspicious   int64 `json:"suspicious"`
		AuthFailures int64 `json:"auth_failures"`
	} `json:"totals"`
	Categories    map[string]int64    `json:"categories"`
	TopIPs        []ThreatTopIP       `json:"top_ips"`
	TopPaths      []ThreatTopPath     `json:"top_paths"`
	TopTalker     *ThreatTopTalker    `json:"top_talker"`
	Samples       []ThreatSample      `json:"samples"`
	ProbeOutcomes ThreatProbeOutcomes `json:"probe_outcomes"`
	ServedProbes  []ThreatServedProbe `json:"served_probes"`
	AuthAttempts  []ThreatAuthAttempt `json:"auth_attempts"`
	AuthPaths     []ThreatAuthPath    `json:"auth_paths"`
	Truncated     bool                `json:"truncated"`
}

// ThreatProbeOutcomes — чем кончились пробы (см. isProbePath).
//
// Без этих счётчиков ответ «получил ли сканер что-нибудь» лежал только в
// access-логе на хосте клиента: десять образцов не говорят, чем кончились
// остальные три тысячи запросов.
type ThreatProbeOutcomes struct {
	Refused    int64 `json:"refused"`
	Redirected int64 `json:"redirected"`
	Served     int64 `json:"served"`
	Failed     int64 `json:"failed"`
}

// ThreatServedProbe — проба, на которую ответили 2xx.
//
// Размер и тип — единственное, по чему платформа отличает отданный файл от
// HTML-оболочки приложения, не скачивая путь сама: запрос платформы к `/.env`
// забанил бы её адрес у клиента, а содержимое секрета оказалось бы у нас.
type ThreatServedProbe struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
	// Bytes — тело ответа (`size` у Caddy); null — формат лога размера не несёт.
	Bytes *int64 `json:"bytes"`
	// ContentType — null, если тип в логе не записан.
	ContentType *string `json:"content_type"`
}

// ThreatAuthAttempt — попытки входа одного адреса на одном пути.
type ThreatAuthAttempt struct {
	IP    string `json:"ip"`
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// ThreatAuthPath — попытки входа на одном пути по всем адресам.
//
// Распределённый подбор — шестьдесят адресов по девять попыток — не набирает
// концентрации ни на одной паре (адрес, путь) и виден только суммой по пути
// вместе с числом адресов.
type ThreatAuthPath struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
	IPs   int64  `json:"ips"`
}

// accessRecord — строка access-лога в том виде, в каком её видит сбор угроз.
type accessRecord struct {
	RemoteIP string
	// Path — как в логе, вместе с query: срезается при учёте.
	Path      string
	Status    int
	UserAgent string
	// Bytes — nil, если формат лога размера не несёт.
	Bytes *int64
	// ContentType — пусто, если тип неизвестен.
	ContentType string
	// Background — фоновый запрос (isBackgroundRequest). Считается там, где
	// ещё виден query: разбор Caddy срезает его до учёта.
	Background bool
}

// ThreatTopTalker — самый активный IP окна по всем запросам.
type ThreatTopTalker struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
	// Background — из Requests фоновые; уходит всегда, отсутствие поля у судьи
	// означает старого агента и счёт по сырому числу.
	Background int64 `json:"background"`
}

type ThreatTopIP struct {
	IP         string   `json:"ip"`
	Count      int64    `json:"count"`
	Categories []string `json:"categories,omitempty"`
	// Counts — сколько событий пришлось на каждую категорию.
	//
	// Общего счётчика для решения о блокировке мало: заблокировать прокси может
	// только то, что через прокси и идёт, а перебор SSH идёт мимо. С одним
	// числом порог набирался чем угодно — двадцать SSH-попыток плюс одна ошибка
	// 404 давали блокировку по HTTP-порогу, которого HTTP-события не набирали.
	Counts map[string]int64 `json:"counts,omitempty"`
}

type ThreatTopPath struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

type ThreatSample struct {
	IP       string `json:"ip,omitempty"`
	Path     string `json:"path,omitempty"`
	Status   *int   `json:"status,omitempty"`
	Category string `json:"category,omitempty"`
}

// Границы окна те же, что в схеме платформы (threatWindowPayloadSchema):
// значение вне диапазона она клампит, но лучше не присылать заведомо неверное.
const (
	minThreatWindowSec     = 60
	maxThreatWindowSec     = 86400
	defaultThreatWindowSec = 180
)

// now подменяется в тестах.
var now = time.Now

// windowSecondsSince — фактическая длительность окна между сдвигами курсора.
// Часы на хосте могут прыгнуть назад (ntp), курсор может быть от версии агента
// без метки времени — в обоих случаях отдаём дефолт, а не отрицательное число.
func windowSecondsSince(prevUnix, nowUnix int64) int {
	if prevUnix <= 0 || nowUnix <= prevUnix {
		return defaultThreatWindowSec
	}
	elapsed := nowUnix - prevUnix
	if elapsed < minThreatWindowSec {
		return minThreatWindowSec
	}
	if elapsed > maxThreatWindowSec {
		return maxThreatWindowSec
	}
	return int(elapsed)
}

func newThreatAccumulator(truncated bool) (*ThreatWindow, *threatAcc) {
	tw := &ThreatWindow{
		SchemaVersion: 2,
		WindowSec:     defaultThreatWindowSec,
		Categories:    map[string]int64{},
		TopIPs:        []ThreatTopIP{},
		TopPaths:      []ThreatTopPath{},
		Samples:       []ThreatSample{},
		ServedProbes:  []ThreatServedProbe{},
		AuthAttempts:  []ThreatAuthAttempt{},
		AuthPaths:     []ThreatAuthPath{},
		Truncated:     truncated,
	}
	acc := &threatAcc{
		ips:       map[string]*threatIpAcc{},
		paths:     map[string]int64{},
		authPairs: map[authPairKey]int64{},
	}
	return tw, acc
}

func (acc *threatAcc) ip(ip string) *threatIpAcc {
	a := acc.ips[ip]
	if a == nil {
		a = &threatIpAcc{categories: map[string]int64{}, seenFuzz: map[string]struct{}{}}
		acc.ips[ip] = a
	}
	return a
}

// noteSSHFailure добавляет в окно неудачные попытки входа по SSH.
//
// Отдельно от HTTP: у попытки входа нет ни пути, ни кода ответа, а `parsed` она
// не увеличивает — это не разобранная строка access-лога, и смешав их, мы
// испортили бы знаменатель, по которому платформа считает долю подозрительного
// трафика.
//
// Счётчик приходит уже дедуплицированным (см. CollectSSHFailures): одна попытка
// входа — одно событие, а не столько, сколько строк написал sshd.
func (tw *ThreatWindow) noteSSHFailure(ip string, attempts int64, acc *threatAcc) {
	if attempts <= 0 {
		return
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return
	}

	a := acc.ip(ip)

	tw.Totals.Suspicious += attempts
	tw.Totals.AuthFailures += attempts
	tw.Categories["ssh_brute"] += attempts

	a.count += attempts
	a.categories["ssh_brute"] += attempts
}

func (tw *ThreatWindow) noteRequest(r accessRecord, acc *threatAcc) {
	tw.Totals.Parsed++

	// Наружу отдаём путь без query и без хвоста: секрет из ссылки восстановления
	// пароля не должен осесть в БД платформы, а слишком длинный URI отбраковала бы
	// схема — вместе со всем окном.
	path := stripQuery(r.Path)
	if len(path) > 512 {
		path = path[:512]
	}

	// Исход пробы — до категории и до схлопывания повторов 404: категория
	// говорит, кто пришёл, а отказ получил каждый запрос. Свои проверки
	// платформы пробами не бывают — краулер аудита ходит и по `/.env`.
	if !isOwnPlatformUserAgent(r.UserAgent) {
		if lower := strings.ToLower(stripQuery(r.Path)); isProbePath(lower) {
			tw.noteProbeOutcome(path, lower, r)
		}
	}

	ip := strings.TrimSpace(r.RemoteIP)
	if ip == "" {
		return
	}
	a := acc.ip(ip)
	a.requests++
	if r.Background {
		a.background++
	}

	cat := classifyThreatLine(r.Path, r.Status, r.UserAgent)
	if cat == "" {
		return
	}
	if cat == "api_fuzz" {
		if _, seen := a.seenFuzz[path]; seen {
			return
		}
		a.seenFuzz[path] = struct{}{}
	}
	tw.Totals.Suspicious++
	tw.Categories[cat]++
	if cat == "auth_brute" || cat == "rate_limited" {
		tw.Totals.AuthFailures++
		tw.noteAuthAttempt(authPairKey{ip: ip, path: path}, acc)
	}
	a.count++
	a.categories[cat]++
	// Пустой путь проваливает схему на платформе и уносит с собой всё окно
	if path != "" {
		acc.paths[path]++
	}

	if len(tw.Samples) < 10 {
		st := r.Status
		tw.Samples = append(tw.Samples, ThreatSample{
			IP: ip, Path: path, Status: &st, Category: cat,
		})
	}
}

// noteProbeOutcome — исход пробы по коду ответа (ADR-0060 §3).
//
// Всё, что не 2xx, 3xx и 5xx, — отказ: 4xx, 444 nginx, 499 и 0, который Caddy
// пишет за соединение, оборванное `abort` на кромке. Ответа там не было вовсе,
// и считать его чем-то кроме отказа значило бы поднимать тревогу «отдано» на
// том, что кромка как раз отказала.
//
// path — путь для отчёта (исходный регистр, без query); lower — он же в нижнем
// регистре для правил.
func (tw *ThreatWindow) noteProbeOutcome(path, lower string, r accessRecord) {
	switch {
	case r.Status >= 200 && r.Status < 300:
		tw.ProbeOutcomes.Served++
	case r.Status >= 300 && r.Status < 400:
		tw.ProbeOutcomes.Redirected++
		return
	case r.Status >= 500 && r.Status < 600:
		tw.ProbeOutcomes.Failed++
		return
	default:
		tw.ProbeOutcomes.Refused++
		return
	}
	if isSecretPath(lower) {
		tw.noteServedProbe(path, r)
	}
}

// noteServedProbe записывает отданный секретный путь (поправка Б).
//
// Один элемент на путь в порядке первого появления: сканер повторяет удачный
// путь, и десять копий одного `/.env` вытеснили бы девять других ответов.
// Повтор сводит факты, а не отбрасывается: HEAD отдаёт 0 байт без типа, и
// первый ответ как окончательный сделал бы пустым файл, отданный следом GET-ом.
//
// HTML в список не попадает: это страница приложения, а не файл, и десяток
// отрисованных 404-с-кодом-200 не должен вытеснить настоящий файл одиннадцатым.
// По той же причине HTML-ответ не меняет и уже записанный путь — ни размер, ни
// тип: страница в 5 КБ не делает отданный `.env` в 412 байт пятикилобайтным
// (случай фикстуры «HTML-ответ на уже отданный файл…»).
func (tw *ThreatWindow) noteServedProbe(path string, r accessRecord) {
	ct := truncateRunes(strings.TrimSpace(r.ContentType), maxContentTypeLen)
	if strings.HasPrefix(strings.ToLower(ct), "text/html") {
		return
	}

	for i := range tw.ServedProbes {
		p := &tw.ServedProbes[i]
		if p.Path != path {
			continue
		}
		if r.Bytes != nil && (p.Bytes == nil || *r.Bytes > *p.Bytes) {
			n := *r.Bytes
			p.Bytes = &n
		}
		if p.ContentType == nil && ct != "" {
			p.ContentType = &ct
		}
		return
	}

	if len(tw.ServedProbes) >= maxServedProbes {
		return
	}
	if r.Bytes != nil {
		same := 0
		for _, p := range tw.ServedProbes {
			if p.Bytes != nil && *p.Bytes == *r.Bytes {
				same++
			}
		}
		if same >= maxSameBytesProbes {
			return
		}
	}

	probe := ThreatServedProbe{Path: path, Status: r.Status}
	if r.Bytes != nil {
		n := *r.Bytes
		probe.Bytes = &n
	}
	if ct != "" {
		probe.ContentType = &ct
	}
	tw.ServedProbes = append(tw.ServedProbes, probe)
}

// noteAuthAttempt считает попытку входа на паре (адрес, путь).
//
// Словарь ограничен: новая пара сверх maxAuthPairs отбрасывается, а окно
// помечается усечённым. Уже известные пары продолжают считаться — подбор,
// начатый до переполнения, не исчезает из-за постороннего шума.
func (tw *ThreatWindow) noteAuthAttempt(key authPairKey, acc *threatAcc) {
	if _, known := acc.authPairs[key]; !known && len(acc.authPairs) >= maxAuthPairs {
		tw.Truncated = true
		return
	}
	acc.authPairs[key]++
}

// truncateRunes режет по символам, а не по байтам: разрез посередине UTF-8
// дал бы невалидную строку, и JSON заменил бы хвост знаком подмены.
func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max])
}

// isInternalIP — приватные и служебные адреса: наш собственный прокси и
// контейнеры. В top_talker им не место, иначе внутренний трафик и порог
// всплеска перешагнёт, и настоящего атакующего из этого поля вытеснит.
func isInternalIP(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsUnspecified() || addr.IsLinkLocalMulticast()
}

func (tw *ThreatWindow) finalize(acc *threatAcc) {
	type row struct {
		ip    string
		count int64
		cats  map[string]int64
	}
	rows := make([]row, 0, len(acc.ips))
	for ip, a := range acc.ips {
		if a.requests > 0 && !isInternalIP(ip) &&
			(tw.TopTalker == nil ||
				talkerScore(a.requests, a.background) > talkerScore(tw.TopTalker.Requests, tw.TopTalker.Background)) {
			tw.TopTalker = &ThreatTopTalker{IP: ip, Requests: a.requests, Background: a.background}
		}
		if a.count == 0 {
			continue
		}
		rows = append(rows, row{ip: ip, count: a.count, cats: a.categories})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })
	for i := 0; i < len(rows) && i < 10; i++ {
		cats := make([]string, 0, len(rows[i].cats))
		for c := range rows[i].cats {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		// Счётчики по категориям — копией: карта аккумулятора переиспользуется
		// между окнами, и отдать её как есть значило бы, что следующее окно
		// меняет уже отправленное.
		counts := make(map[string]int64, len(rows[i].cats))
		for c, n := range rows[i].cats {
			counts[c] = n
		}
		tw.TopIPs = append(tw.TopIPs, ThreatTopIP{
			IP: rows[i].ip, Count: rows[i].count, Categories: cats, Counts: counts,
		})
	}
	type prow struct {
		path  string
		count int64
	}
	prows := make([]prow, 0, len(acc.paths))
	for path, count := range acc.paths {
		prows = append(prows, prow{path: path, count: count})
	}
	sort.Slice(prows, func(i, j int) bool {
		if prows[i].count != prows[j].count {
			return prows[i].count > prows[j].count
		}
		return prows[i].path < prows[j].path
	})
	for i := 0; i < len(prows) && i < 10; i++ {
		tw.TopPaths = append(tw.TopPaths, ThreatTopPath{Path: prows[i].path, Count: prows[i].count})
	}

	// Порядок пар — часть контракта, а не вкус: при равном счёте без полного
	// порядка awk и Go отдавали бы разные пять пар из одного лога, и сверка
	// реализаций по фикстуре ничего бы не значила.
	pairs := make([]ThreatAuthAttempt, 0, len(acc.authPairs))
	for key, count := range acc.authPairs {
		pairs = append(pairs, ThreatAuthAttempt{IP: key.ip, Path: key.path, Count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count != pairs[j].Count {
			return pairs[i].Count > pairs[j].Count
		}
		if pairs[i].Path != pairs[j].Path {
			return pairs[i].Path < pairs[j].Path
		}
		return pairs[i].IP < pairs[j].IP
	})
	if len(pairs) > maxAuthAttempts {
		pairs = pairs[:maxAuthAttempts]
	}
	tw.AuthAttempts = pairs

	// Сумма по пути — из той же карты пар: её предел уже ограничивает память,
	// а при переполнении окно помечено усечённым, и заниженная сумма не
	// выдаёт себя за полную.
	byPath := map[string]*ThreatAuthPath{}
	for key, count := range acc.authPairs {
		ap := byPath[key.path]
		if ap == nil {
			ap = &ThreatAuthPath{Path: key.path}
			byPath[key.path] = ap
		}
		ap.Count += count
		ap.IPs++ // ключ карты — пара, значит каждый адрес на пути встречается один раз
	}
	paths := make([]ThreatAuthPath, 0, len(byPath))
	for _, ap := range byPath {
		paths = append(paths, *ap)
	}
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Count != paths[j].Count {
			return paths[i].Count > paths[j].Count
		}
		return paths[i].Path < paths[j].Path
	})
	if len(paths) > maxAuthPaths {
		paths = paths[:maxAuthPaths]
	}
	tw.AuthPaths = paths
}
