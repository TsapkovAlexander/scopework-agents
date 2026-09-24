package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/hoststate"
)

// Контракт с BFF. Поля обязаны совпадать с
// apps/web/src/app/api/deploy/agent/{enroll,heartbeat}/route.ts.
//
// Это самое хрупкое место всей связки: TypeScript и Go про одно и то же знают
// раздельно, и расхождение проявится не на сборке, а в бою. Поэтому структуры
// держим рядом с комментарием-ссылкой, а в CI обеих сторон нужно гонять общие
// golden-фикстуры.

type enrollRequest struct {
	Token        string `json:"token"`
	PublicKey    string `json:"publicKey"`
	Fingerprint  string `json:"fingerprint"`
	AgentVersion string `json:"agentVersion"`
}

type enrollResponse struct {
	HostID    string `json:"hostId"`
	ProjectID string `json:"projectId"`
}

// Отпечаток в теле не передаётся: сервер берёт его из проверенной подписи.
// Дублировать значение, которому нельзя доверять, — приглашение однажды
// начать читать именно его.
type heartbeatRequest struct {
	AgentVersion string `json:"agentVersion"`
	// ProxyError — почему на этом хосте не поднимается прокси.
	//
	// Пустая строка означает «в порядке» и снимает отметку на сервере. Едет
	// отметкой о жизни, а не отдельной ручкой: она приходит раз в минуту
	// независимо от того, занят ли цикл тяжёлым выкатом, — то есть это
	// единственный канал, работающий именно тогда, когда всё плохо.
	//
	// Без этого поля неисправность видна только в journalctl на самом хосте:
	// приложение остаётся `healthy`, релиз успешным, панель зелёной, а сайт не
	// отвечает ни по одному адресу.
	ProxyError string `json:"proxyError"`
}

// AgentSha256ByArch — суммы бинаря агента по архитектурам. Агент выбирает
// свою по runtime.GOARCH.
type AgentSha256ByArch struct {
	Amd64 string `json:"amd64"`
	Arm64 string `json:"arm64"`
}

// ForArch возвращает сумму для архитектуры этого процесса; пустая строка —
// платформа сумму не отдала (старая платформа или бинарь не собран).
func (s AgentSha256ByArch) ForArch(goarch string) string {
	switch goarch {
	case "amd64":
		return s.Amd64
	case "arm64":
		return s.Arm64
	default:
		return ""
	}
}

// HeartbeatResponse — ответ на отметку о жизни.
//
// TargetAgentSha256 нужна самообновлению: сумма приезжает по TLS от
// платформы, которой агент уже доверяет, и ей проверяется бинарь, скачанный
// публичной ручкой. Старая платформа полей не шлёт — агент просто не
// обновляется, как и раньше.
type HeartbeatResponse struct {
	HostID             string            `json:"hostId"`
	TargetAgentVersion string            `json:"targetAgentVersion"`
	TargetAgentSha256  AgentSha256ByArch `json:"targetAgentSha256"`
	// InventoryRequestedAt — человек попросил осмотреть сервер (0210).
	//
	// Хостовое поле едет хостовым ответом, а не желаемым состоянием: там
	// строки приложений, и признак сервера пришлось бы дублировать в каждой.
	//
	// Метка времени, а не булево: по ней агент отличает новый запрос от того,
	// который уже выполнил, и не осматривает сервер по кругу, если отчёт не
	// доехал до платформы с первого раза.
	InventoryRequestedAt string `json:"inventoryRequestedAt"`

	// Task — задание с параметрами: снять слепок стека или перенести каталог
	// данных в том (0211).
	//
	// Отдельно от осмотра, потому что это разные вещи. Осмотр — состояние: он
	// идемпотентен, без параметров, и «попросили ещё раз» ничего не меняет.
	// Задание имеет цель (какой стек, какой каталог), выполняется один раз и
	// требует отчёта — по нему платформа узнаёт, что делать дальше.
	//
	// Не больше одного за раз: две операции над чужими данными одновременно —
	// это ровно тот случай, когда «а что было первым» выясняют по логам после
	// аварии.
	Task *HostTask `json:"task"`
}

// HostTask — задание платформы агенту.
type HostTask struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// Project — имя compose-проекта на хосте.
	Project string `json:"project"`
	// Dir — каталог с данными относительно каталога стека (для переноса).
	Dir string `json:"dir"`
	// Volume — имя тома, в который переносим.
	Volume string `json:"volume"`
	// BackupSet — какой набор копий разворачивать (задание restore, 0447).
	//
	// Имя набора, а не путь: путь на хосте агент собирает сам от своего
	// рабочего каталога. Принимать путь из задания значило бы дать платформе
	// право назвать любой каталог сервера — та же причина, по которой Dir
	// относительный.
	BackupSet string `json:"backupSet"`
}

// DesiredApp — одно приложение, каким его хочет видеть Scopework.
//
// Env содержит и открытые переменные, и секреты: на хосте разницы между ними
// нет, файл .env целиком закрыт правами 0600.
type DesiredApp struct {
	Slug         string            `json:"slug"`
	Domain       string            `json:"domain"`
	InternalPort int               `json:"internalPort"`
	ReleaseID    string            `json:"releaseId"`
	Compose      string            `json:"compose"`
	Env          map[string]string `json:"env"`
	// BuildArgs — переменные, доступные СБОРКЕ образа из репозитория.
	//
	// Отдельным полем, а не выборкой из Env: в Env открытые и секретные
	// перемешаны (на хосте они всё равно окажутся в одном .env), а в сборку
	// секрету нельзя — аргументы видны в `docker history` собранного образа.
	// Разделение проводит сервер, собирая это поле только из vars_public;
	// агент не может смешать их даже по ошибке.
	BuildArgs map[string]string `json:"buildArgs"`
	// Desired — "present" или "absent". Приложение, которое должно быть
	// остановлено, приходит здесь же с признаком absent, а не пропадает из
	// списка: пропажа неотличима от сбоя выдачи, и по ней нельзя безопасно
	// сносить стеки.
	Desired string `json:"desired"`
	// ReleaseStatus — статус релиза на сервере. Нужен, чтобы отличить
	// «ещё не применяли» от «пробовали и не вышло».
	ReleaseStatus string `json:"releaseStatus"`

	// Files — вспомогательные файлы конфигурации: конфиг Kong, инициализация
	// базы.
	//
	// Для приложений из каталога и для «своего compose» (0206). У приложения из
	// репозитория такие файлы лежат в самом репозитории, и класть поверх них
	// присланные значило бы молча подменять код клиента, — ему сервер шлёт
	// пустой список.
	//
	// Секретов здесь не бывает: содержимое статично, подстановка не делается.
	// Всё, что зависит от секретов, разворачивается уже внутри контейнера из
	// переменных окружения.
	Files []DesiredFile `json:"files"`

	// AdoptedVolumes — имена томов, к которым стеку разрешено подключаться
	// полем `name:` верхнеуровневого тома (0206).
	//
	// Обычному приложению имя тома выводит сам compose как `<проект>_<ключ>`, и
	// любое переопределение агент отвергает: им стек подключился бы к данным
	// вне себя, включая тома соседнего приложения того же хоста. Перехват
	// работающего стека — единственный случай, когда подключение к чужому по
	// имени тому и есть цель, поэтому разрешение узкое: только перечисленные
	// здесь имена, точным совпадением.
	//
	// Пустой список — запрет, и это состояние по умолчанию: старый сервер поля
	// не шлёт вовсе, и «поля нет» обязано значить «нельзя».
	AdoptedVolumes []string `json:"adoptedVolumes"`

	// Adopted — приложение взято под управление вместе с работающим стеком.
	//
	// Отдельным полем, а не по непустому AdoptedVolumes: перехват
	// stateless-стека томов не имеет, и вывод признака из списка отказывал
	// разворачивать ровно тот случай, ради которого перехват и делается.
	Adopted bool `json:"adopted"`

	// ApplySpec — сколько ждать подъёма и устойчивости. Свойство стека, а не
	// агента: десять образов на первом выкате не укладываются в пороги,
	// выведенные на двухконтейнерном n8n.
	ApplySpec ApplySpec `json:"applySpec"`

	// FirstRelease — у приложения это первый релиз, то есть на хосте не должно
	// быть ни его томов, ни каталога.
	//
	// Считает СЕРВЕР: только он знает историю приложения. Локальные отметки
	// агента теряются при переустановке, и «отметки нет» значит «не помню», а
	// не «впервые», — приняв одно за другое, агент отказался бы поднимать уже
	// работающее приложение.
	FirstRelease bool `json:"firstRelease"`
	// PurgeData — при снятии стека удалить и тома. Ставится только явным
	// выбором человека при удалении приложения: восстановить данные после
	// этого неоткуда.
	PurgeData bool `json:"purgeData"`

	// Routes — какие сервисы приложения публикуются наружу и под какими
	// доменами.
	//
	// Пустой список означает старый формат: один домен (Domain) на сервис
	// `app` с портом InternalPort. Совместимость нужна в обе стороны — агент
	// обновляется отдельно от сервера, и версия, потерявшая её, погасила бы
	// все сайты хоста до следующего обновления.
	Routes []DesiredRoute `json:"routes"`

	// SourceType — "template" или "git". У приложения из репозитория Compose
	// приходит ПУСТЫМ: описание стека лежит в самом репозитории, и агент
	// читает его после клона.
	SourceType string `json:"sourceType"`
	// BuildMethod — как получить образ сервиса app из репозитория. Имеет
	// смысл только при SourceType == "git".
	//
	//   "" / "compose" — по умолчанию, единственный способ до этого поля:
	//     читаем docker-compose.yml/compose.yaml из корня репозитория как есть.
	//   "dockerfile" — в репозитории нет compose-файла, только Dockerfile;
	//     агент сам кладёт в рабочую копию compose, который его собирает.
	//   "static" — в репозитории нет ни того, ни другого, только файлы для
	//     раздачи; агент кладёт compose с nginx:alpine поверх них.
	//
	// Старый агент это поле просто не знает (JSON его молча отбросит) и пойдёт
	// по единственному пути, который умеет, — читать compose из репозитория;
	// если его там нет, откажется явной ошибкой, а не тихой поломкой.
	BuildMethod string `json:"buildMethod"`
	GitRepo     string `json:"gitRepo"`
	GitBranch   string `json:"gitBranch"`
	// GitBaseDir — папка приложения ВНУТРИ репозитория (0284). Пусто — корень,
	// как было до появления поля.
	//
	// Клонируется репозиторий целиком, но описание стека (compose, Dockerfile,
	// файлы статики) агент ищет здесь, отсюда же запускает compose. Монорепо
	// иначе развернуть нельзя вовсе: в `apps/web` лежит своё приложение, в
	// `apps/api` — своё, а в корне нет ни одного compose-файла.
	//
	// Старый агент поля не знает и продолжит читать корень: приложение с
	// непустым значением у него не поднимется с явной ошибкой «нет файла
	// описания стека», а не молча развернёт не то.
	GitBaseDir string `json:"gitBaseDir"`
	// GitBuildContextRoot — собирать образ из КОРНЯ репозитория, а не из папки
	// приложения. Имеет смысл только при BuildMethod == "dockerfile".
	//
	// ЗАЧЕМ ОТДЕЛЬНЫЙ ФЛАГ. В монорепо `apps/web/Dockerfile` почти всегда
	// копирует корневые `package.json` и `package-lock.json` и соседние
	// пакеты — контекстом ему нужен корень, хотя сам файл лежит в подпапке.
	// Одного GitBaseDir здесь не хватает: с контекстом в папке приложения
	// такая сборка падает на первом же `COPY package-lock.json`.
	GitBuildContextRoot bool `json:"gitBuildContextRoot"`
	// GitKey — приватный ключ на чтение репозитория, открытым текстом.
	// Расшифрован сервером на последнем шаге перед отправкой по TLS; на диск
	// попадает только на время работы git и стирается сразу после.
	//
	// Приходит для подключения типа deploy_key. Для github_app вместо него
	// приходит GitToken.
	GitKey string `json:"gitKey"`
	// GitToken — короткоживущий токен установки GitHub App (около часа).
	//
	// Отдаётся git через credential helper, читающий его из окружения
	// процесса: на диск не попадает вовсе, в адрес репозитория не
	// подставляется и потому не оседает ни в .git/config, ни в выводе упавшей
	// команды. Заново выписывается на каждый опрос — хранить его агенту негде
	// и незачем.
	GitToken string `json:"gitToken"`

	// Addons — сервисы рядом с приложением (0186): postgres/redis в том же
	// compose. Только для git-приложений со сборкой dockerfile/static — агент
	// рендерит их в синтетический compose из этого разрешённого списка
	// (пришпиленные образы из каталога сервера). У источника «образ» аддоны
	// уже внутри compose_rendered. Старый агент поля не знает: приложение
	// поднимется без БД и упадёт health-гейтом — видимый отказ, не тихий.
	Addons []AddonSpec `json:"addons"`

	// NeedsBackup — релиз меняет версию приложения, и перед применением нужен
	// снимок данных. Ставится сервером только для обновлений: на обычном
	// выкате копировать нечего, данные не трогаются.
	NeedsBackup bool `json:"needsBackup"`
	// BackupSpec — что именно резервировать. Знание живёт в шаблоне: агент не
	// может догадаться, какой сервис является базой.
	BackupSpec BackupSpec `json:"backupSpec"`
	// BackupKeep — сколько наборов хранить на хосте. Ноль означает «поле не
	// прислали»: старая платформа рядом с новым агентом, и тогда действует
	// прежнее число (backupsToKeep). Ретенция считается наборами, а не днями,
	// потому что наборы агент видит на диске, а часам чужого хоста не верит.
	BackupKeep int `json:"backupKeep"`
	// RollbackCompose — описание стека ДО обновления. Снимок, а не ссылка на
	// прошлый релиз: откат должен работать, даже если релиз удалили.
	RollbackCompose string `json:"rollbackCompose"`

	// Allowances — послабления политики compose для этого стека (С1.5). Не
	// поле ответа: их ставит только приём подписанного пакета, из грантов
	// корня к этим байтам compose (signed_state.go). Пришедшее полем ответа
	// было бы разрешением от платформы, а ей выход за политику не положен.
	Allowances []composeguard.Allowance `json:"-"`
}

// AddonSpec — один сервис-аддон из разрешённого списка сервера.
type AddonSpec struct {
	Kind    string `json:"kind"`
	Service string `json:"service"`
	Image   string `json:"image"`
}

// FromGit — собирается ли приложение из репозитория.
func (a DesiredApp) FromGit() bool { return a.SourceType == "git" }

// UntrustedCompose — описание стека писал клиент, а не платформа: репозиторный
// compose и «свой compose» (0185).
//
// НА РЕШЕНИЕ «ПРОВЕРЯТЬ ИЛИ НЕТ» ЭТО БОЛЬШЕ НЕ ВЛИЯЕТ (задача С1.5,
// 18.09.2026): compose-guard стоит на любом источнике, включая шаблоны
// каталога и рендер образа. Довод «это писала платформа» перестаёт работать
// ровно тогда, когда он нужен, — если платформа окажется не собой.
//
// Признак оставлен: он отвечает на другой вопрос — чей текст перед нами, и это
// нужно для сообщений и для будущего разделения политик (что шаблону разрешено
// сверх общей — по подписанному манифесту, ADR-0082).
func (a DesiredApp) UntrustedCompose() bool {
	return a.FromGit() || a.SourceType == "compose"
}

// needsSyntheticCompose — репозиторий не содержит своего описания стека, и
// его собирает сам агент (Dockerfile или статика), а не читает готовое.
func (a DesiredApp) needsSyntheticCompose() bool {
	return a.BuildMethod == buildMethodDockerfile || a.BuildMethod == buildMethodStatic
}

// ShouldRun — должно ли приложение работать на хосте.
func (a DesiredApp) ShouldRun() bool { return a.Desired != "absent" }

// DesiredState — всё, что сервер хочет видеть на хосте: приложения и входы
// в реестры образов. Реестры едут той же поставкой, потому что вход обязан
// случиться ДО того, как compose начнёт тянуть образы.
type DesiredState struct {
	Apps       []DesiredApp         `json:"apps"`
	Registries []RegistryCredential `json:"registries"`
	// DenyIPs — заблокированные на этом хосте адреса и подсети (0204).
	// Список хостовой, а не маршрутный: сканер стучится во все домены сразу.
	// Срок жизни бана отсекает сервер — сюда приезжают только живые записи,
	// и агент о времени не помнит ничего: часы на чужом хосте могут идти как
	// угодно. Пустой список (или его отсутствие у старого сервера) означает
	// «никого не блокируем» — это безопасное умолчание, в отличие от политик
	// маршрута, где неизвестное значение закрывает маршрут целиком.
	DenyIPs []string `json:"denyIps"`
	// PlatformSubdomainBase — база платформенных поддоменов (P2-3). Домен,
	// оканчивающийся на неё, www-редиректа не получает: wildcard-запись
	// клиента покрывает ровно один уровень имён, и `www.` перед платформенным
	// поддоменом не резолвится никогда. Пусто у старого сервера и при
	// выключенной фиче — поведение прежнее.
	PlatformSubdomainBase string `json:"platformSubdomainBase"`
	// ObjectStorage — хранилище клиента для копий (ADR-0046). Пусто, когда
	// компания его не подключила: копии тогда просто остаются на диске, и это
	// не ошибка, а состояние.
	ObjectStorage *ObjectStorageSpec `json:"objectStorage,omitempty"`

	// Accepted — состояние можно применять (ADR-0093, решение 4). Ставит
	// клиент: без корней — когда в ответе есть список приложений, с корнями —
	// только за принятым подписанным пакетом. Не принято — прежнее состояние
	// остаётся на хосте, а не заменяется пустым.
	Accepted bool `json:"-"`
	// SignedPayloadSHA256 — sha256 байтов нагрузки DSSE принятого пакета;
	// пусто у неподписанного. Им локальный журнал записывает приход
	// подписанного состояния: плоских полей в таком ответе нет, а подписанные
	// байты — ровно то, что хеширует журнал отправленного на платформе.
	SignedPayloadSHA256 string `json:"-"`
}

type registryLoginReportItem struct {
	Registry string `json:"registry"`
	OK       bool   `json:"ok"`
}

type registryLoginReportRequest struct {
	Results []registryLoginReportItem `json:"results"`
}

type presenceRequest struct {
	Slugs []string `json:"slugs"`
}

type trafficReportRequest struct {
	Items []DomainTraffic `json:"items"`
	// Truncated — выборка усечена лимитами сбора: цифры занижены, и сервер
	// вправе показать это честно, а не выдавать за точные.
	Truncated bool `json:"truncated"`
}

type reportRequest struct {
	ReleaseID string         `json:"releaseId"`
	Status    string         `json:"status"`
	Detail    map[string]any `json:"detail"`
}

type healthReportRequest struct {
	Apps []healthReportItem `json:"apps"`
}

type healthReportItem struct {
	Slug   string         `json:"slug"`
	Status string         `json:"status"`
	Detail map[string]any `json:"detail"`
}

// ErrUnauthorized — сервер не признал агента: хост отозван либо ключ сменился.
var ErrUnauthorized = errors.New("сервер не признал агента")

// ErrClockSkew — часы хоста разошлись с платформой настолько, что подпись не
// принимается по метке времени.
//
// Отдельная ошибка, а не разновидность ErrUnauthorized: серия отказов
// «не признали» доводит агента до выхода с кодом 3, который systemd не
// перезапускает. Свежий VPS без синхронизации времени выключал себя навсегда за
// шесть минут — и печатал при этом «хост отозван», чего не было.
var ErrClockSkew = errors.New("часы сервера расходятся с платформой")

// Client — HTTP-клиент к BFF Scopework.
type Client struct {
	BaseURL string
	Version string
	http    *http.Client
	// longHTTP — для такта с удержанием (Ш-4): платформа держит ответ до
	// TickHoldSeconds, и общий тридцатисекундный потолок оборвал бы его раньше,
	// чем она успела бы ответить.
	longHTTP *http.Client

	// stateDir — каталог защёлок подписанного состояния (UseStateDir).
	stateDir string
	// now — часы проверки сертификата и доклада; nil — системные.
	now func() time.Time
	// lastSigning — итог проверки последнего ответа; уходит следующим
	// запросом (поле signing).
	signingMu   sync.Mutex
	lastSigning *SigningReport
}

// UseStateDir задаёт каталог состояния агента: там лежат защёлки против
// отката подписанного состояния. Агент с корнями без него не принимает
// ничего — принимать без защёлок значит принимать повтор старого пакета.
func (c *Client) UseStateDir(dir string) { c.stateDir = dir }

// TickHoldSeconds — сколько платформа держит такт, пока у хоста нет работы.
//
// ЗАЧЕМ УДЕРЖАНИЕ. Без него действие пользователя доезжает до хоста за время
// до целого интервала: человек нажал «выкатить», а агент узнает об этом на
// следующем такте. Удержанный запрос отвечает в тот момент, когда работа
// появилась, — доли секунды вместо «в течение минуты», которое интерфейс
// обещает и которое читается как медлительность.
//
// И это ДЕШЕВЛЕ прежнего, а не дороже: одно удерживаемое соединение вместо
// такта раз в минуту. Платформа внутри удержания в базу не ходит — её будит
// то самое действие пользователя.
//
// 25 секунд, а не минута: промежуточные прокси и балансировщики рвут долгие
// соединения по своим срокам, и чем ближе к их умолчаниям, тем чаще агент
// получал бы обрыв вместо ответа.
const TickHoldSeconds = 25

func NewClient(baseURL, version string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Version: version,
		// Таймаут обязателен: без него зависший ответ подвесил бы цикл опроса
		// до бесконечности, и агент замолчал бы, оставаясь «живым» процессом.
		http: &http.Client{Timeout: 30 * time.Second},
		// Запас над сроком удержания: платформа отвечает по нему сама, и рвать
		// соединение раньше значило бы терять её ответ на ровном месте.
		longHTTP: &http.Client{Timeout: (TickHoldSeconds + 20) * time.Second},
	}
}

// post отправляет запрос. Если передана личность, запрос подписывается.
//
// Подписывается строка `<МЕТОД>.<путь>.<отпечаток>.<метка времени>.<sha256 тела>`,
// и точно такую же собирает сервер (apps/web/src/lib/deploy/agentAuth.ts).
//
// Метод и путь входят в подпись намеренно: без них валидная подпись для одной
// ручки годилась бы для любой другой с тем же телом, а тело запроса состояния
// пустое.
//
// Тело подписывается ровно теми байтами, которые уходят в сеть: пересборка
// JSON на любой из сторон дала бы другой хеш и отказ.
//
// Регистрация подписи не несёт — на тот момент ключа сервер ещё не знает,
// доказательством там служит одноразовый токен.
func (c *Client) post(ctx context.Context, path string, payload, out any, id *Identity) error {
	return c.postVia(ctx, c.http, path, payload, out, id)
}

func (c *Client) postVia(
	ctx context.Context,
	httpClient *http.Client,
	path string,
	payload, out any,
	id *Identity,
) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "tracedocs-deploy-agent/"+c.Version)

	if id != nil {
		fingerprint := id.Fingerprint()
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		sum := sha256.Sum256(body)
		message := http.MethodPost + "." + path + "." + fingerprint + "." +
			timestamp + "." + hex.EncodeToString(sum[:])

		signature, err := id.Sign([]byte(message))
		if err != nil {
			return fmt.Errorf("не удалось подписать запрос: %w", err)
		}
		req.Header.Set("X-Deploy-Fingerprint", fingerprint)
		req.Header.Set("X-Deploy-Timestamp", timestamp)
		req.Header.Set("X-Deploy-Signature", signature)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Читаем ограниченно: ответ сервера тоже недоверенный вход, и раздутое
	// тело не должно съедать память агента на чужом хосте. Читаем на байт
	// больше потолка: обрезанный JSON дал бы ошибку разбора, а не честное
	// «ответ больше потолка».
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return fmt.Errorf("ответ %s больше потолка %d байт", path, maxResponseBytes)
	}

	if err := statusError(resp.StatusCode, path, raw); err != nil {
		return &HTTPStatusError{Code: resp.StatusCode, Err: err}
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("не удалось разобрать ответ: %w", err)
	}
	return nil
}

// maxResponseBytes — потолок ответа платформы. Пакет подписи в base64 на
// треть больше самого состояния, и прежний 1 МиБ стал бы тесен хосту с
// десятком приложений (ADR-0093, «Риски»).
const maxResponseBytes = 4 << 20

// HTTPStatusError — платформа ответила не 2xx. Код нужен квитанции недоставки
// (ADR-0077): «платформа лежит» и «платформа отказала» — разные беды, а текст
// ошибки для их различения не годится.
type HTTPStatusError struct {
	Code int
	Err  error
}

func (e *HTTPStatusError) Error() string { return e.Err.Error() }
func (e *HTTPStatusError) Unwrap() error { return e.Err }

func statusError(code int, path string, raw []byte) error {
	switch {
	case code == http.StatusUnauthorized:
		return ErrUnauthorized
	case code == http.StatusConflict && bytes.Contains(raw, []byte(`"clock_skew"`)):
		// Платформа возвращает своё время — называем расхождение числом, а не
		// оставляем человека гадать.
		var skew struct {
			ServerTime int64 `json:"serverTime"`
		}
		_ = json.Unmarshal(raw, &skew)
		if skew.ServerTime > 0 {
			delta := time.Now().Unix() - skew.ServerTime
			direction := "спешат"
			if delta < 0 {
				direction = "отстают"
				delta = -delta
			}
			return fmt.Errorf(
				"%w: часы хоста %s на %d с; включите синхронизацию времени (systemd-timesyncd или chrony)",
				ErrClockSkew, direction, delta)
		}
		return ErrClockSkew
	case code == http.StatusTooManyRequests:
		return fmt.Errorf("сервер ограничивает частоту запросов (429)")
	case code == http.StatusNotFound:
		// Отдельно от прочих: по нему агент понимает, что платформа старше его
		// самого и новой ручки не знает. Остальные коды такого смысла не несут.
		return fmt.Errorf("%w: %s", ErrEndpointUnknown, path)
	case code >= 300:
		return fmt.Errorf("сервер ответил %d", code)
	}
	return nil
}

// Enroll обменивает одноразовый токен установки на регистрацию публичного ключа.
func (c *Client) Enroll(ctx context.Context, token string, id Identity) (enrollResponse, error) {
	var out enrollResponse
	err := c.post(ctx, "/api/deploy/agent/enroll", enrollRequest{
		Token:        token,
		PublicKey:    id.PublicKey,
		Fingerprint:  id.Fingerprint(),
		AgentVersion: c.Version,
	}, &out, nil)
	return out, err
}

// Heartbeat отмечается на сервере и возвращает целевую версию агента.
func (c *Client) Heartbeat(ctx context.Context, id Identity, proxyError string) (HeartbeatResponse, error) {
	var out HeartbeatResponse
	err := c.post(ctx, "/api/deploy/agent/heartbeat", heartbeatRequest{
		AgentVersion: c.Version,
		// Текст режем и здесь, и на сервере: вывод docker бывает
		// многокилобайтным, а в отметке о жизни ему делать нечего.
		ProxyError: tail(proxyError, 1000),
	}, &out, &id)
	return out, err
}

// TickRequest — весь такт агента одним подписанным телом (Ш-3).
//
// ЗАЧЕМ. До этого такт стоил ШЕСТИ обращений к платформе: отметка о жизни,
// желаемое состояние, здоровье, трафик, окно угроз, список развёрнутого. Это
// 8 640 запросов в сутки с одного хоста, каждый со своей проверкой подписи и
// защитой от повторов, — при том что полезной работы в подавляющем
// большинстве тактов нет.
//
// Секции — указатели: nil означает «сказать нечего», и это НЕ то же самое, что
// пустое значение. Пустой список развёрнутого означает «на хосте ничего нет» и
// завершает удаление приложений; отсутствие секции не означает ничего.
type TickRequest struct {
	AgentVersion string `json:"agentVersion"`
	// ProxyError — пустая строка снимает отметку, отсутствие поля сохраняет
	// прежнюю. Разница существенная: иначе обновление агента выглядело бы как
	// самоизлечение прокси.
	ProxyError string `json:"proxyError"`
	// PrivilegeMode — под какими правами агент работает на хосте (ADR-0083):
	// `proxy` (свой пользователь + прокси сокета) или `root`. Едет каждый
	// такт, а не один раз при установке: хост может вернуться на старый юнит
	// после ручного вмешательства, и платформа обязана это увидеть.
	PrivilegeMode string                `json:"privilegeMode,omitempty"`
	Health        []healthReportItem    `json:"health,omitempty"`
	Presence      *presenceRequest      `json:"presence,omitempty"`
	Traffic       *trafficReportRequest `json:"traffic,omitempty"`
	Threat        *threatReportRequest  `json:"threat,omitempty"`
	Workloads     *WorkloadsSection     `json:"workloads,omitempty"`
	// Metrics — состояние хоста для раздела мониторинга серверов.
	//
	// Подключённый для развёртывания сервер уже отчитывается платформе каждую
	// минуту; требовать второй установки — агента мониторинга по SSH — ради тех
	// же цифр незачем. nil означает «снять не удалось», а не «нули».
	Metrics *HostMetrics `json:"metrics,omitempty"`
	// Posture — состояние защищённости сервера (sshd, fail2ban). Тем же
	// именем и тем же форматом, что у агента мониторинга: платформа кладёт
	// оба в одно хранилище и различать их не должна.
	Posture *HostPosture `json:"posture,omitempty"`
	// Checks — доступность опубликованных доменов, проверенная с самого хоста
	// (0237). Пусто, когда владелец проверки выключил.
	Checks []HealthCheckResult `json:"checks,omitempty"`
	// HoldSeconds — сколько платформе держать ответ, если работы для хоста нет
	// (Ш-4). Ноль означает «не держать»: так ведёт себя агент, которому важнее
	// не занимать соединение.
	HoldSeconds int `json:"holdSeconds,omitempty"`
	// StorageKeyAck — отпечаток ключа хранилища, который агент только что
	// принял и положил на диск. Платформа по нему затирает у себя секрет,
	// доставленный всем живым агентам: у неё он нужен только на время доставки.
	StorageKeyAck string `json:"storageKeyAck,omitempty"`
	// Storage — исход пробы хранилища копий (ADR-0046, решение 7).
	//
	// Едет вместе с отчётом о здоровье, а не своим каналом: хранилище — такая
	// же наблюдаемая зависимость, как приложение, и отдельный канал означал бы
	// второй способ узнать то же самое. nil — пробы в этом такте не было
	// (ближе часа с прошлой либо хранилище не подключено), и платформа не
	// меняет состояние: молчание не то же самое, что «недоступно».
	Storage *StorageProbeReport `json:"storage,omitempty"`
	// Report — номер такта, квитанции недоставленных и сигналы дрейфа
	// (ADR-0077). nil — номер не выделен: резерв не записался на диск.
	Report *ReportSection `json:"report,omitempty"`
	// LocalPolicy, LocalJournal, Trust — политика хоста, голова локального
	// журнала и отпечатки вшитых ключей (ADR-0095). Формы — у типов.
	LocalPolicy  *LocalPolicyReport  `json:"localPolicy,omitempty"`
	LocalJournal *LocalJournalReport `json:"localJournal,omitempty"`
	Trust        *TrustReport        `json:"trust,omitempty"`

	// Protocol — что агент исполняет и проверяет (ADR-0093, решение 1). В
	// теле, а не заголовком: тело покрыто подписью запроса. Ставит Tick сам.
	Protocol hoststate.Protocol `json:"protocol"`
	// Signing — итог проверки предыдущего ответа (ADR-0093, решение 7).
	// Только у агента с корнями и только после первого итога. Ставит Tick сам.
	Signing *SigningReport `json:"signing,omitempty"`
}

// StorageProbeReport — что агент узнал о хранилище в этом такте.
type StorageProbeReport struct {
	OK bool `json:"ok"`
	// Error — текст отказа, как его вернуло хранилище. Читает владелец
	// компании: «403 AccessDenied» он покажет своему администратору, «ошибка
	// хранилища» — нет.
	Error string `json:"error,omitempty"`
}

// TickResponse — ответ платформы на такт: то же, что раньше приезжало отметкой
// о жизни и запросом состояния, плюс интервал до следующего прихода.
type TickResponse struct {
	HeartbeatResponse
	DesiredState
	// NextPollSeconds — через сколько прийти снова (Ш-5). Ноль означает, что
	// платформа интервала не назвала, и агент держится своего флага.
	NextPollSeconds int `json:"nextPollSeconds"`
	// HealthChecksEnabled — проверять ли доступность опубликованных доменов
	// (0237). Признак приезжает ответом и применяется со следующего такта:
	// собирать его до первого ответа платформы неоткуда.
	HealthChecksEnabled bool `json:"healthChecksEnabled"`
	// Accepted и ReportAck — сырьём, а не типами: ответ недоверенный, и кривое
	// значение в них не должно ронять разбор всего ответа вместе с желаемым
	// состоянием. Разбираются SectionsOutcome и ParseReportAck.
	Accepted  json.RawMessage `json:"accepted"`
	ReportAck json.RawMessage `json:"reportAck"`
	// Raw — ответ как пришёл: хеш команды для локального журнала считается по
	// сырым байтам, пересборка разошлась бы с платформой (ADR-0095, п. 9).
	Raw json.RawMessage `json:"-"`

	// SignedState — подписанный пакет и значения секретов рядом (ADR-0092).
	// Агенту с корнями платформа плоских полей состояния не шлёт, а если
	// пришлют — они не применяются.
	SignedState json.RawMessage `json:"signedState"`
	// StateWithheld — почему пакета нет: подписант недоступен, отказал, не
	// настроен или протокол несовместим.
	StateWithheld string `json:"stateWithheld"`
}

// TickSectionsOutcome — какие секции окна журнала платформа приняла.
type TickSectionsOutcome struct {
	Traffic bool
	Threat  bool
	// Health и Presence — отчёты здоровья и списка развёрнутого приняты. По ним
	// ставится отметка гейта: отчёт, не дошедший до платформы, обязан уйти
	// следующим тактом, а не через срок гейта.
	Health   bool
	Presence bool
}

// WindowDelivered — можно ли двигать курсоры журналов (ADR-0077, решение 4).
//
// Достаточно одной принятой секции окна: при частичном успехе выбрана потеря
// непринятой половины, а не дубль принятой. У traffic_stats нет ключа
// идемпотентности, и дубль исказил бы статистику молча, а потерянная половина
// видна как провал. Окно, из которого нечего было отправлять, доставлено по
// определению.
func (o TickSectionsOutcome) WindowDelivered(req TickRequest) bool {
	if req.Traffic == nil && req.Threat == nil {
		return true
	}
	return o.Traffic || o.Threat
}

// SectionsOutcome — исход секций окна по ответу 2xx ручки такта.
//
// Ручка отдаёт `accepted.traffic` числом (−1 — не сохранено) и
// `accepted.threat` идентификатором снимка (null — не сохранено). Старая
// платформа поля не знает — её 2xx считается принятым; так же читается и
// неразборчивое значение: повтор принятого окна дал бы дубль.
func (r TickResponse) SectionsOutcome(req TickRequest) TickSectionsOutcome {
	var accepted map[string]json.RawMessage
	if json.Unmarshal(r.Accepted, &accepted) != nil {
		accepted = nil
	}
	sectionOK := func(key string, ok func(json.RawMessage) bool) bool {
		raw, present := accepted[key]
		return !present || ok(raw)
	}
	// У здоровья и списка развёрнутого отдельного поля в accepted нет: их
	// принимает сам ответ 2xx.
	out := TickSectionsOutcome{Health: req.Health != nil, Presence: req.Presence != nil}
	if req.Traffic != nil {
		out.Traffic = sectionOK("traffic", func(raw json.RawMessage) bool {
			var n float64
			return json.Unmarshal(raw, &n) == nil && n >= 0
		})
	}
	if req.Threat != nil {
		out.Threat = sectionOK("threat", func(raw json.RawMessage) bool {
			var id *string
			return json.Unmarshal(raw, &id) == nil && id != nil && *id != ""
		})
	}
	return out
}

// Tick проводит весь обмен одним запросом.
//
// ErrEndpointUnknown означает, что платформа ручки не знает — такое бывает
// ровно в одном случае: агент обновился раньше платформы. Штатно этого не
// происходит (бинарь агент берёт с неё же), но выкат бывает частичным, и
// падать на такой мелочи агент не должен: вызывающий откатывается на шесть
// прежних ручек.
//
// Проверка подписанного состояния — здесь же (acceptState): отказ проверки
// ошибкой не становится, состояние обнуляется с Accepted = false.
func (c *Client) Tick(ctx context.Context, id Identity, req TickRequest) (TickResponse, error) {
	req.Protocol = agentProtocol()
	req.Signing = c.pendingSigning()
	var out TickResponse
	var raw json.RawMessage
	if err := c.postVia(ctx, c.longHTTP, "/api/deploy/agent/tick", req, &raw, &id); err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out, fmt.Errorf("не удалось разобрать ответ: %w", err)
	}
	out.Raw = raw
	c.acceptState(id.Fingerprint(), &out.DesiredState, out.SignedState, out.StateWithheld)
	return out, nil
}

// ErrEndpointUnknown — платформа такой ручки не знает (404).
//
// Штатно этого не бывает: бинарь агент берёт с той же платформы. Но выкат
// бывает частичным, и падать на этом агент не должен — вызывающий откатывается
// на прежний способ обмена.
var ErrEndpointUnknown = errors.New("платформа не знает такой ручки")

// DesiredState забирает желаемое состояние хоста.
//
// Запрос подписывается обязательно: в ответе едут переменные приложений и
// токены реестров. Опознания по отпечатку тут мало — отпечаток не секрет.
//
// Правило приёма то же, что у такта: на этот путь агента загоняет ответ 404 на
// такт, и неподписанное здесь было бы обходом проверки (ADR-0093, решение 10).
func (c *Client) DesiredState(ctx context.Context, id Identity) (DesiredState, error) {
	req := stateRequest{Protocol: agentProtocol(), Signing: c.pendingSigning()}
	var out struct {
		DesiredState
		SignedState   json.RawMessage `json:"signedState"`
		StateWithheld string          `json:"stateWithheld"`
	}
	if err := c.post(ctx, "/api/deploy/agent/state", req, &out, &id); err != nil {
		return out.DesiredState, err
	}
	c.acceptState(id.Fingerprint(), &out.DesiredState, out.SignedState, out.StateWithheld)
	return out.DesiredState, nil
}

// stateRequest — тело /state: то же объявление и доклад, что в такте.
type stateRequest struct {
	Protocol hoststate.Protocol `json:"protocol"`
	Signing  *SigningReport     `json:"signing,omitempty"`
}

// ReportRegistryLogins сообщает серверу об итогах входов в реестры: по успеху
// обновляется last_used_at, по неудаче пишется аудит. Отправляются только
// реальные попытки, поэтому пустой список — не запрос.
func (c *Client) ReportRegistryLogins(ctx context.Context, id Identity, results []RegistryLoginResult) error {
	if len(results) == 0 {
		return nil
	}
	items := make([]registryLoginReportItem, 0, len(results))
	for _, r := range results {
		items = append(items, registryLoginReportItem{Registry: r.Registry, OK: r.OK})
	}
	return c.post(ctx, "/api/deploy/agent/registry-login",
		registryLoginReportRequest{Results: items}, nil, &id)
}

// ReportHealth отправляет состояние всех приложений одним запросом.
//
// Пакетом, а не по одному: при десятке приложений это десять подписанных
// запросов в минуту с каждого хоста вместо одного, и ровно ноль пользы от
// такого дробления.
func (c *Client) ReportHealth(ctx context.Context, id Identity, health []AppHealth) error {
	if len(health) == 0 {
		return nil
	}
	items := make([]healthReportItem, 0, len(health))
	for _, h := range health {
		items = append(items, healthReportItem{
			Slug:   h.Slug,
			Status: string(h.Status),
			Detail: h.Detail,
		})
	}
	return c.post(ctx, "/api/deploy/agent/health", healthReportRequest{Apps: items}, nil, &id)
}

// ReportPresence сообщает, что РЕАЛЬНО развёрнуто на хосте.
//
// По этому списку сервер завершает удаление приложений: помеченное на
// удаление и отсутствующее у агента считается снятым. Пока подтверждения нет,
// приложение остаётся видимым в состоянии «удаляется» — то есть выключенный
// хост не приводит к тихому появлению осиротевшего стека, о котором платформа
// забыла, а он продолжает работать с чужими данными.
//
// Отправляется на каждом цикле, даже пустым: пустой список — это осмысленный
// ответ «здесь ничего нет», по нему удаление тоже должно завершаться.
func (c *Client) ReportPresence(ctx context.Context, id Identity, slugs []string) error {
	if slugs == nil {
		slugs = []string{}
	}
	return c.post(ctx, "/api/deploy/agent/presence", presenceRequest{Slugs: slugs}, nil, &id)
}

type threatReportRequest struct {
	Payload   ThreatWindow `json:"payload"`
	Truncated bool         `json:"truncated"`
}

// ReportThreat отправляет агрегированное окно угроз с кромки Caddy.
func (c *Client) ReportThreat(
	ctx context.Context,
	id Identity,
	payload *ThreatWindow,
	truncated bool,
) error {
	if payload == nil || payload.Totals.Parsed == 0 {
		return nil
	}
	return c.post(ctx, "/api/deploy/agent/threats",
		threatReportRequest{Payload: *payload, Truncated: truncated}, nil, &id)
}

// ReportTraffic отправляет агрегаты access-лога (0187). Пустой список — не
// запрос: тишина на кромке не требует подписи и байтов.
//
// Старая платформа ручки не знает и ответит 404 — вызывающий логирует и
// живёт дальше: статистика не важнее применения желаемого состояния.
func (c *Client) ReportTraffic(
	ctx context.Context,
	id Identity,
	items []DomainTraffic,
	truncated bool,
) error {
	if len(items) == 0 {
		return nil
	}
	return c.post(ctx, "/api/deploy/agent/traffic",
		trafficReportRequest{Items: items, Truncated: truncated}, nil, &id)
}

// Report сообщает серверу результат применения релиза.
func (c *Client) Report(
	ctx context.Context,
	id Identity,
	releaseID, status string,
	detail map[string]any,
) error {
	return c.post(ctx, "/api/deploy/agent/report", reportRequest{
		ReleaseID: releaseID,
		Status:    status,
		Detail:    detail,
	}, nil, &id)
}

// DownloadAgentBinary скачивает бинарь агента своей архитектуры с платформы.
//
// Ручка публичная. Доверие обеспечивает не канал: сумма sha256 из
// heartbeat-ответа и — когда ключ выпущен — ПОДПИСЬ выпуска, которую платформа
// отдаёт заголовком `X-Release-Signature` (ADR-0082, задача С1.3). Сумма
// приезжает от той же стороны, что и файл, поэтому одна она отвечает на вопрос
// «дошло ли целым», но не на вопрос «то ли прислали».
//
// Размер ограничен: прокси, отвечающий бесконечным потоком, не должен съесть
// память хоста.
func (c *Client) DownloadAgentBinary(ctx context.Context, goarch string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/api/deploy/agent-binary?arch="+url.QueryEscape(goarch), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "tracedocs-deploy-agent/"+c.Version)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("платформа ответила %d на запрос бинаря", resp.StatusCode)
	}

	// 200 МиБ с запасом: бинарь агента — единицы мегабайт.
	const maxBinarySize = 200 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		return nil, "", err
	}
	if len(raw) > maxBinarySize {
		return nil, "", fmt.Errorf("бинарь больше %d байт — так не бывает, загрузка отброшена", maxBinarySize)
	}
	return raw, resp.Header.Get("X-Release-Signature"), nil
}

// ReportInventory отправляет карту сервера.
//
// Отдельной ручкой, а не полем отчёта о здоровье: осмотр случается по запросу
// человека и раз в недели, а здоровье — каждую минуту. Смешав их, мы бы гоняли
// килобайты карты в каждом цикле либо усложняли бы разбор отчёта условиями.
func (c *Client) ReportInventory(ctx context.Context, id Identity, inv HostInventory) error {
	return c.post(ctx, "/api/deploy/agent/inventory", inv, nil, &id)
}

// ReportSnapshot отправляет снятый рецепт стека.
//
// Тело несёт ЗНАЧЕНИЯ переменных чужого стека — единственный отчёт агента, где
// они есть. Платформа шифрует их при приёме; здесь они защищены только TLS и
// подписью, как и остальные секреты в этом канале (переменные приложений едут
// им же в обратную сторону).
func (c *Client) ReportSnapshot(ctx context.Context, id Identity, taskID string, snap StackSnapshot) error {
	return c.post(ctx, "/api/deploy/agent/snapshot", struct {
		TaskID   string        `json:"taskId"`
		Snapshot StackSnapshot `json:"snapshot"`
	}{TaskID: taskID, Snapshot: snap}, nil, &id)
}

// ReportMigration отправляет итог переноса каталога в том — со сверкой.
func (c *Client) ReportMigration(ctx context.Context, id Identity, taskID string, res MigrateResult, failure string) error {
	return c.post(ctx, "/api/deploy/agent/migration", struct {
		TaskID string        `json:"taskId"`
		Result MigrateResult `json:"result"`
		Error  string        `json:"error"`
	}{TaskID: taskID, Result: res, Error: tail(failure, 500)}, nil, &id)
}

// ReportBackup отправляет итог снятия копии: имя набора и его размер.
//
// Ручка та же, что у переноса данных: на платформе задание закрывает одна RPC
// (`deploy_report_host_task`), и заводить второй путь значило бы получить два
// места, где задание может остаться незакрытым.
// BackupUpload — исход выгрузки набора в хранилище клиента (ADR-0046).
//
// ОТДЕЛЬНО ОТ ОШИБКИ КОПИИ, потому что это разные беды с разным лечением:
// «копия не снялась» чинят на сервере, «копия не уехала» — в хранилище. Копия,
// снятая успешно и не уехавшая, остаётся успешной копией.
type BackupUpload struct {
	// Status — "done", "failed" или "skipped" (хранилище не подключено).
	Status string
	Key    string
	Bytes  int64
	Error  string
}

func (c *Client) ReportBackup(ctx context.Context, id Identity, taskID, set string, bytes int64, failure string, upload BackupUpload) error {
	result := map[string]any{"set": set, "bytes": bytes}
	if upload.Status != "" {
		result["upload"] = upload.Status
		result["uploadKey"] = upload.Key
		result["uploadBytes"] = upload.Bytes
		result["uploadError"] = tail(upload.Error, 500)
	}
	return c.post(ctx, "/api/deploy/agent/migration", struct {
		TaskID string         `json:"taskId"`
		Result map[string]any `json:"result"`
		Error  string         `json:"error"`
	}{
		TaskID: taskID,
		Result: result,
		Error:  tail(failure, 500),
	}, nil, &id)
}

// ReportRestore отправляет итог восстановления: из какого набора разворачивали
// и сколько это заняло.
//
// Ручка та же, что у переноса и копии: задание любого вида закрывает одна RPC
// на той стороне (`deploy_report_host_task`), и второй путь означал бы второе
// место, где задание может остаться незакрытым.
//
// ДЛИТЕЛЬНОСТЬ МЕРЯЕТ АГЕНТ и шлёт числом миллисекунд: платформа читает
// `result->>'ms'` и кладёт значение в deploy.app_restores.duration_ms. Считать
// её разностью меток нельзя — между постановкой задания и его началом стоит
// ожидание такта, ко времени восстановления отношения не имеющее, а в этой
// колонке лежит обещанное клиенту RTO.
func (c *Client) ReportRestore(
	ctx context.Context,
	id Identity,
	taskID, set string,
	ms int64,
	failure string,
) error {
	return c.post(ctx, "/api/deploy/agent/migration", struct {
		TaskID string         `json:"taskId"`
		Result map[string]any `json:"result"`
		Error  string         `json:"error"`
	}{
		TaskID: taskID,
		Result: map[string]any{"set": set, "ms": ms},
		Error:  tail(failure, 500),
	}, nil, &id)
}

// Сборка секций такта.
//
// Отдельные функции, а не литералы в цикле агента: поля запроса неэкспортируемы
// (их формы — часть контракта с платформой и меняться извне не должны), а
// правило «nil означает „сказать нечего“» должно жить рядом с ними, а не в
// вызывающем коде.

// HealthItems — отчёт о здоровье. Пустой список не отправляем: он означал бы
// «приложений нет», а это не то же самое, что «сказать нечего».
func HealthItems(health []AppHealth) []healthReportItem {
	if len(health) == 0 {
		return nil
	}
	items := make([]healthReportItem, 0, len(health))
	for _, h := range health {
		items = append(items, healthReportItem{Slug: h.Slug, Status: string(h.Status), Detail: h.Detail})
	}
	return items
}

// PresenceSection — список развёрнутого. Пустой список ОСМЫСЛЕН: «на хосте
// ничего нет» завершает удаление приложений, поэтому здесь nil означает только
// «состояние прочитать не удалось».
func PresenceSection(slugs []string) *presenceRequest {
	if slugs == nil {
		return nil
	}
	return &presenceRequest{Slugs: slugs}
}

// TrafficSection — агрегаты access-лога. Тишина на кромке байтов не требует.
func TrafficSection(items []DomainTraffic, truncated bool) *trafficReportRequest {
	if len(items) == 0 {
		return nil
	}
	return &trafficReportRequest{Items: items, Truncated: truncated}
}

// ThreatSection — окно угроз. Окно без разобранных строк не отправляем: это
// 1 440 пустых записей в сутки с хоста, из которых полезны единицы.
//
// Флаг отчёта — сложение: платформа пишет его в отдельную колонку снимка, и
// окно, усечённое изнутри (словарь пар попыток входа), иначе выглядело бы на
// панели полной выборкой.
func ThreatSection(payload *ThreatWindow, truncated bool) *threatReportRequest {
	if payload == nil || payload.Totals.Parsed == 0 {
		return nil
	}
	return &threatReportRequest{Payload: *payload, Truncated: truncated || payload.Truncated}
}

// ReportTickSections рассылает секции такта прежними отдельными ручками.
//
// Путь отката для случая «платформа старше агента». Ошибки склеиваются, а не
// прерывают рассылку: отчёты независимы, и потеря окна трафика не повод не
// отправить здоровье. Исход секций окна возвращается отдельно — по нему
// вызывающий решает судьбу курсоров журналов.
func (c *Client) ReportTickSections(ctx context.Context, id Identity, req TickRequest) (TickSectionsOutcome, error) {
	var failures []string
	send := func(name, path string, payload any) bool {
		if err := c.post(ctx, path, payload, nil, &id); err != nil {
			failures = append(failures, name+": "+err.Error())
			return false
		}
		return true
	}
	var outcome TickSectionsOutcome

	if len(req.Health) > 0 {
		outcome.Health = send("здоровье", "/api/deploy/agent/health", healthReportRequest{Apps: req.Health})
	}
	if req.Traffic != nil {
		outcome.Traffic = send("трафик", "/api/deploy/agent/traffic", *req.Traffic)
	}
	if req.Threat != nil {
		outcome.Threat = send("угрозы", "/api/deploy/agent/threats", *req.Threat)
	}
	if req.Presence != nil {
		outcome.Presence = send("развёрнутое", "/api/deploy/agent/presence", *req.Presence)
	}

	if len(failures) == 0 {
		return outcome, nil
	}
	return outcome, errors.New(strings.Join(failures, "; "))
}
