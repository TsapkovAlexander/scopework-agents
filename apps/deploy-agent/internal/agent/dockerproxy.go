package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
)

// Прокси сокета Docker: последний рубеж между агентом и демоном.
//
// ЗАЧЕМ. Доступ к /var/run/docker.sock — это root на хосте, без оговорок:
// любой, кто говорит с демоном, запускает контейнер с `privileged` и корнем
// хоста в томе и выходит из него администратором машины. Пока агент работал от
// root и держал сокет напрямую, ошибка в разборе compose, шаблон, подписанный
// по невнимательности, или дыра в самом агенте означали ровно это — root на
// чужом сервере ([ADR-0083](../../../docs/adr/ADR-0083-unprivileged-deploy-agent.md)).
//
// Прокси разрывает эту связь: агент работает от своего пользователя и видит не
// сокет демона, а этот прокси. Прокси пропускает перечисленные вызовы и
// отбивает всё остальное, а у вызовов, которыми создают контейнер, читает тело
// и отбивает привилегии.
//
// ПОЧЕМУ БЕЛЫЙ СПИСОК, А НЕ ЧЁРНЫЙ. Docker API растёт, и запрет «опасных»
// вызовов устареет на следующей версии демона: новый вызов приедет разрешённым
// по умолчанию. Разрешённых вызовов у агента немного, и их проще перечислить.
//
// ПОЧЕМУ ПРОВЕРЯЕМ ТЕЛО, А НЕ ТОЛЬКО ПУТЬ. Без `POST /containers/create` агент
// не поднимет ничего, а именно этим вызовом и получают root: одно поле
// `Privileged` или привязка `/:/host` в теле. Белый список путей без разбора
// тела — это разрешение на root, выданное вежливо.
//
// ГДЕ ВТОРАЯ ПОЛОВИНА ЭТОЙ ПОЛИТИКИ. В `compose_guard.go`: там те же привилегии
// ищутся в ТЕКСТЕ описания стека, до запуска. Две проверки не дублируют друг
// друга, а стоят в разных местах цепочки: guard объясняет человеку, что
// не так с его стеком, прокси не верит никому — включая наш собственный код,
// если платформа окажется не собой.

// dockerAPIVersionPrefix — необязательный префикс версии API (`/v1.44/…`).
var dockerAPIVersionPrefix = regexp.MustCompile(`^/v[0-9]+\.[0-9]+`)

// dockerProxyRule — один разрешённый вызов.
type dockerProxyRule struct {
	methods []string
	path    *regexp.Regexp
	// inspectBody — проверка тела, если у вызова оно опасно.
	inspectBody func(body []byte, env dockerBodyEnv) error
}

// Идентификатор контейнера, образа, сети, тома: имена compose содержат буквы,
// цифры, подчёркивание, точку и дефис; идентификаторы — шестнадцатеричные.
const dockerIDPattern = `[A-Za-z0-9][A-Za-z0-9_.-]*`

// dockerProxyRules — всё, что агенту РЕАЛЬНО нужно, и ничего сверх.
//
// Список собран по вызовам самого агента: `docker compose up/down/ps/logs`,
// `docker compose build`, `docker compose exec -T` (снятие копии базы),
// загрузка образов и уборка. Всё, чего здесь нет, отбивается с 403 — включая
// вызовы, которые появятся в Docker завтра.
var dockerProxyRules = []dockerProxyRule{
	// Опрос демона. Без него не работает ни один клиент.
	{methods: []string{"GET", "HEAD"}, path: regexp.MustCompile(`^/_ping$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/version$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/info$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/events$`)},

	// Контейнеры: чтение.
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/containers/json$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/containers/` + dockerIDPattern + `/(json|logs|stats|top|changes)$`)},

	// Контейнеры: жизненный цикл. `create` — единственный вызов, у которого
	// тело решает, получит ли контейнер права хоста.
	{
		methods:     []string{"POST"},
		path:        regexp.MustCompile(`^/containers/create$`),
		inspectBody: inspectContainerCreate,
	},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/containers/` + dockerIDPattern + `/(start|stop|restart|kill|wait|pause|unpause)$`)},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/containers/` + dockerIDPattern + `/attach$`)},
	{methods: []string{"DELETE"}, path: regexp.MustCompile(`^/containers/` + dockerIDPattern + `$`)},

	// Выполнение внутри контейнера: этим снимается копия базы (`pg_dump`).
	//
	// Права хоста это не даёт — процесс остаётся внутри контейнера с теми же
	// ограничениями. Но выйти за них можно, если контейнер привилегированный,
	// поэтому `create` выше и не даёт таких контейнеров появиться.
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/containers/` + dockerIDPattern + `/exec$`), inspectBody: inspectExecCreate},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/exec/` + dockerIDPattern + `/start$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/exec/` + dockerIDPattern + `/json$`)},

	// Образы: загрузка, сборка, чтение, уборка.
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/images/json$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/images/.+/(json|history)$`)},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/images/create$`)},
	{methods: []string{"DELETE"}, path: regexp.MustCompile(`^/images/.+$`)},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/build$`)},
	// BuildKit: сборка идёт через сессию, поднятую тем же клиентом.
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/session$`)},

	// Сети и тома: compose заводит их сам.
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/networks$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/networks/` + dockerIDPattern + `$`)},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/networks/create$`), inspectBody: inspectNetworkCreate},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/networks/` + dockerIDPattern + `/(connect|disconnect)$`)},
	{methods: []string{"DELETE"}, path: regexp.MustCompile(`^/networks/` + dockerIDPattern + `$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/volumes$`)},
	{methods: []string{"GET"}, path: regexp.MustCompile(`^/volumes/` + dockerIDPattern + `$`)},
	{methods: []string{"POST"}, path: regexp.MustCompile(`^/volumes/create$`), inspectBody: inspectVolumeCreate},
	{methods: []string{"DELETE"}, path: regexp.MustCompile(`^/volumes/` + dockerIDPattern + `$`)},
}

// dockerProxyMaxBody — предел тела, которое прокси читает целиком для разбора.
//
// Тела `create` измеряются килобайтами. Предел нужен, чтобы клиент не мог
// занять память прокси бесконечным телом: прокси работает от root, и его
// падение по памяти — отказ развёртывания на всём хосте.
const dockerProxyMaxBody = 4 << 20 // 4 МиБ

// hostConfigView — поля HostConfig, которыми получают права хоста, его память
// или хранилище не с этого сервера.
//
// Разбираем именно их, а не весь HostConfig: поля, которых здесь нет, правами
// хоста не распоряжаются, а перечислять всё целиком значило бы чинить этот
// разбор при каждом обновлении Docker.
type hostConfigView struct {
	Privileged        bool              `json:"Privileged"`
	Binds             []string          `json:"Binds"`
	Mounts            []mountView       `json:"Mounts"`
	CapAdd            []string          `json:"CapAdd"`
	Devices           []json.RawMessage `json:"Devices"`
	DeviceCgroupRules []string          `json:"DeviceCgroupRules"`
	SecurityOpt       []string          `json:"SecurityOpt"`
	CgroupParent      string            `json:"CgroupParent"`
	Cgroup            string            `json:"Cgroup"`
	NetworkMode       string            `json:"NetworkMode"`
	PidMode           string            `json:"PidMode"`
	IpcMode           string            `json:"IpcMode"`
	UTSMode           string            `json:"UTSMode"`
	UsernsMode        string            `json:"UsernsMode"`
	Sysctls           map[string]string `json:"Sysctls"`
	// Tmpfs — путь → опции монтирования строкой (`size=64m,mode=1777`).
	Tmpfs map[string]string `json:"Tmpfs"`
	// ShmSize — размер /dev/shm контейнера в байтах; см. composeguard.MaxShmBytes.
	ShmSize int64 `json:"ShmSize"`
	// VolumeDriver — драйвер, которым демон САМ заводит именованный том из
	// Binds и анонимный том, если такого ещё нет. Имя тома в Binds безобидно,
	// а драйвер рядом превращает его в сетевое хранилище.
	VolumeDriver string `json:"VolumeDriver"`
	// VolumesFrom — контейнеры-доноры `имя[:ro|:rw]`; см. checkVolumesFrom.
	VolumesFrom []string `json:"VolumesFrom"`
}

type mountView struct {
	Type          string `json:"Type"`
	Source        string `json:"Source"`
	Target        string `json:"Target"`
	VolumeOptions *struct {
		DriverConfig *struct {
			Name    string            `json:"Name"`
			Options map[string]string `json:"Options"`
		} `json:"DriverConfig"`
	} `json:"VolumeOptions"`
	TmpfsOptions *struct {
		SizeBytes int64 `json:"SizeBytes"`
		// Options — пары [ключ, значение] или одиночный флаг (API 1.46+).
		// Демон дописывает их ПОСЛЕ size из SizeBytes, и ядро берёт последнее
		// значение: предел в SizeBytes снимается одной парой ["size", "0"].
		Options [][]string `json:"Options"`
	} `json:"TmpfsOptions"`
}

// dockerBodyEnv — что проверкам тела известно о хосте.
type dockerBodyEnv struct {
	allowedBindRoots []string
	// containers — у кого спросить о существующем контейнере; nil — не у кого,
	// и тогда VolumesFrom отбивается целиком, а не пропускается.
	containers containerInspector
}

// containerInspector — спросить демон о контейнере (GET /containers/{name}/json).
type containerInspector interface {
	inspectContainer(name string) (donorContainerView, error)
}

// donorContainerView — поля ответа inspect, по которым судят о доноре томов.
type donorContainerView struct {
	// ID — полный идентификатор того контейнера, в который демон разрешил
	// запрошенную строку; сверяется с ней (см. checkVolumesFrom).
	ID     string `json:"Id"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Mounts []struct {
		Type   string `json:"Type"`
		Name   string `json:"Name"`
		Source string `json:"Source"`
		Driver string `json:"Driver"`
	} `json:"Mounts"`
}

// dockerProxyDonorInspectTimeout — сколько ждать ответа демона о доноре.
//
// Вопрос задаётся посреди чужого `create`, и клиент ждёт вместе с прокси.
// Inspect контейнера отвечает за миллисекунды; демон, молчащий дольше, либо
// завис, либо перегружен, и create в любом случае получит отказ — лучше
// быстрый, чем повисший `docker compose up`.
const dockerProxyDonorInspectTimeout = 5 * time.Second

// upstreamContainerInspector — вопрос о контейнере прямо к демону.
//
// Свой клиент, а не транспорт прокси: у того нет таймаута на заголовки ради
// потоковой сборки, а здесь ответ короткий и ждать его вечно нельзя.
//
// Ответ не кешируется: между проверкой и созданием донора могут подменить, и
// кеш растянул бы это окно с одного запроса на время жизни записи.
type upstreamContainerInspector struct {
	client *http.Client
}

func newUpstreamContainerInspector(socket string) containerInspector {
	return &upstreamContainerInspector{client: &http.Client{
		Timeout: dockerProxyDonorInspectTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}}
}

func (u *upstreamContainerInspector) inspectContainer(name string) (donorContainerView, error) {
	var view donorContainerView
	resp, err := u.client.Get("http://docker/containers/" + name + "/json")
	if err != nil {
		return view, fmt.Errorf("демон недоступен: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return view, fmt.Errorf("контейнер-донор %s не найден", tail(name, 120))
	default:
		return view, fmt.Errorf("демон ответил %d на вопрос о контейнере-доноре %s", resp.StatusCode, tail(name, 120))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, dockerProxyMaxBody)).Decode(&view); err != nil {
		return view, fmt.Errorf("ответ демона о контейнере-доноре %s не разобран: %w", tail(name, 120), err)
	}
	return view, nil
}

// dockerHostConfigFieldNames — JSON-имена всех полей HostConfig, включая
// встроенный Resources: объединение moby api/types/container от 19.03 до master.
//
// ЗАЧЕМ. Демоны до 27.0 разбирали тело create в runconfig.ContainerConfigWrapper,
// где *container.HostConfig встроен без тега («Deprecated. Exported to read
// attributes from json that are not in the inner host config structure»). Нет
// ключа `HostConfig` — getHostConfig() берёт HostConfig целиком с верхнего
// уровня тела; есть — подмешивает сверху Memory, MemorySwap, CpuShares,
// CpusetCpus и VolumeDriver. Прокси читает только `HostConfig`, так что
// `{"Image":"alpine","Binds":["/:/h"],"Privileged":true}` на хосте, перехваченном
// у Coolify с Docker 20.10–26, — это root без единой проверки. С 27.0 обёртка
// стала container.CreateRequest без встраивания, и демон эти поля молча
// выкидывает; отказ для него ничего не отнимает.
//
// ПОЧЕМУ ЗАКРЫТЫЙ СПИСОК ЗАПРЕТА. Опасность — только у полей, которые старый
// демон примет за HostConfig, а их набор старых демонов конечен и известен.
// Новое поле HostConfig старым демоном не читается вовсе, а новый демон не
// читает верхний уровень, — дописывать сюда при обновлении Docker нечего.
// Поля старых версий (KernelMemory*, Capabilities из 19.03) в списке остаются.
//
// ПЕРЕСЕЧЕНИЙ С Config НЕТ — сверено по api/types/container/config.go тех же
// версий; Cpuset обёртки 20.10–26 полем HostConfig не является и не запрещён.
// Поэтому законное тело compose этот список не задевает.
var dockerHostConfigFieldNames = []string{
	// HostConfig.
	"Annotations", "AutoRemove", "Binds", "CapAdd", "CapDrop", "Capabilities",
	"Cgroup", "CgroupnsMode", "ConsoleSize", "ContainerIDFile", "Dns",
	"DnsOptions", "DnsSearch", "ExtraHosts", "GroupAdd", "Init", "IpcMode",
	"Isolation", "Links", "LogConfig", "MaskedPaths", "Mounts", "NetworkMode",
	"OomScoreAdj", "PidMode", "PortBindings", "Privileged", "PublishAllPorts",
	"ReadonlyPaths", "ReadonlyRootfs", "RestartPolicy", "Runtime", "SecurityOpt",
	"ShmSize", "StorageOpt", "Sysctls", "Tmpfs", "UTSMode", "Umask",
	"UsernsMode", "VolumeDriver", "VolumesFrom",
	// Resources, встроенный в HostConfig.
	"BlkioDeviceReadBps", "BlkioDeviceReadIOps", "BlkioDeviceWriteBps",
	"BlkioDeviceWriteIOps", "BlkioWeight", "BlkioWeightDevice", "CgroupParent",
	"CpuCount", "CpuPercent", "CpuPeriod", "CpuQuota", "CpuRealtimePeriod",
	"CpuRealtimeRuntime", "CpuShares", "CpusetCpus", "CpusetMems",
	"DeviceCgroupRules", "DeviceRequests", "Devices", "IOMaximumBandwidth",
	"IOMaximumIOps", "KernelMemory", "KernelMemoryTCP", "Memory",
	"MemoryReservation", "MemorySwap", "MemorySwappiness", "NanoCpus",
	"OomKillDisable", "PidsLimit", "Ulimits",
}

// topLevelHostConfigKeys — ключи верхнего уровня тела, которые старый демон
// примет за HostConfig.
//
// Сравнение — strings.EqualFold: encoding/json демона сопоставляет ключ с полем
// без учёта регистра и по тем же классам свёртки Unicode (`Bindſ` — это Binds).
// Экранирование `\u0042inds` снимает сам разбор в map.
func topLevelHostConfigKeys(body []byte) ([]string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	var found []string
	for key := range top {
		for _, name := range dockerHostConfigFieldNames {
			if strings.EqualFold(key, name) {
				found = append(found, key)
				break
			}
		}
	}
	sort.Strings(found)
	return found, nil
}

type containerCreateView struct {
	// Labels — метки контейнера; нужна одна, com.docker.compose.project.
	Labels     map[string]string `json:"Labels"`
	HostConfig *hostConfigView   `json:"HostConfig"`
}

// inspectContainerCreate — та самая проверка, ради которой прокси написан.
func inspectContainerCreate(body []byte, env dockerBodyEnv) error {
	var req containerCreateView
	if err := json.Unmarshal(body, &req); err != nil {
		// Нечитаемое тело не пропускаем: «разобрать не смогли» — это не
		// «нарушений нет». Клиент, которому нечего скрывать, шлёт валидный JSON.
		return fmt.Errorf("тело запроса не разбирается как JSON: %w", err)
	}

	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// До проверки HostConfig и независимо от того, есть ли он: рядом с ним
	// старый демон тоже подмешивает поля сверху (см. dockerHostConfigFieldNames).
	topKeys, err := topLevelHostConfigKeys(body)
	if err != nil {
		return fmt.Errorf("тело запроса не разбирается как JSON: %w", err)
	}
	if len(topKeys) > 0 {
		add("поля HostConfig на верхнем уровне тела (%s): Docker до 27.0 применяет их как HostConfig "+
			"в обход проверки — перенесите их внутрь HostConfig", tail(strings.Join(topKeys, ", "), 200))
	}

	hc := req.HostConfig
	if hc == nil {
		if len(problems) > 0 {
			return errors.New(strings.Join(problems, "; "))
		}
		return nil
	}

	if hc.Privileged {
		add("Privileged: true — контейнер получает права хоста")
	}
	if len(hc.CapAdd) > 0 {
		add("CapAdd: расширение прав ядра запрещено (%s)", strings.Join(hc.CapAdd, ", "))
	}
	if len(hc.Devices) > 0 {
		add("Devices: проброс устройств хоста запрещён")
	}
	if len(hc.DeviceCgroupRules) > 0 {
		add("DeviceCgroupRules: доступ к устройствам хоста запрещён")
	}
	if hc.CgroupParent != "" {
		add("CgroupParent: управление cgroup запрещено")
	}
	if hc.Cgroup != "" {
		add("Cgroup: управление cgroup запрещено")
	}
	for _, opt := range hc.SecurityOpt {
		if strings.Contains(strings.ToLower(opt), "unconfined") {
			add("SecurityOpt %s отключает профиль изоляции", opt)
		}
	}
	for field, value := range map[string]string{
		"NetworkMode": hc.NetworkMode,
		"PidMode":     hc.PidMode,
		"IpcMode":     hc.IpcMode,
		"UTSMode":     hc.UTSMode,
		"UsernsMode":  hc.UsernsMode,
	} {
		low := strings.ToLower(value)
		// `host` — пространство имён хоста целиком. `container:` — вход в
		// пространство имён соседнего контейнера.
		//
		// NetworkMode тут исключение: compose ставит туда имя своей сети, и
		// `container:` для него тоже законен только в виде сети проекта.
		if low == "host" {
			if field == "NetworkMode" {
				add("NetworkMode: host — контейнер видит сеть хоста")
				continue
			}
			add("%s: host — контейнер получает пространство имён хоста", field)
		} else if strings.HasPrefix(low, "container:") {
			add("%s: %s — вход в пространство имён чужого контейнера запрещён", field, value)
		}
	}
	for key := range hc.Sysctls {
		// Пространство имён sysctl в контейнере ограничено демоном, но
		// `kernel.*` и `fs.*` из него не изолированы вовсе.
		if strings.HasPrefix(key, "kernel.") || strings.HasPrefix(key, "fs.") {
			add("Sysctls %s — параметр ядра хоста, не изолирован контейнером", key)
		}
	}

	for _, bind := range hc.Binds {
		if err := checkBindSource(bindSource(bind), env.allowedBindRoots); err != nil {
			add("Binds %s: %s", tail(bind, 120), err.Error())
		}
	}
	if hc.VolumeDriver != "" && !strings.EqualFold(hc.VolumeDriver, "local") {
		add("VolumeDriver %s: %s", hc.VolumeDriver, errForeignVolumeDriver)
	}
	for target, opts := range hc.Tmpfs {
		if err := composeguard.CheckTmpfsOptions(opts); err != nil {
			add("Tmpfs %s: %s", tail(target, 120), err.Error())
		}
	}
	if err := composeguard.CheckShmSize(hc.ShmSize); err != nil {
		add("ShmSize: %s", err.Error())
	}
	for _, m := range hc.Mounts {
		switch strings.ToLower(m.Type) {
		case "bind":
			if err := checkBindSource(m.Source, env.allowedBindRoots); err != nil {
				add("Mounts %s: %s", tail(m.Source, 120), err.Error())
			}
		case "volume":
			// Демон заводит том по DriverConfig, если тома с этим именем ещё
			// нет, — это тот же `volumes/create`, только в обход его проверки.
			if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
				dc := m.VolumeOptions.DriverConfig
				if err := checkVolumeDriver(dc.Name, dc.Options, env.allowedBindRoots); err != nil {
					add("Mounts %s: %s", tail(m.Target, 120), err.Error())
				}
			}
		case "tmpfs":
			if err := checkTmpfsMount(m); err != nil {
				add("Mounts tmpfs %s: %s", tail(m.Target, 120), err.Error())
			}
		}
	}
	problems = append(problems, checkVolumesFrom(hc.VolumesFrom, req.Labels, env)...)

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// dockerProxyMaxVolumesFrom — сколько строк VolumesFrom принимает прокси.
//
// Каждый донор — отдельный inspect к демону по очереди, до
// dockerProxyDonorInspectTimeout на каждый: без предела одно тело держит create
// и соединение прокси минутами. Считаются строки, а не различные ID — отказ
// обязан наступить до разбора и до первого вопроса демону. Законному стеку
// хватает с запасом: compose шлёт по строке на `volumes_from` сервиса.
const dockerProxyMaxVolumesFrom = 16

// composeProjectLabel — метка, которой compose помечает контейнеры стека.
const composeProjectLabel = "com.docker.compose.project"

// dockerFullID — полный идентификатор контейнера и ничего больше. Якоря
// обязательны и по второй причине: строка донора уходит в путь запроса к
// демону, и `../images` ушёл бы в другой вызов API.
var dockerFullID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// checkVolumesFrom — доноры HostConfig.VolumesFrom.
//
// ПОЧЕМУ ЭТО ПРАВА ХОСТА. Контейнеру достаётся ВСЁ, что смонтировано у донора,
// а проверка привязок тела этого не видит: в теле только имя. На хосте,
// перехваченном у Coolify, донором назовут контейнер самого Coolify с
// /var/run/docker.sock; у любого старого контейнера может быть привязка `/`.
// Поэтому донор пропускается, только если он из того же стека compose и его
// монтирования прошли бы проверку прокси, стой они в теле.
//
// Метку проекта в теле ставит тот же клиент, что шлёт запрос, так что против
// скомпрометированного агента барьер — проверка монтирований донора. Метка
// отсекает чужие стеки у честного клиента.
//
// ПОЧЕМУ ТОМА ДОНОРА — ТОЛЬКО ПО ДРАЙВЕРУ. Том local с `device` через inspect
// контейнера не виден. Но том, заведённый через прокси, уже проверен разбором
// `volumes/create`; а том, существовавший до агента, и так монтируется по имени
// через Binds (именованный том прокси пропускает всегда) — лишнего доступа
// VolumesFrom к нему не добавляет.
//
// ПОЧЕМУ ТОЛЬКО ПОЛНЫЙ ID. Тело уходит демону без изменений, и строку донора
// демон разрешает заново, уже при create (moby, daemon/container.go,
// GetContainer): полный ID → точное имя → уникальный префикс ID. Имя или
// префикс между inspect и create могут начать указывать на другой контейнер,
// и для этого не нужен новый create — хватит удаления. Контейнер с именем,
// равным префиксу ID контейнера Coolify, проходит inspect безобидным; его
// удаляют параллельно с create, префикс разрешается в Coolify, и в контейнер
// приезжает /var/run/docker.sock. Гонку можно повторять сколько угодно.
//
// Полный ID неизменен и не переиспользуется: ни удаление, ни создание не
// меняют, во что он разрешится, — только «в тот же контейнер» или «ни во что».
// Поэтому принимается только он, и сверяется с полем Id ответа inspect: 64-hex
// строка может оказаться и ИМЕНЕМ другого контейнера, тогда Id не совпадёт.
// Законный путь это не сужает: compose шлёт `volumes_from: [svc]` полным ID
// (проверено на compose v5.3.1), а сам агент `--volumes-from` не передаёт.
func checkVolumesFrom(entries []string, bodyLabels map[string]string, env dockerBodyEnv) []string {
	if len(entries) == 0 {
		return nil
	}
	if len(entries) > dockerProxyMaxVolumesFrom {
		return []string{fmt.Sprintf("VolumesFrom: доноров %d, предел прокси %d — каждый проверяется отдельным вопросом демону",
			len(entries), dockerProxyMaxVolumesFrom)}
	}
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	var names []string
	seen := map[string]bool{}
	for _, entry := range entries {
		name, mode, hasMode := strings.Cut(entry, ":")
		switch {
		case hasMode && mode != "ro" && mode != "rw":
			// Демон принимает и `:z`, `:ro,z` — перемаркировку SELinux; донору
			// из своего стека она не нужна, а разбирать её прокси не станет.
			add("VolumesFrom %s: режим %s не разбирается — допустимы только ro и rw", tail(entry, 120), tail(mode, 40))
		case name == "":
			add("VolumesFrom %s: пустое имя контейнера-донора", tail(entry, 120))
		case !dockerFullID.MatchString(name):
			add("VolumesFrom %s: донор принимается только по полному ID (64 шестнадцатеричных знака) — "+
				"имя и префикс ID демон разрешает заново при create, и к тому моменту они могут указывать на другой контейнер",
				tail(entry, 120))
		case !seen[name]:
			// compose при `a` и `a:ro` шлёт один ID дважды.
			seen[name] = true
			names = append(names, name)
		}
	}

	project := bodyLabels[composeProjectLabel]
	if project == "" {
		return append(problems, "VolumesFrom: в теле нет метки "+composeProjectLabel+
			" — не с чем сверить проект донора")
	}
	if env.containers == nil {
		return append(problems, "VolumesFrom: спросить демон о доноре не у кого — что смонтировано у донора, проверить нельзя")
	}

	for _, name := range names {
		donor, err := env.containers.inspectContainer(name)
		if err != nil {
			add("VolumesFrom %s: %s", tail(name, 120), err.Error())
			continue
		}
		if donor.ID != name {
			// 64-hex строка оказалась именем другого контейнера: проверены
			// были бы его монтирования, а не того, что смонтирует create.
			add("VolumesFrom %s: ID донора не совпадает с ответом демона (%s)", tail(name, 120), tail(donor.ID, 80))
			continue
		}
		if got := donor.Config.Labels[composeProjectLabel]; got != project {
			add("VolumesFrom %s: донор не из этого проекта (%q, а создаётся %q)", tail(name, 120), got, project)
		}
		for _, m := range donor.Mounts {
			switch strings.ToLower(m.Type) {
			case "bind":
				if err := checkBindSource(m.Source, env.allowedBindRoots); err != nil {
					add("VolumesFrom %s: у донора привязка %s: %s", tail(name, 120), tail(m.Source, 120), err.Error())
				}
			case "volume":
				if m.Driver != "" && !strings.EqualFold(m.Driver, "local") {
					add("VolumesFrom %s: у донора том %s: Driver %s: %s",
						tail(name, 120), tail(m.Name, 120), m.Driver, errForeignVolumeDriver)
				}
			case "tmpfs":
				// Каталога хоста нет.
			default:
				add("VolumesFrom %s: у донора монтирование типа %s — прокси такой тип не разбирает",
					tail(name, 120), tail(m.Type, 40))
			}
		}
	}
	return problems
}

// bindSource — левая часть привязки `источник:цель[:опции]`.
//
// Разбор идёт СЛЕВА, а не по последнему двоеточию: путь хоста может содержать
// двоеточие, и разбор справа отдал бы под источник кусок цели.
func bindSource(bind string) string {
	if i := strings.Index(bind, ":"); i >= 0 {
		return bind[:i]
	}
	// Привязка без двоеточия — это анонимный том, каталога хоста нет.
	return ""
}

// checkBindSource — можно ли монтировать этот источник.
//
// Именованный том (источник без ведущего слэша) разрешён всегда: он живёт в
// пространстве демона и каталогов хоста не открывает.
//
// ПОЧЕМУ РАСКРЫВАЕМ ССЫЛКИ. Ядро монтирует то, куда ведёт путь, а не то, как
// он написан. В git-репозитории приложения может лежать `data -> /`: лексически
// путь внутри рабочего каталога, а в контейнер уезжает корень хоста. Поэтому
// префикс сравнивается по раскрытому пути, а сокет Docker ищется в обоих.
//
// Корни раскрываются тем же способом: рабочий каталог сам может лежать за
// ссылкой (`/opt` на отдельном разделе, `/var` -> `/private/var` на macOS), и
// без этого раскрытый источник не совпал бы с нераскрытым корнем — ложный
// отказ законной привязке. Корни — доверенная настройка, поэтому если корень
// не раскрывается, берётся как написан.
//
// ЧЕГО ЭТО НЕ ЗАКРЫВАЕТ. Монтирование делает демон при `start`, а не при
// `create`, и повторно при каждом перезапуске по restart policy — мимо прокси.
// Подмену каталога на ссылку ПОСЛЕ create эта проверка не видит, а сделать её
// могут сам агент (он владелец рабочих каталогов) и любой контейнер с
// привязкой рабочего каталога на запись. Проверка закрывает ссылки, которые уже
// лежат на месте: из репозитория, от прошлого запуска. Полное закрытие —
// отдельный rootless dockerd на приложение (см. начало compose_guard.go), не
// прокси.
func checkBindSource(source string, allowedBindRoots []string) error {
	if source == "" || !strings.HasPrefix(source, "/") {
		return nil
	}
	// До Clean, по исходной строке: Clean убирает `l/..` лексически, а ядро
	// разрешает `..` ПОСЛЕ ссылки. При `l -> /вне/deep` путь `<корень>/l/../x`
	// очищается в `<корень>/x`, а монтируется `/вне/x`. Демон источник не
	// очищает (вживую Mounts[].Source = `/tmp/zqx/l/../x`), так что проверять
	// приходится то, что написано. Законному источнику `..` не нужен: compose
	// шлёт абсолютные очищенные пути, агент строит их через filepath.Join.
	if composeguard.HasDotDotSegment(source) {
		return errors.New("в источнике привязки сегмент `..`: ядро разрешает его после ссылок, " +
			"и путь может вести не туда, куда выглядит — запишите путь без `..`")
	}
	clean := filepath.Clean(source)
	if isDockerSocketPath(clean) {
		// Отдельной строкой, хотя проверка корней это тоже поймала бы:
		// сокет демона в томе — ровно тот путь, ради которого прокси и стоит.
		return errors.New("сокет Docker в контейнере — это права хоста")
	}
	resolved, err := composeguard.ResolveBindPath(clean)
	if err != nil {
		return fmt.Errorf("источник привязки не раскрывается (висячая ссылка, петля или нет доступа) — куда он ведёт, неизвестно: %w", err)
	}
	if isDockerSocketPath(resolved) {
		return fmt.Errorf("ссылка ведёт в %s: сокет Docker в контейнере — это права хоста", resolved)
	}
	for _, root := range allowedBindRoots {
		root = filepath.Clean(root)
		if r, err := composeguard.ResolveBindPath(root); err == nil {
			root = r
		}
		if resolved == root || strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			return nil
		}
	}
	if resolved != clean {
		return fmt.Errorf("каталог хоста вне рабочих каталогов агента (%s): ссылка ведёт в %s",
			strings.Join(allowedBindRoots, ", "), resolved)
	}
	return fmt.Errorf("каталог хоста вне рабочих каталогов агента (%s)",
		strings.Join(allowedBindRoots, ", "))
}

// isDockerSocketPath — похож ли путь на сокет демона.
func isDockerSocketPath(p string) bool {
	return p == "/var/run/docker.sock" || p == "/run/docker.sock" ||
		strings.HasSuffix(p, "/docker.sock")
}

// inspectExecCreate — запрет привилегированного exec.
//
// `Privileged: true` у exec поднимает права процесса внутри уже работающего
// контейнера: без этой проверки непривилегированный контейнер годился бы как
// точка входа.
func inspectExecCreate(body []byte, _ dockerBodyEnv) error {
	var req struct {
		Privileged bool `json:"Privileged"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("тело запроса не разбирается как JSON: %w", err)
	}
	if req.Privileged {
		return errors.New("Privileged: true у exec поднимает права внутри контейнера")
	}
	return nil
}

// inspectNetworkCreate — запрет сетей, выводящих контейнер на хост.
func inspectNetworkCreate(body []byte, _ dockerBodyEnv) error {
	var req struct {
		Driver  string            `json:"Driver"`
		Options map[string]string `json:"Options"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("тело запроса не разбирается как JSON: %w", err)
	}
	switch strings.ToLower(req.Driver) {
	case "", "bridge", "overlay":
		// Пусто = bridge по умолчанию.
	default:
		return fmt.Errorf("Driver %s: сеть вне bridge выводит контейнер на интерфейсы хоста", req.Driver)
	}
	return nil
}

// inspectVolumeCreate — запрет тома, который на деле является каталогом хоста.
//
// Драйвер `local` с опцией `device` монтирует в контейнер что угодно с хоста,
// а выглядит в compose как обычный именованный том. Без этой проверки запрет
// привязок обходился бы одним объявлением тома.
func inspectVolumeCreate(body []byte, env dockerBodyEnv) error {
	var req struct {
		Driver     string            `json:"Driver"`
		DriverOpts map[string]string `json:"DriverOpts"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("тело запроса не разбирается как JSON: %w", err)
	}
	return checkVolumeDriver(req.Driver, req.DriverOpts, env.allowedBindRoots)
}

// errForeignVolumeDriver — почему драйвер тома, кроме local, не пускаем.
const errForeignVolumeDriver = "драйвер тома, кроме local, запрещён: сторонние " +
	"драйверы монтируют хранилище не с этого сервера, и прокси не видит, что именно"

// checkVolumeDriver — общая проверка тома для `volumes/create` и для тома,
// объявленного прямо в `Mounts` у `containers/create`.
//
// ПОЧЕМУ ТОЛЬКО local. Драйвер nfs, cifs или плагин — это монтирование чужого
// хранилища: сетевой диск другого клиента, внутреннее хранилище за сетью
// хоста, выход с сервера клиента в его же локальную сеть. Ни один шаблон
// каталога и ни одно приложение из git чужих драйверов не объявляет: compose
// без `driver` шлёт `local`, а `driver_opts` запрещает ещё compose_guard.
func checkVolumeDriver(driver string, opts map[string]string, allowedBindRoots []string) error {
	if driver != "" && !strings.EqualFold(driver, "local") {
		return fmt.Errorf("Driver %s: %s", driver, errForeignVolumeDriver)
	}
	return checkLocalVolumeOpts(opts, allowedBindRoots)
}

// checkLocalVolumeOpts — опции драйвера local.
//
// Драйвер local — это вызов mount(2) с опциями из запроса: `type` — файловая
// система, `o` — опции монтирования, `device` — что монтировать. Запрет по
// списку опасных систем (nfs, cifs) устарел бы на первой же не названной:
// overlay с `lowerdir=/` отдаёт корень хоста, ext4 на блочном устройстве —
// диск хоста, smb3 — тот же cifs. Поэтому разрешённых ровно два вида: привязка
// каталога внутри рабочих каталогов агента и tmpfs с пределом.
func checkLocalVolumeOpts(opts map[string]string, allowedBindRoots []string) error {
	for key := range opts {
		switch key {
		case "type", "o", "device":
		default:
			// Драйвер local других ключей не принимает, так что законному
			// тому они не нужны; а ключ в другом регистре (`Type`) разошёлся
			// бы с тем, что проверено здесь.
			return fmt.Errorf("DriverOpts %s: неизвестная опция тома local", tail(key, 60))
		}
	}
	mountOpts := opts["o"]
	device := opts["device"]
	// Адрес в опциях — это nfs или cifs под любым `type`: сетевое хранилище.
	if strings.Contains(strings.ToLower(mountOpts), "addr=") {
		return fmt.Errorf("DriverOpts o=%s: addr= — адрес сетевого хранилища, монтирование с чужого узла запрещено",
			tail(mountOpts, 120))
	}
	switch fsType := strings.ToLower(opts["type"]); fsType {
	case "", "none":
		if device == "" {
			return nil
		}
		// Относительный путь mount(2) разрешает от рабочего каталога демона,
		// то есть от корня хоста: `etc` — это /etc, и checkBindSource принял
		// бы его за имя тома.
		if !strings.HasPrefix(device, "/") {
			return fmt.Errorf("DriverOpts device %s: путь привязки обязан быть абсолютным", tail(device, 120))
		}
		if err := checkBindSource(device, allowedBindRoots); err != nil {
			return fmt.Errorf("DriverOpts device %s: %s", tail(device, 120), err.Error())
		}
		return nil
	case "tmpfs":
		// Флаги привязки в `o` отбивает CheckTmpfsOptions: с ними ядро не
		// смотрит на тип, и device монтируется как каталог хоста.
		if err := composeguard.CheckTmpfsOptions(mountOpts); err != nil {
			return fmt.Errorf("DriverOpts type=tmpfs: %s", err.Error())
		}
		// У tmpfs нет источника: device для ядра — только имя в таблице
		// монтирований. Путь здесь осмыслен лишь вместе с флагом привязки,
		// поэтому принимаем ровно то, что шлёт compose, и пустое значение.
		if device != "" && device != "tmpfs" {
			return fmt.Errorf("DriverOpts type=tmpfs device %s: у tmpfs источник не задаётся, допустимо только device=tmpfs",
				tail(device, 120))
		}
		return nil
	default:
		return fmt.Errorf("DriverOpts type=%s: том local монтирует только каталог внутри рабочих каталогов агента "+
			"(type=none, o=bind) или tmpfs с пределом; сетевые и дисковые файловые системы запрещены", tail(fsType, 60))
	}
}

// checkTmpfsMount — tmpfs, объявленный в `Mounts`.
func checkTmpfsMount(m mountView) error {
	var parts []string
	if m.TmpfsOptions != nil {
		if m.TmpfsOptions.SizeBytes < 0 {
			return fmt.Errorf("SizeBytes %d: отрицательный размер", m.TmpfsOptions.SizeBytes)
		}
		// SizeBytes 0 — «не задан», то есть половина памяти хоста.
		if m.TmpfsOptions.SizeBytes > 0 {
			parts = append(parts, fmt.Sprintf("size=%d", m.TmpfsOptions.SizeBytes))
		}
		// Тем же порядком, что и демон: сначала size из SizeBytes, потом
		// Options — ядро применит последнее.
		for _, o := range m.TmpfsOptions.Options {
			parts = append(parts, strings.Join(o, "="))
		}
	}
	return composeguard.CheckTmpfsOptions(strings.Join(parts, ","))
}

// dockerProxyDecision — решение по одному запросу.
type dockerProxyDecision struct {
	Allowed bool
	Reason  string
}

// decideDockerProxy — пропустить или отбить.
// containers вариативный, чтобы прежние вызовы собирались: без него VolumesFrom отбивается.
func decideDockerProxy(method, rawPath string, body []byte, allowedBindRoots []string, containers ...containerInspector) dockerProxyDecision {
	path := dockerAPIVersionPrefix.ReplaceAllString(rawPath, "")
	if path == "" {
		path = "/"
	}
	for _, rule := range dockerProxyRules {
		if !matchMethod(rule.methods, method) || !rule.path.MatchString(path) {
			continue
		}
		if rule.inspectBody != nil {
			env := dockerBodyEnv{allowedBindRoots: allowedBindRoots}
			if len(containers) > 0 {
				env.containers = containers[0]
			}
			if err := rule.inspectBody(body, env); err != nil {
				return dockerProxyDecision{Reason: err.Error()}
			}
		}
		return dockerProxyDecision{Allowed: true}
	}
	return dockerProxyDecision{Reason: fmt.Sprintf("вызов %s %s не входит в список разрешённых агенту", method, tail(path, 120))}
}

func matchMethod(methods []string, method string) bool {
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

// DockerProxyOptions — настройки прокси сокета.
type DockerProxyOptions struct {
	// UpstreamSocket — сокет демона Docker.
	UpstreamSocket string
	// ListenSocket — сокет, который слушает прокси и видит агент.
	ListenSocket string
	// AllowedBindRoots — каталоги хоста, которые разрешено монтировать.
	AllowedBindRoots []string
	// SocketUID/SocketGID — владелец сокета; -1 оставляет как есть.
	SocketUID int
	SocketGID int
	// Logf — куда писать отказы. Отказ пишется всегда: молчащий запрет
	// неотличим от поломки демона.
	Logf func(format string, args ...any)
	// PolicyPath — файл политики сервера (ADR-0095); пусто — PolicyPath
	// пакета. Пустое значение не выключает проверку: забытое поле не должно
	// молча открывать демона в режиме наблюдения.
	PolicyPath string
}

// RunDockerProxy поднимает прокси и работает до отмены контекста.
func RunDockerProxy(ctx context.Context, opts DockerProxyOptions) error {
	if opts.UpstreamSocket == "" {
		opts.UpstreamSocket = "/var/run/docker.sock"
	}
	if opts.ListenSocket == "" {
		return errors.New("не задан путь сокета, который слушает прокси")
	}
	if len(opts.AllowedBindRoots) == 0 {
		return errors.New("не заданы каталоги, которые разрешено монтировать: пустой список запретил бы всё, включая работу агента")
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}

	// Старый сокет мог остаться от прошлого запуска: bind по занятому пути
	// отказывает, и прокси не поднимался бы после несмертельного падения.
	if err := os.Remove(opts.ListenSocket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("не удалось убрать прежний сокет %s: %w", opts.ListenSocket, err)
	}
	if err := os.MkdirAll(filepath.Dir(opts.ListenSocket), 0o750); err != nil {
		return fmt.Errorf("каталог сокета: %w", err)
	}

	listener, err := net.Listen("unix", opts.ListenSocket)
	if err != nil {
		return fmt.Errorf("не удалось занять сокет %s: %w", opts.ListenSocket, err)
	}
	defer listener.Close()

	// Права ставим ДО того, как кто-то успел подключиться: сокет, созданный с
	// умолчаниями, доступен всем локальным пользователям, а за ним стоит демон.
	if err := os.Chmod(opts.ListenSocket, 0o660); err != nil {
		return fmt.Errorf("права на сокет: %w", err)
	}
	if opts.SocketUID >= 0 || opts.SocketGID >= 0 {
		uid, gid := opts.SocketUID, opts.SocketGID
		if uid < 0 {
			uid = os.Getuid()
		}
		if gid < 0 {
			gid = os.Getgid()
		}
		if err := os.Chown(opts.ListenSocket, uid, gid); err != nil {
			return fmt.Errorf("владелец сокета: %w", err)
		}
	}

	handler := newDockerProxyHandler(opts)
	server := &http.Server{Handler: handler}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	opts.Logf("прокси сокета Docker слушает %s (демон: %s)", opts.ListenSocket, opts.UpstreamSocket)
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// dockerProxyPolicy — режим сервера для прокси (ADR-0095, п. 5).
//
// Файл перечитывается, когда у него сменились время изменения или размер:
// правка действует со следующего вызова без перезапуска прокси, а разбирать
// файл на каждый вызов демона root-процессу незачем.
type dockerProxyPolicy struct {
	path string

	mu      sync.Mutex
	stamp   string
	observe bool
}

// policyStamp — отпечаток записи файла политики: время изменения и размер и
// самой записи в каталоге, и того, на что она указывает.
//
// Одного Stat мало: висячая ссылка для него неотличима от отсутствия файла, и
// прокси, закэшировавший «файла нет», пропустил бы запись там, где агент
// видит негодный файл и закрыл всё.
func policyStamp(path string) string {
	describe := func(info os.FileInfo, err error) string {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return "нет"
		case err != nil:
			return "ошибка " + err.Error()
		}
		return fmt.Sprintf("%v %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano())
	}
	return describe(os.Lstat(path)) + " | " + describe(os.Stat(path))
}

// observeOnly — пропускать ли только чтение.
func (pp *dockerProxyPolicy) observeOnly() bool {
	stamp := policyStamp(pp.path)
	pp.mu.Lock()
	defer pp.mu.Unlock()
	if stamp == pp.stamp {
		return pp.observe
	}
	pp.stamp, pp.observe = stamp, LoadLocalPolicyFrom(pp.path).ObserveOnly()
	return pp.observe
}

// observeRefusal — почему вызов не проходит в режиме наблюдения; пусто —
// проходит дальше, к белому списку. Пропускается ПЕРЕСЕЧЕНИЕ списка с
// GET/HEAD, а не замена: чтение вне списка по-прежнему отбивается.
func observeRefusal(r *http.Request) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "политика сервера: режим наблюдения — пропускается только чтение"
	}
	// Подключение к потоку контейнера — ввод в него, а не чтение, каким бы
	// методом ни пришло.
	if r.Header.Get("Upgrade") != "" || headerHasToken(r.Header, "Connection", "upgrade") {
		return "политика сервера: режим наблюдения — подключение к контейнеру запрещено"
	}
	return ""
}

func headerHasToken(h http.Header, name, token string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func newDockerProxyHandler(opts DockerProxyOptions) http.Handler {
	policyPath := opts.PolicyPath
	if policyPath == "" {
		policyPath = PolicyPath
	}
	policy := &dockerProxyPolicy{path: policyPath}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", opts.UpstreamSocket)
		},
		// Сборка и логи идут потоком; буферизация ответа превратила бы
		// `docker compose build` в тишину на несколько минут.
		ResponseHeaderTimeout: 0,
	}
	donors := newUpstreamContainerInspector(opts.UpstreamSocket)
	reverse := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = "docker"
		},
		Transport:     transport,
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			opts.Logf("прокси: демон не ответил: %v", err)
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "demon unreachable\n")
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Политика — ДО разбора тела: в наблюдении запись отбивается целиком,
		// и читать её тело незачем.
		if policy.observeOnly() {
			if reason := observeRefusal(r); reason != "" {
				denyDockerProxy(w, opts, r, reason)
				return
			}
		}
		// Версия API и тело start — в любом режиме (dockerproxy_request.go).
		if reason := refuseDockerRequest(r); reason != "" {
			denyDockerProxy(w, opts, r, reason)
			return
		}

		var body []byte
		if needsBodyInspection(r) {
			limited := io.LimitReader(r.Body, dockerProxyMaxBody+1)
			read, err := io.ReadAll(limited)
			if err != nil {
				denyDockerProxy(w, opts, r, "тело запроса не прочитано: "+err.Error())
				return
			}
			if len(read) > dockerProxyMaxBody {
				denyDockerProxy(w, opts, r, "тело запроса больше предела прокси")
				return
			}
			body = read
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			r.ContentLength = int64(len(body))
		}

		decision := decideDockerProxy(r.Method, r.URL.Path, body, opts.AllowedBindRoots, donors)
		if !decision.Allowed {
			denyDockerProxy(w, opts, r, decision.Reason)
			return
		}
		reverse.ServeHTTP(w, r)
	})
}

// needsBodyInspection — нужно ли читать тело целиком.
//
// Тело читается только у вызовов, где оно решает; у сборки образа телом идёт
// весь контекст в несколько сот мегабайт, и читать его в память значило бы
// положить прокси на первом же приложении.
func needsBodyInspection(r *http.Request) bool {
	path := dockerAPIVersionPrefix.ReplaceAllString(r.URL.Path, "")
	for _, rule := range dockerProxyRules {
		if rule.inspectBody != nil && matchMethod(rule.methods, r.Method) && rule.path.MatchString(path) {
			return true
		}
	}
	return false
}

func denyDockerProxy(w http.ResponseWriter, opts DockerProxyOptions, r *http.Request, reason string) {
	opts.Logf("ОТКАЗ %s %s: %s", r.Method, r.URL.Path, reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "прокси сокета Scopework: " + reason,
	})
}
