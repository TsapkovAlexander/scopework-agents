// Package composeguard — политика compose, общая для агента и подписанта
// (ADR-0082, решения 6 и 7; ADR-0092, решение 5): один код решает, что можно
// поднять на хосте клиента, до подписи и перед подъёмом. Две копии разошлись бы
// на первом же новом поле, и стек, отвергнутый агентом, подписант бы подписал.
//
// Пакет работает только с уже нормализованным видом и текстом файлов: вызов
// `docker compose config` и чтение диска остаются у того, кто их делает.
package composeguard

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
)

// EdgeNetwork — внешняя сеть прокси платформы, единственная внешняя сеть,
// которую политика пропускает. Агент ссылается на эту константу, а не держит
// свою: разойдись они — прокси подключал бы стеки к сети, которую политика
// отвергает, или наоборот.
const EdgeNetwork = "tracedocs-edge"

// Проверка описания стека перед запуском.
//
// ЗАЧЕМ. Для приложений из каталога compose пишем мы, и проверять там нечего.
// Для приложений из репозитория его пишет клиент, а поднимаем мы — от root, с
// доступом к docker.sock. Рядом на диске лежат секреты платформы: приватный
// ключ агента, токены реестров проекта, ключи репозиториев. Без проверки
// достаточно одной строки в docker-compose.yml
//
//	volumes: ["/etc/tracedocs/deploy:/s:ro"]
//
// чтобы получить их все, а с монтированием docker.sock — root на хосте.
//
// Кто может это сделать: любой, у кого есть push в подключённый репозиторий, —
// в том числе подрядчик без единого права в Scopework, а при включённом
// автовыкате это происходит само, по коммиту.
//
// ЧТО ЭТО НЕ РЕШАЕТ. Стек всё равно поднимается общим демоном docker, и на
// хосте по-прежнему один uid для всех приложений проекта. Настоящая изоляция —
// отдельный rootless dockerd на приложение; это следующий шаг, а не замена
// этой проверке.
//
// Проверяем НОРМАЛИЗОВАННЫЙ вид (`docker compose config`), а не исходный YAML:
// иначе достаточно записать то же самое другим синтаксисом — короткой формой
// тома, якорем YAML, extends из соседнего файла.

// composeModel — то, что нам нужно из нормализованного вида. Остальные поля
// игнорируются: разбирать всю схему compose незачем и хрупко.
type composeModel struct {
	// Name — имя compose-проекта. В нормализованном виде оно есть всегда, и
	// именно из него compose выводит имена томов (<проект>_<ключ>). Нужно,
	// чтобы отличить имя, проставленное самим compose, от переопределённого
	// автором — см. volumeNameViolation.
	Name     string                    `json:"name"`
	Services map[string]composeService `json:"services"`
	// Volumes — верхнеуровневые определения томов. Проверять их обязательно:
	// bind на путь хоста можно спрятать здесь через local-драйвер с
	// driver_opts, и в записи сервиса он нормализуется как безобидный
	// type=volume. Без этой проверки `driver_opts: {type: none, device: /,
	// o: bind}` монтировал бы корень хоста, минуя проверку bind-путей.
	Volumes map[string]composeVolume `json:"volumes"`
	// Secrets и Configs с полем file — ещё один способ подать в контейнер файл
	// хоста, мимо проверки томов. Проверено на живом docker: `secrets:
	// {x: {file: /etc/tracedocs/deploy/agent.key}}` кладёт ключ агента в
	// /run/secrets/x, а configs — по указанному target.
	Secrets map[string]composeFileSource `json:"secrets"`
	Configs map[string]composeFileSource `json:"configs"`
	// Networks — внешняя сеть это тот же «определён вне стека», что и внешний
	// том, только для связности. Проверено на живом docker: запись
	// `networks: {x: {external: true, name: <сеть соседа>}}` подключает
	// контейнер к чужой сети, и соседний контейнер отвечает по имени.
	Networks map[string]composeNetwork `json:"networks"`
}

// composeNetwork — сеть стека. Внешняя опасна тем же, чем внешний том.
type composeNetwork struct {
	Name     string `json:"name"`
	External any    `json:"external"`
}

// composeFileSource — секрет или конфиг, поданный файлом хоста.
type composeFileSource struct {
	File string `json:"file"`
}

type composeService struct {
	Privileged bool     `json:"privileged"`
	CapAdd     []string `json:"cap_add"`
	Devices    []any    `json:"devices"`
	// DeviceCgroupRules — тот же доступ к устройству хоста, что и devices, но
	// другим полем: правило cgroup разрешает старший:младший номер, а узел
	// контейнер создаёт себе сам — CAP_MKNOD входит в набор по умолчанию.
	// Проверено на живом docker: `b 254:0 rwm` без privileged и без devices
	// позволяет mknod и чтение сырого диска хоста; `w` в правиле — и запись.
	// На этом же диске лежат приватный ключ агента, токены реестров и .env
	// всех приложений хоста.
	DeviceCgroupRules []string `json:"device_cgroup_rules"`
	NetworkMode       string   `json:"network_mode"`
	Pid               string   `json:"pid"`
	Ipc               string   `json:"ipc"`
	UsernsMode        string   `json:"userns_mode"`
	Cgroup            string   `json:"cgroup"`
	// CgroupParent — ветка cgroup хоста, в которую встаёт контейнер. Выход из
	// ветки docker уводит его из-под пределов и учёта, которые демон ставит
	// своим контейнерам.
	CgroupParent string `json:"cgroup_parent"`
	// Uts — единственное значение, которое понимает docker, это host:
	// пространство имён имени хоста. Законного случая у стека клиента нет.
	Uts         string   `json:"uts"`
	SecurityOpt []string `json:"security_opt"`
	// VolumesFrom — устаревшее поле, которое переживает нормализацию
	// `docker compose config` и до 0310 не проверялось вовсе. Запись
	//
	//	volumes_from: ["container:<слаг соседа>-db-1"]
	//
	// монтирует В СВОЙ контейнер все тома чужого контейнера на этом хосте —
	// то есть ровно то, что запрещают проверки томов выше, только другой
	// дверью. Имена контейнеров предсказуемы: `<слаг>-<сервис>-1`.
	VolumesFrom []string `json:"volumes_from"`
	// Build — сборка образа. context это каталог, который целиком уезжает
	// демону docker, а Dockerfile волен скопировать оттуда что угодно в образ.
	// Каталог вне приложения здесь равносилен чтению файлов хоста.
	Build *struct {
		Context    string `json:"context"`
		Dockerfile string `json:"dockerfile"`
		// AdditionalContexts — второй context под другим именем: каждый
		// названный каталог уезжает демону так же, как основной.
		AdditionalContexts map[string]string `json:"additional_contexts"`
		// Network — сеть на время сборки. `host` снимает изоляцию: сборка
		// ходит по локальным адресам хоста, включая метаданные облака.
		Network string `json:"network"`
		// Ssh, Secrets, Entitlements — способы передать в сборку то, чего в
		// контексте нет: агентский ключ, секрет, привилегию buildkit.
		Ssh          []any `json:"ssh"`
		Secrets      []any `json:"secrets"`
		Entitlements []any `json:"entitlements"`
	} `json:"build"`
	// Ports — публикация наружу. Для недоверенного стека запрещена целиком:
	// наружу приложение выходит только через прокси платформы, а прямой порт
	// обходит вместе с ним TLS и все политики доступа домена (пароль, список
	// IP, forward_auth), навешенные владельцем проекта.
	Ports   []any `json:"ports"`
	Volumes []struct {
		Type   string `json:"type"`
		Source string `json:"source"`
		Target string `json:"target"`
		// Tmpfs — опции длинной формы `type: tmpfs`. size нормализованный вид
		// отдаёт байтами строкой ("67108864"), а compose передаёт демону как
		// Mounts[].TmpfsOptions.SizeBytes.
		Tmpfs *struct {
			Size any `json:"size"`
		} `json:"tmpfs"`
	} `json:"volumes"`
	// Tmpfs — короткая форма: `/run` или `/run:size=64m,mode=1777`. compose
	// режет строку по первому двоеточию и отдаёт демону как HostConfig.Tmpfs,
	// опции без изменений (замерено на compose v5.3.1).
	Tmpfs []string `json:"tmpfs"`
	// ShmSize — размер /dev/shm. Нормализованный вид отдаёт байты строкой
	// ("268435456"), compose передаёт демону как HostConfig.ShmSize.
	ShmSize any `json:"shm_size"`
}

// composeVolume — верхнеуровневое определение тома. External как any: в
// нормализованном виде это либо булево, либо объект {name}; отсутствие поля —
// nil, и это норма.
type composeVolume struct {
	Driver     string            `json:"driver"`
	DriverOpts map[string]string `json:"driver_opts"`
	External   any               `json:"external"`
	// Name — итоговое имя тома в docker. Обычно его проставляет сам compose
	// как <проект>_<ключ>, но автор может задать своё — и тогда стек
	// подключается к тому, определённому вне его, включая тома соседнего
	// приложения на этом же хосте.
	Name string `json:"name"`
}

// Violation — одно нарушение. Отдельным типом, чтобы в отчёт попадало
// имя сервиса: «стек отклонён» без указания, чем именно, чинить невозможно.
type Violation struct {
	Service string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("сервис %s: %s", v.Service, v.Reason)
}

/*
 * Разрешительный список: что не перечислено — отклоняется.
 *
 * ЗАЧЕМ ПЕРЕВЕРНУТЬ ЛОГИКУ. Проверка была списком запретов, и любое поле, о
 * котором не подумали, по умолчанию разрешалось. За два захода перебора это
 * дало ШЕСТЬ дыр подряд: volumes_from, device_cgroup_rules, secrets, configs,
 * env_file, внешняя сеть. Каждая закрывалась отдельной строкой, а следующая
 * находилась там, куда ещё не посмотрели. Шесть попаданий подряд — это не
 * невезение, а свойство подхода.
 *
 * Здесь та же схема, что у DenyByDefaultGuard в apps/api: отсутствие решения
 * падает закрыто. Новое поле compose (а они появляются: use_api_socket,
 * provider, gpus) по умолчанию не проедет, пока его не разберут и не впишут.
 *
 * ЧЕГО ЭТО СТОИТ. Стек с редким, но законным полем будет отклонён, и человеку
 * придётся его убрать или прийти к нам. Это назойливо — и это осознанная цена:
 * ошибка в сторону отказа стоит одного разговора, ошибка в другую сторону
 * стоила доступа к диску хоста.
 */

// safeServiceKeys — поля сервиса, которые разобраны и признаны безопасными.
// Опасные поля с собственными правилами (volumes, ports, privileged и прочие)
// добавляются сюда из checkedServiceKeys в init: отклонять их этим списком
// нельзя — сообщение «поле неизвестно» вышло бы невнятным.
var safeServiceKeys = map[string]bool{
	// Обычная жизнь приложения.
	"image": true, "command": true, "entrypoint": true, "environment": true,
	"env_file": true, "working_dir": true, "user": true, "hostname": true,
	"container_name": true, "restart": true, "depends_on": true, "healthcheck": true,
	"expose": true, "networks": true, "labels": true, "annotations": true,
	"platform": true, "pull_policy": true, "profiles": true, "attach": true,
	"stdin_open": true, "tty": true, "read_only": true, "init": true,
	"stop_grace_period": true, "stop_signal": true, "scale": true,
	"post_start": true, "pre_stop": true, "extends": true, "label_file": true,
	// Сеть внутри стека.
	"dns": true, "dns_opt": true, "dns_search": true, "domainname": true,
	"extra_hosts": true, "links": true, "mac_address": true,
	// Ресурсы: злоупотребление вредит своему же серверу, границ не нарушает.
	"cpus": true, "cpu_shares": true, "cpu_period": true, "cpu_quota": true,
	"cpu_count": true, "cpu_percent": true, "cpuset": true,
	"mem_limit": true, "mem_reservation": true, "mem_swappiness": true,
	"memswap_limit": true, "oom_kill_disable": true, "oom_score_adj": true,
	"pids_limit": true, "shm_size": true, "storage_opt": true, "ulimits": true,
	"tmpfs": true, "sysctls": true, "deploy": true, "logging": true,
	"cap_drop": true, "group_add": true, "isolation": true, "develop": true,
}

// checkedServiceKeys — опасные поля, которые пропускает разрешительный список,
// потому что их разбирают отдельные правила Check. Отдельной группой, чтобы тест
// требовал правило на каждое: uts и cgroup_parent стояли в общем перечне без
// правила, и пометка «проверяется отдельно» разрешала их целиком.
var checkedServiceKeys = map[string]bool{
	"volumes": true, "volumes_from": true, "secrets": true, "configs": true,
	"build": true, "ports": true, "privileged": true, "cap_add": true,
	"devices": true, "device_cgroup_rules": true, "cgroup": true,
	"cgroup_parent": true, "security_opt": true, "network_mode": true,
	"pid": true, "ipc": true, "userns_mode": true, "uts": true,
}

func init() {
	for key := range checkedServiceKeys {
		safeServiceKeys[key] = true
	}
}

// safeTopLevelKeys — верхний уровень описания.
var safeTopLevelKeys = map[string]bool{
	"services": true, "networks": true, "volumes": true, "secrets": true,
	"configs": true, "name": true, "version": true, "include": true,
}

// unknownKeys ищет поля, о которых мы не думали.
func unknownKeys(normalized []byte) []Violation {
	var raw struct {
		Services map[string]map[string]json.RawMessage `json:"services"`
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(normalized, &raw); err != nil {
		return nil
	}
	_ = json.Unmarshal(normalized, &top)

	var out []Violation
	for key := range top {
		if !safeTopLevelKeys[key] && !strings.HasPrefix(key, "x-") {
			out = append(out, Violation{
				Service: "описание",
				Reason:  "поле " + tail(key, 60) + " платформе неизвестно и потому запрещено",
			})
		}
	}
	for name, svc := range raw.Services {
		for key := range svc {
			if safeServiceKeys[key] || strings.HasPrefix(key, "x-") {
				continue
			}
			out = append(out, Violation{
				Service: name,
				Reason: "поле " + tail(key, 60) + " платформе неизвестно и потому запрещено: " +
					"разрешены только разобранные поля, чтобы новое не проезжало молча",
			})
		}
	}
	return out
}

// Options — всё, что политика знает о месте стека на хосте.
type Options struct {
	// Roots — каталоги, из которых МОЖНО монтировать: рабочий каталог
	// приложения и его рабочая копия репозитория. Всё остальное на хосте — чужое.
	Roots []string
	// ServiceDirs — СЛУЖЕБНЫЕ каталоги: в них лежит описание стека, которым
	// агент его поднимает (задача С1.6). Пусто — служебного каталога нет, так
	// проверяются модели без места на диске.
	ServiceDirs []string
	// AdoptedVolumes — имена существующих томов, к которым разрешено
	// подключаться полем `name:` (перехват работающего стека, 0206). Пустой
	// список — обычный запрет.
	AdoptedVolumes []string
	// Allowances — послабления из гранта, подписанного корнем (С1.5). Кроме
	// проверенного гранта, взяться им неоткуда: ни из compose, ни из записи
	// приложения в базе.
	Allowances []Allowance
}

// Check разбирает нормализованный вид и возвращает нарушения.
func Check(normalized []byte, opt Options) ([]Violation, error) {
	// Негодное послабление — не повод решить «без него»: грант, который эта
	// версия не понимает, мог разрешать что-то, чего она не умеет ограничить.
	if err := ValidateAllowances(opt.Allowances); err != nil {
		return nil, err
	}
	allowedRoots, allowedVolumeNames, serviceDirs := opt.Roots, opt.AdoptedVolumes, opt.ServiceDirs
	var model composeModel
	if err := json.Unmarshal(normalized, &model); err != nil {
		return nil, fmt.Errorf("не удалось разобрать нормализованный compose: %w", err)
	}
	if len(model.Services) == 0 {
		return nil, fmt.Errorf("в описании стека нет ни одного сервиса")
	}

	var out []Violation
	add := func(service, reason string) {
		out = append(out, Violation{Service: service, Reason: reason})
	}

	for name, svc := range model.Services {
		if svc.Privileged {
			add(name, "privileged: true снимает почти все ограничения контейнера")
		}
		if len(svc.CapAdd) > 0 {
			add(name, "cap_add: расширение прав ядра запрещено ("+strings.Join(svc.CapAdd, ", ")+")")
		}
		if len(svc.DeviceCgroupRules) > 0 {
			add(name, "device_cgroup_rules: доступ к устройствам хоста запрещён ("+
				tail(strings.Join(svc.DeviceCgroupRules, ", "), 120)+")")
		}
		if len(svc.Devices) > 0 {
			add(name, "devices: проброс устройств хоста запрещён")
		}

		if svc.Cgroup != "" {
			add(name, "cgroup: управление cgroup контейнера запрещено")
		}
		if svc.CgroupParent != "" {
			add(name, "cgroup_parent: перенос контейнера в чужую ветку cgroup хоста запрещён")
		}
		if svc.Uts != "" {
			add(name, "uts: "+tail(svc.Uts, 40)+" — пространство имён UTS хоста запрещено")
		}
		if len(svc.Ports) > 0 && !portsCovered(name, svc.Ports, opt.Allowances) {
			add(name, "ports: публикация порта наружу запрещена — приложение "+
				"выходит только через прокси платформы (иначе обходятся TLS и "+
				"политики доступа домена)")
		}

		for field, value := range map[string]string{
			"network_mode": svc.NetworkMode,
			"pid":          svc.Pid,
			"ipc":          svc.Ipc,
			"userns_mode":  svc.UsernsMode,
		} {
			// host — пространство имён хоста целиком. container:/service: —
			// вход в пространство имён СОСЕДНЕГО контейнера: менее
			// привилегированный контрибьютор так дотянулся бы до более
			// чувствительного приложения того же проекта.
			low := strings.ToLower(value)
			if low == "host" {
				add(name, field+": host — контейнер получает доступ к пространству имён хоста")
			} else if strings.HasPrefix(low, "container:") || strings.HasPrefix(low, "service:") {
				add(name, field+": "+value+" — вход в пространство имён чужого контейнера запрещён")
			}
		}

		for _, opt := range svc.SecurityOpt {
			if strings.Contains(strings.ToLower(opt), "unconfined") {
				add(name, "security_opt "+opt+" отключает профиль изоляции")
			}
		}

		if svc.Build != nil {
			if svc.Build.Context != "" && filepath.IsAbs(svc.Build.Context) &&
				!IsPathAllowedIn(svc.Build.Context, allowedRoots, serviceDirs) {
				add(name, "build.context "+tail(svc.Build.Context, 120)+
					" вне каталогов приложения: содержимое уезжает в сборку и попадает в образ")
			}

			// ДОПОЛНИТЕЛЬНЫЕ КОНТЕКСТЫ — ТА ЖЕ ДВЕРЬ, ЧТО И ОСНОВНОЙ. Проверялся
			// один `context`, а `additional_contexts` разбор выбрасывал молча:
			// каталог `/etc/tracedocs/deploy` приезжал в образ вместе с закрытым
			// ключом агента, и клиент получал его в своём же образе.
			for alias, ctx := range svc.Build.AdditionalContexts {
				if ctx == "" || !filepath.IsAbs(ctx) {
					continue
				}
				if !IsPathAllowedIn(ctx, allowedRoots, serviceDirs) {
					add(name, "build.additional_contexts."+tail(alias, 40)+" "+tail(ctx, 120)+
						" вне каталогов приложения: содержимое уезжает в сборку и попадает в образ")
				}
			}

			// Абсолютный Dockerfile читается вне каталога приложения — тот же
			// выход наружу, только через инструкцию сборки, а не её контекст.
			if filepath.IsAbs(svc.Build.Dockerfile) && !IsPathAllowedIn(svc.Build.Dockerfile, allowedRoots, serviceDirs) {
				add(name, "build.dockerfile "+tail(svc.Build.Dockerfile, 120)+
					" вне каталогов приложения: файл сборки читается с хоста")
			}

			// `network: host` на время сборки снимает изоляцию сети: сборка
			// видит локальные адреса хоста и соседние контейнеры.
			if svc.Build.Network == "host" {
				add(name, "build.network host запрещено: сборка получила бы сеть хоста")
			}

			// Проброс ключей и привилегий в сборку. Всё это способы отдать
			// Dockerfile то, чего в контексте нет, — от агентского ключа до
			// снятия песочницы buildkit.
			if len(svc.Build.Ssh) > 0 {
				add(name, "build.ssh запрещено: проброс ключей хоста в сборку")
			}
			if len(svc.Build.Secrets) > 0 {
				add(name, "build.secrets запрещено: секрет хоста уехал бы в сборку")
			}
			if len(svc.Build.Entitlements) > 0 {
				add(name, "build.entitlements запрещено: снимает песочницу сборки")
			}
		}

		// volumes_from: ссылка на СВОЙ сервис безопасна — его тома уже
		// проверены здесь же. Всё остальное — чужие данные: и `container:`,
		// и имя сервиса, которого в этом стеке нет.
		for _, ref := range svc.VolumesFrom {
			target := ref
			if i := strings.LastIndex(target, ":"); i >= 0 {
				if mode := target[i+1:]; mode == "ro" || mode == "rw" {
					target = target[:i]
				}
			}
			if strings.HasPrefix(target, "container:") {
				add(name, "volumes_from "+tail(ref, 120)+
					" запрещено: монтирует тома чужого контейнера на этом хосте")
				continue
			}
			if _, ok := model.Services[target]; !ok {
				add(name, "volumes_from "+tail(ref, 120)+
					" запрещено: сервиса с таким именем в этом стеке нет")
			}
		}

		for _, reason := range composeMemoryViolations(svc) {
			add(name, reason)
		}

		for _, vol := range svc.Volumes {
			// Именованные тома безопасны при условии, что их ОПРЕДЕЛЕНИЕ
			// безопасно (проверяется ниже, в секции volumes). Здесь ловим
			// только прямой bind в записи сервиса.
			if vol.Type != "bind" {
				continue
			}
			if !IsPathAllowedIn(vol.Source, allowedRoots, serviceDirs) {
				add(name, "монтирование хостового пути "+tail(vol.Source, 120)+
					" запрещено: разрешены только каталоги самого приложения")
			}
		}
	}

	// Секреты и конфиги, поданные файлом: то же чтение хоста, что и bind, только
	// другим полем и с другой точкой монтирования.
	for kind, set := range map[string]map[string]composeFileSource{
		"секрет": model.Secrets, "конфиг": model.Configs,
	} {
		for srcName, src := range set {
			if src.File == "" {
				continue
			}
			if !IsPathAllowedIn(src.File, allowedRoots, serviceDirs) {
				add(kind+" "+srcName, "file "+tail(src.File, 120)+
					" вне каталогов приложения: так в контейнер попадает любой файл хоста")
			}
		}
	}

	// Сети: внешняя допустима ровно одна — наша собственная edge, которую
	// платформа вписывает в описание сама. Любая другая внешняя сеть означает
	// подключение к чужому стеку: контейнеры в ней достижимы по именам, и это
	// обходит границу между приложениями так же, как внешний том обходит
	// границу между данными.
	for netName, net := range model.Networks {
		if !isExternalVolume(net.External) {
			continue
		}
		target := net.Name
		if target == "" {
			target = netName
		}
		if target != EdgeNetwork {
			add("сеть "+netName, "внешняя сеть "+tail(target, 80)+
				" запрещена: она определена вне стека и ведёт к чужим контейнерам")
		}
	}

	// Верхнеуровневые тома: bind-через-local, сторонние драйверы, external.
	for volName, vol := range model.Volumes {
		who := "том " + volName
		if len(vol.DriverOpts) > 0 {
			// Именно здесь прячется local bind: device+o:bind монтирует
			// произвольный путь хоста под видом именованного тома.
			add(who, "driver_opts запрещены: через них монтируется путь хоста в обход проверки томов")
		}
		if vol.Driver != "" && vol.Driver != "local" {
			add(who, "сторонний драйвер тома ("+vol.Driver+") запрещён")
		}
		if isExternalVolume(vol.External) {
			add(who, "external-том запрещён: он определён вне стека и может указывать на чужие данные")
		}
		if reason := volumeNameViolation(model.Name, volName, vol.Name, allowedVolumeNames); reason != "" {
			add(who, reason)
		}
	}

	out = append(out, unknownKeys(normalized)...)

	return out, nil
}

// volumeNameViolation — не подменил ли автор итоговое имя тома.
//
// ЗАЧЕМ. Проверка external выше запрещает том, «определённый вне стека». Поле
// name даёт ровно тот же эффект и мимо неё проходит:
//
//	volumes: {stolen: {name: <слаг соседа>_db-data}}
//
// Запись сервиса при этом нормализуется в безобидное `{type: volume, source:
// stolen}` — по ней подмену не видно вовсе, видно только здесь.
//
// ПОЧЕМУ НЕ ЗАПРЕТ ЦЕЛИКОМ. `docker compose config` пишет name КАЖДОМУ тому,
// даже если автор его не указывал: проверено на compose v2 — том `data` в
// проекте `myapp` выходит как `{"name":"myapp_data"}`. Глухой запрет отклонил
// бы каждый существующий стек. Поэтому сверяем со значением, которое compose
// проставил бы сам.
//
// Сравнение точное, а не по префиксу: `backend-evil_data` начинается с имени
// проекта `backend` и принадлежит другому приложению.
//
// ПЕРЕХВАТ РАБОТАЮЩЕГО СТЕКА (0206). Стек, который платформа берёт под
// управление, подключается к уже существующим томам именно этим полем — данные
// не копируются и не переименовываются. Поэтому разрешение узкое: allowed —
// имена, зафиксированные сервером при приёме приложения, точное совпадение.
// Список приезжает отдельным полем желаемого состояния, а не выводится из
// самого compose: «разрешено то, что написано» означало бы «разрешено всё».
//
// Пустой allowed — обычный запрет: старый сервер поля не шлёт, и «не пришло»
// обязано значить «нельзя».
func volumeNameViolation(project, volKey, name string, allowed []string) string {
	// Пустое имя — только у выдуманных входов: в нормализованном виде поле
	// есть всегда. Подмены оно не даёт, docker выведет имя сам.
	if name == "" || name == project+"_"+volKey {
		return ""
	}
	for _, ok := range allowed {
		if name == ok {
			return ""
		}
	}
	// Пустое имя проекта отдельной ветки не требует: ожидаемое значение тогда
	// не совпадёт ни с чем осмысленным, и отказ произойдёт здесь же.
	return "имя тома переопределено на " + tail(name, 120) +
		": так стек подключается к тому вне себя, в том числе к данным " +
		"соседнего приложения. Имя тома назначает платформа"
}

// isExternalVolume — объявлен ли том внешним. nil (поля нет) и явный false —
// норма; true или объект — внешний.
func isExternalVolume(external any) bool {
	if external == nil {
		return false
	}
	if b, ok := external.(bool); ok {
		return b
	}
	// Объект {name: ...} — тоже внешний.
	return true
}

// Файлы, которыми агент поднимает стек. Отдать их контейнеру во владение —
// значит отдать ему следующий подъём (задача С1.6).
//
// `.env` В СПИСКЕ НЕТ, И ЭТО РЕШЕНИЕ, А НЕ ПРОПУСК. Монтировать свой `.env`
// внутрь контейнера — законный и частый приём (его проверяет
// `TestComposeGuardAllowsBindInsideProject`), а содержимое этого файла
// приложение и так получает переменными. Запрет сломал бы работающие стеки
// ради того, что уже и так у контейнера есть. Подмена `.env` меняет
// переменные, но не даёт привилегий — в отличие от подмены compose.
var selfRewriteNames = map[string]bool{
	"docker-compose.yml":  true,
	"docker-compose.yaml": true,
	"compose.yml":         true,
	"compose.yaml":        true,
}

// isSelfRewrite — bind даёт контейнеру писать в собственное описание стека.
//
// ДЫРА ВОСПРОИЗВЕДЕНА ДО ПОЧИНКИ (compose_self_rewrite_test.go, пять красных
// тестов). Bind внутри каталога приложения разрешён законно — так приложение
// хранит данные. Но в том же каталоге лежат `docker-compose.yml` и `.env`,
// которыми агент этот стек и запускает: контейнер, получивший свой каталог
// целиком, переписывает файл, по которому его поднимают, и следующий подъём —
// самовосстановление после падения (`recover.go`) — стартует уже подменённый
// стек: с `privileged`, сокетом докера, любым томом хоста.
//
// Guard при этом отрабатывает честно: на момент выката файл был чистым. Ловить
// подмену постфактум нечем, поэтому запрещаем сам bind.
func isSelfRewrite(clean string, serviceDirs []string) bool {
	if selfRewriteNames[filepath.Base(clean)] {
		return true
	}
	// СЛУЖЕБНЫЙ каталог приложения целиком — там лежат те же файлы. Рабочая
	// копия репозитория сюда НЕ входит: её compose агент не поднимает, он
	// готовит свой в служебном каталоге.
	for _, dir := range serviceDirs {
		if dir != "" && filepath.Clean(dir) == clean {
			return true
		}
	}
	return false
}

// IsPathAllowedIn — лежит ли путь внутри одного из разрешённых корней и не
// отдаёт ли он контейнеру описание стека (serviceDirs, задача С1.6).
//
// Сравнение по очищенному пути с разделителем на конце: без разделителя
// `/opt/tracedocs/deploy/apps/web-evil` прошёл бы как «внутри»
// `/opt/tracedocs/deploy/apps/web`.
//
// СИМЛИНКИ. Репозиторий может закоммитить симлинк `evil -> /` и смонтировать
// `./evil` — путь остаётся внутри рабочей копии по тексту, а docker при
// монтировании резолвит его в корень хоста. Поэтому путь считается
// разрешённым, только если внутри корней И его лексический вид, И тот, каким
// его увидит ядро (ResolveBindPath): ссылки раскрыты в существующей части,
// несуществующий хвост приклеен как есть.
func IsPathAllowedIn(source string, allowedRoots []string, serviceDirs []string) bool {
	if source == "" {
		return false
	}
	// `..` — отказ по исходной строке, ДО Clean: Clean убирает `l/..`
	// лексически, а ядро разрешает `..` после ссылки, и при `l -> /вне/deep`
	// путь `<каталог>/l/../x` монтирует `/вне/x`. Относительные пути compose
	// очищает сам (`./l/../x` приходит сюда уже `<каталог>/x`, и демону уходит
	// он же), так что `..` здесь бывает только в абсолютном пути, записанном
	// с ним, — а такой compose отдаёт демону без очистки (compose v5.3.1).
	// Выход наружу через `../x` отбивает WithinRoots: compose присылает его
	// уже очищенным абсолютным путём вне каталога.
	if HasDotDotSegment(source) {
		return false
	}
	clean := filepath.Clean(source)
	if !WithinRoots(clean, allowedRoots) {
		return false
	}
	if isSelfRewrite(clean, serviceDirs) {
		return false
	}
	// Раскрываем ссылки в СУЩЕСТВУЮЩЕЙ части пути, хвост приклеиваем как есть.
	// Прежний вариант при ошибке EvalSymlinks («пути ещё нет») пропускал путь
	// целиком — и `l -> /` плюс `./l/новый-каталог` проходил: docker создаёт
	// недостающий источник через MkdirAll, пройдя по ссылке наружу. Висячая
	// ссылка и петля — отказ: куда ведут, неизвестно.
	resolved, err := ResolveBindPath(clean)
	if err != nil {
		return false
	}
	return WithinRoots(resolved, allowedRoots)
}

// WithinRoots — лежит ли очищенный путь внутри одного из корней. Корни тоже
// резолвятся: служебные каталоги могут лежать за симлинком (/opt на macOS,
// /var → /private/var), и без резолва легитимный путь отвергался бы.
func WithinRoots(clean string, allowedRoots []string) bool {
	// Сравниваем ОБЕ формы с обеих сторон.
	//
	// Резолвить только корень недостаточно: docker пишет в метку
	// `com.docker.compose.project.working_dir` лексический путь, без разбора
	// симлинков. На хосте, где `/opt` — симлинк (частая раскладка при отдельном
	// разделе под данные), корень превращался в `/mnt/opt/...`, префикс не
	// совпадал — и собственный стек платформы считался чужим: осмотр предлагал
	// его к перехвату, а задание остановки его останавливало.
	candidates := []string{clean}
	if resolved, err := filepath.EvalSymlinks(clean); err == nil && resolved != clean {
		candidates = append(candidates, resolved)
	}

	for _, root := range allowedRoots {
		roots := []string{filepath.Clean(root)}
		if resolved, err := filepath.EvalSymlinks(roots[0]); err == nil && resolved != roots[0] {
			roots = append(roots, resolved)
		}
		for _, r := range roots {
			for _, c := range candidates {
				if c == r || strings.HasPrefix(c, r+string(filepath.Separator)) {
					return true
				}
			}
		}
	}
	return false
}

// composeMemoryViolations — tmpfs и /dev/shm без предела или сверх него.
//
// ЗАЧЕМ ЗДЕСЬ, ЕСЛИ ЕСТЬ ПРОКСИ. Прокси сокета Docker агента такой контейнер
// отбивает — но кодом 403 посреди `docker compose up`, когда часть сервисов
// уже пересоздана, и человек видит отказ демона, а не свою строку. Здесь тот
// же вердикт приходит при проверке текста, до запуска, с именем сервиса и
// подсказкой, что написать; у подписанта — до подписи.
//
// ПОЧЕМУ ТЕ ЖЕ ФУНКЦИИ, ЧТО У ПРОКСИ. Стек, прошедший эту проверку, обязан
// пройти и прокси, иначе проверка текста врёт. Вердикт выносят
// CheckTmpfsOptions и CheckShmSize (hostmem.go) — их же зовёт прокси, а
// совпадение держит TestComposeGuardPamyatSoglasovanaSProxy в internal/agent.
//
// ПОЧЕМУ ПРОКСИ НЕ ПОДСТАВЛЯЕТ ПРЕДЕЛ САМ. Прокси тела не переписывает: всё,
// что он пропустил, дошло до демона байт в байт. Подставленный размер был бы
// решением за автора стека, о котором тот узнал бы по «No space left on
// device» в контейнере, а не по сообщению.
func composeMemoryViolations(svc composeService) []string {
	var out []string
	for _, entry := range svc.Tmpfs {
		target, opts, _ := strings.Cut(entry, ":")
		if err := CheckTmpfsOptions(opts); err != nil {
			out = append(out, "tmpfs "+tail(target, 120)+": "+err.Error()+
				" — задайте размер явно, например "+tail(target, 60)+":size=64m")
		}
	}
	for _, vol := range svc.Volumes {
		if vol.Type != "tmpfs" {
			continue
		}
		var size any
		if vol.Tmpfs != nil {
			size = vol.Tmpfs.Size
		}
		n, ok := composeBytes(size)
		if !ok {
			out = append(out, "volumes tmpfs "+tail(vol.Target, 120)+
				": tmpfs.size не разобран — ожидается размер, например 64m")
			continue
		}
		// Тем же путём, что прокси для Mounts: SizeBytes 0 — «не задан».
		opts := ""
		if n != 0 {
			opts = "size=" + strconv.FormatInt(n, 10)
		}
		if err := CheckTmpfsOptions(opts); err != nil {
			out = append(out, "volumes tmpfs "+tail(vol.Target, 120)+": "+err.Error()+
				" — задайте tmpfs.size, например 64m")
		}
	}
	if n, ok := composeBytes(svc.ShmSize); !ok {
		out = append(out, "shm_size не разобран — ожидается размер, например 256m")
	} else if err := CheckShmSize(n); err != nil {
		out = append(out, "shm_size: "+err.Error())
	}
	return out
}

// composeBytes — размер из нормализованного вида: байты строкой (compose v2+)
// или числом (старые сборки). nil — поле не задано: 0, и это не ошибка.
func composeBytes(v any) (int64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	case float64:
		if x != math.Trunc(x) || x >= math.MaxInt64 || x <= math.MinInt64 {
			return 0, false
		}
		return int64(x), true
	}
	return 0, false
}

// tail — хвост строки для текста нарушения: путь из чужого compose может быть
// сколь угодно длинным, а текст уходит в отчёт на платформу.
func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
