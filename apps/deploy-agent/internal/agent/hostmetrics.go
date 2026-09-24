package agent

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Метрики хоста для раздела мониторинга серверов.
//
// ЗАЧЕМ ЭТО ДЕЛАЕТ АГЕНТ РАЗВЁРТЫВАНИЯ. Мониторинг серверов и развёртывание —
// две системы, которые смотрят на один и тот же сервер. У мониторинга есть
// свой агент, ставящийся по SSH отдельным заданием, и своё «добавить сервер».
// Но подключённый для развёртывания хост УЖЕ отчитывается платформе каждую
// минуту подписанным каналом, и требовать от человека второй установки ради
// тех же цифр — работа, которой не должно быть.
//
// Поэтому метрики едут секцией такта, а платформа кладёт их в то же хранилище,
// что и снимки от агента мониторинга. В разделе мониторинга такой сервер
// появляется сам, без кнопки «добавить».
//
// ЧТО СОБИРАЕМ И ЧЕГО НЕ СОБИРАЕМ. Только то, что читается из /proc и statfs
// без единой внешней команды: загрузка, память, диск, время работы. Ни сети,
// ни состояния sshd, ни проверок доступности — это епархия агента мониторинга,
// у него для этого есть и права, и установленные утилиты. Дублировать его
// целиком значило бы завести вторую реализацию того же, а расходиться они
// начали бы с первой правки.

// HostMetrics — снимок состояния хоста.
//
// Имена полей совпадают с тем, что принимает ручка приёма мониторинга
// (monitoringMetricsSchema): платформа кладёт их в общее хранилище без
// перевода, и лишний слой отображения был бы местом, где два формата
// разъезжаются.
type HostMetrics struct {
	CPUPercent    *float64    `json:"cpu_percent"`
	Load1m        *float64    `json:"load_1m"`
	Load5m        *float64    `json:"load_5m"`
	Load15m       *float64    `json:"load_15m"`
	MemUsedBytes  *int64      `json:"mem_used_bytes"`
	MemTotalBytes *int64      `json:"mem_total_bytes"`
	Disk          []Mount     `json:"disk"`
	UptimeSeconds *float64    `json:"uptime_seconds"`
	Containers    *Containers `json:"containers"`
	Network       *Network    `json:"network"`
}

// Containers — сколько контейнеров на хосте и в каком они состоянии.
//
// Считаем ВСЕ, а не только свои: раздел мониторинга показывает состояние
// сервера целиком, и чужой стек занимает ту же память и тот же диск. Разделять
// «наши» и «чужие» здесь значило бы показывать половину картины на хосте,
// который подключили именно потому, что на нём уже что-то работает.
type Containers struct {
	Running    int `json:"running"`
	Total      int `json:"total"`
	Restarting int `json:"restarting"`
}

// Mount — занятость файловой системы.
//
// Имена полей — те же, что у схемы приёма мониторинга (diskMountSchema):
// `mount`, а не `path`. Разойдясь на одном имени, снимок отвергается целиком с
// «invalid_payload», и метрик в разделе не появляется вовсе.
type Mount struct {
	Mount      string `json:"mount"`
	UsedBytes  int64  `json:"used_bytes"`
	TotalBytes int64  `json:"total_bytes"`
	// UsedPercent считаем здесь: платформа показывает занятость диска в
	// процентах, и вычислять их из двух полей на каждой отрисовке — лишняя
	// возможность ошибиться в делении на ноль.
	UsedPercent float64 `json:"used_percent"`
}

// cpuSample — сырые счётчики /proc/stat для расчёта загрузки между тактами.
type cpuSample struct {
	total, idle float64
	at          time.Time
}

// lastCPU — предыдущий замер. Загрузка процессора — величина за ИНТЕРВАЛ, а не
// мгновенная: /proc/stat отдаёт счётчики с момента загрузки системы, и одно
// чтение даёт среднее за всё время работы сервера, то есть бесполезное число.
var lastCPU cpuSample

// CollectHostMetrics снимает состояние хоста.
//
// Ошибки чтения отдельных источников не прерывают сбор: поле остаётся nil,
// платформа читает это как «не знаем». Полностью пустой снимок отправлять
// незачем, поэтому вызывающий проверяет результат на пустоту.
//
// Только Linux: /proc есть только там, а агент развёртывания нигде больше и не
// работает — systemd-юнит, docker, compose.
func CollectHostMetrics(ctx context.Context) *HostMetrics {
	m := &HostMetrics{}

	if l1, l5, l15, ok := readLoadAvg(); ok {
		m.Load1m, m.Load5m, m.Load15m = &l1, &l5, &l15
	}
	if used, total, ok := readMemory(); ok {
		m.MemUsedBytes, m.MemTotalBytes = &used, &total
	}
	if up, ok := readUptime(); ok {
		m.UptimeSeconds = &up
	}
	if cpu, ok := readCPUPercent(time.Now()); ok {
		m.CPUPercent = &cpu
	}
	m.Disk = readDisk()
	m.Containers = readContainers(ctx)
	m.Network = readNetwork()

	if m.Load1m == nil && m.MemTotalBytes == nil && len(m.Disk) == 0 {
		return nil
	}
	return m
}

func readLoadAvg() (float64, float64, float64, bool) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	f := strings.Fields(string(raw))
	if len(f) < 3 {
		return 0, 0, 0, false
	}
	l1, e1 := strconv.ParseFloat(f[0], 64)
	l5, e5 := strconv.ParseFloat(f[1], 64)
	l15, e15 := strconv.ParseFloat(f[2], 64)
	if e1 != nil || e5 != nil || e15 != nil {
		return 0, 0, 0, false
	}
	return l1, l5, l15, true
}

// readMemory — занятая память по MemAvailable, а не по MemFree.
//
// MemFree на любом работающем сервере близок к нулю: ядро отдаёт свободное
// под кеш страниц и вернёт его по первому требованию. Отчёт по MemFree
// показывал бы «память кончилась» на совершенно здоровом хосте.
func readMemory() (used int64, total int64, ok bool) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}

	var available int64
	for _, line := range strings.Split(string(raw), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		kb, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(value), " kB"), 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "MemTotal":
			total = kb * 1024
		case "MemAvailable":
			available = kb * 1024
		}
	}
	if total <= 0 || available <= 0 {
		return 0, 0, false
	}
	return total - available, total, true
}

func readUptime() (float64, bool) {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(raw))
	if len(f) < 1 {
		return 0, false
	}
	up, err := strconv.ParseFloat(f[0], 64)
	return up, err == nil
}

// readCPUPercent — доля занятого времени процессора с прошлого замера.
//
// Первый вызов после запуска агента возвращает false: сравнивать не с чем, а
// показывать среднее с момента загрузки сервера — врать. Второй такт даёт
// честное число за интервал между ними.
func readCPUPercent(now time.Time) (float64, bool) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, false
	}

	var sample cpuSample
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		for i, field := range strings.Fields(line)[1:] {
			v, err := strconv.ParseFloat(field, 64)
			if err != nil {
				return 0, false
			}
			sample.total += v
			// Поля 3 и 4 (idle, iowait) — время простоя. iowait включаем: с
			// точки зрения «занят ли сервер работой» ожидание диска простой, а
			// не нагрузка.
			if i == 3 || i == 4 {
				sample.idle += v
			}
		}
		break
	}
	if sample.total == 0 {
		return 0, false
	}
	sample.at = now

	prev := lastCPU
	lastCPU = sample
	if prev.total == 0 || sample.total <= prev.total {
		return 0, false
	}

	busy := (sample.total - prev.total) - (sample.idle - prev.idle)
	percent := busy / (sample.total - prev.total) * 100
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	return percent, true
}

// readDisk — занятость корня и каталога стеков платформы.
//
// Два места, а не все смонтированные: корень отвечает за жизнь системы, а
// каталог стеков — за то, куда растут образы и тома. Часто это одна файловая
// система, и тогда второй записи не будет: одинаковые цифры под разными
// именами только мешают.
func readDisk() []Mount {
	// Совпадение считаем по размерам, а не по идентификатору файловой системы:
	// поле Fsid в syscall называется по-разному на разных платформах, а агент
	// собирается и проверяется не только под Linux. Две записи с одинаковыми
	// «всего» и «свободно» — это одна и та же файловая система; ошибиться здесь
	// можно только совпадением до байта, и цена ошибки — одна лишняя строка.
	type size struct{ total, free int64 }
	seen := map[size]bool{}
	var out []Mount

	for _, path := range []string{"/", DefaultPaths().WorkDir} {
		total, free, err := statfsUsage(path)
		if err != nil || total == 0 {
			continue
		}
		if seen[size{total, free}] {
			continue
		}
		seen[size{total, free}] = true

		used := total - free
		percent := 0.0
		if total > 0 {
			percent = float64(used) / float64(total) * 100
		}
		out = append(out, Mount{
			Mount: path, UsedBytes: used, TotalBytes: total, UsedPercent: percent,
		})
	}
	return out
}

// statfsUsage — размер файловой системы, на которой лежит путь, и сколько на
// ней доступно для записи.
func statfsUsage(path string) (total, avail int64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	total = int64(st.Blocks) * int64(st.Bsize)
	// Доступное считаем по Bavail, а не Bfree: часть блоков зарезервирована
	// под root, и обычные записи в них не пройдут. Показывать их как
	// свободные значит обещать место, которого приложению не дадут.
	avail = int64(st.Bavail) * int64(st.Bsize)
	return total, avail, nil
}

// readContainers — счётчики контейнеров по данным демона.
//
// `docker info` вместо перечисления `docker ps`: демон уже держит эти числа, и
// один запрос к нему дешевле, чем разбор списка, который на нагруженном хосте
// бывает в сотни строк. Перезапускающиеся считаются отдельно — контейнер в
// цикле перезапуска формально «есть», но работой это не является, и в сводке
// сервера это первое, что нужно заметить.
//
// Ошибка означает «не знаем»: nil, а не нули. Нули читались бы как «на сервере
// ничего не запущено» — прямая ложь на хосте, где демон просто не ответил.
func readContainers(ctx context.Context) *Containers {
	cmd := newDockerCmd(ctx, "", "info", "--format",
		"{{.ContainersRunning}} {{.Containers}} {{.ContainersPaused}}")
	cmd.Env = dockerEnv()

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return nil
	}
	running, err1 := strconv.Atoi(fields[0])
	total, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return nil
	}

	// Перезапускающиеся отдельным вопросом: `docker info` их числом не отдаёт,
	// а именно они означают «поднялось и падает». Считаем по состоянию, а не по
	// разнице «всего минус работающие»: в неё попали бы и намеренно
	// остановленные.
	restarting := 0
	rc := newDockerCmd(ctx, "", "ps", "--filter", "status=restarting", "--quiet")
	rc.Env = dockerEnv()
	if raw, err := rc.Output(); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if strings.TrimSpace(line) != "" {
				restarting++
			}
		}
	}

	return &Containers{Running: running, Total: total, Restarting: restarting}
}

// HostPosture — состояние защищённости сервера.
//
// ЗАЧЕМ ЭТО ЗДЕСЬ. Цена угрозы зависит от того, можно ли ею воспользоваться:
// перебор SSH на сервере с входом только по ключу — фоновый шум, а на сервере
// с открытым паролем и выключенным fail2ban — работающая атака в один шаг. Без
// этих фактов платформа будит владельца одинаково в обоих случаях.
//
// Агент мониторинга это собирает; агент развёртывания — нет, и сервер,
// подключённый только через развёртывание, оставался с прочерками там, где у
// остальных стоят ответы. Пробел закрывается теми же тремя вопросами и теми же
// именами полей.
//
// Все поля — указатели: nil означает «не знаем», а не «выключено». Разница
// существенная, потому что при неизвестном состоянии платформа НЕ понижает
// уровень тревоги.
type HostPosture struct {
	SSHPasswordAuth *bool   `json:"ssh_password_auth"`
	SSHRootLogin    *string `json:"ssh_root_login"`
	Fail2banActive  *bool   `json:"fail2ban_active"`
}

// CollectHostPosture опрашивает sshd и fail2ban.
func CollectHostPosture(ctx context.Context) *HostPosture {
	p := &HostPosture{}

	// `sshd -T` печатает ИТОГОВЫЙ конфиг — со всеми Include и Match, то есть
	// ровно то, что применяется. Чтение sshd_config глазами врёт: на Ubuntu
	// значение из sshd_config.d перебивает главный файл.
	if out, err := exec.CommandContext(ctx, "sshd", "-T").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			key, value, found := strings.Cut(strings.TrimSpace(line), " ")
			if !found {
				continue
			}
			switch key {
			case "passwordauthentication":
				p.SSHPasswordAuth = boolPtr(value == "yes")
			case "permitrootlogin":
				switch value {
				case "yes", "no", "prohibit-password", "forced-commands-only":
					p.SSHRootLogin = strPtr(value)
				case "without-password":
					// Устаревшее написание того же самого. Приводим к
					// современному: иначе схема приёма отвергнет значение.
					p.SSHRootLogin = strPtr("prohibit-password")
				}
			}
		}
	}

	// `is-active` выходит с ненулевым кодом, когда сервис не запущен, — это не
	// ошибка вызова, а ответ.
	if out, err := exec.CommandContext(ctx, "systemctl", "is-active", "fail2ban").Output(); err == nil {
		p.Fail2banActive = boolPtr(strings.TrimSpace(string(out)) == "active")
	} else if len(out) > 0 {
		switch strings.TrimSpace(string(out)) {
		case "inactive", "failed", "activating", "deactivating":
			p.Fail2banActive = boolPtr(false)
		}
	}

	if p.SSHPasswordAuth == nil && p.SSHRootLogin == nil && p.Fail2banActive == nil {
		return nil
	}
	return p
}

func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

// Network — счётчики сетевых интерфейсов с момента загрузки системы.
//
// Отдаём накопленные значения, а не скорость: платформа хранит ряд снимков и
// считает разницу сама. Скорость, посчитанная агентом, зависела бы от точности
// его интервала, а он плавает — удержание такта, джиттер, назначенный
// платформой период.
type Network struct {
	RxBytes int64 `json:"rx_bytes"`
	TxBytes int64 `json:"tx_bytes"`
}

// readNetwork суммирует трафик по всем интерфейсам, кроме локального.
//
// Локальный (`lo`) исключается: через него идёт обмен между контейнерами на
// одном хосте, и на сервере с базой рядом с приложением он в разы превышает
// внешний трафик. Сложив их, мы показали бы владельцу число, к внешней сети
// отношения не имеющее.
func readNetwork() *Network {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}

	n := &Network{}
	found := false

	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue // заголовки таблицы
		}
		iface := strings.TrimSpace(name)
		if iface == "" || iface == "lo" {
			continue
		}
		// Виртуальные интерфейсы docker считают тот же трафик второй раз:
		// пакет, прошедший через veth в контейнер, уже посчитан на внешнем.
		if strings.HasPrefix(iface, "veth") || strings.HasPrefix(iface, "br-") ||
			strings.HasPrefix(iface, "docker") {
			continue
		}

		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		rx, err1 := strconv.ParseInt(f[0], 10, 64)
		tx, err2 := strconv.ParseInt(f[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		n.RxBytes += rx
		n.TxBytes += tx
		found = true
	}

	if !found {
		return nil
	}
	return n
}
