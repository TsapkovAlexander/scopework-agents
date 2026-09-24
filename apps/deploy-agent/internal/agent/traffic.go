package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Трафик приложений (0187): агрегаты структурированного access-log Caddy.
//
// Лог читается ЛОКАЛЬНО и инкрементально: только новые байты с прошлого
// цикла. В control plane уезжают ТОЛЬКО агрегаты по доменам: сырой лог с URL
// и адресами — данные клиента, им нечего делать в нашей базе (план, «Слой
// безопасности на кромке»).
//
// КАК ОПОЗНАЁТСЯ «ТОТ ЖЕ ФАЙЛ». По отпечатку начала файла, а НЕ по inode.
// Inode для этого негоден: ext4 переиспользует только что освобождённый
// номер, и после ротации новый файл часто получает inode старого. Агент
// принял бы его за прежний, отсчитал старое смещение в новом файле и молча
// потерял бы весь трафик до этой точки — а если смещение пришлось на
// середину строки, ещё и читал бы обрывки. Отпечаток такого не допускает:
// новый файл начинается с другой строки, значит и отпечаток другой.
//
// Ограничители фиксированы: максимум строк за цикл (защита CPU от флуда),
// ограниченные словари путей и адресов (защита памяти). Упёршись в предел,
// сбор честно помечает выборку усечённой, а не молчит.

const (
	// maxTrafficLinesPerTick — дальше этого за цикл не читаем: при флуде
	// важнее применить желаемое состояние, чем досчитать статистику.
	maxTrafficLinesPerTick = 50000
	// maxTrackedPaths — на домен; хвост редких путей растворяется в общем
	// счётчике запросов, top-10 он не меняет.
	maxTrackedPaths = 500
	// maxTrackedIPs — на домен; дальше уникальность занижается, и это
	// отражается флагом усечения.
	maxTrackedIPs = 10000
	topPathsLimit = 10
	// trafficFingerprintLen — сколько байт начала файла образуют отпечаток.
	// Одной строки access-лога хватает с запасом, а читать больше незачем:
	// отпечаток снимается на каждом цикле.
	trafficFingerprintLen = 256
)

type PathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// DomainTraffic — агрегат по одному опубликованному домену за окно с
// прошлого сбора.
type DomainTraffic struct {
	Domain    string      `json:"domain"`
	Requests  int64       `json:"requests"`
	BytesOut  int64       `json:"bytesOut"`
	Status2xx int64       `json:"status2xx"`
	Status3xx int64       `json:"status3xx"`
	Status4xx int64       `json:"status4xx"`
	Status5xx int64       `json:"status5xx"`
	TopPaths  []PathCount `json:"topPaths"`
	UniqueIPs int         `json:"uniqueIps"`
}

type trafficCursor struct {
	Offset int64 `json:"offset"`
	// FpLen — сколько байт начала файла покрывает отпечаток (файл мог быть
	// короче окна), Fp — их sha256. Пара «сколько + что» нужна целиком:
	// сравнивать надо ровно тот кусок, с которого отпечаток снят.
	//
	// FpLen == 0 — отпечатка нет (первый запуск или курсор от версии агента
	// без него). Тогда файл читается с начала: одно окно может посчитаться
	// дважды, и это несравнимо дешевле молчаливой потери трафика.
	FpLen int64  `json:"fpLen"`
	Fp    string `json:"fp"`
	// UpdatedAtUnix — когда курсор сдвигали в прошлый раз. Нужен, чтобы окно
	// угроз несло фактическую длительность, а не константу: пороги детекции
	// заданы «за окно», и 180 в подписи к суточной выборке — прямая ложь.
	UpdatedAtUnix int64 `json:"updatedAtUnix"`
}

func (p Paths) trafficLogPath() string {
	return filepath.Join(p.proxyDir(), "logs", "access.json")
}

func (p Paths) trafficCursorPath() string {
	return filepath.Join(p.StateDir, "traffic-cursor.json")
}

// Строка access-лога Caddy — читаем только нужные поля.
type caddyAccessLine struct {
	Logger string `json:"logger"`
	Status int    `json:"status"`
	// Size — указатель: отсутствие поля и пустое тело — разные факты для
	// served_probes («размер неизвестен» против «отдано 0 байт»).
	Size    *int64 `json:"size"`
	Request struct {
		Host     string `json:"host"`
		URI      string `json:"uri"`
		RemoteIP string `json:"remote_ip"`
		Headers  struct {
			UserAgent []string `json:"User-Agent"`
		} `json:"headers"`
	} `json:"request"`
	RespHeaders struct {
		ContentType []string `json:"Content-Type"`
	} `json:"resp_headers"`
}

type domainAccumulator struct {
	traffic DomainTraffic
	paths   map[string]int64
	ips     map[string]struct{}
}

// TrafficWindow — окно журналов, собранное, но ещё не подтверждённое.
//
// ДОСТАВКА = ПОДТВЕРЖДЕНИЕ (ADR-0077, решение 4). Курсоры access-лога и
// журнала аутентификации раньше сохранялись внутри сбора, до отправки, и
// неудачный такт съедал окно без следа: трафик за минуту и попытки подбора
// SSH не доезжали никогда. Теперь сбор отдаёт окно и новые курсоры, а
// записывает их Commit — вызывающий зовёт его, только когда платформа окно
// приняла. Не принято — следующий сбор читает те же строки.
type TrafficWindow struct {
	Items     []DomainTraffic
	Threat    *ThreatWindow
	Truncated bool

	paths         Paths
	trafficCursor *trafficCursor
	sshCursor     *sshAuthCursor
}

// Commit записывает курсоры окна: его строки больше не читаются.
func (w TrafficWindow) Commit() {
	if w.trafficCursor != nil {
		saveTrafficCursor(w.paths, *w.trafficCursor)
	}
	if w.sshCursor != nil {
		saveSSHAuthCursor(w.paths, *w.sshCursor)
	}
}

// CollectTraffic — сбор с немедленной фиксацией курсоров, для случаев, где
// доставку подтверждать нечем.
func CollectTraffic(p Paths) (items []DomainTraffic, threat *ThreatWindow, truncated bool, err error) {
	w, err := CollectTrafficWindow(p)
	if err != nil {
		return nil, nil, false, err
	}
	w.Commit()
	return w.Items, w.Threat, w.Truncated, nil
}

// CollectTrafficWindow читает новые строки access-лога и возвращает агрегаты
// по доменам и окно угроз по хосту. Truncated — выборка усечена. Курсоры не
// двигаются до Commit.
func CollectTrafficWindow(p Paths) (TrafficWindow, error) {
	window := TrafficWindow{paths: p}
	logPath := p.trafficLogPath()

	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return window, nil
		}
		return window, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return window, err
	}
	var truncated bool

	cursor := loadTrafficCursor(p)
	// Первый запуск (курсора ещё нет): лог читается с начала и может содержать
	// хоть сутки. Отдавать это как окно в 180 секунд нельзя — пороги детекции
	// сработали бы на накопленной за день истории. Курсор двигаем, угрозы молчат.
	bootstrap := cursor.FpLen == 0 && cursor.Offset == 0
	// Тот ли это файл, с которого мы читали в прошлый раз. Отпечаток
	// сравнивается ровно по тому куску, с которого был снят: файл короче —
	// значит точно другой (ротация, усечение).
	sameFile := false
	if cursor.FpLen > 0 && info.Size() >= cursor.FpLen {
		if fp, fpErr := fileFingerprint(f, cursor.FpLen); fpErr == nil && fp == cursor.Fp {
			sameFile = true
		}
	}
	// Другой файл — читаем с начала. Смещение за концом того же файла —
	// тоже с начала, иначе застрянем за концом навсегда.
	if !sameFile || cursor.Offset > info.Size() {
		cursor.Offset = 0
	}

	if _, err := f.Seek(cursor.Offset, io.SeekStart); err != nil {
		return window, err
	}

	acc := make(map[string]*domainAccumulator)
	threatWin, threatState := newThreatAccumulator(false)
	reader := bufio.NewReaderSize(f, 256*1024)
	offset := cursor.Offset
	lines := 0

	for {
		if lines >= maxTrafficLinesPerTick {
			truncated = true
			break
		}
		line, readErr := reader.ReadBytes('\n')
		if readErr != nil {
			// Хвост без перевода строки — недописанная запись: оставляем её
			// следующему циклу, оффсет не двигаем.
			break
		}
		offset += int64(len(line))
		lines++

		var entry caddyAccessLine
		if json.Unmarshal(line, &entry) != nil {
			continue // мусорная строка не валит сбор
		}
		if entry.Logger != "" && !strings.HasPrefix(entry.Logger, "http.log.access") {
			continue
		}

		// Путь без query: строка запроса — данные клиента, и в топе она
		// размножала бы один и тот же путь до неузнаваемости.
		path := entry.Request.URI
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}

		// Угрозы — по ЛЮБОЙ строке, до проверки Host. Сканер ходит по адресу
		// сервера, без Host или с портом в нём; фильтр по домену стоял раньше
		// учёта угроз, и массовая разведка на кромке клиентов не попадала ни в
		// одно окно, хотя лежала в логе (ADR-0060, «Сопутствующие находки»).
		rec := accessRecord{
			RemoteIP: entry.Request.RemoteIP,
			Path:     path,
			Status:   entry.Status,
			Bytes:    entry.Size,
			// По URI с query: признак предзагрузки Next.js живёт именно там.
			Background: isBackgroundRequest(entry.Request.URI, entry.Status),
		}
		if len(entry.Request.Headers.UserAgent) > 0 {
			rec.UserAgent = entry.Request.Headers.UserAgent[0]
		}
		if len(entry.RespHeaders.ContentType) > 0 {
			rec.ContentType = entry.RespHeaders.ContentType[0]
		}
		threatWin.noteRequest(rec, threatState)

		// Агрегаты трафика — только по доменам: их показывают в карточке
		// приложения, а у «198.51.100.10:80» или пустого Host карточки нет.
		host := strings.ToLower(entry.Request.Host)
		if host == "" || !safeDomain.MatchString(host) {
			continue
		}

		a := acc[host]
		if a == nil {
			a = &domainAccumulator{
				traffic: DomainTraffic{Domain: host},
				paths:   make(map[string]int64),
				ips:     make(map[string]struct{}),
			}
			acc[host] = a
		}

		a.traffic.Requests++
		if entry.Size != nil {
			a.traffic.BytesOut += *entry.Size
		}
		switch {
		case entry.Status >= 200 && entry.Status < 300:
			a.traffic.Status2xx++
		case entry.Status >= 300 && entry.Status < 400:
			a.traffic.Status3xx++
		case entry.Status >= 400 && entry.Status < 500:
			a.traffic.Status4xx++
		case entry.Status >= 500:
			a.traffic.Status5xx++
		}

		if _, seen := a.paths[path]; seen || len(a.paths) < maxTrackedPaths {
			a.paths[path]++
		} else {
			truncated = true
		}

		if _, seen := a.ips[entry.Request.RemoteIP]; seen {
			// уже учтён
		} else if len(a.ips) < maxTrackedIPs {
			a.ips[entry.Request.RemoteIP] = struct{}{}
		} else {
			truncated = true
		}
	}

	// Отпечаток снимаем заново с ТЕКУЩЕГО файла: он «дозревает», если раньше
	// файл был короче окна. Сравнение на следующем цикле идёт по этой же
	// длине, так что рост файла ложным несовпадением не станет.
	next := trafficCursor{Offset: offset}
	next.FpLen = trafficFingerprintLen
	if info.Size() < next.FpLen {
		next.FpLen = info.Size()
	}
	if fp, fpErr := fileFingerprint(f, next.FpLen); fpErr == nil {
		next.Fp = fp
	} else {
		// Без отпечатка курсор бесполезен и опасен: на следующем цикле он
		// заставил бы читать с середины чужого файла. Обнуляем — перечитаем
		// с начала.
		next.FpLen = 0
	}
	next.UpdatedAtUnix = now().Unix()
	window.trafficCursor = &next

	var items []DomainTraffic
	for _, a := range acc {
		a.traffic.TopPaths = topPaths(a.paths)
		a.traffic.UniqueIPs = len(a.ips)
		items = append(items, a.traffic)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Domain < items[j].Domain })
	window.Items, window.Truncated = items, truncated
	if bootstrap {
		return window, nil
	}
	// Перебор SSH — в то же окно.
	//
	// Читается свой журнал (auth.log/secure) со своим курсором: у попытки входа
	// нет ни пути, ни кода ответа, и в access-логе Caddy её не бывает. До этого
	// сервер, подключённый только через развёртывание, показывал «вход по
	// паролю открыт» и НОЛЬ попыток подбора — платформа знала, что дверь
	// открыта, и не видела, что в неё стучат.
	sshAttempts, sshByIP, sshCursor := collectSSHFailures(p)
	window.sshCursor = sshCursor
	for ip, count := range sshByIP {
		threatWin.noteSSHFailure(ip, count, threatState)
	}

	// Сложение, а не присваивание: окно могло усечься само (словарь пар
	// попыток входа), и выборка лога целиком об этом не знает.
	threatWin.Truncated = threatWin.Truncated || truncated
	threatWin.WindowSec = windowSecondsSince(cursor.UpdatedAtUnix, now().Unix())
	threatWin.finalize(threatState)

	// Окно отправляем, если есть ЛИБО разобранный трафик, ЛИБО попытки входа.
	// Раньше условие смотрело только на `parsed`, и перебор SSH на сервере без
	// единого HTTP-запроса не доехал бы вовсе.
	if threatWin.Totals.Parsed == 0 && sshAttempts == 0 {
		return window, nil
	}
	window.Threat = threatWin
	return window, nil
}

func topPaths(paths map[string]int64) []PathCount {
	out := make([]PathCount, 0, len(paths))
	for path, count := range paths {
		out = append(out, PathCount{Path: path, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Path < out[j].Path
	})
	if len(out) > topPathsLimit {
		out = out[:topPathsLimit]
	}
	return out
}

// fileFingerprint — sha256 первых n байт файла. ReadAt, а не Read: позиция
// чтения не двигается, и вызывающий волен делать Seek когда угодно.
func fileFingerprint(f *os.File, n int64) (string, error) {
	if n <= 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, 0); err != nil && err != io.EOF {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

func loadTrafficCursor(p Paths) trafficCursor {
	var cursor trafficCursor
	raw, err := os.ReadFile(p.trafficCursorPath())
	if err != nil {
		return cursor
	}
	// Битый курсор равносилен отсутствующему: перечитаем файл с начала —
	// double-count одного окна лучше вечного застревания.
	_ = json.Unmarshal(raw, &cursor)
	return cursor
}

func saveTrafficCursor(p Paths, cursor trafficCursor) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return
	}
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return
	}
	if err := writeFileAtomic(p.trafficCursorPath(), raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "курсор трафика не сохранён: %v\n", err)
	}
}
