package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

// Локальный журнал команд на сервере (ADR-0095, п. 9).
//
// ЗАЧЕМ. Журнал отправленного живёт на платформе (ADR-0085) и от самой
// платформы не защищает: взломанная не запишет строку. Этот журнал ведёт
// хост — что пришло, что решила политика, что исполнено, — и платформа его
// не видит иначе как докладом.
//
// ФОРМАТ — JSON Lines с ключами в фиксированном порядке:
//
//	{"v":1,"seq":N,"at":"<UTC>","type":"receive|result|policy|genesis",
//	 "kind":"desired_state|host_task|self_update","hash":"<sha256 команды>",
//	 "summary":{…},"decision":"accepted|refused","reason":"…","prev":"<sha256 предыдущей строки>"}
//
// prev — sha256 байтов предыдущей строки без перевода строки; у genesis пусто.
// Подмена или удаление строки ломает цепочку всех последующих, и проверить её
// можно без нашего бинаря: sha256sum и jq.
//
// ТОЛЬКО ДОПИСЫВАНИЕ. O_APPEND, 0600; установщик ставит на файл `chattr +a`,
// и пользователь агента не может ни переписать, ни усечь его. Каждая строка
// печатается и в stdout — в journald, который пишет root: копия, которую
// пользователь агента не перепишет вовсе.

const (
	JournalKindDesiredState = "desired_state"
	JournalKindHostTask     = "host_task"
	JournalKindSelfUpdate   = "self_update"

	DecisionAccepted = "accepted"
	DecisionRefused  = "refused"

	journalTypeGenesis = "genesis"
	journalTypeReceive = "receive"
	journalTypeResult  = "result"
	journalTypePolicy  = "policy"

	// journalReportEntries — сколько последних строк уходит в доклад: сверка с
	// журналом платформы идёт по окну, а не по всей истории.
	journalReportEntries = 20
	// journalMaxLine — больше этого строку не читаем: штатно в ней сотни байт,
	// а файл — недоверенный вход при проверке.
	journalMaxLine = 1 << 20
)

// fsAppendFL — FS_APPEND_FL из include/uapi/linux/fs.h: атрибут `chattr +a`.
const fsAppendFL = 0x00000020

// journalFileFlags — чтение флагов inode; подменяется тестами, потому что
// атрибут на машине прогона не поставить.
var journalFileFlags = readFileFlags

// JournalAppendOnly — стоит ли на файле атрибут «только дописывание». nil —
// определить нельзя (не Linux, ФС без атрибутов, файл не открыть): это не
// «нет», и докладывать его как «нет» значило бы пугать там, где просто не
// видно.
func JournalAppendOnly(path string) *bool {
	flags, err := journalFileFlags(path)
	if err != nil {
		return nil
	}
	appendOnly := flags&fsAppendFL != 0
	return &appendOnly
}

// JournalReportMaxAge — доклад журнала уходит при смене головы и не реже раза
// в час: платформа, потерявшая доклад (откат базы), получит его снова.
const JournalReportMaxAge = time.Hour

// JournalEntry — одна строка журнала. Порядок полей — порядок ключей в строке.
type JournalEntry struct {
	V        int             `json:"v"`
	Seq      int64           `json:"seq"`
	At       string          `json:"at"`
	Type     string          `json:"type"`
	Kind     string          `json:"kind"`
	Hash     string          `json:"hash"`
	Summary  json.RawMessage `json:"summary"`
	Decision string          `json:"decision"`
	Reason   string          `json:"reason"`
	Prev     string          `json:"prev"`
}

// JournalHead — номер и хеш последней строки.
type JournalHead struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// Journal — журнал, открытый агентом. Не потокобезопасен: пишет только
// основной цикл.
type Journal struct {
	path string
	out  io.Writer
	now  func() time.Time
	head JournalHead
	// needsNewline — файл кончается оборванной строкой (сбой посреди записи):
	// новая запись начинается с новой строки, а не приклеивается к обрывку.
	needsNewline bool
	// lastByKind — хеш и решение последней записи receive по виду: новая
	// строка — на смену команды или решения, а не на каждый такт.
	lastByKind map[string]string
	// policyKey — состояние и хеш файла политики из последней строки policy.
	policyKey string
	recent    []JournalEntry
	// broken — файл не удалось прочитать при открытии: дописывать в него,
	// не зная головы, значит порвать цепочку самим. Строки идут только в stdout.
	broken error
	err    string
}

// OpenJournal открывает журнал и восстанавливает голову из файла. Не падает:
// агент без журнала продолжает работать, а причина уходит в доклад.
func OpenJournal(path string, out io.Writer, agentVersion string) *Journal {
	j := &Journal{path: path, out: out, now: time.Now, lastByKind: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		j.broken = err
		j.err = clipUTF16("журнал не читается: "+err.Error(), 500)
		return j
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		j.needsNewline = true
	}

	lines := splitJournalLines(raw)
	for _, line := range lines {
		var e JournalEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			// Испорченная строка не мешает дописывать: цепочка продолжится от
			// её байтов, а проверка покажет, где она сломана.
			j.head = JournalHead{Seq: j.head.Seq + 1, Hash: sha256Hex(line)}
			continue
		}
		j.head = JournalHead{Seq: e.Seq, Hash: sha256Hex(line)}
		j.remember(e)
	}
	if len(lines) == 0 {
		summary, _ := json.Marshal(map[string]string{"agentVersion": agentVersion})
		_ = j.append(JournalEntry{Type: journalTypeGenesis, Summary: summary})
	}
	return j
}

func splitJournalLines(raw []byte) []string {
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func (j *Journal) remember(e JournalEntry) {
	switch e.Type {
	case journalTypeReceive:
		j.lastByKind[e.Kind] = e.Hash + "\x00" + e.Decision
	case journalTypePolicy:
		var s struct {
			State string `json:"state"`
		}
		_ = json.Unmarshal(e.Summary, &s)
		j.policyKey = policyJournalKey(s.State, e.Hash)
	}
	j.recent = append(j.recent, e)
	if len(j.recent) > journalReportEntries {
		j.recent = j.recent[len(j.recent)-journalReportEntries:]
	}
}

func (j *Journal) append(e JournalEntry) error {
	e.V = 1
	e.Seq = j.head.Seq + 1
	e.At = j.now().UTC().Format(time.RFC3339)
	e.Prev = j.head.Hash
	if len(e.Summary) == 0 {
		e.Summary = json.RawMessage(`{}`)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	// Сначала stdout: если файл не примет строку, копия в journald останется.
	fmt.Fprintln(j.out, string(line))

	if j.broken != nil {
		return j.broken
	}
	payload := append(line, '\n')
	if j.needsNewline {
		payload = append([]byte{'\n'}, payload...)
	}
	if err := appendFile(j.path, payload); err != nil {
		j.err = clipUTF16("запись в журнал не удалась: "+err.Error(), 500)
		return err
	}
	j.needsNewline = false
	j.err = ""
	j.head = JournalHead{Seq: e.Seq, Hash: sha256Hex(string(line))}
	j.remember(e)
	return nil
}

func appendFile(path string, payload []byte) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(payload); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func marshalSummary(summary any) json.RawMessage {
	if summary == nil {
		return nil
	}
	raw, err := json.Marshal(summary)
	// Сводка — всегда объект: null в строке проверка приняла бы за подмену.
	if err != nil || isJSONNull(raw) {
		return nil
	}
	return raw
}

// Receive пишет «пришла команда» — ДО исполнения. Повтор той же команды с тем
// же решением не пишется: платформа приносит её каждый такт, пока не примет
// отчёт. Возвращает, появилась ли строка.
func (j *Journal) Receive(kind, hash string, summary any, decision, reason string) (bool, error) {
	key := hash + "\x00" + decision
	if j.lastByKind[kind] == key {
		return false, nil
	}
	// Отметка ставится и при сбое записи: строка ушла в stdout, а повтор на
	// каждом такте утопил бы journald в одинаковых строках.
	j.lastByKind[kind] = key
	return true, j.append(JournalEntry{
		Type: journalTypeReceive, Kind: kind, Hash: hash,
		Summary: marshalSummary(summary), Decision: decision, Reason: reason,
	})
}

// ForgetReceive забывает последнюю запись receive вида kind: следующий приход
// той же команды ляжет новой строкой.
//
// Нужна там, где платформа команду НЕ отправила (ответ с stateWithheld):
// платформа после своей строки «не отправлено» пишет то же состояние заново,
// и хост обязан сделать так же. Иначе после deploy → observe → deploy с тем же
// состоянием у платформы две строки «отправлено», у хоста одна, и сверка
// журналов показывает ложное platform_only — ложный признак подмены.
func (j *Journal) ForgetReceive(kind string) {
	if j == nil {
		return
	}
	delete(j.lastByKind, kind)
}

// Result пишет исход команды — ПОСЛЕ исполнения.
func (j *Journal) Result(kind, hash string, summary any, decision, reason string) error {
	return j.append(JournalEntry{
		Type: journalTypeResult, Kind: kind, Hash: hash,
		Summary: marshalSummary(summary), Decision: decision, Reason: reason,
	})
}

func policyJournalKey(state, sha string) string {
	if state == "" || state == PolicyAbsent {
		return ""
	}
	return state + ":" + sha
}

// NotePolicy пишет строку policy, когда сменился файл политики: «когда
// включили исполнение» видно из журнала, а не только из памяти владельца.
func (j *Journal) NotePolicy(p LocalPolicy) (bool, error) {
	key := policyJournalKey(p.State, p.Sha256)
	if key == j.policyKey {
		return false, nil
	}
	j.policyKey = key
	summary := map[string]any{"state": p.State}
	if p.State != PolicyAbsent {
		summary["mode"] = p.Mode
		summary["commands"] = p.Commands
		summary["deployAgentUpdates"] = p.DeployAgentUpdates.String()
		summary["monitorAgentUpdates"] = p.MonitorAgentUpdates.String()
		summary["containerLogs"] = p.ContainerLogs
		summary["protected"] = p.Protected
		if p.Err != "" {
			summary["error"] = p.Err
		}
	}
	return true, j.append(JournalEntry{Type: journalTypePolicy, Hash: p.Sha256, Summary: marshalSummary(summary)})
}

// Head — голова журнала: номер и хеш последней записанной строки.
func (j *Journal) Head() JournalHead { return j.head }

// Err — последняя ошибка журнала; пусто, если последняя запись удалась.
func (j *Journal) Err() string { return j.err }

// LocalJournalReport — поле localJournal тела такта (разбирает платформа,
// apps/web/src/lib/deploy/localJournal.ts):
//
//	{"head":{"seq":12,"hash":"<sha256 последней строки>"},
//	 "entries":[{"seq":11,"at":"2026-09-23T10:00:00Z","type":"receive",
//	             "kind":"host_task","hash":"<sha256 команды>",
//	             "decision":"refused","reason":"режим наблюдения"}, …],
//	 "appendOnly":true,
//	 "error":"<только если журнал не пишется>"}
//
// entries — до 20 последних строк любого типа по возрастанию seq; у genesis и
// policy kind пуст. appendOnly — стоит ли `chattr +a`; поля нет, когда
// определить нельзя (ADR-0095, п. 9: «ФС без атрибута — агент докладывает»). summary и prev в доклад не входят: сверка с журналом
// платформы идёт по паре (kind, hash), а цепочку проверяет владелец на
// сервере (`journal verify`) — платформе здесь верить не на что.
type LocalJournalReport struct {
	Head       JournalHead          `json:"head"`
	Entries    []JournalReportEntry `json:"entries"`
	AppendOnly *bool                `json:"appendOnly,omitempty"`
	Error      string               `json:"error,omitempty"`
}

// JournalReportEntry — строка журнала в докладе.
type JournalReportEntry struct {
	Seq      int64  `json:"seq"`
	At       string `json:"at"`
	Type     string `json:"type"`
	Kind     string `json:"kind"`
	Hash     string `json:"hash"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// Report — голова и последние записи для такта.
func (j *Journal) Report() *LocalJournalReport {
	entries := make([]JournalReportEntry, 0, len(j.recent))
	for _, e := range j.recent {
		entries = append(entries, JournalReportEntry{
			Seq: e.Seq, At: e.At, Type: e.Type, Kind: e.Kind, Hash: e.Hash,
			Decision: e.Decision, Reason: clipUTF16(e.Reason, 200),
		})
	}
	return &LocalJournalReport{Head: j.head, Entries: entries, AppendOnly: j.AppendOnly(), Error: j.err}
}

// AppendOnly — атрибут на файле журнала сейчас (см. JournalAppendOnly).
func (j *Journal) AppendOnly() *bool { return JournalAppendOnly(j.path) }

// JournalBreak — цепочка сломана: Line — номер первой строки (с единицы),
// после которой ей нельзя верить.
type JournalBreak struct {
	Line   int
	Reason string
}

func (e *JournalBreak) Error() string { return fmt.Sprintf("строка %d: %s", e.Line, e.Reason) }

// VerifyJournal проверяет цепочку. *JournalBreak — сломана; другая ошибка —
// файл не прочитать (это не «цепочка цела» и не «сломана»).
//
// Правка строки N видна на строке N+1: её prev не сходится с хешем N, и
// виноватой называется N. Удаление видно по разрыву номеров. Последнюю
// строку цепочка не защищает — её сверяют с копией в journald.
func VerifyJournal(path string) (JournalHead, error) {
	f, err := os.Open(path)
	if err != nil {
		return JournalHead{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), journalMaxLine)
	var head JournalHead
	var prevLine string
	n := 0
	for scanner.Scan() {
		n++
		line := scanner.Text()
		var e JournalEntry
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil || e.V != 1 || !bytes.HasPrefix(bytes.TrimSpace(e.Summary), []byte("{")) {
			return head, &JournalBreak{Line: n, Reason: "строка не разбирается как запись журнала"}
		}
		if n == 1 {
			if e.Type != journalTypeGenesis || e.Seq != 1 || e.Prev != "" {
				return head, &JournalBreak{Line: 1, Reason: "первая строка — не genesis"}
			}
		} else {
			if e.Seq != head.Seq+1 {
				return head, &JournalBreak{Line: n, Reason: fmt.Sprintf(
					"номер записи %d, ожидался %d — строка удалена или вставлена", e.Seq, head.Seq+1)}
			}
			if e.Prev != sha256Hex(prevLine) {
				return head, &JournalBreak{Line: n - 1, Reason: fmt.Sprintf(
					"хеш строки не совпадает с prev строки %d — строка изменена", n)}
			}
		}
		prevLine = line
		head = JournalHead{Seq: e.Seq, Hash: sha256Hex(line)}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return head, &JournalBreak{Line: n + 1, Reason: "строка длиннее предела"}
		}
		return head, err
	}
	if n == 0 {
		return head, &JournalBreak{Line: 1, Reason: "журнал пуст — нет даже записи genesis"}
	}
	return head, nil
}

// ShowJournal печатает строки с номером от since. Нечитаемые строки
// печатаются всегда: спрятать их значило бы спрятать подмену.
func ShowJournal(path string, since int64, w io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), journalMaxLine)
	for scanner.Scan() {
		line := scanner.Text()
		var e struct {
			Seq int64 `json:"seq"`
		}
		if json.Unmarshal([]byte(line), &e) == nil && e.Seq < since {
			continue
		}
		fmt.Fprintln(w, line)
	}
	return scanner.Err()
}

// desiredStateKeys — порядок ключей состояния, как его собирает
// apps/web/src/lib/deploy/desiredStatePayload.ts. Держит фикстура
// command-hash.json: изменился состав на платформе — упадёт тест здесь.
var desiredStateKeys = []string{"apps", "registries", "denyIps", "platformSubdomainBase", "objectStorage"}

// CommandHash — хеши команд одного ответа такта; пусто — команды нет.
type CommandHash struct {
	State string
	Task  string
	// TaskID — чьё это задание: отметку о жизни может обновить и запасной
	// канал, и хеш из ответа годится, только если задание то же.
	TaskID string
}

// CommandHashes считает хеши команд по СЫРЫМ байтам ответа.
//
// Платформа хеширует JSON.stringify тела (hashCommandBody, ADR-0085), а Go
// сериализует иначе: экранирует <, > и &. Пересобранное тело разошлось бы с
// платформой на первом & в переменной окружения, и сверка журналов показала бы
// подмену там, где её не было.
func CommandHashes(raw []byte) CommandHash {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return CommandHash{}
	}
	var out CommandHash
	if task, ok := m["task"]; ok && !isJSONNull(task) {
		out.Task = sha256Hex(string(task))
		var id struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(task, &id)
		out.TaskID = id.ID
	}
	if payload, ok := desiredStatePayload(raw); ok {
		out.State = stateJournalHash(payload)
	}
	return out
}

// stateJournalHash — хеш состояния для журнала: sha256 байтов груза.
//
// После слияния со штабом Г сюда передаются байты DSSE payload — ровно то,
// что подписано, — а не пересериализация: подписанный груз и есть тело,
// которое платформа хеширует в журнал ADR-0085.
func stateJournalHash(payload []byte) string { return sha256Hex(string(payload)) }

// desiredStatePayload достаёт из ответа такта (без конверта подписи) ровно
// те байты, что хеширует платформа: hashCommandBody(result.payload) в
// desiredStatePayload.ts = JSON.stringify({apps, registries, denyIps,
// platformSubdomainBase, objectStorage?}). Ключи — в порядке фикстуры
// command-hash.json, значения — сырыми байтами ответа, без пробелов.
//
// Нет apps — состояния в ответе нет (ADR-0095, п. 6), и строки журнала нет.
func desiredStatePayload(raw []byte) ([]byte, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	if apps, ok := m["apps"]; !ok || isJSONNull(apps) {
		return nil, false
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for _, key := range desiredStateKeys {
		value, ok := m[key]
		if !ok {
			continue
		}
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + key + `":`)
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), true
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// StateHashFallback — хеш состояния, когда сырых байтов нет (обмен прежними
// ручками при откате платформы).
//
// С платформой не сойдётся: json.Marshal экранирует <, > и &, а JSON.stringify
// нет; допустимо — этот путь живёт только для платформы старше единого такта,
// у которой журнала ADR-0085 нет и сверять не с чем.
func StateHashFallback(state DesiredState) string {
	raw, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	payload, ok := desiredStatePayload(raw)
	if !ok {
		return ""
	}
	return stateJournalHash(payload)
}

// TaskHashFallback — то же для задания.
func TaskHashFallback(task HostTask) string {
	raw, err := json.Marshal(task)
	if err != nil {
		return ""
	}
	return sha256Hex(string(raw))
}

// SelfUpdateHash — отпечаток предложения обновиться: цель и суммы.
// Платформа такие предложения в журнал не пишет, сверять не с чем — отпечаток
// нужен только отсеву повторов.
func SelfUpdateHash(hb HeartbeatResponse) string {
	raw, _ := json.Marshal(struct {
		Version string            `json:"targetAgentVersion"`
		Sha256  AgentSha256ByArch `json:"targetAgentSha256"`
	}{hb.TargetAgentVersion, hb.TargetAgentSha256})
	return sha256Hex(string(raw))
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// DesiredStateSummary — сводка состояния для журнала: ИМЕНА, без значений.
// Как summarizeDesiredState платформы: журнал с секретами клиента стоил бы
// дороже, чем его отсутствие, — его кража равнялась бы краже сервера.
func DesiredStateSummary(state DesiredState) map[string]any {
	apps := make([]map[string]any, 0, len(state.Apps))
	for _, app := range state.Apps {
		envKeys := make([]string, 0, len(app.Env))
		for key := range app.Env {
			envKeys = append(envKeys, key)
		}
		sort.Strings(envKeys)
		apps = append(apps, map[string]any{
			"slug":       nullIfEmpty(app.Slug),
			"desired":    nullIfEmpty(app.Desired),
			"sourceType": nullIfEmpty(app.SourceType),
			"releaseId":  nullIfEmpty(app.ReleaseID),
			"domain":     nullIfEmpty(app.Domain),
			"gitRepo":    nullIfEmpty(app.GitRepo),
			"gitBranch":  nullIfEmpty(app.GitBranch),
			// Сам compose в журнал не кладём: хеша хватает, чтобы увидеть
			// «изменился».
			"composeHash": sha256Hex(app.Compose)[:16],
			"envKeys":     envKeys,
			"hasGitKey":   app.GitKey != "",
			"hasGitToken": app.GitToken != "",
		})
	}
	registries := make([]any, 0, len(state.Registries))
	for _, r := range state.Registries {
		registries = append(registries, nullIfEmpty(r.Registry))
	}
	return map[string]any{
		"apps":             apps,
		"registries":       registries,
		"denyIpCount":      len(state.DenyIPs),
		"hasObjectStorage": state.ObjectStorage != nil,
	}
}

// HostTaskSummary — сводка задания: что за операция и над чем.
func HostTaskSummary(task HostTask) map[string]any {
	return map[string]any{
		"taskId":    nullIfEmpty(task.ID),
		"kind":      nullIfEmpty(task.Kind),
		"stack":     nullIfEmpty(task.Project),
		"dataDir":   nullIfEmpty(task.Dir),
		"volume":    nullIfEmpty(task.Volume),
		"backupSet": nullIfEmpty(task.BackupSet),
	}
}
