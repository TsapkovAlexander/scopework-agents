package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

// Локальная политика хоста (ADR-0095).
//
// ЗАЧЕМ. Всё, что клиент сегодня «настраивает» — режимы обновления, пин,
// журнал отправленного, — живёт в базе платформы, и взломанная платформа
// меняет это сама. Контроль у клиента — это то, что платформа переключить не
// может: файл root на его сервере, который агент только читает.
//
// ГДЕ ЛЕЖИТ. `/etc/tracedocs`, а не каталог агента: `/etc/tracedocs/deploy`
// принадлежит пользователю агента, и файл там агент мог бы переписать сам.
//
// КАК ЧИТАЕТСЯ. Каждый такт заново: правка действует со следующего такта без
// перезапуска службы. Файла нет — поведение 2.1.0 без исключений (ни один
// работающий хост не меняется от выката). Файл негоден — закрыто всё: владелец
// писал его, чтобы ограничить, и ошибка разбора не должна открывать.
//
// Семантика разбора — общая с агентом мониторинга и install.sh, её держит
// фикстура packages/deploy-core/fixtures/host-policy.json.

// PolicyPath — файл политики. Переменная, а не константа, ради тестов.
var PolicyPath = "/etc/tracedocs/agent-policy.conf"

// PolicyMaxBytes — предел файла в БАЙТАХ: символы считались бы по-разному в
// трёх разборах, и один из них принял бы то, что другой закрыл.
const PolicyMaxBytes = 4096

// CommandKinds — закрытый список видов команд (ADR-0095, п. 4), в порядке, в
// котором агент докладывает действующий список. Обязан совпадать с ветками
// RunTask, с host_tasks_kind_check и с COMMAND_KINDS платформы (плюс apply и
// inventory, которые не задания): новый вид без строки здесь не появится —
// упадёт тест фикстуры.
var CommandKinds = []string{
	"apply", "backup", "restore", "export", "migrate-data", "start-stack", "stop-stack", "inventory",
}

const (
	PolicyAbsent  = "absent"
	PolicyValid   = "valid"
	PolicyInvalid = "invalid"

	PolicyModeObserve = "observe"
	PolicyModeDeploy  = "deploy"
)

// UpdateRule — правило самообновления из файла: manual, no_major, auto или
// pinned X.Y.Z.
//
// no_major — тот же режим, что у платформы (миграция 0492): мелкое само,
// смена MAJOR — только переустановкой. Он здесь, потому что команда установки
// из интерфейса несёт режим компании в --updates, и граница «кроме крупных»
// должна держаться на хосте, а не только в выборе цели платформой.
type UpdateRule struct {
	Kind string
	Pin  string
}

// String — каноническая запись: `pinned X.Y.Z` с одним пробелом, какой бы
// разделитель ни стоял в файле. Её же ждёт разбор доклада платформой.
func (u UpdateRule) String() string {
	if u.Kind == "pinned" {
		return "pinned " + u.Pin
	}
	return u.Kind
}

// LocalPolicy — действующая политика хоста.
type LocalPolicy struct {
	// State — absent (файла нет), valid или invalid (закрыто всё).
	State               string
	Mode                string
	Commands            []string
	DeployAgentUpdates  UpdateRule
	MonitorAgentUpdates UpdateRule
	ContainerLogs       string
	// Protected — файл и каталог принадлежат root и не доступны на запись
	// никому другому. Незащищённый файл ИСПОЛНЯЕТСЯ: ограничения из него всё
	// равно строже, чем без него. Unprotected — почему нет, для владельца.
	Protected   bool
	Unprotected string
	// Sha256 — хеш байтов файла; пусто, если файл не читается.
	Sha256 string
	// Err — почему файл негоден. Только у invalid.
	Err string
}

// closedPolicy — то, во что превращается негодный файл: наблюдение, ничего из
// списка, ручные обновления, логи контейнеров закрыты.
func closedPolicy(reason string) LocalPolicy {
	return LocalPolicy{
		State:               PolicyInvalid,
		Mode:                PolicyModeObserve,
		Commands:            []string{},
		DeployAgentUpdates:  UpdateRule{Kind: "manual"},
		MonitorAgentUpdates: UpdateRule{Kind: "manual"},
		ContainerLogs:       "deny",
		Err:                 clipUTF16(reason, 500),
	}
}

var policyKeys = map[string]bool{
	"version": true, "mode": true, "commands": true,
	"deploy_agent_updates": true, "monitor_agent_updates": true, "container_logs": true,
}

// ParsePolicy разбирает ТЕКСТ файла. Файла нет — это не сюда, а LoadLocalPolicy.
func ParsePolicy(text []byte) LocalPolicy {
	if len(text) > PolicyMaxBytes {
		return closedPolicy(fmt.Sprintf("файл больше %d байт", PolicyMaxBytes))
	}
	// Нулевой байт — где угодно, даже в комментарии: bash-агент мониторинга
	// не держит NUL в переменной и увидел бы другой текст, чем этот разбор.
	if bytes.IndexByte(text, 0) >= 0 {
		return closedPolicy("в файле нулевой байт")
	}

	values := map[string]string{}
	for i, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = line[:cut]
		}
		line = strings.Trim(line, " \t")
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			return closedPolicy(fmt.Sprintf("строка %d: нет «=»", i+1))
		}
		key = strings.Trim(key, " \t")
		value = strings.Trim(value, " \t")
		if !policyKeys[key] {
			return closedPolicy(fmt.Sprintf("строка %d: незнакомый ключ «%s»", i+1, clipRunes(key, 40)))
		}
		if _, seen := values[key]; seen {
			return closedPolicy(fmt.Sprintf("строка %d: ключ %s повторён", i+1, key))
		}
		values[key] = value
	}

	version, ok := values["version"]
	if !ok {
		return closedPolicy("нет строки version=1")
	}
	if version != "1" {
		return closedPolicy("version должен быть 1")
	}

	// Отсутствующий ключ — самое строгое значение (ADR-0095, п. 1).
	p := LocalPolicy{
		State:               PolicyValid,
		Mode:                PolicyModeObserve,
		DeployAgentUpdates:  UpdateRule{Kind: "manual"},
		MonitorAgentUpdates: UpdateRule{Kind: "manual"},
		ContainerLogs:       "deny",
	}
	if v, ok := values["mode"]; ok {
		if v != PolicyModeObserve && v != PolicyModeDeploy {
			return closedPolicy("mode: ожидалось observe или deploy")
		}
		p.Mode = v
	}
	if v, ok := values["container_logs"]; ok {
		if v != "allow" && v != "deny" {
			return closedPolicy("container_logs: ожидалось allow или deny")
		}
		p.ContainerLogs = v
	}
	for _, u := range []struct {
		key  string
		rule *UpdateRule
	}{
		{"deploy_agent_updates", &p.DeployAgentUpdates},
		{"monitor_agent_updates", &p.MonitorAgentUpdates},
	} {
		v, ok := values[u.key]
		if !ok {
			continue
		}
		parsed, ok := parseUpdateRule(v)
		if !ok {
			return closedPolicy(u.key + ": ожидалось manual, no_major, auto или pinned X.Y.Z")
		}
		*u.rule = parsed
	}

	raw, listed := values["commands"]
	switch {
	case listed:
		chosen := map[string]bool{}
		for _, item := range strings.Split(raw, ",") {
			item = strings.Trim(item, " \t")
			if item == "" {
				continue
			}
			if !isCommandKind(item) {
				return closedPolicy(fmt.Sprintf("commands: незнакомый вид «%s»", clipRunes(item, 40)))
			}
			chosen[item] = true
		}
		p.Commands = []string{}
		for _, kind := range CommandKinds {
			if chosen[kind] {
				p.Commands = append(p.Commands, kind)
			}
		}
	case p.Mode == PolicyModeDeploy:
		// mode=deploy без списка — все виды: сам deploy и есть явное включение
		// исполнения, и молча превращать его в «ничего нельзя» значит путать
		// владельца, правящего файл руками.
		p.Commands = append([]string{}, CommandKinds...)
	default:
		p.Commands = []string{}
	}
	return p
}

func isCommandKind(kind string) bool {
	for _, k := range CommandKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// parseUpdateRule — manual | no_major | auto | pinned<пробелы или табы>X.Y.Z.
func parseUpdateRule(v string) (UpdateRule, bool) {
	switch v {
	case "manual", "no_major", "auto":
		return UpdateRule{Kind: v}, true
	}
	rest, ok := strings.CutPrefix(v, "pinned")
	if !ok || rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return UpdateRule{}, false
	}
	version := strings.TrimLeft(rest, " \t")
	if _, ok := parseAgentVersion(version); !ok || version != strings.TrimSpace(version) {
		return UpdateRule{}, false
	}
	return UpdateRule{Kind: "pinned", Pin: version}, true
}

// policyLstat и policyStat — подменяются тестами: владелец root на машине
// прогона не воспроизводится.
var (
	policyLstat = os.Lstat
	policyStat  = os.Stat
)

// LoadLocalPolicy читает файл политики этого хоста.
func LoadLocalPolicy() LocalPolicy { return LoadLocalPolicyFrom(PolicyPath) }

// LoadLocalPolicyFrom — то же по явному пути (прокси сокета, тесты).
func LoadLocalPolicyFrom(path string) LocalPolicy {
	info, err := policyLstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return LocalPolicy{State: PolicyAbsent}
	}
	if err != nil {
		return closedPolicy("файл политики не читается: " + err.Error())
	}

	var p LocalPolicy
	if text, sum, err := readPolicyFile(path); err != nil {
		// Файл есть, но прочитать его нельзя (каталог, права, битая ссылка):
		// это не «политики нет», а негодная политика.
		p = closedPolicy("файл политики не читается: " + err.Error())
	} else {
		p = ParsePolicy(text)
		p.Sha256 = sum
	}
	p.Protected, p.Unprotected = policyProtection(path, info)
	return p
}

// readPolicyFile — первые PolicyMaxBytes+1 байт для разбора и sha256 файла
// целиком. Хеш потоком: файл больше предела всё равно докладывается своим
// хешем, но в память целиком не читается.
func readPolicyFile(path string) ([]byte, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	var head limitedBuffer
	head.limit = PolicyMaxBytes + 1
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(sum, &head), f); err != nil {
		return nil, "", err
	}
	return head.data, hex.EncodeToString(sum.Sum(nil)), nil
}

type limitedBuffer struct {
	data  []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - len(b.data); room > 0 {
		if len(p) < room {
			room = len(p)
		}
		b.data = append(b.data, p[:room]...)
	}
	return len(p), nil
}

// policyProtection — может ли файл переписать кто-то, кроме root.
//
// Файл и каталог проверяются оба: файл root в каталоге, открытом на запись,
// подменяется переименованием.
func policyProtection(path string, info os.FileInfo) (bool, string) {
	if info.Mode()&os.ModeSymlink != 0 {
		return false, "файл политики — символическая ссылка"
	}
	if !info.Mode().IsRegular() {
		return false, "файл политики — не обычный файл"
	}
	if uid, ok := fileOwnerUID(info); !ok || uid != 0 {
		return false, "владелец файла политики не root"
	}
	if info.Mode().Perm()&0o022 != 0 {
		return false, "файл политики доступен на запись не только root"
	}
	dir, err := policyStat(filepath.Dir(path))
	if err != nil {
		return false, "каталог файла политики не читается"
	}
	if uid, ok := fileOwnerUID(dir); !ok || uid != 0 {
		return false, "владелец каталога файла политики не root"
	}
	if dir.Mode().Perm()&0o022 != 0 {
		return false, "каталог файла политики доступен на запись не только root"
	}
	return true, ""
}

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

func (p LocalPolicy) allows(kind string) bool {
	for _, k := range p.Commands {
		if k == kind {
			return true
		}
	}
	return false
}

// ObserveOnly — хост только наблюдается: файл есть и режим не deploy
// (негодный файл тоже здесь — он закрывает всё).
func (p LocalPolicy) ObserveOnly() bool {
	return p.State != PolicyAbsent && p.Mode != PolicyModeDeploy
}

// refusal — почему политика не даёт исполнить команду вида kind; пусто — даёт.
func (p LocalPolicy) refusal(kind string) string {
	switch {
	case p.State == PolicyAbsent:
		return ""
	case p.State == PolicyInvalid:
		return "файл политики негоден"
	case kind == "inventory":
		// Осмотр только читает хост, поэтому живёт по списку в любом режиме:
		// ради него observe и ставят перед перехватом стека.
		if p.allows(kind) {
			return ""
		}
		return "вид «inventory» не в списке commands"
	case p.Mode != PolicyModeDeploy:
		return "режим наблюдения"
	case !p.allows(kind):
		return fmt.Sprintf("вид «%s» не в списке commands", clipRunes(kind, 40))
	}
	return ""
}

// taskRefusal — то же для задания. Осмотр читает хост и разрешён в
// наблюдении, но только как осмотр: задание с видом inventory или apply —
// подделка, и в observe оно не исполняется ни под каким именем.
func (p LocalPolicy) taskRefusal(kind string) string {
	switch {
	case p.State == PolicyAbsent:
		return ""
	case p.State == PolicyInvalid:
		return "файл политики негоден"
	case p.Mode != PolicyModeDeploy:
		return "режим наблюдения"
	case kind == "apply" || kind == "inventory":
		return fmt.Sprintf("«%s» — не вид задания", kind)
	}
	return p.refusal(kind)
}

// TickPlan — что можно в этом такте.
type TickPlan struct {
	// Apply — уборка, входы в реестры, прокси и применение стеков.
	Apply bool
	// StateRefusal — почему состояние не применяется; пусто — применяется.
	StateRefusal string
	// Recover — перезапуск упавших сервисов: это то же применение.
	Recover bool
	// BaselineDrift — сверять дрейф только с базовой линией applied.json:
	// агент ничего не применяет, и «наше изменение в пути» быть не может.
	BaselineDrift bool
	// Storage — принять ключ хранилища копий на диск и пробовать бакет.
	Storage bool
	// Inventory — осмотр сервера по запросу человека.
	Inventory bool
	// Task — задание к исполнению; Refused — задание, в котором отказано.
	Task         *HostTask
	Refused      *HostTask
	RefuseReason string
	// Updates — действующее правило самообновления.
	Updates UpdateRule
}

// HealthApps — чьё здоровье опрашивать в этом такте. В наблюдении без
// желаемого состояния — то, что агент применял сам (applied.json): состояние
// хосту в этом режиме не отдаётся, и иначе платформа не видела бы здоровья
// вовсе.
func (plan TickPlan) HealthApps(p Paths, apps []DesiredApp) []DesiredApp {
	if plan.BaselineDrift && apps == nil {
		return BaselineApps(p)
	}
	return apps
}

// Decide — одна чистая функция над политикой и ответом платформы (ADR-0095,
// п. 2). main.go только спрашивает её: свойство «в observe не исполняется
// ничего при любом ответе» проверяется на ней, а не перечислением случаев.
func Decide(p LocalPolicy, hb HeartbeatResponse, state DesiredState, haveReleaseKeys bool) TickPlan {
	plan := TickPlan{
		StateRefusal: p.refusal("apply"),
		Updates:      EffectiveDeployUpdates(p, haveReleaseKeys),
	}
	// Состояние без apps — не состояние (ADR-0095, п. 6): пустой список «снять
	// всё» — это "apps":[], а не отсутствие поля.
	plan.Apply = plan.StateRefusal == "" && state.Apps != nil
	plan.Recover = plan.StateRefusal == ""
	plan.BaselineDrift = plan.StateRefusal != ""
	// Ключ хранилища ложится на диск, а проба ПИШЕТ объект в бакет клиента:
	// в наблюдении — ни того, ни другого.
	plan.Storage = state.ObjectStorage != nil &&
		(p.State == PolicyAbsent || (p.State == PolicyValid && p.Mode == PolicyModeDeploy))
	plan.Inventory = hb.InventoryRequestedAt != "" && p.refusal("inventory") == ""
	if hb.Task != nil {
		task := *hb.Task
		if reason := p.taskRefusal(task.Kind); reason == "" {
			plan.Task = &task
		} else {
			plan.Refused = &task
			plan.RefuseReason = reason
		}
	}
	return plan
}

// EffectiveDeployUpdates — как агент обновляется на деле.
//
// Файла нет — auto: цель называет платформа, как в 2.1.0. Файл есть, а
// вшитого ключа выпуска нет — подпись бинаря не проверяется
// (VerifyReleaseSignature без ключей пропускает всё), и платформа может
// прислать любой бинарь под любым номером. Бинарь, который не читает
// политику, отменяет её целиком, поэтому без ключа (ADR-0095, п. 3):
//   - pinned — как manual: номер версии без подписи ничего не доказывает, и
//     взломанная платформа отдаст свой бинарь ровно под закреплённым номером;
//   - no_major — как manual по той же причине: граница MAJOR — тоже номер, и
//     бинарь со сменой поведения придёт под следующей минорной;
//   - auto — как manual, если политика хоть что-то ограничивает: observe или
//     неполный список commands. В deploy со всеми видами обновление не
//     добавляет ничего сверх того, что исполнение уже разрешает.
func EffectiveDeployUpdates(p LocalPolicy, haveReleaseKeys bool) UpdateRule {
	if p.State == PolicyAbsent {
		return UpdateRule{Kind: "auto"}
	}
	if !haveReleaseKeys && unsignedUpdateLiftsPolicy(p) {
		return UpdateRule{Kind: "manual"}
	}
	return p.DeployAgentUpdates
}

// unsignedUpdateLiftsPolicy — снял бы неподписанный бинарь ограничение,
// которое файл ставит. Правило общее с агентом мониторинга
// (monitor-push.sh, host_policy_effective_updates) — держит фикстура
// host-policy.json, раздел updateCases.
func unsignedUpdateLiftsPolicy(p LocalPolicy) bool {
	switch p.DeployAgentUpdates.Kind {
	case "pinned", "no_major":
		return true
	case "auto":
		if p.Mode != PolicyModeDeploy {
			return true
		}
		for _, kind := range CommandKinds {
			if !p.allows(kind) {
				return true
			}
		}
	}
	return false
}

// AllowsSelfUpdate — пускает ли политика обновиться на target. Откат,
// сумму и подпись проверяет PrepareSelfUpdate — здесь только политика.
func AllowsSelfUpdate(p LocalPolicy, current, target string, haveReleaseKeys bool) bool {
	return SelfUpdateRefusal(p, current, target, haveReleaseKeys) == ""
}

// SelfUpdateRefusal — почему политика не пускает обновиться; пусто — пускает.
func SelfUpdateRefusal(p LocalPolicy, current, target string, haveReleaseKeys bool) string {
	rule := EffectiveDeployUpdates(p, haveReleaseKeys)
	target = strings.TrimSpace(target)
	switch rule.Kind {
	case "auto":
		return ""
	case "pinned":
		if target != rule.Pin {
			return fmt.Sprintf("закреплена версия %s, предложена %s", rule.Pin, clipRunes(target, 40))
		}
		// Пин ниже текущей — не повод откатываться: запрет отката (С1.3)
		// политика не отменяет.
		if !isNewerAgentVersion(current, rule.Pin) {
			return fmt.Sprintf("закреплённая версия %s не новее текущей %s", rule.Pin, clipRunes(current, 40))
		}
		return ""
	case "no_major":
		// Нечитаемая версия с любой стороны — отказ: не зная MAJOR, нельзя
		// сказать, что шаг мелкий.
		c, okc := parseAgentVersion(current)
		t, okt := parseAgentVersion(target)
		if !okc || !okt || c[0] != t[0] {
			return fmt.Sprintf("deploy_agent_updates=no_major: смена MAJOR %s → %s — только переустановкой",
				clipRunes(current, 40), clipRunes(target, 40))
		}
		return ""
	}
	if p.DeployAgentUpdates.Kind != "manual" {
		return fmt.Sprintf("deploy_agent_updates=%s без вшитого ключа выпуска исполняется как manual: подпись выпуска проверить нечем",
			p.DeployAgentUpdates)
	}
	return "deploy_agent_updates=manual"
}

// LocalPolicyReport — поле localPolicy тела такта.
//
// Набор ключей фиксирован: разбор платформы (apps/web/src/lib/deploy/hostPolicy.ts)
// считает лишний ключ мусором и закрывает всё. Файла нет — {"present":false}.
// Значения ДЕЙСТВУЮЩИЕ: у негодного файла закрытые, и рядом error.
type LocalPolicyReport struct {
	Present                     bool
	Sha256                      string
	Protected                   bool
	Mode                        string
	Commands                    []string
	DeployAgentUpdates          string
	DeployAgentUpdatesEffective string
	MonitorAgentUpdates         string
	ContainerLogs               string
	Error                       string
}

func (r LocalPolicyReport) MarshalJSON() ([]byte, error) {
	if !r.Present {
		return []byte(`{"present":false}`), nil
	}
	commands := r.Commands
	if commands == nil {
		commands = []string{}
	}
	return json.Marshal(struct {
		Present                     bool     `json:"present"`
		Sha256                      string   `json:"sha256"`
		Protected                   bool     `json:"protected"`
		Mode                        string   `json:"mode"`
		Commands                    []string `json:"commands"`
		DeployAgentUpdates          string   `json:"deployAgentUpdates"`
		DeployAgentUpdatesEffective string   `json:"deployAgentUpdatesEffective"`
		MonitorAgentUpdates         string   `json:"monitorAgentUpdates"`
		ContainerLogs               string   `json:"containerLogs"`
		Error                       string   `json:"error,omitempty"`
	}{true, r.Sha256, r.Protected, r.Mode, commands, r.DeployAgentUpdates,
		r.DeployAgentUpdatesEffective, r.MonitorAgentUpdates, r.ContainerLogs, r.Error})
}

// Report — доклад политики в такте.
func (p LocalPolicy) Report(haveReleaseKeys bool) LocalPolicyReport {
	if p.State == PolicyAbsent {
		return LocalPolicyReport{}
	}
	report := LocalPolicyReport{
		Present:                     true,
		Sha256:                      p.Sha256,
		Protected:                   p.Protected,
		Mode:                        p.Mode,
		Commands:                    p.Commands,
		DeployAgentUpdates:          p.DeployAgentUpdates.String(),
		DeployAgentUpdatesEffective: EffectiveDeployUpdates(p, haveReleaseKeys).String(),
		MonitorAgentUpdates:         p.MonitorAgentUpdates.String(),
		ContainerLogs:               p.ContainerLogs,
	}
	if p.State == PolicyInvalid {
		report.Error = p.Err
	}
	return report
}

// BaselineApps — приложения, которые агент применял сам (applied.json).
//
// Нужны наблюдению без желаемого состояния: платформа не отдаёт состояние
// хосту в observe, а здоровье уже поднятых стеков докладывать надо. Значения
// .env читаются только для затирания вывода docker перед отправкой — в отчёт
// они не попадают.
func BaselineApps(p Paths) []DesiredApp {
	applied := LoadApplied(p)
	slugs := make([]string, 0, len(applied.Apps))
	for slug := range applied.Apps {
		if safeSlug.MatchString(slug) {
			slugs = append(slugs, slug)
		}
	}
	sort.Strings(slugs)
	apps := make([]DesiredApp, 0, len(slugs))
	for _, slug := range slugs {
		app := DesiredApp{Slug: slug, Desired: "present"}
		if raw, err := readLimited(filepath.Join(p.appDir(slug), ".env"), maxSnapshotEnvBytes); err == nil {
			app.Env = parseEnvFile(raw)
		}
		apps = append(apps, app)
	}
	return apps
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

// clipUTF16 — предел длины так, как его считает платформа (String.length в
// JS — единицы UTF-16, а не байты и не руны).
func clipUTF16(s string, n int) string {
	if utf16Len(s) <= n {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if used+w > n-1 {
			break
		}
		b.WriteRune(r)
		used += w
	}
	b.WriteString("…")
	return b.String()
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n++
		if r > 0xFFFF {
			n++
		}
	}
	return n
}
