package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Контроль у владельца сервера (ADR-0095): политика хоста, локальный журнал
// команд и отпечатки вшитых ключей.
//
// Здесь две половины. Подкоманды для человека на сервере — `journal verify`,
// `journal show`, `policy show`, `version --trust`: они работают без платформы
// и без сети, потому что опора — сам файл на сервере, а не экран, который
// рисует платформа. И то, что такт делает с политикой и журналом: решение
// принимает agent.Decide, здесь только запись в журнал и доклад.

// localControl — политика и журнал между тактами.
type localControl struct {
	journal *agent.Journal
	// raw — сырой ответ, из которого пришли состояние и задание: хеш команды
	// считается по нему, иначе он разошёлся бы с журналом платформы.
	raw json.RawMessage
	// payloadHash — sha256 нагрузки DSSE подписанного состояния, принятого
	// из того же ответа; пусто — подписанного состояния в нём не было.
	payloadHash string
	// policy — прочитана в начале такта; ей же решаются задание и
	// самообновление, которое идёт уже после обмена.
	policy agent.LocalPolicy
	trust  agent.TrustReport
	// stateHash и stateFresh — приход состояния этого такта: исход применения
	// пишется только к новой строке.
	stateHash  string
	stateFresh bool
	// journalMark — отметка доклада журнала, отложенная до доставки такта.
	journalMark *gateMark
	// withheld — последняя причина, по которой платформа не прислала
	// состояние; в лог — только при смене, а не каждую минуту.
	withheld string
}

// hostControl — контроллер агента; cmdRun ставит его до первого такта.
//
// nil — только в тестах, и он НЕ открывает политику: файл политики читается
// и решение принимается всегда, без контроллера нет лишь журнала и доклада
// доверия. Забытый контроллер не может превратить observe в «можно всё».
var hostControl *localControl

func journalPath(dir string) string { return filepath.Join(dir, "journal.log") }

// proxyBinaryPath — бинарь прокси сокета: root, /usr/local/bin, самообновление
// его не трогает (ADR-0095, п. 5).
var proxyBinaryPath = "/usr/local/bin/tracedocs-deploy-agent"

func newLocalControl(ctx context.Context, dir string) *localControl {
	// Испорченный список ключей выпуска — вслух при старте: самообновление
	// отказывает целиком, и узнать это надо не из отказа через месяц.
	if err := agent.ReleaseKeysError(); err != nil {
		fmt.Fprintf(os.Stderr, "ВНИМАНИЕ: %v — самообновление отключено до переустановки исправной сборкой\n", err)
	}
	return &localControl{
		journal: agent.OpenJournal(journalPath(dir), os.Stdout, Version),
		// Версию прокси снимаем один раз: бинарь меняется только
		// переустановкой, а переустановка перезапускает и агента.
		trust: agent.NewTrustReport(proxyBinaryVersion(ctx)),
	}
}

// proxyBinaryVersion — что печатает `version` бинаря прокси; пусто, если его
// нет. Прокси без режима наблюдения пропустил бы к демону запись и в observe —
// карточка сервера должна это видеть по номеру.
func proxyBinaryVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, proxyBinaryPath, "version").Output()
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	if !utf8.ValidString(line) || len(line) > 64 {
		return ""
	}
	return line
}

// haveDesiredState — принёс ли ответ желаемое состояние.
//
// Ответ без apps — НЕ состояние (ADR-0095, п. 6): так платформа не отдаёт его
// хосту в observe, и принять такой ответ за «снять всё» значило бы снести
// хост. "apps":[] — законное «снять всё», и старая платформа всегда шлёт apps
// массивом, так что для неё ничего не меняется.
func haveDesiredState(resp agent.TickResponse) bool { return resp.DesiredState.Apps != nil }

// received — ответ такта доехал: запомнить сырые байты для хешей, сказать,
// если состояние удержано, и отметить доклад журнала доставленным.
// Прежними ручками доклад журнала не уходит — там и отмечать нечего.
func (l *localControl) received(resp agent.TickResponse, gate *agent.ReportGate, legacy bool) {
	if l == nil {
		return
	}
	l.raw = resp.Raw
	l.payloadHash = resp.DesiredState.SignedPayloadSHA256
	var body struct {
		StateWithheld string `json:"stateWithheld"`
	}
	_ = json.Unmarshal(l.raw, &body)
	if body.StateWithheld != l.withheld && body.StateWithheld != "" {
		fmt.Printf("платформа не прислала желаемое состояние: %s — стеки не трогаю\n", body.StateWithheld)
	}
	l.withheld = body.StateWithheld
	if body.StateWithheld != "" {
		// Симметрично правилу платформы: после «не отправлено» то же состояние
		// пишется заново (ForgetReceive).
		l.journal.ForgetReceive(agent.JournalKindDesiredState)
	}
	if !legacy && l.journalMark != nil {
		gate.Mark("journal", l.journalMark.hash, l.journalMark.at)
	}
	l.journalMark = nil
}

// currentPolicy — политика этого такта; без контроллера читается с диска.
func (l *localControl) currentPolicy() agent.LocalPolicy {
	if l == nil {
		return agent.LoadLocalPolicy()
	}
	return l.policy
}

// beginTick читает политику, пишет её смену и приход состояния в журнал,
// кладёт доклады в такт и возвращает решение на этот такт.
func (l *localControl) beginTick(
	report *agent.TickRequest,
	hb *agent.HeartbeatResponse,
	state agent.DesiredState,
	haveState bool,
) agent.TickPlan {
	policy := agent.LoadLocalPolicy()
	keys := agent.ReleaseSignatureRequired()
	policyReport := policy.Report(keys)
	report.LocalPolicy = &policyReport

	var current agent.HeartbeatResponse
	if hb != nil {
		current = *hb
	}
	plan := agent.Decide(policy, current, state, keys)
	if l == nil {
		return plan
	}

	l.policy = policy
	if _, err := l.journal.NotePolicy(policy); err != nil {
		fmt.Fprintf(os.Stderr, "журнал: %v\n", err)
	}
	trust := l.trust
	report.Trust = &trust
	l.stateHash, l.stateFresh = l.receiveState(state, haveState, plan)
	return plan
}

// receiveState пишет приход состояния ДО сверки и применения. Возвращает хеш
// и то, новая ли это строка: исход пишется только к новой.
func (l *localControl) receiveState(state agent.DesiredState, haveState bool, plan agent.TickPlan) (string, bool) {
	hash := l.arrivedStateHash(state, haveState)
	if hash == "" {
		return "", false
	}
	decision, reason := agent.DecisionAccepted, ""
	if !plan.Apply {
		decision, reason = agent.DecisionRefused, plan.StateRefusal
	}
	fresh, err := l.journal.Receive(agent.JournalKindDesiredState, hash, agent.DesiredStateSummary(state), decision, reason)
	if err != nil {
		fmt.Fprintf(os.Stderr, "журнал: %v\n", err)
	}
	return hash, fresh
}

// arrivedStateHash — хеш состояния из последнего ответа; пусто — состояния в
// нём не было.
//
// Подписанное — по байтам нагрузки DSSE (контракт с журналом отправленного на
// платформе): плоских полей в таком ответе нет, а если пришли, агент с корнями
// их не применяет, и запись их прихода была бы ложной строкой журнала.
//
// Пересборка из разобранного — только когда сырых байтов нет вовсе (обмен
// прежними ручками). Состояние в памяти переживает ответы без состояния
// (удержание, отказ подписи), и хеш по нему на таком такте записал бы приход,
// которого не было.
func (l *localControl) arrivedStateHash(state agent.DesiredState, haveState bool) string {
	if l.payloadHash != "" {
		return l.payloadHash
	}
	if roots, err := agent.StateRootsStatus(); err != nil || len(roots) > 0 {
		return ""
	}
	if hash := agent.CommandHashes(l.raw).State; hash != "" {
		return hash
	}
	if haveState && l.raw == nil {
		return agent.StateHashFallback(state)
	}
	return ""
}

// stateApplied — исход применения нового состояния. Итог по релизам уходит
// платформе отчётами применения; здесь — только факт исполнения.
func (l *localControl) stateApplied() {
	if l == nil || !l.stateFresh {
		return
	}
	if err := l.journal.Result(agent.JournalKindDesiredState, l.stateHash, nil, agent.DecisionAccepted, ""); err != nil {
		fmt.Fprintf(os.Stderr, "журнал: %v\n", err)
	}
}

// recoverUnderPolicy — самовосстановление, если политика даёт применять:
// это `docker compose up`, то есть то же применение.
func recoverUnderPolicy(ctx context.Context, plan agent.TickPlan, paths agent.Paths, apps []agent.DesiredApp, health []agent.AppHealth) error {
	if !plan.Recover {
		return nil
	}
	return agent.RecoverUnhealthy(ctx, paths, apps, health)
}

// runTask — задание под политикой хоста: приход — в журнал ДО исполнения или
// отказа, разрешённое исполняется, запрещённое отклоняется с отчётом (без
// отчёта задание висело бы в pending, а агент брал бы его каждый такт).
//
// Решение — тем же agent.Decide и по той отметке о жизни, что принесла это
// задание: запасной канал может подменить её посреди такта.
func (l *localControl) runTask(
	ctx context.Context,
	client *agent.Client,
	id agent.Identity,
	paths agent.Paths,
	task agent.HostTask,
	apps []agent.DesiredApp,
	storage *agent.ObjectStorageSpec,
) error {
	plan := agent.Decide(l.currentPolicy(), agent.HeartbeatResponse{Task: &task}, agent.DesiredState{},
		agent.ReleaseSignatureRequired())
	hash, fresh := l.receiveTask(task, plan.RefuseReason)
	if plan.Task == nil {
		return agent.RefuseTask(ctx, client, id, paths, task, plan.RefuseReason)
	}
	err := agent.RunTask(ctx, client, id, paths, task, apps, storage)
	if fresh {
		// Текст ошибки в журнал не идёт: в выводе чужих команд бывают значения
		// переменных, а причина и так уезжает отчётом задания.
		if jerr := l.journal.Result(agent.JournalKindHostTask, hash,
			map[string]bool{"ok": err == nil}, agent.DecisionAccepted, ""); jerr != nil {
			fmt.Fprintf(os.Stderr, "журнал: %v\n", jerr)
		}
	}
	return err
}

// receiveTask пишет приход задания. Без контроллера — ничего.
func (l *localControl) receiveTask(task agent.HostTask, refusal string) (string, bool) {
	if l == nil {
		return "", false
	}
	hashes := agent.CommandHashes(l.raw)
	hash := hashes.Task
	if hash == "" || hashes.TaskID != task.ID {
		// Задание принесла запасная отметка о жизни, а не такт: сырых байтов
		// именно этого задания нет.
		hash = agent.TaskHashFallback(task)
	}
	decision := agent.DecisionAccepted
	if refusal != "" {
		decision = agent.DecisionRefused
	}
	fresh, err := l.journal.Receive(agent.JournalKindHostTask, hash, agent.HostTaskSummary(task), decision, refusal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "журнал: %v\n", err)
	}
	return hash, fresh
}

// addJournalReport кладёт в такт голову журнала и последние записи — только
// при смене головы, тем же гейтом, что здоровье: в устойчивом состоянии
// журнал не меняется неделями, и слать его каждую минуту незачем. Отметка —
// по доставке такта (received).
func (l *localControl) addJournalReport(report *agent.TickRequest, gate *agent.ReportGate) {
	if l == nil {
		return
	}
	l.journalMark = nil
	head := l.journal.Head()
	// Снятый атрибут — тоже новость: голова от `chattr -a` не меняется.
	key := fmt.Sprintf("%d:%s:%s:%s", head.Seq, head.Hash, l.journal.Err(), appendOnlyText(l.journal.AppendOnly()))
	now := time.Now()
	if !gate.Allow("journal", key, now, agent.JournalReportMaxAge) {
		return
	}
	report.LocalJournal = l.journal.Report()
	l.journalMark = &gateMark{hash: key, at: now}
}

// selfUpdate — самообновление под политикой хоста (ADR-0095, п. 3).
//
// Политика спрашивается ДО загрузки: при manual или чужом пине бинарь не
// скачивается вовсе. Откат, сумму, подпись и годность вшитых ключей проверяет
// PrepareSelfUpdate.
func (l *localControl) selfUpdate(
	ctx context.Context,
	client *agent.Client,
	paths agent.Paths,
	hb agent.HeartbeatResponse,
) (string, bool) {
	target := strings.TrimSpace(hb.TargetAgentVersion)
	if target == "" || target == strings.TrimSpace(Version) {
		return "", false
	}
	refusal := agent.SelfUpdateRefusal(l.currentPolicy(), Version, target, agent.ReleaseSignatureRequired())
	if refusal == "" {
		if err := agent.ReleaseKeysError(); err != nil {
			refusal = err.Error()
		}
	}
	decision := agent.DecisionAccepted
	if refusal != "" {
		decision = agent.DecisionRefused
	}
	hash := agent.SelfUpdateHash(hb)
	fresh := true
	if l != nil {
		var err error
		fresh, err = l.journal.Receive(agent.JournalKindSelfUpdate, hash,
			map[string]string{"from": Version, "to": target}, decision, refusal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "журнал: %v\n", err)
		}
	}
	if refusal != "" {
		if fresh {
			fmt.Fprintf(os.Stderr, "самообновление до %s отклонено: %s\n", target, refusal)
		}
		return "", false
	}

	binPath, ok := agent.PrepareSelfUpdate(ctx, client, paths, hb, Version)
	if l != nil && (fresh || ok) {
		if err := l.journal.Result(agent.JournalKindSelfUpdate, hash,
			map[string]any{"to": target, "installed": ok}, agent.DecisionAccepted, ""); err != nil {
			fmt.Fprintf(os.Stderr, "журнал: %v\n", err)
		}
	}
	return binPath, ok
}

// cmdJournal — `journal verify|show`. Коды выхода verify: 0 — цепочка цела,
// 1 — сломана (печатается номер первой сломанной строки), 2 — не читается.
func cmdJournal(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "journal verify [--file=…] | journal show [--since=N] [--file=…]")
		return 2
	}
	fs := flag.NewFlagSet("journal "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", journalPath(defaultDir), "файл журнала")
	since := fs.Int64("since", 0, "печатать записи с этим номером и дальше")

	switch args[0] {
	case "verify":
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		head, err := agent.VerifyJournal(*file)
		var broken *agent.JournalBreak
		switch {
		case errors.As(err, &broken):
			fmt.Fprintf(stdout, "цепочка сломана: %s\n", broken.Error())
			fmt.Fprintf(stdout, "атрибут только дописывания (chattr +a): %s\n", appendOnlyText(agent.JournalAppendOnly(*file)))
			return 1
		case err != nil:
			fmt.Fprintf(stderr, "журнал не читается: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "цепочка цела: записей %d, последняя %s\n", head.Seq, head.Hash)
		// Цепочка ловит правку, но не защищает от неё: без атрибута
		// пользователь агента перепишет файл целиком, вместе с цепочкой.
		fmt.Fprintf(stdout, "атрибут только дописывания (chattr +a): %s\n", appendOnlyText(agent.JournalAppendOnly(*file)))
		return 0
	case "show":
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if err := agent.ShowJournal(*file, *since, stdout); err != nil {
			fmt.Fprintf(stderr, "журнал не читается: %v\n", err)
			return 2
		}
		return 0
	}
	fmt.Fprintf(stderr, "неизвестная подкоманда journal %q\n", args[0])
	return 2
}

func appendOnlyText(appendOnly *bool) string {
	switch {
	case appendOnly == nil:
		return "не определить на этой файловой системе"
	case *appendOnly:
		return "есть"
	}
	return "нет — журнал может переписать пользователь агента"
}

// cmdPolicy — `policy show`: действующая политика так, как её исполнит агент.
// Код выхода 1 — файл негоден (агент закрыл всё), 0 — годен или его нет.
func cmdPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "show" {
		fmt.Fprintln(stderr, "policy show")
		return 2
	}
	p := agent.LoadLocalPolicy()
	writePolicy(stdout, agent.PolicyPath, p, agent.ReleaseSignatureRequired())
	if p.State == agent.PolicyInvalid {
		return 1
	}
	return 0
}

func writePolicy(w io.Writer, path string, p agent.LocalPolicy, haveReleaseKeys bool) {
	fmt.Fprintf(w, "файл: %s\n", path)
	if p.State == agent.PolicyAbsent {
		fmt.Fprintln(w, "политика не задана: файла нет, агент исполняет команды платформы, как до появления политики")
		return
	}
	if p.State == agent.PolicyInvalid {
		fmt.Fprintf(w, "файл негоден: %s\nдействует закрытая политика:\n", p.Err)
	}
	if p.Protected {
		fmt.Fprintln(w, "защищён: да")
	} else {
		fmt.Fprintf(w, "защищён: нет — %s\n", p.Unprotected)
	}
	if p.Sha256 != "" {
		fmt.Fprintf(w, "sha256: %s\n", p.Sha256)
	}
	fmt.Fprintf(w, "mode=%s\n", p.Mode)
	fmt.Fprintf(w, "commands=%s\n", strings.Join(p.Commands, ","))
	updates := p.DeployAgentUpdates.String()
	if effective := agent.EffectiveDeployUpdates(p, haveReleaseKeys).String(); effective != updates {
		updates += " (исполняется как " + effective + ": без вшитого ключа выпуска подпись обновления проверить нечем)"
	}
	fmt.Fprintf(w, "deploy_agent_updates=%s\n", updates)
	fmt.Fprintf(w, "monitor_agent_updates=%s\n", p.MonitorAgentUpdates)
	fmt.Fprintf(w, "container_logs=%s\n", p.ContainerLogs)
}

// cmdVersion — `version [--trust]`. Простой `version` — одна строка с
// номером, как прежде: её читают install.sh и доклад версии прокси.
func cmdVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "--trust" {
		fmt.Fprintln(stdout, Version)
		return 0
	}
	stateRoots, stateErr := agent.StateRootsStatus()
	return versionTrust(stdout, stderr, Version, agent.TrustedReleaseKeys(), agent.ReleaseKeysError(), stateRoots, stateErr)
}

// versionTrust — `version --trust`: ровно три строки, их читает install.sh и
// сверяет сборка выпуска. Пусто после «=» — ключей (корней) нет. Испорченный
// список ключей или корней — причина в stderr и код 1: сборка падает на сверке
// отпечатков, так и нужно.
//
// Строка `state_roots=` есть всегда, даже пустая: у этой сборки есть код
// проверки подписи состояния, и install.sh по пустой строке говорит «корней
// нет», а по отсутствию строки (старые агенты) — молчит.
func versionTrust(stdout, stderr io.Writer, version string, releaseKeys []ed25519.PublicKey, keysErr error, stateRoots []ed25519.PublicKey, stateErr error) int {
	for _, err := range []error{keysErr, stateErr} {
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "version=%s\nrelease_keys=%s\nstate_roots=%s\n",
		version, strings.Join(fingerprintsOf(releaseKeys), ","), strings.Join(fingerprintsOf(stateRoots), ","))
	return 0
}

func fingerprintsOf(keys []ed25519.PublicKey) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, agent.KeyFingerprint(key))
	}
	return out
}

// localUsage — строки справки о командах владельца сервера.
func localUsage() string {
	return fmt.Sprintf(`  journal verify [--file=%s]
        Проверка цепочки локального журнала команд. Коды выхода:
        0 — цела, 1 — сломана (номер строки), 2 — не читается.

  journal show [--since=N] [--file=…]
        Записи журнала с номера N.

  policy show
        Политика сервера (%s) так, как её исполняет агент.
        Код выхода 1 — файл негоден и закрыто всё.

  version [--trust]
        Номер версии; с --trust — ещё отпечатки вшитых ключей.
`, journalPath(defaultDir), agent.PolicyPath)
}
