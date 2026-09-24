package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Сигналы нагрузок в процессе агента (ADR-0091): плановая выборка раз в 60 с,
// внеочередная по потоку docker events, будильник такта и секция workloads.
//
// СИНГЛТОН ПАКЕТА, а не значение у вызывающего: в main.go для этой работы
// разрешены только вставки вызовов, и сигнатуры tick и exchange не меняются.
// Поэтому каждая функция ниже безопасна при не запущенной подсистеме — до
// старта, после остановки и между ними (самообновление, чей exec не удался).

type workloadTimings struct {
	interval   time.Duration // плановая выборка: ряд не зависит от частоты такта (решение 2)
	debounce   time.Duration // окно, в котором события потока сливаются в одну выборку (решение 5)
	wake       time.Duration // будильник такта не чаще (решение 5)
	backoffMin time.Duration // отступ переподключения потока
	backoffMax time.Duration
}

var workloadDefaultTimings = workloadTimings{interval: time.Minute, debounce: 2 * time.Second,
	wake: time.Minute, backoffMin: time.Second, backoffMax: time.Minute}

var (
	workloadsMu  sync.Mutex
	workloadsRun *workloadRuntime
)

type workloadRuntime struct {
	paths     Paths
	collector workloadCollector
	timings   workloadTimings
	now       func() time.Time

	series *WorkloadSeries
	events *WorkloadEvents
	images *WorkloadImages

	// Буфер в одно место: второй сигнал, пока первый не взят, ничего не добавляет.
	nudge, resync, wake chan struct{}

	mu   sync.Mutex
	last *workloadLatest // последняя удавшаяся выборка: из неё текущие значения секции
	gate workloadWakeGate

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type workloadLatest struct {
	sample WorkloadSample
	stacks map[string]bool
	images map[string]WorkloadImageVerdict
}

func newWorkloadRuntime(paths Paths, collector workloadCollector, timings workloadTimings, now func() time.Time) *workloadRuntime {
	return &workloadRuntime{paths: paths, collector: collector, timings: timings, now: now,
		series: NewWorkloadSeries(now()), events: LoadWorkloadEvents(paths), images: LoadWorkloadImages(paths),
		nudge: make(chan struct{}, 1), resync: make(chan struct{}, 1), wake: make(chan struct{}, 1),
		gate: workloadWakeGate{every: timings.wake}}
}

func currentWorkloads() *workloadRuntime {
	workloadsMu.Lock()
	defer workloadsMu.Unlock()
	return workloadsRun
}

func workloadSignal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// StartWorkloads запускает выборку (первая — сразу, дальше раз в 60 с) и поток
// docker events. Повторный старт без остановки ничего не делает.
func StartWorkloads(ctx context.Context, paths Paths) {
	if currentWorkloads() != nil {
		return
	}
	startWorkloadRuntime(ctx, newWorkloadRuntime(paths, defaultWorkloadCollector(), workloadDefaultTimings, time.Now))
}

func startWorkloadRuntime(ctx context.Context, rt *workloadRuntime) {
	workloadsMu.Lock()
	defer workloadsMu.Unlock()
	if workloadsRun != nil {
		return
	}
	ctx, rt.cancel = context.WithCancel(ctx)
	rt.wg.Add(2)
	go func() {
		defer rt.wg.Done()
		rt.run(ctx)
	}()
	go func() {
		defer rt.wg.Done()
		workloadFollowEvents(ctx, rt.timings.backoffMin, rt.timings.backoffMax,
			func() { workloadSignal(rt.nudge) }, func() { workloadSignal(rt.resync) })
	}()
	workloadsRun = rt
}

// StopWorkloads останавливает подсистему и ЖДЁТ её: отмена убивает дочерние
// docker (группой процессов, newDockerCmd), ожидание их дожидается. Перед
// exec самообновления это обязательно — пережившие exec `docker events`
// копились бы по одному на каждое обновление.
func StopWorkloads() {
	workloadsMu.Lock()
	rt := workloadsRun
	workloadsRun = nil
	workloadsMu.Unlock()
	if rt == nil {
		return
	}
	rt.cancel()
	rt.wg.Wait()
}

// WorkloadsApplyBegin и WorkloadsApplyEnd обрамляют применение релизов: пока
// оно идёт, вердикт образа стеков — unknown (apply_in_progress), а релиз,
// сменивший идентичность между ними, получает эталон apply (решение 6).
func WorkloadsApplyBegin() {
	if rt := currentWorkloads(); rt != nil {
		rt.images.BeginApply(LoadApplied(rt.paths))
	}
}

func WorkloadsApplyEnd() {
	if rt := currentWorkloads(); rt != nil {
		rt.images.EndApply(LoadApplied(rt.paths))
	}
}

// WorkloadsAttach кладёт секцию в тело такта, собранное целиком: бюджет
// секции считается от остального тела (решение 9), поэтому зовётся последней.
// nil — секции нет: подсистема не запущена, выборок ещё не было или секция не
// помещается даже пустой.
func WorkloadsAttach(req *TickRequest) {
	if req == nil {
		return
	}
	rt := currentWorkloads()
	if rt == nil {
		return
	}
	req.Workloads = nil
	rest, err := json.Marshal(req)
	if err != nil {
		return
	}
	req.Workloads = rt.section(len(rest))
}

// WorkloadsDelivered снимает с очередей ровно то, что ушло в секции, и только
// при accepted.workloads == 1: отсутствие поля — «не доставлено» (решение 1).
func WorkloadsDelivered(req TickRequest, resp TickResponse) {
	rt := currentWorkloads()
	if rt == nil || req.Workloads == nil || !WorkloadsAccepted(resp) {
		return
	}
	rt.series.Acknowledge(req.Workloads.Buckets)
	if err := rt.events.Acknowledge(req.Workloads.Events); err != nil {
		fmt.Fprintf(os.Stderr, "нагрузки: %v\n", err)
	}
}

// WorkloadsWake — будильник такта: проблемное событие (crashed, restarted,
// unhealthy), не чаще раза в минуту. До старта — nil-канал, и case в select
// на нём не срабатывает никогда.
func WorkloadsWake() <-chan struct{} {
	if rt := currentWorkloads(); rt != nil {
		return rt.wake
	}
	return nil
}

func (rt *workloadRuntime) run(ctx context.Context) {
	planned := time.NewTicker(rt.timings.interval)
	defer planned.Stop()
	var debounce, wake <-chan time.Time

	rt.sample(ctx, true)
	for {
		select {
		case <-ctx.Done():
			return
		case <-planned.C:
			rt.sample(ctx, true)
		case <-rt.nudge:
			// Первое событие открывает окно, остальные в него сливаются.
			if debounce == nil {
				debounce = time.After(rt.timings.debounce)
			}
			continue
		case <-debounce:
			debounce = nil
			rt.sample(ctx, false)
		case <-rt.resync:
			// Сверка после разрыва — сразу; она же закрывает открытое окно.
			debounce = nil
			rt.sample(ctx, false)
		case <-wake:
			rt.wakeIfDue()
		}
		wake = rt.wakeAfter()
	}
}

// sample — одна выборка. В корзины идут только плановые: внеочередные будит
// поток, и контейнер в цикле перезапуска раздувал бы samples и тянул avg к
// моментам падений. Сверка событий и эталон образа — на каждой.
func (rt *workloadRuntime) sample(ctx context.Context, planned bool) {
	at := rt.now()
	s, err := rt.collector.collect(ctx, at)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "нагрузки: выборки нет: %v\n", err)
		}
		return
	}
	applied := LoadApplied(rt.paths)
	stacks := WorkloadPlatformStacks(applied)
	if planned {
		rt.series.AddPlanned(s, stacks)
	}
	events, err := rt.events.Reconcile(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "нагрузки: %v\n", err)
	}
	verdicts, err := rt.images.Evaluate(s, applied)
	if err != nil {
		fmt.Fprintf(os.Stderr, "нагрузки: %v\n", err)
	}

	rt.mu.Lock()
	rt.last = &workloadLatest{sample: s, stacks: stacks, images: verdicts}
	fire := rt.gate.note(at, WorkloadHasProblemEvents(events))
	rt.mu.Unlock()
	if fire {
		workloadSignal(rt.wake)
	}
}

func (rt *workloadRuntime) wakeIfDue() {
	rt.mu.Lock()
	fire := rt.gate.note(rt.now(), false)
	rt.mu.Unlock()
	if fire {
		workloadSignal(rt.wake)
	}
}

// wakeAfter — таймер отложенного будильника или nil, если будить нечего.
func (rt *workloadRuntime) wakeAfter() <-chan time.Time {
	rt.mu.Lock()
	due := rt.gate.due()
	rt.mu.Unlock()
	if due.IsZero() {
		return nil
	}
	return time.After(max(due.Sub(rt.now()), 0))
}

func (rt *workloadRuntime) section(restBodyBytes int) *WorkloadsSection {
	rt.mu.Lock()
	last := rt.last
	// Собираемый такт возьмёт уже поставленные события: будильник, поднятый
	// до него, им и исполнен. Иначе следом ушёл бы второй такт с тем же
	// содержимым — а такт расшифровывает секреты всех приложений хоста.
	rt.gate.pending = false
	select {
	case <-rt.wake:
	default:
	}
	rt.mu.Unlock()
	if last == nil {
		return nil
	}
	return BuildWorkloadsSection(WorkloadSectionInput{
		Sample: last.sample, Stacks: last.stacks, Images: last.images,
		Since: rt.series.Since(), Buckets: rt.series.Pending(), Events: rt.events.Pending(),
		DroppedBuckets: rt.series.DroppedBuckets(), DroppedEvents: rt.events.Dropped(),
	}, restBodyBytes)
}

// workloadWakeGate — будильник такта не чаще раза в every. Проблема, пришедшая
// раньше срока, не теряется, а ждёт его: иначе падение через полминуты после
// предыдущего ждало бы планового такта, а он бывает и раз в пять минут.
type workloadWakeGate struct {
	every   time.Duration
	last    time.Time
	pending bool
}

// note — выборка в момент now поставила (problem) или не поставила проблемное
// событие; true — будить такт сейчас.
func (g *workloadWakeGate) note(now time.Time, problem bool) bool {
	if problem {
		g.pending = true
	}
	if !g.pending || (!g.last.IsZero() && now.Sub(g.last) < g.every) {
		return false
	}
	g.pending, g.last = false, now
	return true
}

// due — когда будить отложенную проблему; нулевое время — будить нечего.
func (g *workloadWakeGate) due() time.Time {
	if !g.pending {
		return time.Time{}
	}
	return g.last.Add(g.every)
}
