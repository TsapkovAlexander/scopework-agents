package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Пакетный API сигналов нагрузок для main.go (ADR-0091): фоновая выборка,
// будильник такта, секция и её подтверждение.

// workloadTestClock — часы выборки, которые тест двигает сам: минута
// ожидания будильника не должна стоить минуты прогона.
type workloadTestClock struct{ now time.Time }

func (c *workloadTestClock) Now() time.Time { return c.now }

// workloadTestRuntime — подсистема на подставном docker и своих часах,
// поставленная синглтоном пакета без фоновых горутин: выборки тест зовёт сам.
func workloadTestRuntime(t *testing.T) (*workloadRuntime, *workloadDockerStub, *workloadTestClock) {
	t.Helper()
	d := installWorkloadDocker(t)
	d.host(nil, "", nil, "")
	clock := &workloadTestClock{now: testWorkloadStart.Add(10 * time.Second)}
	rt := newWorkloadRuntime(Paths{StateDir: t.TempDir()}, workloadTestCollector(t), workloadDefaultTimings, clock.Now)
	rt.cancel = func() {}
	workloadsMu.Lock()
	workloadsRun = rt
	workloadsMu.Unlock()
	t.Cleanup(func() {
		workloadsMu.Lock()
		workloadsRun = nil
		workloadsMu.Unlock()
	})
	return rt, d, clock
}

// workloadStartTestRuntime — подсистема целиком, с выборкой по таймеру и потоком.
func workloadStartTestRuntime(t *testing.T, timings workloadTimings) *workloadDockerStub {
	t.Helper()
	d := installWorkloadDocker(t)
	d.host(nil, "", nil, "")
	startWorkloadRuntime(context.Background(),
		newWorkloadRuntime(Paths{StateDir: t.TempDir()}, workloadTestCollector(t), timings, time.Now))
	t.Cleanup(StopWorkloads)
	return d
}

func workloadFastTimings() workloadTimings {
	return workloadTimings{interval: time.Hour, debounce: 50 * time.Millisecond, wake: time.Minute,
		backoffMin: 10 * time.Millisecond, backoffMax: 40 * time.Millisecond}
}

func workloadInspectExited(id, project, service string, code int, finishedAt string) string {
	return fmt.Sprintf(`{"Id":%q,"Name":"/%s-%s-1","RestartCount":0,"Image":%q,`+
		`"State":{"Status":"exited","Running":false,"Pid":0,"ExitCode":%d,"OOMKilled":false,`+
		`"StartedAt":"2026-09-23T09:00:00Z","FinishedAt":%q},"HostConfig":{"NetworkMode":"bridge"},`+
		`"Config":{"Image":"app:1","Labels":{"com.docker.compose.project":%q,"com.docker.compose.service":%q}}}`,
		id, project, service, testWorkloadImage(1), code, finishedAt, project, service)
}

// workloadOne — на хосте один контейнер в данном состоянии.
func workloadOne(d *workloadDockerStub, inspect string) {
	d.host([]string{testWorkloadID(1)}, workloadInspectArray(inspect), nil, "")
}

func workloadWoken() bool {
	select {
	case <-WorkloadsWake():
		return true
	default:
		return false
	}
}

func workloadEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("не дождались: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// До старта и после остановки main.go зовёт всё то же самое — ничего не
// должно ни падать, ни трогать такт.
func TestWorkloadsNilSafeBeforeStart(t *testing.T) {
	StopWorkloads()
	if WorkloadsWake() != nil {
		t.Fatal("будильник до старта — не nil-канал: select сработал бы на нём")
	}
	req := TickRequest{AgentVersion: "3.0.0"}
	WorkloadsAttach(&req)
	WorkloadsAttach(nil)
	if req.Workloads != nil {
		t.Fatal("секция без запущенной подсистемы")
	}
	WorkloadsDelivered(req, TickResponse{Accepted: json.RawMessage(`{"workloads":1}`)})
	WorkloadsApplyBegin()
	WorkloadsApplyEnd()
	StopWorkloads()
}

// Будильник не чаще раза в минуту, и проблема, пришедшая раньше срока, не
// теряется, а ждёт его (ADR-0091, решение 5).
func TestWorkloadWakeGateAtMostOncePerMinute(t *testing.T) {
	g := workloadWakeGate{every: time.Minute}
	t0 := testWorkloadStart
	steps := []struct {
		at      time.Duration
		problem bool
		fire    bool
		due     time.Duration // 0 — будить нечего
	}{
		{0, false, false, 0},
		{time.Second, true, true, 0},
		{11 * time.Second, true, false, 61 * time.Second},
		{21 * time.Second, true, false, 61 * time.Second},
		{60 * time.Second, false, false, 61 * time.Second},
		{61 * time.Second, false, true, 0},
		{62 * time.Second, false, false, 0},
		{200 * time.Second, true, true, 0},
	}
	for _, s := range steps {
		if got := g.note(t0.Add(s.at), s.problem); got != s.fire {
			t.Fatalf("на %s (проблема %v): будить %v, ожидалось %v", s.at, s.problem, got, s.fire)
		}
		want := time.Time{}
		if s.due != 0 {
			want = t0.Add(s.due)
		}
		if got := g.due(); !got.Equal(want) {
			t.Fatalf("на %s: срок %v, ожидался %v", s.at, got, want)
		}
	}
}

// Сквозь выборки: падение будит такт, второе падение через 10 с — нет, оно
// ждёт минуты; остановка с чистым кодом не будит вовсе.
func TestWorkloadWakeFromSamples(t *testing.T) {
	rt, d, clock := workloadTestRuntime(t)
	ctx := context.Background()

	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 1, 0, ""))
	rt.sample(ctx, true)
	if workloadWoken() {
		t.Fatal("точка отсчёта разбудила такт")
	}

	clock.now = clock.now.Add(10 * time.Second)
	workloadOne(d, workloadInspectExited(testWorkloadID(1), "orbita", "app", 1, "2026-09-23T10:00:15Z"))
	rt.sample(ctx, false)
	if !workloadWoken() {
		t.Fatal("падение не разбудило такт")
	}

	clock.now = clock.now.Add(10 * time.Second)
	workloadOne(d, workloadInspectExited(testWorkloadID(1), "orbita", "app", 2, "2026-09-23T10:00:25Z"))
	rt.sample(ctx, false)
	if workloadWoken() {
		t.Fatal("второе падение через 10 с разбудило такт: будильник чаще раза в минуту")
	}

	clock.now = clock.now.Add(55 * time.Second)
	rt.sample(ctx, true)
	if !workloadWoken() {
		t.Fatal("отложенная проблема не разбудила такт по истечении минуты")
	}

	clock.now = clock.now.Add(2 * time.Minute)
	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 1, 0, ""))
	rt.sample(ctx, true)
	workloadOne(d, workloadInspectExited(testWorkloadID(1), "orbita", "app", 0, "2026-09-23T10:04:00Z"))
	rt.sample(ctx, true)
	if workloadWoken() {
		t.Fatal("чистая остановка разбудила такт: её везёт плановый")
	}
}

// Внеочередные выборки в корзины не идут: контейнер в цикле перезапуска
// раздувал бы samples и тянул avg к моментам падений.
func TestWorkloadUrgentSampleSkipsBuckets(t *testing.T) {
	rt, d, clock := workloadTestRuntime(t)
	ctx := context.Background()
	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 10, 0, ""))

	rt.sample(ctx, true)
	clock.now = clock.now.Add(5 * time.Minute)
	rt.sample(ctx, false)
	if got := rt.series.Pending(); len(got) != 0 {
		t.Fatalf("внеочередная выборка закрыла корзину: %+v", got)
	}
	clock.now = clock.now.Add(time.Second)
	rt.sample(ctx, true)
	got := rt.series.Pending()
	if len(got) != 1 || got[0].Samples != 1 {
		t.Fatalf("корзины %+v, ожидалась одна с одной плановой выборкой", got)
	}
}

// Сквозной прогон: выборка → секция в теле такта → подтверждение снимает
// ровно то, что ушло, и только при accepted.workloads == 1.
func TestWorkloadsSectionAndAcknowledge(t *testing.T) {
	rt, d, clock := workloadTestRuntime(t)
	ctx := context.Background()
	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 10, 0, ""))
	rt.sample(ctx, true)
	clock.now = clock.now.Add(5 * time.Minute)
	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 10, 1, ""))
	rt.sample(ctx, true)

	req := TickRequest{AgentVersion: "3.0.0"}
	WorkloadsAttach(&req)
	sec := req.Workloads
	if sec == nil || len(sec.Containers) != 1 || len(sec.Buckets) != 1 || len(sec.Events) != 1 ||
		sec.Events[0].Kind != WorkloadEventRestarted || sec.CollectedAt != workloadTimestamp(clock.now) {
		t.Fatalf("секция такта: %+v", sec)
	}
	if raw, err := json.Marshal(req); err != nil || !strings.Contains(string(raw), `"workloads":{"version":1`) {
		t.Fatalf("секция не в теле такта: %v", err)
	}

	for _, accepted := range []string{`{"workloads":-1}`, `{"traffic":1}`, `null`, `{"workloads":"1"}`} {
		WorkloadsDelivered(req, TickResponse{Accepted: json.RawMessage(accepted)})
		if len(rt.series.Pending()) != 1 || len(rt.events.Pending()) != 1 {
			t.Fatalf("ответ %s снял очереди без подтверждения", accepted)
		}
	}
	WorkloadsDelivered(req, TickResponse{Accepted: json.RawMessage(`{"workloads":1}`)})
	if len(rt.series.Pending()) != 0 || len(rt.events.Pending()) != 0 {
		t.Fatal("подтверждённое не снято")
	}
	if left := LoadWorkloadEvents(rt.paths).Pending(); len(left) != 0 {
		t.Fatalf("подтверждённые события остались на диске: %+v", left)
	}
}

// Бюджет считается от остального тела такта (736 КиБ): секция, что не
// помещается, не едет вовсе, а прежняя секция в запросе не мерится как «тело».
func TestWorkloadsSectionMeasuresRestOfBody(t *testing.T) {
	rt, d, _ := workloadTestRuntime(t)
	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 10, 0, ""))
	rt.sample(context.Background(), true)

	stale := &WorkloadsSection{Containers: make([]WorkloadContainer, 2000)}
	req := TickRequest{AgentVersion: "3.0.0", Workloads: stale}
	WorkloadsAttach(&req)
	if req.Workloads == nil || req.Workloads == stale {
		t.Fatal("прежняя секция посчитана остальным телом")
	}

	req = TickRequest{AgentVersion: strings.Repeat("x", WorkloadsMaxTickBodyBytes)}
	WorkloadsAttach(&req)
	if req.Workloads != nil {
		t.Fatal("секция приложена к телу, которое уже на пределе: такт получил бы 413")
	}
}

// Пока идёт применение, вердикт образа стеков платформы — apply_in_progress;
// релиз, применённый между Begin и End, получает эталон apply.
func TestWorkloadsApplyBracketsVerdict(t *testing.T) {
	rt, d, _ := workloadTestRuntime(t)
	workloadOne(d, workloadInspectRunning(testWorkloadID(1), "orbita", "app", 10, 0, ""))
	verdict := func() WorkloadImageVerdict {
		rt.sample(context.Background(), true)
		rt.mu.Lock()
		defer rt.mu.Unlock()
		return rt.last.images[testWorkloadID(1)]
	}

	WorkloadsApplyBegin()
	// Применение записало applied.json, выборка пришла посреди него.
	if err := SaveApplied(rt.paths, appliedWith(map[string]AppliedRecord{"orbita": healthyApp("r1", "h1")})); err != nil {
		t.Fatal(err)
	}
	if v := verdict(); v.Reason != WorkloadReasonApplyInProgress {
		t.Fatalf("во время применения: %+v", v)
	}
	WorkloadsApplyEnd()
	if v := verdict(); v.Verdict != WorkloadVerdictMatch || v.BaselineSource != WorkloadBaselineApply {
		t.Fatalf("после применения: %+v", v)
	}
}

// Остановка не оставляет `docker events`: перед exec самообновления
// осиротевший поток жил бы рядом с потоком новой версии.
func TestWorkloadsStopLeavesNoChild(t *testing.T) {
	d := workloadStartTestRuntime(t, workloadFastTimings())
	pid := workloadWaitPid(t, d, 1)
	if WorkloadsWake() == nil {
		t.Fatal("будильник запущенной подсистемы — nil")
	}
	StopWorkloads()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("docker events (pid %d) пережил остановку: %v", pid, err)
	}
	if WorkloadsWake() != nil {
		t.Fatal("будильник остановленной подсистемы — не nil")
	}
}

// Обрыв потока — переподключение и сразу полная сверка: события в разрыве
// поток потерял, сверка — нет.
func TestWorkloadsStreamBreakReconnectsAndResyncs(t *testing.T) {
	d := installWorkloadDocker(t)
	d.write("events.modes", "exit\n")
	d.host(nil, "", nil, "")
	startWorkloadRuntime(context.Background(),
		newWorkloadRuntime(Paths{StateDir: t.TempDir()}, workloadTestCollector(t), workloadFastTimings(), time.Now))
	t.Cleanup(StopWorkloads)

	workloadWaitPid(t, d, 2)
	// Плановая выборка — раз в час, событий в потоке нет: вторая выборка
	// может прийти только от переподключения.
	workloadEventually(t, "полная сверка после переподключения", func() bool { return d.count("ps ") == 2 })
}

// События внутри окна (в бою 2 с) сливаются в одну внеочередную выборку.
// Строки идут с паузой, чтобы первая выборка успела закончиться: иначе они
// слились бы в буфере канала и без окна, и тест ничего бы не проверял.
func TestWorkloadsStreamEventsMergeIntoOneSample(t *testing.T) {
	d := installWorkloadDocker(t)
	d.write("events.out", `{"Type":"container","Action":"die"}`+"\n"+
		`{"Type":"container","Action":"start"}`+"\n"+
		`{"Type":"container","Action":"exec_start: pg_isready"}`+"\n"+
		`{"Type":"container","Action":"health_status: healthy"}`+"\n")
	d.write("events.pace", "0.15\n")
	d.host(nil, "", nil, "")
	timings := workloadFastTimings()
	timings.debounce = time.Second
	startWorkloadRuntime(context.Background(),
		newWorkloadRuntime(Paths{StateDir: t.TempDir()}, workloadTestCollector(t), timings, time.Now))
	t.Cleanup(StopWorkloads)

	workloadEventually(t, "внеочередная выборка по событиям", func() bool { return d.count("ps ") >= 2 })
	time.Sleep(time.Second)
	if n := d.count("ps "); n != 2 {
		t.Fatalf("выборок %d: события окна не слились в одну", n)
	}
}
