package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Очередь событий на диске (ADR-0091, решение 5): базовая линия сдвигается
// только вместе с записью очереди, пределы 200 записей и 64 КиБ, за такт не
// больше 20, подтверждение снимает ровно отправленное.

func eventKeys(events []WorkloadEvent) []string {
	keys := make([]string, 0, len(events))
	for _, e := range events {
		keys = append(keys, e.Key)
	}
	return keys
}

func eventByKind(t *testing.T, events []WorkloadEvent, kind string) WorkloadEvent {
	t.Helper()
	for _, e := range events {
		if e.Kind == kind {
			return e
		}
	}
	t.Fatalf("нет события %s среди %v", kind, events)
	return WorkloadEvent{}
}

// transitionSamples — до и после: падение, нездоровье и новый сервис разом.
func transitionSamples() (before, after []WorkloadObservedContainer) {
	worker := pyContainer("orbita-worker-1", pyID1)
	web := testRunning(2, "orbita", "web")
	web.Health = "healthy"
	before = []WorkloadObservedContainer{worker, web}

	crashed := worker
	crashed.State, crashed.Running, crashed.ExitCode = "exited", false, 1
	crashed.FinishedAt = "2026-09-23T10:08:21.76409Z"
	sick := web
	sick.Health = "unhealthy"
	return before, []WorkloadObservedContainer{crashed, sick, testRunning(3, "orbita", "api")}
}

// Упала запись — базовая линия прежняя, и повтор даёт те же события с теми
// же ключами. Сдвинься линия без очереди, событие было бы потеряно навсегда.
func TestWorkloadEventsRetryAfterFailedWriteGivesSameKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w := LoadWorkloadEvents(Paths{StateDir: dir})
	before, after := transitionSamples()
	if _, err := w.Reconcile(testWorkloadSample(minute(0), before...)); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if events, err := w.Reconcile(testWorkloadSample(minute(1), after...)); err == nil || events != nil {
		t.Fatalf("запись в пропавший каталог прошла: %v %v", events, err)
	}
	if len(w.Pending()) != 0 {
		t.Fatal("событие в очереди без записи на диск")
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	retried, err := w.Reconcile(testWorkloadSample(minute(2), after...))
	if err != nil {
		t.Fatal(err)
	}
	if len(retried) != 3 || !slices.Equal(eventKeys(w.Pending()), eventKeys(retried)) {
		t.Fatalf("повтор после упавшей записи: %v", retried)
	}

	// Те же ключи, что у сверки без сбоя: сборка и падение — детерминированно.
	control := LoadWorkloadEvents(Paths{StateDir: t.TempDir()})
	_, _ = control.Reconcile(testWorkloadSample(minute(0), before...))
	expected, _ := control.Reconcile(testWorkloadSample(minute(1), after...))
	for _, kind := range []string{WorkloadEventCrashed, WorkloadEventDeployed} {
		if eventByKind(t, retried, kind).Key != eventByKind(t, expected, kind).Key {
			t.Errorf("%s: ключ повтора разошёлся с ключом сверки без сбоя", kind)
		}
	}
	// Нездоровье держит отметку эпизода, заведённую упавшей попыткой.
	episode := w.episodes["orbita-web-1"]
	if !strings.HasPrefix(episode.Since, workloadTimestamp(minute(1))+"#") {
		t.Fatalf("эпизод заведён заново: %s", episode.Since)
	}
	web := after[1]
	want := workloadEventKey([]any{web.Name, WorkloadEventUnhealthy, web.ID, episode.Since})
	if eventByKind(t, retried, WorkloadEventUnhealthy).Key != want {
		t.Fatal("ключ unhealthy не от эпизода упавшей попытки")
	}

	if events, _ := w.Reconcile(testWorkloadSample(minute(3), after...)); len(events) != 0 {
		t.Fatalf("базовая линия не сдвинулась после записи: %v", events)
	}
}

func queueEvent(i int, name string) WorkloadEvent {
	return WorkloadEvent{Key: fmt.Sprintf("%032x", i), Kind: WorkloadEventStopped, Name: name, At: "2026-09-23T10:00:00Z"}
}

func queueBytes(events []WorkloadEvent) int {
	total := 0
	for _, e := range events {
		total += workloadEventBytes(e)
	}
	return total
}

func TestWorkloadEventQueueLimits(t *testing.T) {
	var many []WorkloadEvent
	for i := 0; i < 250; i++ {
		many = append(many, queueEvent(i, fmt.Sprintf("c-%d", i)))
	}
	out, added, evicted := workloadEnqueue(nil, many)
	if len(out) != workloadEventQueueMaxEntries || evicted != 50 || len(added) != 250 || out[0].Key != many[50].Key {
		t.Fatalf("200 записей: %d, вытеснено %d, первая %s", len(out), evicted, out[0].Key)
	}

	var heavy []WorkloadEvent
	for i := 0; i < 120; i++ {
		e := queueEvent(i, strings.Repeat("n", 250)+fmt.Sprint(i))
		e.Image = strPtr(strings.Repeat("r", 500))
		heavy = append(heavy, e)
	}
	out, _, evicted = workloadEnqueue(nil, heavy)
	if queueBytes(out) > workloadEventQueueMaxBytes || evicted == 0 || out[len(out)-1].Key != heavy[119].Key {
		t.Fatalf("64 КиБ: %d байт, вытеснено %d", queueBytes(out), evicted)
	}
	if queueBytes(out)+workloadEventBytes(heavy[int(evicted)-1]) <= workloadEventQueueMaxBytes {
		t.Fatal("вытеснено больше, чем требовал предел")
	}

	// Повтор ключа не занимает места второй раз.
	out, added, _ = workloadEnqueue(out, heavy[len(heavy)-3:])
	if len(added) != 0 || out[len(out)-1].Key != heavy[119].Key {
		t.Fatalf("повтор ключа добавлен: %d", len(added))
	}
}

// removeServices — базовая линия из n compose-сервисов, затем все пропали:
// n событий removed одной сверкой.
func removeServices(t *testing.T, w *WorkloadEvents, n int) {
	t.Helper()
	var cs []WorkloadObservedContainer
	for i := 0; i < n; i++ {
		cs = append(cs, testRunning(i+1, "orbita", fmt.Sprintf("s%03d", i)))
	}
	if _, err := w.Reconcile(testWorkloadSample(minute(0), cs...)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reconcile(testWorkloadSample(minute(1))); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadEventsOverflowCountsDropped(t *testing.T) {
	w := LoadWorkloadEvents(Paths{StateDir: t.TempDir()})
	removeServices(t, w, 210)
	queued := len(w.state.Queue)
	if queued > workloadEventQueueMaxEntries || queueBytes(w.state.Queue) > workloadEventQueueMaxBytes {
		t.Fatalf("очередь вне пределов: %d записей, %d байт", queued, queueBytes(w.state.Queue))
	}
	if w.Dropped() != int64(210-queued) {
		t.Fatalf("вытеснено %d, в очереди %d из 210", w.Dropped(), queued)
	}
	// Вытесняются старейшие: последним в очереди стоит последнее событие сверки.
	if last := w.state.Queue[queued-1]; last.Name != "orbita-s209-1" {
		t.Fatalf("последним стоит %s", last.Name)
	}
}

func TestWorkloadEventsPendingAndAcknowledge(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	w := LoadWorkloadEvents(p)
	removeServices(t, w, 30)

	sent := w.Pending()
	if len(sent) != WorkloadsMaxEvents || sent[0].Key != w.state.Queue[0].Key {
		t.Fatalf("за такт %d событий, первое — не старейшее", len(sent))
	}
	// Пока такт в пути, сверка поставила новое событие: подтверждение его не снимает.
	fresh := testRunning(500, "orbita", "late")
	if _, err := w.Reconcile(testWorkloadSample(minute(2), fresh)); err != nil {
		t.Fatal(err)
	}
	if err := w.Acknowledge(sent); err != nil {
		t.Fatal(err)
	}
	rest := w.Pending()
	if len(rest) != 11 || rest[len(rest)-1].Name != "orbita-late-1" {
		t.Fatalf("после подтверждения: %d, последнее %s", len(rest), rest[len(rest)-1].Name)
	}
	for _, e := range rest {
		if slices.Contains(eventKeys(sent), e.Key) {
			t.Fatalf("подтверждённое осталось: %s", e.Key)
		}
	}
	if err := w.Acknowledge([]WorkloadEvent{{Key: strings.Repeat("f", 32)}}); err != nil || len(w.Pending()) != 11 {
		t.Fatal("чужой ключ снял событие")
	}

	// Перезапуск агента: очередь и базовая линия читаются с диска.
	again := LoadWorkloadEvents(p)
	if !slices.Equal(eventKeys(again.Pending()), eventKeys(rest)) || again.Dropped() != 0 {
		t.Fatalf("после перезапуска: %v", eventKeys(again.Pending()))
	}
	if events, err := again.Reconcile(testWorkloadSample(minute(3), fresh)); err != nil || len(events) != 0 {
		t.Fatalf("базовая линия не пережила перезапуск: %v %v", events, err)
	}
}

func TestWorkloadEventsBrokenFileIsFirstRun(t *testing.T) {
	p := Paths{StateDir: t.TempDir()}
	if err := os.WriteFile(workloadEventsPath(p), []byte(`{"v":1,"baseline":`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := LoadWorkloadEvents(p)
	_, after := transitionSamples()
	if events, _ := w.Reconcile(testWorkloadSample(minute(0), after...)); len(events) != 0 {
		t.Fatalf("битый файл — точка отсчёта, а не события: %v", events)
	}
}
