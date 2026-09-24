package agent

import (
	"strings"
	"testing"
)

// Классификация событий контейнеров — порт сверки агента мониторинга
// (ADR-0061, решение 4). Ключи сверены с эталоном: их посчитал python3 тем же
// выражением, что и monitor-push.sh, —
// hashlib.sha256(json.dumps(fingerprint).encode("utf-8")).hexdigest()[:32].

const (
	pyID1  = "1cf48d6c97398c2ab33dd6da957b5e7424d036cfddd9d14e1a721b888b6512b5"
	pyID2  = "0a3674119334e1cfb5f520c73c8d77c0d906b6d93b129fb5e661d79a0be286a4"
	pyImg1 = "sha256:770519f9d6ef81c37c4e8055193c545de3fc1af909cf20e4214bd17a94437212"
	pyImg2 = "sha256:b44ad5f364bd4f9c37d611ac3000be819a50f769380b03292e53152199be6ca8"
)

func TestWorkloadEventKeyMatchesPython(t *testing.T) {
	cases := []struct {
		fingerprint []any
		key         string
	}{
		{[]any{"orbita-web-1", "deployed", pyID1, pyImg1, pyID2, pyImg2}, "12414dd669fe42d72db8414ccb3153ab"},
		{[]any{"orbita-web-1", "deployed", pyID1, pyImg1, nil, nil}, "cc10985b1bd6fa9ce526885a8a6be4e8"},
		{[]any{"orbita-worker-1", "restarted", pyID1, 3, "2026-09-23T10:08:21.764090123Z"}, "438b9307f2781ca7b145ac6056ca7c8e"},
		{[]any{"orbita-worker-1", "restarted", pyID1, 0, nil}, "1ed4bffbf91685e13f55aaa900786cec"},
		{[]any{"orbita-worker-1", "crashed", pyID1, "2026-09-23T10:08:21.76409Z"}, "ece1e6828876d2a95c391c24c5de60c7"},
		{[]any{"orbita-worker-1", "stopped", pyID1, "2026-09-23T10:08:21Z"}, "9cd91f524e10606b15291b2cad1b793e"},
		{[]any{"orbita-web-1", "unhealthy", pyID1, "2026-09-23T10:13:41.482Z#9f3a01bc"}, "73048895ff74983aa87d5eae788b9040"},
		{[]any{"orbita-web-1", "unhealthy", pyID1, nil}, "49ac8b00d34bb166c7a4c3464ea34812"},
		{[]any{"orbita-web-1", "removed", pyID1}, "d1063c9b36b23bc29052443527a24ec8"},
		{[]any{"сервис-ё-1", "crashed", pyID1, "2026-09-23T10:08:21Z"}, "e962c6620c2523b1b1c9976f35586946"},
		{[]any{"app-\U0001F680 \"q\" \\ / \n\t\r\b\f \x01 \x7f", "restarted", "", int64(jsonSafeIntMax), ""}, "26c365dba126bca7c1c5ea2c12124c5d"},
	}
	for _, tc := range cases {
		if got := workloadEventKey(tc.fingerprint); got != tc.key {
			t.Errorf("%s: ключ %s, у Python %s", workloadPyJSON(tc.fingerprint), got, tc.key)
		}
	}
}

// Сериализация — json.dumps по умолчанию: разделители ", " и ": ",
// ensure_ascii (не-ASCII и управляющие — \uXXXX строчными, суррогатные пары
// за пределами BMP), None — null.
func TestWorkloadPyJSONMatchesPythonDefaults(t *testing.T) {
	cases := map[string][]any{
		`["\u0441\u0435\u0440\u0432\u0438\u0441-\u0451-1", "crashed", null, 0]`: {"сервис-ё-1", "crashed", nil, 0},
		`["app-\ud83d\ude80 \"q\" \\ / \n\t\r\b\f \u0001 \u007f", -5, 9007199254740991]`: {
			"app-\U0001F680 \"q\" \\ / \n\t\r\b\f \x01 \x7f", -5, int64(jsonSafeIntMax)},
		`[]`: {},
	}
	for want, fp := range cases {
		if got := workloadPyJSON(fp); got != want {
			t.Errorf("%q\n получено %s\nожидалось %s", fp, got, want)
		}
	}
}

// reconcileTwice — точка отсчёта первой выборкой, события — второй.
func reconcileTwice(t *testing.T, before, after []WorkloadObservedContainer) []WorkloadEvent {
	t.Helper()
	w := LoadWorkloadEvents(Paths{StateDir: t.TempDir()})
	if events, err := w.Reconcile(testWorkloadSample(minute(0), before...)); err != nil || len(events) != 0 {
		t.Fatalf("точка отсчёта: %v, %v", events, err)
	}
	events, err := w.Reconcile(testWorkloadSample(minute(1), after...))
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func onlyEvent(t *testing.T, events []WorkloadEvent, kind string) WorkloadEvent {
	t.Helper()
	if len(events) != 1 || events[0].Kind != kind {
		t.Fatalf("ожидалось одно событие %s, получено %+v", kind, events)
	}
	return events[0]
}

func pyContainer(name, id string) WorkloadObservedContainer {
	c := testRunning(1, "orbita", strings.TrimSuffix(strings.TrimPrefix(name, "orbita-"), "-1"))
	c.Name, c.ID = name, id
	return c
}

// Первая сверка после установки или потери состояния — точка отсчёта:
// иначе хост с тридцатью контейнерами начинался бы с тридцати сборок.
func TestWorkloadEventsFirstReconcileIsBaseline(t *testing.T) {
	w := LoadWorkloadEvents(Paths{StateDir: t.TempDir()})
	crashed := pyContainer("orbita-worker-1", pyID1)
	crashed.State, crashed.Running, crashed.ExitCode = "exited", false, 1
	crashed.FinishedAt = "2026-09-23T10:08:21Z"
	crashed.Health = "unhealthy"
	events, err := w.Reconcile(testWorkloadSample(minute(0), crashed, testRunning(2, "orbita", "web")))
	if err != nil || len(events) != 0 || len(w.Pending()) != 0 {
		t.Fatalf("точка отсчёта дала события: %v %v", events, err)
	}
}

func TestWorkloadEventsRestarted(t *testing.T) {
	before := pyContainer("orbita-worker-1", pyID1)
	before.RestartCount = 3
	before.FinishedAt = "2026-09-23T10:08:21.764090123Z"
	after := before
	after.RestartCount = 5
	after.State, after.Restarting, after.ExitCode = "restarting", true, 2
	after.FinishedAt = "2026-09-23T10:09:00Z"

	ev := onlyEvent(t, reconcileTwice(t, []WorkloadObservedContainer{before}, []WorkloadObservedContainer{after}), WorkloadEventRestarted)
	// Отсчёт — от принятого состояния: повтор после потерянного ответа даёт тот же ключ.
	if ev.Key != "438b9307f2781ca7b145ac6056ca7c8e" || *ev.Restarts != 2 {
		t.Fatalf("restarted: ключ %s, перезапусков %v", ev.Key, *ev.Restarts)
	}
	if ev.ExitCode == nil || *ev.ExitCode != 2 || ev.At != "2026-09-23T10:09:00Z" || ev.Health != nil || ev.PrevImage != nil {
		t.Fatalf("поля restarted: %+v", ev)
	}
}

func TestWorkloadEventsCrashedAndStopped(t *testing.T) {
	before := pyContainer("orbita-worker-1", pyID1)
	exit := func(code int, oom bool) WorkloadObservedContainer {
		c := before
		c.State, c.Running, c.ExitCode, c.OOMKilled = "exited", false, code, oom
		c.FinishedAt = "2026-09-23T10:08:21.76409Z"
		return c
	}

	ev := onlyEvent(t, reconcileTwice(t, []WorkloadObservedContainer{before}, []WorkloadObservedContainer{exit(1, false)}), WorkloadEventCrashed)
	if ev.Key != "ece1e6828876d2a95c391c24c5de60c7" || *ev.ExitCode != 1 || *ev.OOMKilled || ev.At != "2026-09-23T10:08:21.76409Z" {
		t.Fatalf("crashed: %+v", ev)
	}
	// OOM — падение и при коде 137, который без OOM значит ручную остановку.
	onlyEvent(t, reconcileTwice(t, []WorkloadObservedContainer{before}, []WorkloadObservedContainer{exit(137, true)}), WorkloadEventCrashed)

	// Чистые коды — литералом, а не списком из кода: иначе правка списка
	// правила бы и проверку.
	for _, code := range []int{0, 130, 137, 143} {
		ev := onlyEvent(t, reconcileTwice(t, []WorkloadObservedContainer{before}, []WorkloadObservedContainer{exit(code, false)}), WorkloadEventStopped)
		if *ev.ExitCode != code || ev.Restarts != nil {
			t.Fatalf("stopped %d: %+v", code, ev)
		}
	}
}

// Новый контейнер, вышедший чисто, — разовая работа, сделанная до конца; упавший — падение.
func TestWorkloadEventsNewExitedContainer(t *testing.T) {
	base := testRunning(1, "orbita", "web")
	job := testRunning(2, "orbita", "migrate")
	job.ComposeOneoff = true
	job.State, job.Running, job.FinishedAt = "exited", false, "2026-09-23T10:00:30Z"
	if events := reconcileTwice(t, []WorkloadObservedContainer{base}, []WorkloadObservedContainer{base, job}); len(events) != 0 {
		t.Fatalf("чистый выход разовой задачи дал события: %+v", events)
	}
	job.ExitCode = 3
	onlyEvent(t, reconcileTwice(t, []WorkloadObservedContainer{base}, []WorkloadObservedContainer{base, job}), WorkloadEventCrashed)
}

func TestWorkloadEventsUnhealthyEpisodes(t *testing.T) {
	w := LoadWorkloadEvents(Paths{StateDir: t.TempDir()})
	c := testRunning(1, "orbita", "web")
	c.Health = "healthy"
	sick := c
	sick.Health = "unhealthy"
	step := func(n int, x WorkloadObservedContainer) []WorkloadEvent {
		events, err := w.Reconcile(testWorkloadSample(minute(n), x))
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	step(0, c)
	first := onlyEvent(t, step(1, sick), WorkloadEventUnhealthy)
	if deref(first.Health) != "unhealthy" || first.ExitCode != nil {
		t.Fatalf("unhealthy: %+v", first)
	}
	if events := step(2, sick); len(events) != 0 {
		t.Fatalf("тот же эпизод повторён: %+v", events)
	}
	step(3, c)
	// Новый эпизод после выздоровления — новый ключ, иначе платформа
	// отбросила бы его как повтор первого.
	second := onlyEvent(t, step(4, sick), WorkloadEventUnhealthy)
	if second.Key == first.Key {
		t.Fatal("второй эпизод получил ключ первого")
	}
}

func TestWorkloadEventsDeployed(t *testing.T) {
	before := pyContainer("orbita-web-1", pyID2)
	before.ImageID, before.ImageRef = pyImg2, "registry.example.test/orbita/web:2.4.0"
	after := pyContainer("orbita-web-1", pyID1)
	after.ImageID, after.ImageRef = pyImg1, "registry.example.test/orbita/web:2.4.1"

	ev := onlyEvent(t, reconcileTwice(t, []WorkloadObservedContainer{before}, []WorkloadObservedContainer{after}), WorkloadEventDeployed)
	if ev.Key != "12414dd669fe42d72db8414ccb3153ab" || deref(ev.PrevImageID) != pyImg2 ||
		deref(ev.PrevImage) != "registry.example.test/orbita/web:2.4.0" || ev.ExitCode != nil {
		t.Fatalf("deployed: %+v", ev)
	}

	// Новый постоянный compose-сервис — сборка; разовый и без compose — нет.
	fresh := pyContainer("orbita-web-1", pyID1)
	fresh.ImageID = pyImg1
	ev = onlyEvent(t, reconcileTwice(t, nil, []WorkloadObservedContainer{fresh}), WorkloadEventDeployed)
	if ev.Key != "cc10985b1bd6fa9ce526885a8a6be4e8" || ev.PrevImageID != nil {
		t.Fatalf("новый сервис: %+v", ev)
	}
	oneoff := fresh
	oneoff.ComposeOneoff = true
	plain := testRunning(3, "", "legacy-cron")
	if events := reconcileTwice(t, nil, []WorkloadObservedContainer{oneoff, plain}); len(events) != 0 {
		t.Fatalf("разовый и не-compose контейнер дали сборку: %+v", events)
	}
}

func TestWorkloadEventsRemovedAndComposeRecreate(t *testing.T) {
	w := LoadWorkloadEvents(Paths{StateDir: t.TempDir()})
	web := pyContainer("orbita-web-1", pyID1)
	plain := testRunning(3, "", "legacy-cron")
	step := func(n int, cs ...WorkloadObservedContainer) []WorkloadEvent {
		events, err := w.Reconcile(testWorkloadSample(minute(n), cs...))
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	step(0, web, plain)
	ev := onlyEvent(t, step(1), WorkloadEventRemoved)
	if ev.Key != "d1063c9b36b23bc29052443527a24ec8" || deref(ev.ComposeService) != "web" {
		t.Fatalf("removed: %+v", ev)
	}
	// `compose down` и `up` с тем же образом — не сборка.
	again := web
	again.ID = pyID2
	if events := step(2, again); len(events) != 0 {
		t.Fatalf("пересоздание с тем же образом дало события: %+v", events)
	}
}

// Проблемные виды будят такт (решение 5), остальные уходят плановым.
func TestWorkloadHasProblemEvents(t *testing.T) {
	for kind, want := range map[string]bool{
		WorkloadEventRestarted: true, WorkloadEventCrashed: true, WorkloadEventUnhealthy: true,
		WorkloadEventDeployed: false, WorkloadEventStopped: false, WorkloadEventRemoved: false,
	} {
		if got := WorkloadHasProblemEvents([]WorkloadEvent{{Kind: kind}}); got != want {
			t.Errorf("%s: %v", kind, got)
		}
	}
	if WorkloadHasProblemEvents(nil) {
		t.Error("пусто — будить нечего")
	}
}

func TestWorkloadEventsKeepAtMost512Containers(t *testing.T) {
	var cs []WorkloadObservedContainer
	for i := 0; i < 600; i++ {
		c := testRunning(i+1, "", "run")
		c.Name = "adhoc-" + testWorkloadID(i)[56:]
		c.State, c.Running = "exited", false
		cs = append(cs, c)
	}
	web := testRunning(1000, "orbita", "web")
	cs = append(cs, web)
	selected := workloadSelectContainers(cs)
	if len(selected) != workloadMaxBaselineContainers {
		t.Fatalf("выбрано %d", len(selected))
	}
	if _, ok := selected[web.Name]; !ok {
		t.Fatal("compose-сервис выпал из-за остатков docker run")
	}
}
