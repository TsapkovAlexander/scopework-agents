package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Такт с номером отчёта через настоящий клиент и настоящую очередь на диске
// (ADR-0077). Сборка такта целиком здесь не гоняется — она трогает docker и
// хост; проверяется то, что решает судьбу номера, квитанций и курсоров.

type tickBody struct {
	Report *agent.ReportSection `json:"report"`
}

func testIdentity(t *testing.T) agent.Identity {
	t.Helper()
	id, err := agent.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func driftRecord() agent.DriftRecord {
	return agent.DriftRecord{
		Object:     "compose",
		Slug:       "shop-front",
		Status:     "missing",
		ObservedAt: time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC),
	}
}

// prepare — то, что tick делает с номером: резерв в начале, сигналы ключом
// такта, секция в конце.
func prepare(t *testing.T, paths agent.Paths, queue *agent.ReportQueue, drift bool) agent.TickRequest {
	t.Helper()
	number := reserveReportNumber(paths, false)
	if number == nil {
		t.Fatal("номер не зарезервирован")
	}
	if drift {
		if err := queue.Enqueue(number.Epoch, number.Seq, []agent.DriftRecord{driftRecord()}); err != nil {
			t.Fatal(err)
		}
	}
	var req agent.TickRequest
	attachReport(&req, queue, number)
	return req
}

func TestTickReportSurvivesFailedTickAndAck(t *testing.T) {
	var bodies []tickBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body tickBody
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("тело такта не разбирается: %v", err)
		}
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ack := agent.ReportAck{Epoch: body.Report.Epoch, Seq: body.Report.Seq}
		for _, item := range body.Report.Drift {
			ack.Drift = append(ack.Drift, agent.DriftKey{Epoch: item.Epoch, Seq: item.Seq, Idx: item.Idx})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"reportAck": ack})
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	queue := agent.LoadReportQueue(paths)
	gate := agent.NewReportGate()
	client := agent.NewClient(srv.URL, "test")
	id := testIdentity(t)
	legacy := false

	first := prepare(t, paths, queue, true)
	if _, err := exchange(t.Context(), client, id, first, tickDelivery{}, gate, queue, &legacy); err == nil {
		t.Fatal("500 не дошёл до вызывающего")
	}

	second := prepare(t, paths, queue, false)
	if _, err := exchange(t.Context(), client, id, second, tickDelivery{}, gate, queue, &legacy); err != nil {
		t.Fatalf("второй такт: %v", err)
	}

	if len(bodies) != 2 || bodies[0].Report == nil || bodies[1].Report == nil {
		t.Fatalf("тела без секции report: %+v", bodies)
	}
	r1, r2 := bodies[0].Report, bodies[1].Report
	if r2.Epoch != r1.Epoch || r2.Seq != r1.Seq+1 {
		t.Fatalf("номера %s/%d → %s/%d, ожидался следующий в той же эпохе", r1.Epoch, r1.Seq, r2.Epoch, r2.Seq)
	}
	want := agent.UndeliveredRange{From: r1.Seq, To: r1.Seq, Reason: agent.UndeliveredHTTP5xx}
	if len(r2.Undelivered) != 1 || r2.Undelivered[0] != want {
		t.Fatalf("квитанция первого такта %+v, ожидалось %+v", r2.Undelivered, want)
	}
	if len(r2.Drift) != 1 || r2.Drift[0].Seq != r1.Seq {
		t.Fatalf("сигнал первого такта не уехал повторно: %+v", r2.Drift)
	}

	// После подтверждения очередь пуста и на диске: следующий такт после
	// рестарта ничего не повторит.
	left := agent.LoadReportQueue(paths).Section(agent.ReportNumber{Epoch: r2.Epoch, Seq: r2.Seq + 1})
	if len(left.Drift) != 0 || len(left.Undelivered) != 0 || left.QueueDropped != nil {
		t.Fatalf("после подтверждения в очереди осталось %+v", left)
	}
}

// Старая платформа: 200 без reportAck. Такт штатный, сигнал дрейфа остаётся
// ждать платформы, которая его подтвердит.
func TestTickWithoutReportAckKeepsQueue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"nextPollSeconds":60}`))
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	queue := agent.LoadReportQueue(paths)
	legacy := false

	req := prepare(t, paths, queue, true)
	resp, err := exchange(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), req,
		tickDelivery{}, agent.NewReportGate(), queue, &legacy)
	if err != nil || resp.NextPollSeconds != 60 {
		t.Fatalf("такт без подтверждения упал: %v, %+v", err, resp)
	}
	if drift := agent.LoadReportQueue(paths).Section(agent.ReportNumber{Epoch: req.Report.Epoch, Seq: req.Report.Seq + 1}).Drift; len(drift) != 1 {
		t.Fatalf("очередь без подтверждения изменилась: %+v", drift)
	}
}

// collectWindow — окно журнала с одной строкой на свежем курсоре.
func collectWindow(t *testing.T, paths agent.Paths) agent.TrafficWindow {
	t.Helper()
	logs := filepath.Join(paths.WorkDir, "proxy", "logs")
	if err := os.MkdirAll(logs, 0o750); err != nil {
		t.Fatal(err)
	}
	line := `{"logger":"http.log.access.log0","status":200,"size":1,"request":{"host":"a.example.com","uri":"/","remote_ip":"1.1.1.1"}}` + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.json"), []byte(line), 0o640); err != nil {
		t.Fatal(err)
	}
	w, err := agent.CollectTrafficWindow(paths)
	if err != nil || len(w.Items) != 1 {
		t.Fatalf("окно не собрано: %+v, %v", w, err)
	}
	return w
}

func windowRequest(w agent.TrafficWindow) agent.TickRequest {
	threat := &agent.ThreatWindow{}
	threat.Totals.Parsed = 1
	return agent.TickRequest{
		Traffic: agent.TrafficSection(w.Items, false),
		Threat:  agent.ThreatSection(threat, false),
	}
}

// Неудачный такт не двигает курсор и не съедает запас разобранных строк.
func TestFailedTickKeepsCursorAndPendingParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	window := collectWindow(t, paths)
	gate := agent.NewReportGate()
	legacy := false

	_, err := exchange(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), windowRequest(window),
		tickDelivery{window: window, takenParsed: 7}, gate, agent.LoadReportQueue(paths), &legacy)
	if err == nil {
		t.Fatal("502 не дошёл до вызывающего")
	}
	if _, statErr := os.Stat(filepath.Join(paths.StateDir, "traffic-cursor.json")); !os.IsNotExist(statErr) {
		t.Fatalf("курсор трафика записан после неудачного такта: %v", statErr)
	}
	if again, _ := agent.CollectTrafficWindow(paths); len(again.Items) != 1 {
		t.Fatalf("следующий сбор не видит тех же строк: %+v", again.Items)
	}
	if got := gate.TakePendingParsed(); got != 7 {
		t.Fatalf("запас разобранных строк %d, ожидалось 7", got)
	}
}

// Отдельные ручки: трафик принят, угрозы нет — курсор сдвигается (потеря
// непринятой половины, а не дубль принятой), запас возвращается.
func TestLegacyPartialSuccessMovesCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/deploy/agent/threats" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	window := collectWindow(t, paths)
	gate := agent.NewReportGate()
	legacy := true

	req := windowRequest(window)
	if _, err := exchange(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), req,
		tickDelivery{window: window, takenParsed: 5}, gate, agent.LoadReportQueue(paths), &legacy); err != nil {
		t.Fatalf("состояние не получено: %v", err)
	}
	if again, _ := agent.CollectTrafficWindow(paths); len(again.Items) != 0 {
		t.Fatalf("курсор не сдвинут после принятого трафика: %+v", again.Items)
	}
	if got := gate.TakePendingParsed(); got != 5 {
		t.Fatalf("запас разобранных строк %d, ожидалось 5 — окно угроз не принято", got)
	}
	// В режиме отдельных ручек номер не выделяется.
	if reserveReportNumber(paths, true) != nil {
		t.Fatal("номер выделен в режиме отдельных ручек")
	}
}

// Сверка дрейфа в такте (ADR-0078): правка compose между тактами уезжает
// записью report.drift следующего такта, а после подтверждения очередь пуста
// и событие не повторяется.
func TestTickDriftSignalAckedOnce(t *testing.T) {
	var bodies []tickBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body tickBody
		if err := json.Unmarshal(raw, &body); err != nil || body.Report == nil {
			t.Errorf("тело такта без секции report: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		bodies = append(bodies, body)
		ack := agent.ReportAck{Epoch: body.Report.Epoch, Seq: body.Report.Seq, Drift: []agent.DriftKey{}}
		for _, item := range body.Report.Drift {
			ack.Drift = append(ack.Drift, agent.DriftKey{Epoch: item.Epoch, Seq: item.Seq, Idx: item.Idx})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"reportAck": ack})
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	queue := agent.LoadReportQueue(paths)
	gate := agent.NewReportGate()
	client := agent.NewClient(srv.URL, "test")
	id := testIdentity(t)
	legacy := false

	const compose = "services:\n  app:\n    image: nginx\n"
	const env = "APP_SLUG='shop-front'\n"
	app := agent.DesiredApp{Slug: "shop-front", Desired: "present", ReleaseID: "release-1", Compose: compose}
	apps := []agent.DesiredApp{app}
	dir := filepath.Join(paths.WorkDir, "apps", app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	composePath := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(compose), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	// Отметка — как после применения этой версией агента: хеши записанного.
	// Отпечаток нарочно не совпадает с желаемым — применение «в пути».
	applied := `{"apps":{"shop-front":{"release_id":"release-1","config_hash":"x","status":"healthy",` +
		`"compose_sha256":"` + hexSha256(compose) + `","env_sha256":"` + hexSha256(env) + `"}}}`
	if err := os.WriteFile(filepath.Join(paths.StateDir, "applied.json"), []byte(applied), 0o600); err != nil {
		t.Fatal(err)
	}

	tickOnce := func() *agent.ReportSection {
		t.Helper()
		number := reserveReportNumber(paths, false)
		observeDrift(paths, agent.ProxyOptions{}, apps, queue, number)
		var req agent.TickRequest
		attachReport(&req, queue, number)
		if _, err := exchange(t.Context(), client, id, req, tickDelivery{}, gate, queue, &legacy); err != nil {
			t.Fatalf("такт: %v", err)
		}
		return bodies[len(bodies)-1].Report
	}

	if first := tickOnce(); len(first.Drift) != 2 {
		t.Fatalf("первое наблюдение: %+v", first.Drift)
	}
	if quiet := tickOnce(); len(quiet.Drift) != 0 {
		t.Fatalf("без изменений уехали сигналы: %+v", quiet.Drift)
	}

	if err := os.WriteFile(composePath, []byte(compose+"    privileged: true\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	edited := tickOnce()
	if len(edited.Drift) != 1 {
		t.Fatalf("правка compose не уехала: %+v", edited.Drift)
	}
	item := edited.Drift[0]
	if item.Object != "compose" || item.Slug != app.Slug || item.Status != "mismatch" ||
		item.Disposition != "foreign_over_pending" || item.Seq != edited.Seq ||
		item.DiskSha == "" || item.ExpectedSha != hexSha256(compose) {
		t.Fatalf("запись правки: %+v", item)
	}

	left := agent.LoadReportQueue(paths).Section(agent.ReportNumber{Epoch: edited.Epoch, Seq: edited.Seq + 1})
	if len(left.Drift) != 0 {
		t.Fatalf("после подтверждения в очереди осталось %+v", left.Drift)
	}
	if again := tickOnce(); len(again.Drift) != 0 {
		t.Fatalf("событие правки повторилось: %+v", again.Drift)
	}
}

func hexSha256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Отметка гейта здоровья и списка развёрнутого — только по доставке
// (reportgate.go: «отметку ставит Mark ПОСЛЕ успешной отправки»). До правки
// отметка ставилась при сборке такта, и после неудачного такта оба отчёта
// придерживались до срока гейта — до пяти минут.
func TestFailedTickDoesNotMarkHealthAndPresence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	gate := agent.NewReportGate()
	legacy := false
	now := time.Now()

	req, delivery := gatedRequest(t, gate, now)
	if _, err := exchange(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), req,
		delivery, gate, agent.LoadReportQueue(paths), &legacy); err == nil {
		t.Fatal("502 не дошёл до вызывающего")
	}
	if !gate.Allow("health", "h1", now, agent.HealthReportMaxAge) {
		t.Fatal("здоровье отмечено доставленным после неудачного такта")
	}
	if !gate.Allow("presence", "p1", now, agent.PresenceReportMaxAge) {
		t.Fatal("список развёрнутого отмечен доставленным после неудачного такта")
	}
}

func TestDeliveredTickMarksHealthAndPresence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	gate := agent.NewReportGate()
	legacy := false
	now := time.Now()

	req, delivery := gatedRequest(t, gate, now)
	if _, err := exchange(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), req,
		delivery, gate, agent.LoadReportQueue(paths), &legacy); err != nil {
		t.Fatal(err)
	}
	if gate.Allow("health", "h1", now, agent.HealthReportMaxAge) {
		t.Fatal("доставленное здоровье не отмечено — отчёт уйдёт повторно без изменений")
	}
	if gate.Allow("presence", "p1", now, agent.PresenceReportMaxAge) {
		t.Fatal("доставленный список развёрнутого не отмечен")
	}
}

// Отдельные ручки: здоровье не принято, список принят — отмечается только
// принятое.
func TestLegacyMarksOnlyAcceptedHealthAndPresence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/deploy/agent/health" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	paths := agent.Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	gate := agent.NewReportGate()
	legacy := true
	now := time.Now()

	req, delivery := gatedRequest(t, gate, now)
	if _, err := exchange(t.Context(), agent.NewClient(srv.URL, "test"), testIdentity(t), req,
		delivery, gate, agent.LoadReportQueue(paths), &legacy); err != nil {
		t.Fatalf("состояние не получено: %v", err)
	}
	if !gate.Allow("health", "h1", now, agent.HealthReportMaxAge) {
		t.Fatal("непринятое здоровье отмечено доставленным")
	}
	if gate.Allow("presence", "p1", now, agent.PresenceReportMaxAge) {
		t.Fatal("принятый список развёрнутого не отмечен")
	}
}

// gatedRequest — такт с секциями здоровья и списка развёрнутого, собранный так
// же, как в tick: секция в запросе, отметка — в исходе доставки.
func gatedRequest(t *testing.T, gate *agent.ReportGate, now time.Time) (agent.TickRequest, tickDelivery) {
	t.Helper()
	if !gate.Allow("health", "h1", now, agent.HealthReportMaxAge) ||
		!gate.Allow("presence", "p1", now, agent.PresenceReportMaxAge) {
		t.Fatal("гейт закрыт до первой отправки")
	}
	req := agent.TickRequest{
		Health:   agent.HealthItems([]agent.AppHealth{{Slug: "shop", Status: "healthy"}}),
		Presence: agent.PresenceSection([]string{"shop"}),
	}
	delivery := tickDelivery{
		health:   &gateMark{hash: "h1", at: now},
		presence: &gateMark{hash: "p1", at: now},
	}
	return req, delivery
}
