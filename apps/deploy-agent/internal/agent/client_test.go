package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Ответ на отметку о жизни — второй контракт с BFF после желаемого состояния,
// и единственный, у которого нет golden-фикстуры: он короткий и меняется редко.
// Но именно через него едет запрос осмотра (0210), а расхождение имён здесь
// выглядит как «кнопка нажата, сервер молчит» — без единой ошибки в журнале.
//
// Строка ниже — ровно то, что отдаёт apps/web/src/app/api/deploy/agent/heartbeat/route.ts.
func TestHeartbeatResponseContract(t *testing.T) {
	const fromBFF = `{
	  "hostId": "8f14e45f-ceea-467a-9e6f-1b2c3d4e5f60",
	  "targetAgentVersion": "9f20e78",
	  "targetAgentSha256": {"amd64": "aa", "arm64": "bb"},
	  "inventoryRequestedAt": "2026-08-07T09:15:00.000Z"
	}`

	var hb HeartbeatResponse
	if err := json.Unmarshal([]byte(fromBFF), &hb); err != nil {
		t.Fatalf("ответ платформы не разбирается: %v", err)
	}
	if hb.InventoryRequestedAt != "2026-08-07T09:15:00.000Z" {
		t.Fatalf("запрос осмотра не доехал: %q", hb.InventoryRequestedAt)
	}
	if hb.TargetAgentSha256.ForArch("amd64") != "aa" {
		t.Fatalf("суммы бинаря разобраны неверно: %+v", hb.TargetAgentSha256)
	}

	// Осмотра не просили — поле приходит пустой строкой, а не отсутствует:
	// агент сравнивает его с меткой выполненного осмотра, и null сломал бы
	// разбор всего ответа, то есть заодно и самообновление.
	var idle HeartbeatResponse
	if err := json.Unmarshal([]byte(`{"hostId":"x","inventoryRequestedAt":""}`), &idle); err != nil {
		t.Fatalf("ответ без запроса осмотра не разбирается: %v", err)
	}
	if idle.InventoryRequestedAt != "" {
		t.Fatalf("пустой запрос осмотра разобран как %q", idle.InventoryRequestedAt)
	}
}

// Отчёт о восстановлении — вторая половина контракта с deploy_report_host_task
// (0447): платформа читает `result->>'ms'` и кладёт число в
// deploy.app_restores.duration_ms. Разойдись имя поля — задание закрылось бы
// успехом, а журнал RTO остался бы пустым, и выяснилось бы это на первом же
// разборе аварии, когда цифра и нужна.
func TestReportRestoreCarriesSetAndDuration(t *testing.T) {
	var gotPath string
	var got struct {
		TaskID string `json:"taskId"`
		Result struct {
			Set string `json:"set"`
			MS  int64  `json:"ms"`
		} `json:"result"`
		Error string `json:"error"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("отчёт агента не разбирается: %v", err)
		}
		_, _ = w.Write([]byte(`{"accepted":true}`))
	}))
	defer srv.Close()

	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := NewClient(srv.URL, "test").ReportRestore(
		t.Context(), id, "task-1", "20260910-120000", 4321, "",
	); err != nil {
		t.Fatalf("отчёт не ушёл: %v", err)
	}

	// Ручка та же, что у переноса и копии: задание любого вида закрывает одна
	// RPC, и второй путь означал бы второе место, где оно может зависнуть.
	if gotPath != "/api/deploy/agent/migration" {
		t.Errorf("отчёт ушёл не туда: %s", gotPath)
	}
	if got.TaskID != "task-1" {
		t.Errorf("задание названо неверно: %q", got.TaskID)
	}
	if got.Result.Set != "20260910-120000" {
		t.Errorf("набор не доехал: %q", got.Result.Set)
	}
	if got.Result.MS != 4321 {
		t.Errorf("длительность не доехала: %d", got.Result.MS)
	}
	if got.Error != "" {
		t.Errorf("удача уехала с ошибкой: %q", got.Error)
	}
}

// Усечение окна угроз обязано доехать до флага отчёта, а не только до поля
// внутри окна: платформа пишет флаг отчёта в отдельную колонку снимка, и
// переполнение словаря пар без этого выглядело бы на панели полной выборкой.
func TestThreatSectionCarriesWindowTruncation(t *testing.T) {
	w := &ThreatWindow{Truncated: true}
	w.Totals.Parsed = 1

	if s := ThreatSection(w, false); s == nil || !s.Truncated {
		t.Fatalf("усечение окна потеряно в отчёте: %+v", s)
	}
	if s := ThreatSection(&ThreatWindow{Totals: w.Totals}, true); s == nil || !s.Truncated {
		t.Fatalf("усечение выборки лога потеряно в отчёте: %+v", s)
	}
}
