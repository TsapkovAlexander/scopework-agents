package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Отказ в задании по политике хоста (ADR-0095, п. 2). Без отчёта задание висит
// в pending навсегда, агент берёт его каждый такт, а человек смотрит на
// «выполняется…» без конца — та же грабля, на которой уже обожглись слепок
// стека и плановая копия (export.go).

type refusalReport struct {
	Path   string
	TaskID string         `json:"taskId"`
	Result map[string]any `json:"result"`
	Error  string         `json:"error"`
}

func refusalPlatform(t *testing.T, status int) (*Client, func() []refusalReport) {
	t.Helper()
	var mu sync.Mutex
	var got []refusalReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var rep refusalReport
		_ = json.Unmarshal(raw, &rep)
		rep.Path = r.URL.Path
		mu.Lock()
		got = append(got, rep)
		mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test"), func() []refusalReport {
		mu.Lock()
		defer mu.Unlock()
		return append([]refusalReport{}, got...)
	}
}

func testRefusalIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRefuseTaskReportsOnceAndMarks(t *testing.T) {
	cases := []struct {
		kind       string
		wantResult map[string]any
	}{
		// Копия и восстановление отчитываются своими функциями — теми же, что
		// у настоящего исхода, чтобы платформа закрыла задание тем же путём.
		{"backup", map[string]any{"set": "", "bytes": float64(0)}},
		{"restore", map[string]any{"set": "20260922-031500", "ms": float64(0)}},
		{"export", map[string]any{}},
		{"migrate-data", map[string]any{}},
		{"start-stack", map[string]any{}},
		{"stop-stack", map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			client, reports := refusalPlatform(t, http.StatusOK)
			p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
			task := HostTask{ID: "t-" + tc.kind, Kind: tc.kind, Project: "shop", BackupSet: "20260922-031500"}

			if err := RefuseTask(t.Context(), client, testRefusalIdentity(t), p, task, "режим наблюдения"); err != nil {
				t.Fatalf("отказ не доставлен: %v", err)
			}
			got := reports()
			if len(got) != 1 || got[0].Path != "/api/deploy/agent/migration" || got[0].TaskID != task.ID {
				t.Fatalf("отчёт об отказе: %+v", got)
			}
			if got[0].Error != "не исполнено: политика сервера — режим наблюдения" {
				t.Fatalf("текст отказа %q", got[0].Error)
			}
			for key, want := range tc.wantResult {
				if got[0].Result[key] != want {
					t.Fatalf("result[%s] = %v, ожидалось %v (%+v)", key, got[0].Result[key], want, got[0].Result)
				}
			}
			if len(got[0].Result) != len(tc.wantResult) {
				t.Fatalf("лишнее в result: %+v", got[0].Result)
			}

			raw, err := os.ReadFile(filepath.Join(p.StateDir, "task.json"))
			if err != nil || !strings.Contains(string(raw), `"task_id":"`+task.ID+`"`) {
				t.Fatalf("отметка task.json не записана: %s, %v", raw, err)
			}

			// Платформа приносит задание каждый такт, пока не примет отчёт:
			// второй отказ не шлёт ничего.
			if err := RefuseTask(t.Context(), client, testRefusalIdentity(t), p, task, "режим наблюдения"); err != nil {
				t.Fatal(err)
			}
			if n := len(reports()); n != 1 {
				t.Fatalf("повторный отказ отправлен ещё раз: запросов %d", n)
			}
		})
	}
}

// Отчёт не доехал — отметки нет, и следующий такт отчитается снова: иначе
// платформа так и не узнала бы, что задание не исполнено.
func TestRefuseTaskRetriesUndelivered(t *testing.T) {
	client, reports := refusalPlatform(t, http.StatusInternalServerError)
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	task := HostTask{ID: "t1", Kind: "backup", Project: "shop"}

	if err := RefuseTask(t.Context(), client, testRefusalIdentity(t), p, task, "режим наблюдения"); err == nil {
		t.Fatal("отказ платформы не дошёл до вызывающего")
	}
	if _, err := os.Stat(filepath.Join(p.StateDir, "task.json")); !os.IsNotExist(err) {
		t.Fatalf("отметка записана при недоставленном отчёте: %v", err)
	}
	_ = RefuseTask(t.Context(), client, testRefusalIdentity(t), p, task, "режим наблюдения")
	if n := len(reports()); n != 2 {
		t.Fatalf("повтор недоставленного отказа: запросов %d", n)
	}
}

// Неотправленный исход восстановления переживает отказ в другом задании —
// тем же правилом, что у RunTask.
func TestRefuseTaskKeepsUnreportedRestore(t *testing.T) {
	client, _ := refusalPlatform(t, http.StatusOK)
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	markPath := filepath.Join(p.StateDir, "task.json")
	pending := taskMark{TaskID: "old", Unreported: &unreportedRestore{TaskID: "r1", Set: "s", MS: 5}}
	if err := saveTaskMark(markPath, pending); err != nil {
		t.Fatal(err)
	}
	if err := RefuseTask(t.Context(), client, testRefusalIdentity(t), p,
		HostTask{ID: "t2", Kind: "backup"}, "режим наблюдения"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(markPath)
	var mark taskMark
	if err := json.Unmarshal(raw, &mark); err != nil || mark.TaskID != "t2" ||
		mark.Unreported == nil || mark.Unreported.TaskID != "r1" {
		t.Fatalf("отметка после отказа: %s", raw)
	}
}
