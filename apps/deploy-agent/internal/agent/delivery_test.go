package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Доставка = подтверждение (ADR-0077, решение 4). Курсоры журналов двигаются
// только после того, как платформа приняла окно: до этого неудачный такт
// съедал окно трафика и попытки подбора SSH без следа.

func readOrEmpty(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return raw
}

func TestTrafficWindowCursorsMoveOnlyOnCommit(t *testing.T) {
	p := trafficPaths(t)
	authLog := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(authLog, []byte("Aug  9 03:00:00 srv sshd[1]: Server listening\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := sshAuthLogPaths
	sshAuthLogPaths = []string{authLog}
	defer func() { sshAuthLogPaths = saved }()

	// Знакомство с журналами: курсоры встают, окно угроз ещё не отдаётся.
	appendLog(t, p, accessLine("a.example.com", "/", "1.1.1.1", 200, 1))
	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := CollectTraffic(p); err != nil {
		t.Fatal(err)
	}

	appendLog(t, p, accessLine("a.example.com", "/new", "1.1.1.1", 200, 1))
	f, err := os.OpenFile(authLog, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("Aug  9 03:00:05 srv sshd[2]: Failed password for root from 203.0.113.7 port 51240 ssh2\n")
	f.Close()

	trafficBefore := readOrEmpty(t, p.trafficCursorPath())
	sshBefore := readOrEmpty(t, p.sshAuthCursorPath())

	// Такт не доехал (500, обрыв): окно собрано, но не зафиксировано.
	lost, err := CollectTrafficWindow(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(lost.Items) != 1 || lost.Threat == nil || lost.Threat.Totals.AuthFailures == 0 {
		t.Fatalf("окно собрано неполным: %+v, угрозы %+v", lost.Items, lost.Threat)
	}
	if !bytes.Equal(readOrEmpty(t, p.trafficCursorPath()), trafficBefore) {
		t.Fatal("курсор трафика сдвинут до подтверждения")
	}
	if !bytes.Equal(readOrEmpty(t, p.sshAuthCursorPath()), sshBefore) {
		t.Fatal("курсор ssh-auth сдвинут до подтверждения")
	}

	// Следующий такт читает те же строки — и после подтверждения идёт дальше.
	retry, err := CollectTrafficWindow(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(retry.Items) != 1 || retry.Items[0].Requests != 1 ||
		retry.Threat == nil || retry.Threat.Totals.AuthFailures != lost.Threat.Totals.AuthFailures {
		t.Fatalf("повторный сбор не увидел тех же строк: %+v", retry)
	}
	retry.Commit()

	after, err := CollectTrafficWindow(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Items) != 0 || after.Threat != nil {
		t.Fatalf("после подтверждения окно прочитано повторно: %+v", after)
	}
}

// Ответ ручки такта: `accepted.traffic` — число или −1, `accepted.threat` —
// идентификатор снимка или null (apps/web/src/app/api/deploy/agent/tick/route.ts).
func TestTickResponseSectionsOutcome(t *testing.T) {
	req := TickRequest{
		Traffic: &trafficReportRequest{Items: []DomainTraffic{{Domain: "a.example.com"}}},
		Threat:  &threatReportRequest{},
	}
	cases := []struct {
		name            string
		body            string
		traffic, threat bool
	}{
		{"старая платформа без accepted", `{}`, true, true},
		{"обе приняты", `{"accepted":{"traffic":3,"threat":"8f14e45f"}}`, true, true},
		{"трафик отвергнут", `{"accepted":{"traffic":-1,"threat":"8f14e45f"}}`, false, true},
		{"угрозы отвергнуты", `{"accepted":{"traffic":0,"threat":null}}`, true, false},
		{"мусор вместо accepted", `{"accepted":"yes"}`, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var resp TickResponse
			if err := json.Unmarshal([]byte(c.body), &resp); err != nil {
				t.Fatalf("ответ не разбирается: %v", err)
			}
			got := resp.SectionsOutcome(req)
			if got.Traffic != c.traffic || got.Threat != c.threat {
				t.Fatalf("исход %+v, ожидалось трафик=%v угрозы=%v", got, c.traffic, c.threat)
			}
		})
	}

	// Неотправленная секция принятой не считается.
	var resp TickResponse
	if got := resp.SectionsOutcome(TickRequest{}); got.Traffic || got.Threat {
		t.Fatalf("неотправленные секции приняты: %+v", got)
	}
}

// Неразборчивое подтверждение не роняет такт: желаемое состояние едет тем же
// ответом, и его потеря из-за поля отчёта остановила бы выкаты.
func TestTickResponseToleratesBrokenReportFields(t *testing.T) {
	var resp TickResponse
	body := `{"nextPollSeconds":5,"accepted":[1,2],"reportAck":"garbage"}`
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("такт упал на поле отчёта: %v", err)
	}
	if resp.NextPollSeconds != 5 || ParseReportAck(resp.ReportAck) != nil {
		t.Fatalf("разобрано %+v", resp)
	}
}

func TestWindowDelivered(t *testing.T) {
	traffic := &trafficReportRequest{}
	threat := &threatReportRequest{}
	cases := []struct {
		name    string
		req     TickRequest
		outcome TickSectionsOutcome
		want    bool
	}{
		{"окно не отправлялось", TickRequest{}, TickSectionsOutcome{}, true},
		{"трафик принят, угрозы нет", TickRequest{Traffic: traffic, Threat: threat}, TickSectionsOutcome{Traffic: true}, true},
		{"угрозы приняты, трафик нет", TickRequest{Traffic: traffic, Threat: threat}, TickSectionsOutcome{Threat: true}, true},
		{"ничего не принято", TickRequest{Traffic: traffic, Threat: threat}, TickSectionsOutcome{}, false},
	}
	for _, c := range cases {
		if got := c.outcome.WindowDelivered(c.req); got != c.want {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

// Режим отдельных ручек: частичный успех секций виден вызывающему по секции.
func TestReportTickSectionsOutcomePerSection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/deploy/agent/threats" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	req := TickRequest{
		Traffic: &trafficReportRequest{Items: []DomainTraffic{{Domain: "a.example.com"}}},
		Threat:  &threatReportRequest{},
	}
	outcome, err := NewClient(srv.URL, "test").ReportTickSections(t.Context(), id, req)
	if err == nil {
		t.Fatal("отказ ручки угроз не дошёл до вызывающего")
	}
	if !outcome.Traffic || outcome.Threat {
		t.Fatalf("исход %+v, ожидалось трафик принят, угрозы нет", outcome)
	}
	if !outcome.WindowDelivered(req) {
		t.Fatal("окно с принятым трафиком не считается доставленным — курсор встанет")
	}
}
