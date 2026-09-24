package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Контракт секции report такта и подтверждения reportAck (ADR-0077, ADR-0078).
//
// Ту же фикстуру читает разбор платформы. Смысл тот же, что у
// desired_state_contract_test.go: поле, предел или причину добавили на одной
// стороне и забыли на другой — падает здесь, а не на хосте клиента молча
// отброшенной записью дрейфа.

type tickReportFixture struct {
	Limits struct {
		MaxSeq                int64 `json:"maxSeq"`
		MaxUndelivered        int   `json:"maxUndelivered"`
		MaxDriftPerTick       int   `json:"maxDriftPerTick"`
		MaxIdx                int   `json:"maxIdx"`
		MaxReportSectionBytes int   `json:"maxReportSectionBytes"`
		QueueMaxEntries       int   `json:"queueMaxEntries"`
		QueueMaxBytes         int   `json:"queueMaxBytes"`
	} `json:"limits"`
	Enums struct {
		UndeliveredReason []string `json:"undeliveredReason"`
		DriftObject       []string `json:"driftObject"`
		DriftStatus       []string `json:"driftStatus"`
		DriftDisposition  []string `json:"driftDisposition"`
	} `json:"enums"`
	Report    json.RawMessage `json:"report"`
	ReportAck json.RawMessage `json:"reportAck"`
}

func loadTickReportFixture(t *testing.T) tickReportFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..",
		"packages", "deploy-core", "fixtures", "tick-report.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не удалось прочитать эталон контракта: %v", err)
	}
	var fx tickReportFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("эталон не разбирается: %v", err)
	}
	return fx
}

// strictDecode — DisallowUnknownFields ради сценария, из-за которого фикстура
// заведена: поле добавили в разбор платформы и забыли в агенте.
func strictDecode(t *testing.T, raw []byte, out any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("эталон не разбирается структурами агента: %v", err)
	}
}

func TestTickReportFixtureParses(t *testing.T) {
	fx := loadTickReportFixture(t)

	var report ReportSection
	strictDecode(t, fx.Report, &report)
	if report.Seq != 42 || len(report.Undelivered) != 2 || report.QueueDropped == nil || len(report.Drift) != 4 {
		t.Fatalf("секция разобрана не целиком: %+v", report)
	}

	// Сериализация агентом — ровно эталон: omitempty там, где поле необязательно,
	// и ни одного лишнего имени.
	again, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	_ = json.Unmarshal(fx.Report, &want)
	_ = json.Unmarshal(again, &got)
	wantRaw, _ := json.Marshal(want)
	gotRaw, _ := json.Marshal(got)
	if !bytes.Equal(wantRaw, gotRaw) {
		t.Fatalf("агент пишет секцию иначе, чем эталон:\n%s\n%s", gotRaw, wantRaw)
	}

	var ack ReportAck
	strictDecode(t, fx.ReportAck, &ack)
	parsed := ParseReportAck(fx.ReportAck)
	if parsed == nil || len(parsed.Drift) != 4 {
		t.Fatalf("подтверждение эталона не принято агентом: %+v", parsed)
	}
	// Эталонный отчёт везёт queueDropped. Если признак записи не дошёл до
	// агента под своим именем, агент никогда не снимет счётчик вытеснения.
	if !parsed.QueueDroppedRecorded {
		t.Fatalf("queueDroppedRecorded эталона не разобран агентом: %+v", parsed)
	}
}

func TestTickReportFixtureLimitsMatchAgent(t *testing.T) {
	l := loadTickReportFixture(t).Limits
	checks := []struct {
		name         string
		fixture, go_ int64
	}{
		{"maxSeq", l.MaxSeq, MaxReportSeq},
		{"maxUndelivered", int64(l.MaxUndelivered), MaxUndeliveredRanges},
		{"maxDriftPerTick", int64(l.MaxDriftPerTick), MaxDriftPerTick},
		{"maxIdx", int64(l.MaxIdx), MaxDriftIdx},
		{"maxReportSectionBytes", int64(l.MaxReportSectionBytes), MaxReportSectionBytes},
		{"queueMaxEntries", int64(l.QueueMaxEntries), ReportQueueMaxEntries},
		{"queueMaxBytes", int64(l.QueueMaxBytes), ReportQueueMaxBytes},
	}
	for _, c := range checks {
		if c.fixture == 0 || c.fixture != c.go_ {
			t.Errorf("%s: эталон %d, агент %d", c.name, c.fixture, c.go_)
		}
	}
}

func TestTickReportFixtureEnumsMatchAgent(t *testing.T) {
	e := loadTickReportFixture(t).Enums
	pairs := []struct {
		name           string
		fixture, agent []string
	}{
		{"undeliveredReason", e.UndeliveredReason, undeliveredReasons},
		{"driftObject", e.DriftObject, driftObjects},
		{"driftStatus", e.DriftStatus, driftStatuses},
		{"driftDisposition", e.DriftDisposition, driftDispositions},
	}
	for _, p := range pairs {
		if len(p.fixture) == 0 || strings.Join(p.fixture, ",") != strings.Join(p.agent, ",") {
			t.Errorf("%s: эталон %v, агент %v", p.name, p.fixture, p.agent)
		}
	}
}

// У env хешей не бывает никогда: хеш файла переменных — это проверяемый
// отпечаток секретов клиента, и платформа отбрасывает такую запись целиком.
func TestDriftItemForEnvNeverCarriesHashes(t *testing.T) {
	q := LoadReportQueue(Paths{StateDir: t.TempDir()})
	err := q.Enqueue(testEpoch, 7, []DriftRecord{{
		Object:      "env",
		Slug:        "shop-front",
		Status:      "mismatch",
		Disposition: "foreign",
		ObservedAt:  time.Now(),
		DiskSha:     strings.Repeat("1", 64),
		ExpectedSha: strings.Repeat("2", 64),
	}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(q.Section(ReportNumber{Epoch: testEpoch, Seq: 8}).Drift)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("diskSha")) || bytes.Contains(raw, []byte("expectedSha")) {
		t.Fatalf("env уехал с хешами: %s", raw)
	}
}
