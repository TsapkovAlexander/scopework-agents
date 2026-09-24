package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Очередь отчёта (ADR-0077, решения 2–3): квитанции недоставленных тактов и
// записи дрейфа, которые удаляются только по явному подтверждению платформы.

const testEpoch = "3f2a9c1e0b7d4e6fa1c2d3e4f5a6b7c8"

func queuePaths(t *testing.T) Paths {
	t.Helper()
	return Paths{StateDir: t.TempDir()}
}

func composeRecord(slug string) DriftRecord {
	return DriftRecord{
		Object:      "compose",
		Slug:        slug,
		Status:      "mismatch",
		Disposition: "foreign",
		ObservedAt:  time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC),
		DiskSha:     strings.Repeat("1", 64),
		ExpectedSha: strings.Repeat("2", 64),
	}
}

func num(seq int64) ReportNumber { return ReportNumber{Epoch: testEpoch, Seq: seq} }

func TestUndeliveredMergesNeighboursWithSameReason(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	q.NoteUndelivered(num(3), UndeliveredHTTP5xx)
	q.NoteUndelivered(num(4), UndeliveredHTTP5xx)
	q.NoteUndelivered(num(5), UndeliveredTimeout)
	q.NoteUndelivered(num(7), UndeliveredTimeout)

	got := q.Section(num(8)).Undelivered
	want := []UndeliveredRange{
		{From: 3, To: 4, Reason: UndeliveredHTTP5xx},
		{From: 5, To: 5, Reason: UndeliveredTimeout},
		{From: 7, To: 7, Reason: UndeliveredTimeout},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("диапазоны %+v, ожидалось %+v", got, want)
	}
}

// Переполнение не теряет номера: старейшие склеиваются, а причина честно
// становится «другое» — у склейки двух разных причин одной нет.
func TestUndeliveredOverflowMergesOldestAsOther(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	// Чередование причин не даёт соседям склеиться штатно.
	for seq := int64(1); seq <= MaxUndeliveredRanges+2; seq++ {
		reason := UndeliveredNetwork
		if seq%2 == 0 {
			reason = UndeliveredTimeout
		}
		q.NoteUndelivered(num(seq), reason)
	}

	got := q.Section(num(100)).Undelivered
	if len(got) != MaxUndeliveredRanges {
		t.Fatalf("диапазонов %d, ожидалось %d", len(got), MaxUndeliveredRanges)
	}
	if got[0] != (UndeliveredRange{From: 1, To: 3, Reason: UndeliveredOther}) {
		t.Fatalf("старейший диапазон %+v, ожидалась склейка 1–3 с причиной other", got[0])
	}
	if last := got[len(got)-1]; last.From != MaxUndeliveredRanges+2 || last.To != MaxUndeliveredRanges+2 {
		t.Fatalf("свежий диапазон потерян: %+v", last)
	}
}

// Квитанции прежней эпохи не относятся к новой: номер 5 в новой эпохе — это
// другой такт, и старый диапазон объяснял бы то, чего не было.
func TestUndeliveredDroppedOnEpochChange(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	q.NoteUndelivered(num(5), UndeliveredNetwork)

	other := ReportNumber{Epoch: strings.Repeat("a", 32), Seq: 6}
	if got := q.Section(other).Undelivered; len(got) != 0 {
		t.Fatalf("в новой эпохе уехали квитанции прежней: %+v", got)
	}
}

func TestEnqueueAssignsIdxAndStripsEnvHashes(t *testing.T) {
	p := queuePaths(t)
	q := LoadReportQueue(p)

	env := composeRecord("shop-front")
	env.Object = "env"
	caddy := composeRecord("")
	caddy.Object = "caddyfile"
	if err := q.Enqueue(testEpoch, 40, []DriftRecord{composeRecord("shop-front"), env, caddy}); err != nil {
		t.Fatal(err)
	}
	// Второй вызов в том же такте продолжает нумерацию: одинаковый ключ
	// платформа приняла бы за повтор и молча проглотила бы сигнал.
	if err := q.Enqueue(testEpoch, 40, []DriftRecord{composeRecord("git-blog")}); err != nil {
		t.Fatal(err)
	}

	drift := LoadReportQueue(p).Section(num(41)).Drift
	if len(drift) != 4 {
		t.Fatalf("записей %d, ожидалось 4: %+v", len(drift), drift)
	}
	for i, item := range drift {
		if item.Idx != i || item.Epoch != testEpoch || item.Seq != 40 {
			t.Fatalf("ключ записи %d: %+v", i, item)
		}
	}
	if drift[0].ObservedAt != "2026-09-17T10:00:00Z" {
		t.Fatalf("observedAt %q", drift[0].ObservedAt)
	}
	if drift[1].DiskSha != "" || drift[1].ExpectedSha != "" {
		t.Fatalf("у env остались хеши: %+v", drift[1])
	}
}

func TestEnqueueRejectsInvalidRecordsKeepsValid(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))

	noSlug := composeRecord("")
	badStatus := composeRecord("shop-front")
	badStatus.Status = "hacked"
	caddyWithSlug := composeRecord("shop-front")
	caddyWithSlug.Object = "caddyfile"
	shortSha := composeRecord("shop-front")
	shortSha.DiskSha = "abc"

	err := q.Enqueue(testEpoch, 5, []DriftRecord{noSlug, badStatus, composeRecord("shop-front"), caddyWithSlug, shortSha})
	if err == nil {
		t.Fatal("негодные записи прошли молча")
	}
	if drift := q.Section(num(6)).Drift; len(drift) != 1 || drift[0].Slug != "shop-front" {
		t.Fatalf("в очереди %+v, ожидалась одна годная запись", drift)
	}

	if err := q.Enqueue("XYZ", 5, []DriftRecord{composeRecord("shop-front")}); err == nil {
		t.Fatal("ключ с негодной эпохой принят")
	}
}

// Переполнение вытесняет старейшую запись, но не бесследно: платформа узнаёт,
// сколько и из каких тактов пропало.
func TestQueueEvictsOldestAndCountsDropped(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	// Короткая запись без хешей: предел по числу срабатывает раньше, чем по байтам.
	short := DriftRecord{Object: "caddyfile", Status: "no_baseline", ObservedAt: time.Now()}
	for seq := int64(1); seq <= ReportQueueMaxEntries+3; seq++ {
		if err := q.Enqueue(testEpoch, seq, []DriftRecord{short}); err != nil {
			t.Fatal(err)
		}
	}

	if n := len(q.state.Drift); n != ReportQueueMaxEntries {
		t.Fatalf("в очереди %d записей, предел %d", n, ReportQueueMaxEntries)
	}
	dropped := q.Section(num(1000)).QueueDropped
	if dropped == nil || *dropped != (QueueDropped{Count: 3, FromSeq: 1, ToSeq: 3}) {
		t.Fatalf("queueDropped %+v, ожидалось {3 1 3}", dropped)
	}
	if q.state.Drift[0].Seq != 4 {
		t.Fatalf("старейшая оставшаяся запись из такта %d, ожидался 4", q.state.Drift[0].Seq)
	}
}

func TestQueueEvictsByBytes(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	// Длинный slug и большой номер такта — запись около 340 байт: двести таких
	// перешагивают 64 КБ раньше, чем очередь упирается в число записей.
	long := composeRecord("s" + strings.Repeat("a", 38) + "z")
	const base = int64(9007199254740000)
	for i := int64(0); i < ReportQueueMaxEntries; i++ {
		if err := q.Enqueue(testEpoch, base+i, []DriftRecord{long}); err != nil {
			t.Fatal(err)
		}
	}
	kept := len(q.state.Drift)
	if kept >= ReportQueueMaxEntries {
		t.Fatalf("предел по байтам не сработал: %d записей, %d байт", kept, driftBytes(q.state.Drift))
	}
	if b := driftBytes(q.state.Drift); b > ReportQueueMaxBytes {
		t.Fatalf("очередь %d байт, предел %d", b, ReportQueueMaxBytes)
	}
	want := QueueDropped{Count: int64(ReportQueueMaxEntries - kept), FromSeq: base, ToSeq: base + int64(ReportQueueMaxEntries-kept) - 1}
	if q.state.Dropped == nil || *q.state.Dropped != want {
		t.Fatalf("вытеснение учтено как %+v, ожидалось %+v", q.state.Dropped, want)
	}
}

func TestSectionCapsDriftPerTickAndBytes(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	for seq := int64(1); seq <= 3; seq++ {
		batch := make([]DriftRecord, MaxDriftIdx+1)
		for i := range batch {
			batch[i] = composeRecord("shop-front")
		}
		if err := q.Enqueue(testEpoch, seq, batch); err != nil {
			t.Fatal(err)
		}
	}
	section := q.Section(num(10))
	if len(section.Drift) != MaxDriftPerTick {
		t.Fatalf("за такт %d записей, предел %d", len(section.Drift), MaxDriftPerTick)
	}

	// Предел по байтам — второй рубеж: и с самыми длинными годными записями
	// секция в него обязана укладываться.
	long := composeRecord("s" + strings.Repeat("a", 38) + "z")
	q2 := LoadReportQueue(queuePaths(t))
	for seq := int64(1); seq <= 3; seq++ {
		batch := make([]DriftRecord, MaxDriftIdx+1)
		for i := range batch {
			batch[i] = long
		}
		_ = q2.Enqueue(testEpoch, seq, batch)
	}
	raw, _ := json.Marshal(q2.Section(num(10)))
	if len(raw) > MaxReportSectionBytes {
		t.Fatalf("секция %d байт, предел %d", len(raw), MaxReportSectionBytes)
	}
}

// Удаляется только то, что платформа назвала, и только из отправленного.
// Ключ, которого в теле не было, — подделка или чужой ответ. Квитанции,
// уехавшие в подтверждённом теле, снимаются; вытеснение — только если
// платформа сказала, что записала его.
func TestDeliveredRemovesOnlyAckedSentItems(t *testing.T) {
	for name, recorded := range map[string]bool{
		"вытеснение записано":    true,
		"вытеснение не записано": false,
	} {
		t.Run(name, func(t *testing.T) {
			p := queuePaths(t)
			q := LoadReportQueue(p)
			_ = q.Enqueue(testEpoch, 1, []DriftRecord{composeRecord("a-app"), composeRecord("b-app")})
			q.NoteUndelivered(num(2), UndeliveredNetwork)
			q.state.Dropped = &QueueDropped{Count: 2, FromSeq: 1, ToSeq: 1}

			sent := q.Section(num(3))
			// Запись, поставленная после сборки секции, в теле не была.
			_ = q.Enqueue(testEpoch, 3, []DriftRecord{composeRecord("c-app")})

			q.Delivered(sent, &ReportAck{Epoch: testEpoch, Seq: 3, QueueDroppedRecorded: recorded, Drift: []DriftKey{
				{Epoch: testEpoch, Seq: 1, Idx: 0},
				{Epoch: testEpoch, Seq: 3, Idx: 0}, // не отправлялась
			}})

			left := LoadReportQueue(p)
			if len(left.state.Drift) != 2 || left.state.Drift[0].Slug != "b-app" || left.state.Drift[1].Slug != "c-app" {
				t.Fatalf("осталось %+v, ожидались b-app и c-app", left.state.Drift)
			}
			if len(left.state.Undelivered) != 0 {
				t.Fatalf("подтверждённые квитанции остались: %+v", left.state.Undelivered)
			}
			if recorded && left.state.Dropped != nil {
				t.Fatalf("записанное вытеснение осталось: %+v", left.state.Dropped)
			}
			if !recorded && (left.state.Dropped == nil || *left.state.Dropped != (QueueDropped{Count: 2, FromSeq: 1, ToSeq: 1})) {
				t.Fatalf("незаписанное вытеснение снято: %+v", left.state.Dropped)
			}
		})
	}
}

// Платформа могла отложить queue_dropped пределом такта и подтвердить сам
// такт. Без явного признака счётчик остаётся и уезжает следующим тактом —
// под новым номером, то есть новым ключом в журнале. Старая платформа поля не
// знает вовсе, негодный тип равен негодному подтверждению.
func TestDeliveredWithoutQueueDroppedRecordedKeepsCounter(t *testing.T) {
	for name, raw := range map[string]string{
		"поля нет": `{"epoch":"` + testEpoch + `","seq":3,"drift":[]}`,
		"false":    `{"epoch":"` + testEpoch + `","seq":3,"queueDroppedRecorded":false,"drift":[]}`,
		"строка":   `{"epoch":"` + testEpoch + `","seq":3,"queueDroppedRecorded":"true","drift":[]}`,
		"число":    `{"epoch":"` + testEpoch + `","seq":3,"queueDroppedRecorded":1,"drift":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := queuePaths(t)
			q := LoadReportQueue(p)
			q.state.Dropped = &QueueDropped{Count: 40, FromSeq: 1, ToSeq: 2}

			q.Delivered(q.Section(num(3)), ParseReportAck(json.RawMessage(raw)))

			left := LoadReportQueue(p)
			if left.state.Dropped == nil || *left.state.Dropped != (QueueDropped{Count: 40, FromSeq: 1, ToSeq: 2}) {
				t.Fatalf("вытеснение без подтверждения записи изменилось: %+v", left.state.Dropped)
			}
			if next := left.Section(num(4)).QueueDropped; next == nil || next.Count != 40 {
				t.Fatalf("следующий такт не везёт вытеснение: %+v", next)
			}
		})
	}
}

// Вытеснение, случившееся между сборкой секции и подтверждением, в теле не
// было: подтверждение снимает только отправленную часть.
func TestDeliveredRemovesOnlySentDroppedCount(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	q.state.Dropped = &QueueDropped{Count: 2, FromSeq: 1, ToSeq: 1}
	sent := q.Section(num(3))
	q.state.Dropped.Count += 5

	q.Delivered(sent, &ReportAck{Epoch: testEpoch, Seq: 3, QueueDroppedRecorded: true})

	if q.state.Dropped == nil || q.state.Dropped.Count != 5 {
		t.Fatalf("после подтверждения осталось %+v, ожидалось 5", q.state.Dropped)
	}
	if next := q.Section(num(4)).QueueDropped; next == nil || next.Count != 5 {
		t.Fatalf("следующий такт везёт %+v, ожидалось 5", next)
	}
}

// 2xx без подходящего reportAck: платформа старая или запись в базу не прошла
// (ADR-0077, р.3). Снять квитанции значило бы потерять их, а сам такт — тоже
// недоставленный: без квитанции на него следующий номер пришёл бы с
// необъяснённым пропуском и открыл инцидент, который закрывает только человек.
func TestDeliveredWithoutAckKeepsReceiptsAndExplainsSent(t *testing.T) {
	for name, ack := range map[string]*ReportAck{
		"нет ack":          nil,
		"ack чужого такта": {Epoch: testEpoch, Seq: 2},
		"ack чужой эпохи":  {Epoch: strings.Repeat("a", 32), Seq: 3},
	} {
		t.Run(name, func(t *testing.T) {
			p := queuePaths(t)
			q := LoadReportQueue(p)
			q.NoteUndelivered(num(2), UndeliveredNetwork)
			q.state.Dropped = &QueueDropped{Count: 2, FromSeq: 1, ToSeq: 1}

			sent := q.Section(num(3))
			q.Delivered(sent, ack)

			left := LoadReportQueue(p)
			if left.state.Dropped == nil || *left.state.Dropped != (QueueDropped{Count: 2, FromSeq: 1, ToSeq: 1}) {
				t.Fatalf("вытеснение без подтверждения изменилось: %+v", left.state.Dropped)
			}
			got := left.Section(num(4)).Undelivered
			want := []UndeliveredRange{
				{From: 2, To: 2, Reason: UndeliveredNetwork},
				{From: 3, To: 3, Reason: UndeliveredOther},
			}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("секция такта 4 объясняет %+v, ожидалось %+v", got, want)
			}
		})
	}
}

// Старая платформа не подтверждает никогда. Квитанции на каждый такт обязаны
// склеиваться в один диапазон, а не раздувать секцию до склейки переполнения.
func TestDeliveredWithoutAckEverKeepsOneRange(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	for seq := int64(1); seq <= 3*MaxUndeliveredRanges; seq++ {
		q.Delivered(q.Section(num(seq)), nil)
	}

	got := q.Section(num(3*MaxUndeliveredRanges + 1)).Undelivered
	want := []UndeliveredRange{{From: 1, To: 3 * MaxUndeliveredRanges, Reason: UndeliveredOther}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("квитанции %+v, ожидался один диапазон %+v", got, want)
	}
}

// Старая платформа или ошибка записи в базу: 2xx пришёл, подтверждения нет —
// записи дрейфа остаются до следующего такта.
func TestDeliveredWithoutAckKeepsDrift(t *testing.T) {
	q := LoadReportQueue(queuePaths(t))
	_ = q.Enqueue(testEpoch, 1, []DriftRecord{composeRecord("a-app")})
	sent := q.Section(num(2))

	q.Delivered(sent, nil)
	q.Delivered(sent, &ReportAck{Epoch: testEpoch, Seq: 99, Drift: []DriftKey{{Epoch: testEpoch, Seq: 1, Idx: 0}}})

	if len(q.state.Drift) != 1 {
		t.Fatalf("очередь без подтверждения изменилась: %+v", q.state.Drift)
	}
}

func TestParseReportAckIsTolerant(t *testing.T) {
	for _, raw := range []string{``, `null`, `"x"`, `{"epoch":1}`, `{"epoch":"XYZ","seq":1,"drift":[]}`} {
		if ack := ParseReportAck(json.RawMessage(raw)); ack != nil {
			t.Fatalf("из %q разобрано подтверждение %+v", raw, ack)
		}
	}
	ack := ParseReportAck(json.RawMessage(`{"epoch":"` + testEpoch + `","seq":3,"drift":[{"epoch":"` + testEpoch + `","seq":1,"idx":0}]}`))
	if ack == nil || ack.Seq != 3 || len(ack.Drift) != 1 {
		t.Fatalf("годное подтверждение не разобрано: %+v", ack)
	}
	if ack.QueueDroppedRecorded {
		t.Fatal("подтверждение без поля queueDroppedRecorded считается записавшим вытеснение")
	}
}

func TestLoadReportQueueSurvivesGarbage(t *testing.T) {
	p := queuePaths(t)
	if err := writeFileAtomic(p.reportQueuePath(), []byte(`{"drift":`), 0o600); err != nil {
		t.Fatal(err)
	}
	q := LoadReportQueue(p)
	if err := q.Enqueue(testEpoch, 1, []DriftRecord{composeRecord("a-app")}); err != nil {
		t.Fatal(err)
	}
	if len(LoadReportQueue(p).state.Drift) != 1 {
		t.Fatal("очередь не восстановилась после битого файла")
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestUndeliveredReasonForErrors(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&HTTPStatusError{Code: 500, Err: errors.New("сервер ответил 500")}, UndeliveredHTTP5xx},
		{&HTTPStatusError{Code: 429, Err: errors.New("429")}, UndeliveredHTTP4xx},
		{&HTTPStatusError{Code: http.StatusUnauthorized, Err: ErrUnauthorized}, UndeliveredUnauthorized},
		{&HTTPStatusError{Code: http.StatusForbidden, Err: errors.New("403")}, UndeliveredUnauthorized},
		{fmt.Errorf("такт: %w", ErrUnauthorized), UndeliveredUnauthorized},
		{context.DeadlineExceeded, UndeliveredTimeout},
		{&url.Error{Op: "Post", URL: "x", Err: timeoutErr{}}, UndeliveredTimeout},
		{&url.Error{Op: "Post", URL: "x", Err: &net.OpError{Op: "dial", Err: errors.New("refused")}}, UndeliveredNetwork},
		{errors.New("не удалось разобрать ответ"), UndeliveredOther},
	}
	for _, c := range cases {
		if got := UndeliveredReasonFor(c.err); got != c.want {
			t.Errorf("%v → %q, ожидалось %q", c.err, got, c.want)
		}
	}
}
