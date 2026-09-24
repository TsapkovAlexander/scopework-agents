package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// Очередь отчёта (ADR-0077, решения 2–3).
//
// ЧТО В НЕЙ, А ЧЕГО НЕТ. Периодический такт — снимок, а не событие: следующее
// тело его заменяет, и повторять устаревшие метрики незачем. Поэтому от
// неудачного такта остаётся только квитанция-диапазон «номера N–M не дошли,
// причина такая-то». Целиком лежат лишь незаменимые записи — сигналы дрейфа
// (ADR-0078): «файл на диске расходился с применённым» в 10:00 не восстановит
// ни один следующий такт, если к 10:05 файл вернули.
//
// Файл один — report-queue.json: квитанции, записи дрейфа и счётчик
// вытесненного живут и сбрасываются вместе, и два файла могли бы разойтись.

// Пределы секции и очереди. Совпадают с limits эталона
// packages/deploy-core/fixtures/tick-report.json — сверяет контрактный тест.
const (
	MaxUndeliveredRanges  = 32
	MaxDriftPerTick       = 50
	MaxDriftIdx           = 63
	MaxReportSectionBytes = 32 << 10
	ReportQueueMaxEntries = 200
	ReportQueueMaxBytes   = 64 << 10
)

// Причины недоставки.
const (
	UndeliveredNetwork      = "network"
	UndeliveredTimeout      = "timeout"
	UndeliveredHTTP4xx      = "http_4xx"
	UndeliveredHTTP5xx      = "http_5xx"
	UndeliveredUnauthorized = "unauthorized"
	UndeliveredOther        = "other"
)

var (
	undeliveredReasons = []string{
		UndeliveredNetwork, UndeliveredTimeout, UndeliveredHTTP4xx,
		UndeliveredHTTP5xx, UndeliveredUnauthorized, UndeliveredOther,
	}
	driftObjects      = []string{"compose", "env", "caddyfile"}
	driftStatuses     = []string{"match", "mismatch", "missing", "unreadable", "no_baseline"}
	driftDispositions = []string{"in_transit", "foreign", "foreign_over_pending"}

	driftSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
	driftShaPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// UndeliveredRange — номера from..to одной эпохи не дошли по одной причине.
type UndeliveredRange struct {
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	Reason string `json:"reason"`
}

// QueueDropped — сколько записей дрейфа вытеснено переполнением и из каких
// тактов. Вытеснение без следа превратило бы предел очереди в способ спрятать
// дрейф: достаточно нашуметь двумя сотнями безобидных сигналов.
type QueueDropped struct {
	Count   int64 `json:"count"`
	FromSeq int64 `json:"fromSeq"`
	ToSeq   int64 `json:"toSeq"`
}

// DriftItem — запись дрейфа в очереди и на проводе. Ключ {epoch, seq, idx} —
// такт, в котором сигнал возник, а не тот, которым он уехал: по нему платформа
// делает повтор идемпотентным.
type DriftItem struct {
	Epoch       string `json:"epoch"`
	Seq         int64  `json:"seq"`
	Idx         int    `json:"idx"`
	Object      string `json:"object"`
	Slug        string `json:"slug,omitempty"`
	Status      string `json:"status"`
	Disposition string `json:"disposition,omitempty"`
	ObservedAt  string `json:"observedAt"`
	DiskSha     string `json:"diskSha,omitempty"`
	ExpectedSha string `json:"expectedSha,omitempty"`
}

// DriftRecord — сигнал дрейфа без ключа: ключ назначает очередь.
type DriftRecord struct {
	Object      string
	Slug        string
	Status      string
	Disposition string
	ObservedAt  time.Time
	// DiskSha, ExpectedSha — только для compose и caddyfile. У env очередь их
	// снимает сама.
	DiskSha     string
	ExpectedSha string
}

// ReportSection — секция report тела такта.
type ReportSection struct {
	Epoch        string             `json:"epoch"`
	Seq          int64              `json:"seq"`
	Undelivered  []UndeliveredRange `json:"undelivered,omitempty"`
	QueueDropped *QueueDropped      `json:"queueDropped,omitempty"`
	Drift        []DriftItem        `json:"drift,omitempty"`
}

// DriftKey — ключ записи дрейфа в подтверждении.
type DriftKey struct {
	Epoch string `json:"epoch"`
	Seq   int64  `json:"seq"`
	Idx   int    `json:"idx"`
}

// ReportAck — подтверждение платформы: записи с этими ключами легли в базу.
//
// QueueDroppedRecorded — сигнал вытеснения ЭТОГО такта лёг в журнал. Отдельный
// признак, потому что платформа может отложить его пределом такта и всё равно
// подтвердить такт; без поля (старая платформа) он false, и счётчик остаётся.
type ReportAck struct {
	Epoch                string     `json:"epoch"`
	Seq                  int64      `json:"seq"`
	QueueDroppedRecorded bool       `json:"queueDroppedRecorded"`
	Drift                []DriftKey `json:"drift"`
}

// ParseReportAck разбирает подтверждение из ответа такта.
//
// Ответ платформы — недоверенный вход, и разбирается он отдельно от
// остального ответа: кривое поле подтверждения не должно ронять разбор
// желаемого состояния. Негодное подтверждение равносильно отсутствующему —
// очередь цела. Это касается и queueDroppedRecorded неверного типа: сводить
// его к false было бы доверием к ответу, который уже не соблюдает контракт.
func ParseReportAck(raw json.RawMessage) *ReportAck {
	if len(raw) == 0 {
		return nil
	}
	var ack ReportAck
	if json.Unmarshal(raw, &ack) != nil || !reportEpochPattern.MatchString(ack.Epoch) || ack.Seq < 1 {
		return nil
	}
	return &ack
}

// UndeliveredReasonFor — причина недоставки по ошибке отправки.
func UndeliveredReasonFor(err error) string {
	var status *HTTPStatusError
	var netErr net.Error
	switch {
	case errors.Is(err, ErrUnauthorized):
		return UndeliveredUnauthorized
	case errors.As(err, &status):
		switch {
		case status.Code == http.StatusUnauthorized || status.Code == http.StatusForbidden:
			return UndeliveredUnauthorized
		case status.Code >= 500:
			return UndeliveredHTTP5xx
		case status.Code >= 400:
			return UndeliveredHTTP4xx
		}
		return UndeliveredOther
	case errors.Is(err, context.DeadlineExceeded):
		return UndeliveredTimeout
	case errors.As(err, &netErr):
		if netErr.Timeout() {
			return UndeliveredTimeout
		}
		return UndeliveredNetwork
	}
	return UndeliveredOther
}

// ReportQueue — очередь отчёта на диске. Не потокобезопасна: живёт в основном
// цикле, как и ReportGate.
type ReportQueue struct {
	path  string
	state reportQueueState
}

type reportQueueState struct {
	// UndeliveredEpoch — эпоха, к которой относятся квитанции. Номер 5 новой
	// эпохи — другой такт, и квитанция прежней объясняла бы то, чего не было.
	UndeliveredEpoch string             `json:"undeliveredEpoch,omitempty"`
	Undelivered      []UndeliveredRange `json:"undelivered,omitempty"`
	Dropped          *QueueDropped      `json:"dropped,omitempty"`
	Drift            []DriftItem        `json:"drift,omitempty"`
}

// reportQueueMaxFileBytes — больше этого файл очереди не читаем: штатно он
// укладывается в 64 КБ записей и пару килобайт квитанций, а раздутый файл на
// чужом сервере не должен съесть память агента.
const reportQueueMaxFileBytes = 1 << 20

func (p Paths) reportQueuePath() string {
	return filepath.Join(p.StateDir, "report-queue.json")
}

// LoadReportQueue читает очередь с диска. Битый или раздутый файл равносилен
// пустой очереди: застрять навсегда на нечитаемом файле хуже, чем потерять
// его содержимое.
func LoadReportQueue(p Paths) *ReportQueue {
	q := &ReportQueue{path: p.reportQueuePath()}
	raw, err := os.ReadFile(q.path)
	if err != nil || len(raw) > reportQueueMaxFileBytes {
		return q
	}
	if json.Unmarshal(raw, &q.state) != nil {
		q.state = reportQueueState{}
		return q
	}
	if len(q.state.Undelivered) > MaxUndeliveredRanges {
		q.state.Undelivered = q.state.Undelivered[len(q.state.Undelivered)-MaxUndeliveredRanges:]
	}
	q.evict()
	return q
}

// Enqueue ставит в очередь сигналы дрейфа такта {epoch, seq}.
//
// idx назначается по порядку и продолжает уже стоящие записи того же такта:
// одинаковый ключ платформа приняла бы за повтор и молча проглотила бы второй
// сигнал. Негодная запись в очередь не попадает — платформа всё равно
// отбросила бы её, а годные соседи от неё не страдают; об отброшенных
// сообщает ошибка.
func (q *ReportQueue) Enqueue(epoch string, seq int64, items []DriftRecord) error {
	if !reportEpochPattern.MatchString(epoch) || seq < 1 || seq > MaxReportSeq {
		return fmt.Errorf("негодный ключ такта %q/%d", epoch, seq)
	}

	idx := 0
	for _, existing := range q.state.Drift {
		if existing.Epoch == epoch && existing.Seq == seq && existing.Idx >= idx {
			idx = existing.Idx + 1
		}
	}

	var rejected []error
	for _, r := range items {
		if idx > MaxDriftIdx {
			rejected = append(rejected, fmt.Errorf("больше %d записей за такт", MaxDriftIdx+1))
			break
		}
		item, err := driftItemFrom(epoch, seq, idx, r)
		if err != nil {
			rejected = append(rejected, err)
			continue
		}
		q.state.Drift = append(q.state.Drift, item)
		idx++
	}
	q.evict()

	if err := q.save(); err != nil {
		rejected = append(rejected, err)
	}
	return errors.Join(rejected...)
}

func driftItemFrom(epoch string, seq int64, idx int, r DriftRecord) (DriftItem, error) {
	item := DriftItem{
		Epoch:       epoch,
		Seq:         seq,
		Idx:         idx,
		Object:      r.Object,
		Slug:        r.Slug,
		Status:      r.Status,
		Disposition: r.Disposition,
		DiskSha:     r.DiskSha,
		ExpectedSha: r.ExpectedSha,
	}
	switch {
	case !slices.Contains(driftObjects, r.Object):
		return item, fmt.Errorf("дрейф: неизвестный объект %q", r.Object)
	case !slices.Contains(driftStatuses, r.Status):
		return item, fmt.Errorf("дрейф %s: неизвестный статус %q", r.Object, r.Status)
	case r.Disposition != "" && !slices.Contains(driftDispositions, r.Disposition):
		return item, fmt.Errorf("дрейф %s: неизвестное толкование %q", r.Object, r.Disposition)
	case r.ObservedAt.IsZero():
		return item, fmt.Errorf("дрейф %s: нет времени наблюдения", r.Object)
	}

	// У Caddyfile приложения нет — он один на хост; у compose и env без
	// приложения сигнал не к чему привязать.
	if r.Object == "caddyfile" {
		if r.Slug != "" {
			return item, errors.New("дрейф caddyfile: slug недопустим")
		}
	} else if !driftSlugPattern.MatchString(r.Slug) {
		return item, fmt.Errorf("дрейф %s: негодный slug", r.Object)
	}

	// Хеш файла переменных — проверяемый отпечаток секретов клиента: по нему
	// перебором сверяют догадку о значении. Наружу он не уходит никогда.
	if r.Object == "env" {
		item.DiskSha, item.ExpectedSha = "", ""
	}
	for _, sha := range []string{item.DiskSha, item.ExpectedSha} {
		if sha != "" && !driftShaPattern.MatchString(sha) {
			return item, fmt.Errorf("дрейф %s: негодный хеш", r.Object)
		}
	}

	item.ObservedAt = r.ObservedAt.UTC().Format(time.RFC3339)
	return item, nil
}

// NoteUndelivered оставляет квитанцию: номер n не дошёл по причине reason.
func (q *ReportQueue) NoteUndelivered(n ReportNumber, reason string) {
	if q.state.UndeliveredEpoch != n.Epoch {
		q.state.UndeliveredEpoch = n.Epoch
		q.state.Undelivered = nil
	}

	u := q.state.Undelivered
	if last := len(u) - 1; last >= 0 && u[last].Reason == reason && u[last].To+1 == n.Seq {
		u[last].To = n.Seq
	} else {
		u = append(u, UndeliveredRange{From: n.Seq, To: n.Seq, Reason: reason})
	}
	// Долгий обрыв с меняющимися причинами не должен раздувать секцию. Склейка
	// старейших сохраняет главное — какие номера не дошли, — а причина у
	// склейки разных причин одна честная: «другое».
	for len(u) > MaxUndeliveredRanges {
		merged := UndeliveredRange{From: u[0].From, To: u[1].To, Reason: UndeliveredOther}
		u = append([]UndeliveredRange{merged}, u[2:]...)
	}
	q.state.Undelivered = u
	q.saveOrLog()
}

// Section собирает секцию report для такта n: квитанции этой эпохи,
// накопленное вытеснение и старейшие записи дрейфа в пределах такта.
func (q *ReportQueue) Section(n ReportNumber) ReportSection {
	s := ReportSection{Epoch: n.Epoch, Seq: n.Seq}
	if q.state.UndeliveredEpoch == n.Epoch {
		for _, u := range q.state.Undelivered {
			if u.From >= 1 && u.From <= u.To && u.To < n.Seq {
				s.Undelivered = append(s.Undelivered, u)
			}
		}
	}
	if q.state.Dropped != nil {
		dropped := *q.state.Dropped
		s.QueueDropped = &dropped
	}
	for _, item := range q.state.Drift {
		if len(s.Drift) == MaxDriftPerTick {
			break
		}
		s.Drift = append(s.Drift, item)
		// Потолок тела такта общий для всех секций, и отчёт о дрейфе не должен
		// вытеснять из него здоровье и трафик.
		if raw, err := json.Marshal(s); err != nil || len(raw) > MaxReportSectionBytes {
			s.Drift = s.Drift[:len(s.Drift)-1]
			break
		}
	}
	return s
}

// Delivered — такт с секцией sent получил 2xx.
//
// Всё снимается только по подтверждению этого такта: ack отдаётся после
// записи в базу (ADR-0077, р.3). 2xx без него — старая платформа или сбой
// записи, и такт по сути не доставлен: квитанции и вытеснение остаются, а на
// сам такт заводится квитанция. Иначе следующий номер пришёл бы с
// необъяснённым пропуском. У старой платформы такие квитанции идут подряд с
// одной причиной и склеиваются в один диапазон.
//
// Квитанции, уехавшие в подтверждённом теле, снимаются сразу. Удерживать их
// незачем: они объясняют номера ниже курсора этого такта, и в следующем такте
// уже ничего не объяснят, а место под них в журнале резервирует сама платформа.
//
// Вытеснение — только по QueueDroppedRecorded: платформа могла отложить его
// пределом такта, и снятие по одному совпадению номера стёрло бы факт
// вытеснения везде. Неснятый счётчик уезжает следующим тактом под новым ключом.
// Снимается ровно отправленная часть: вытесненное после сборки секции в теле
// не было.
//
// Записи дрейфа — только из отправленных: ключ, которого в теле не было, —
// чужой или подделанный ответ.
func (q *ReportQueue) Delivered(sent ReportSection, ack *ReportAck) {
	if ack == nil || ack.Epoch != sent.Epoch || ack.Seq != sent.Seq {
		q.NoteUndelivered(ReportNumber{Epoch: sent.Epoch, Seq: sent.Seq}, UndeliveredOther)
		return
	}

	if q.state.UndeliveredEpoch == sent.Epoch {
		q.state.Undelivered = slices.DeleteFunc(q.state.Undelivered, func(u UndeliveredRange) bool {
			return slices.Contains(sent.Undelivered, u)
		})
	}
	if ack.QueueDroppedRecorded && sent.QueueDropped != nil && q.state.Dropped != nil {
		q.state.Dropped.Count -= sent.QueueDropped.Count
		if q.state.Dropped.Count <= 0 {
			q.state.Dropped = nil
		}
	}

	sentKeys := make(map[DriftKey]bool, len(sent.Drift))
	for _, item := range sent.Drift {
		sentKeys[DriftKey{Epoch: item.Epoch, Seq: item.Seq, Idx: item.Idx}] = true
	}
	acked := make(map[DriftKey]bool, len(sentKeys))
	// Разбор ограничен числом отправленного: больше ключей, чем было
	// записей в теле, честный ответ не содержит.
	for i, key := range ack.Drift {
		if i >= len(sent.Drift) {
			break
		}
		if sentKeys[key] {
			acked[key] = true
		}
	}
	q.state.Drift = slices.DeleteFunc(q.state.Drift, func(item DriftItem) bool {
		return acked[DriftKey{Epoch: item.Epoch, Seq: item.Seq, Idx: item.Idx}]
	})
	q.saveOrLog()
}

// evict вытесняет старейшие записи сверх пределов и учитывает вытесненное.
func (q *ReportQueue) evict() {
	size := driftBytes(q.state.Drift)
	for len(q.state.Drift) > 0 &&
		(len(q.state.Drift) > ReportQueueMaxEntries || size > ReportQueueMaxBytes) {
		oldest := q.state.Drift[0]
		q.state.Drift = q.state.Drift[1:]
		size -= driftBytes([]DriftItem{oldest})
		d := q.state.Dropped
		if d == nil {
			q.state.Dropped = &QueueDropped{Count: 1, FromSeq: oldest.Seq, ToSeq: oldest.Seq}
			continue
		}
		d.Count++
		d.FromSeq = min(d.FromSeq, oldest.Seq)
		d.ToSeq = max(d.ToSeq, oldest.Seq)
	}
}

// driftBytes — объём записей так, как они уйдут в сеть.
func driftBytes(items []DriftItem) int {
	total := 0
	for _, item := range items {
		raw, _ := json.Marshal(item)
		total += len(raw)
	}
	return total
}

func (q *ReportQueue) save() error {
	raw, err := json.Marshal(q.state)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(q.path, raw, 0o600); err != nil {
		return fmt.Errorf("очередь отчёта не сохранена: %w", err)
	}
	return nil
}

// saveOrLog — очередь в памяти остаётся верной и без диска; потеряется она
// только при рестарте, и молчать об этом нельзя.
func (q *ReportQueue) saveOrLog() {
	if err := q.save(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
