package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// Очередь событий контейнеров в каталоге состояния агента (ADR-0091,
// решение 5).
//
// ОДИН ФАЙЛ НА ОЧЕРЕДЬ И БАЗОВУЮ ЛИНИЮ, одной атомарной записью. Базовая линия
// сдвигается после записи в очередь, а не после принятого такта: событие уже
// на диске и уйдёт с подтверждением. Раздельные файлы расходились бы на сбое
// между двумя записями — базовая линия сдвинута, а очередь нет (событие
// потеряно навсегда), либо наоборот. Одна запись даёт «оба или ни одного», и
// упавшая запись оставляет прежнюю линию: следующая сверка породит те же
// события с теми же ключами.
//
// Эпизоды нездоровья в файл не входят и живут в памяти: повтор упавшей
// записи в том же процессе берёт ту же отметку, а после перезапуска
// повторять нечего — упавшее событие не ушло никуда.

const (
	workloadEventQueueMaxEntries = 200
	workloadEventQueueMaxBytes   = 64 << 10
	workloadEventsFileVersion    = 1
	// Больше этого файл не читаем: штатно в нём до 512 контейнеров базовой
	// линии и 64 КиБ очереди, а раздутый файл на чужом сервере не должен
	// съесть память агента.
	workloadEventsMaxFileBytes = 1 << 20
)

// WorkloadEvents — сверка событий и их очередь. Безопасна для двух горутин:
// выборка сверяет, такт отдаёт и подтверждает.
type WorkloadEvents struct {
	mu       sync.Mutex
	path     string
	state    workloadEventsState
	saved    []byte // последнее записанное: неизменное состояние не пишется
	episodes map[string]workloadEpisode
	dropped  int64
}

type workloadEventsState struct {
	V int `json:"v"`
	// Baseline — nil: точки отсчёта ещё нет, первая сверка её поставит.
	Baseline *workloadEventsBaseline `json:"baseline"`
	Queue    []WorkloadEvent         `json:"queue"`
}

type workloadEventsBaseline struct {
	Containers map[string]workloadBaselineContainer `json:"containers"`
	Gone       map[string]workloadGoneContainer     `json:"gone"`
}

func workloadEventsPath(p Paths) string { return filepath.Join(p.StateDir, "workload-events.json") }

// LoadWorkloadEvents читает очередь и базовую линию. Битый, раздутый или
// чужой версии файл равносилен первому запуску: застрять на нечитаемом файле
// хуже, чем начать с точки отсчёта.
func LoadWorkloadEvents(p Paths) *WorkloadEvents {
	w := &WorkloadEvents{path: workloadEventsPath(p), episodes: map[string]workloadEpisode{}}
	raw, err := os.ReadFile(w.path)
	if err != nil || len(raw) > workloadEventsMaxFileBytes {
		return w
	}
	var state workloadEventsState
	if json.Unmarshal(raw, &state) != nil || state.V != workloadEventsFileVersion {
		return w
	}
	if state.Baseline != nil && state.Baseline.Containers == nil {
		state.Baseline = nil
	}
	state.Queue, _, w.dropped = workloadEnqueue(nil, state.Queue)
	w.state = state
	return w
}

// Reconcile сверяет полный список контейнеров выборки с базовой линией и
// ставит новые события в очередь. Зовётся на КАЖДУЮ выборку — плановую и
// внеочередную: классифицирует сверка, поток docker events только будит.
//
// Возвращает события, поставленные этой сверкой (для будильника такта —
// WorkloadHasProblemEvents). Ошибка — запись не удалась: ни очередь, ни
// базовая линия не сдвинулись.
func (w *WorkloadEvents) Reconcile(s WorkloadSample) ([]WorkloadEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	current := workloadSelectContainers(s.Containers)
	w.episodes = workloadUpdateEpisodes(w.episodes, current, s.At)

	next := workloadEventsState{
		V:        workloadEventsFileVersion,
		Baseline: &workloadEventsBaseline{Containers: current, Gone: map[string]workloadGoneContainer{}},
		Queue:    w.state.Queue,
	}
	var added []WorkloadEvent
	var evicted int64
	// Без базовой линии это точка отсчёта (ADR-0061, решение 3): иначе
	// установка агента на сервер с тридцатью контейнерами началась бы с
	// тридцати «новых сборок».
	if prev := w.state.Baseline; prev != nil {
		events, gone := workloadDiff(prev.Containers, prev.Gone, current, w.episodes, s.At)
		next.Baseline.Gone = gone
		next.Queue, added, evicted = workloadEnqueue(w.state.Queue, events)
	}
	if err := w.save(next); err != nil {
		return nil, err
	}
	w.state = next
	w.dropped += evicted
	return added, nil
}

// workloadEnqueue добавляет события в хвост очереди и вытесняет старейшие
// сверх 200 записей и 64 КиБ. Повтор ключа не добавляется: одно событие в
// очереди дважды платформа всё равно схлопнет, а место оно заняло бы.
// Исходный срез не меняется — очередь сдвигается только после записи.
func workloadEnqueue(queue, events []WorkloadEvent) (out, added []WorkloadEvent, evicted int64) {
	out = slices.Clone(queue)
	keys := make(map[string]bool, len(out)+len(events))
	for _, e := range out {
		keys[e.Key] = true
	}
	for _, e := range events {
		if keys[e.Key] {
			continue
		}
		keys[e.Key] = true
		out = append(out, e)
		added = append(added, e)
	}

	size := 0
	for _, e := range out {
		size += workloadEventBytes(e)
	}
	for len(out) > 0 && (len(out) > workloadEventQueueMaxEntries || size > workloadEventQueueMaxBytes) {
		size -= workloadEventBytes(out[0])
		out = out[1:]
		evicted++
	}
	if out == nil {
		out = []WorkloadEvent{}
	}
	return out, added, evicted
}

// workloadEventBytes — объём события так, как оно уйдёт в сеть.
func workloadEventBytes(e WorkloadEvent) int {
	raw, _ := json.Marshal(e)
	return len(raw)
}

// Pending — не больше 20 старейших событий очереди (решение 9).
func (w *WorkloadEvents) Pending() []WorkloadEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.state.Queue[:min(len(w.state.Queue), WorkloadsMaxEvents)])
}

// Acknowledge снимает ровно отправленные события (по ключу) — только после
// WorkloadsAccepted. В памяти подтверждение учитывается и при ошибке записи:
// на диске останутся лишние события, и после перезапуска они уйдут повтором,
// который платформа примет без второй строки.
func (w *WorkloadEvents) Acknowledge(sent []WorkloadEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	keys := make(map[string]bool, len(sent))
	for _, e := range sent {
		keys[e.Key] = true
	}
	w.state.Queue = slices.DeleteFunc(slices.Clone(w.state.Queue), func(e WorkloadEvent) bool { return keys[e.Key] })
	return w.save(w.state)
}

// Dropped — вытеснено с запуска процесса (dropped_events секции);
// подтверждение его не обнуляет.
func (w *WorkloadEvents) Dropped() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dropped
}

func (w *WorkloadEvents) save(state workloadEventsState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if bytes.Equal(raw, w.saved) {
		return nil
	}
	if err := writeFileAtomic(w.path, raw, 0o600); err != nil {
		return fmt.Errorf("очередь событий контейнеров не сохранена: %w", err)
	}
	w.saved = raw
	return nil
}
