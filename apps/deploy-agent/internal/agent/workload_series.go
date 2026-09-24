package agent

import (
	"cmp"
	"slices"
	"sync"
	"time"
)

// Ряды нагрузок — пятиминутные корзины на хосте (ADR-0091, решение 2).
//
// Корзины живут только в памяти: ADR-0077 держит на диске квитанции и разовые
// наблюдения, а разрыв после перезапуска агента платформа видит по since и
// номерам тактов (альтернатива «л»). В корзину идут только плановые выборки
// раз в 60 с: внеочередные будит поток docker events, и контейнер в цикле
// перезапуска раздувал бы samples и тянул бы avg к моментам падений.

// workloadCounterMemory — сколько помнить счётчики пропавшего из выборки
// имени. Дольше двух корзин незачем: Docker не возвращает удалённый
// контейнер, а вернувшееся имя — это уже другой контейнер.
const workloadCounterMemory = 2 * WorkloadsBucketSeconds * time.Second

// WorkloadSeries — корзины процесса агента. Безопасна для двух горутин:
// выборка пишет, такт читает и подтверждает.
type WorkloadSeries struct {
	mu      sync.Mutex
	since   time.Time
	sampled bool // была плановая выборка: без неё дельте не от чего считаться
	open    *workloadOpenBucket
	closed  []WorkloadBucket // закрытые неподтверждённые, старейшая первой
	dropped int64
	last    map[string]workloadCounters // по имени контейнера
}

// workloadCounters — последние известные значения счётчиков по имени.
//
// run — id и время запуска: счётчики cgroup принадлежат группе запуска, и
// перезапуск того же контейнера начинает их с нуля. Перезапуски считает
// Docker на контейнер, им хватает id.
type workloadCounters struct {
	id, run             string
	cpu, throttled, oom *int64
	restarts            int64
	seen                time.Time
}

type workloadOpenBucket struct {
	start      time.Time
	samples    int
	containers map[string]*workloadContainerAcc
	volumes    map[string]*workloadVolumeAcc
}

type workloadContainerAcc struct {
	platform                      bool
	memSum, memN                  int64
	memMax, pidsMax, connsMax     *int64
	cpu, throttled, oom, restarts *int64 // суммы известных дельт
}

type workloadVolumeAcc struct {
	platform       bool
	usedSum, usedN int64
	usedMax, total *int64
}

// NewWorkloadSeries — ряды процесса, запущенного в since: он же поле since
// секции, от него накапливается dropped_buckets.
func NewWorkloadSeries(since time.Time) *WorkloadSeries {
	return &WorkloadSeries{since: since, last: map[string]workloadCounters{}}
}

func (s *WorkloadSeries) Since() time.Time { return s.since }

// workloadBucketStart — начало корзины: floor(t / 300) по эпохе UTC.
func workloadBucketStart(t time.Time) time.Time {
	sec := t.Unix()
	return time.Unix(sec-((sec%WorkloadsBucketSeconds)+WorkloadsBucketSeconds)%WorkloadsBucketSeconds, 0).UTC()
}

// AddPlanned добавляет плановую выборку. stacks — WorkloadPlatformStacks:
// строки стеков платформы при переполнении корзины остаются первыми.
//
// Выборка из следующей корзины закрывает текущую. Выборка из прошлой (часы
// ушли назад) пропускается целиком: второй корзины с тем же началом
// платформа не примет, а счётчики честно досчитают следующая выборка.
func (s *WorkloadSeries) AddPlanned(sample WorkloadSample, stacks map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	start := workloadBucketStart(sample.At)
	if s.open != nil && start.Before(s.open.start) {
		return
	}
	if s.open != nil && start.After(s.open.start) {
		s.closeOpen()
	}
	if s.open == nil {
		s.open = &workloadOpenBucket{start: start,
			containers: map[string]*workloadContainerAcc{}, volumes: map[string]*workloadVolumeAcc{}}
	}
	gauges := s.open.samples < workloadMaxBucketSamples
	if gauges {
		s.open.samples++
	}

	for _, c := range sample.Containers {
		acc := s.open.containers[c.Name]
		if acc == nil {
			acc = &workloadContainerAcc{}
			s.open.containers[c.Name] = acc
		}
		acc.platform = c.ComposeProject != "" && stacks[c.ComposeProject]
		s.addCounters(acc, c, sample.At)
		if gauges {
			acc.addGauges(c)
		}
	}
	for _, v := range sample.Volumes {
		acc := s.open.volumes[v.Name]
		if acc == nil {
			acc = &workloadVolumeAcc{}
			s.open.volumes[v.Name] = acc
		}
		acc.platform = v.ComposeProject != "" && stacks[v.ComposeProject]
		if gauges && v.Fs.Status == "ok" {
			acc.add(v.Fs)
		}
	}

	s.sampled = true
	for name, c := range s.last {
		if sample.At.Sub(c.seen) > workloadCounterMemory {
			delete(s.last, name)
		}
	}
}

// addCounters прибавляет дельты счётчиков контейнера c к корзине.
func (s *WorkloadSeries) addCounters(acc *workloadContainerAcc, c WorkloadObservedContainer, at time.Time) {
	prev, known := s.last[c.Name]
	run := c.ID + "|" + c.StartedAt
	sameRun := known && prev.run == run
	sameID := known && prev.id == c.ID

	restarts := int64(max(c.RestartCount, 0))
	next := workloadCounters{id: c.ID, run: run, restarts: restarts, seen: at,
		cpu: c.Cgroup.CPUUsageUsec, throttled: c.Cgroup.CPUNrThrottled, oom: c.Cgroup.OOMKills}
	// Значение, которое в этой выборке не прочиталось, помнится прежним: сбой
	// чтения не должен превращать следующий прирост в накопленное с запуска.
	if sameRun {
		next.cpu = cmp.Or(next.cpu, prev.cpu)
		next.throttled = cmp.Or(next.throttled, prev.throttled)
		next.oom = cmp.Or(next.oom, prev.oom)
	}
	s.last[c.Name] = next

	// Первая выборка процесса — точка отсчёта: накопленное контейнером до
	// старта агента за пять минут не случилось.
	if !s.sampled {
		return
	}
	acc.cpu = workloadAddDelta(acc.cpu, prev.cpu, c.Cgroup.CPUUsageUsec, sameRun)
	acc.throttled = workloadAddDelta(acc.throttled, prev.throttled, c.Cgroup.CPUNrThrottled, sameRun)
	acc.oom = workloadAddDelta(acc.oom, prev.oom, c.Cgroup.OOMKills, sameRun)
	acc.restarts = workloadAddDelta(acc.restarts, &prev.restarts, &restarts, sameID)
}

// workloadAddDelta прибавляет к sum прирост счётчика от prev до cur.
//
// Счётчик другого запуска или другого контейнера (same == false) начался с
// нуля, и его прирост — всё значение; так же читается сброс (cur < prev).
// Отрицательной дельты не бывает: пересоздание обнуляет счётчики, и минус
// был бы ложью (решение 2). Тот же счётчик без прежнего значения — прирост
// неизвестен, и выдумывать его нельзя.
func workloadAddDelta(sum, prev, cur *int64, same bool) *int64 {
	var d int64
	switch {
	case cur == nil:
		return sum
	case !same || (prev != nil && *cur < *prev):
		d = *cur
	case prev == nil:
		return sum
	default:
		d = *cur - *prev
	}
	total := d
	if sum != nil {
		total = min(*sum+d, jsonSafeIntMax)
	}
	return &total
}

func workloadMaxOf(cur *int64, v *int64) *int64 {
	if v == nil || (cur != nil && *cur >= *v) {
		return cur
	}
	n := *v
	return &n
}

func (acc *workloadContainerAcc) addGauges(c WorkloadObservedContainer) {
	if c.Cgroup.Status == "ok" && c.Cgroup.MemoryBytes != nil {
		acc.memSum += *c.Cgroup.MemoryBytes
		acc.memN++
		acc.memMax = workloadMaxOf(acc.memMax, c.Cgroup.MemoryBytes)
	}
	if c.Cgroup.Status == "ok" {
		acc.pidsMax = workloadMaxOf(acc.pidsMax, c.Cgroup.Pids)
	}
	if c.Net.Status == "ok" {
		acc.connsMax = workloadMaxOf(acc.connsMax, workloadCount(c.Net.Established))
	}
}

func (acc *workloadVolumeAcc) add(fs VolumeFsStats) {
	if fs.UsedBytes != nil {
		acc.usedSum += *fs.UsedBytes
		acc.usedN++
		acc.usedMax = workloadMaxOf(acc.usedMax, fs.UsedBytes)
	}
	if fs.TotalBytes != nil {
		total := *fs.TotalBytes
		acc.total = &total
	}
}

func workloadAvg(sum, n int64) *int64 {
	if n == 0 {
		return nil
	}
	avg := sum / n
	return workloadMetric(&avg)
}

// closeOpen закрывает текущую корзину: строки стеков платформы первыми, в
// пределах контракта, с пометкой усечения; сверх двенадцати в ожидании
// вытесняется старейшая.
func (s *WorkloadSeries) closeOpen() {
	o := s.open
	s.open = nil

	b := WorkloadBucket{Start: workloadTimestamp(o.start), Seconds: WorkloadsBucketSeconds, Samples: o.samples,
		Containers: []WorkloadBucketContainer{}, Volumes: []WorkloadBucketVolume{}}
	for _, name := range workloadRowOrder(o.containers, func(a *workloadContainerAcc) bool { return a.platform }) {
		if len(b.Containers) == WorkloadsMaxContainers {
			b.Truncated = true
			break
		}
		acc := o.containers[name]
		b.Containers = append(b.Containers, WorkloadBucketContainer{
			Name: name, MemAvgBytes: workloadAvg(acc.memSum, acc.memN), MemMaxBytes: workloadMetric(acc.memMax),
			CPUUsageUsec: acc.cpu, CPUNrThrottled: acc.throttled, OOMKills: acc.oom,
			PidsMax: workloadMetric(acc.pidsMax), ConnsMax: acc.connsMax, Restarts: acc.restarts,
		})
	}
	for _, name := range workloadRowOrder(o.volumes, func(a *workloadVolumeAcc) bool { return a.platform }) {
		if len(b.Volumes) == WorkloadsMaxVolumes {
			b.Truncated = true
			break
		}
		acc := o.volumes[name]
		b.Volumes = append(b.Volumes, WorkloadBucketVolume{Name: name, UsedAvgBytes: workloadAvg(acc.usedSum, acc.usedN),
			UsedMaxBytes: workloadMetric(acc.usedMax), TotalBytes: workloadMetric(acc.total)})
	}

	s.closed = append(s.closed, b)
	for len(s.closed) > WorkloadsMaxBuckets {
		s.closed = s.closed[1:]
		s.dropped++
	}
}

// workloadRowOrder — имена строк: стеки платформы первыми, внутри — по имени.
func workloadRowOrder[T any](rows map[string]T, platform func(T) bool) []string {
	names := make([]string, 0, len(rows))
	for name := range rows {
		if name != "" && len(name) <= workloadMaxNameBytes {
			names = append(names, name)
		}
	}
	slices.SortFunc(names, func(a, b string) int {
		if pa, pb := platform(rows[a]), platform(rows[b]); pa != pb {
			if pa {
				return -1
			}
			return 1
		}
		return cmp.Compare(a, b)
	})
	return names
}

// Pending — закрытые неподтверждённые корзины, старейшая первой. Незакрытая
// не отдаётся никогда: корзина пишется на платформе один раз, и неполная
// заняла бы её ключ.
func (s *WorkloadSeries) Pending() []WorkloadBucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.closed)
}

// Acknowledge снимает ровно отправленные корзины (по началу): закрытые, пока
// такт был в пути, остаются ждать своего.
func (s *WorkloadSeries) Acknowledge(sent []WorkloadBucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	starts := make(map[string]bool, len(sent))
	for _, b := range sent {
		starts[b.Start] = true
	}
	s.closed = slices.DeleteFunc(s.closed, func(b WorkloadBucket) bool { return starts[b.Start] })
}

// DroppedBuckets — вытеснено с запуска процесса; подтверждение его не
// обнуляет (контракт: счётчик накопительный с since).
func (s *WorkloadSeries) DroppedBuckets() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}
