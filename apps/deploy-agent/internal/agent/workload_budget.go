package agent

import (
	"cmp"
	"encoding/json"
	"slices"
	"time"
)

// Сборка секции workloads под бюджет (ADR-0091, решение 9).
//
// Сначала жёсткие пределы контракта — их платформа проверяет теми же числами
// и отвергает секцию целиком. Затем размер: секция не больше
// min(256 КиБ, 736 КиБ − остальное тело), потому что тело держится минимум на
// 32 КиБ ниже потолка 768 КиБ, а 413 роняет весь такт вместе с желаемым
// состоянием и выкатом.
//
// Порядок отсечения по размеру: лишние корзины откладываются (уходят
// старейшие), пиры 32 → 8 → 0, последняя корзина, контейнеры вне стеков
// платформы, тома вне стеков, стековые контейнеры, стековые тома и в самом
// конце события. Отложенные корзины и события не теряются — они ждут
// следующего такта в своих очередях.
//
// Старейшая корзина уступает место только после пиров (ADR-0091, решение 9 —
// порядок отсечения записан там). Отложи её раньше пиров — на хосте, где
// текущие значения почти занимают бюджет, корзины не уходили бы никогда и через час вытеснялись бы
// все до одной, а пиры — лишь текущее значение, которое следующий такт
// пришлёт заново.

// workloadSectionKeyBytes — во что обходится ключ секции в теле такта: остальное
// тело меряется без него.
const workloadSectionKeyBytes = len(`,"workloads":`)

var workloadPeerLevels = [...]int{WorkloadsMaxPeers, 8, 0}

// WorkloadSectionInput — всё, из чего собирается секция такта.
type WorkloadSectionInput struct {
	// Sample — последняя выборка, плановая или внеочередная: текущие значения
	// и collected_at.
	Sample WorkloadSample
	Stacks map[string]bool // WorkloadPlatformStacks
	// Images — WorkloadImages.Evaluate по этой же выборке; контейнер без
	// вердикта получает unknown с причиной.
	Images  map[string]WorkloadImageVerdict
	Since   time.Time        // WorkloadSeries.Since
	Buckets []WorkloadBucket // WorkloadSeries.Pending
	Events  []WorkloadEvent  // WorkloadEvents.Pending
	// DroppedBuckets и DroppedEvents — WorkloadSeries.DroppedBuckets и
	// WorkloadEvents.Dropped.
	DroppedBuckets, DroppedEvents int64
}

// BuildWorkloadsSection собирает секцию. restBodyBytes — длина тела такта без
// секции (json.Marshal того же TickRequest с Workloads == nil).
//
// nil — секция не помещается даже пустой: такт уходит без неё, и ничего из
// очередей не подтверждается. Подтверждать (WorkloadsAccepted) можно ровно
// то, что вернулось в секции: корзины и события сверх неё остаются ждать.
func BuildWorkloadsSection(in WorkloadSectionInput, restBodyBytes int) *WorkloadsSection {
	budget := min(WorkloadsMaxSectionBytes, WorkloadsMaxTickBodyBytes-restBodyBytes-workloadSectionKeyBytes)
	if budget <= 0 {
		return nil
	}
	p := newWorkloadPlan(in)
	fits := func() bool { return p.size() <= budget }

	for !fits() && p.nb > 1 {
		p.nb--
	}
	for !fits() && p.level < len(workloadPeerLevels)-1 {
		p.level++
	}
	if !fits() {
		p.nb = 0
	}
	for !fits() && p.nc > p.platformC {
		p.nc--
	}
	for !fits() && p.nv > p.platformV {
		p.nv--
	}
	for !fits() && p.nc > 0 {
		p.nc--
	}
	for !fits() && p.nv > 0 {
		p.nv--
	}
	for !fits() && p.ne > 0 {
		p.ne--
	}
	if !fits() {
		return nil
	}
	// Освободившееся после отсечения место — корзинам: они ждут в памяти, и
	// каждая неотправленная приближает вытеснение.
	for p.nb < len(p.buckets) {
		p.nb++
		if !fits() {
			p.nb--
			break
		}
	}

	s := p.section()
	// Размер считается по частям; итог сверяется целиком, потому что ошибка в
	// счёте стоила бы 413 всего такта.
	if raw, err := json.Marshal(s); err != nil || len(raw) > budget {
		return nil
	}
	return s
}

// workloadPlan — что войдёт в секцию: префиксы упорядоченных списков и
// уровень пиров. Размеры элементов посчитаны один раз: массив из n элементов
// в JSON — их сумма и n−1 запятая.
type workloadPlan struct {
	base       WorkloadsSection
	containers []WorkloadContainer
	volumes    []WorkloadVolume
	buckets    []WorkloadBucket
	events     []WorkloadEvent

	cSize                 [][len(workloadPeerLevels)]int
	vSize, bSize, eSize   []int
	platformC, platformV  int   // стековые — в начале списков
	omittedC, omittedV    int64 // отброшенное до бюджета
	level, nc, nv, nb, ne int
}

func newWorkloadPlan(in WorkloadSectionInput) *workloadPlan {
	p := &workloadPlan{base: WorkloadsSection{
		Version:        WorkloadsSectionVersion,
		Since:          workloadTimestamp(in.Since),
		CollectedAt:    workloadTimestamp(in.Sample.At),
		DroppedBuckets: max(in.DroppedBuckets, 0),
		DroppedEvents:  max(in.DroppedEvents, 0),
		Containers:     []WorkloadContainer{},
		Volumes:        []WorkloadVolume{},
		Buckets:        []WorkloadBucket{},
		Events:         []WorkloadEvent{},
	}}
	p.containers, p.platformC, p.omittedC = workloadCurrentContainers(in)
	p.volumes, p.platformV, p.omittedV = workloadCurrentVolumes(in)
	p.buckets = workloadClosedBuckets(in.Buckets, in.Sample.At)
	p.events = in.Events[:min(len(in.Events), WorkloadsMaxEvents)]

	p.cSize = make([][len(workloadPeerLevels)]int, len(p.containers))
	for i, c := range p.containers {
		for level, n := range workloadPeerLevels {
			p.cSize[i][level] = workloadJSONSize(workloadTrimPeers(c, n))
		}
	}
	p.vSize = workloadSizes(p.volumes)
	p.bSize = workloadSizes(p.buckets)
	p.eSize = workloadSizes(p.events)
	p.nc, p.nv, p.nb, p.ne = len(p.containers), len(p.volumes), len(p.buckets), len(p.events)
	return p
}

func workloadJSONSize(v any) int {
	raw, _ := json.Marshal(v)
	return len(raw)
}

func workloadSizes[T any](items []T) []int {
	sizes := make([]int, len(items))
	for i, item := range items {
		sizes[i] = workloadJSONSize(item)
	}
	return sizes
}

func workloadArrayBytes(sizes []int) int {
	total := max(len(sizes)-1, 0)
	for _, n := range sizes {
		total += n
	}
	return total
}

// truncation — поля отсечения: любой отброшенный контейнер или том и пиры,
// срезанные бюджетом. Отложенные корзины и события отсечением не считаются:
// они уйдут следующим тактом.
func (p *workloadPlan) truncation() (bool, int64, int64) {
	omittedC := p.omittedC + int64(len(p.containers)-p.nc)
	omittedV := p.omittedV + int64(len(p.volumes)-p.nv)
	peersCut := false
	for _, c := range p.containers[:p.nc] {
		if len(c.Network.Peers) > workloadPeerLevels[p.level] {
			peersCut = true
			break
		}
	}
	return omittedC > 0 || omittedV > 0 || peersCut, omittedC, omittedV
}

func (p *workloadPlan) size() int {
	skeleton := p.base
	skeleton.Truncated, skeleton.OmittedContainers, skeleton.OmittedVolumes = p.truncation()
	containers := make([]int, p.nc)
	for i := range containers {
		containers[i] = p.cSize[i][p.level]
	}
	// Пустые массивы уже в скелете как «[]»: добавляется только содержимое.
	return workloadJSONSize(skeleton) + workloadArrayBytes(containers) + workloadArrayBytes(p.vSize[:p.nv]) +
		workloadArrayBytes(p.bSize[:p.nb]) + workloadArrayBytes(p.eSize[:p.ne])
}

func (p *workloadPlan) section() *WorkloadsSection {
	s := p.base
	s.Truncated, s.OmittedContainers, s.OmittedVolumes = p.truncation()
	for _, c := range p.containers[:p.nc] {
		s.Containers = append(s.Containers, workloadTrimPeers(c, workloadPeerLevels[p.level]))
	}
	s.Volumes = append(s.Volumes, p.volumes[:p.nv]...)
	s.Buckets = append(s.Buckets, p.buckets[:p.nb]...)
	s.Events = append(s.Events, p.events[:p.ne]...)
	return &s
}

// workloadTrimPeers оставляет n пиров с наибольшим числом соединений:
// сборщик отдаёт их по убыванию.
func workloadTrimPeers(c WorkloadContainer, n int) WorkloadContainer {
	if len(c.Network.Peers) <= n {
		return c
	}
	c.Network.Peers = append([]WorkloadPeer{}, c.Network.Peers[:n]...)
	c.Network.PeersTruncated = true
	return c
}

// workloadFirst — true раньше false.
func workloadFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
}

func workloadUp(state string) bool {
	return state == "running" || state == "restarting" || state == "paused"
}

// workloadCurrentContainers — строки контейнеров в порядке важности: стеки
// платформы, работающие, compose-сервисы, по имени; отсечение идёт с хвоста.
// Негодная строка и повтор имени (платформа отвергла бы секцию) — в omitted.
func workloadCurrentContainers(in WorkloadSectionInput) ([]WorkloadContainer, int, int64) {
	var rows []WorkloadContainer
	var omitted int64
	seen := map[string]bool{}
	for _, c := range in.Sample.Containers {
		row, ok := workloadContainerRow(c, in.Stacks, in.Images[c.ID])
		if !ok || seen[row.Name] {
			omitted++
			continue
		}
		seen[row.Name] = true
		rows = append(rows, row)
	}
	slices.SortStableFunc(rows, func(a, b WorkloadContainer) int {
		return cmp.Or(workloadFirst(a.PlatformStack, b.PlatformStack), workloadFirst(workloadUp(a.State), workloadUp(b.State)),
			workloadFirst(a.ComposeService != nil, b.ComposeService != nil), cmp.Compare(a.Name, b.Name))
	})
	if len(rows) > WorkloadsMaxContainers {
		omitted += int64(len(rows) - WorkloadsMaxContainers)
		rows = rows[:WorkloadsMaxContainers]
	}
	platform := 0
	for _, r := range rows {
		if r.PlatformStack {
			platform++
		}
	}
	return rows, platform, omitted
}

func workloadCurrentVolumes(in WorkloadSectionInput) ([]WorkloadVolume, int, int64) {
	var rows []WorkloadVolume
	var omitted int64
	seen := map[string]bool{}
	for _, v := range in.Sample.Volumes {
		row, ok := workloadVolumeRow(v, in.Stacks)
		if !ok || seen[row.Name] {
			omitted++
			continue
		}
		seen[row.Name] = true
		rows = append(rows, row)
	}
	slices.SortStableFunc(rows, func(a, b WorkloadVolume) int {
		return cmp.Or(workloadFirst(a.PlatformStack, b.PlatformStack), cmp.Compare(a.Name, b.Name))
	})
	if len(rows) > WorkloadsMaxVolumes {
		omitted += int64(len(rows) - WorkloadsMaxVolumes)
		rows = rows[:WorkloadsMaxVolumes]
	}
	platform := 0
	for _, r := range rows {
		if r.PlatformStack {
			platform++
		}
	}
	return rows, platform, omitted
}

// workloadClosedBuckets — старейшие корзины, закрытые к collected_at. Корзина
// пишется на платформе один раз, и не закрытая к моменту выборки (часы ушли
// назад) заняла бы ключ неполной строкой; она подождёт.
func workloadClosedBuckets(buckets []WorkloadBucket, collectedAt time.Time) []WorkloadBucket {
	out := []WorkloadBucket{}
	seen := map[string]bool{}
	for _, b := range buckets {
		start, err := time.Parse(time.RFC3339Nano, b.Start)
		if err != nil || seen[b.Start] || start.Add(WorkloadsBucketSeconds*time.Second).After(collectedAt) {
			continue
		}
		seen[b.Start] = true
		out = append(out, b)
	}
	slices.SortStableFunc(out, func(a, b WorkloadBucket) int { return cmp.Compare(a.Start, b.Start) })
	return out[:min(len(out), WorkloadsMaxBuckets)]
}
