package agent

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Бюджет секции (ADR-0091, решение 9): жёсткие пределы, затем размер —
// min(256 КиБ, 736 КиБ − остальное тело). 413 роняет весь такт вместе с
// желаемым состоянием, а секцию сверх пределов платформа отвергает целиком.

var (
	contractHex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	contractImageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	contractReason  = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	contractKey     = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
)

// checkWorkloadsContract — пределы workloadsSectionSchema (workloads.ts),
// которые агент обязан соблюдать сам: платформа отвергнет секцию целиком.
func checkWorkloadsContract(t *testing.T, s *WorkloadsSection) {
	t.Helper()
	fail := func(format string, args ...any) { t.Helper(); t.Fatalf("контракт: "+format, args...) }
	str := func(what string, v *string, max int) {
		if v != nil && (*v == "" || len(*v) > max) {
			fail("%s %q", what, *v)
		}
	}
	metric := func(what string, v *int64) {
		if v != nil && (*v < 0 || *v > jsonSafeIntMax) {
			fail("%s %d", what, *v)
		}
	}
	ts := func(what, v string) time.Time {
		at, err := time.Parse(time.RFC3339Nano, v)
		if err != nil || !strings.HasSuffix(v, "Z") {
			fail("%s %q", what, v)
		}
		return at
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > WorkloadsMaxSectionBytes {
		fail("размер %d, %v", len(raw), err)
	}
	collected := ts("collected_at", s.CollectedAt)
	ts("since", s.Since)
	if s.Version != 1 || s.Containers == nil || s.Volumes == nil || s.Buckets == nil || s.Events == nil {
		fail("версия или null вместо массива")
	}
	if len(s.Containers) > 100 || len(s.Volumes) > 50 || len(s.Buckets) > 12 || len(s.Events) > 20 {
		fail("пределы числа элементов")
	}
	names := map[string]bool{}
	for _, c := range s.Containers {
		if names[c.Name] || !contractHex64.MatchString(c.ID) || c.Name == "" || len(c.Name) > 256 {
			fail("контейнер %q", c.Name)
		}
		names[c.Name] = true
		str("compose_project", c.ComposeProject, 128)
		str("compose_service", c.ComposeService, 128)
		str("health", c.Health, 32)
		str("image.ref", c.Image.Ref, 512)
		if c.State == "" || len(c.State) > 32 || c.RestartCount < 0 || c.OOMKilled == nil {
			fail("состояние %+v", c)
		}
		if c.ExitCode != nil && (*c.ExitCode < math.MinInt32 || *c.ExitCode > math.MaxInt32) {
			fail("exit_code")
		}
		for _, v := range []*string{c.StartedAt, c.FinishedAt} {
			if v != nil {
				ts("время контейнера", *v)
			}
		}
		img := c.Image
		if !slices.Contains([]string{"match", "mismatch", "unknown"}, img.Verdict) ||
			(img.ID != nil && !contractImageID.MatchString(*img.ID)) ||
			(img.BaselineID != nil && !contractImageID.MatchString(*img.BaselineID)) ||
			(img.Reason != nil && !contractReason.MatchString(*img.Reason)) ||
			(img.BaselineSource != nil && *img.BaselineSource != "apply" && *img.BaselineSource != "adopted") {
			fail("образ %+v", img)
		}
		cg := c.Cgroup
		if (cg.Status != "ok" && cg.Status != "unavailable") || (cg.Reason != nil && !contractReason.MatchString(*cg.Reason)) {
			fail("cgroup %+v", cg)
		}
		for _, v := range []*int64{cg.MemoryBytes, cg.MemoryMaxBytes, cg.OOMKills, cg.CPUUsageUsec, cg.CPUNrThrottled, cg.Pids} {
			metric("cgroup", v)
		}
		n := c.Network
		if (n.Status != "ok" && n.Status != "unavailable") || n.Peers == nil || len(n.Peers) > 32 ||
			(n.NetnsOwner != nil && !contractHex64.MatchString(*n.NetnsOwner)) {
			fail("сеть %+v", n)
		}
		for _, v := range []*int64{n.Established, n.Inbound, n.Outbound, n.External} {
			metric("сеть", v)
		}
		for _, p := range n.Peers {
			addr, err := netip.ParseAddr(p.Address)
			if err != nil || len(p.Address) > 45 || !netnsPeerIsInternal(addr.Unmap()) || p.Port < 0 || p.Port > 65535 ||
				(p.Direction != "in" && p.Direction != "out") || p.Count < 1 {
				fail("пир %+v", p)
			}
		}
	}
	names = map[string]bool{}
	for _, v := range s.Volumes {
		if names[v.Name] || v.Name == "" || len(v.Name) > 256 || v.Driver == "" || len(v.Driver) > 128 ||
			(v.Status != "ok" && v.Status != "unavailable") {
			fail("том %+v", v)
		}
		names[v.Name] = true
		str("compose_project тома", v.ComposeProject, 128)
		for _, m := range []*int64{v.FsTotalBytes, v.FsAvailBytes, v.FsUsedBytes} {
			metric("том", m)
		}
	}
	starts := map[string]bool{}
	for _, b := range s.Buckets {
		start := ts("start", b.Start)
		if starts[b.Start] || start.Unix()%300 != 0 || start.Add(300*time.Second).After(collected) ||
			b.Seconds != 300 || b.Samples < 1 || b.Samples > 10 || len(b.Containers) > 100 || len(b.Volumes) > 50 {
			fail("корзина %s", b.Start)
		}
		starts[b.Start] = true
		rows := map[string]bool{}
		for _, r := range b.Containers {
			if rows[r.Name] || r.Name == "" {
				fail("строка корзины %q", r.Name)
			}
			rows[r.Name] = true
			for _, m := range []*int64{r.MemAvgBytes, r.MemMaxBytes, r.CPUUsageUsec, r.CPUNrThrottled, r.OOMKills, r.PidsMax, r.ConnsMax, r.Restarts} {
				metric("корзина", m)
			}
		}
		rows = map[string]bool{}
		for _, r := range b.Volumes {
			if rows[r.Name] || r.Name == "" {
				fail("том корзины %q", r.Name)
			}
			rows[r.Name] = true
		}
	}
	for _, e := range s.Events {
		if !contractKey.MatchString(e.Key) || workloadEventOrder[e.Kind] == 0 && e.Kind != WorkloadEventRestarted ||
			e.Name == "" || len(e.Name) > 256 || len(e.At) < 10 || len(e.At) > 48 {
			fail("событие %+v", e)
		}
		ts("at", e.At)
		str("image события", e.Image, 512)
		str("image_id события", e.ImageID, 128)
		str("health события", e.Health, 32)
		if e.Restarts != nil && (*e.Restarts < 0 || *e.Restarts > 1_000_000) {
			fail("restarts события")
		}
	}
}

// budgetInput — хост из platform контейнеров стека orbita и других чужих,
// каждый с peers внутренними пирами; тома, корзины и события — по полной.
func budgetInput(platform, other, peers, volumes, buckets, events int) WorkloadSectionInput {
	at := testWorkloadStart.Add(time.Hour)
	in := WorkloadSectionInput{
		Sample: WorkloadSample{At: at}, Stacks: map[string]bool{"orbita": true},
		Images: map[string]WorkloadImageVerdict{}, Since: testWorkloadStart,
		DroppedBuckets: 3, DroppedEvents: 7,
	}
	big := i64(987_654_321_012)
	for i := 0; i < platform+other; i++ {
		project := "orbita"
		if i >= platform {
			project = "shop"
		}
		c := testRunning(i+1, project, fmt.Sprintf("service-with-a-rather-long-name-%03d", i))
		c.ImageRef = "registry.example.test/" + project + "/" + c.ComposeService + ":2026.09.23-build.4411-" + strings.Repeat("a", 24)
		c.Health = "healthy"
		c.RestartCount = 12345
		c.FinishedAt = "2026-09-23T10:02:18.911305123Z"
		c.Cgroup = CgroupStats{Status: "ok", MemoryBytes: big, MemoryMaxBytes: big, OOMKills: big, CPUUsageUsec: big, CPUNrThrottled: big, Pids: big}
		c.Net = NetStats{Status: "ok", Established: 99999, Inbound: 99999, Outbound: 99999, External: 99999, Peers: []TCPPeer{}}
		for p := 0; p < peers; p++ {
			c.Net.Peers = append(c.Net.Peers, TCPPeer{Address: fmt.Sprintf("fd12:3456:789a:1:ffff:ffff:ffff:%x", 0x1000+p),
				Port: 65000 + p, Direction: "out", Count: 999_999})
		}
		in.Sample.Containers = append(in.Sample.Containers, c)
		in.Images[c.ID] = WorkloadImageVerdict{Verdict: WorkloadVerdictMismatch, BaselineID: testWorkloadImage(9000 + i), BaselineSource: WorkloadBaselineApply}
	}
	for i := 0; i < volumes; i++ {
		project := "orbita"
		if i >= volumes/2 {
			project = "shop"
		}
		in.Sample.Volumes = append(in.Sample.Volumes, WorkloadObservedVolume{
			Name: fmt.Sprintf("%s_volume-with-a-rather-long-name-%03d", project, i), Driver: "local", ComposeProject: project,
			Fs: VolumeFsStats{Status: "ok", TotalBytes: big, AvailBytes: big, UsedBytes: big}})
	}
	for b := 0; b < buckets; b++ {
		bucket := WorkloadBucket{Start: workloadTimestamp(testWorkloadStart.Add(time.Duration(b*5) * time.Minute)),
			Seconds: 300, Samples: 5, Containers: []WorkloadBucketContainer{}, Volumes: []WorkloadBucketVolume{}}
		// Строк не больше, чем пропускает сама корзина при закрытии.
		for _, c := range in.Sample.Containers[:min(len(in.Sample.Containers), WorkloadsMaxContainers)] {
			bucket.Containers = append(bucket.Containers, WorkloadBucketContainer{Name: c.Name, MemAvgBytes: big, MemMaxBytes: big,
				CPUUsageUsec: big, CPUNrThrottled: big, OOMKills: big, PidsMax: big, ConnsMax: big, Restarts: big})
		}
		for _, v := range in.Sample.Volumes[:min(len(in.Sample.Volumes), WorkloadsMaxVolumes)] {
			bucket.Volumes = append(bucket.Volumes, WorkloadBucketVolume{Name: v.Name, UsedAvgBytes: big, UsedMaxBytes: big, TotalBytes: big})
		}
		in.Buckets = append(in.Buckets, bucket)
	}
	for e := 0; e < events; e++ {
		c := workloadBaselineContainer{ID: testWorkloadID(e + 1), Image: strings.Repeat("r", 120), ImageID: testWorkloadImage(e + 1),
			ComposeProject: "orbita", ComposeService: fmt.Sprintf("service-%03d", e)}
		prev := c
		prev.ID, prev.ImageID = testWorkloadID(e+500), testWorkloadImage(e+500)
		in.Events = append(in.Events, workloadMakeEvent(fmt.Sprintf("orbita-service-with-a-rather-long-name-%03d-1", e),
			WorkloadEventDeployed, c, &prev, 0, false, nil, at))
	}
	return in
}

func sectionBytes(t *testing.T, s *WorkloadsSection) int {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}

// Критерий 3 ADR-0091: 100 контейнеров с полными пирами, 50 томов, 12 корзин
// по 100 + 50 строк и 20 событий не выводят тело такта за 736 КиБ.
func TestWorkloadBudgetWorstCaseFits(t *testing.T) {
	in := budgetInput(50, 50, WorkloadsMaxPeers, WorkloadsMaxVolumes, WorkloadsMaxBuckets, WorkloadsMaxEvents)
	rest := 480 << 10
	s := BuildWorkloadsSection(in, rest)
	if s == nil {
		t.Fatal("секция не собрана")
	}
	checkWorkloadsContract(t, s)
	size := sectionBytes(t, s)
	if size > WorkloadsMaxSectionBytes || rest+len(`,"workloads":`)+size > WorkloadsMaxTickBodyBytes {
		t.Fatalf("секция %d байт, тело %d", size, rest+size)
	}
	// Отсечение ставит truncated; первыми уходят корзины и пиры, а не контейнеры.
	if !s.Truncated || len(s.Containers) != 100 || len(s.Volumes) != 50 || len(s.Events) != 20 || len(s.Buckets) < 1 {
		t.Fatalf("truncated %v, контейнеров %d, томов %d, событий %d, корзин %d",
			s.Truncated, len(s.Containers), len(s.Volumes), len(s.Events), len(s.Buckets))
	}
	if s.OmittedContainers != 0 || s.DroppedBuckets != 3 || s.DroppedEvents != 7 {
		t.Fatalf("счётчики: %d %d %d", s.OmittedContainers, s.DroppedBuckets, s.DroppedEvents)
	}
	if s.Buckets[0].Start != in.Buckets[0].Start {
		t.Fatal("уходят не старейшие корзины")
	}
	t.Logf("худший случай: %d байт, корзин %d, пиров на контейнер %d", size, len(s.Buckets), len(s.Containers[0].Network.Peers))
}

func TestWorkloadBudgetEverythingFits(t *testing.T) {
	in := budgetInput(3, 2, 4, 4, 3, 2)
	s := BuildWorkloadsSection(in, 1024)
	checkWorkloadsContract(t, s)
	if s.Truncated || s.OmittedContainers != 0 || len(s.Buckets) != 3 || len(s.Containers[0].Network.Peers) != 4 {
		t.Fatalf("влезающее отсечено: %+v", s)
	}
	// Платформенные — первыми.
	if !s.Containers[0].PlatformStack || s.Containers[len(s.Containers)-1].PlatformStack {
		t.Fatal("порядок: стеки платформы первыми")
	}
}

// Порядок отсечения на всём диапазоне бюджета: корзины (старейшая держится),
// пиры 32 → 8 → 0, последняя корзина, контейнеры вне стеков, тома вне стеков,
// стековые контейнеры, стековые тома, события.
func TestWorkloadBudgetCutOrder(t *testing.T) {
	in := budgetInput(10, 10, 20, 12, 5, 6)
	full := sectionBytes(t, BuildWorkloadsSection(in, 0))
	for budget := full; budget > 0; budget -= max(full/300, 1) {
		s := BuildWorkloadsSection(in, WorkloadsMaxTickBodyBytes-len(`,"workloads":`)-budget)
		if s == nil {
			if budget > 600 {
				t.Fatalf("бюджет %d: секции нет", budget)
			}
			continue
		}
		checkWorkloadsContract(t, s)
		if size := sectionBytes(t, s); size > budget {
			t.Fatalf("бюджет %d: секция %d", budget, size)
		}
		checkCutOrder(t, in, s, budget)
	}
}

func checkCutOrder(t *testing.T, in WorkloadSectionInput, s *WorkloadsSection, budget int) {
	t.Helper()
	var platformC, otherC, platformV, otherV int
	peers := 0
	peersCut := false
	for _, c := range s.Containers {
		if c.PlatformStack {
			platformC++
		} else {
			otherC++
		}
		peers = max(peers, len(c.Network.Peers))
		peersCut = peersCut || c.Network.PeersTruncated
	}
	for _, v := range s.Volumes {
		if v.PlatformStack {
			platformV++
		} else {
			otherV++
		}
	}
	containersCut := len(s.Containers) < 20
	volumesCut := len(s.Volumes) < 12
	fail := func(what string) {
		t.Helper()
		t.Fatalf("бюджет %d: %s (контейнеры %d+%d, тома %d+%d, пиры %d, корзин %d, событий %d)", budget, what, platformC, otherC, platformV, otherV, peers, len(s.Buckets), len(s.Events))
	}

	for i, b := range s.Buckets {
		if b.Start != in.Buckets[i].Start {
			fail("отправлены не старейшие корзины")
		}
	}
	// Старейшая корзина уступает только после пиров: иначе на хосте, где
	// текущие значения почти занимают бюджет, корзины не уходили бы никогда.
	if len(s.Buckets) == 0 && peers > 0 {
		fail("последняя корзина отложена раньше пиров")
	}
	if containersCut && peers != 0 {
		fail("контейнеры срезаны раньше пиров")
	}
	if otherC > 0 && platformC < 10 {
		fail("чужой контейнер пережил стековый")
	}
	if volumesCut && otherC > 0 {
		fail("том срезан раньше чужого контейнера")
	}
	if platformC < 10 && otherV > 0 {
		fail("стековый контейнер срезан раньше чужого тома")
	}
	if platformV < 6 && platformC > 0 {
		fail("стековый том срезан раньше стекового контейнера")
	}
	if len(s.Events) < 6 && (len(s.Containers) > 0 || len(s.Volumes) > 0) {
		fail("события срезаны раньше контейнеров и томов")
	}
	if s.OmittedContainers != int64(20-len(s.Containers)) || s.OmittedVolumes != int64(12-len(s.Volumes)) {
		fail("счётчики пропущенного")
	}
	if s.Truncated != (containersCut || volumesCut || peersCut) {
		fail("truncated не отражает отсечение")
	}
}

func TestWorkloadBudgetHardLimitsAndInvalidRows(t *testing.T) {
	in := budgetInput(20, 110, 0, 60, 0, 25)
	bad := in.Sample.Containers[0]
	bad.ID = "short"
	dup := in.Sample.Containers[1]
	dup.ID = testWorkloadID(7777)
	in.Sample.Containers = append(in.Sample.Containers, bad, dup)
	s := BuildWorkloadsSection(in, 0)
	checkWorkloadsContract(t, s)
	if len(s.Containers) != 100 || s.OmittedContainers != 32 || len(s.Volumes) != 50 || s.OmittedVolumes != 10 || !s.Truncated {
		t.Fatalf("контейнеров %d (пропущено %d), томов %d (пропущено %d)", len(s.Containers), s.OmittedContainers, len(s.Volumes), s.OmittedVolumes)
	}
	for _, c := range s.Containers[:20] {
		if !c.PlatformStack {
			t.Fatal("стековый контейнер вытеснен пределом 100")
		}
	}
	// Корзин и событий сверх предела секция не берёт, но и не теряет: они
	// ждут следующего такта в своих очередях, поэтому это не truncated.
	if len(s.Events) != 20 || s.Events[0].Key != in.Events[0].Key {
		t.Fatalf("событий %d", len(s.Events))
	}
	buckets := budgetInput(1, 0, 0, 0, 14, 0)
	buckets.Sample.At = testWorkloadStart.Add(2 * time.Hour)
	s = BuildWorkloadsSection(buckets, 0)
	checkWorkloadsContract(t, s)
	if len(s.Buckets) != 12 || s.Buckets[0].Start != buckets.Buckets[0].Start || s.Truncated {
		t.Fatalf("корзин %d, первая %s", len(s.Buckets), s.Buckets[0].Start)
	}
}

// Корзина, не закрытая к collected_at, заняла бы ключ неполной строкой.
func TestWorkloadBudgetSkipsBucketsNotClosedAtCollection(t *testing.T) {
	in := budgetInput(1, 0, 0, 0, 3, 0)
	in.Sample.At = testWorkloadStart.Add(12 * time.Minute) // закрыты 10:00 и 10:05, а 10:10 — нет
	s := BuildWorkloadsSection(in, 0)
	checkWorkloadsContract(t, s)
	if len(s.Buckets) != 2 {
		t.Fatalf("корзин %d", len(s.Buckets))
	}
}

func TestWorkloadBudgetTooSmallOrRestTooBig(t *testing.T) {
	in := budgetInput(1, 0, 0, 0, 0, 0)
	if s := BuildWorkloadsSection(in, WorkloadsMaxTickBodyBytes); s != nil {
		t.Fatal("тело уже в потолке — секции места нет")
	}
	if s := BuildWorkloadsSection(in, WorkloadsMaxTickBodyBytes-len(`,"workloads":`)-100); s != nil {
		t.Fatal("в 100 байт секция не помещается даже пустой")
	}
	// Пустой хост — не отказ: секция с пустыми массивами говорит «нагрузок нет».
	bare := WorkloadSectionInput{Sample: WorkloadSample{At: testWorkloadStart}, Since: testWorkloadStart}
	empty := BuildWorkloadsSection(bare, 0)
	checkWorkloadsContract(t, empty)
	if empty.Truncated || len(empty.Containers) != 0 {
		t.Fatalf("пустая секция: %+v", empty)
	}

	// Граница — байт в байт, вместе с ключом секции в теле: остальное тело,
	// ключ и секция вместе ровно 736 КиБ проходят, на байт больше — нет.
	size := sectionBytes(t, empty)
	rest := WorkloadsMaxTickBodyBytes - len(`,"workloads":`) - size
	if BuildWorkloadsSection(bare, rest) == nil {
		t.Fatal("секция ровно в бюджет не собрана")
	}
	if BuildWorkloadsSection(bare, rest+1) != nil {
		t.Fatal("тело такта вышло за 736 КиБ на байт")
	}
}
