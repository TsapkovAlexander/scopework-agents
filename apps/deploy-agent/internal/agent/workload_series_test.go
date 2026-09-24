package agent

import (
	"fmt"
	"testing"
	"time"
)

// Пятиминутные корзины (ADR-0091, решение 2): выравнивание по UTC, avg и max
// для gauge, дельты счётчиков без отрицательных значений, двенадцать корзин
// в ожидании и снятие ровно подтверждённых.

func minute(n int) time.Time { return testWorkloadStart.Add(time.Duration(n) * time.Minute) }

// withCounters — контейнер с заданными счётчиками cgroup и перезапусков.
func withCounters(c WorkloadObservedContainer, cpu int64, restarts int) WorkloadObservedContainer {
	c.Cgroup.CPUUsageUsec = i64(cpu)
	c.RestartCount = restarts
	return c
}

// closeWith закрывает текущую корзину выборкой из следующей.
func onlyBucket(t *testing.T, s *WorkloadSeries) WorkloadBucket {
	t.Helper()
	pending := s.Pending()
	if len(pending) != 1 {
		t.Fatalf("закрытых корзин %d, ожидалась одна", len(pending))
	}
	return pending[0]
}

func bucketRow(t *testing.T, b WorkloadBucket, name string) WorkloadBucketContainer {
	t.Helper()
	for _, row := range b.Containers {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("в корзине %s нет строки %s", b.Start, name)
	return WorkloadBucketContainer{}
}

func TestWorkloadBucketStartAlignsToUTC(t *testing.T) {
	local := time.FixedZone("UTC+7", 7*3600)
	cases := map[time.Time]string{
		time.Date(2026, 9, 23, 17, 4, 59, 999999999, local): "2026-09-23T10:00:00Z",
		time.Date(2026, 9, 23, 10, 5, 0, 0, time.UTC):       "2026-09-23T10:05:00Z",
		time.Date(2026, 9, 23, 10, 7, 30, 0, time.UTC):      "2026-09-23T10:05:00Z",
		// Пояс с получасом: выравнивание — по эпохе UTC, а не по местным часам.
		time.Date(2026, 9, 23, 15, 42, 0, 0, time.FixedZone("UTC+5:30", 5*3600+1800)): "2026-09-23T10:10:00Z",
	}
	for at, want := range cases {
		if got := workloadTimestamp(workloadBucketStart(at)); got != want {
			t.Errorf("%v: %s, ожидалось %s", at, got, want)
		}
	}
}

func TestWorkloadSeriesAvgAndMax(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	for i, mem := range []int64{100, 200, 300, 400, 500} {
		c := testRunning(1, "orbita", "web")
		c.Cgroup.MemoryBytes = i64(mem)
		c.Cgroup.Pids = i64(int64(10 + i))
		c.Net.Established = 7 - i
		total, used := int64(1000), int64(100*(i+1))
		s.AddPlanned(WorkloadSample{At: minute(i), Containers: []WorkloadObservedContainer{c},
			Volumes: []WorkloadObservedVolume{{Name: "orbita_pgdata", Driver: "local", ComposeProject: "orbita",
				Fs: VolumeFsStats{Status: "ok", TotalBytes: &total, UsedBytes: &used}}}}, nil)
	}
	if len(s.Pending()) != 0 {
		t.Fatal("незакрытая корзина не отдаётся: она заняла бы ключ неполной строкой")
	}
	s.AddPlanned(testWorkloadSample(minute(5), testRunning(1, "orbita", "web")), nil)

	b := onlyBucket(t, s)
	if b.Start != "2026-09-23T10:00:00Z" || b.Seconds != 300 || b.Samples != 5 || b.Truncated {
		t.Fatalf("корзина: %+v", b)
	}
	row := bucketRow(t, b, "orbita-web-1")
	if *row.MemAvgBytes != 300 || *row.MemMaxBytes != 500 || *row.PidsMax != 14 || *row.ConnsMax != 7 {
		t.Fatalf("gauge: avg %d max %d pids %d conns %d", *row.MemAvgBytes, *row.MemMaxBytes, *row.PidsMax, *row.ConnsMax)
	}
	vol := b.Volumes[0]
	if vol.Name != "orbita_pgdata" || *vol.UsedAvgBytes != 300 || *vol.UsedMaxBytes != 500 || *vol.TotalBytes != 1000 {
		t.Fatalf("том: %+v", vol)
	}
}

func TestWorkloadSeriesUnavailableGaugesAreNull(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	c := testRunning(1, "", "legacy-cron")
	c.Cgroup = cgroupUnavailable("cgroup_v1")
	c.Net = netnsUnavailable("host_network")
	s.AddPlanned(testWorkloadSample(minute(0), c), nil)
	s.AddPlanned(testWorkloadSample(minute(1), c), nil)
	s.AddPlanned(testWorkloadSample(minute(5), c), nil)

	row := bucketRow(t, onlyBucket(t, s), "legacy-cron")
	if row.MemAvgBytes != nil || row.CPUUsageUsec != nil || row.ConnsMax != nil || row.PidsMax != nil {
		t.Fatalf("«нет данных» обязано быть null, а не нулём: %+v", row)
	}
	// Перезапуски читаются из inspect и без cgroup: вторая выборка дала дельту 0.
	if row.Restarts == nil || *row.Restarts != 0 {
		t.Fatalf("перезапуски: %v", row.Restarts)
	}
}

// Сброс счётчика (новое < старого) считается от нуля нового счётчика:
// отрицательная дельта была бы ложью. Первая выборка процесса — точка отсчёта.
func TestWorkloadSeriesDeltaOnCounterReset(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	base := testRunning(1, "orbita", "web")
	for i, step := range []struct {
		cpu      int64
		restarts int
	}{{1000, 0}, {1500, 1}, {200, 1}, {300, 0}, {350, 2}} {
		s.AddPlanned(testWorkloadSample(minute(i), withCounters(base, step.cpu, step.restarts)), nil)
	}
	s.AddPlanned(testWorkloadSample(minute(5), base), nil)

	row := bucketRow(t, onlyBucket(t, s), "orbita-web-1")
	// +500, сброс → +200, +100, +50.
	if *row.CPUUsageUsec != 850 {
		t.Fatalf("cpu за корзину %d, ожидалось 850", *row.CPUUsageUsec)
	}
	// +1, 0, ручной restart обнулил счётчик → 0, +2.
	if *row.Restarts != 3 {
		t.Fatalf("перезапуски за корзину %d, ожидалось 3", *row.Restarts)
	}
}

// Пересоздание обнуляет счётчики: у нового id дельта — его значение целиком,
// даже если оно больше прежнего.
func TestWorkloadSeriesDeltaOnIDChange(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	old := withCounters(testRunning(1, "orbita", "web"), 1500, 7)
	s.AddPlanned(testWorkloadSample(minute(0), old), nil)
	s.AddPlanned(testWorkloadSample(minute(1), withCounters(old, 1600, 7)), nil)

	recreated := withCounters(testRunning(2, "orbita", "web"), 5000, 0)
	s.AddPlanned(testWorkloadSample(minute(2), recreated), nil)
	s.AddPlanned(testWorkloadSample(minute(5), recreated), nil)

	row := bucketRow(t, onlyBucket(t, s), "orbita-web-1")
	if *row.CPUUsageUsec != 100+5000 {
		t.Fatalf("cpu %d, ожидалось 5100 (а не 100 + 3400)", *row.CPUUsageUsec)
	}
	if *row.Restarts != 0 {
		t.Fatalf("перезапуски %d: новый контейнер начинает с нуля, а не с −7", *row.Restarts)
	}
}

// Перезапуск того же контейнера — новая группа cgroup, её счётчики с нуля.
func TestWorkloadSeriesDeltaOnRestartSameID(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	c := withCounters(testRunning(1, "orbita", "web"), 1500, 0)
	s.AddPlanned(testWorkloadSample(minute(0), c), nil)
	c = withCounters(c, 1600, 1)
	c.StartedAt = "2026-09-23T10:00:30Z"
	s.AddPlanned(testWorkloadSample(minute(1), c), nil)
	s.AddPlanned(testWorkloadSample(minute(5), c), nil)

	row := bucketRow(t, onlyBucket(t, s), "orbita-web-1")
	if *row.CPUUsageUsec != 1600 || *row.Restarts != 1 {
		t.Fatalf("cpu %d (ожидалось 1600), перезапуски %d", *row.CPUUsageUsec, *row.Restarts)
	}
}

func TestWorkloadSeriesNewContainerCountsFromZero(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	web := withCounters(testRunning(1, "orbita", "web"), 90_000, 4)
	s.AddPlanned(testWorkloadSample(minute(0), web), nil)
	worker := withCounters(testRunning(2, "orbita", "worker"), 700, 0)
	s.AddPlanned(testWorkloadSample(minute(1), web, worker), nil)
	s.AddPlanned(testWorkloadSample(minute(5), web, worker), nil)

	b := onlyBucket(t, s)
	if row := bucketRow(t, b, "orbita-worker-1"); *row.CPUUsageUsec != 700 {
		t.Fatalf("новый контейнер: cpu %d, ожидалось 700", *row.CPUUsageUsec)
	}
	// Первая выборка процесса — точка отсчёта, а не накопленное с запуска
	// контейнера: иначе корзина после рестарта агента несла бы часы работы.
	if row := bucketRow(t, b, "orbita-web-1"); *row.CPUUsageUsec != 0 || *row.Restarts != 0 {
		t.Fatalf("точка отсчёта: cpu %d, перезапуски %d", *row.CPUUsageUsec, *row.Restarts)
	}
}

func TestWorkloadSeriesEvictsOldestBeyondTwelve(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	c := testRunning(1, "orbita", "web")
	for i := 0; i <= 13; i++ {
		s.AddPlanned(testWorkloadSample(minute(5*i), c), nil)
	}
	pending := s.Pending()
	if len(pending) != WorkloadsMaxBuckets || s.DroppedBuckets() != 1 {
		t.Fatalf("в ожидании %d, вытеснено %d", len(pending), s.DroppedBuckets())
	}
	if pending[0].Start != workloadTimestamp(minute(5)) {
		t.Fatalf("вытеснена не старейшая: первая %s", pending[0].Start)
	}

	s.AddPlanned(testWorkloadSample(minute(70), c), nil)
	if s.DroppedBuckets() != 2 || s.Pending()[0].Start != workloadTimestamp(minute(10)) {
		t.Fatalf("второе вытеснение: %d, первая %s", s.DroppedBuckets(), s.Pending()[0].Start)
	}
}

func TestWorkloadSeriesAcknowledgeRemovesOnlySent(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	c := testRunning(1, "orbita", "web")
	for i := 0; i <= 3; i++ {
		s.AddPlanned(testWorkloadSample(minute(5*i), c), nil)
	}
	sent := s.Pending()[:2]
	// Пока такт в пути, закрылась ещё одна корзина: подтверждение её не снимает.
	s.AddPlanned(testWorkloadSample(minute(20), c), nil)
	s.Acknowledge(sent)

	pending := s.Pending()
	if len(pending) != 2 || pending[0].Start != workloadTimestamp(minute(10)) || pending[1].Start != workloadTimestamp(minute(15)) {
		t.Fatalf("после подтверждения: %v", starts(pending))
	}
	// Подтверждение не обнуляет вытеснение: счётчик накопительный (контракт).
	if s.DroppedBuckets() != 0 {
		t.Fatal("вытеснения не было")
	}
}

func starts(buckets []WorkloadBucket) []string {
	out := make([]string, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, b.Start)
	}
	return out
}

func TestWorkloadSeriesRowsCappedPlatformFirst(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	stacks := map[string]bool{"orbita": true}
	var sample WorkloadSample
	for i := 0; i < 120; i++ {
		project := "zzz"
		if i >= 100 {
			project = "orbita"
		}
		sample.Containers = append(sample.Containers, testRunning(i+1, project, fmt.Sprintf("s%03d", i)))
	}
	for i := 0; i < 60; i++ {
		project := "zzz"
		if i >= 55 {
			project = "orbita"
		}
		sample.Volumes = append(sample.Volumes, WorkloadObservedVolume{Name: fmt.Sprintf("v%03d", i), Driver: "local",
			ComposeProject: project, Fs: volumeUnavailable("mount_not_found")})
	}
	sample.At = minute(0)
	s.AddPlanned(sample, stacks)
	s.AddPlanned(testWorkloadSample(minute(5)), stacks)

	b := onlyBucket(t, s)
	if len(b.Containers) != WorkloadsMaxContainers || len(b.Volumes) != WorkloadsMaxVolumes || !b.Truncated {
		t.Fatalf("строк %d/%d, усечение %v", len(b.Containers), len(b.Volumes), b.Truncated)
	}
	for i := 100; i < 120; i++ {
		bucketRow(t, b, fmt.Sprintf("orbita-s%03d-1", i))
	}
	if b.Volumes[0].Name != "v055" {
		t.Fatalf("тома стеков платформы — первыми: %s", b.Volumes[0].Name)
	}
}

// Выше десяти выборок платформа отвергла бы секцию: лишние выборки корзины
// двигают счётчики, но не gauge и не samples.
func TestWorkloadSeriesSamplesCapped(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	for i := 0; i < 12; i++ {
		c := withCounters(testRunning(1, "orbita", "web"), int64(1000+100*i), 0)
		s.AddPlanned(testWorkloadSample(testWorkloadStart.Add(time.Duration(i)*20*time.Second), c), nil)
	}
	s.AddPlanned(testWorkloadSample(minute(5), withCounters(testRunning(1, "orbita", "web"), 3000, 0)), nil)

	b := onlyBucket(t, s)
	if b.Samples != workloadMaxBucketSamples {
		t.Fatalf("samples %d", b.Samples)
	}
	if row := bucketRow(t, b, "orbita-web-1"); *row.CPUUsageUsec != 1100 {
		t.Fatalf("cpu %d: все 11 приростов по 100", *row.CPUUsageUsec)
	}
}

// Часы ушли назад: корзина с тем же началом не появляется дважды — платформа
// отвергла бы повтор ключа.
func TestWorkloadSeriesClockGoesBack(t *testing.T) {
	s := NewWorkloadSeries(minute(0))
	c := testRunning(1, "orbita", "web")
	s.AddPlanned(testWorkloadSample(minute(5), c), nil)
	s.AddPlanned(testWorkloadSample(minute(1), c), nil)
	s.AddPlanned(testWorkloadSample(minute(6), c), nil)
	s.AddPlanned(testWorkloadSample(minute(10), c), nil)

	b := onlyBucket(t, s)
	if b.Start != workloadTimestamp(minute(5)) || b.Samples != 2 {
		t.Fatalf("корзина %s, выборок %d", b.Start, b.Samples)
	}
}
