package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Преобразование наблюдения в строки секции. Любое значение вне контракта
// платформа отвергла бы вместе со всей секцией хоста, поэтому граница
// проверяется здесь, а не надеждой на сборщик.

func TestWorkloadContainerRowRunning(t *testing.T) {
	c := testRunning(1, "orbita", "web")
	c.Health = "healthy"
	c.Net.Peers = []TCPPeer{{Address: "172.18.0.3", Port: 5432, Direction: "out", Count: 2}}
	stacks := map[string]bool{"orbita": true}

	row, ok := workloadContainerRow(c, stacks, WorkloadImageVerdict{
		Verdict: "match", BaselineID: c.ImageID, BaselineSource: "apply",
	})
	if !ok {
		t.Fatal("годный контейнер отброшен")
	}
	if !row.PlatformStack || deref(row.ComposeProject) != "orbita" || deref(row.Health) != "healthy" {
		t.Fatalf("метки и здоровье: %+v", row)
	}
	// Работающий контейнер ещё не завершался: Docker держит там 0, и это
	// читалось бы как чистый выход.
	if row.ExitCode != nil || row.FinishedAt != nil || row.OOMKilled == nil || *row.OOMKilled {
		t.Fatalf("код выхода и время завершения у работающего: %+v", row)
	}
	if deref(row.StartedAt) != "2026-09-23T09:00:00.123456789Z" {
		t.Fatalf("started_at: %s", deref(row.StartedAt))
	}
	if row.Image.Verdict != "match" || deref(row.Image.BaselineSource) != "apply" || deref(row.Image.ID) != c.ImageID {
		t.Fatalf("образ: %+v", row.Image)
	}
	if row.Cgroup.Status != "ok" || row.Cgroup.Reason != nil || *row.Cgroup.MemoryBytes != 100<<20 {
		t.Fatalf("cgroup: %+v", row.Cgroup)
	}
	if row.Network.Status != "ok" || *row.Network.Established != 3 || len(row.Network.Peers) != 1 {
		t.Fatalf("сеть: %+v", row.Network)
	}
}

func TestWorkloadContainerRowExitedAndUnavailable(t *testing.T) {
	c := testRunning(2, "orbita", "worker")
	c.State, c.Running = "exited", false
	c.ExitCode, c.OOMKilled = 137, true
	c.FinishedAt = "2026-09-23T10:08:21.76409Z"
	// Docker хранит последний статус проверки и у вышедшего контейнера.
	c.Health = "unhealthy"
	c.Cgroup = cgroupUnavailable("not_running")
	c.Net = NetStats{Status: "unavailable", Reason: "shared_netns", NetnsOwner: testWorkloadID(1)}

	row, ok := workloadContainerRow(c, nil, WorkloadImageVerdict{})
	if !ok {
		t.Fatal("годный контейнер отброшен")
	}
	if row.ExitCode == nil || *row.ExitCode != 137 || !*row.OOMKilled || row.Health != nil {
		t.Fatalf("вышедший: %+v", row)
	}
	if row.Cgroup.Status != "unavailable" || deref(row.Cgroup.Reason) != "not_running" || row.Cgroup.MemoryBytes != nil {
		t.Fatalf("cgroup: %+v", row.Cgroup)
	}
	if deref(row.Network.Reason) != "shared_netns" || deref(row.Network.NetnsOwner) != testWorkloadID(1) ||
		row.Network.Established != nil || row.Network.Peers == nil {
		t.Fatalf("сеть: %+v", row.Network)
	}
	// Без вердикта и вне стеков платформы — «не знаем» с причиной, а не пустой enum.
	if row.PlatformStack || row.Image.Verdict != "unknown" || deref(row.Image.Reason) != "not_platform_stack" {
		t.Fatalf("образ: %+v", row.Image)
	}
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), `"peers":null`) {
		t.Fatalf("peers обязан быть массивом: %s", raw)
	}
}

func TestWorkloadContainerRowRejectsWhatContractRejects(t *testing.T) {
	cases := map[string]func(*WorkloadObservedContainer){
		"короткий id":     func(c *WorkloadObservedContainer) { c.ID = c.ID[:12] },
		"id в верхнем":    func(c *WorkloadObservedContainer) { c.ID = strings.Repeat("A", 64) },
		"пустое имя":      func(c *WorkloadObservedContainer) { c.Name = "" },
		"имя длиннее 256": func(c *WorkloadObservedContainer) { c.Name = strings.Repeat("a", 257) },
	}
	for name, spoil := range cases {
		c := testRunning(3, "orbita", "web")
		spoil(&c)
		if _, ok := workloadContainerRow(c, nil, WorkloadImageVerdict{}); ok {
			t.Errorf("%s: строка принята", name)
		}
	}
}

func TestWorkloadContainerRowNormalizesValues(t *testing.T) {
	c := testRunning(4, strings.Repeat("ё", 100), "web")
	c.Health = "none"
	c.ImageID = "not-a-digest"
	c.ImageRef = ""
	c.State = ""
	c.Cgroup = CgroupStats{} // сборщик не заполнил
	c.Cgroup.Pids = i64(jsonSafeIntMax + 1)
	c.Net.Peers = make([]TCPPeer, 40)
	for i := range c.Net.Peers {
		c.Net.Peers[i] = TCPPeer{Address: fmt.Sprintf("10.0.0.%d", i), Port: 80, Direction: "in", Count: 1}
	}
	c.Net.Peers[0].Count = 0

	row, ok := workloadContainerRow(c, nil, WorkloadImageVerdict{Verdict: "bogus", Reason: "Not A Code"})
	if !ok {
		t.Fatal("строка отброшена")
	}
	if len(*row.ComposeProject) != 128 || !strings.HasPrefix(*row.ComposeProject, "ё") {
		t.Fatalf("метка режется по границе символа до 128 байт: %d", len(*row.ComposeProject))
	}
	if row.Health != nil || row.Image.ID != nil || row.Image.Ref != nil || row.State != "unknown" {
		t.Fatalf("пустые и негодные значения: %+v", row)
	}
	if row.Image.Verdict != "unknown" || row.Image.Reason != nil {
		t.Fatalf("негодный вердикт: %+v", row.Image)
	}
	if row.Cgroup.Status != "unavailable" || row.Cgroup.Pids != nil {
		t.Fatalf("незаполненный cgroup: %+v", row.Cgroup)
	}
	if len(row.Network.Peers) != WorkloadsMaxPeers || !row.Network.PeersTruncated || row.Network.Peers[0].Count < 1 {
		t.Fatalf("пиры: %d, усечение %v", len(row.Network.Peers), row.Network.PeersTruncated)
	}
}

func TestWorkloadVolumeRow(t *testing.T) {
	stacks := map[string]bool{"orbita": true}
	total, avail, used := int64(100), int64(60), int64(40)
	row, ok := workloadVolumeRow(WorkloadObservedVolume{
		Name: "orbita_pgdata", Driver: "local", ComposeProject: "orbita",
		Fs: VolumeFsStats{Status: "ok", TotalBytes: &total, AvailBytes: &avail, UsedBytes: &used},
	}, stacks)
	if !ok || !row.PlatformStack || row.Status != "ok" || *row.FsUsedBytes != 40 || row.Reason != nil {
		t.Fatalf("том: %+v", row)
	}

	row, ok = workloadVolumeRow(WorkloadObservedVolume{
		Name: "backup", Driver: "example/sshfs:latest", Fs: volumeUnavailable("driver_not_local"),
	}, stacks)
	if !ok || row.PlatformStack || row.ComposeProject != nil || row.Status != "unavailable" ||
		deref(row.Reason) != "driver_not_local" || row.FsTotalBytes != nil {
		t.Fatalf("недоступный том: %+v", row)
	}

	if _, ok := workloadVolumeRow(WorkloadObservedVolume{Name: "", Driver: "local"}, stacks); ok {
		t.Fatal("том без имени принят")
	}
	if _, ok := workloadVolumeRow(WorkloadObservedVolume{Name: "x"}, stacks); ok {
		t.Fatal("том без драйвера принят")
	}
}

func TestWorkloadPlatformStacks(t *testing.T) {
	stacks := WorkloadPlatformStacks(AppliedState{Apps: map[string]AppliedRecord{
		"orbita": {Status: "healthy"}, "kassa": {Status: "failed"},
	}})
	if !stacks["orbita"] || !stacks["kassa"] || stacks["legacy"] || len(stacks) != 2 {
		t.Fatalf("стеки: %v", stacks)
	}
}
