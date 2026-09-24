package agent

import (
	"fmt"
	"time"
)

// Общие заготовки тестов секции workloads.

// testWorkloadID — полный id контейнера: 64 hex, как отдаёт inspect.
func testWorkloadID(n int) string { return fmt.Sprintf("%064x", n) }

// testWorkloadImage — id образа в форме, которую принимает контракт.
func testWorkloadImage(n int) string { return "sha256:" + testWorkloadID(n) }

func i64(v int64) *int64 { return &v }

var testWorkloadStart = time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)

// testRunning — работающий контейнер с прочитанными cgroup и сетью. Без
// project — контейнер вне compose по имени service, без меток.
func testRunning(n int, project, service string) WorkloadObservedContainer {
	name := fmt.Sprintf("%s-%s-1", project, service)
	if project == "" {
		name, service = service, ""
	}
	return WorkloadObservedContainer{
		ID:             testWorkloadID(n),
		Name:           name,
		ComposeProject: project,
		ComposeService: service,
		State:          "running",
		Running:        true,
		Pid:            1000 + n,
		RestartCount:   0,
		StartedAt:      "2026-09-23T09:00:00.123456789Z",
		FinishedAt:     "0001-01-01T00:00:00Z",
		ImageRef:       "registry.example.test/" + project + "/" + service + ":1",
		ImageID:        testWorkloadImage(n),
		Cgroup: CgroupStats{
			Status: "ok", MemoryBytes: i64(100 << 20), MemoryMaxBytes: i64(1 << 30),
			OOMKills: i64(0), CPUUsageUsec: i64(1_000_000), CPUNrThrottled: i64(0), Pids: i64(10),
		},
		Net: NetStats{Status: "ok", Established: 3, Inbound: 2, Outbound: 1, Peers: []TCPPeer{}},
	}
}

func testWorkloadSample(at time.Time, containers ...WorkloadObservedContainer) WorkloadSample {
	return WorkloadSample{At: at, Containers: containers}
}
