package agent

import (
	"encoding/json"
	"time"
)

// Секция workloads такта (ADR-0091): текущие значения нагрузок хоста,
// закрытые неподтверждённые пятиминутные корзины и события контейнеров.
//
// Точка правды контракта — packages/server-monitoring/src/workloads.ts и её
// золотая фикстура fixtures/workloads-section.json; типы ниже маршалятся ровно
// в неё. КАЖДЫЙ ключ присутствует всегда, «нет данных» — null: поэтому нигде
// нет omitempty, а nil-срезы в секцию не попадают (null вместо массива
// платформа отвергла бы вместе со всей секцией).

// Пределы секции. Совпадают с workloads.ts — сверяет контрактный тест.
const (
	WorkloadsSectionVersion   = 1
	WorkloadsMaxContainers    = 100
	WorkloadsMaxVolumes       = 50
	WorkloadsMaxPeers         = 32
	WorkloadsMaxEvents        = 20
	WorkloadsMaxBuckets       = 12
	WorkloadsBucketSeconds    = 300
	WorkloadsMaxSectionBytes  = 256 << 10
	WorkloadsMaxTickBodyBytes = 736 << 10

	// Пять плановых выборок на корзину, остальное — запас на сдвиг таймера.
	// Выше предела платформа отвергла бы секцию целиком.
	workloadMaxBucketSamples = 10
)

// WorkloadsSection — секция workloads тела такта.
//
// DroppedBuckets и DroppedEvents накопительные с Since (старт процесса):
// ответ такта может потеряться, и обнулённый подтверждением счётчик пришёл бы
// повторно как новая потеря.
type WorkloadsSection struct {
	Version           int                 `json:"version"`
	Since             string              `json:"since"`
	CollectedAt       string              `json:"collected_at"`
	Truncated         bool                `json:"truncated"`
	OmittedContainers int64               `json:"omitted_containers"`
	OmittedVolumes    int64               `json:"omitted_volumes"`
	DroppedBuckets    int64               `json:"dropped_buckets"`
	DroppedEvents     int64               `json:"dropped_events"`
	Containers        []WorkloadContainer `json:"containers"`
	Volumes           []WorkloadVolume    `json:"volumes"`
	Buckets           []WorkloadBucket    `json:"buckets"`
	Events            []WorkloadEvent     `json:"events"`
}

// WorkloadContainer — текущее значение контейнера.
type WorkloadContainer struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	ComposeProject *string `json:"compose_project"`
	ComposeService *string `json:"compose_service"`
	PlatformStack  bool    `json:"platform_stack"`
	State          string  `json:"state"`
	Health         *string `json:"health"`
	RestartCount   int64   `json:"restart_count"`
	// ExitCode — null, пока контейнер не завершён: Docker держит там 0, и
	// это читалось бы как чистый выход.
	ExitCode   *int            `json:"exit_code"`
	OOMKilled  *bool           `json:"oom_killed"`
	StartedAt  *string         `json:"started_at"`
	FinishedAt *string         `json:"finished_at"`
	Image      WorkloadImage   `json:"image"`
	Cgroup     WorkloadCgroup  `json:"cgroup"`
	Network    WorkloadNetwork `json:"network"`
}

// WorkloadImage — фактический образ против эталона релиза (решение 6).
type WorkloadImage struct {
	Ref            *string `json:"ref"`
	ID             *string `json:"id"`
	Verdict        string  `json:"verdict"`
	Reason         *string `json:"reason"`
	BaselineID     *string `json:"baseline_id"`
	BaselineSource *string `json:"baseline_source"`
}

type WorkloadCgroup struct {
	Status         string  `json:"status"`
	Reason         *string `json:"reason"`
	MemoryBytes    *int64  `json:"memory_bytes"`
	MemoryMaxBytes *int64  `json:"memory_max_bytes"`
	OOMKills       *int64  `json:"oom_kills"`
	CPUUsageUsec   *int64  `json:"cpu_usage_usec"`
	CPUNrThrottled *int64  `json:"cpu_nr_throttled"`
	Pids           *int64  `json:"pids"`
}

type WorkloadNetwork struct {
	Status         string         `json:"status"`
	Reason         *string        `json:"reason"`
	NetnsOwner     *string        `json:"netns_owner"`
	Established    *int64         `json:"established"`
	Inbound        *int64         `json:"inbound"`
	Outbound       *int64         `json:"outbound"`
	External       *int64         `json:"external"`
	Peers          []WorkloadPeer `json:"peers"`
	PeersTruncated bool           `json:"peers_truncated"`
}

type WorkloadPeer struct {
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Direction string `json:"direction"`
	Count     int    `json:"count"`
}

type WorkloadVolume struct {
	Name           string  `json:"name"`
	Driver         string  `json:"driver"`
	ComposeProject *string `json:"compose_project"`
	PlatformStack  bool    `json:"platform_stack"`
	Status         string  `json:"status"`
	Reason         *string `json:"reason"`
	FsTotalBytes   *int64  `json:"fs_total_bytes"`
	FsAvailBytes   *int64  `json:"fs_avail_bytes"`
	FsUsedBytes    *int64  `json:"fs_used_bytes"`
}

// WorkloadBucket — закрытая пятиминутная корзина. Start выровнен по UTC на
// 300 с; строки идут по имени, а не по id: имя переживает пересоздание.
type WorkloadBucket struct {
	Start      string                    `json:"start"`
	Seconds    int                       `json:"seconds"`
	Samples    int                       `json:"samples"`
	Truncated  bool                      `json:"truncated"`
	Containers []WorkloadBucketContainer `json:"containers"`
	Volumes    []WorkloadBucketVolume    `json:"volumes"`
}

type WorkloadBucketContainer struct {
	Name           string `json:"name"`
	MemAvgBytes    *int64 `json:"mem_avg_bytes"`
	MemMaxBytes    *int64 `json:"mem_max_bytes"`
	CPUUsageUsec   *int64 `json:"cpu_usage_usec"`
	CPUNrThrottled *int64 `json:"cpu_nr_throttled"`
	OOMKills       *int64 `json:"oom_kills"`
	PidsMax        *int64 `json:"pids_max"`
	ConnsMax       *int64 `json:"conns_max"`
	Restarts       *int64 `json:"restarts"`
}

type WorkloadBucketVolume struct {
	Name         string `json:"name"`
	UsedAvgBytes *int64 `json:"used_avg_bytes"`
	UsedMaxBytes *int64 `json:"used_max_bytes"`
	TotalBytes   *int64 `json:"total_bytes"`
}

// WorkloadEvent — событие контейнера: поля ADR-0061 без хвоста лога
// (решение 5), каждый ключ обязателен.
type WorkloadEvent struct {
	Key            string  `json:"key"`
	Kind           string  `json:"kind"`
	Name           string  `json:"name"`
	ComposeProject *string `json:"compose_project"`
	ComposeService *string `json:"compose_service"`
	Image          *string `json:"image"`
	ImageID        *string `json:"image_id"`
	PrevImage      *string `json:"prev_image"`
	PrevImageID    *string `json:"prev_image_id"`
	ExitCode       *int    `json:"exit_code"`
	OOMKilled      *bool   `json:"oom_killed"`
	Restarts       *int64  `json:"restarts"`
	Health         *string `json:"health"`
	At             string  `json:"at"`
}

// workloadTimestamp — единственный формат времени секции: UTC с «Z».
// Выравнивание корзины и ключ ряда в базе не должны зависеть от пояса, в
// котором агент записал момент.
func workloadTimestamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// workloadDockerTime — время из inspect в формате секции. Нулевое время Docker
// (0001-01-01, «не запускался», «не завершался») — null, как и нечитаемое.
func workloadDockerTime(raw string) *string {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || t.Year() <= 1 {
		return nil
	}
	s := workloadTimestamp(t)
	return &s
}

// WorkloadsAccepted — платформа сохранила секцию этого такта.
//
// Только accepted.workloads == 1. В отличие от прочих секций, отсутствие
// поля — «не доставлено» (ADR-0091, решение 1): старая платформа, не знающая
// секции, иначе подтверждала бы её молчанием, и агент стирал бы очередь
// событий. Так же читается любой мусор: подтверждение снимает с диска то,
// что больше не повторится.
func WorkloadsAccepted(resp TickResponse) bool {
	var accepted map[string]json.RawMessage
	if json.Unmarshal(resp.Accepted, &accepted) != nil {
		return false
	}
	raw, ok := accepted["workloads"]
	if !ok {
		return false
	}
	var n *float64
	return json.Unmarshal(raw, &n) == nil && n != nil && *n == 1
}
