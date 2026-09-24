package agent

import (
	"math"
	"regexp"
	"time"
	"unicode/utf8"
)

// Наблюдение нагрузок хоста — то, что выборка (раз в 60 с и внеочередная по
// потоку docker events) снимает с Docker и /proc, и его перевод в строки
// секции workloads (ADR-0091, решения 2–5).
//
// Выборка заполняет модель как есть, без нормализации: здоровье, коды выхода
// и нулевые времена Docker толкуются здесь и в сверке событий одним способом.

// WorkloadSample — одна выборка: ПОЛНЫЙ список контейнеров (`ps -a`) и томов
// хоста. Сверка событий читает пропажу из списка как удаление, поэтому
// неполный список выдавать нельзя: не удалось — выборки нет.
type WorkloadSample struct {
	At         time.Time
	Containers []WorkloadObservedContainer
	Volumes    []WorkloadObservedVolume
}

// WorkloadObservedContainer — контейнер по inspect и файлам /proc его процесса.
type WorkloadObservedContainer struct {
	ID   string // полный, 64 hex
	Name string // без ведущего «/»
	// Метки com.docker.compose.project, .service и .oneoff ("True" — разовый
	// `compose run`). Пустая строка — метки нет.
	ComposeProject, ComposeService string
	ComposeOneoff                  bool

	// State.Status, State.Running, State.Restarting, State.Pid, State.ExitCode,
	// State.OOMKilled, State.Health.Status ("" — проверки нет), RestartCount.
	State               string
	Running, Restarting bool
	Pid                 int
	ExitCode            int
	OOMKilled           bool
	Health              string
	RestartCount        int
	// State.StartedAt и State.FinishedAt строками inspect: нулевое время
	// Docker (0001-01-01T00:00:00Z) толкует workloadDockerTime.
	StartedAt, FinishedAt string

	ImageRef string // Config.Image — что объявлено
	ImageID  string // .Image — что запущено, sha256:…
	// HostConfig.NetworkMode — вход ResolveNetnsOwners: по нему выборка решает,
	// чей netns читать за контейнер.
	NetworkMode string

	Cgroup CgroupStats // ReadContainerCgroup по Pid
	Net    NetStats    // ReadNetnsTCP по Pid владельца netns или причина
}

// WorkloadObservedVolume — том по `volume inspect` и заполненность его ФС.
type WorkloadObservedVolume struct {
	Name, Driver   string
	ComposeProject string // метка com.docker.compose.project
	Mountpoint     string // вход VolumeUsage
	Fs             VolumeFsStats
}

// WorkloadPlatformStacks — compose-проекты стеков платформы: compose-проект
// приложения — его slug (composemodel.go), а приложение платформы — то, что
// агент применял (applied.json). При отсечении они уходят последними
// (решение 9), эталон образа есть только у них (решение 6).
func WorkloadPlatformStacks(applied AppliedState) map[string]bool {
	stacks := make(map[string]bool, len(applied.Apps))
	for slug := range applied.Apps {
		stacks[slug] = true
	}
	return stacks
}

var (
	workloadContainerIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	workloadImageIDPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	workloadReasonPattern      = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
)

// Пределы строк контракта. Длину zod считает в UTF-16, байт UTF-8 не меньше,
// поэтому предел в байтах — с запасом верный.
const (
	workloadMaxNameBytes  = 256
	workloadMaxLabelBytes = 128
	workloadMaxStateBytes = 32
	workloadMaxRefBytes   = 512
	workloadMaxPeerAddr   = 45
)

// workloadHealth — статус проверки здоровья, который ещё что-то значит. У
// неработающего контейнера Docker хранит последний статус давно не идущей
// проверки, и вышедший числился бы «не проходит проверку» (ADR-0061, найдено
// на стенде 11.09.2026); "none" — проверки нет.
func workloadHealth(c WorkloadObservedContainer) string {
	switch c.State {
	case "running", "restarting", "paused":
	default:
		return ""
	}
	if c.Health == "none" {
		return ""
	}
	return c.Health
}

func workloadExited(state string) bool { return state == "exited" || state == "dead" }

// workloadExitKnown — код выхода относится к завершённому запуску. У
// перезапускающегося контейнера он — причина последнего выхода.
func workloadExitKnown(state string) bool { return workloadExited(state) || state == "restarting" }

// workloadTruncate режет строку до max байт по границе символа.
func workloadTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// workloadText — пустой строки в секции нет (контракт): пусто — null.
func workloadText(s string, max int) *string {
	if s == "" {
		return nil
	}
	s = workloadTruncate(s, max)
	return &s
}

func workloadReason(s string) *string {
	if !workloadReasonPattern.MatchString(s) {
		return nil
	}
	return &s
}

func workloadImageIDOf(s string) *string {
	if !workloadImageIDPattern.MatchString(s) {
		return nil
	}
	return &s
}

// workloadMetric — число выше 2^53−1 платформа отвергла бы вместе со всей
// секцией; такое значение — «нет данных».
func workloadMetric(v *int64) *int64 {
	if v == nil || *v < 0 || *v > jsonSafeIntMax {
		return nil
	}
	n := *v
	return &n
}

func workloadCount(v int) *int64 {
	n := int64(v)
	return workloadMetric(&n)
}

// workloadContainerRow — строка контейнера секции; false — контейнер нельзя
// отдать, не нарушив контракт (id не 64 hex, имя пустое или длиннее предела).
// Имя не режется: оно ключ строки, и обрезанное совпало бы с чужим.
func workloadContainerRow(c WorkloadObservedContainer, stacks map[string]bool, v WorkloadImageVerdict) (WorkloadContainer, bool) {
	if !workloadContainerIDPattern.MatchString(c.ID) || c.Name == "" || len(c.Name) > workloadMaxNameBytes {
		return WorkloadContainer{}, false
	}
	platform := c.ComposeProject != "" && stacks[c.ComposeProject]
	oom := c.OOMKilled
	row := WorkloadContainer{
		ID:             c.ID,
		Name:           c.Name,
		ComposeProject: workloadText(c.ComposeProject, workloadMaxLabelBytes),
		ComposeService: workloadText(c.ComposeService, workloadMaxLabelBytes),
		PlatformStack:  platform,
		State:          workloadTruncate(c.State, workloadMaxStateBytes),
		Health:         workloadText(workloadHealth(c), workloadMaxStateBytes),
		RestartCount:   int64(max(c.RestartCount, 0)),
		OOMKilled:      &oom,
		StartedAt:      workloadDockerTime(c.StartedAt),
		FinishedAt:     workloadDockerTime(c.FinishedAt),
		Image:          workloadImageRow(c, platform, v),
		Cgroup:         workloadCgroupRow(c.Cgroup),
		Network:        workloadNetworkRow(c.Net),
	}
	if row.State == "" {
		row.State = "unknown"
	}
	if workloadExitKnown(c.State) && c.ExitCode >= math.MinInt32 && c.ExitCode <= math.MaxInt32 {
		code := c.ExitCode
		row.ExitCode = &code
	}
	return row, true
}

func workloadImageRow(c WorkloadObservedContainer, platform bool, v WorkloadImageVerdict) WorkloadImage {
	img := WorkloadImage{
		Ref:        workloadText(c.ImageRef, workloadMaxRefBytes),
		ID:         workloadImageIDOf(c.ImageID),
		Verdict:    v.Verdict,
		Reason:     workloadReason(v.Reason),
		BaselineID: workloadImageIDOf(v.BaselineID),
	}
	switch v.Verdict {
	case WorkloadVerdictMatch, WorkloadVerdictMismatch, WorkloadVerdictUnknown:
	case "":
		// Вердикта нет — эталон не оценивали. Причина та же, что дал бы сам
		// эталон: у чужого стека его не бывает, у своего его ещё нет.
		img.Verdict = WorkloadVerdictUnknown
		reason := WorkloadReasonNotPlatformStack
		if platform {
			reason = WorkloadReasonNoBaseline
		}
		img.Reason = &reason
	default:
		img.Verdict, img.Reason = WorkloadVerdictUnknown, nil
	}
	if v.BaselineSource == WorkloadBaselineApply || v.BaselineSource == WorkloadBaselineAdopted {
		source := v.BaselineSource
		img.BaselineSource = &source
	}
	return img
}

// Статус сборщика, кроме "ok", — «нет данных»: нулевое значение (сборщик не
// дошёл до контейнера) не должно давать строку, которую отвергнет enum.
func workloadCgroupRow(s CgroupStats) WorkloadCgroup {
	if s.Status != "ok" {
		return WorkloadCgroup{Status: "unavailable", Reason: workloadReason(s.Reason)}
	}
	return WorkloadCgroup{
		Status:         "ok",
		MemoryBytes:    workloadMetric(s.MemoryBytes),
		MemoryMaxBytes: workloadMetric(s.MemoryMaxBytes),
		OOMKills:       workloadMetric(s.OOMKills),
		CPUUsageUsec:   workloadMetric(s.CPUUsageUsec),
		CPUNrThrottled: workloadMetric(s.CPUNrThrottled),
		Pids:           workloadMetric(s.Pids),
	}
}

func workloadNetworkRow(n NetStats) WorkloadNetwork {
	row := WorkloadNetwork{Peers: []WorkloadPeer{}}
	if n.Status != "ok" {
		row.Status, row.Reason = "unavailable", workloadReason(n.Reason)
		if workloadContainerIDPattern.MatchString(n.NetnsOwner) {
			owner := n.NetnsOwner
			row.NetnsOwner = &owner
		}
		return row
	}
	row.Status = "ok"
	row.Established = workloadCount(n.Established)
	row.Inbound = workloadCount(n.Inbound)
	row.Outbound = workloadCount(n.Outbound)
	row.External = workloadCount(n.External)
	row.PeersTruncated = n.PeersTruncated
	for _, p := range n.Peers {
		if p.Count < 1 || p.Port < 0 || p.Port > 65535 || (p.Direction != "in" && p.Direction != "out") ||
			p.Address == "" || len(p.Address) > workloadMaxPeerAddr {
			continue
		}
		if len(row.Peers) == WorkloadsMaxPeers {
			row.PeersTruncated = true
			break
		}
		row.Peers = append(row.Peers, WorkloadPeer{Address: p.Address, Port: p.Port, Direction: p.Direction, Count: p.Count})
	}
	return row
}

// workloadVolumeRow — строка тома; false — том без имени или драйвера.
func workloadVolumeRow(v WorkloadObservedVolume, stacks map[string]bool) (WorkloadVolume, bool) {
	if v.Name == "" || len(v.Name) > workloadMaxNameBytes || v.Driver == "" {
		return WorkloadVolume{}, false
	}
	row := WorkloadVolume{
		Name:           v.Name,
		Driver:         workloadTruncate(v.Driver, workloadMaxLabelBytes),
		ComposeProject: workloadText(v.ComposeProject, workloadMaxLabelBytes),
		PlatformStack:  v.ComposeProject != "" && stacks[v.ComposeProject],
	}
	if v.Fs.Status != "ok" {
		row.Status, row.Reason = "unavailable", workloadReason(v.Fs.Reason)
		return row, true
	}
	row.Status = "ok"
	row.FsTotalBytes = workloadMetric(v.Fs.TotalBytes)
	row.FsAvailBytes = workloadMetric(v.Fs.AvailBytes)
	row.FsUsedBytes = workloadMetric(v.Fs.UsedBytes)
	return row, true
}
