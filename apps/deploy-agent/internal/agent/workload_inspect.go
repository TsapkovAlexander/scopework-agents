package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Полная выборка нагрузок хоста (ADR-0091, решения 2–3): список и inspect
// контейнеров и томов через CLI docker, сигналы — из файлов /proc и cgroup.
//
// Только вызовы, которые прокси сокета уже пропускает (ADR-0083): список и
// inspect контейнеров, список и inspect томов. Статистики Docker здесь нет и
// не будет: её запрещает ADR-0066 (решение 4), держит TestNoDockerStats.

// workloadCollectTimeout — срок одной выборки. Зависший демон не должен
// останавливать плановые выборки навсегда: следующая попробует заново.
const workloadCollectTimeout = 30 * time.Second

// workloadCollector — где выборка читает файлы хоста. Полями, а не
// константами: тесты гоняются не на Linux и подставляют раскладку во
// временном каталоге.
type workloadCollector struct {
	procRoot, cgroupRoot, mountinfo string
}

func defaultWorkloadCollector() workloadCollector {
	return workloadCollector{procRoot: "/proc", cgroupRoot: "/sys/fs/cgroup", mountinfo: "/proc/self/mountinfo"}
}

// collect снимает выборку на момент at. Ошибка — выборки нет вовсе: сверка
// событий читает пропажу контейнера из списка как удаление, и неполный список
// родил бы ложные removed, а корзины — ложные провалы.
func (c workloadCollector) collect(ctx context.Context, at time.Time) (WorkloadSample, error) {
	ctx, cancel := context.WithTimeout(ctx, workloadCollectTimeout)
	defer cancel()

	containers, err := workloadInspectContainers(ctx)
	if err != nil {
		return WorkloadSample{}, err
	}
	volumes, err := workloadInspectVolumes(ctx)
	if err != nil {
		return WorkloadSample{}, err
	}
	c.readContainerSignals(containers)
	c.readVolumeUsage(volumes)
	return WorkloadSample{At: at, Containers: containers, Volumes: volumes}, nil
}

// workloadInspectedContainer — поля `docker container inspect`, которые
// читает выборка.
type workloadInspectedContainer struct {
	ID           string `json:"Id"`
	Name         string `json:"Name"`
	Image        string `json:"Image"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status                         string
		Running, Restarting, OOMKilled bool
		Pid, ExitCode                  int
		StartedAt, FinishedAt          string
		Health                         *struct{ Status string }
	}
	Config struct {
		Image  string
		Labels map[string]string
	}
	HostConfig struct {
		NetworkMode string
	}
}

type workloadInspectedVolume struct {
	Name, Driver, Mountpoint string
	Labels                   map[string]string
}

func workloadInspectContainers(ctx context.Context) ([]WorkloadObservedContainer, error) {
	out, err := workloadDocker(ctx, nil, "ps", "-aq", "--no-trunc")
	if err != nil {
		return nil, err
	}
	ids := strings.Fields(string(out))
	for _, id := range ids {
		// Строка не id — вывод не понят, и считать его полным списком нельзя.
		if !workloadContainerIDPattern.MatchString(id) {
			return nil, fmt.Errorf("docker ps: строка %q — не id контейнера", workloadTruncate(id, 80))
		}
	}
	containers := []WorkloadObservedContainer{}
	if len(ids) == 0 {
		return containers, nil
	}

	// `container inspect`, а не `inspect`: без типа CLI перебирает образы,
	// сети и тома, а прокси сокета пропускает не всё из этого.
	out, err = workloadDocker(ctx, []string{"no such container", "no such object"},
		append([]string{"container", "inspect"}, ids...)...)
	if err != nil {
		return nil, err
	}
	var inspected []workloadInspectedContainer
	if err := json.Unmarshal(out, &inspected); err != nil {
		return nil, fmt.Errorf("docker container inspect: вывод не разобран: %w", err)
	}
	for _, r := range inspected {
		c := WorkloadObservedContainer{
			ID:             r.ID,
			Name:           strings.TrimPrefix(r.Name, "/"),
			ComposeProject: r.Config.Labels["com.docker.compose.project"],
			ComposeService: r.Config.Labels["com.docker.compose.service"],
			ComposeOneoff:  r.Config.Labels["com.docker.compose.oneoff"] == "True",
			State:          r.State.Status,
			Running:        r.State.Running,
			Restarting:     r.State.Restarting,
			Pid:            r.State.Pid,
			ExitCode:       r.State.ExitCode,
			OOMKilled:      r.State.OOMKilled,
			RestartCount:   r.RestartCount,
			StartedAt:      r.State.StartedAt,
			FinishedAt:     r.State.FinishedAt,
			ImageRef:       r.Config.Image,
			ImageID:        r.Image,
			NetworkMode:    r.HostConfig.NetworkMode,
		}
		if r.State.Health != nil {
			c.Health = r.State.Health.Status
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func workloadInspectVolumes(ctx context.Context) ([]WorkloadObservedVolume, error) {
	out, err := workloadDocker(ctx, nil, "volume", "ls", "-q")
	if err != nil {
		return nil, err
	}
	names := strings.Fields(string(out))
	volumes := []WorkloadObservedVolume{}
	if len(names) == 0 {
		return volumes, nil
	}
	// «--» перед именами: имя тома стороннего драйвера не проверяет никто, и
	// начаться с «-» оно может.
	out, err = workloadDocker(ctx, []string{"no such volume", "no such object"},
		append([]string{"volume", "inspect", "--"}, names...)...)
	if err != nil {
		return nil, err
	}
	var inspected []workloadInspectedVolume
	if err := json.Unmarshal(out, &inspected); err != nil {
		return nil, fmt.Errorf("docker volume inspect: вывод не разобран: %w", err)
	}
	for _, r := range inspected {
		volumes = append(volumes, WorkloadObservedVolume{Name: r.Name, Driver: r.Driver,
			ComposeProject: r.Labels["com.docker.compose.project"], Mountpoint: r.Mountpoint})
	}
	return volumes, nil
}

// workloadDocker — stdout команды docker.
//
// missing — фразы отказа «такого объекта нет». Объект, удалённый между
// списком и inspect, — законный пропуск: CLI печатает найденное и
// завершается с 1. Отказ, целиком состоящий из таких строк, — ответ; любая
// другая строка (прокси, права, демон) — сбой, и выборки нет.
func workloadDocker(ctx context.Context, missing []string, args ...string) ([]byte, error) {
	cmd := newDockerCmd(ctx, "", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	var exit *exec.ExitError
	if ctx.Err() == nil && errors.As(err, &exit) && workloadOnlyMissing(stderr.String(), missing) {
		return stdout.Bytes(), nil
	}
	return nil, fmt.Errorf("docker %s %s: %w: %s", args[0], args[1], err, tail(stderr.String(), 300))
}

func workloadOnlyMissing(stderr string, missing []string) bool {
	lines := 0
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		known := false
		for _, phrase := range missing {
			known = known || strings.Contains(line, phrase)
		}
		if !known {
			return false
		}
		lines++
	}
	return lines > 0
}

// readContainerSignals дочитывает cgroup и сеть. Сбой чтения — «нет данных»
// с причиной у одного сигнала, а не отказ выборки: список контейнеров уже
// полный, и терять его из-за одного файла нельзя.
func (c workloadCollector) readContainerSignals(containers []WorkloadObservedContainer) {
	modes := make(map[string]string, len(containers))
	for _, ct := range containers {
		modes[ct.ID] = ct.NetworkMode
	}
	netns := ResolveNetnsOwners(modes)
	for i := range containers {
		ct := &containers[i]
		ct.Cgroup = ReadContainerCgroup(c.procRoot, c.cgroupRoot, ct.Pid)
		// Общий netns читается у владельца: у соседа те же сокеты удвоили бы счёт.
		if a := netns[ct.ID]; a.Reason != "" {
			ct.Net = netnsUnavailable(a.Reason)
			ct.Net.NetnsOwner = a.Owner
			continue
		}
		ct.Net = ReadNetnsTCP(c.procRoot, ct.Pid, WorkloadsMaxPeers)
	}
}

// readVolumeUsage — заполненность ФС томов. mountinfo читается один раз на
// выборку: он один для всех томов, а у хоста с оверлеями — сотни строк.
func (c workloadCollector) readVolumeUsage(volumes []WorkloadObservedVolume) {
	if len(volumes) == 0 {
		return
	}
	mounts, err := c.readMountinfo()
	isRoot := os.Geteuid() == 0
	for i := range volumes {
		v := &volumes[i]
		// Без таблицы монтирований покрывающей точки не найти, а догадка дала
		// бы заполненность чужой ФС. Том чужого драйвера объясняется драйвером.
		if err != nil && v.Driver == "local" {
			v.Fs = volumeUnavailable("mountinfo_unreadable")
			continue
		}
		v.Fs = VolumeUsage(mounts, v.Mountpoint, v.Driver, isRoot, statfsUsage)
	}
}

func (c workloadCollector) readMountinfo() ([]MountInfoEntry, error) {
	f, err := os.Open(c.mountinfo)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMountinfo(f)
}
