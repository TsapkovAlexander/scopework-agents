package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Полная выборка нагрузок через CLI docker (ADR-0091, решения 2–3).
//
// ШОВ — ПОДДЕЛЬНЫЙ `docker` В PATH, как у восстановления (restore_test.go):
// newDockerCmd ищет двоичный файл по PATH, а dockerEnv() пробрасывает PATH
// дочернему процессу, поэтому боевому коду шов ради теста не нужен. Ответы
// подкоманд лежат файлами и меняются между выборками; каталог вшит в текст
// скрипта, потому что dockerEnv() отрезает остальное окружение.

type workloadDockerStub struct {
	t   *testing.T
	dir string
}

func installWorkloadDocker(t *testing.T) *workloadDockerStub {
	t.Helper()
	bin, dir := t.TempDir(), t.TempDir()
	script := "#!/bin/sh\n" +
		"d=" + shellQuote(dir) + "\n" +
		`printf '%s\n' "$*" >> "$d/calls"` + "\n" +
		`case "$1 $2" in` + "\n" +
		`  "ps "*) k=ps;;` + "\n" +
		`  "container inspect") k=container-inspect;;` + "\n" +
		`  "volume ls") k=volume-ls;;` + "\n" +
		`  "volume inspect") k=volume-inspect;;` + "\n" +
		`  "events "*) k=events;;` + "\n" +
		`  *) echo "подставной docker: неизвестная команда $*" >&2; exit 2;;` + "\n" +
		`esac` + "\n" +
		// Поток: pid каждого запуска в журнал, режим запуска — строкой
		// events.modes по его номеру; без строки поток висит, как настоящий.
		// events.pace — пауза перед каждой строкой: события приходят не пачкой.
		`if [ "$k" = events ]; then` + "\n" +
		`  echo $$ >> "$d/events.pids"` + "\n" +
		`  n=$(( $(wc -l < "$d/events.pids") ))` + "\n" +
		`  mode=$(sed -n "${n}p" "$d/events.modes" 2>/dev/null)` + "\n" +
		`  pace=$(cat "$d/events.pace" 2>/dev/null)` + "\n" +
		`  if [ -f "$d/events.out" ]; then` + "\n" +
		`    while IFS= read -r line; do [ -n "$pace" ] && sleep "$pace"; printf '%s\n' "$line"; done < "$d/events.out"` + "\n" +
		`  fi` + "\n" +
		`  [ "$mode" = exit ] && exit 1` + "\n" +
		`  exec sleep 3600` + "\n" +
		`fi` + "\n" +
		`cat "$d/$k.out" 2>/dev/null` + "\n" +
		`cat "$d/$k.err" >&2 2>/dev/null` + "\n" +
		`exit $(cat "$d/$k.code" 2>/dev/null || echo 0)` + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	d := &workloadDockerStub{t: t, dir: dir}
	// Страховка на случай провала до остановки: висящий поток — наш дочерний
	// процесс, и пережить тест он не должен.
	t.Cleanup(func() {
		for _, pid := range d.eventsPids() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return d
}

// respond задаёт ответ подкоманды: ps, container-inspect, volume-ls, volume-inspect.
func (d *workloadDockerStub) respond(key, stdout, stderr string, code int) {
	d.t.Helper()
	for name, content := range map[string]string{".out": stdout, ".err": stderr, ".code": strconv.Itoa(code)} {
		if err := os.WriteFile(filepath.Join(d.dir, key+name), []byte(content), 0o644); err != nil {
			d.t.Fatal(err)
		}
	}
}

func (d *workloadDockerStub) write(name, content string) {
	d.t.Helper()
	if err := os.WriteFile(filepath.Join(d.dir, name), []byte(content), 0o644); err != nil {
		d.t.Fatal(err)
	}
}

func (d *workloadDockerStub) calls() []string {
	raw, _ := os.ReadFile(filepath.Join(d.dir, "calls"))
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// count — сколько вызовов начинается с prefix.
func (d *workloadDockerStub) count(prefix string) int {
	n := 0
	for _, c := range d.calls() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (d *workloadDockerStub) eventsPids() []int {
	raw, _ := os.ReadFile(filepath.Join(d.dir, "events.pids"))
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		if pid, err := strconv.Atoi(f); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// host — успешные ответы всей выборки: списки и inspect контейнеров и томов.
func (d *workloadDockerStub) host(containers []string, inspect string, volumes []string, volumeInspect string) {
	d.respond("ps", workloadLines(containers), "", 0)
	d.respond("container-inspect", inspect, "", 0)
	d.respond("volume-ls", workloadLines(volumes), "", 0)
	d.respond("volume-inspect", volumeInspect, "", 0)
}

func workloadLines(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, "\n") + "\n"
}

// workloadInspectRunning — контейнер compose так, как его печатает
// `docker container inspect`: с полями, которые выборка не читает.
func workloadInspectRunning(id, project, service string, pid, restarts int, health string) string {
	healthJSON := ""
	if health != "" {
		healthJSON = fmt.Sprintf(`,"Health":{"Status":%q,"FailingStreak":0,"Log":[]}`, health)
	}
	return fmt.Sprintf(`{"Id":%q,"Created":"2026-09-23T08:59:58.1Z","Path":"docker-entrypoint.sh","Args":["postgres"],`+
		`"State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,`+
		`"Pid":%d,"ExitCode":0,"Error":"","StartedAt":"2026-09-23T09:00:00.123456789Z","FinishedAt":"0001-01-01T00:00:00Z"%s},`+
		`"Image":%q,"Name":"/%s-%s-1","RestartCount":%d,`+
		`"HostConfig":{"NetworkMode":"%s_default","RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0}},`+
		`"Config":{"Hostname":"db","Image":"postgres:16","Labels":{"com.docker.compose.project":%q,`+
		`"com.docker.compose.service":%q,"com.docker.compose.oneoff":"False"}},`+
		`"NetworkSettings":{"Networks":{}}}`,
		id, pid, healthJSON, testWorkloadImage(pid), project, service, restarts, project, project, service)
}

func workloadInspectArray(objects ...string) string { return "[" + strings.Join(objects, ",") + "]\n" }

func workloadVolumeJSON(name, driver, project, mountpoint string) string {
	return fmt.Sprintf(`{"CreatedAt":"2026-09-20T10:00:00Z","Driver":%q,"Labels":{"com.docker.compose.project":%q,`+
		`"com.docker.compose.volume":"db-data"},"Mountpoint":%q,"Name":%q,"Options":null,"Scope":"local"}`,
		driver, project, mountpoint, name)
}

// workloadTestCollector — корни /proc и cgroup во временных каталогах, без
// mountinfo: выборка без томов его не читает.
func workloadTestCollector(t *testing.T) workloadCollector {
	return workloadCollector{procRoot: t.TempDir(), cgroupRoot: t.TempDir(), mountinfo: filepath.Join(t.TempDir(), "mountinfo")}
}

func workloadCollect(t *testing.T, c workloadCollector) WorkloadSample {
	t.Helper()
	s, err := c.collect(context.Background(), testWorkloadStart)
	if err != nil {
		t.Fatalf("выборка: %v", err)
	}
	return s
}

func TestWorkloadInspectMapsContainersAndVolumes(t *testing.T) {
	d := installWorkloadDocker(t)
	f := newCgroupFixture(t, true)
	id1, id2, id3 := testWorkloadID(1), testWorkloadID(2), testWorkloadID(3)

	// Свой netns и cgroup у первого; второй — разовый `compose run`, вышедший
	// по OOM в netns первого; третий — в сети хоста.
	scope := "/system.slice/docker-" + id1 + ".scope"
	f.process(t, "4242", "0::"+scope+"\n")
	f.scope(t, scope, cgroupScopeFiles())
	tcp := tcpLine("020012AC:1538", "030012AC:9C41", tcpEstablished) // 172.18.0.2:5432 ← 172.18.0.3
	writeProcNet(t, f.proc, 4242, strp(tcpLine("00000000:1538", "00000000:0000", tcpListen)+tcp), nil)

	oneoff := fmt.Sprintf(`{"Id":%q,"Name":"/orbita-migrate-run-1f2e","RestartCount":0,"Image":%q,`+
		`"State":{"Status":"exited","Running":false,"Restarting":false,"OOMKilled":true,"Pid":0,"ExitCode":137,`+
		`"StartedAt":"2026-09-23T09:01:00Z","FinishedAt":"2026-09-23T09:02:00Z"},`+
		`"HostConfig":{"NetworkMode":"container:%s"},`+
		`"Config":{"Image":"orbita/app:7","Labels":{"com.docker.compose.project":"orbita","com.docker.compose.service":"migrate","com.docker.compose.oneoff":"True"}}}`,
		id2, testWorkloadImage(9), id1)
	hostNet := fmt.Sprintf(`{"Id":%q,"Name":"/node-exporter","RestartCount":0,"Image":%q,`+
		`"State":{"Status":"running","Running":true,"Pid":4343,"ExitCode":0,"StartedAt":"2026-09-23T08:00:00Z","FinishedAt":"0001-01-01T00:00:00Z"},`+
		`"HostConfig":{"NetworkMode":"host"},"Config":{"Image":"prom/node-exporter","Labels":null}}`,
		id3, testWorkloadImage(3))

	volRoot := t.TempDir()
	mountinfo := filepath.Join(t.TempDir(), "mountinfo")
	line := "36 1 8:1 / " + strings.ReplaceAll(volRoot, " ", `\040`) + " rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
	if err := os.WriteFile(mountinfo, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	d.host([]string{id1, id2, id3}, workloadInspectArray(workloadInspectRunning(id1, "orbita", "db", 4242, 2, "healthy"), oneoff, hostNet),
		[]string{"orbita_db-data", "nfs-share"},
		workloadInspectArray(
			workloadVolumeJSON("orbita_db-data", "local", "orbita", filepath.Join(volRoot, "volumes", "orbita_db-data", "_data")),
			workloadVolumeJSON("nfs-share", "rexray", "", "/mnt/rexray/nfs-share")))

	s := workloadCollect(t, workloadCollector{procRoot: f.proc, cgroupRoot: f.root, mountinfo: mountinfo})

	for _, want := range []string{"ps -aq --no-trunc", "container inspect " + id1 + " " + id2 + " " + id3,
		"volume ls -q", "volume inspect -- orbita_db-data nfs-share"} {
		if d.count(want) != 1 {
			t.Fatalf("вызов %q не сделан ровно один раз: %q", want, d.calls())
		}
	}
	if !s.At.Equal(testWorkloadStart) || len(s.Containers) != 3 || len(s.Volumes) != 2 {
		t.Fatalf("выборка %v: %d контейнеров, %d томов", s.At, len(s.Containers), len(s.Volumes))
	}

	db := s.Containers[0]
	if db.ID != id1 || db.Name != "orbita-db-1" || db.ComposeProject != "orbita" || db.ComposeService != "db" ||
		db.ComposeOneoff || db.State != "running" || !db.Running || db.Pid != 4242 || db.Health != "healthy" ||
		db.RestartCount != 2 || db.StartedAt != "2026-09-23T09:00:00.123456789Z" || db.FinishedAt != "0001-01-01T00:00:00Z" ||
		db.ImageRef != "postgres:16" || db.ImageID != testWorkloadImage(4242) || db.NetworkMode != "orbita_default" {
		t.Fatalf("контейнер базы разобран неверно: %+v", db)
	}
	if db.Cgroup.Status != "ok" || db.Cgroup.MemoryBytes == nil || *db.Cgroup.MemoryBytes != 412385280 {
		t.Fatalf("cgroup базы: %+v", db.Cgroup)
	}
	if db.Net.Status != "ok" || db.Net.Established != 1 || db.Net.Inbound != 1 {
		t.Fatalf("сеть базы: %+v", db.Net)
	}

	run := s.Containers[1]
	if run.Name != "orbita-migrate-run-1f2e" || !run.ComposeOneoff || run.State != "exited" || run.Running ||
		run.ExitCode != 137 || !run.OOMKilled || run.Health != "" || run.FinishedAt != "2026-09-23T09:02:00Z" {
		t.Fatalf("разовый контейнер разобран неверно: %+v", run)
	}
	if run.Cgroup.Status != "unavailable" || run.Cgroup.Reason != "not_running" {
		t.Fatalf("cgroup вышедшего: %+v", run.Cgroup)
	}
	if run.Net.Status != "unavailable" || run.Net.Reason != "shared_netns" || run.Net.NetnsOwner != id1 || run.Net.Peers == nil {
		t.Fatalf("сеть соседа по netns: %+v", run.Net)
	}

	if exp := s.Containers[2]; exp.Net.Reason != "host_network" || exp.ComposeProject != "" {
		t.Fatalf("контейнер в сети хоста: %+v", exp)
	}

	vol := s.Volumes[0]
	if vol.Name != "orbita_db-data" || vol.Driver != "local" || vol.ComposeProject != "orbita" ||
		vol.Fs.Status != "ok" || vol.Fs.TotalBytes == nil || *vol.Fs.TotalBytes <= 0 {
		t.Fatalf("том разобран неверно: %+v (fs %+v)", vol, vol.Fs)
	}
	if nfs := s.Volumes[1]; nfs.Fs.Status != "unavailable" || nfs.Fs.Reason != "driver_not_local" {
		t.Fatalf("том чужого драйвера: %+v", nfs.Fs)
	}
}

// Контейнер, удалённый между `ps` и inspect, законно пропал: сверка прочтёт
// его отсутствие как удаление, и это правда.
func TestWorkloadInspectContainerGoneBetweenListAndInspect(t *testing.T) {
	for _, gone := range []string{
		"Error response from daemon: No such container: " + testWorkloadID(2),
		"Error: No such object: " + testWorkloadID(2),
	} {
		t.Run(gone[:12], func(t *testing.T) {
			d := installWorkloadDocker(t)
			d.host([]string{testWorkloadID(1), testWorkloadID(2)}, "", nil, "")
			d.respond("container-inspect", workloadInspectArray(workloadInspectRunning(testWorkloadID(1), "orbita", "db", 10, 0, "")), gone+"\n", 1)

			s := workloadCollect(t, workloadTestCollector(t))
			if len(s.Containers) != 1 || s.Containers[0].ID != testWorkloadID(1) {
				t.Fatalf("контейнеры %+v, ожидался один оставшийся", s.Containers)
			}
		})
	}
}

func TestWorkloadInspectVolumeGoneBetweenListAndInspect(t *testing.T) {
	d := installWorkloadDocker(t)
	d.host(nil, "", []string{"a", "b"}, "")
	d.respond("volume-inspect", workloadInspectArray(workloadVolumeJSON("a", "local", "", "/var/lib/docker/volumes/a/_data")),
		"Error response from daemon: get b: no such volume\n", 1)

	s := workloadCollect(t, workloadTestCollector(t))
	if len(s.Volumes) != 1 || s.Volumes[0].Name != "a" {
		t.Fatalf("тома %+v, ожидался один оставшийся", s.Volumes)
	}
	// mountinfo нет — это «нет данных» с причиной, а не заполненность чужой ФС.
	if fs := s.Volumes[0].Fs; fs.Status != "unavailable" || fs.Reason != "mountinfo_unreadable" {
		t.Fatalf("том без mountinfo: %+v", fs)
	}
}

// Любой другой отказ — выборки нет: неполный список контейнеров сверка
// прочла бы как удаление всего, чего в нём не хватило.
func TestWorkloadInspectFailureIsNoSample(t *testing.T) {
	id1, id2 := testWorkloadID(1), testWorkloadID(2)
	running := workloadInspectArray(workloadInspectRunning(id1, "orbita", "db", 10, 0, ""))
	cases := map[string]func(d *workloadDockerStub){
		"демон недоступен": func(d *workloadDockerStub) {
			d.respond("ps", "", "Cannot connect to the Docker daemon at unix:///run/tracedocs/docker.sock. Is the docker daemon running?\n", 1)
		},
		"список не из id": func(d *workloadDockerStub) {
			d.respond("ps", "WARNING: something\n"+id1+"\n", "", 0)
		},
		"прокси отказал в inspect": func(d *workloadDockerStub) {
			d.respond("container-inspect", running, "Error response from daemon: 403 Forbidden\n", 1)
		},
		"пропажа вперемешку с отказом": func(d *workloadDockerStub) {
			d.respond("container-inspect", running, "Error response from daemon: No such container: "+id2+"\npermission denied\n", 1)
		},
		"отказ без текста": func(d *workloadDockerStub) {
			d.respond("container-inspect", running, "", 1)
		},
		"вывод inspect не JSON": func(d *workloadDockerStub) {
			d.respond("container-inspect", "not json", "", 0)
		},
		"список томов не прочитан": func(d *workloadDockerStub) {
			d.respond("volume-ls", "", "Error response from daemon: 403 Forbidden\n", 1)
		},
		"inspect тома отказал": func(d *workloadDockerStub) {
			d.respond("volume-inspect", "[]", "Error response from daemon: 403 Forbidden\n", 1)
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			d := installWorkloadDocker(t)
			d.host([]string{id1, id2}, running, []string{"a"}, workloadInspectArray(workloadVolumeJSON("a", "local", "", "/v/a")))
			breakIt(d)
			if s, err := workloadTestCollector(t).collect(context.Background(), testWorkloadStart); err == nil {
				t.Fatalf("выборка выдана при отказе: %+v", s)
			}
		})
	}
}

func TestWorkloadInspectEmptyHost(t *testing.T) {
	d := installWorkloadDocker(t)
	d.host(nil, "", nil, "")

	s := workloadCollect(t, workloadTestCollector(t))
	if s.Containers == nil || s.Volumes == nil || len(s.Containers)+len(s.Volumes) != 0 {
		t.Fatalf("пустой хост: %+v", s)
	}
	if d.count("container inspect") != 0 || d.count("volume inspect") != 0 {
		t.Fatalf("inspect без списка: %q", d.calls())
	}
}

// Зависший docker не держит выборку дольше её срока.
func TestWorkloadInspectHonoursContext(t *testing.T) {
	installWorkloadDocker(t).host(nil, "", nil, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := workloadTestCollector(t).collect(ctx, time.Now()); err == nil {
		t.Fatal("выборка по отменённому контексту")
	}
}
