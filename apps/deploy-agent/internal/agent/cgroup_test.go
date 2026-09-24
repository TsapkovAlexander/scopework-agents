package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// Файлы cgroup v2 чужого контейнера на тестовой машине не прочитать, поэтому
// раскладка /proc и /sys/fs/cgroup собирается во временном каталоге.

const cgroupTestScope = "/system.slice/docker-1cf48d6c97398c2ab33dd6da957b5e7424d036cfddd9d14e1a721b888b6512b5.scope"

type cgroupFixture struct {
	proc, root string
}

func newCgroupFixture(t *testing.T, v2 bool) cgroupFixture {
	t.Helper()
	f := cgroupFixture{proc: t.TempDir(), root: t.TempDir()}
	if v2 {
		writeCgroupFile(t, filepath.Join(f.root, "cgroup.controllers"), "cpuset cpu io memory hugetlb pids rdma misc\n")
	}
	return f
}

func writeCgroupFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f cgroupFixture) process(t *testing.T, pid, content string) {
	t.Helper()
	writeCgroupFile(t, filepath.Join(f.proc, pid, "cgroup"), content)
}

func (f cgroupFixture) scope(t *testing.T, rel string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(f.root, rel)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		writeCgroupFile(t, filepath.Join(dir, name), content)
	}
}

func cgroupScopeFiles() map[string]string {
	return map[string]string{
		"memory.current": "412385280\n",
		"memory.max":     "1073741824\n",
		"memory.events":  "low 0\nhigh 0\nmax 17\noom 3\noom_kill 2\noom_group_kill 0\n",
		"cpu.stat": "usage_usec 8812345678\nuser_usec 6000000000\nsystem_usec 2812345678\n" +
			"nr_periods 5000\nnr_throttled 12\nthrottled_usec 99000\n",
		"pids.current": "23\n",
	}
}

func cgroupWant(t *testing.T, name string, got *int64, want int64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: nil, ожидалось %d", name, want)
	}
	if *got != want {
		t.Fatalf("%s: %d, ожидалось %d", name, *got, want)
	}
}

func TestCgroupReadsAllSignals(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+"\n")
	f.scope(t, cgroupTestScope, cgroupScopeFiles())

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.Status != "ok" || got.Reason != "" {
		t.Fatalf("статус %q/%q, ожидалось ok без причины", got.Status, got.Reason)
	}
	cgroupWant(t, "memory.current", got.MemoryBytes, 412385280)
	cgroupWant(t, "memory.max", got.MemoryMaxBytes, 1073741824)
	// oom_kill, а не max и не oom: max — сколько раз упёрлись в предел, oom —
	// сколько раз вызывался OOM, убитых процессов из них могло не быть.
	cgroupWant(t, "oom_kill", got.OOMKills, 2)
	cgroupWant(t, "usage_usec", got.CPUUsageUsec, 8812345678)
	cgroupWant(t, "nr_throttled", got.CPUNrThrottled, 12)
	cgroupWant(t, "pids.current", got.Pids, 23)
}

// Путь берётся только из строки 0:: — ответа ядра о том, где процесс на самом
// деле. Пути v1-иерархий и именованной name=systemd указывают в другое дерево.
func TestCgroupPathOnlyFromUnifiedLine(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242",
		"12:pids:/docker/wrong\n"+
			"4:memory:/docker/wrong\n"+
			"1:name=systemd:/docker/wrong\n"+
			"0::"+cgroupTestScope+"\n")
	f.scope(t, "/docker/wrong", map[string]string{"memory.current": "1\n"})
	f.scope(t, cgroupTestScope, cgroupScopeFiles())

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	cgroupWant(t, "memory.current", got.MemoryBytes, 412385280)
}

func TestCgroupNoUnifiedLineIsNotGuessed(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "4:memory:/docker/abc\n1:name=systemd:/docker/abc\n")
	f.scope(t, "/docker/abc", map[string]string{"memory.current": "1\n"})

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.Status != "unavailable" || got.Reason != "cgroup_path_unknown" {
		t.Fatalf("статус %q/%q, ожидалось unavailable/cgroup_path_unknown", got.Status, got.Reason)
	}
	if got.MemoryBytes != nil {
		t.Fatal("значение прочитано по пути v1-иерархии")
	}
}

// Процесс вне пространства имён cgroup читающего ядро показывает через «/..»,
// а корневая группа — это весь хост: ни то, ни другое не данные контейнера.
func TestCgroupRejectsPathsOutsideContainer(t *testing.T) {
	for _, path := range []string{"/", "/../../system.slice/x.scope", "relative/x.scope"} {
		f := newCgroupFixture(t, true)
		f.process(t, "4242", "0::"+path+"\n")
		writeCgroupFile(t, filepath.Join(f.root, "memory.current"), "999\n")

		got := ReadContainerCgroup(f.proc, f.root, 4242)
		if got.Status != "unavailable" || got.Reason != "cgroup_path_unknown" {
			t.Fatalf("путь %q: статус %q/%q, ожидалось cgroup_path_unknown", path, got.Status, got.Reason)
		}
	}
}

// Гибридный режим: строка 0:: есть, но контроллеры смонтированы v1 — в
// единой иерархии нет ни памяти, ни процессора. Это «нет данных», а не нули.
func TestCgroupV1WhenRootHasNoControllers(t *testing.T) {
	f := newCgroupFixture(t, false)
	f.process(t, "4242", "4:memory:/docker/abc\n1:name=systemd:/docker/abc\n0::/docker/abc\n")
	f.scope(t, "/docker/abc", cgroupScopeFiles())

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.Status != "unavailable" || got.Reason != "cgroup_v1" {
		t.Fatalf("статус %q/%q, ожидалось unavailable/cgroup_v1", got.Status, got.Reason)
	}
	if got.MemoryBytes != nil || got.CPUUsageUsec != nil || got.Pids != nil {
		t.Fatalf("на cgroup v1 отданы значения: %+v", got)
	}
}

func TestCgroupMemoryMaxUnlimitedIsNil(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+"\n")
	files := cgroupScopeFiles()
	files["memory.max"] = "max\n"
	f.scope(t, cgroupTestScope, files)

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.Status != "ok" {
		t.Fatalf("статус %q, ожидалось ok", got.Status)
	}
	if got.MemoryMaxBytes != nil {
		t.Fatalf("memory.max=max прочитан как %d", *got.MemoryMaxBytes)
	}
}

// Контракт секции отвергает её целиком на числе выше 2^53−1. Предел памяти
// такого размера — фактически «без предела», и он не должен ронять секцию.
func TestCgroupValueBeyondJSONRangeIsNil(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+"\n")
	files := cgroupScopeFiles()
	files["memory.max"] = "9223372036854771712\n"
	f.scope(t, cgroupTestScope, files)

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.MemoryMaxBytes != nil {
		t.Fatalf("memory.max за пределом JSON прочитан как %d", *got.MemoryMaxBytes)
	}
	cgroupWant(t, "memory.current", got.MemoryBytes, 412385280)
}

// Контроллер не включён для группы — его файлов нет. Остальные сигналы при
// этом настоящие, поэтому статус ok, а пропавшее поле — nil.
func TestCgroupMissingControllerFileIsNilField(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+"\n")
	files := cgroupScopeFiles()
	delete(files, "pids.current")
	// Без контроллера cpu в cpu.stat остаются только базовые ключи.
	files["cpu.stat"] = "usage_usec 500\nuser_usec 300\nsystem_usec 200\n"
	f.scope(t, cgroupTestScope, files)

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.Status != "ok" {
		t.Fatalf("статус %q, ожидалось ok", got.Status)
	}
	if got.Pids != nil {
		t.Fatalf("pids без файла: %d", *got.Pids)
	}
	if got.CPUNrThrottled != nil {
		t.Fatalf("nr_throttled без ключа: %d", *got.CPUNrThrottled)
	}
	cgroupWant(t, "usage_usec", got.CPUUsageUsec, 500)
	cgroupWant(t, "memory.current", got.MemoryBytes, 412385280)
}

func TestCgroupGarbageValueIsNil(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+"\n")
	files := cgroupScopeFiles()
	files["memory.current"] = "много\n"
	files["pids.current"] = "-3\n"
	f.scope(t, cgroupTestScope, files)

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.MemoryBytes != nil || got.Pids != nil {
		t.Fatalf("мусор прочитан как число: %+v", got)
	}
}

func TestCgroupNotRunning(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+"\n")
	f.scope(t, cgroupTestScope, cgroupScopeFiles())

	cases := map[string]int{"pid 0": 0, "отрицательный pid": -1, "процесса нет": 5151}
	for name, pid := range cases {
		got := ReadContainerCgroup(f.proc, f.root, pid)
		if got.Status != "unavailable" || got.Reason != "not_running" {
			t.Fatalf("%s: статус %q/%q, ожидалось unavailable/not_running", name, got.Status, got.Reason)
		}
	}
}

// Процесс завершился между чтением /proc и чтением группы: ядро уже убрало
// каталог (или пометило путь « (deleted)»).
func TestCgroupScopeGoneIsNotRunning(t *testing.T) {
	f := newCgroupFixture(t, true)
	f.process(t, "4242", "0::"+cgroupTestScope+" (deleted)\n")

	got := ReadContainerCgroup(f.proc, f.root, 4242)
	if got.Status != "unavailable" || got.Reason != "not_running" {
		t.Fatalf("статус %q/%q, ожидалось unavailable/not_running", got.Status, got.Reason)
	}
}
