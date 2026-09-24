package agent

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Поконтейнерные сигналы cgroup v2 (ADR-0091, решение 3).
//
// Файлы группы читаются напрямую, а не через статистику Docker: её запрещает
// ADR-0066 (решение 4), и она держит запрос два цикла сбора. Агенту без root
// файлы группы чужого контейнера открыты (0444, memory.max — 0644), а
// /proc/<pid>/cgroup — тоже; прав агенту это не добавляет (ADR-0083).

// CgroupStats — сигналы группы одного контейнера. Имена полей повторяют блок
// `cgroup` секции workloads (packages/server-monitoring/src/workloads.ts).
//
// nil в поле при Status "ok" — «этого файла или ключа у группы нет»:
// контроллер не включён, либо значение не число. У MemoryMaxBytes nil при ok
// значит предел «max» — так его и читает контракт.
type CgroupStats struct {
	Status, Reason string

	MemoryBytes, MemoryMaxBytes, OOMKills, CPUUsageUsec, CPUNrThrottled, Pids *int64
}

// jsonSafeIntMax — наибольшее целое, которое JSON.parse на платформе примет
// без округления. Контракт секции отвергает число выше целиком, вместе со
// всеми контейнерами хоста, поэтому читатели сигналов такое число не отдают.
const jsonSafeIntMax int64 = 1<<53 - 1

func cgroupUnavailable(reason string) CgroupStats {
	return CgroupStats{Status: "unavailable", Reason: reason}
}

// ReadContainerCgroup читает сигналы группы процесса pid.
//
// procRoot и cgroupRoot — /proc и /sys/fs/cgroup на хосте; параметрами они
// потому, что тесты гоняются не на Linux.
func ReadContainerCgroup(procRoot, cgroupRoot string, pid int) CgroupStats {
	if pid <= 0 {
		return cgroupUnavailable("not_running")
	}

	// Корень без cgroup.controllers — v1 или гибрид: строка 0:: в файле
	// процесса у гибрида есть, но контроллеры памяти и процессора смонтированы
	// в v1, и в единой иерархии их файлов нет. «Нет данных», а не пропуск:
	// ADR-0066 (решение 5) не даёт выдавать отсутствие сигнала за норму.
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cgroupUnavailable("cgroup_v1")
		}
		return cgroupUnavailable("read_failed")
	}

	raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return cgroupUnavailable(cgroupReadFailure(err))
	}
	rel, ok := cgroupUnifiedPath(raw)
	if !ok {
		return cgroupUnavailable("cgroup_path_unknown")
	}

	dir := filepath.Join(cgroupRoot, rel)
	if _, err := os.Stat(dir); err != nil {
		// Процесс завершился между двумя чтениями: группу уже убрали, а путь
		// в его файле ядро помечает « (deleted)» — такого каталога нет.
		return cgroupUnavailable(cgroupReadFailure(err))
	}

	s := CgroupStats{Status: "ok"}
	s.MemoryBytes = cgroupReadValue(dir, "memory.current")
	// «max» числом не разбирается и остаётся nil — ровно то, что контракт
	// читает как «без предела».
	s.MemoryMaxBytes = cgroupReadValue(dir, "memory.max")
	s.Pids = cgroupReadValue(dir, "pids.current")

	events := cgroupReadKeyed(dir, "memory.events")
	// oom_kill, а не oom: oom считает вызовы OOM в группе, и убитых процессов
	// за ними могло не быть.
	s.OOMKills = cgroupValue(events["oom_kill"])

	// usage_usec в cpu.stat есть всегда, а nr_throttled — только при
	// включённом контроллере cpu; поэтому nil по ключу, а не по файлу.
	cpu := cgroupReadKeyed(dir, "cpu.stat")
	s.CPUUsageUsec = cgroupValue(cpu["usage_usec"])
	s.CPUNrThrottled = cgroupValue(cpu["nr_throttled"])
	return s
}

// cgroupUnifiedPath — путь группы из строки «0::<path>».
//
// Только отсюда, а не выводом из драйвера cgroup Docker: драйвер и
// вложенность меняют раскладку, а файл процесса — ответ ядра о том, где
// процесс на самом деле. Строки v1-иерархий, включая именованную
// name=systemd, указывают в другие деревья и не годятся даже как догадка.
func cgroupUnifiedPath(raw []byte) (string, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		path, found := strings.CutPrefix(line, "0::")
		if !found {
			continue
		}
		// Корневая группа — это весь хост, а процесс вне пространства имён
		// cgroup читающего ядро показывает через «/..»: ни то, ни другое не
		// данные контейнера, а filepath.Join вывел бы «..» за cgroupRoot.
		if !strings.HasPrefix(path, "/") || path == "/" {
			return "", false
		}
		for _, part := range strings.Split(path, "/") {
			if part == ".." {
				return "", false
			}
		}
		return path, true
	}
	return "", false
}

// cgroupReadFailure отличает ушедший процесс от отказа чтения: первое —
// обычное состояние остановленного контейнера, второе — поломка, которую
// нельзя показывать как «не работает».
func cgroupReadFailure(err error) string {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return "not_running"
	}
	return "read_failed"
}

func cgroupReadValue(dir, name string) *int64 {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil
	}
	return cgroupValue(string(bytes.TrimSpace(raw)))
}

// cgroupReadKeyed разбирает плоский файл «ключ значение» (memory.events,
// cpu.stat). Нет файла — пустой набор, и каждое поле из него станет nil.
func cgroupReadKeyed(dir, name string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if key, value, ok := strings.Cut(sc.Text(), " "); ok {
			out[key] = value
		}
	}
	return out
}

func cgroupValue(s string) *int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 || v > jsonSafeIntMax {
		return nil
	}
	return &v
}
