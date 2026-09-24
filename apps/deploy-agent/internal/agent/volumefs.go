package agent

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
)

// Заполненность файловой системы, на которой лежит том (ADR-0091, решение 3).
//
// Считается заполненность носителя, а не размер тома: ADR-0066 спрашивает,
// кончится ли место у состояния. Без du и обхода каталога — это дорого на
// больших томах, — и без /system/df, который прокси сокета закрывает.

// MountInfoEntry — строка /proc/<pid>/mountinfo, поля без экранирования.
// Root — какой каталог исходной ФС смонтирован: у привязки он не «/».
type MountInfoEntry struct {
	MountPoint, Root, FSType, Source string
}

// VolumeFsStats — блок заполненности тома секции workloads.
type VolumeFsStats struct {
	Status, Reason                    string
	TotalBytes, AvailBytes, UsedBytes *int64
}

// ParseMountinfo разбирает mountinfo (proc(5)).
//
// Непонятная строка — ошибка разбора целиком, а не пропуск: без неё
// покрывающей стала бы точка родителя, и том получил бы заполненность чужой
// файловой системы.
func ParseMountinfo(r io.Reader) ([]MountInfoEntry, error) {
	var out []MountInfoEntry
	sc := bufio.NewScanner(r)
	// Строка оверлея несёт в опциях все нижние слои, и у образа со многими
	// слоями она длиннее 64 КиБ, на которых Scanner останавливается по умолчанию.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		e, ok := mountinfoParseLine(line)
		if !ok {
			return nil, fmt.Errorf("mountinfo, строка %d: неизвестный формат", n)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("mountinfo: %w", err)
	}
	return out, nil
}

// mountinfoParseLine: «id parent major:minor root mountpoint options
// [необязательные поля…] - fstype source superoptions». Необязательных полей
// может быть сколько угодно, поэтому тип и источник ищутся за разделителем.
func mountinfoParseLine(line string) (MountInfoEntry, bool) {
	fields := strings.Fields(line)
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || len(fields) < sep+3 {
		return MountInfoEntry{}, false
	}
	e := MountInfoEntry{
		Root:       mountinfoUnescape(fields[3]),
		MountPoint: mountinfoUnescape(fields[4]),
		FSType:     mountinfoUnescape(fields[sep+1]),
		Source:     mountinfoUnescape(fields[sep+2]),
	}
	if !strings.HasPrefix(e.MountPoint, "/") {
		return MountInfoEntry{}, false
	}
	return e, true
}

// mountinfoUnescape снимает восьмеричное экранирование ядра: пробел, таб,
// перевод строки и обратная косая печатаются как \040, \011, \012, \134.
func mountinfoUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && mountinfoIsOctal(s[i+1:i+4]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func mountinfoIsOctal(s string) bool {
	if len(s) != 3 || s[0] > '3' {
		return false
	}
	for i := 0; i < 3; i++ {
		if s[i] < '0' || s[i] > '7' {
			return false
		}
	}
	return true
}

// CoveringMount — точка монтирования, на ФС которой лежит path: самый
// длинный префикс по границе компонента пути (/var/lib/docker2 не покрывает
// /var/lib/docker/…). При равной длине берётся последняя запись: наложенное
// монтирование прячет предыдущее под собой.
func CoveringMount(entries []MountInfoEntry, path string) (MountInfoEntry, bool) {
	if !strings.HasPrefix(path, "/") {
		return MountInfoEntry{}, false
	}
	path = filepath.Clean(path)
	var best MountInfoEntry
	found := false
	for _, e := range entries {
		mp := e.MountPoint
		covers := mp == "/" || path == mp || strings.HasPrefix(path, mp+"/")
		if covers && (!found || len(mp) >= len(best.MountPoint)) {
			best, found = e, true
		}
	}
	return best, found
}

func volumeUnavailable(reason string) VolumeFsStats {
	return VolumeFsStats{Status: "unavailable", Reason: reason}
}

// VolumeUsage — заполненность ФС тома volumeDir (Mountpoint из inspect тома).
//
// statfs идёт по покрывающей точке монтирования, а не по каталогу тома:
// /var/lib/docker — 0710, агенту без root путь внутрь закрыт, а statfs самой
// точки (/ или /var/lib/docker) открыт и отвечает про ту же ФС. Если точка —
// сам каталог тома (том — своя ФС или привязка на этот каталог), statfs
// возможен только под root; прокси для этого не расширяется (ADR-0091,
// альтернатива «з»).
func VolumeUsage(entries []MountInfoEntry, volumeDir, driver string, isRoot bool,
	statfs func(string) (int64, int64, error)) VolumeFsStats {
	if driver != "local" {
		return volumeUnavailable("driver_not_local")
	}
	m, ok := CoveringMount(entries, volumeDir)
	if !ok {
		return volumeUnavailable("mount_not_found")
	}

	if m.MountPoint == filepath.Clean(volumeDir) && !isRoot {
		return volumeUnavailable("own_fs_requires_root")
	}

	total, avail, err := statfs(m.MountPoint)
	if err != nil {
		// Отдельная ФС глубже /var/lib/docker (скажем, /var/lib/docker/volumes
		// на своём диске): точка закрыта без root так же, как каталог тома.
		if !isRoot && errors.Is(err, fs.ErrPermission) {
			return volumeUnavailable("own_fs_requires_root")
		}
		return volumeUnavailable("statfs_failed")
	}
	// Пустая ФС читалась бы как «занято 0 из 0», переполнение блоков на размер
	// — как отрицательный объём, а число выше 2^53−1 контракт отвергает вместе
	// со всей секцией.
	if total <= 0 || total > jsonSafeIntMax || avail < 0 || avail > total {
		return volumeUnavailable("statfs_invalid")
	}
	used := total - avail
	return VolumeFsStats{Status: "ok", TotalBytes: &total, AvailBytes: &avail, UsedBytes: &used}
}
