package agent

import (
	"errors"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

const volumeTestDir = "/var/lib/docker/volumes/orbita_pgdata/_data"

func TestMountinfoParsesEscapedFields(t *testing.T) {
	raw := "" +
		"22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,errors=remount-ro\n" +
		// Необязательных полей может не быть вовсе…
		"31 22 0:27 / /mnt/my\\040disk rw,nosuid - ext4 /dev/sdb\\0401 rw\n" +
		// …или быть несколько.
		"32 22 252:17 /srv/tab\\011and\\012nl /var/lib/back\\134slash rw shared:7 master:3 propagate_from:2 - xfs /dev/vdb rw\n"

	got, err := ParseMountinfo(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := []MountInfoEntry{
		{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"},
		{MountPoint: "/mnt/my disk", Root: "/", FSType: "ext4", Source: "/dev/sdb 1"},
		{MountPoint: "/var/lib/back\\slash", Root: "/srv/tab\tand\nnl", FSType: "xfs", Source: "/dev/vdb"},
	}
	if len(got) != len(want) {
		t.Fatalf("записей %d, ожидалось %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("запись %d: %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
}

// Пропущенная строка сдвинула бы покрывающую точку на родителя, и том получил
// бы заполненность чужой файловой системы. Поэтому непонятная строка — ошибка
// разбора целиком, а не молчаливый пропуск.
func TestMountinfoRejectsMalformedLine(t *testing.T) {
	for _, line := range []string{
		"22 1 252:1 / / rw,relatime shared:1 ext4 /dev/vda1 rw", // нет разделителя
		"22 1 252:1 / / - ext4 /dev/vda1 rw",                    // разделитель раньше опций
		"22 1 252:1 / / rw,relatime -",                          // нет типа и источника
		"22 1 252:1 / relative rw,relatime - ext4 /dev/vda1 rw", // точка не абсолютна
	} {
		if _, err := ParseMountinfo(strings.NewReader(line + "\n")); err == nil {
			t.Fatalf("строка %q разобрана без ошибки", line)
		}
	}
}

func TestMountinfoCoveringMountLongestPrefixByComponent(t *testing.T) {
	entries := []MountInfoEntry{
		{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"},
		{MountPoint: "/var/lib/docker2", Root: "/", FSType: "xfs", Source: "/dev/vdc"},
		{MountPoint: "/var/lib/docker", Root: "/", FSType: "xfs", Source: "/dev/vdb"},
		{MountPoint: "/var/lib/docker/volumes/other/_data", Root: "/", FSType: "nfs", Source: "nas:/x"},
	}
	cases := map[string]string{
		volumeTestDir:                                "/var/lib/docker",
		"/var/lib/docker":                            "/var/lib/docker",
		"/var/lib/docker2/volumes/x/_data":           "/var/lib/docker2",
		"/var/lib/dockerx/volumes/x/_data":           "/",
		"/var/lib/docker/volumes/other/_data/nested": "/var/lib/docker/volumes/other/_data",
		"/var/lib/docker/volumes/other/_data2":       "/var/lib/docker",
		"/":                                          "/",
	}
	for path, want := range cases {
		got, ok := CoveringMount(entries, path)
		if !ok || got.MountPoint != want {
			t.Fatalf("%s: покрывает %q (ok=%v), ожидалось %q", path, got.MountPoint, ok, want)
		}
	}
	if _, ok := CoveringMount(entries, "relative/path"); ok {
		t.Fatal("относительный путь получил покрывающую точку")
	}
	if _, ok := CoveringMount(nil, volumeTestDir); ok {
		t.Fatal("пустой mountinfo дал покрывающую точку")
	}
}

// Две записи на одной точке — наложенное монтирование: видна последняя,
// предыдущая спрятана под ней.
func TestMountinfoCoveringMountPrefersTopOfStack(t *testing.T) {
	entries := []MountInfoEntry{
		{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"},
		{MountPoint: "/var/lib/docker", Root: "/", FSType: "ext4", Source: "/dev/old"},
		{MountPoint: "/var/lib/docker", Root: "/", FSType: "xfs", Source: "/dev/new"},
	}
	got, ok := CoveringMount(entries, volumeTestDir)
	if !ok || got.Source != "/dev/new" {
		t.Fatalf("покрывает %+v, ожидалась верхняя запись /dev/new", got)
	}
}

type volumeStatfsCall struct {
	paths []string
}

func (c *volumeStatfsCall) fn(total, avail int64, err error) func(string) (int64, int64, error) {
	return func(path string) (int64, int64, error) {
		c.paths = append(c.paths, path)
		return total, avail, err
	}
}

func volumeWantOK(t *testing.T, got VolumeFsStats, total, avail int64) {
	t.Helper()
	if got.Status != "ok" || got.Reason != "" {
		t.Fatalf("статус %q/%q, ожидалось ok", got.Status, got.Reason)
	}
	if got.TotalBytes == nil || got.AvailBytes == nil || got.UsedBytes == nil {
		t.Fatalf("при ok пустое поле: %+v", got)
	}
	if *got.TotalBytes != total || *got.AvailBytes != avail || *got.UsedBytes != total-avail {
		t.Fatalf("заполненность %d/%d/%d, ожидалось %d/%d/%d",
			*got.TotalBytes, *got.AvailBytes, *got.UsedBytes, total, avail, total-avail)
	}
}

func volumeWantUnavailable(t *testing.T, got VolumeFsStats, reason string) {
	t.Helper()
	if got.Status != "unavailable" || got.Reason != reason {
		t.Fatalf("статус %q/%q, ожидалось unavailable/%s", got.Status, got.Reason, reason)
	}
	if got.TotalBytes != nil || got.AvailBytes != nil || got.UsedBytes != nil {
		t.Fatalf("при unavailable отданы цифры: %+v", got)
	}
}

// Обычный local-том лежит на ФС покрывающей точки. statfs идёт по точке
// монтирования, а не по каталогу тома: /var/lib/docker — 0710, и агенту без
// root путь внутрь закрыт, а сама точка открыта.
func TestVolumeFsStatfsOfCoveringMount(t *testing.T) {
	entries := []MountInfoEntry{
		{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"},
		// /var/lib/docker — привязка каталога с другого диска: root ≠ «/».
		{MountPoint: "/var/lib/docker", Root: "/srv/docker", FSType: "xfs", Source: "/dev/vdb"},
	}
	var call volumeStatfsCall
	got := VolumeUsage(entries, volumeTestDir, "local", false, call.fn(100_000, 61_000, nil))

	volumeWantOK(t, got, 100_000, 61_000)
	if len(call.paths) != 1 || call.paths[0] != "/var/lib/docker" {
		t.Fatalf("statfs звался по %v, ожидалось [/var/lib/docker]", call.paths)
	}
}

// Том — своя ФС или привязка прямо на каталог тома: statfs точки монтирования
// и есть statfs каталога тома, а он без root закрыт.
func TestVolumeFsOwnFilesystemRequiresRoot(t *testing.T) {
	entries := []MountInfoEntry{
		{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"},
		{MountPoint: volumeTestDir, Root: "/exports/media", FSType: "ext4", Source: "/dev/vdc"},
	}

	var unpriv volumeStatfsCall
	got := VolumeUsage(entries, volumeTestDir, "local", false, unpriv.fn(1, 1, nil))
	volumeWantUnavailable(t, got, "own_fs_requires_root")
	if len(unpriv.paths) != 0 {
		t.Fatalf("без root statfs всё равно звался: %v", unpriv.paths)
	}

	var root volumeStatfsCall
	got = VolumeUsage(entries, volumeTestDir+"/", "local", true, root.fn(500_000, 20_000, nil))
	volumeWantOK(t, got, 500_000, 20_000)
	if len(root.paths) != 1 || root.paths[0] != volumeTestDir {
		t.Fatalf("под root statfs звался по %v, ожидалось по каталогу тома", root.paths)
	}
}

// Отдельная ФС глубже /var/lib/docker (скажем, /var/lib/docker/volumes на
// своём диске): точку монтирования агент без root не видит, и отказ ядра —
// та же причина, что у тома на своей ФС, а не безымянная ошибка.
func TestVolumeFsPermissionDeniedWithoutRoot(t *testing.T) {
	entries := []MountInfoEntry{
		{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"},
		{MountPoint: "/var/lib/docker/volumes", Root: "/", FSType: "xfs", Source: "/dev/vdd"},
	}
	denied := &fs.PathError{Op: "statfs", Path: "/var/lib/docker/volumes", Err: syscall.EACCES}

	var call volumeStatfsCall
	got := VolumeUsage(entries, volumeTestDir, "local", false, call.fn(0, 0, denied))
	volumeWantUnavailable(t, got, "own_fs_requires_root")

	got = VolumeUsage(entries, volumeTestDir, "local", true, call.fn(0, 0, denied))
	volumeWantUnavailable(t, got, "statfs_failed")
}

func TestVolumeFsDriverNotLocal(t *testing.T) {
	entries := []MountInfoEntry{{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"}}
	var call volumeStatfsCall
	got := VolumeUsage(entries, volumeTestDir, "example/sshfs:latest", true, call.fn(1, 1, nil))

	volumeWantUnavailable(t, got, "driver_not_local")
	if len(call.paths) != 0 {
		t.Fatalf("для стороннего драйвера звался statfs: %v", call.paths)
	}
}

func TestVolumeFsStatfsError(t *testing.T) {
	entries := []MountInfoEntry{{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"}}
	var call volumeStatfsCall
	got := VolumeUsage(entries, volumeTestDir, "local", false, call.fn(0, 0, errors.New("input/output error")))
	volumeWantUnavailable(t, got, "statfs_failed")
}

// Ответ statfs, который нельзя отдать: пустая ФС читалась бы как «занято 0 из
// 0», переполнение блоков на размер — как отрицательный объём, а число выше
// 2^53−1 контракт отвергает вместе со всей секцией.
func TestVolumeFsStatfsOutOfRange(t *testing.T) {
	entries := []MountInfoEntry{{MountPoint: "/", Root: "/", FSType: "ext4", Source: "/dev/vda1"}}
	cases := map[string][2]int64{
		"пустая ФС":             {0, 0},
		"отрицательный объём":   {-4096, 0},
		"свободно больше всего": {100, 101},
		"отрицательно свободно": {100, -1},
		"выше 2^53−1":           {1 << 60, 1 << 59},
	}
	for name, c := range cases {
		var call volumeStatfsCall
		got := VolumeUsage(entries, volumeTestDir, "local", false, call.fn(c[0], c[1], nil))
		if got.Status != "unavailable" || got.Reason != "statfs_invalid" {
			t.Fatalf("%s: статус %q/%q, ожидалось unavailable/statfs_invalid", name, got.Status, got.Reason)
		}
	}
}

func TestVolumeFsNoCoveringMount(t *testing.T) {
	var call volumeStatfsCall
	volumeWantUnavailable(t, VolumeUsage(nil, volumeTestDir, "local", true, call.fn(1, 1, nil)), "mount_not_found")
	volumeWantUnavailable(t, VolumeUsage([]MountInfoEntry{{MountPoint: "/", Root: "/"}}, "", "local", true, call.fn(1, 1, nil)), "mount_not_found")
	if len(call.paths) != 0 {
		t.Fatalf("без покрывающей точки звался statfs: %v", call.paths)
	}
}
