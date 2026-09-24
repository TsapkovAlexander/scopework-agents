//go:build linux

package agent

import (
	"os"
	"syscall"
	"unsafe"
)

// fsIocGetflags — FS_IOC_GETFLAGS = _IOR('f', 1, long) из
// include/uapi/linux/fs.h; значение для 64-разрядных сборок (amd64, arm64 —
// других агент не собирает): 0x80086601.
const fsIocGetflags = 0x80086601

// readFileFlags — флаги inode, как их показывает lsattr.
//
// Буфер восьмибайтный: макрос объявлен через long, а ядро пишет int. В
// восемь байт влезает и то, и другое, и на little-endian младшие четыре байта
// — ровно флаги; четырёхбайтный буфер при записи long испортил бы память.
func readFileFlags(path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var flags uint64
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), fsIocGetflags,
		uintptr(unsafe.Pointer(&flags))); errno != 0 {
		// ENOTTY и EOPNOTSUPP — ФС атрибутов не знает: «определить нельзя».
		return 0, errno
	}
	return uint32(flags), nil
}
