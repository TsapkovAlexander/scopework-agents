package agent

import "syscall"

// freeBytes — сколько свободно на файловой системе, где лежит путь.
//
// Через syscall из стандартной библиотеки, без внешних зависимостей: у агента
// их нет вовсе, и заводить одну ради одного вызова незачем.
//
// Берётся Bavail, а не Bfree: Bfree включает блоки, зарезервированные под
// root, и на почти полном диске давал бы обнадёживающе большое число, тогда
// как запись обычным процессом уже не проходит.
func freeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
