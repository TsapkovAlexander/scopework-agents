//go:build !linux

package agent

import "errors"

// readFileFlags — вне Linux атрибутов inode в этом смысле нет: агент на
// сервере работает только под Linux, здесь — сборка для разработки.
func readFileFlags(string) (uint32, error) {
	return 0, errors.New("флаги файла читаются только в Linux")
}
