package composeguard

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Путь привязки глазами ядра. Общий для политики compose (IsPathAllowedIn) и
// прокси сокета Docker агента (checkBindSource): разойдись они — стек проходил
// бы проверку текста и падал на прокси посреди выката, а в режиме без прокси
// монтировал бы то, что проверка текста сочла своим каталогом.

// HasDotDotSegment — есть ли в пути сегмент `..`: между разделителями, в
// начале или в конце. Подстрока не в счёт: `a..b` — законное имя каталога.
func HasDotDotSegment(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// ResolveBindPath — путь, каким его увидит ядро: ссылки раскрыты в самой
// длинной существующей части, несуществующий хвост приклеен как есть.
//
// ПОЧЕМУ ПРЕФИКС, А НЕ ВЕСЬ ПУТЬ. Отсутствующий источник из Binds Docker
// создаёт сам, и EvalSymlinks на нём вернул бы ошибку — законная привязка к
// ещё не созданному каталогу получила бы ложный отказ.
//
// ПОЧЕМУ ВИСЯЧАЯ ССЫЛКА — ОШИБКА. Если запись на диске есть, а раскрыть её
// нельзя (ссылка в никуда, петля, нечитаемый каталог), куда ведёт путь,
// неизвестно. А Docker создаст отсутствующий источник через MkdirAll, пройдя по
// висячей ссылке НАРУЖУ: ссылка на несуществующий
// `/etc/systemd/system/x.service.d` — и контейнер пишет туда override от root.
func ResolveBindPath(p string) (string, error) {
	cur := filepath.Clean(p)
	var rest []string // хвост, которого нет на диске, от ближнего к дальнему
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			parts := []string{resolved}
			for i := len(rest) - 1; i >= 0; i-- {
				parts = append(parts, rest[i])
			}
			return filepath.Join(parts...), nil
		}
		if _, lerr := os.Lstat(cur); lerr == nil || !errors.Is(lerr, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
}
