package agent

import (
	"strings"
	"sync"
	"testing"
)

// Буфер хвоста — единственное место, где живёт вывод работающей команды.
// Ошибись он в обрезке, прогресс показывал бы начало десятиминутного pull
// вместо происходящего сейчас, а рост без предела удерживал бы мегабайты
// вывода в памяти агента на чужом хосте.

func TestTailBufferKeepsOnlyTail(t *testing.T) {
	b := newTailBuffer(10)

	if _, err := b.Write([]byte("0123456789ABCDEF")); err != nil {
		t.Fatal(err)
	}
	if got := b.Tail(); got != "6789ABCDEF" {
		t.Fatalf("хвост %q, ожидалось %q", got, "6789ABCDEF")
	}

	// Дозапись вытесняет старое, а не дописывается к нему.
	if _, err := b.Write([]byte("xyz")); err != nil {
		t.Fatal(err)
	}
	if got := b.Tail(); got != "9ABCDEFxyz" {
		t.Fatalf("хвост после дозаписи %q, ожидалось %q", got, "9ABCDEFxyz")
	}
}

func TestTailBufferShortWritesAccumulate(t *testing.T) {
	b := newTailBuffer(100)
	for i := 0; i < 5; i++ {
		if _, err := b.Write([]byte("ab")); err != nil {
			t.Fatal(err)
		}
	}
	if got := b.Tail(); got != strings.Repeat("ab", 5) {
		t.Fatalf("накопление сломано: %q", got)
	}
}

// В буфер одновременно пишут stdout и stderr команды, читает тикер прогресса.
// Гонка здесь — это порча вывода, который уезжает на сервер; тест существует,
// чтобы её ловил -race.
func TestTailBufferConcurrentAccess(t *testing.T) {
	b := newTailBuffer(64)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _ = b.Write([]byte("line\n"))
				_ = b.Tail()
			}
		}()
	}
	wg.Wait()

	if got := len(b.Tail()); got > 64 {
		t.Fatalf("хвост длиннее предела: %d", got)
	}
}
