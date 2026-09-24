package main

import (
	"errors"
	"fmt"
	"testing"

	"tracedocs.ru/deploy-agent/internal/agent"
)

// Судьба агента на чужом хосте решается одним счётчиком, и цена ошибки в нём
// несимметрична: лишний круг ожидания стоит минуты, а преждевременный выход —
// выключенного хоста, который не поднимется сам (systemd не перезапускает
// код 3) и обнаружится по неработающему сайту.
//
// Так и произошло 2026-08-07: платформа была недоступна во время выката,
// агент получил отказ и остановился насовсем.

func TestDeniedStreakNeedsUnbrokenRun(t *testing.T) {
	streak := 0
	for i := 1; i <= deniedStreakLimit-1; i++ {
		streak = nextDeniedStreak(streak, agent.ErrUnauthorized)
		if streak >= deniedStreakLimit {
			t.Fatalf("остановка на %d отказе, а предел %d", i, deniedStreakLimit)
		}
	}

	// Один успешный проход посреди серии обнуляет её целиком: иначе редкие
	// одиночные отказы за сутки сложились бы в ложный «отзыв».
	if got := nextDeniedStreak(streak, nil); got != 0 {
		t.Fatalf("успех не обнулил счётчик: %d", got)
	}
}

func TestDeniedStreakStopsAtLimit(t *testing.T) {
	streak := 0
	for i := 0; i < deniedStreakLimit; i++ {
		streak = nextDeniedStreak(streak, agent.ErrUnauthorized)
	}
	if streak < deniedStreakLimit {
		t.Fatalf("после %d отказов подряд счётчик %d — отзыв не сработает никогда",
			deniedStreakLimit, streak)
	}
}

// Сетевой сбой — это отсутствие ответа, а не отказ. Приближать к остановке он
// не должен: сутки без связи с платформой закончились бы «отзывом» на ровном
// месте, хотя ни один сервер ничего про этот хост не говорил.
func TestNetworkErrorDoesNotCountAsDenial(t *testing.T) {
	streak := nextDeniedStreak(3, errors.New("dial tcp: connection refused"))
	if streak != 0 {
		t.Fatalf("сетевой сбой засчитан как отказ: %d", streak)
	}
}

// Отказ, завёрнутый в контекст (так его и возвращает tick), обязан опознаваться:
// сравнение по значению вместо errors.Is молча отключило бы всю защиту.
func TestWrappedUnauthorizedIsCounted(t *testing.T) {
	wrapped := fmt.Errorf("желаемое состояние: %w", agent.ErrUnauthorized)
	if got := nextDeniedStreak(1, wrapped); got != 2 {
		t.Fatalf("завёрнутый отказ не опознан: %d", got)
	}
}

// Расхождение часов не приближает агента к остановке.
//
// Свежий VPS без NTP уходит вперёд на десяток секунд. enroll подписи не несёт
// и проходит, а первый же подписанный запрос отвергался по метке времени —
// и на шестой минуте агент выходил с кодом 3, который systemd не
// перезапускает. Хост в панели оставался «active» и молчал навсегда.
func TestClockSkewDoesNotCountAsDenied(t *testing.T) {
	streak := 4
	if got := nextDeniedStreak(streak, agent.ErrClockSkew); got != 0 {
		t.Fatalf("расхождение часов засчитано отказом: серия %d", got)
	}
	wrapped := fmt.Errorf("%w: на 12 с", agent.ErrClockSkew)
	if got := nextDeniedStreak(streak, wrapped); got != 0 {
		t.Fatalf("обёрнутое расхождение часов засчитано отказом: серия %d", got)
	}
	// Настоящий отказ по-прежнему считается.
	if got := nextDeniedStreak(streak, agent.ErrUnauthorized); got != streak+1 {
		t.Fatalf("отказ платформы перестал считаться: %d", got)
	}
}
