package agent

import (
	"fmt"
	"strings"
	"time"
)

// Параметры применения стека — то, что нельзя задать одним числом на всех.
//
// ЗАЧЕМ. Пороги были константами, выведенными на n8n: два контейнера, оба с
// готовым образом, `--wait-timeout 180`. Стек из десятка сервисов на первом
// выкате тянет десяток образов, и в 180 секунд не укладывается практически
// никогда. Результат — не «долго», а «отказ»: релиз помечается failed, агент
// уходит в паузу на десять минут и повторяет ровно тот же неуспех, потому что
// образы за это время никуда не делись.
//
// Сколько ждать — свойство стека, а не агента, поэтому значение приходит из
// шаблона. Границы агент навязывает свои: вход недоверенный.
//
// ЧЕГО ЗДЕСЬ НЕТ И ПОЧЕМУ — ИСПРАВЛЕНО 2026-08-08.
//
// Раньше здесь было записано, что разрешить одноразовым контейнерам выходить с
// кодом 0 невозможно без отказа от `--wait`: он якобы отказывает на ЛЮБОМ
// вышедшем контейнере. Это неверно, и проверено на настоящем compose.
//
// `up --wait` отказывает только тогда, когда выход НЕ ОБЪЯВЛЕН ожидаемым. Тот
// же стек с `depends_on: {condition: service_completed_successfully}` у
// сервиса, которому нужен результат одноразового, поднимается с кодом 0 —
// compose ждёт завершения, а не работы.
//
// Значит флаг здесь не нужен вовсе: намерение объявляется в самом compose, где
// ему и место.
//
// ЧТО ОСТАВАЛОСЬ СЛОМАННЫМ ДО 2026-08-08. Вывод выше верен для `up --wait`, но
// сразу за ним стоит waitStable, и он-то как раз видел `exited` и ронял выкат.
// Итог был тот же, что и до разбора: стек с миграциями не разворачивался вовсе,
// а повтор каждые десять минут давал ровно тот же отказ. Теперь checkServiceStates
// принимает список сервисов, объявленных завершающимися, и берёт его из того же
// depends_on — то есть из места, где намерение и объявлено.

// ApplySpec — параметры применения, приходящие из шаблона.
type ApplySpec struct {
	WaitTimeoutSeconds    int `json:"waitTimeoutSeconds"`
	StableChecks          int `json:"stableChecks"`
	StableIntervalSeconds int `json:"stableIntervalSeconds"`
}

// Границы. Ноль в таймауте означал бы отказ на каждом выкате, а сутки —
// заблокированный на сутки цикл агента: приложения применяются последовательно,
// и хост перестал бы отчитываться, оставаясь живым.
const (
	defaultWaitTimeoutSeconds = 180
	minWaitTimeoutSeconds     = 60
	maxWaitTimeoutSeconds     = 1800

	defaultStableChecks = 3
	maxStableChecks     = 10

	defaultStableIntervalSeconds = 5
	maxStableIntervalSeconds     = 60
)

func clampInt(value, min, max, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// normalized приводит параметры к допустимым границам.
func (s ApplySpec) normalized() ApplySpec {
	return ApplySpec{
		WaitTimeoutSeconds: clampInt(
			s.WaitTimeoutSeconds, minWaitTimeoutSeconds, maxWaitTimeoutSeconds, defaultWaitTimeoutSeconds),
		StableChecks: clampInt(s.StableChecks, 1, maxStableChecks, defaultStableChecks),
		StableIntervalSeconds: clampInt(
			s.StableIntervalSeconds, 1, maxStableIntervalSeconds, defaultStableIntervalSeconds),
	}
}

func (s ApplySpec) WaitTimeout() time.Duration {
	return time.Duration(s.WaitTimeoutSeconds) * time.Second
}

func (s ApplySpec) StableInterval() time.Duration {
	return time.Duration(s.StableIntervalSeconds) * time.Second
}

// checkServiceStates разбирает вывод `docker compose ps --all` и решает, здоров
// ли стек.
//
// Вынесено из waitStable отдельной функцией ради проверяемости: правила «что
// считать здоровым» — самая содержательная часть health gate, а внутри цикла,
// который ходит в docker, они не проверялись вовсе.
func checkServiceStates(psOutput string, expected []string, completed map[string]bool) error {
	seen := map[string]bool{}

	for _, line := range strings.Split(strings.TrimSpace(psOutput), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			return fmt.Errorf("неразобранная строка состояния: %q", tail(line, 120))
		}
		service, state := fields[0], fields[1]
		health := ""
		if len(fields) > 2 {
			health = strings.TrimSpace(fields[2])
		}
		exitCode := ""
		if len(fields) > 3 {
			exitCode = strings.TrimSpace(fields[3])
		}

		if state != "running" {
			// Сервис, объявленный завершающимся (`depends_on` с условием
			// service_completed_successfully), ВЫШЕДШИЙ с кодом 0 — это
			// отработавшие миграции, а не отказ. Отличать обязательно: без
			// этого стек с миграциями не разворачивался вовсе.
			//
			// Состояние ровно `exited`: у `created` (стартовать не смог) и у
			// `paused` docker тоже отдаёт код 0, и сервис, который не
			// запускался вообще, прошёл бы за отработавший.
			if completed[service] && state == "exited" && exitCode == "0" {
				seen[service] = true
				continue
			}
			return fmt.Errorf("сервис %s в состоянии %s (код выхода %s)", service, state, exitCode)
		}
		// Пустое поле — у сервиса нет healthcheck, и running это максимум,
		// что о нём известно. Всё остальное, кроме healthy, — не готов.
		if health != "" && health != "healthy" {
			return fmt.Errorf("сервис %s не прошёл проверку: %s", service, health)
		}
		seen[service] = true
	}

	// Сервис, которого нет в выводе вовсе, — это «контейнер не создан», а не
	// «состояние неизвестно». Без сверки со списком из compose такой случай
	// был бы неотличим от здорового стека.
	for _, service := range expected {
		if !seen[service] {
			return fmt.Errorf("сервис %s не создан", service)
		}
	}
	return nil
}
