package agent

import (
	"strings"
	"testing"
	"time"
)

// Параметры применения приходят с сервера, то есть это недоверенный вход.
// Проверяем и приведение к разумным границам, и разбор состояния стека.

func TestApplySpecDefaults(t *testing.T) {
	spec := ApplySpec{}.normalized()

	if spec.WaitTimeout() != 180*time.Second {
		t.Fatalf("таймаут по умолчанию %v, ожидалось 180s", spec.WaitTimeout())
	}
	if spec.StableChecks != 3 {
		t.Fatalf("замеров по умолчанию %d, ожидалось 3", spec.StableChecks)
	}
	if spec.StableInterval() != 5*time.Second {
		t.Fatalf("пауза по умолчанию %v, ожидалось 5s", spec.StableInterval())
	}
}

// Сервер может прислать что угодно — ноль, отрицательное число, сутки. Ноль
// означал бы мгновенный отказ на каждом выкате, сутки — заблокированный на
// сутки цикл агента и хост, выглядящий мёртвым.
func TestApplySpecClamped(t *testing.T) {
	wild := ApplySpec{
		WaitTimeoutSeconds:    100000,
		StableChecks:          -4,
		StableIntervalSeconds: 3600,
	}.normalized()

	if wild.WaitTimeout() > 30*time.Minute {
		t.Fatalf("таймаут не ограничен: %v", wild.WaitTimeout())
	}
	if wild.StableChecks < 1 {
		t.Fatalf("число замеров не ограничено снизу: %d", wild.StableChecks)
	}
	if wild.StableInterval() > time.Minute {
		t.Fatalf("пауза не ограничена: %v", wild.StableInterval())
	}
}

// Тяжёлый стек обязан получить своё значение, а не потолок и не значение n8n.
func TestApplySpecHonoursTemplateValue(t *testing.T) {
	spec := ApplySpec{WaitTimeoutSeconds: 600}.normalized()

	if spec.WaitTimeout() != 600*time.Second {
		t.Fatalf("таймаут шаблона потерян: %v", spec.WaitTimeout())
	}
}

func psLine(service, state, health, code string) string {
	return strings.Join([]string{service, state, health, code}, "\t")
}

func TestServiceStatesHealthy(t *testing.T) {
	out := strings.Join([]string{
		psLine("db", "running", "healthy", "0"),
		psLine("app", "running", "healthy", "0"),
	}, "\n")

	if err := checkServiceStates(out, []string{"db", "app"}, nil); err != nil {
		t.Fatalf("здоровый стек признан неисправным: %v", err)
	}
}

// Сервис без healthcheck: running — это максимум, что о нём известно.
func TestServiceStatesAllowsMissingHealthcheck(t *testing.T) {
	out := psLine("imgproxy", "running", "", "0")

	if err := checkServiceStates(out, []string{"imgproxy"}, nil); err != nil {
		t.Fatalf("сервис без healthcheck отвергнут: %v", err)
	}
}

func TestServiceStatesRejectsExited(t *testing.T) {
	out := psLine("db", "exited", "", "0")

	if err := checkServiceStates(out, []string{"db"}, nil); err == nil {
		t.Fatal("вышедший сервис принят за здоровый")
	}
}

// Миграции: сервис объявлен завершающимся и вышел с нулём — это штатный исход.
//
// До разделения этих двух случаев стек с миграциями не разворачивался вовсе:
// `up --wait` его принимал, а проверка устойчивости роняла релиз, и повтор
// каждые десять минут давал ровно тот же отказ.
func TestServiceStatesAcceptsCompletedService(t *testing.T) {
	out := strings.Join([]string{
		psLine("migrate", "exited", "", "0"),
		psLine("app", "running", "healthy", "0"),
	}, "\n")

	completed := map[string]bool{"migrate": true}
	if err := checkServiceStates(out, []string{"migrate", "app"}, completed); err != nil {
		t.Fatalf("отработавшие миграции признаны отказом: %v", err)
	}
}

// Признак «завершается» не отменяет проверку кода выхода: упавшая миграция
// обязана валить выкат, иначе приложение поднимется на неподготовленной базе.
func TestServiceStatesRejectsCompletedWithFailure(t *testing.T) {
	out := psLine("migrate", "exited", "", "1")

	completed := map[string]bool{"migrate": true}
	if err := checkServiceStates(out, []string{"migrate"}, completed); err == nil {
		t.Fatal("миграция с ненулевым кодом выхода принята за успешную")
	}
}

// Сервис, НЕ объявленный завершающимся, остаётся отказом даже с нулём: код 0
// бывает и у контейнера, который просто закончился раньше времени.
func TestServiceStatesRejectsUndeclaredExit(t *testing.T) {
	out := psLine("worker", "exited", "", "0")

	completed := map[string]bool{"migrate": true}
	if err := checkServiceStates(out, []string{"worker"}, completed); err == nil {
		t.Fatal("необъявленный выход принят за штатный")
	}
}

func TestServiceStatesRejectsUnhealthy(t *testing.T) {
	out := psLine("app", "running", "unhealthy", "0")

	if err := checkServiceStates(out, []string{"app"}, nil); err == nil {
		t.Fatal("сервис, не прошедший проверку, принят")
	}
}

// Сервис, которого нет в выводе вовсе, — это «контейнер не создан», а не
// «состояние неизвестно». Без сверки со списком из compose такой случай был бы
// неотличим от здорового стека.
func TestServiceStatesRejectsMissingService(t *testing.T) {
	out := psLine("db", "running", "healthy", "0")

	if err := checkServiceStates(out, []string{"db", "app"}, nil); err == nil {
		t.Fatal("отсутствующий сервис не замечен")
	}
}

// Контейнер в состоянии `created` (создан, стартовать не смог) docker отдаёт с
// кодом выхода 0. Сервис, который не запускался ВООБЩЕ, не имеет права пройти
// за отработавший: приложение поднялось бы на неподготовленной базе.
func TestServiceStatesRejectsCreatedWithZeroExit(t *testing.T) {
	completed := map[string]bool{"migrate": true}
	for _, state := range []string{"created", "paused", "restarting"} {
		out := psLine("migrate", state, "", "0")
		if err := checkServiceStates(out, []string{"migrate"}, completed); err == nil {
			t.Fatalf("состояние %q с кодом 0 принято за отработавшую миграцию", state)
		}
	}
}
