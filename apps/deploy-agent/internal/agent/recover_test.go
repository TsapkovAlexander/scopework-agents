package agent

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Восстановление — единственное место, где агент по собственной инициативе
// трогает чужой стек. Проверять его наблюдением за боевым сервером нельзя:
// ошибка здесь выглядит как «платформа сама перезапускает мне контейнеры без
// причины» либо как «упавший ночью сервис пролежал до утра».

func applied(status string, attempts int, last time.Time) AppliedRecord {
	return AppliedRecord{
		ReleaseID:        "rel-1",
		ConfigHash:       "hash",
		Status:           status,
		RecoveryAttempts: attempts,
		LastRecovery:     last,
	}
}

var running = DesiredApp{Slug: "app", Desired: "present"}

func TestRecoveryLiftsUnhealthyApp(t *testing.T) {
	now := time.Now().UTC()
	d := decideRecovery(applied("healthy", 0, time.Time{}), true, running, HealthDown, now, false)

	if !d.Recover || d.Attempt != 1 {
		t.Fatalf("упавшее приложение не поднимается: %+v", d)
	}
}

// Здоровое не трогаем. Кажется очевидным — но именно это отделяет
// восстановление от «перезапускать всё подряд каждую минуту».
func TestRecoverySkipsHealthy(t *testing.T) {
	d := decideRecovery(applied("healthy", 0, time.Time{}), true, running, HealthHealthy, time.Now(), false)
	if d.Recover {
		t.Fatalf("здоровое приложение поднимается заново: %+v", d)
	}
}

// «Не знаем» — не повод вмешиваться: неизвестное состояние бывает у только что
// развёрнутого приложения и при сбое опроса docker.
func TestRecoverySkipsUnknown(t *testing.T) {
	d := decideRecovery(applied("healthy", 0, time.Time{}), true, running, HealthUnknown, time.Now(), false)
	if d.Recover {
		t.Fatalf("приложение с неизвестным состоянием поднимается: %+v", d)
	}
}

// Снимаемое приложение поднимать нельзя — это прямо противоположно желаемому
// состоянию, и один такой подъём вернул бы к жизни стек, который человек
// только что удалил.
func TestRecoverySkipsAppBeingRemoved(t *testing.T) {
	stopping := DesiredApp{Slug: "app", Desired: "absent"}
	d := decideRecovery(applied("healthy", 0, time.Time{}), true, stopping, HealthDown, time.Now(), false)
	if d.Recover {
		t.Fatalf("снимаемое приложение поднимается: %+v", d)
	}
}

// Неудачный выкат чинит механика применения, у неё своя пауза. Иначе две
// механики поднимали бы один стек наперегонки.
func TestRecoveryLeavesFailedDeployToApply(t *testing.T) {
	d := decideRecovery(applied("failed", 0, time.Time{}), true, running, HealthDown, time.Now(), false)
	if d.Recover {
		t.Fatalf("после неудачного выката вмешивается восстановление: %+v", d)
	}
}

// Паузы растут: приложение, падающее на старте, не должно перезапускаться
// каждую минуту — это жжёт процессор клиента и топит в журнале настоящую
// причину.
func TestRecoveryBackoffGrows(t *testing.T) {
	now := time.Now().UTC()

	// Только что пробовали — ждём.
	d := decideRecovery(applied("healthy", 1, now.Add(-30*time.Second)), true, running, HealthDown, now, false)
	if d.Recover {
		t.Fatalf("вторая попытка без паузы: %+v", d)
	}

	// Пауза выдержана — пробуем снова.
	d = decideRecovery(applied("healthy", 1, now.Add(-3*time.Minute)), true, running, HealthDown, now, false)
	if !d.Recover || d.Attempt != 2 {
		t.Fatalf("после паузы попытка не выполняется: %+v", d)
	}

	if recoveryBackoff(1) != 2*time.Minute || recoveryBackoff(3) != 8*time.Minute {
		t.Fatalf("паузы не удваиваются: %v, %v", recoveryBackoff(1), recoveryBackoff(3))
	}
}

// Потолок: пять подъёмов не помогли — шестой не поможет. Дальше агент
// перестаёт вмешиваться и оставляет отказ видимым.
func TestRecoveryStopsAtCeiling(t *testing.T) {
	now := time.Now().UTC()
	d := decideRecovery(applied("healthy", maxRecoveryAttempts, now.Add(-time.Hour)), true, running, HealthDown, now, false)

	if d.Recover {
		t.Fatalf("после потолка попытки продолжаются: %+v", d)
	}
	if d.Reason == "" {
		t.Fatal("причина отказа не названа — в журнале будет тишина")
	}
}

// Серия не длится вечно: одна ночная авария не должна навсегда лишить
// приложение права на восстановление.
func TestRecoverySeriesResets(t *testing.T) {
	now := time.Now().UTC()
	long := now.Add(-recoveryResetAfter - time.Minute)

	d := decideRecovery(applied("healthy", maxRecoveryAttempts, long), true, running, HealthDown, now, false)
	if !d.Recover || d.Attempt != 1 {
		t.Fatalf("старая серия не сброшена: %+v", d)
	}
}

// Сорвавшееся восстановление из копии оставляет тома смешанными: часть уже из
// копии, часть прежняя. Упавший стек при флаге не поднимается, даже когда
// всё остальное за подъём — запись здоровая, попыток не было. Причина обязана
// быть названа: иначе лежащее приложение неотличимо от забытого.
func TestRecoverySkipsInterruptedRestore(t *testing.T) {
	d := decideRecovery(applied("healthy", 0, time.Time{}), true, running, HealthDown, time.Now(), true)

	if d.Recover {
		t.Fatalf("после сорвавшегося восстановления стек поднимается на смешанных томах: %+v", d)
	}
	if d.Reason == "" {
		t.Fatal("причина не названа — в журнале не видно, что стек лежит намеренно")
	}
}

// Приложение, которое ещё не разворачивали, поднимает выкат, а не
// восстановление: у него нет ни каталога, ни .env.
func TestRecoverySkipsNeverApplied(t *testing.T) {
	d := decideRecovery(AppliedRecord{}, false, running, HealthDown, time.Now(), false)
	if d.Recover {
		t.Fatalf("неразвёрнутое приложение поднимается восстановлением: %+v", d)
	}
}

// Выкат, проверка здоровья и восстановление работают с ОДНИМ каталогом.
//
// Три места звали compose из разных каталогов: applyOne — из служебного, куда
// кладётся подготовленное описание, а checkOne и recoverApp для приложения из
// репозитория подставляли рабочую копию. Последствия разные и оба тихие.
// Проверка здоровья опрашивала проект автора (у репозитория со своим `name:`
// контейнеров такого проекта нет) и объявляла здоровый стек лежащим.
// Восстановление поднимало СЫРОЕ описание автора: с публикацией портов на
// 0.0.0.0 в обход прокси и TLS, с авторскими именами контейнеров и без сети
// прокси.
//
// Обычным тестом это не ловится: каждая функция по отдельности исправна, ломает
// их только расхождение каталогов. Поэтому проверяется текст — тем же приёмом,
// что и порядок записи .env в composemodel_test.go.
func TestComposeRunsFromSingleDirectory(t *testing.T) {
	for _, file := range []string{"health.go", "recover.go"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s не читается: %v", file, err)
		}
		if strings.Contains(string(raw), "p.repoDir(") {
			t.Errorf("%s снова берёт рабочую копию как каталог compose: "+
				"стек поднят из служебного каталога, и опрашивать/поднимать "+
				"нужно его же", file)
		}
	}

	raw, err := os.ReadFile("apply.go")
	if err != nil {
		t.Fatalf("apply.go не читается: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "runDir := dir") {
		t.Skip("ориентир runDir в apply.go изменился — тест пересобрать")
	}
	// Переприсваивание runDir вернуло бы расхождение, ради которого тест и
	// написан: applyOne ушёл бы в рабочую копию, а health/recover остались бы в
	// служебном каталоге.
	if strings.Contains(text, "runDir = ") {
		t.Error("applyOne переприсваивает runDir: каталог запуска снова " +
			"разошёлся с тем, который опрашивают health.go и recover.go")
	}
}

// Недопустимый slug не должен доходить до файловой системы.
//
// Путь до каталога стека собирается прямо в recoverApp, и проверять его в
// вызывающих значит держать безопасность на договорённости между функциями.
// Сегодня applyOne такой каталог не заведёт — но это его свойство, а не наше.
func TestRecoverAppRejectsUnsafeSlug(t *testing.T) {
	for _, slug := range []string{
		"../../etc/systemd/system",
		"..",
		"app/../../root",
		"",
		"ПРОЕКТ",
	} {
		err := recoverApp(context.Background(), Paths{WorkDir: t.TempDir()}, DesiredApp{Slug: slug})
		if err == nil {
			t.Fatalf("slug %q принят, а должен быть отвергнут", slug)
		}
		if !strings.Contains(err.Error(), "недопустимый slug") {
			t.Fatalf("slug %q: ожидали отказ по slug, получили: %v", slug, err)
		}
	}
}
