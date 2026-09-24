package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Опрос здоровья не должен выдавать «поломку» там, где приложения на хосте
// никогда и не было. Такие сообщения дороже, чем кажется: они всплывают на
// карточке проекта красным чипом и в блоке «требует внимания», то есть тратят
// внимание человека на несуществующий инцидент.

func TestCheckOneReportsNeverDeployedWhenDirMissing(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	app := DesiredApp{Slug: "app2", Desired: "present"}

	got := checkOne(context.Background(), p, app)

	if got.Status != HealthUnknown {
		t.Fatalf("статус = %q, ожидался %q", got.Status, HealthUnknown)
	}
	if _, bad := got.Detail["error"]; bad {
		t.Fatalf("в подробностях техническая ошибка вместо объяснения: %v", got.Detail)
	}
}

// Каталог создаётся первым же действием выката, а .env пишется в самом конце —
// после клонирования репозитория и проверки compose. Значит «каталог есть,
// .env нет» означает ровно одно: выкат начинался и не дошёл до конца.
//
// Реальный случай: выкат упал на недопустимом адресе репозитория, а проверка
// здоровья следом показала «couldn't find env file: /opt/.../app2/.env» —
// docker'овская фраза про файл, которого человек в глаза не видел, вместо
// настоящей причины, которая была в журнале выката.
func TestCheckOneReportsNeverDeployedWhenEnvMissing(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	app := DesiredApp{Slug: "app2", Desired: "present", SourceType: "git"}

	if err := os.MkdirAll(p.appDir(app.Slug), 0o750); err != nil {
		t.Fatal(err)
	}

	got := checkOne(context.Background(), p, app)

	if got.Status != HealthUnknown {
		t.Fatalf("статус = %q, ожидался %q", got.Status, HealthUnknown)
	}
	if _, bad := got.Detail["error"]; bad {
		t.Fatalf("в подробностях техническая ошибка вместо объяснения: %v", got.Detail)
	}
	reason, _ := got.Detail["reason"].(string)
	if !strings.Contains(reason, "разверт") && !strings.Contains(reason, "разворач") {
		t.Fatalf("причина %q не объясняет, что приложение ещё не разворачивалось", reason)
	}
	if strings.Contains(reason, ".env") {
		t.Fatalf("причина %q говорит о внутреннем файле агента, а не о состоянии приложения", reason)
	}
}

// Обратная сторона: если .env на месте, ранний выход не должен срабатывать —
// иначе развёрнутое приложение навсегда осталось бы «неизвестным».
func TestCheckOneGoesOnWhenEnvPresent(t *testing.T) {
	p := Paths{StateDir: t.TempDir(), WorkDir: t.TempDir()}
	app := DesiredApp{Slug: "app2", Desired: "present"}

	dir := p.appDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("FOO=bar\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := checkOne(context.Background(), p, app)

	// Docker в тестовой среде может отсутствовать — значение статуса здесь не
	// важно, важно, что проверка пошла дальше раннего выхода.
	if reason, _ := got.Detail["reason"].(string); strings.Contains(reason, "разворач") {
		t.Fatalf("ранний выход сработал на развёрнутом приложении: %v", got.Detail)
	}
}

// Остановленный сервис обязан делать приложение нездоровым.
//
// До 2026-08-07 `compose ps` вызывался без --all, и остановленные контейнеры
// просто исчезали из вывода: на боевом стенде два лежащих сервиса Supabase из
// десяти оставили приложение в состоянии healthy — платформа показывала
// «работает» стеку, у которого не отвечали Storage и PostgREST.
func TestStoppedServiceMakesAppUnhealthy(t *testing.T) {
	states := parseContainerStates(
		"app\trunning\thealthy\n" +
			"storage\texited\t\n" +
			"rest\texited\t\n")

	if len(states) != 3 {
		t.Fatalf("разобрано состояний %d, ожидалось 3", len(states))
	}
	if got := summarize(states); got == HealthHealthy {
		t.Fatalf("стек с двумя остановленными сервисами признан здоровым: %s", got)
	}
}

// Сервис, которого нет вовсе (контейнер удалили), — тоже отказ. Иначе
// `docker rm` остаётся способом сделать приложение здоровым.
func TestMissingServiceCountsAsDown(t *testing.T) {
	states := []containerState{
		{Service: "app", State: "running", Health: "healthy"},
		{Service: "storage", State: "missing"},
	}
	if got := summarize(states); got == HealthHealthy {
		t.Fatalf("стек с пропавшим сервисом признан здоровым: %s", got)
	}
	if containerAlive(states[1]) {
		t.Fatal("пропавший сервис засчитан живым")
	}
}

// Отработавшие миграции не делают приложение нездоровым.
//
// Без этого стек с сервисом инициализации навсегда оставался degraded: выкат
// проходил, а карточка приложения показывала неисправность, которой нет.
func TestCompletedServiceCountsAsAlive(t *testing.T) {
	states := parseContainerStates(
		"migrate\texited\t\t0\n" +
			"app\trunning\thealthy\t0\n")
	if len(states) != 2 {
		t.Fatalf("состояния не разобрались: %+v", states)
	}
	if states[0].ExitCode != "0" {
		t.Fatalf("код выхода потерян: %+v", states[0])
	}

	// Без признака — прежнее строгое поведение.
	if got := summarize(states); got != HealthDegraded {
		t.Fatalf("без признака завершения ожидался degraded, получен %s", got)
	}

	states[0].Completed = true
	if got := summarize(states); got != HealthHealthy {
		t.Fatalf("стек с отработавшими миграциями признан %s", got)
	}
}

// Признак не отменяет проверку кода выхода.
func TestCompletedServiceWithFailureIsNotAlive(t *testing.T) {
	states := parseContainerStates("migrate\texited\t\t1\n")
	states[0].Completed = true
	if containerAlive(states[0]) {
		t.Fatal("миграция, упавшая с кодом 1, считается живой")
	}
}

// То же правило в проверке здоровья: `created` с кодом 0 живым не считается.
func TestCompletedRequiresExitedState(t *testing.T) {
	for _, state := range []string{"created", "paused", "restarting"} {
		states := parseContainerStates("migrate\t" + state + "\t\t0\n")
		states[0].Completed = true
		if containerAlive(states[0]) {
			t.Fatalf("состояние %q признано отработавшей миграцией", state)
		}
	}

	exited := parseContainerStates("migrate\texited\t\t0\n")
	exited[0].Completed = true
	if !containerAlive(exited[0]) {
		t.Fatal("настоящая отработавшая миграция признана отказом")
	}
}
