package agent

import (
	"context"
	"testing"
	"time"
)

// Гонка docker при пересоздании контейнера: `up` падает не потому, что стек
// сломан, а потому, что демон ещё убирает прежний контейнер. На боевом
// приложении это дало три подряд упавших выката за полчаса.

func TestIsRecreateRace(t *testing.T) {
	// Оба текста — дословно от демона, из журнала выката 14.08.2026.
	race := []string{
		`Container vporu-web-1 Recreate
 Container vporu-web-1 Error response from daemon: Conflict. The container name "/e5fa6db78c6d_vporu-web-1" is already in use by container "817c4f2239c8".`,
		`Container vporu-web-1 Recreate
 Container vporu-web-1 Error response from daemon: removal of container 0acc8d16ce13 is already in progress`,
	}
	for _, out := range race {
		if !isRecreateRace(out) {
			t.Errorf("гонка пересоздания не опознана:\n%s", out)
		}
	}

	// Настоящие отказы повторять нельзя: повтор скроет причину и удвоит время
	// выката, а закончится тем же самым.
	real := []string{
		"docker compose up: exit status 1: no such image: acme/web:latest",
		`Error response from daemon: driver failed programming external connectivity: address already in use`,
		"dependency failed to start: container vporu-db-1 exited (1)",
		"",
	}
	for _, out := range real {
		if isRecreateRace(out) {
			t.Errorf("обычный отказ принят за гонку: %q", out)
		}
	}
}

func labeledContainer(name, project string) dockerContainer {
	c := dockerContainer{Name: "/" + name}
	c.Config.Labels = map[string]string{"com.docker.compose.project": project}
	return c
}

// Удаляются ТОЛЬКО переименованные докером остатки и только своего проекта.
func TestRenamedLeftoversPicksOnlyOwnRemnants(t *testing.T) {
	containers := []dockerContainer{
		// Остаток прерванного пересоздания — его и убираем.
		labeledContainer("e5fa6db78c6d_vporu-web-1", "vporu"),
		// Работающий контейнер приложения: его удаление было бы аварией
		// вместо починки.
		labeledContainer("vporu-web-1", "vporu"),
		// Остаток ЧУЖОГО проекта на том же хосте — не наше дело.
		labeledContainer("aabbccddeeff_other-web-1", "other"),
		// Имя лишь похоже на форму докера: не 12 hex.
		labeledContainer("abc_vporu-web-1", "vporu"),
		labeledContainer("e5fa6db78c6dz_vporu-web-1", "vporu"),
	}

	got := renamedLeftovers(containers, "vporu")
	if len(got) != 1 || got[0] != "e5fa6db78c6d_vporu-web-1" {
		t.Fatalf("к удалению отобрано %v, ожидался только остаток пересоздания", got)
	}
}

// Slug приходит с сервера и уезжает в аргументы docker: агент живёт на чужой
// машине и не доверяет входу второй раз.
func TestRemoveRenamedLeftoversRejectsBadSlug(t *testing.T) {
	if _, err := removeRenamedLeftovers(context.Background(), "../../etc"); err == nil {
		t.Fatal("недопустимый slug принят")
	}
}

// Пауза перед повтором обязана прерываться отменой такта: агент не должен
// висеть в ожидании, когда его уже остановили.
func TestWaitBeforeRetryHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	if err := waitBeforeRetry(ctx, time.Minute); err == nil {
		t.Fatal("отменённый контекст не прервал ожидание")
	}
	if time.Since(started) > time.Second {
		t.Fatal("ожидание не прервалось сразу")
	}
}
