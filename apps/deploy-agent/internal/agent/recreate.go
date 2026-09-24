package agent

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Гонка docker при пересоздании контейнера.
//
// ЧТО ПРОИСХОДИТ. `docker compose up` пересоздаёт контейнер в два шага: сперва
// переименовывает прежний в `<12hex>_<имя>`, освобождая имя, потом удаляет его
// и создаёт новый. Если удаление ещё идёт, а создание уже началось, демон
// отвечает одним из двух:
//
//	Conflict. The container name "/e5fa6db78c6d_vporu-web-1" is already in use…
//	removal of container 0acc8d16… is already in progress
//
// Выкат при этом падает целиком. На боевом приложении это дало три подряд
// упавших выката за полчаса (14.08.2026): контейнер тяжело останавливался,
// каждая следующая попытка заставала предыдущую уборку незавершённой, и стек
// оставался на старом коде при зелёном автодеплое в интерфейсе.
//
// ЧТО ДЕЛАЕМ. Отличаем эту ошибку от настоящих отказов и повторяем подъём,
// убрав переименованный остаток. Повтор ограничен: гонка разрешается за
// секунды, а бесконечные попытки скрыли бы реальную поломку.

// Оставленный докером остаток: 12 hex, подчёркивание, обычное имя контейнера.
// Именно эту форму демон создаёт сам при пересоздании — руками её не пишут.
var renamedContainerRe = regexp.MustCompile(`^[0-9a-f]{12}_(.+)$`)

// Признаки гонки в выводе compose. Оба текста приходят от самого демона.
var recreateRaceMarkers = []string{
	"is already in use by container",
	"is already in progress",
}

// isRecreateRace — ошибка подъёма вызвана незавершённой уборкой прежнего
// контейнера, а не поломкой стека.
//
// По тексту, потому что кода ошибки у compose нет: он отдаёт единственный
// ненулевой статус на любую беду. Маркеры узкие — «нет такого образа» или
// «порт занят» под них не попадают, и повтор на них не сработает.
func isRecreateRace(output string) bool {
	lower := strings.ToLower(output)
	for _, marker := range recreateRaceMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// renamedLeftovers — контейнеры проекта, которых docker переименовал под
// пересоздание и не успел удалить.
//
// Отбор двойной: сначала лейбл проекта (чужого мы не трогаем НИКОГДА), затем
// форма имени. Одного лейбла мало — под него попадает и работающий контейнер
// приложения, а его удаление было бы аварией вместо починки.
func renamedLeftovers(containers []dockerContainer, slug string) []string {
	var out []string
	for _, c := range containers {
		if c.Config.Labels["com.docker.compose.project"] != slug {
			continue
		}
		name := strings.TrimPrefix(c.Name, "/")
		if renamedContainerRe.MatchString(name) {
			out = append(out, name)
		}
	}
	return out
}

// removeRenamedLeftovers убирает остатки прерванного пересоздания.
//
// Возвращает имена удалённых — они уходят в отчёт о выкате: молча удалять
// контейнеры на чужом сервере платформа не должна, даже свои собственные.
func removeRenamedLeftovers(ctx context.Context, slug string) ([]string, error) {
	if !safeSlug.MatchString(slug) {
		return nil, fmt.Errorf("недопустимый slug приложения: %q", slug)
	}

	containers, err := inspectComposeContainers(ctx)
	if err != nil {
		return nil, err
	}

	names := renamedLeftovers(containers, slug)
	if len(names) == 0 {
		return nil, nil
	}

	// -f обязателен: остаток бывает и в состоянии running, если демона
	// прервали между переименованием и остановкой.
	args := append([]string{"rm", "-f"}, names...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = dockerEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("не удалось убрать остатки пересоздания: %w: %s",
			err, tail(string(out), 200))
	}
	return names, nil
}

// recreateRaceBackoff — пауза перед повтором.
//
// Уборка контейнера — секунды, и повтор без паузы застал бы ровно то же
// состояние. Значение маленькое намеренно: выкат и так уже задержан.
const recreateRaceBackoff = 3 * time.Second

// waitBeforeRetry — пауза, прерываемая отменой такта.
func waitBeforeRetry(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
