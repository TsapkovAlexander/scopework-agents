package agent

import (
	"context"
	"fmt"
	"os"
	"strings"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
)

// Проверка описания стека перед запуском.
//
// Сама политика — что можно поднять на хосте клиента — живёт в
// pkg/composeguard: тот же код решает у подписанта до подписи (ADR-0092,
// решение 5), и две копии разошлись бы на первом же новом поле — стек,
// отвергнутый агентом, подписант бы подписал. Здесь остаётся то, что умеет
// только агент: запуск `docker compose config` и чтение файлов с диска.
//
// Проверяем НОРМАЛИЗОВАННЫЙ вид (`docker compose config`), а не исходный YAML:
// иначе достаточно записать то же самое другим синтаксисом — короткой формой
// тома, якорем YAML, extends из соседнего файла.

// composeViolation — одно нарушение: имя сервиса и причина.
type composeViolation = composeguard.Violation

// checkComposeSafety — политика без служебного каталога: так проверяются
// модели без места на диске.
func checkComposeSafety(normalized []byte, allowedRoots []string, allowedVolumeNames []string) ([]composeViolation, error) {
	return checkComposeSafetyIn(normalized, allowedRoots, allowedVolumeNames, nil)
}

// checkComposeSafetyIn — то же со СЛУЖЕБНЫМИ каталогами: в них лежит описание
// стека, которым агент его поднимает (задача С1.6).
func checkComposeSafetyIn(normalized []byte, allowedRoots []string, allowedVolumeNames []string, serviceDirs []string) ([]composeViolation, error) {
	return composeguard.Check(normalized, composeguard.Options{
		Roots:          allowedRoots,
		ServiceDirs:    serviceDirs,
		AdoptedVolumes: allowedVolumeNames,
	})
}

// withinRoots — лежит ли очищенный путь внутри одного из корней. Им же осмотр
// хоста отличает свои стеки от чужих.
func withinRoots(clean string, allowedRoots []string) bool {
	return composeguard.WithinRoots(clean, allowedRoots)
}

// checkStackFileRefs — ссылки описания на файлы (env_file, label_file,
// include, extends) по исходному тексту, с обходом включённых описаний.
// Звать ДО первого `docker compose`: эти поля compose исполняет сам, читая
// файл, и нормализация их стирает (composeguard/filerefs.go).
func checkStackFileRefs(sf composeguard.StackFiles) error {
	violations := composeguard.CheckStackFileRefs(sf)
	if len(violations) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(violations))
	for _, v := range violations {
		reasons = append(reasons, v.String())
	}
	return &composeRefusal{reasons: reasons}
}

// verifyStackFileRefs — обе линии проверки ссылок на файлы (env_file,
// label_file, include, extends). Звать ДО любого вызова compose, который эти
// ссылки исполняет.
//
// Первая — по тексту (checkStackFileRefs): она не пускает к compose
// абсолютные пути include и extends, которые он прочёл бы при любых флагах.
// Вторая — по модели самого compose, снятой без чтения env_file
// (composeguard.ModelRefArgs): промах разбора текста становится здесь
// отказом, а не `.env` соседа в контейнере. Модель второй линии живёт только
// в памяти и в отчёт не уходит — текст отказа без путей.
func verifyStackFileRefs(ctx context.Context, sf composeguard.StackFiles, target composeTarget) error {
	if err := checkStackFileRefs(sf); err != nil {
		return err
	}
	out, err := composeRefModel(ctx, target)
	if err != nil {
		return fmt.Errorf("docker compose config: %w", err)
	}
	violations := composeguard.CheckModelFileRefs([]byte(out), sf)
	if len(violations) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(violations))
	for _, v := range violations {
		reasons = append(reasons, v.String())
	}
	return &composeRefusal{reasons: reasons}
}

// composeRefModel — модель второй линии с теми же файлами, каталогом проекта
// и .env, что у подъёма: пути в ней compose разрешает так же, как на `up`.
func composeRefModel(ctx context.Context, target composeTarget) (string, error) {
	args := append([]string{}, composeguard.ModelRefArgs...)
	if target.ComposeFile != "" {
		args = append([]string{"--project-directory", target.ProjectDir, "-f", target.ComposeFile}, args...)
	}
	return dockerComposeParsed(ctx, target.ProjectDir, target.EnvFile, args...)
}

// composeTarget — что нормализовать.
type composeTarget struct {
	// ProjectDir — каталог проекта: от него разрешаются относительные пути, из
	// него запускается compose.
	ProjectDir string
	// ComposeFile — явный файл описания. Пусто — compose находит его в
	// ProjectDir сам, как на подъёме.
	//
	// Явный файл нужен восстановлению: описание лежит в наборе копий, а
	// поднимется из каталога приложения — и пути обязаны разрешаться от него.
	ComposeFile string
	// EnvFile — тот же .env, что на подъёме: без него подстановка ${VAR} даст
	// другой результат, и проверять мы будем не то, что поднимется.
	EnvFile string
}

// composeConfig снимает нормализованный вид стека.
//
// Шов для тестов: проверить, что guard стоит на каждом источнике, можно только
// моделью, которую docker без настоящего стека не отдаст.
//
// stdout БЕЗ stderr: `docker compose` печатает предупреждения туда, и самое
// частое из них — про устаревший `version:`, который стоит в подавляющем
// большинстве публичных репозиториев. Склеенный вывод начинался с `time=`, и
// разбор JSON падал на втором символе.
var composeConfig = func(ctx context.Context, target composeTarget) (string, error) {
	args := []string{"config", "--format", "json"}
	if target.ComposeFile != "" {
		args = append([]string{"--project-directory", target.ProjectDir, "-f", target.ComposeFile}, args...)
	}
	return dockerComposeParsed(ctx, target.ProjectDir, target.EnvFile, args...)
}

// composeRefusal — отказ политики. Отдельным типом, чтобы восстановление
// назвало нарушения своими словами: в отчёт платформе уходят последние 500
// байт текста, и шапка выката поверх своей вытеснила бы первые из них.
type composeRefusal struct {
	reasons []string
}

func (e *composeRefusal) Error() string {
	return fmt.Sprintf(
		"описание стека отклонено платформой:\n  %s\n"+
			"Эти возможности дают контейнеру доступ к хосту и к секретам "+
			"развёртывания, поэтому запрещены",
		strings.Join(e.reasons, "\n  "),
	)
}

// verifyComposeSafety поднимает нормализованный вид и проверяет его политикой.
//
// CheckSecretVars агент не зовёт: шаблону и своему compose его применил
// подписант к тем же подписанным байтам, а у git-приложения репозиторий и
// ветку выбирает подписанное состояние, и секрет в опасном поле чужого
// описания даёт web не больше, чем подпись другого репозитория (ADR-0092,
// «Честная граница»); значения же, опасные сами по себе, ловит Check ниже —
// модель здесь с подстановкой настоящих значений.
func verifyComposeSafety(ctx context.Context, target composeTarget, opt composeguard.Options) error {
	// Ссылки на файлы — ДО нормализации: `docker compose config` исполняет
	// env_file, include и extends сам, и файл соседа оказался бы прочитан
	// раньше, чем его запретили. Корень — каталог проекта: там лежат описание,
	// .env и файлы шаблона, а относительные пути compose разрешает от него.
	sf := composeguard.StackFiles{Root: target.ProjectDir, ProjectDir: target.ProjectDir}
	if target.ComposeFile != "" {
		// Файл назван явно: не прочитался — проверка не проведена, а не
		// «нарушений нет».
		if _, err := os.Stat(target.ComposeFile); err != nil {
			return fmt.Errorf("описание стека не читается: %w", err)
		}
		sf.Entries = []string{target.ComposeFile}
	}
	if err := verifyStackFileRefs(ctx, sf, target); err != nil {
		return err
	}

	out, err := composeConfig(ctx, target)
	if err != nil {
		return fmt.Errorf("docker compose config: %w: %s", err, tail(out, 400))
	}

	violations, err := composeguard.Check([]byte(out), opt)
	if err != nil {
		return err
	}
	if len(violations) == 0 {
		return nil
	}

	reasons := make([]string, 0, len(violations))
	for _, v := range violations {
		reasons = append(reasons, v.String())
	}
	return &composeRefusal{reasons: reasons}
}
