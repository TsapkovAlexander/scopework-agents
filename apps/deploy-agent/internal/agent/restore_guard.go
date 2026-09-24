package agent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/stackdir"
)

// verifyRestoreSet прогоняет описание стека из набора копий той же политикой,
// что выкат (ADR-0092, решение 14). Зовётся до флага восстановления и `down`:
// отказ оставляет прежний стек работать, а его файлы — на месте.
//
// ЗАЧЕМ. Восстановление поднимает compose и .env из набора, а набор — файлы с
// диска хоста. Автооткат снимает его перед обновлением с того, что лежит в
// каталоге приложения, а туда описание пишется ДО проверки (applyOne): набор
// мог унести отвергнутый compose, и откат поднял бы его мимо политики. Задание
// восстановления приносит только имя набора, но выбрать его может и
// взломанная платформа.
//
// Хеш записанного агентом (С1.6, рубеж 2) здесь не сверяется: после удачного
// восстановления базовая линия переходит на файлы набора, при отказе файлы не
// тронуты.
func verifyRestoreSet(ctx context.Context, p Paths, app DesiredApp, setDir string) error {
	refuse := func(reason string) error {
		return fmt.Errorf("описание стека из набора копий %s отклонено: %s; стек не останавливался, данные не тронуты",
			filepath.Base(setDir), reason)
	}

	composeFile := filepath.Join(setDir, "docker-compose.yml")
	envFile := filepath.Join(setDir, ".env")

	// Оба файла обязаны быть в наборе: без одного из них поднялся бы прежний
	// с диска, которого эта проверка не видела. Ссылка — не файл из копии:
	// проверили бы одно, а вернули бы то, на что она укажет при записи.
	for _, path := range []string{composeFile, envFile} {
		name := filepath.Base(path)
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return refuse("в наборе нет " + name)
		case err != nil:
			return refuse(name + " в наборе не читается: " + err.Error())
		case !info.Mode().IsRegular():
			return refuse(name + " в наборе — не обычный файл")
		}
	}

	raw, err := os.ReadFile(envFile)
	if err != nil {
		return refuse(".env в наборе не читается: " + err.Error())
	}
	if reason := envOutsideRenderRule(string(raw), app.Slug); reason != "" {
		return refuse(reason)
	}
	composeRaw, err := os.ReadFile(composeFile)
	if err != nil {
		return refuse("docker-compose.yml в наборе не читается: " + err.Error())
	}

	// Файлы набора лягут в каталог приложения и поднимутся оттуда, поэтому
	// нормализуются от него: относительный путь в наборе — это путь в
	// каталоге приложения, а не в каталоге копии. Корни и служебный каталог —
	// те же, что у выката.
	appDir := p.appDir(app.Slug)
	roots := []string{appDir}
	if app.FromGit() {
		roots = append(roots, p.repoDir(app.Slug))
	}
	err = verifyComposeSafety(ctx,
		composeTarget{ProjectDir: appDir, ComposeFile: composeFile, EnvFile: envFile},
		composeguard.Options{Roots: roots, ServiceDirs: []string{appDir}, AdoptedVolumes: app.AdoptedVolumes,
			Allowances: restoreAllowances(app, composeRaw)},
	)
	if err == nil {
		return nil
	}
	// Шапку выката не повторяем: в отчёт уходят последние 500 байт текста, и
	// она вытеснила бы сами нарушения.
	var refusal *composeRefusal
	if errors.As(err, &refusal) {
		return refuse(strings.Join(refusal.reasons, "; "))
	}
	return refuse(err.Error())
}

// restoreAllowances — послабления гранта для набора. Грант подписан к байтам
// compose приложения (ADR-0092, решение 11), и набору с другим описанием он не
// принадлежит: иначе грант на порт одного шаблона открывал бы его любому
// набору, выбранному заданием. Приложению из репозитория грант не положен и
// при выкате (attachAllowances): его описание не из подписанных байтов.
func restoreAllowances(app DesiredApp, setCompose []byte) []composeguard.Allowance {
	if app.FromGit() || len(app.Allowances) == 0 {
		return nil
	}
	if sha256.Sum256(setCompose) != sha256.Sum256([]byte(app.Compose)) {
		return nil
	}
	return app.Allowances
}

// envOutsideRenderRule — чем .env набора отличается от того, что агент пишет
// сам (renderEnv): APP_SLUG — своего приложения, ключей compose и docker нет,
// имена — только те, что renderEnv пропускает. Пусто — отличий нет.
//
// Иначе имя проекта или файл стека уходят мимо проверенного: COMPOSE_FILE
// подменяет описание, COMPOSE_PROJECT_NAME и чужой APP_SLUG — проект, и
// `up --remove-orphans` сносит контейнеры соседа, DOCKER_HOST уводит подъём к
// другому демону.
func envOutsideRenderRule(raw, slug string) string {
	env := parseEnvFile(raw)
	if got := env["APP_SLUG"]; got != slug {
		return fmt.Sprintf(".env набора: APP_SLUG %q вместо %q", tail(got, 60), slug)
	}
	var foreign []string
	for key := range env {
		if key == "APP_SLUG" || key == "APP_DOMAIN" {
			continue
		}
		// Имя, которое renderEnv не пишет (`export APP_SLUG`), разбор выше
		// видит одним ключом, а compose — другим: проверили бы не тот .env.
		if !stackdir.SafeEnvKey.MatchString(key) || stackdir.IsReservedEnvKey(key) {
			foreign = append(foreign, tail(key, 60))
		}
	}
	if len(foreign) == 0 {
		return ""
	}
	sort.Strings(foreign)
	return ".env набора: ключи, которых агент не пишет: " + strings.Join(foreign, ", ")
}
