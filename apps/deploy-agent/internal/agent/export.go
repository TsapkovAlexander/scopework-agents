package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Снятие слепка чужого стека и перенос его данных в тома.
//
// ЗАЧЕМ. Осмотр (inventory.go) отвечает на вопрос «что здесь есть» и намеренно
// не читает ни значений переменных, ни содержимого файлов. Чтобы взять стек под
// управление, этого мало: нужен полный рецепт — текст compose, значения
// переменных, конфиги. Разделение сделано ради того, чтобы «посмотреть, что на
// сервере» не копировало секреты всех чужих систем: слепок снимается с ОДНОГО
// стека и только после того, как человек сказал «переношу вот этот».
//
// ЗДЕСЬ ЧИТАЮТСЯ СЕКРЕТЫ. В отличие от осмотра, слепок несёт значения
// переменных: без них перенесённый стек не поднимется. Поэтому:
//   - задание приходит на КОНКРЕТНЫЙ проект, а не «на все»;
//   - агент читает только внутри каталога этого проекта (путь берётся из меток
//     docker, а не из задания);
//   - платформа шифрует значения сразу при приёме и хранит их до создания
//     приложения, а не бессрочно.
//
// ПЕРЕНОС ДАННЫХ — отдельная операция и единственная, где агент трогает чужие
// данные. Он останавливает стек, копирует каталог в именованный том и сверяет
// результат по числу файлов и сумме размеров. Копия, а не перемещение:
// оригинал остаётся на диске как откат, пока человек не убедится, что всё на
// месте.

const (
	maxSnapshotComposeBytes = 512 << 10
	maxSnapshotEnvBytes     = 128 << 10
	maxSnapshotFileBytes    = 128 << 10
	maxSnapshotTotalBytes   = 4 << 20
)

// StackSnapshot — полный рецепт одного стека.
type StackSnapshot struct {
	Project    string `json:"project"`
	WorkingDir string `json:"workingDir"`
	Compose    string `json:"compose"`
	// Env — значения переменных стека. Секреты; шифруются платформой при приёме.
	Env map[string]string `json:"env"`
	// ConfigFiles — содержимое конфигов, смонтированных файлами. Ключ — путь
	// относительно каталога стека.
	ConfigFiles map[string]string `json:"configFiles"`
	Digests     map[string]string `json:"digests"`
	Volumes     []string          `json:"volumes"`
	DataDirs    []SnapshotDataDir `json:"dataDirs"`
	Truncated   bool              `json:"truncated"`
}

// SnapshotDataDir — каталог с данными: его придётся переносить в том.
type SnapshotDataDir struct {
	Path  string `json:"path"`
	Files int    `json:"files"`
	Bytes int64  `json:"bytes"`
}

// CollectSnapshot снимает рецепт стека с хоста.
//
// project — имя compose-проекта; всё остальное агент выясняет сам. Платформа не
// передаёт ни одного пути: иначе задание «сними слепок» стало бы способом
// прочитать любой файл на сервере клиента.
func CollectSnapshot(ctx context.Context, project string) (StackSnapshot, error) {
	snap := StackSnapshot{
		Project:     project,
		Env:         map[string]string{},
		ConfigFiles: map[string]string{},
		Digests:     map[string]string{},
		Volumes:     []string{},
		DataDirs:    []SnapshotDataDir{},
	}
	if !safeProjectName(project) {
		return snap, fmt.Errorf("недопустимое имя проекта %q", tail(project, 40))
	}

	containers, err := inspectComposeContainers(ctx)
	if err != nil {
		return snap, err
	}

	var mine []dockerContainer
	for _, c := range containers {
		if c.Config.Labels["com.docker.compose.project"] == project {
			mine = append(mine, c)
		}
	}
	if len(mine) == 0 {
		return snap, fmt.Errorf("на сервере нет контейнеров проекта %q", tail(project, 40))
	}

	snap.WorkingDir = mine[0].Config.Labels["com.docker.compose.project.working_dir"]
	configFile := firstConfigFile(mine[0].Config.Labels["com.docker.compose.project.config_files"])
	if snap.WorkingDir == "" || configFile == "" {
		return snap, fmt.Errorf("docker не сообщил, где лежит описание проекта %q", tail(project, 40))
	}

	// Описание стека читаем ФАЙЛОМ, а не `compose config`.
	//
	// Нормализованный вид подставил бы значения переменных прямо в текст, и
	// пароли оказались бы в поле, которое платформа хранит открытым. Плюс
	// `config` выполняет `extends` из соседних каталогов — то есть читает
	// файлы, о которых мы не просили.
	compose, err := readLimited(configFile, maxSnapshotComposeBytes)
	if err != nil {
		return snap, fmt.Errorf("не удалось прочитать %s: %w", filepath.Base(configFile), err)
	}
	snap.Compose = compose

	// Переменные стека: .env рядом с описанием.
	if raw, err := readLimited(filepath.Join(snap.WorkingDir, ".env"), maxSnapshotEnvBytes); err == nil {
		snap.Env = parseEnvFile(raw)
	}

	// Дайджест — у образа, а не у контейнера: поля RepoDigests в осмотре
	// контейнера нет. Отказ осмотра образа слепок не роняет — поле останется
	// пустым, и нормализация скажет «дайджест не определён» вместо того, чтобы
	// пришпилить стек идентификатором, которого нет ни в одном реестре.
	images := inspectImageDigests(ctx, mine)

	total := len(snap.Compose)
	seenDirs := map[string]bool{}
	for _, c := range mine {
		service := c.Config.Labels["com.docker.compose.service"]
		if service == "" {
			continue
		}
		snap.Digests[service] = imageDigest(c, images)

		mounts, _ := mountsOf(c)
		for _, m := range mounts {
			if m.Type == "volume" && m.Name != "" {
				snap.Volumes = append(snap.Volumes, m.Name)
				continue
			}
			if m.Type != "bind" || m.Source == "" {
				continue
			}
			rel, ok := relativeToDir(m.Source, snap.WorkingDir)
			if !ok {
				// Монтирование вне каталога стека (докер-сокет, чужие пути) —
				// не наше дело: такие сервисы всё равно не переносятся.
				continue
			}

			info, err := os.Stat(m.Source)
			if err != nil {
				continue
			}
			if info.IsDir() {
				// Один каталог нередко смонтирован в несколько сервисов сразу
				// (у Supabase объекты Storage читают три). Для человека это
				// один каталог и один перенос: три одинаковые строки с
				// кнопкой «перенести» — приглашение скопировать одно и то же
				// трижды.
				if seenDirs[rel] {
					continue
				}
				seenDirs[rel] = true
				files, bytes := dirSize(m.Source)
				snap.DataDirs = append(snap.DataDirs, SnapshotDataDir{Path: rel, Files: files, Bytes: bytes})
				continue
			}
			if _, seen := snap.ConfigFiles[rel]; seen {
				continue
			}
			content, err := readLimited(m.Source, maxSnapshotFileBytes)
			if err != nil {
				continue
			}
			if total+len(content) > maxSnapshotTotalBytes {
				snap.Truncated = true
				continue
			}
			total += len(content)
			snap.ConfigFiles[rel] = content
		}
	}

	snap.Volumes = uniqueSorted(snap.Volumes)
	sort.Slice(snap.DataDirs, func(i, j int) bool { return snap.DataDirs[i].Path < snap.DataDirs[j].Path })
	return snap, nil
}

// safeProjectName — имя проекта приходит по сети и подставляется в сравнение с
// метками. Ограничиваем его тем, что вообще бывает именем compose-проекта.
func safeProjectName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// relativeToDir — путь внутри каталога стека, приведённый к относительному.
//
// Чужие панели пишут монтирования абсолютными путями; платформа кладёт файлы
// приложения относительно его каталога. Всё, что вне каталога стека, слепок не
// забирает вовсе.
func relativeToDir(path, dir string) (string, bool) {
	clean := filepath.Clean(path)
	root := filepath.Clean(dir)
	if root == "" || root == "." {
		return "", false
	}
	if clean == root {
		return "", false
	}
	if !strings.HasPrefix(clean, root+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(strings.TrimPrefix(clean, root+string(filepath.Separator))), true
}

func readLimited(path string, limit int) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > int64(limit) {
		return "", fmt.Errorf("файл больше %d байт", limit)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// parseEnvFile разбирает .env стека.
//
// Кавычки снимаются: docker compose трактует `KEY='значение'` как значение без
// кавычек, и оставить их значило бы перенести пароль вместе с апострофами —
// стек поднялся бы и не смог подключиться к собственной базе.
func parseEnvFile(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		key = strings.TrimSpace(key)
		if !found || key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '\'' && value[len(value)-1] == '\'') ||
				(value[0] == '"' && value[len(value)-1] == '"') {
				value = value[1 : len(value)-1]
			}
		}
		out[key] = value
	}
	return out
}

func dirSize(path string) (files int, bytes int64) {
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	return files, bytes
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// MigrateResult — итог переноса каталога в том.
// Поля переноса помечены omitempty намеренно.
//
// Той же структурой отчитываются задания остановки и подъёма стека, где
// переноса не было вовсе. Без omitempty в журнал уезжали нули и `matched:
// false` — и остановка стека выглядела в событии `host.task_finished` как
// провалившийся перенос данных, то есть как авария вместо выполненной просьбы.
type MigrateResult struct {
	Volume      string `json:"volume,omitempty"`
	SourceFiles int    `json:"sourceFiles,omitempty"`
	SourceBytes int64  `json:"sourceBytes,omitempty"`
	TargetFiles int    `json:"targetFiles,omitempty"`
	TargetBytes int64  `json:"targetBytes,omitempty"`
	Matched     bool   `json:"matched,omitempty"`
	// StackStopped — чужой стек остановлен и НЕ поднят обратно.
	//
	// В отчёте отдельным полем, а не в тексте: после удачного переноса стек
	// остаётся лежать намеренно, и человек обязан узнать об этом из отчёта, а
	// не по отсутствию сайта.
	StackStopped bool `json:"stackStopped,omitempty"`
	// Restored — стек возвращён в работу после неудачи.
	Restored bool `json:"restored,omitempty"`
}

// copyImage — образ, в котором выполняется копирование и сверка.
//
// Тот же, что у резервных копий (backup.go). Расхождение здесь стоило бы
// дорого: образ тянется на хост в момент операции, а чужого тега на хосте
// заведомо нет — значит лишний поход в реестр там, где он опаснее всего.
const copyImage = "alpine:3.21"

// migrateFreeSpaceFactor — запас сверх размера каталога.
//
// Копия делается рядом с оригиналом (том docker лежит на той же файловой
// системе), то есть на время переноса данные занимают место дважды.
const migrateFreeSpaceFactor = 1.1

// migrateMinFreeBytes — неснижаемый остаток после копирования.
const migrateMinFreeBytes = 512 << 20

// migrateDeps — точки соприкосновения с миром.
//
// Вынесены полями ради тестов: проверять здесь надо не «скопировалось ли», а
// ПОРЯДОК — образ до остановки, замер после, подъём при любом отказе. Именно
// порядок и был сломан, и ни один тест против настоящего docker его бы не
// поймал дёшево.
type migrateDeps struct {
	docker     func(ctx context.Context, args ...string) (string, error)
	compose    func(ctx context.Context, dir string, args ...string) (string, error)
	workingDir func(ctx context.Context, project string) (string, error)
	dirSize    func(path string) (int, int64)
	freeBytes  func(path string) (int64, error)
}

func defaultMigrateDeps() migrateDeps {
	return migrateDeps{}.withDefaults()
}

// withDefaults подставляет настоящие вызовы вместо незаданных.
//
// Не для красоты: незаполненное поле — это nil-функция, а её вызов посреди
// операции над боевыми данными означает панику агента при уже остановленном
// стеке. Пусть лучше отсутствие подмены значит «делай по-настоящему».
func (d migrateDeps) withDefaults() migrateDeps {
	if d.docker == nil {
		d.docker = runDocker
	}
	if d.compose == nil {
		d.compose = dockerCompose
	}
	if d.workingDir == nil {
		d.workingDir = composeWorkingDir
	}
	if d.dirSize == nil {
		d.dirSize = dirSize
	}
	if d.freeBytes == nil {
		d.freeBytes = freeBytes
	}
	return d
}

// composeWorkingDir — каталог стека по меткам docker.
//
// Путь берётся у docker, а не из задания: принять готовый путь значило бы дать
// платформе право копировать в том любой каталог сервера.
func composeWorkingDir(ctx context.Context, project string) (string, error) {
	containers, err := inspectComposeContainers(ctx)
	if err != nil {
		return "", err
	}
	for _, c := range containers {
		if c.Config.Labels["com.docker.compose.project"] == project {
			return c.Config.Labels["com.docker.compose.project.working_dir"], nil
		}
	}
	return "", fmt.Errorf("на сервере нет контейнеров проекта %q", tail(project, 40))
}

// MigrateDataDir переносит каталог стека в именованный том.
//
// ПОРЯДОК ВАЖЕН. Стек останавливается ДО копирования: копировать каталог, в
// который пишет работающий сервис, — значит получить том, отличающийся от
// оригинала непредсказуемо. Останавливаем весь проект, а не один контейнер:
// файлы одного сервиса нередко пишет соседний.
//
// КОПИЯ, А НЕ ПЕРЕМЕЩЕНИЕ. Оригинал остаётся на диске: пока человек не увидел,
// что стек работает на томе, единственный способ вернуться — исходный каталог.
//
// СВЕРКА ОБЯЗАТЕЛЬНА. Число файлов и сумма размеров считаются с обеих сторон;
// расхождение возвращается как есть, без попытки «дочинить». Молча
// разошедшийся перенос данных — худший исход операции.
func MigrateDataDir(ctx context.Context, p Paths, project, dir, volume string) (MigrateResult, error) {
	// Перенос останавливает стек и копирует его данные — то же полномочие, что
	// у остановки, и та же проверка перед ним.
	if err := refuseManagedStack(ctx, p, project); err != nil {
		return MigrateResult{Volume: volume}, err
	}
	return migrateDataDir(ctx, project, dir, volume, defaultMigrateDeps())
}

func migrateDataDir(
	ctx context.Context,
	project, dir, volume string,
	deps migrateDeps,
) (res MigrateResult, err error) {
	deps = deps.withDefaults()
	res.Volume = volume

	if !safeProjectName(project) {
		return res, fmt.Errorf("недопустимое имя проекта %q", tail(project, 40))
	}
	if !safeVolumeName(volume) {
		return res, fmt.Errorf("недопустимое имя тома %q", tail(volume, 60))
	}

	workingDir, err := deps.workingDir(ctx, project)
	if err != nil {
		return res, err
	}
	if workingDir == "" {
		return res, fmt.Errorf("docker не сообщил, где лежит проект %q", tail(project, 40))
	}

	// Путь собираем САМИ из каталога проекта и относительного имени: принять
	// готовый путь из задания значило бы дать платформе копировать в том любой
	// каталог сервера, включая /etc.
	rel := filepath.Clean("/" + dir)
	source := filepath.Join(workingDir, rel)
	if _, ok := relativeToDir(source, workingDir); !ok {
		return res, fmt.Errorf("каталог %q вне каталога стека", tail(dir, 60))
	}
	info, statErr := os.Stat(source)
	if statErr != nil || !info.IsDir() {
		return res, fmt.Errorf("каталога %s на сервере нет", tail(dir, 60))
	}

	// --- всё, что можно проверить, проверяем ДО остановки --------------------
	//
	// После стопа боевой стек лежит, и каждая проверка, отложенная на «потом»,
	// превращается из отказа в простой.

	_, approxBytes := deps.dirSize(source)
	free, freeErr := deps.freeBytes(workingDir)
	if freeErr != nil {
		return res, fmt.Errorf("не удалось узнать свободное место: %w", freeErr)
	}
	need := int64(float64(approxBytes)*migrateFreeSpaceFactor) + migrateMinFreeBytes
	if free < need {
		return res, fmt.Errorf(
			"для переноса нужно %d МиБ свободного места, доступно %d МиБ: "+
				"копия делается рядом с оригиналом, и на время переноса данные занимают место дважды",
			need>>20, free>>20)
	}

	// Образ для копирования тянем ДО остановки.
	//
	// На боевом хосте первый же поход в Docker Hub упёрся в 429: лимит
	// считается на подсеть провайдера, и соседи по хостингу выбирают квоту за
	// вас. Сделай мы это после стопа — чужой лимит означал бы лежащий прод.
	if _, inspectErr := deps.docker(ctx, "image", "inspect", copyImage); inspectErr != nil {
		if out, pullErr := deps.docker(ctx, "pull", copyImage); pullErr != nil {
			return res, fmt.Errorf(
				"образ %s для копирования недоступен: %w: %s. Стек не остановлен",
				copyImage, pullErr, tail(out, 200))
		}
	}

	// --- с этого момента чужой стек лежит ------------------------------------

	if out, stopErr := deps.compose(ctx, workingDir, "-p", project, "stop"); stopErr != nil {
		return res, fmt.Errorf("не удалось остановить стек: %w: %s", stopErr, tail(out, 300))
	}
	res.StackStopped = true

	// Любой отказ дальше обязан вернуть стек в работу. Провал операции не
	// должен означать лежащий прод: оригинал каталога не тронут, копировать
	// можно будет ещё раз, а сервис всё это время должен работать.
	defer func() {
		if err == nil {
			return
		}
		if _, startErr := deps.compose(ctx, workingDir, "-p", project, "start"); startErr == nil {
			res.StackStopped = false
			res.Restored = true
		}
	}()

	// Успешный `stop` не означает остановленный стек: с чужим именем проекта
	// compose отработает без ошибки и не остановит ничего. Дальше мы копировали
	// бы каталог под работающей записью — молча, и сверка могла бы сойтись.
	if out, psErr := deps.compose(ctx, workingDir, "-p", project, "ps", "-q"); psErr != nil {
		return res, fmt.Errorf("не удалось проверить, что стек остановлен: %w: %s", psErr, tail(out, 200))
	} else if strings.TrimSpace(out) != "" {
		return res, fmt.Errorf(
			"стек %q продолжает работать после остановки — копировать каталог под работающей записью нельзя",
			tail(project, 40))
	}

	// Считаем источник ТОЛЬКО СЕЙЧАС: живой сервис пишет в каталог, и замер до
	// остановки расходился бы с копией на удачном переносе.
	res.SourceFiles, res.SourceBytes = deps.dirSize(source)

	if out, volErr := deps.docker(ctx, "volume", "create", volume); volErr != nil {
		return res, fmt.Errorf("не удалось создать том: %w: %s", volErr, tail(out, 200))
	}

	// Копируем внутри контейнера: так не нужно знать, где docker держит тома,
	// и права с владельцами сохраняются вместе с содержимым.
	if out, cpErr := deps.docker(ctx, "run", "--rm",
		"-v", source+":/from:ro",
		"-v", volume+":/to",
		copyImage, "sh", "-c", "cp -a /from/. /to/"); cpErr != nil {
		return res, fmt.Errorf("копирование не удалось: %w: %s", cpErr, tail(out, 300))
	}

	out, verifyErr := deps.docker(ctx, "run", "--rm", "-v", volume+":/to", copyImage,
		"sh", "-c", "find /to -type f | wc -l; find /to -type f -exec stat -c %s {} + | awk '{s+=$1} END {print s+0}'")
	if verifyErr != nil {
		return res, fmt.Errorf("сверка не удалась: %w: %s", verifyErr, tail(out, 200))
	}
	fmt.Sscanf(strings.TrimSpace(out), "%d\n%d", &res.TargetFiles, &res.TargetBytes)

	res.Matched = res.TargetFiles == res.SourceFiles && res.TargetBytes == res.SourceBytes
	// Стек остаётся остановленным намеренно: следом платформа поднимает свой на
	// тех же данных, а работающий чужой писал бы в каталог, копию которого мы
	// уже сняли. Отчёт несёт это отдельным полем.
	return res, nil
}

// StartStack возвращает чужой стек в работу.
//
// Отдельная операция, потому что нужна отдельная кнопка: после переноса данных
// стек остаётся остановленным, и единственным способом поднять его обратно был
// бы вход по SSH. Откат обязан быть в том же интерфейсе, что и действие.
func StartStack(ctx context.Context, p Paths, project string) error {
	if !safeProjectName(project) {
		return fmt.Errorf("недопустимое имя проекта %q", tail(project, 40))
	}
	if err := refuseManagedStack(ctx, p, project); err != nil {
		return err
	}
	workingDir, err := composeWorkingDir(ctx, project)
	if err != nil {
		return err
	}
	if out, err := dockerCompose(ctx, workingDir, "-p", project, "start"); err != nil {
		return fmt.Errorf("не удалось поднять стек: %w: %s", err, tail(out, 300))
	}
	return nil
}

// refuseManagedStack — отказ трогать стек, которым распоряжается сама
// платформа.
//
// ЗАЧЕМ. Задания приходят с именем проекта, и это имя не проверял НИКТО:
// `deploy_request_stack_task` пишет его как есть, а фильтр «наш/чужой» жил
// только в разметке кнопок интерфейса. Запрос с именем `tracedocs-proxy` и
// видом `stop-stack` останавливал прокси платформы — то есть гасил все домены
// сервера разом; с именем платформенного приложения — его стек.
//
// Прав для этого хватало обычных owner/admin своего проекта, так что чужие
// проекты недосягаемы, а восстановление наступает само (EnsureProxy делает
// `up -d` каждый такт, RecoverUnhealthy поднимает приложения). Но «кнопки
// такой нет» — не защита: защита обязана стоять там, где выполняется
// действие. Признак «наш» агент и так вычисляет сам при осмотре.
//
// Две проверки, а не одна. Каталог — основная: она опознаёт и приложения, и
// прокси по фактическому расположению. Префикс имени — на случай, когда
// каталог прочитать не удалось: имена `tracedocs-*` платформа резервирует за
// собой (см. slugIsReserved на стороне сервера), и чужого стека с таким
// именем быть не должно.
func refuseManagedStack(ctx context.Context, p Paths, project string) error {
	if project == proxyProjectName || strings.HasPrefix(project, reservedProjectPrefix) {
		return fmt.Errorf(
			"%s — стек самой платформы, управлять им заданиями нельзя", project)
	}

	dir, err := composeWorkingDir(ctx, project)
	if err != nil {
		// «Не нашли контейнеров» — не повод разрешать: дальше вызывающий всё
		// равно упрётся в ту же ошибку, а мы не выдали разрешения вслепую.
		return err
	}
	if withinRoots(filepath.Clean(dir), ManagedRoots(p)) {
		return fmt.Errorf(
			"стек %s развёрнут этой платформой (%s) — управляйте им через карточку приложения",
			project, dir)
	}
	return nil
}

// reservedProjectPrefix — имена, зарезервированные платформой за собой.
const reservedProjectPrefix = "tracedocs-"

// StopStack останавливает чужой стек, не разрушая его.
//
// `stop`, а не `down`: down удаляет контейнеры и сети, и вернуть чужой стек
// после этого можно только пересозданием — на compose-файле, который писали не
// мы и который может не подняться повторно. stop обратим командой start
// (StartStack), поэтому пара действий в интерфейсе симметрична.
func StopStack(ctx context.Context, p Paths, project string) error {
	if !safeProjectName(project) {
		return fmt.Errorf("недопустимое имя проекта %q", tail(project, 40))
	}
	if err := refuseManagedStack(ctx, p, project); err != nil {
		return err
	}
	workingDir, err := composeWorkingDir(ctx, project)
	if err != nil {
		return err
	}
	if out, err := dockerCompose(ctx, workingDir, "-p", project, "stop"); err != nil {
		return fmt.Errorf("не удалось остановить стек: %w: %s", err, tail(out, 300))
	}
	return nil
}

func safeVolumeName(name string) bool {
	if len(name) < 2 || len(name) > 128 {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case (r == '-' || r == '_' || r == '.') && i > 0:
		default:
			return false
		}
	}
	return true
}

func runDocker(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = dockerEnv()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// snapshotJSON — размер готового слепка для журнала агента.
func snapshotJSON(snap StackSnapshot) int {
	raw, err := json.Marshal(snap)
	if err != nil {
		return 0
	}
	return len(raw)
}

// taskMark — отметка о заданиях в task.json.
//
// TaskID — последнее задание, чей отчёт платформа приняла. Unreported —
// восстановление, исход которого записан, а отчёт ещё не доехал (ADR-0063,
// решение 7). Старый формат `{"task_id"}` читается как «отчёт принят»: прежний
// агент писал его только после принятого отчёта.
//
// Неотправленный исход хранится только у восстановления: отчёт слепка стека
// несёт значения переменных, и держать его на диске ради повтора нельзя.
type taskMark struct {
	TaskID     string             `json:"task_id"`
	Unreported *unreportedRestore `json:"unreported,omitempty"`
}

type unreportedRestore struct {
	TaskID string `json:"task_id"`
	Set    string `json:"set"`
	MS     int64  `json:"ms"`
	// Error уже затёрт значениями переменных внутри RestoreBackup.
	Error string `json:"error"`
}

func saveTaskMark(path string, mark taskMark) error {
	raw, err := json.Marshal(mark)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

// RunTask выполняет задание платформы: снять слепок или перенести данные.
//
// Задание выполняется РОВНО ОДИН РАЗ на идентификатор: отметка о жизни приносит
// его каждую минуту, пока платформа не приняла отчёт, и без защиты агент
// снимал бы слепок чужого стека по кругу, а перенос данных — повторял бы
// копирование гигабайтов.
func RunTask(
	ctx context.Context,
	client *Client,
	id Identity,
	p Paths,
	task HostTask,
	// apps — желаемое состояние с последнего такта. Нужно заданию на копию:
	// ЧТО резервировать, знает шаблон (BackupSpec), а не агент, и догадаться
	// он не может — какой из сервисов база, видно только из описания.
	apps []DesiredApp,
	// storage — хранилище клиента для копий (ADR-0046) или nil, если компания
	// его не подключила. Отдельным параметром, а не полем в apps: хранилище
	// одно на всю компанию, и класть его копию в каждое приложение значило бы
	// рассылать ключ столько раз, сколько у хоста стеков.
	storage *ObjectStorageSpec,
) error {
	markPath := filepath.Join(p.StateDir, "task.json")

	var mark taskMark
	if raw, err := os.ReadFile(markPath); err == nil {
		_ = json.Unmarshal(raw, &mark)
	}
	if mark.TaskID == task.ID || task.ID == "" {
		return nil
	}

	switch task.Kind {
	case "export":
		snap, err := CollectSnapshot(ctx, task.Project)
		if err != nil {
			// Неудачу обязана узнать платформа, а не только stderr агента.
			//
			// Раньше ошибка просто печаталась: задание навсегда оставалось в
			// `pending`, отметка task.json не писалась (она ставится в конце),
			// и агент повторял ту же падающую операцию каждую минуту. Диалог
			// перехвата при этом держал кнопку заблокированной с подписью
			// «Снимаем описание…» — бессрочно.
			//
			// Ручка та же, что у переноса данных: она переводит задание в
			// `failed` с текстом. Отдельной заводить незачем.
			if reportErr := client.ReportMigration(
				ctx, id, task.ID, MigrateResult{}, err.Error(),
			); reportErr != nil {
				fmt.Fprintf(os.Stderr, "отчёт о неудаче слепка: %v\n", reportErr)
			}
			return err
		}
		if err := client.ReportSnapshot(ctx, id, task.ID, snap); err != nil {
			return err
		}
		fmt.Printf("слепок стека %s снят: %d сервисов, %d конфигов, %d КиБ\n",
			task.Project, len(snap.Digests), len(snap.ConfigFiles), snapshotJSON(snap)/1024)

	case "backup":
		// Плановая копия (8.1). Раньше копия снималась только перед выкатом
		// версии: не выкатывали месяц — копий нет за месяц.
		var target DesiredApp
		found := false
		for _, app := range apps {
			if app.Slug == task.Project {
				target = app
				found = true
				break
			}
		}
		if !found {
			// Приложения нет в желаемом состоянии: его удалили между
			// постановкой задания и тактом. Отчитываемся ошибкой, иначе
			// задание висит в pending навсегда и агент повторяет его каждую
			// минуту — та же грабля, что была у слепка стека.
			failure := fmt.Sprintf("приложение %s не найдено в желаемом состоянии", task.Project)
			if err := client.ReportBackup(ctx, id, task.ID, "", 0, failure, BackupUpload{}); err != nil {
				fmt.Fprintf(os.Stderr, "отчёт о неудаче копии: %v\n", err)
			}
			return errors.New(failure)
		}

		// Восстановление сорвалось посреди: тома могут быть наполовину из копии.
		// Копия с такого стека при ротации вытеснила бы годную — ту самую, из
		// которой восстановление ещё можно повторить. Отказ без отметки, как у
		// остальных отказов копии.
		if hasRestoreFlag(p, target.Slug) {
			failure := "копия не снята: восстановление из копии не завершилось, и данные приложения " +
				"могут быть несогласованными — копия с них вытеснила бы годную при ротации. " +
				"Копии снова снимаются после удачного восстановления или выката"
			if err := client.ReportBackup(ctx, id, task.ID, "", 0, failure, BackupUpload{}); err != nil {
				fmt.Fprintf(os.Stderr, "отчёт о неудаче копии: %v\n", err)
			}
			return errors.New(failure)
		}

		dir, err := CreateBackup(ctx, p, target, target.BackupSpec)
		if err != nil {
			if reportErr := client.ReportBackup(ctx, id, task.ID, "", 0, err.Error(), BackupUpload{}); reportErr != nil {
				fmt.Fprintf(os.Stderr, "отчёт о неудаче копии: %v\n", reportErr)
			}
			return err
		}
		if dir == "" {
			// Пустой спецификации соответствует пустая копия: у приложения нет
			// ни базы, ни томов — резервировать нечего. Это не ошибка, но и не
			// копия: сказать «снята» значило бы обещать восстановление того,
			// чего не сохраняли.
			failure := "приложению нечего резервировать: в шаблоне не объявлены ни база, ни тома"
			if err := client.ReportBackup(ctx, id, task.ID, "", 0, failure, BackupUpload{}); err != nil {
				fmt.Fprintf(os.Stderr, "отчёт о пустой копии: %v\n", err)
			}
			return nil
		}

		set := filepath.Base(dir)
		size := dirBytes(dir)

		/*
		 * ВЫГРУЗКА ИДЁТ ПОСЛЕ СНЯТИЯ И НЕ ОТМЕНЯЕТ ЕГО (ADR-0046, решение 7).
		 * Копия уже лежит на диске клиента и защищает от `DROP TABLE`; отказ
		 * хранилища этого не отменяет, поэтому задание закрывается успехом, а
		 * беда с выгрузкой едет отдельным полем. Повтор — при следующей плановой
		 * копии: набор остаётся на диске, и бесконечный повтор на чужом канале
		 * мы себе не устраиваем.
		 */
		upload := BackupUpload{Status: "skipped"}
		if storage != nil && storage.configured() {
			result, upErr := UploadBackupSet(ctx, *storage, task.Project, target.Slug, dir)
			if upErr != nil {
				upload = BackupUpload{Status: "failed", Error: upErr.Error()}
				fmt.Fprintf(os.Stderr, "копия %s не уехала в хранилище: %v\n", task.Project, upErr)
			} else {
				upload = BackupUpload{
					Status: "done",
					Key:    result.ObjectKeys[0],
					Bytes:  result.Bytes,
				}
				fmt.Printf("копия %s уехала в хранилище: объектов %d, %d КиБ\n",
					task.Project, len(result.ObjectKeys), result.Bytes/1024)
			}
		}

		if err := client.ReportBackup(ctx, id, task.ID, set, size, "", upload); err != nil {
			return err
		}
		fmt.Printf("копия %s снята: набор %s, %d КиБ\n", task.Project, set, size/1024)

	case "restore":
		// Возврат приложения к выбранной копии по кнопке владельца (8.2, 0447).
		// До этого RestoreBackup звался ровно из одного места — автоотката
		// после неудачного обновления: вернуться к копии платформа умела
		// только сама и только в одном сценарии, а владелец — никак.
		//
		// Об исходе отчитываемся при ЛЮБОМ отказе, включая отказ на входе:
		// без отчёта задание висит в pending навсегда, агент берёт его каждую
		// минуту, а человек смотрит на «восстанавливаем…» без конца. Та же
		// грабля, на которой уже обожглись слепок стека и плановая копия.
		refuse := func(failure string) error {
			if err := client.ReportRestore(ctx, id, task.ID, task.BackupSet, 0, failure); err != nil {
				fmt.Fprintf(os.Stderr, "отчёт о неудаче восстановления: %v\n", err)
			}
			return errors.New(failure)
		}

		// Исход уже записан, не доехал только отчёт: повторяем ОТЧЁТ, а не
		// операцию. Второй прогон снова погасил бы стек и перезаписал тома
		// поверх того, что приложение успело записать. Подпись у запроса
		// свежая сама: одинаковую платформа отвергла бы как повтор.
		if u := mark.Unreported; u != nil && u.TaskID == task.ID {
			if err := client.ReportRestore(ctx, id, task.ID, u.Set, u.MS, u.Error); err != nil {
				return err
			}
			if err := saveTaskMark(markPath, taskMark{TaskID: task.ID}); err != nil {
				return err
			}
			fmt.Printf("отчёт о восстановлении %s из набора %s доставлен повторно\n", task.Project, u.Set)
			return nil
		}

		var target DesiredApp
		known := false
		for _, app := range apps {
			if app.Slug == task.Project {
				target = app
				known = true
				break
			}
		}
		if !known {
			// Приложение удалили между постановкой задания и тактом.
			// Разворачивать копию того, чего платформа больше не знает, значит
			// поднять на хосте стек, которым никто не управляет.
			return refuse(fmt.Sprintf("приложение %s не найдено в желаемом состоянии", task.Project))
		}

		if !validBackupSet(task.BackupSet) {
			return refuse(fmt.Sprintf("недопустимое имя набора копий: %q", tail(task.BackupSet, 40)))
		}

		// Путь собирает АГЕНТ: задание приносит только имя набора.
		setDir := filepath.Join(p.backupsDir(task.Project), task.BackupSet)
		if info, err := os.Stat(setDir); err != nil || !info.IsDir() {
			// На хосте держатся последние backup_keep наборов, а платформа
			// помнит все снятые: набор мог уехать в хранилище клиента и
			// исчезнуть с диска. Отказ внятный — иначе человек получил бы
			// ошибку docker про пустой каталог и гадал бы, что она означает.
			return refuse(fmt.Sprintf(
				"набор копий %s на хосте не найден: его унесла ротация либо он снимался не здесь",
				task.BackupSet))
		}

		// Время меряем вокруг самой операции — это и есть RTO, который верхний
		// тариф обещает измерять.
		started := time.Now()
		restoreErr := RestoreBackup(ctx, p, target, setDir)
		ms := time.Since(started).Milliseconds()
		// Файлы стека вернулись из набора при любом исходе, дошедшем до их
		// записи: без переноса базовой линии сверка дрейфа (ADR-0078) назвала бы
		// восстановление по кнопке владельца чужой правкой.
		adoptRestoredBaseline(p, task.Project, setDir)

		// Отмена ctx — это остановка агента (main.go:859, signal.NotifyContext),
		// своего срока у задания нет (main.go:703). Отказ убитого вместе с
		// группой процессов docker — не исход операции: записанный фазой 1, он
		// закрыл бы задание ложным отказом, а флаг держал бы стек лежащим до
		// нового нажатия владельца. Поэтому исход не пишем, отчёт не шлём и
		// возвращаем ошибку: задание выдадут снова, и восстановление пойдёт с
		// начала (ADR-0063, решение 6).
		//
		// ОГРАНИЧЕНИЕ: если у RunTask когда-нибудь появится свой срок, эта
		// ветка превратит его истечение в бесконечный повтор — задание будет
		// начинаться заново на каждой выдаче и срываться о тот же срок.
		if restoreErr != nil && ctx.Err() != nil {
			return fmt.Errorf("восстановление %s прервано остановкой агента, повторится после запуска: %w",
				task.Project, restoreErr)
		}

		failure := ""
		if restoreErr != nil {
			failure = restoreErr.Error()
		}

		// Фаза 1: исход — на диск ДО отчёта. Потерянный отчёт без этого
		// означал бы повтор всей операции на следующей выдаче задания. Ошибка
		// записи отчёт не останавливает: платформа хотя бы узнает исход сейчас.
		pending := mark
		pending.Unreported = &unreportedRestore{TaskID: task.ID, Set: task.BackupSet, MS: ms, Error: failure}
		if err := saveTaskMark(markPath, pending); err != nil {
			fmt.Fprintf(os.Stderr, "исход восстановления %s не записан до отчёта: %v\n", task.Project, err)
		}

		if reportErr := client.ReportRestore(ctx, id, task.ID, task.BackupSet, ms, failure); reportErr != nil {
			return reportErr
		}
		if restoreErr != nil {
			fmt.Fprintf(os.Stderr, "восстановление %s из набора %s: %v\n",
				task.Project, task.BackupSet, restoreErr)
		} else {
			fmt.Printf("приложение %s восстановлено из набора %s за %d с\n",
				task.Project, task.BackupSet, ms/1000)
		}

		// Фаза 2: отчёт принят — задание закрыто, и сорвавшееся тоже.
		// Разрушительная операция, чей неудачный исход платформа уже приняла,
		// без нового нажатия владельца повторяться не должна.
		if err := saveTaskMark(markPath, taskMark{TaskID: task.ID}); err != nil {
			return err
		}
		return restoreErr

	case "migrate-data":
		res, err := MigrateDataDir(ctx, p, task.Project, task.Dir, task.Volume)
		failure := ""
		if err != nil {
			failure = err.Error()
		}
		// Отчёт отправляем в ЛЮБОМ случае, включая неудачу: платформа обязана
		// узнать, что перенос не состоялся, — иначе человек будет ждать
		// завершения операции, которой уже нет.
		if reportErr := client.ReportMigration(ctx, id, task.ID, res, failure); reportErr != nil {
			return reportErr
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "перенос данных %s: %v (стек %s)\n", task.Dir, err,
				map[bool]string{true: "возвращён в работу", false: "ОСТАЛСЯ ОСТАНОВЛЕН"}[res.Restored])
		} else {
			fmt.Printf("перенос %s → %s: файлов %d→%d, байт %d→%d, сверка %s; стек оставлен остановленным\n",
				task.Dir, task.Volume, res.SourceFiles, res.TargetFiles,
				res.SourceBytes, res.TargetBytes, map[bool]string{true: "сошлась", false: "РАЗОШЛАСЬ"}[res.Matched])
		}

	case "start-stack":
		// Откат переноса: поднять чужой стек обратно. Отчёт отправляем в любом
		// случае — человек нажал кнопку и ждёт ответа именно на неё.
		startErr := StartStack(ctx, p, task.Project)
		failure := ""
		if startErr != nil {
			failure = startErr.Error()
		}
		if reportErr := client.ReportMigration(ctx, id, task.ID,
			MigrateResult{StackStopped: startErr != nil, Restored: startErr == nil}, failure); reportErr != nil {
			return reportErr
		}
		if startErr != nil {
			fmt.Fprintf(os.Stderr, "подъём стека %s: %v\n", task.Project, startErr)
		} else {
			fmt.Printf("стек %s поднят обратно\n", task.Project)
		}

	case "stop-stack":
		// Остановка перед перехватом: платформа поднимет свой стек на тех же
		// портах, и работающий чужой ей помешает. Отчёт — в любом случае:
		// «остановлено» и «не смогли» ведут к разным следующим шагам.
		stopErr := StopStack(ctx, p, task.Project)
		failure := ""
		if stopErr != nil {
			failure = stopErr.Error()
		}
		if reportErr := client.ReportMigration(ctx, id, task.ID,
			MigrateResult{StackStopped: stopErr == nil}, failure); reportErr != nil {
			return reportErr
		}
		if stopErr != nil {
			fmt.Fprintf(os.Stderr, "остановка стека %s: %v\n", task.Project, stopErr)
		} else {
			fmt.Printf("стек %s остановлен\n", task.Project)
		}

	default:
		return fmt.Errorf("неизвестное задание %q", tail(task.Kind, 40))
	}

	// Отметку пишем ПОСЛЕ отчёта: иначе неудачная доставка означала бы, что
	// задание «выполнено», а платформа его результата так и не увидела.
	// Неотправленный исход восстановления переносится как есть: он не должен
	// пропасть оттого, что между тактами прошло задание другого вида.
	mark.TaskID = task.ID
	return saveTaskMark(markPath, mark)
}

// dirBytes — размер каталога набора копий. Ошибки обхода игнорируются
// намеренно: размер идёт в журнал для человека, и неточность в нём не повод
// объявлять снятую копию неудачной.
func dirBytes(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}
