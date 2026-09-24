package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Переменные, доступные СБОРКЕ приложения из репозитория.
//
// ЗАЧЕМ. Next.js вшивает NEXT_PUBLIC_* в клиентский бандл на этапе сборки, а
// не читает их при запуске. Платформа отдавала переменные только в рантайм,
// поэтому приложение поднималось здоровым, проходило health gate и показывало
// в браузере undefined вместо адреса API. Отказ виден пользователю, не в CI.
//
// Замерено на переносимых приложениях: `NEXT_PUBLIC_*` есть у шести из девяти
// живых git-приложений, у b2b-admin-web их одиннадцать.
//
// ЧТО СЮДА НЕ ПОПАДАЕТ. Секреты. Аргументы сборки видны в `docker history`
// собранного образа — значит переданный туда секрет остаётся в метаданных
// слоёв навсегда. Именно это обнаружено у Coolify: он помечает build-time
// каждую переменную, и в образах лежат SUPABASE_SERVICE_ROLE_KEY, токены
// SMS-шлюзов и ключи встраивания. Разделение проводит сервер: в контракт
// приезжает отдельное поле buildArgs, собранное ТОЛЬКО из vars_public, и
// агент не смешивает его с общим окружением даже случайно.

// fromDirective — начало ступени сборки. Регистр и отступ на усмотрение
// автора; `COPY --from=` и слово FROM внутри команды сюда не подходят,
// потому что якорь требует начала строки.
var fromDirective = regexp.MustCompile(`(?i)^\s*FROM\s+\S`)

// selectBuildArgs — какие имена уедут в сборку.
//
// Правила те же, что у .env: имя проверяется второй раз уже на хосте (вход с
// сервера недоверенный), служебные имена платформы отбрасываются — отдать в
// сборку APP_SLUG значит позволить репозиторию увести имя compose-проекта.
//
// Порядок фиксирован сортировкой: имена уезжают в текст compose, а его
// отпечаток решает, переприменять ли стек. Плавающий порядок означал бы
// пересборку на каждом цикле агента.
func selectBuildArgs(args map[string]string) []string {
	names := make([]string, 0, len(args))
	for name := range args {
		if safeEnvKey.MatchString(name) && !isReservedEnvKey(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil
	}
	return names
}

// injectBuildArgs объявляет аргументы после каждой ступени сборки.
//
// Без объявления `ARG` docker молча игнорирует `--build-arg`: значение до
// сборки не доходит, и симптом ровно тот же, что был до всей этой работы.
// Coolify подставляет ARG сам, поэтому в переносимых репозиториях объявлений
// может не быть вовсе — полагаться на то, что автор их написал, нельзя.
//
// После КАЖДОГО FROM, а не один раз сверху: область видимости аргумента
// заканчивается на следующей ступени, и объявление только в начале файла не
// дошло бы до ступени, где выполняется сборка фронтенда.
//
// Повторное объявление безвредно, если автор уже написал своё: `ARG` без
// значения переобъявляет имя, не затирая переданное значение. Поэтому
// разбирать, что там уже есть, не нужно.
//
// Оригинальный файл не изменяется — результат пишется рядом отдельным файлом
// (см. writeBuildDockerfile). Править код клиента перед сборкой платформа не
// вправе, а сгенерированный файл видно глазами и можно сверить.
func injectBuildArgs(dockerfile string, names []string) string {
	if len(names) == 0 {
		return dockerfile
	}

	var declaration strings.Builder
	for _, name := range names {
		fmt.Fprintf(&declaration, "ARG %s\n", name)
	}
	block := declaration.String()

	lines := strings.Split(dockerfile, "\n")
	out := make([]string, 0, len(lines)+len(names)*2)
	for _, line := range lines {
		out = append(out, line)
		if fromDirective.MatchString(line) {
			out = append(out, strings.TrimSuffix(block, "\n"))
		}
	}
	return strings.Join(out, "\n")
}

// Имя генерируемого Dockerfile.
//
// Соседний файл, а не правка исходного: код клиента платформа перед сборкой
// не изменяет, а сгенерированный файл видно глазами и можно сверить с
// оригиналом. Имя нарочно узнаваемое — если он попадётся в репозитории
// человеку, понятно, откуда взялся.
//
// Файл живёт в рабочей копии и переживает `git clean -fd` не дольше одного
// цикла: FetchRepo чистит untracked, поэтому он пишется заново перед каждой
// сборкой — как и синтетический compose.
const buildDockerfileName = "Dockerfile.tracedocs"

// requireDockerfile — есть ли в корне рабочей копии Dockerfile.
//
// Проверка отдельная и безусловная. Раньше она жила внутри
// writeBuildDockerfile, а тот выходил по первому же `if len(names) == 0` —
// то есть у приложения БЕЗ переменных сборки (самый частый случай для
// бэкенда) наличие файла не проверял никто. Отсутствие всплывало на фазе
// build сырым текстом docker: «failed to read dockerfile: open
// /opt/tracedocs/deploy/repos/<slug>/Dockerfile: no such file or directory» —
// после клонирования, подъёма прежнего стека и минут ожидания.
//
// Каталог передаётся готовым: это папка приложения (0284), по умолчанию —
// корень рабочей копии. Имя файла по-прежнему одно: путь к Dockerfile внутри
// папки в контракте не задаётся, и об этом говорим прямо, чтобы человек не
// искал, где переопределить имя.
func requireDockerfile(dir, baseDir string) error {
	path := filepath.Join(dir, "Dockerfile")
	if _, err := os.Stat(path); err != nil {
		where := "в корне репозитория"
		if baseDir != "" {
			where = fmt.Sprintf("в папке %s репозитория", baseDir)
		}
		return fmt.Errorf(
			"%s нет файла Dockerfile — способ сборки «образ из Dockerfile» ищет его "+
				"по имени Dockerfile в указанной папке приложения (другие имена платформа "+
				"пока не поддерживает): %w", where, err)
	}
	return nil
}

// writeBuildDockerfile готовит Dockerfile со объявленными ARG.
//
// Вызывается только когда у приложения есть переменные сборки: без них
// собираем по оригиналу, и лишнего файла в рабочей копии не появляется.
func writeBuildDockerfile(dir string, app DesiredApp, names []string) error {
	if len(names) == 0 {
		return nil
	}
	source := filepath.Join(dir, "Dockerfile")

	raw, err := os.ReadFile(source)
	if err != nil {
		// Отдельное сообщение: «нет Dockerfile» — самая частая причина
		// неудачи этого способа сборки, и общий текст ошибки чтения файла
		// заставлял бы искать её по пути в конце строки.
		where := "в корне репозитория"
		if app.GitBaseDir != "" {
			where = "в папке " + app.GitBaseDir + " репозитория"
		}
		return fmt.Errorf("Dockerfile не найден %s: %w", where, err)
	}

	target := filepath.Join(dir, buildDockerfileName)
	body := injectBuildArgs(string(raw), names)
	if err := writeFileAtomic(target, []byte(body), 0o640); err != nil {
		return fmt.Errorf("не удалось записать %s: %w", buildDockerfileName, err)
	}
	return nil
}
