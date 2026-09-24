package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Получение кода приложения из репозитория.
//
// Сборка идёт НА ХОСТЕ, а не в нашем контуре. Так у платформы не оказывается
// ни чужого кода, ни собранных из него образов, а клиенту не нужно ни отдавать
// нам доступ к репозиторию навсегда, ни поднимать собственный реестр. Плата —
// хост тратит свои ресурсы на сборку, и мы не можем прогнать образ через
// проверки до выката.
//
// compose берётся из самого репозитория. Своего шаблонизатора здесь нет
// намеренно: подстановку ${VAR} делает docker compose из .env, который агент
// пишет рядом ровно так же, как для приложений из каталога.

// Сколько ждём сеть. Репозиторий может быть большим, а канал у клиента — узким,
// но бесконечно висеть цикл агента не может.
const gitTimeout = 5 * time.Minute

// Глубина клона. Полная история для сборки не нужна, а на больших репозиториях
// разница в трафике измеряется сотнями мегабайт.
const gitCloneDepth = "1"

// safeGitRepo — адрес репозитория.
//
// Только SSH-форма scp-подобного вида (git@host:owner/repo.git) и ssh://.
// HTTPS сознательно не поддержан: он потребовал бы хранить логин и пароль или
// токен в открытом виде в URL, который попадёт и в .git/config на хосте, и в
// вывод команд. Ключ на один репозиторий с правом только на чтение — меньшая
// уступка.
//
// Начинаться с дефиса адрес не может: иначе git прочитал бы его как флаг.
// Первый символ имени пользователя — не дефис. `[user@]host` git отдаёт в ssh
// ОДНИМ аргументом, и `-F.ssh@host:a/b` там читается как флаг -F: подсунутый
// конфиг ssh даёт ProxyCommand, то есть выполнение произвольной команды. От
// этого нас защищала бы только внутренняя проверка самого git
// (CVE-2017-1000117), а опираться на неё в модели «агент от root на чужой
// машине» не стоит — тем более что цена запрета один символ.
var safeGitRepo = regexp.MustCompile(
	`^(ssh://)?[a-zA-Z0-9._~][a-zA-Z0-9._~-]*@[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?[:/][A-Za-z0-9._~/-]{1,200}$`,
)

// safeGitHubRepoPath — репозиторий, выбранный через GitHub App: `owner/repo`.
//
// Адрес для клона агент собирает сам, а токен подаёт git отдельно. Форма узкая
// намеренно: сегмент начинается с буквы или цифры (ведущий дефис однажды
// прочитался бы как флаг), слэш внутри сегмента запрещён — иначе `a/../../x`
// увёл бы запрос на другой путь GitHub.
var safeGitHubRepoPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// Имя переменной окружения, из которой credential helper читает токен.
//
// Через окружение, а не через аргументы: argv виден в `ps` любому процессу на
// хосте, окружение — только владельцу процесса и root. Токен в аргументах
// означал бы утечку клиенту же на его собственном сервере.
const gitTokenEnvName = "TRACEDOCS_GIT_TOKEN"

// Пользователь, под которым GitHub принимает токен установки. Значение
// фиксировано протоколом GitHub, паролем служит сам токен.
const gitTokenUser = "x-access-token"

// safeGitRef — имя ветки. Узко и намеренно: значение уходит в аргументы git,
// а `--upload-pack=...` в виде имени ветки — известный способ выполнить
// произвольную команду.
var safeGitRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$`)

// safeGitPublicRepo — публичный репозиторий: клон анонимный, по https.
//
// Зеркало GIT_PUBLIC_HTTPS_RE в BFF и CHECK apps_git_repo_check (0178) — три
// копии обязаны совпадать. Только https (http — код, подменяемый по пути и
// исполняемый от root); хост — доменное имя с точкой и буквенной TLD
// (IP-литералы и односегментные имена не проходят: адрес во внутреннюю сеть
// был бы исходящим запросом с хоста клиента по нашему указанию); '@', '%',
// '?', '#' исключены классом символов — креды и обходы в URL оседали бы в
// .git/config и в выводе упавших команд.
var safeGitPublicRepo = regexp.MustCompile(
	`^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}(:[0-9]{1,5})?/[A-Za-z0-9._~/-]{1,200}$`,
)

// safeGitBaseDir — папка приложения внутри репозитория (0284).
//
// Зеркало GIT_BASE_DIR_RE в BFF и CHECK apps_git_base_dir_check — три копии
// обязаны совпадать.
//
// Сегмент начинается с буквы, цифры или подчёркивания, поэтому `.` и `..`
// сегментами быть не могут в принципе: путь склеивается с рабочей копией через
// filepath.Join, и `../../etc` увёл бы корень раздачи статики за её пределы.
// Ведущий и хвостовой слэш запрещены той же формой — значение приходит уже
// нормализованным, а `//` и `/` дали бы разные пути к одному каталогу и
// разъехались бы с отпечатком состояния.
//
// Скрытые каталоги (`.github`, `.config`) исключены намеренно: приложения там
// не живут, а разрешить ведущую точку значит охранять `..` одной лишь длиной
// сегмента.
var safeGitBaseDir = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$`)

// Потолок длины пути папки — тот же, что у CHECK в базе.
const maxGitBaseDirLen = 200

// repoAppDir — каталог приложения внутри рабочей копии репозитория.
//
// Имя с приставкой repo — не украшение: `p.appDir(slug)` рядом означает
// СЛУЖЕБНЫЙ каталог приложения на хосте (там .env и конфиги платформы), и
// перепутать их значит смонтировать секреты в контейнер как содержимое сайта.
//
// Пустой GitBaseDir даёт саму рабочую копию: так вело себя всё до появления
// поля, и приложения, созданные раньше, обязаны работать без единой правки.
//
// Симлинки разыменовываются ДЛЯ ПРОВЕРКИ, и результат обязан остаться внутри
// рабочей копии. Проверка не теоретическая: содержимое каталога — код клиента,
// и коммит с `apps/web -> /etc` превратил бы способ «статика» в раздачу
// системных файлов сервера по его же домену, а способ «Dockerfile» — в
// сборочный контекст из чужого каталога.
//
// Возвращается при этом ЛЕКСИЧЕСКИЙ путь, а не разыменованный. Его агент
// отдаёт docker, а тот пишет его в метку `project.working_dir` как есть — и по
// этой метке платформа потом узнаёт собственные стеки. Отдай мы сюда
// разыменованный, на хосте с симлинком в служебном пути (`/opt` на отдельном
// разделе — частая раскладка) метка перестала бы совпадать с каталогом, и
// собственный стек считался бы чужим.
func repoAppDir(p Paths, app DesiredApp) (string, error) {
	root := p.repoDir(app.Slug)
	if app.GitBaseDir == "" {
		return root, nil
	}
	if err := validateGitBaseDir(app.GitBaseDir); err != nil {
		return "", err
	}

	dir := filepath.Join(root, app.GitBaseDir)

	// EvalSymlinks заодно проверяет существование: отдельный Stat не нужен, а
	// сообщение здесь понятнее сырого «no such file or directory» из docker
	// минутами позже.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf(
			"в репозитории нет папки %q, указанной как папка приложения: %w",
			app.GitBaseDir, err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("не удалось разобрать путь рабочей копии: %w", err)
	}
	if realDir != realRoot && !strings.HasPrefix(realDir, realRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf(
			"папка приложения %q ведёт за пределы репозитория — платформа такой стек не разворачивает",
			app.GitBaseDir)
	}

	info, err := os.Stat(realDir)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать папку приложения %q: %w", app.GitBaseDir, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%q в репозитории — файл, а не папка приложения", app.GitBaseDir)
	}
	return dir, nil
}

// validateGitBaseDir — форма значения, пришедшего с сервера.
//
// Отдельно от repoAppDir: форму проверяем ДО клона (validateGitSource), а каталог
// появляется только после него.
func validateGitBaseDir(base string) error {
	if base == "" {
		return nil
	}
	if len(base) > maxGitBaseDirLen || !safeGitBaseDir.MatchString(base) {
		return fmt.Errorf("недопустимая папка приложения в репозитории: %q", tail(base, 120))
	}
	return nil
}

// Имена, под которыми ищем описание стека в репозитории. Порядок значим:
// первое найденное и используется.
var composeFileNames = []string{
	"docker-compose.yml",
	"docker-compose.yaml",
	"compose.yml",
	"compose.yaml",
}

// Способы получить образ сервиса app из git-репозитория. См. DesiredApp.BuildMethod.
const (
	buildMethodCompose    = "compose"
	buildMethodDockerfile = "dockerfile"
	buildMethodStatic     = "static"
)

// writeSyntheticCompose кладёт в рабочую копию compose, которого репозиторий
// сам не содержит: клиент выбрал сборку из Dockerfile или раздачу файлов как
// есть, а не готовый docker-compose.yml.
//
// Пишется ПОВЕРХ любого файла с тем же именем, что уже есть в репозитории:
// способ сборки задан на сервере, и случайный docker-compose.yml, оставшийся
// не по адресу в чужом репозитории, не должен его перебивать молча.
//
// Сервис называется "app" и подключается к общей сети прокси — та же
// конвенция об имени контейнера (<slug>-app-1), на которой строится
// маршрутизация в proxy.go, поэтому доменные маршруты работают без единой
// правки там: `name: ${APP_SLUG}` даёт совпадающее имя compose-проекта,
// ${APP_SLUG} подставляет сам docker compose из .env, который агент пишет
// рядом ровно как для любого другого приложения.
//
// Порт сюда не попадает: Caddy обращается к контейнеру по адресу
// <slug>-app-1:<InternalPort>, а что именно слушает контейнер на этом порту —
// вопрос Dockerfile/образа, а не текста compose. Для static сервер всегда
// подставляет в желаемое состояние порт 80 (см. deploy_get_desired_state) —
// ровно то, что слушает nginx:alpine по умолчанию.
// staticNginxConfName — конфиг раздачи статики, живущий в служебном каталоге.
//
// Не в рабочей копии: там его снёс бы `git clean` при следующем выкате, а до
// того он попал бы в сборочный контекст и в выдачу как обычный файл сайта.
const staticNginxConfName = "static-nginx.conf"

// writeStaticNginxConf кладёт конфигурацию nginx для способа сборки «статика».
//
// Отличается от стандартной ровно одним: запретом на скрытые файлы. Корень
// раздачи — рабочая копия репозитория, и без запрета наружу уезжает весь .git.
// Исключение для `.well-known` оставлено намеренно: это единственный служебный
// путь с точкой, который сайты обязаны отдавать (подтверждения владения,
// security.txt), и запрет на него ломал бы законные сценарии.
func writeStaticNginxConf(p Paths, slug string) error {
	dir := p.appDir(slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("не удалось создать каталог приложения: %w", err)
	}

	conf := `server {
    listen       80;
    server_name  localhost;

    # Подтверждения владения доменом — единственный служебный путь с точкой,
    # который сайт обязан отдавать. Якорь ^ обязателен: без него правило
    # покрывало бы и /что-угодно/.well-known/, то есть было бы шире заявленного.
    location ~ ^/\.well-known/ {
        root   /usr/share/nginx/html;
    }

    # Скрытые файлы наружу не отдаются: корнем раздачи служит рабочая копия
    # git, и без этого блока .git/config (адрес приватного репозитория) и
    # .git/index (перечень всех отслеживаемых путей) скачивал любой.
    #
    # Только return: deny здесь мёртв — return отрабатывает в фазе rewrite,
    # раньше фазы доступа, и до deny управление не доходит.
    location ~ ^/\. {
        return 404;
    }

    # Служебные файлы, которые агент кладёт в рабочую копию сам. Они не часть
    # сайта, но лежат в его корне: в compose видны абсолютные пути агента,
    # имена сервисов-аддонов и внутреннее устройство стека.
    location = /docker-compose.yml {
        return 404;
    }
    location = /Dockerfile.tracedocs {
        return 404;
    }

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
`

	path := filepath.Join(dir, staticNginxConfName)
	if err := writeFileAtomic(path, []byte(conf), 0o640); err != nil {
		return fmt.Errorf("не удалось записать конфигурацию раздачи статики: %w", err)
	}
	return nil
}

// syntheticBuildPaths — что писать в `context` и `dockerfile` синтетического
// compose.
//
// Без флага — как было до появления папки приложения: контекст «.», то есть
// каталог самого compose, имя файла рядом. С флагом контекстом становится
// КОРЕНЬ рабочей копии, и оба пути абсолютные: относительный подъём («../..»)
// зависел бы от числа сегментов папки и молча ломался бы на каждой правке
// этого поля, а абсолютный путь агент и так уже пишет в env_file и в том
// статики рядом.
func syntheticBuildPaths(p Paths, app DesiredApp, dir, dockerfileName string) (string, string) {
	if !app.GitBuildContextRoot {
		return ".", dockerfileName
	}
	return p.repoDir(app.Slug), filepath.Join(dir, dockerfileName)
}

func writeSyntheticCompose(p Paths, app DesiredApp) error {
	// Папка приложения (0284): всё, что ниже, пишется и ищется в ней. Пустая —
	// сама рабочая копия, то есть поведение до появления поля.
	dir, err := repoAppDir(p, app)
	if err != nil {
		return err
	}

	var service string
	switch app.BuildMethod {
	case buildMethodDockerfile:
		// Наличие Dockerfile — предварительная проверка, а не побочный эффект
		// подготовки ARG: без переменных сборки ту ветку не вызывали вовсе, и
		// отсутствие файла всплывало сырым текстом docker минутами позже.
		if err := requireDockerfile(dir, app.GitBaseDir); err != nil {
			return err
		}
		// HEALTHCHECK сюда не добавляется намеренно: проверка выполняется
		// ВНУТРИ контейнера, а что за инструменты есть в образе клиента
		// (curl? wget? вообще ничего?) — неизвестно. Снаружи приложение
		// проверяет HTTP-проба агента (probe.go) — ей от образа не нужно
		// ничего.
		//
		// Сборка идёт по СГЕНЕРИРОВАННОМУ Dockerfile, если у приложения есть
		// переменные сборки: в него дописаны объявления ARG, без которых
		// docker молча игнорирует --build-arg. Оригинал клиента не трогаем —
		// см. writeBuildDockerfile.
		names := selectBuildArgs(app.BuildArgs)
		dockerfileName := "Dockerfile"
		if len(names) > 0 {
			dockerfileName = buildDockerfileName
		}
		buildContext, dockerfile := syntheticBuildPaths(p, app, dir, dockerfileName)
		service = "    build:\n      context: " + buildContext + "\n      dockerfile: " + dockerfile + "\n"
		if len(names) > 0 {
			service += "      args:\n"
			for _, name := range names {
				// Значение подставит сам docker compose из .env, который
				// агент пишет рядом: писать его в текст compose значило бы
				// класть переменные приложения на диск рабочей копии, под
				// `git clean` и в сборочный контекст.
				service += "        " + name + ": ${" + name + "}\n"
			}
		}
	case buildMethodStatic:
		// Для статики образ наш (nginx:alpine), и wget в нём гарантирован —
		// поэтому здесь healthcheck объявляется: docker сам перезапустит
		// зависший nginx, а health gate при выкате перестаёт считать
		// «запустился» достаточным.
		//
		// Корнем раздачи служит сама рабочая копия, а в ней лежит .git от
		// клона. Конфигурация nginx по умолчанию скрытые файлы не запрещает,
		// поэтому до этой правки `https://домен/.git/config` отдавал адрес и
		// владельца приватного репозитория, `/.git/index` — полный перечень
		// отслеживаемых путей, включая файлы, на которые с сайта нет ни одной
		// ссылки. Конфиг с запретом монтируется рядом.
		if err := writeStaticNginxConf(p, app.Slug); err != nil {
			return err
		}
		service = "    image: nginx:alpine\n" +
			"    volumes:\n" +
			"      - .:/usr/share/nginx/html:ro\n" +
			"      - " + filepath.Join(p.appDir(app.Slug), staticNginxConfName) +
			":/etc/nginx/conf.d/default.conf:ro\n" +
			"    healthcheck:\n" +
			"      test: [\"CMD\", \"wget\", \"-q\", \"-O\", \"/dev/null\", \"http://127.0.0.1/\"]\n" +
			"      interval: 30s\n      timeout: 5s\n      retries: 3\n"
	default:
		return fmt.Errorf("неизвестный способ сборки git-приложения: %q", app.BuildMethod)
	}

	// Переменные и секреты приложения обязаны попадать в окружение
	// контейнера. --env-file, которым агент запускает compose, задаёт лишь
	// подстановку ${VAR} в самом YAML — в окружение процессов он не кладёт
	// ничего, и до env_file переменные dockerfile-приложения молча не
	// доезжали до контейнера вовсе. Путь абсолютный: .env живёт в служебном
	// каталоге агента, а не в рабочей копии — положить его рядом значило бы
	// отдавать секреты под `git clean` и в сборочный контекст образа.
	envFile := "    env_file:\n" +
		"      - " + filepath.Join(p.appDir(app.Slug), ".env") + "\n"

	addons, err := renderAddonServices(app.Addons)
	if err != nil {
		return err
	}

	compose := "name: ${APP_SLUG}\n" +
		"services:\n" +
		"  app:\n" +
		service +
		envFile +
		"    restart: unless-stopped\n" +
		// Приложение ждёт ГОТОВНОСТИ аддонов, а не их запуска: иначе миграции
		// на старте бьют в postgres, который ещё не принимает соединения.
		addons.dependsOn +
		"    networks:\n" +
		"      - edge\n" +
		addons.services +
		"networks:\n" +
		"  edge:\n" +
		"    external: true\n" +
		"    name: " + EdgeNetwork + "\n" +
		addons.volumes

	// На практике FetchRepo к этому моменту уже создал каталог клоном, а appDir
	// выше отказал бы для несуществующей папки, — но функция не должна молча
	// полагаться на порядок вызовов снаружи.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("не удалось создать каталог репозитория: %w", err)
	}

	path := filepath.Join(dir, "docker-compose.yml")
	if err := writeFileAtomic(path, []byte(compose), 0o640); err != nil {
		return fmt.Errorf("не удалось записать синтетический compose: %w", err)
	}

	// Dockerfile с объявленными ARG — рядом и только при наличии переменных
	// сборки. Порядок важен: compose уже ссылается на этот файл по имени.
	if app.BuildMethod == buildMethodDockerfile {
		if err := writeBuildDockerfile(dir, app, selectBuildArgs(app.BuildArgs)); err != nil {
			return err
		}
	}
	return nil
}

func (p Paths) repoDir(slug string) string { return filepath.Join(p.WorkDir, "repos", slug) }

func (p Paths) gitKeyPath(slug string) string {
	// Ключ лежит в приватном каталоге состояния, а не в рабочем: рабочий
	// каталог монтируется в контейнеры соседними стеками, состояние — нет.
	return filepath.Join(p.StateDir, "git-keys", slug)
}

// validateGitSource проверяет то, что пришло с сервера.
//
// Агент живёт на чужой машине и не доверяет входу второй раз: одна ошибка на
// той стороне не должна превращаться в выполнение произвольной команды здесь.
func validateGitSource(app DesiredApp) error {
	if !safeSlug.MatchString(app.Slug) {
		return fmt.Errorf("недопустимый slug приложения: %q", app.Slug)
	}
	if !safeGitRef.MatchString(app.GitBranch) {
		return fmt.Errorf("недопустимое имя ветки: %q", tail(app.GitBranch, 80))
	}
	// Форму папки приложения проверяем здесь, до клона: сам каталог появится
	// только после него, а отказ по форме не должен ждать сетевой операции.
	if err := validateGitBaseDir(app.GitBaseDir); err != nil {
		return err
	}

	// Форма адреса и способ доступа связаны жёстко. Разрешить их вразнобой —
	// значит позволить отправить токен установки на произвольный хост: сервер
	// прислал бы `git@чужой.host:a/b` вместе с токеном, и credential helper
	// отдал бы его туда.
	if app.usesToken() {
		if !safeGitHubRepoPath.MatchString(app.GitRepo) {
			return fmt.Errorf("недопустимый репозиторий GitHub: %q", tail(app.GitRepo, 120))
		}
		return nil
	}

	// Публичная https-форма (0178): клон анонимный, учётных данных быть НЕ
	// должно. Ключ рядом с публичным адресом — признак рассинхрона сервера:
	// применять его некуда, а молча проигнорировать значит скрыть проблему.
	if app.isPublicRepo() {
		if !safeGitPublicRepo.MatchString(app.GitRepo) {
			return fmt.Errorf("недопустимый адрес публичного репозитория: %q", tail(app.GitRepo, 120))
		}
		if strings.TrimSpace(app.GitKey) != "" {
			return fmt.Errorf("для публичного репозитория %s прислан ключ — формы доступа разошлись", app.Slug)
		}
		return nil
	}

	if !safeGitRepo.MatchString(app.GitRepo) {
		return fmt.Errorf("недопустимый адрес репозитория: %q", tail(app.GitRepo, 120))
	}
	if strings.TrimSpace(app.GitKey) == "" {
		return fmt.Errorf("для приложения %s не передан ключ репозитория", app.Slug)
	}
	return nil
}

// isPublicRepo — анонимный клон по https: форма адреса и есть признак способа
// доступа, сервер прибивает их соответствие CHECK'ом (0178).
func (a DesiredApp) isPublicRepo() bool {
	return strings.HasPrefix(a.GitRepo, "https://")
}

// usesToken — доступ к репозиторию по токену установки, а не по ключу.
func (a DesiredApp) usesToken() bool { return strings.TrimSpace(a.GitToken) != "" }

// cloneURL — адрес, который уезжает в аргументы git.
//
// Для токена собирается здесь и БЕЗ учётных данных внутри: адрес попадает в
// .git/config и в вывод любой упавшей команды, а токен там остался бы навсегда.
func (a DesiredApp) cloneURL() string {
	if a.usesToken() {
		return "https://github.com/" + a.GitRepo + ".git"
	}
	return a.GitRepo
}

// writeGitKey кладёт приватный ключ на диск.
//
// Через файл, а не через переменную окружения или stdin, потому что ssh умеет
// брать ключ только из файла. Права 0600 и приватный каталог 0700 — иначе ssh
// откажется его использовать, и это правильное поведение.
//
// Хвостовой перевод строки обязателен: ssh не читает ключ без него и выдаёт
// невнятное «invalid format».
func writeGitKey(p Paths, app DesiredApp) (string, error) {
	dir := filepath.Join(p.StateDir, "git-keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// MkdirAll не сужает права уже существующего каталога.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}

	key := strings.TrimRight(app.GitKey, "\n") + "\n"
	path := p.gitKeyPath(app.Slug)
	if err := writeFileAtomic(path, []byte(key), 0o600); err != nil {
		return "", fmt.Errorf("не удалось сохранить ключ репозитория: %w", err)
	}
	return path, nil
}

// gitSSHCommand собирает команду ssh для git.
//
// StrictHostKeyChecking=accept-new: ключ хоста запоминается при первом
// обращении и сверяется при всех последующих. Это честная граница — от
// подмены при ПЕРВОМ клоне не защищает, от подмены потом защищает. Полное
// закрепление потребовало бы возить с агентом ключи хостов всех git-сервисов
// и обновлять их при ротации; отдельная настройка known_hosts на хосте
// уважается, потому что мы указываем именно пользовательский файл.
//
// IdentitiesOnly=yes обязателен: без него ssh переберёт все ключи из агента
// и из ~/.ssh, и в лучшем случае упрётся в лимит попыток, а в худшем уйдёт в
// репозиторий не с тем ключом.
func gitSSHCommand(keyPath string) string {
	return fmt.Sprintf(
		"ssh -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new "+
			"-o BatchMode=yes -o ConnectTimeout=15",
		keyPath,
	)
}

// gitCredentialHelper — helper, отдающий git имя пользователя и токен.
//
// Токен берётся ИЗ ОКРУЖЕНИЯ, а не подставляется в саму строку: строка уезжает
// в конфигурацию git и может всплыть в выводе при ошибке, окружение — нет.
// Подстановку делает shell в момент вызова helper'а.
func gitCredentialHelper() string {
	return "!f() { echo username=" + gitTokenUser + "; echo password=$" + gitTokenEnvName + "; }; f"
}

func gitCommand(ctx context.Context, dir string, auth gitAuth, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// Окружение минимальное и явное — по той же причине, что и у docker:
	// наследованное могло бы подменить конфигурацию git или маршрут ssh.
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		// Никаких интерактивных запросов: агент работает без терминала, и
		// запрос пароля означал бы зависший процесс, а не понятную ошибку.
		"GIT_TERMINAL_PROMPT=0",
	}

	if auth.anonymous {
		// Анонимный клон публичного репозитория. Сброс credential.helper
		// обязателен и здесь: глобальный helper хоста (osxkeychain, store)
		// иначе подставил бы ЛИЧНЫЕ учётные данные владельца сервера, и
		// «публичный» клон молча заработал бы на чужом доступе — вместе со
		// всеми правами этого доступа.
		env = append(env,
			"GIT_CONFIG_COUNT=1",
			"GIT_CONFIG_KEY_0=credential.helper",
			"GIT_CONFIG_VALUE_0=",
		)
	} else if auth.token != "" {
		// Конфигурация через окружение, а не через `git -c`: значения `-c`
		// видны в `ps` вместе со всей командной строкой. Здесь в argv не
		// попадает ни токен, ни даже имя helper'а.
		//
		// Первым идёт ПУСТОЙ credential.helper — он сбрасывает список. Без
		// сброса git опросил бы и helper'ы из глобального конфига хоста:
		// настроенный клиентом osxkeychain или store ответил бы первым и
		// подсунул свои учётные данные вместо наших.
		env = append(env,
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=credential.helper",
			"GIT_CONFIG_VALUE_0=",
			"GIT_CONFIG_KEY_1=credential.helper",
			"GIT_CONFIG_VALUE_1="+gitCredentialHelper(),
			gitTokenEnvName+"="+auth.token,
		)
	} else {
		env = append(env, "GIT_SSH_COMMAND="+gitSSHCommand(auth.keyPath))
	}

	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// gitAuth — чем открывается репозиторий: ключ, токен или анонимно (публичный
// https). Заполнено ровно одно.
type gitAuth struct {
	keyPath   string
	token     string
	anonymous bool
}

// FetchRepo приводит локальную копию репозитория к нужной ветке.
//
// Возвращает хеш коммита — он попадает в отчёт о выкате, и без него по истории
// нельзя понять, что именно развёрнуто.
func FetchRepo(ctx context.Context, p Paths, app DesiredApp) (string, error) {
	if err := validateGitSource(app); err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()

	var auth gitAuth
	if app.usesToken() {
		// Токен на диск не кладётся вовсе — в этом и смысл пути через
		// GitHub App: на хосте клиента не остаётся ни файла, ни его следов
		// после OOM или SIGKILL.
		auth.token = app.GitToken
	} else if app.isPublicRepo() {
		// Публичный репозиторий: ни ключа, ни токена — и ни файла ключа на
		// диске, писать нечего.
		auth.anonymous = true
	} else {
		keyPath, err := writeGitKey(p, app)
		if err != nil {
			return "", err
		}
		// Ключ нужен только на время работы с репозиторием. Оставлять его на
		// диске между циклами незачем: в желаемом состоянии он приходит
		// каждый раз.
		defer os.Remove(keyPath)
		auth.keyPath = keyPath
	}

	repoURL := app.cloneURL()
	dir := p.repoDir(app.Slug)

	// Смена адреса репозитория требует ЧИСТОГО клона, а не обновления на месте.
	//
	// `reset --hard` + `clean -fd` возвращают отслеживаемые файлы, но не
	// трогают игнорируемые: `-x` не передаётся сознательно, иначе каждый цикл
	// стирал бы `.env`, который агент пишет сам. Пока репозиторий тот же, это
	// верно. Как только он сменился, остатки прежнего владельца каталога
	// (`dist/`, `build/`, дампы, конфиги из его `.gitignore`) остаются на
	// диске — и для способа `static` корнем nginx служит сама рабочая копия,
	// то есть чужие файлы начинают отдаваться наружу по домену нового
	// приложения. Для `dockerfile` они же уезжают в контекст сборки.
	if _, statErr := os.Stat(filepath.Join(dir, ".git")); statErr != nil || repoChanged(ctx, dir, auth, repoURL) {
		// Каталог мог остаться от неудачного клона — тогда git откажется
		// клонировать в него, и приложение залипнет навсегда.
		if err := os.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("не удалось очистить каталог репозитория: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
			return "", err
		}

		if out, err := gitCommand(ctx, "", auth, "clone",
			"--depth", gitCloneDepth, "--branch", app.GitBranch, "--single-branch",
			"--", repoURL, dir); err != nil {
			return "", fmt.Errorf("git clone: %w: %s", err, tail(out, 500))
		}
	} else {
		// Адрес здесь заведомо прежний: расхождение уже увело в ветку клона
		// выше. Обновляем на месте — это дёшево и сохраняет `.env`.
		if out, err := gitCommand(ctx, dir, auth, "fetch",
			"--depth", gitCloneDepth, "origin", app.GitBranch); err != nil {
			return "", fmt.Errorf("git fetch: %w: %s", err, tail(out, 500))
		}
		// Жёсткий сброс, а не merge: рабочая копия принадлежит платформе, и
		// локальных правок в ней быть не должно. Merge на расходящейся истории
		// потребовал бы разрешения конфликта, которое делать некому.
		if out, err := gitCommand(ctx, dir, auth, "reset", "--hard",
			"FETCH_HEAD"); err != nil {
			return "", fmt.Errorf("git reset: %w: %s", err, tail(out, 500))
		}
		// Файлы, не отслеживаемые git, остаются от прошлой сборки и могут
		// перебить содержимое репозитория. -d, но не -x: игнорируемое
		// содержимое (кеши сборки, node_modules) стирать на каждом цикле
		// незачем — переклон при смене адреса закрывает случай, когда оно
		// принадлежит уже другому репозиторию.
		if out, err := gitCommand(ctx, dir, auth, "clean", "-fd"); err != nil {
			return "", fmt.Errorf("git clean: %w: %s", err, tail(out, 500))
		}
	}

	out, err := gitCommand(ctx, dir, auth, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git rev-parse: %w: %s", err, tail(out, 200))
	}
	return strings.TrimSpace(out), nil
}

// repoChanged — рабочая копия склонирована с ДРУГОГО адреса.
//
// Ошибка чтения (нет .git/config, каталог битый) означает «неизвестно», и
// ответ здесь `true`: клон заново дороже обновления, но безопасен всегда, а
// обновление поверх неизвестного состояния — нет.
func repoChanged(ctx context.Context, dir string, auth gitAuth, want string) bool {
	// `config --get`, а НЕ `remote get-url`.
	//
	// `get-url` применяет переписывание `url.<base>.insteadOf` из глобального
	// конфига хоста, а он у клиента свой и нам неподконтролен. Правило вида
	// `url."ssh://git@github.com/".insteadOf "git@github.com:"` меняет ответ, и
	// исходная форма адреса не совпадёт с ним НИКОГДА — каждое применение
	// уходило бы в полный переклон вместо `fetch`. На большом репозитории это
	// упирается в пятиминутный срок команды git, то есть выкат, который раньше
	// проходил, начинает падать без видимой причины.
	out, err := gitCommand(ctx, dir, auth, "config", "--get", "remote.origin.url")
	if err != nil {
		return true
	}
	return strings.TrimSpace(out) != want
}

// readComposeFromRepo достаёт описание стека из склонированного репозитория.
//
// Ищем в папке приложения (0284) — по умолчанию это корень рабочей копии.
// Дальше корня и папки не спускаемся: имя файла берётся из своего же списка,
// а путь папки проверен формой и разыменован внутри appDir.
func readComposeFromRepo(p Paths, app DesiredApp) (string, error) {
	dir, err := repoAppDir(p, app)
	if err != nil {
		return "", err
	}

	for _, name := range composeFileNames {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			return "", fmt.Errorf("%s в репозитории пуст", name)
		}
		return string(raw), nil
	}

	where := "в корне репозитория"
	if app.GitBaseDir != "" {
		where = fmt.Sprintf("в папке %s репозитория", app.GitBaseDir)
	}
	return "", fmt.Errorf(
		"%s нет файла описания стека (искали %s)",
		where, strings.Join(composeFileNames, ", "),
	)
}

// PurgeGitKeys вычищает ключи репозиториев, оставшиеся от прошлых запусков.
//
// Обычно ключ удаляется сразу после работы с репозиторием (defer), но defer не
// отрабатывает при SIGKILL и OOM — а OOM во время клона большого репозитория
// вполне реален. Тогда приватный ключ остаётся лежать на диске до следующего
// успешного цикла.
//
// Терять нечего: ключи приходят в желаемом состоянии на каждом цикле.
func PurgeGitKeys(p Paths) {
	dir := filepath.Join(p.StateDir, "git-keys")
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "не удалось вычистить ключи репозиториев: %v\n", err)
	}
}

// removeRepo убирает рабочую копию снятого приложения.
//
// Вместе со стеком: код клиента не должен оставаться на диске после того, как
// приложение удалили из платформы.
func removeRepo(p Paths, slug string) {
	if !safeSlug.MatchString(slug) {
		return
	}
	if err := os.RemoveAll(p.repoDir(slug)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "не удалось удалить рабочую копию %s: %v\n", slug, err)
	}
	if err := os.Remove(p.gitKeyPath(slug)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "не удалось удалить ключ репозитория %s: %v\n", slug, err)
	}
}
