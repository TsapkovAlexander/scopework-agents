package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
	"tracedocs.ru/deploy-agent/pkg/stackdir"
)

// Применение желаемого состояния на хосте.
//
// Агент не «выполняет команды с сервера» — он получает описание того, что
// должно работать, и приводит хост к этому виду сам. Разница принципиальная:
// сервер не может заставить агента запустить произвольную команду, он может
// только объявить желаемый набор приложений.

// safeSlug, safeEnvKey и правила .env ниже — из pkg/stackdir: подписант
// собирает модель compose тем же .env, что агент на хосте, и разойдись они —
// подписанное агент бы отверг.
var safeSlug = stackdir.SafeSlug

// safeDomain — то же самое для имени, которое уедет в конфиг прокси.
var safeDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

var safeEnvKey = stackdir.SafeEnvKey

// Paths — расположение файлов агента на хосте.
type Paths struct {
	// StateDir — приватное состояние: ключ, отметки о применённом.
	StateDir string
	// WorkDir — рабочие каталоги стеков и прокси.
	WorkDir string
}

func DefaultPaths() Paths {
	return Paths{
		StateDir: "/etc/tracedocs/deploy",
		WorkDir:  "/opt/tracedocs/deploy",
	}
}

func (p Paths) appDir(slug string) string { return filepath.Join(p.WorkDir, "apps", slug) }

// ApplyResult — что рассказать серверу о попытке применения.
type ApplyResult struct {
	ReleaseID string
	Status    string // healthy | failed
	Detail    map[string]any
}

// Apply приводит хост к желаемому состоянию.
//
// Возвращает результаты только по тем приложениям, которые реально трогали.
// Уже применённое пропускается: без этого агент поднимал бы все стеки заново
// каждую минуту и тратил на ожидание устойчивости весь цикл, из-за чего
// heartbeat уходил бы с задержкой в минуты и хост выглядел бы мёртвым.
//
// Ошибка одного стека не останавливает остальные: сломанный n8n не повод не
// обновить соседа.
//
// progress получает ход применения: фазу и уже затёртый хвост вывода команд.
// nil допустим — тогда ход никуда не сообщается.
func Apply(ctx context.Context, p Paths, apps []DesiredApp, progress ProgressFunc) []ApplyResult {
	state := LoadApplied(p)
	results := make([]ApplyResult, 0, len(apps))
	now := time.Now()

	for _, app := range apps {
		if !app.ShouldRun() {
			// Остановленные снимает уборка — здесь их не трогаем.
			continue
		}

		rec, found := state.Apps[app.Slug]
		// Описание стека в служебном каталоге: его отсутствие у применённого
		// приложения означает наследство прежней версии агента, которая
		// поднимала git-стек из рабочей копии. Переприменить обязательно —
		// иначе проверка здоровья и восстановление, работающие только из
		// служебного каталога, останутся без файла навсегда.
		composeMissing := false
		if _, statErr := os.Stat(filepath.Join(p.appDir(app.Slug), "docker-compose.yml")); statErr != nil {
			composeMissing = true
		}
		should, reason := needsApply(rec, found, app, now, composeMissing)
		if !should {
			continue
		}

		// Затирание — здесь, а не у отправителя: значения переменных есть
		// только в этом цикле, а хвост лога виден любому участнику проекта.
		report := func(phase, output string) {
			if progress != nil {
				progress(app.ReleaseID, phase, redactSecrets(output, app.redactionValues()))
			}
		}

		start := time.Now()
		detail := map[string]any{"reason": reason}

		// Данные прошлого одноимённого приложения на первом релизе.
		//
		// Поднять стек поверх них можно, и он даже частично поднимется — но
		// база уже создана со старыми паролями, init-скрипты повторно не
		// выполняются, и сервисы получат «password authentication failed».
		// Отказ с внятным текстом полезнее стека, который выглядит почти
		// работающим и не работает.
		//
		// Отказ НЕ распространяется на повтор собственного упавшего выката:
		// признак «платформа уже разворачивала это приложение здесь» отличает
		// свои тома от чужих остатков. Без него первый выкат, упавший после
		// подъёма базы, запирал приложение навсегда — даже правка переменных
		// возвращала тот же отказ.
		var refusal error
		if app.FirstRelease {
			volumes, volErr := listAppVolumes(ctx, app.Slug)
			if volErr != nil {
				fmt.Fprintf(os.Stderr, "проверка данных %s: %v\n", app.Slug, volErr)
			} else {
				// Перехваченные тома исключаются: их наличие — смысл перехвата,
				// а не остатки прошлого приложения.
				refusal = staleDataRefusal(app.Slug, true, deployedHere(p, app.Slug),
					volumes, app.AdoptedVolumes)
			}
		}

		// Чужой стек с тем же именем проекта.
		//
		// Только на первом релизе и только для неперехваченных: у
		// перехваченного совпадение имени — это и есть операция, а не
		// столкновение.
		if refusal == nil && app.FirstRelease && !app.Adopted {
			containers, listErr := inspectComposeContainers(ctx)
			if listErr != nil {
				fmt.Fprintf(os.Stderr, "проверка чужих стеков %s: %v\n", app.Slug, listErr)
			} else {
				refusal = foreignProjectRefusal(app.Slug, containers,
					[]string{p.WorkDir, p.StateDir})
			}
		}

		// Перехваченный стек: его тома прямо сейчас может держать прежний стек,
		// который никто не остановил. Поднять свой поверх — не конфликт, а порча
		// данных, и проверка обязана стоять ЗДЕСЬ, в агенте: только он видит, что
		// на хосте работает на самом деле.
		//
		// На каждом выкате, а не только на первом: остановленный стек прежней
		// панели возвращается сам после перезапуска демона или перезагрузки
		// хоста. Контейнеры при остановке не удаляются и сохраняют прежнюю
		// политику перезапуска — «остановлен» здесь не навсегда.
		if refusal == nil && len(app.AdoptedVolumes) > 0 {
			holders, holdErr := listVolumeHolders(ctx)
			if holdErr != nil {
				fmt.Fprintf(os.Stderr, "проверка владельцев томов %s: %v\n", app.Slug, holdErr)
			} else {
				refusal = adoptedVolumesRefusal(
					foreignVolumeHolders(holders, app.Slug, app.AdoptedVolumes))
			}
		}

		if refusal != nil {
			detail["took_ms"] = time.Since(start).Milliseconds()
			detail["error"] = refusal.Error()
			// Хеши — прежние: файлы отказ не трогал, и обнулённая базовая линия
			// превратила бы следующую сверку в «нет данных».
			state.Apps[app.Slug] = AppliedRecord{
				ReleaseID:     app.ReleaseID,
				ConfigHash:    configHash(app),
				Status:        "failed",
				LastAttempt:   start,
				ComposeSha256: rec.ComposeSha256,
				EnvSha256:     rec.EnvSha256,
			}
			results = append(results, ApplyResult{
				ReleaseID: app.ReleaseID, Status: "failed", Detail: detail,
			})
			continue
		}

		// Резервная копия ДО того, как тронули стек.
		//
		// Только для обновлений версии: обычный выкат данных не меняет, и
		// копировать нечего. Неудача копии останавливает обновление — это
		// намеренно. Обновиться без возможности вернуться хуже, чем не
		// обновиться: миграции схемы необратимы.
		var backupDir string
		if app.NeedsBackup {
			report("backup", "")
			var backupErr error
			backupDir, backupErr = CreateBackup(ctx, p, app, app.BackupSpec)
			if backupErr != nil {
				detail["took_ms"] = time.Since(start).Milliseconds()
				detail["error"] = redactSecrets(
					"резервная копия не создана, обновление отменено: "+backupErr.Error(),
					app.redactionValues())
				state.Apps[app.Slug] = AppliedRecord{
					ReleaseID:     app.ReleaseID,
					ConfigHash:    configHash(app),
					Status:        "failed",
					LastAttempt:   start,
					ComposeSha256: rec.ComposeSha256,
					EnvSha256:     rec.EnvSha256,
				}
				results = append(results, ApplyResult{
					ReleaseID: app.ReleaseID, Status: "failed", Detail: detail,
				})
				continue
			}
			detail["backup"] = filepath.Base(backupDir)
			fmt.Printf("резервная копия %s: %s\n", app.Slug, backupDir)
		}

		// written начинается с прежних хешей: выкат, оборвавшийся между
		// записью .env и compose, переписал только один файл.
		written := AppliedRecord{ComposeSha256: rec.ComposeSha256, EnvSha256: rec.EnvSha256}
		extra, err := applyOne(ctx, p, app, report, &written)
		for k, v := range extra {
			detail[k] = v
		}
		detail["took_ms"] = time.Since(start).Milliseconds()

		// Обновление не поднялось — возвращаем данные и конфигурацию.
		//
		// Без этого приложение осталось бы лежать на новой версии с уже
		// мигрированной базой: старый образ её не прочитает, и клиент получил
		// бы неработающий сервис без пути назад.
		if err != nil && backupDir != "" {
			fmt.Fprintf(os.Stderr, "обновление %s не удалось, откатываюсь\n", app.Slug)
			if rbErr := RestoreBackup(ctx, p, app, backupDir); rbErr != nil {
				detail["rollback_error"] = redactSecrets(rbErr.Error(), app.redactionValues())
			} else {
				detail["rolled_back"] = true
			}
			// Откат вернул файлы из набора — это тоже запись агента, и без
			// переноса сверка назвала бы собственный откат чужой правкой.
			written = restoredBaseline(p, app.Slug, backupDir, written)
		}

		status := "healthy"
		if err != nil {
			status = "failed"
			// Текст ошибки содержит хвост вывода docker и git, а там попадаются
			// значения переменных приложения. Он уезжает на сервер, ложится в
			// историю релизов и виден ЛЮБОМУ участнику проекта — включая тех, у
			// кого прав на управление развёртыванием нет. Затираем значения до
			// отправки: у агента они на руках, замена стоит один проход.
			detail["error"] = redactSecrets(err.Error(), app.redactionValues())
		}

		// Удачный выкат приводит стек к рабочему состоянию, проверенному так
		// же, как любой выкат, и снимает флаг восстановления (ADR-0063,
		// решение 6). Иначе самовосстановление осталось бы выключенным у
		// работающего приложения навсегда.
		if status == "healthy" {
			if err := clearRestoreFlag(p, app.Slug); err != nil {
				fmt.Fprintf(os.Stderr, "флаг восстановления %s не снят: %v\n", app.Slug, err)
			}
		}

		state.Apps[app.Slug] = AppliedRecord{
			ReleaseID:     app.ReleaseID,
			ConfigHash:    configHash(app),
			Status:        status,
			LastAttempt:   start,
			ComposeSha256: written.ComposeSha256,
			EnvSha256:     written.EnvSha256,
		}

		results = append(results, ApplyResult{
			ReleaseID: app.ReleaseID,
			Status:    status,
			Detail:    detail,
		})
	}

	if err := SaveApplied(p, state); err != nil {
		// Не сохранили отметки — на следующем цикле всё применится заново.
		// Неприятно, но не разрушительно, поэтому не роняем цикл.
		fmt.Fprintf(os.Stderr, "не удалось сохранить отметки о применённом: %v\n", err)
	}

	return results
}

// Cleanup снимает стеки, которых не должно быть на хосте.
//
// Убираются два случая: приложение помечено absent и приложение исчезло из
// желаемого состояния совсем (удалено в интерфейсе). Второе безопасно только
// потому, что ручка состояния теперь либо отдаёт полный список, либо отказывает
// целиком — частичного ответа не бывает, и пустой список действительно значит
// «ничего не должно работать».
//
// Тома по умолчанию НЕ удаляются: в них данные приложения, и восстановить их
// после ошибочной остановки иначе будет неоткуда. Удаляются только по явной
// отметке purgeData, которую человек ставит при удалении приложения. Файл .env,
// наоборот, стирается сразу — в нём пароли, и оставлять их на диске после
// снятия стека незачем.
func Cleanup(ctx context.Context, p Paths, apps []DesiredApp) []string {
	state := LoadApplied(p)
	if len(state.Apps) == 0 {
		return nil
	}

	shouldRun := make(map[string]bool, len(apps))
	// Отметку «удалить данные» несёт то же желаемое состояние, в котором
	// приложение помечено absent: решение принято до того, как агент пришёл, и
	// должно дожить до момента снятия стека.
	purge := make(map[string]bool, len(apps))
	for _, a := range apps {
		if a.ShouldRun() {
			shouldRun[a.Slug] = true
		} else if a.PurgeData {
			purge[a.Slug] = true
		}
	}

	var removed []string
	// Отметка может исчезнуть и без снятия стека — например, когда каталога
	// уже нет. Такие изменения тоже надо сохранить, иначе записи о давно
	// исчезнувших приложениях копились бы в файле бесконечно.
	changed := false

	for slug := range state.Apps {
		if shouldRun[slug] {
			continue
		}
		if !safeSlug.MatchString(slug) {
			// В отметках оказался мусор — трогать по нему файловую систему
			// нельзя, но и держать запись незачем.
			delete(state.Apps, slug)
			changed = true
			continue
		}

		dir := p.appDir(slug)
		if _, err := os.Stat(dir); err != nil {
			// Каталога нет — снимать нечего, стек уже не развёрнут.
			delete(state.Apps, slug)
			changed = true
			continue
		}

		// Снимаем ПО ИМЕНИ ПРОЕКТА, а не по файлу описания.
		//
		// Прежде снятие звало compose из каталога с описанием и передавало
		// `--env-file`. Любая пропажа делала стек несносимым: стёртый .env,
		// изменившийся файл, другое имя проекта внутри него. На боевом хосте
		// это дало отказ «couldn't find env file», повторявшийся каждую минуту
		// двадцать раз подряд, — уборка не могла завершиться никогда.
		//
		// Имени проекта достаточно: `docker compose -p <имя> down` снимает
		// контейнеры и сеть, не читая ни файла, ни переменных.
		containers, listErr := inspectComposeContainers(ctx)
		if listErr != nil {
			fmt.Fprintf(os.Stderr, "снятие %s: не удалось осмотреть контейнеры: %v\n", slug, listErr)
			continue
		}

		downFailed := false
		for _, project := range tearDownProjects(containers, slug, p.repoDir(slug)) {
			if out, err := dockerCompose(ctx, dir, "-p", project, "down", "--remove-orphans"); err != nil {
				fmt.Fprintf(os.Stderr, "не удалось снять стек %s (проект %s): %v: %s\n",
					slug, project, err, tail(out, 300))
				downFailed = true
			}
		}
		if downFailed {
			// Отметку оставляем: попробуем снова на следующем цикле.
			continue
		}

		if err := os.Remove(filepath.Join(dir, ".env")); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "стек %s снят, но .env не удалён: %v\n", slug, err)
		}

		// Рабочая копия репозитория — вместе со стеком: код клиента не должен
		// оставаться на диске после того, как приложение убрали из платформы.
		removeRepo(p, slug)

		// Данные — только по явной отметке. Тома удаляются ПОСЛЕ снятия стека:
		// занятый том docker не отдаст, и попытка до `down` провалилась бы.
		if purge[slug] {
			purged, failed := removeAppVolumes(ctx, slug)
			if len(purged) > 0 {
				fmt.Printf("удалены данные %s: %v\n", slug, purged)
			}
			if len(failed) > 0 {
				// Не молчим и не считаем успехом: оставшийся том помешает
				// развернуть приложение с тем же именем заново, и узнать об
				// этом лучше сейчас, а не через месяц из невнятной ошибки
				// аутентификации.
				fmt.Fprintf(os.Stderr, "данные %s удалены НЕ полностью, остались: %v\n", slug, failed)
			}
		}

		// Каталог приложения — ПОСЛЕДНИМ и обязательно.
		//
		// По нему PresentSlugs решает, что развёрнуто на хосте, а сервер по
		// этому списку подтверждает удаление. Оставленный пустой каталог
		// означал, что агент вечно докладывает приложение живым: карточка
		// навсегда застревала в «Удаляется», хотя ни контейнера, ни тома на
		// хосте уже не было.
		//
		// После `down`, а не до: до него здесь лежит compose, которым стек и
		// снимается, и повтор на следующем цикле стал бы невозможен.
		removeAppDir(p, slug)

		delete(state.Apps, slug)
		changed = true
		removed = append(removed, slug)
	}

	if changed {
		if err := SaveApplied(p, state); err != nil {
			fmt.Fprintf(os.Stderr, "не удалось сохранить отметки после уборки: %v\n", err)
		}
	}
	return removed
}

// removeAppDir убирает служебный каталог приложения.
//
// Именно его наличие означает для PresentSlugs «приложение развёрнуто», а для
// сервера — «удаление ещё не подтверждено». Ошибка не роняет уборку: стек уже
// снят, и повтор случится на следующем цикле.
func removeAppDir(p Paths, slug string) {
	if !safeSlug.MatchString(slug) {
		return
	}
	if err := os.RemoveAll(p.appDir(slug)); err != nil {
		fmt.Fprintf(os.Stderr, "стек %s снят, но каталог не удалён: %v\n", slug, err)
	}
}

// applyOne поднимает один стек.
//
// extra — то, что стоит рассказать платформе помимо факта успеха: список
// сервисов, объявивших публикацию. Без него человек не знает имён, из которых
// выбирать домены, и остаётся с конвенцией, о которой нигде не сказано.
//
// written получает sha256 каждого файла стека сразу после его удачной записи —
// базовую линию сверки дрейфа (ADR-0078). Сразу, а не в конце: выкат может
// оборваться после любой записи, а файл на диске уже новый.
func applyOne(
	ctx context.Context,
	p Paths,
	app DesiredApp,
	report func(phase, output string),
	written *AppliedRecord,
) (extra map[string]any, err error) {
	extra = map[string]any{}
	if !safeSlug.MatchString(app.Slug) {
		return extra, fmt.Errorf("недопустимый slug приложения: %q", app.Slug)
	}
	if app.Domain != "" && !safeDomain.MatchString(app.Domain) {
		return extra, fmt.Errorf("недопустимый домен: %q", app.Domain)
	}

	dir := p.appDir(app.Slug)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return extra, fmt.Errorf("не удалось создать каталог %s: %w", dir, err)
	}

	// Каталог, ИЗ которого запускается compose.
	//
	// Для приложения из каталога описание присылает сервер, и мы кладём его
	// рядом; плейсхолдеры ${VAR} разворачивает сам docker compose из .env —
	// своего шаблонизатора нет намеренно.
	//
	// Для приложения из репозитория — тот же служебный каталог: описание туда
	// кладётся уже ПОДГОТОВЛЕННЫМ (снятые `ports` и `container_name`, сеть
	// прокси, `name: <slug>`), а пути внутрь рабочей копии подставляет
	// prepareRepoCompose. Каталог здесь ровно один, и это важно: проверка
	// здоровья и самовосстановление обязаны смотреть в тот же проект compose,
	// иначе здоровый стек рапортуется как down, а восстановление поднимает
	// сырое описание автора в обход нормализации.
	//
	// .env остаётся в служебном каталоге и передаётся явно: положить его в
	// рабочую копию значило бы отдавать пароли под `git clean` и рисковать тем,
	// что он попадёт в сборочный контекст образа.
	runDir := dir
	envPath := filepath.Join(dir, ".env")
	// repoDir — рабочая копия репозитория. Нужна отдельно от runDir: compose
	// запускается из служебного каталога, а относительные пути описания стека
	// ведут в копию, и guard обязан считать её законным корнем.
	repoDir := ""

	// .env пишем ДО разбора источника.
	//
	// Описание стека из репозитория читает сам docker compose, а ему передаётся
	// `--env-file` с этим путём: файла ещё нет — команда падает с «couldn't find
	// env file», и выкат обрывается на разборе, не дойдя до подъёма. Раньше
	// порядок не имел значения, потому что compose звали только после.
	//
	// Зависимостей от источника у содержимого нет: renderEnv читает только само
	// приложение.
	env := renderEnv(app)
	if err := writeFileAtomic(envPath, []byte(env), 0o600); err != nil {
		return extra, fmt.Errorf("не удалось записать .env: %w", err)
	}
	written.EnvSha256 = sha256Hex(env)

	if app.FromGit() {
		commit, err := FetchRepo(ctx, p, app)
		if err != nil {
			return extra, err
		}
		fmt.Printf("репозиторий %s обновлён до %s\n", app.Slug, tail(commit, 12))

		// Dockerfile/статика: в репозитории по определению нет compose —
		// агент кладёт его сам, ПОСЛЕ FetchRepo (тот на каждом цикле чистит
		// untracked-файлы через `git clean -fd`, и записанный раньше compose
		// исчез бы) и ДО чтения ниже, которое дальше работает одинаково для
		// всех трёх способов сборки.
		if app.needsSyntheticCompose() {
			if err := writeSyntheticCompose(p, app); err != nil {
				return extra, err
			}
		}

		if _, err := readComposeFromRepo(p, app); err != nil {
			return extra, err
		}
		repoDir = p.repoDir(app.Slug)

		// Каталог, из которого запускается compose, — папка приложения (0284).
		// Для приложения без неё это сама рабочая копия, то есть прежнее
		// поведение. Корнем для guard остаётся ВСЯ рабочая копия: при сборке из
		// корня монорепо контекст лежит выше папки приложения, и сузить корень
		// до неё значило бы отвергнуть собственный синтетический compose.
		srcDir, srcErr := repoAppDir(p, app)
		if srcErr != nil {
			return extra, srcErr
		}

		// Описание из репозитория приводим к тому, что платформа готова
		// поднять, — вместо того чтобы требовать этого от автора.
		//
		// Раньше репозиторий обязан был знать четыре вещи, ни одна из которых
		// нигде не написана: входной сервис называется `app`, он подключён к
		// сети прокси, в файле стоит имя проекта с идентификатором приложения,
		// а `ports` запрещены. Несовпадение давало зелёный выкат и молчащий
		// домен.
		//
		// Модель снимает сам compose: якоря, `extends` и `x-`-фрагменты уже
		// раскрыты, сети явные, пути абсолютные — поэтому готовый файл можно
		// положить в служебный каталог и запускать оттуда, не трогая рабочую
		// копию git.
		prepared, err := prepareRepoCompose(ctx, p, app, envPath)
		if err != nil {
			return extra, err
		}
		if len(prepared.Candidates) > 0 {
			extra["publish_candidates"] = prepared.Candidates
		}

		// Стек под прежним именем проекта гасим ДО подъёма своего.
		//
		// Имя проекта теперь задаём мы, и compose увидел бы другой проект:
		// поднял бы второй комплект контейнеров рядом, оставив прежний
		// работать. Два комплекта на одних томах — не конфликт, а порча.
		if stopped, stopErr := shutdownPreviousProject(ctx, prepared.PreviousProject, srcDir, repoDir); stopErr != nil {
			return extra, stopErr
		} else if stopped {
			report("prepare", fmt.Sprintf(
				"снят стек под прежним именем проекта %q — платформа поднимет его под %q",
				prepared.PreviousProject, app.Slug))
		}
		if err := writeFileAtomic(filepath.Join(dir, "docker-compose.yml"), prepared.File, 0o640); err != nil {
			return extra, fmt.Errorf("не удалось записать описание стека: %w", err)
		}
		written.ComposeSha256 = sha256Hex(string(prepared.File))
		for _, note := range prepared.Notes {
			report("prepare", note)
		}
	} else {
		if strings.TrimSpace(app.Compose) == "" {
			return extra, fmt.Errorf("пустое описание стека для %s", app.Slug)
		}
		if err := writeFileAtomic(filepath.Join(dir, "docker-compose.yml"),
			[]byte(app.Compose), 0o640); err != nil {
			return extra, fmt.Errorf("не удалось записать compose: %w", err)
		}
		written.ComposeSha256 = sha256Hex(app.Compose)

		// Файлы конфигурации — ПОСЛЕ compose и ДО подъёма: стек монтирует их с
		// первой же секунды (конфиг Kong, инициализация базы), и разложить их
		// позже значило бы поднять сервисы без конфигурации.
		//
		// Ветка охватывает каталог, образ и «свой compose» (0206); у приложения
		// из репозитория такие файлы лежат в рабочей копии, и запись поверх
		// подменяла бы код клиента файлами, пришедшими по сети, — ему сервер
		// шлёт пустой список, а сюда исполнение не заходит вовсе.
		if err := writeTemplateFiles(dir, app.Files); err != nil {
			return extra, err
		}
	}

	// ПРОВЕРЯЕТСЯ ЛЮБОЙ COMPOSE, А НЕ ТОЛЬКО КЛИЕНТСКИЙ (задача С1.5).
	//
	// Раньше guard стоял только на описании, написанном клиентом: шаблон
	// каталога и рендер образа считались доверенными, потому что их пишет
	// платформа. Но вся эта работа как раз о том, что платформа может оказаться
	// не собой: запись в `deploy.*` или код в web дают произвольный compose на
	// каждом подключённом сервере. Довод «это наше» перестаёт работать ровно
	// тогда, когда он нужен.
	//
	// Проверяем ДО запуска: после `up` любое ограничение уже бессмысленно.
	//
	// Шаблоны каталога это переживают: они написаны под те же правила —
	// именованные тома, без `ports`, без сокета докера (проверено по шаблонам
	// на бою 18.09.2026). Шаблон, который правила нарушит, честно откажет — и
	// это лучше, чем тихо получить привилегию через «доверенный» источник.
	{
		roots := []string{runDir, dir}
		if repoDir != "" {
			roots = append(roots, repoDir)
		}
		// Служебный каталог — runDir: в нём лежит описание стека, которым
		// агент его и поднимает, и его нельзя отдавать контейнеру во владение
		// (задача С1.6).
		if err := verifyComposeSafety(ctx,
			composeTarget{ProjectDir: runDir, EnvFile: envPath},
			composeguard.Options{Roots: roots, ServiceDirs: []string{runDir}, AdoptedVolumes: app.AdoptedVolumes,
				// Послабления — только из проверенного гранта корня к этим
				// байтам compose (С1.5); без подписи их нет вовсе.
				Allowances: app.Allowances},
		); err != nil {
			return extra, err
		}
	}

	// Сеть прокси должна существовать до подъёма стека: шаблон объявляет её
	// внешней, и без неё compose откажется стартовать.
	if err := ensureEdgeNetwork(ctx); err != nil {
		return extra, err
	}

	// Пороги приходят из шаблона: стек из десятка сервисов на первом выкате
	// тянет десяток образов, и 180 секунд, выведенные на двухконтейнерном n8n,
	// для него означают не «долго», а «отказ». Агент границы всё равно
	// навязывает свои — вход недоверенный.
	spec := app.ApplySpec.normalized()

	// Сборка — ДО подъёма и отдельной фазой.
	//
	// `up` собирает образ, только если его нет, поэтому без этого шага второй и
	// все последующие выкаты приложения из репозитория поднимали контейнер из
	// образа первого выката: свежий коммит доезжал до рабочей копии и не
	// доезжал до контейнера. Подробности и объяснение границ — build.go.
	//
	// Список образов снимается ДО сборки: после успешного подъёма он скажет,
	// что именно вытеснила пересборка и что можно убрать с диска.
	var imagesBefore []string
	if app.needsImageBuild() {
		imagesBefore = projectImageIDs(ctx, runDir, envPath)

		report("build", "")
		if err := buildImages(ctx, p, runDir, envPath,
			func(t string) { report("build", t) }); err != nil {
			return extra, err
		}
	}

	// --wait заставляет compose дождаться, пока сервисы станут healthy (или
	// running, если проверки нет), и вернуть ненулевой код, если не дождался.
	// Своя реализация этого ожидания оказалась хуже: `docker compose ps` без
	// --all не показывает вышедшие контейнеры вовсе, поэтому упавший сервис
	// просто исчезал из вывода и стек объявлялся здоровым.
	//
	// Вывод стримится в отчёты о ходе: подъём тяжёлого стека занимает минуты,
	// и всё это время пользователь видел «Разворачивается» без подробностей —
	// и шёл смотреть журнал агента по SSH, куда платформа и должна была его
	// не пускать.
	report("up", "")
	upArgs := []string{"up", "-d", "--remove-orphans",
		"--wait", "--wait-timeout", strconv.Itoa(spec.WaitTimeoutSeconds)}

	out, err := dockerComposeStreamEnv(ctx, runDir, envPath,
		func(t string) { report("up", t) }, upArgs...)

	// Гонка пересоздания — не отказ стека, а незавершённая уборка прежнего
	// контейнера (см. recreate.go). Повтор ровно один: гонка разрешается за
	// секунды, а бесконечные попытки скрыли бы настоящую поломку.
	if err != nil && isRecreateRace(out) {
		report("up", "docker не успел убрать прежний контейнер — убираем остаток и повторяем")
		removed, pruneErr := removeRenamedLeftovers(ctx, app.Slug)
		if pruneErr != nil {
			fmt.Fprintf(os.Stderr, "уборка остатков %s: %v\n", app.Slug, pruneErr)
		} else if len(removed) > 0 {
			report("up", "убраны остатки пересоздания: "+strings.Join(removed, ", "))
		}
		if waitErr := waitBeforeRetry(ctx, recreateRaceBackoff); waitErr != nil {
			return extra, waitErr
		}
		out, err = dockerComposeStreamEnv(ctx, runDir, envPath,
			func(t string) { report("up", t) }, upArgs...)
		if err == nil {
			extra["recreate_race_retried"] = true
		}
	}

	if err != nil {
		// Та же подсказка, что при сборке: подъём образа из реестра упирается
		// в лимит Docker Hub ровно так же, а для приложения из готового образа
		// это ЕДИНСТВЕННОЕ место, где отказ вообще возникает.
		return extra, fmt.Errorf("docker compose up: %w: %s%s", err,
			explainPullLimit(ctx, p, tail(out, 800)),
			failedServiceLogs(ctx, runDir, envPath, out, app))
	}

	// compose дождался готовности — теперь убеждаемся, что состояние
	// устойчиво. Сервис без healthcheck считается готовым в момент старта, и
	// падение через две секунды после него compose уже не заметит.
	report("stabilize", "")
	if err := waitStable(ctx, runDir, envPath, spec); err != nil {
		return extra, err
	}

	// Стек здоров — но это ещё не значит, что домен работает.
	//
	// Все проверки выше смотрят на стек и ни одна — на связь стека с прокси.
	// Из-за этого выкат мог быть зелёным при полностью мёртвом домене: прокси
	// направлен в контейнер, которого нет, потому что сервис в репозитории
	// называется иначе. Причина не следовала ни из чего и находилась только
	// чтением исходников платформы.
	report("publish", "")
	if err := VerifyRoutes(ctx, app); err != nil {
		return extra, err
	}

	// Уборка — только после подтверждённого здоровья.
	//
	// Раньше снести прежний образ значило бы лишить хост единственного
	// работоспособного состояния: отката на предыдущий образ у git-приложений
	// нет, и при неудачном выкате поднять «как было» можно лишь тем, что ещё
	// лежит на диске.
	if app.needsImageBuild() {
		dropUnusedImages(ctx, imagesBefore, projectImageIDs(ctx, runDir, envPath))
	}
	return extra, nil
}

// isReservedEnvKey — имена, которые приложение переопределить не может
// (APP_SLUG, APP_DOMAIN, COMPOSE_*, DOCKER_*): правило в pkg/stackdir.
func isReservedEnvKey(key string) bool { return stackdir.IsReservedEnvKey(key) }

// renderEnv собирает .env приложения. Тот же текст строит подписант, поэтому
// правило одно — в pkg/stackdir.
func renderEnv(app DesiredApp) string {
	return stackdir.RenderEnv(app.Slug, app.Domain, app.Env)
}

func ensureEdgeNetwork(ctx context.Context) error {
	check := exec.CommandContext(ctx, "docker", "network", "inspect", EdgeNetwork)
	if err := check.Run(); err == nil {
		return nil
	}
	create := exec.CommandContext(ctx, "docker", "network", "create", EdgeNetwork)
	if out, err := create.CombinedOutput(); err != nil {
		// Гонка с параллельным созданием — не ошибка.
		if strings.Contains(string(out), "already exists") {
			return nil
		}
		return fmt.Errorf("не удалось создать сеть %s: %w: %s", EdgeNetwork, err, tail(string(out), 300))
	}
	return nil
}

// dockerEnv — окружение для docker и docker compose. Задаём явно и минимально.
//
// По умолчанию дочерний процесс наследует окружение агента, а docker
// compose читает оттуда очень много: переменная из окружения ПЕРЕБИВАЕТ
// значение из .env, а COMPOSE_PROJECT_NAME переопределяет `name:` в самом
// compose. Случайный COMPOSE_PROJECT_NAME в юните схлопнул бы все
// приложения хоста в один проект, и `up --remove-orphans` в каталоге
// одного снёс бы контейнеры другого. Туда же COMPOSE_FILE и COMPOSE_PROFILES.
//
// DOCKER_HOST раньше отсекался вместе с ними — с 18.09.2026 он пробрасывается
// (ADR-0083): под непривилегированным пользователем агент говорит не с
// сокетом демона, а со своим прокси, и его адрес задаётся именно этой
// переменной. Опасение осталось прежним — случайное значение в юните увело бы
// весь docker не туда, — но теперь значение там НЕ случайное, его ставит
// установщик рядом с User=.
//
// DOCKER_CONFIG пробрасывается сознательно: агент задаёт его при старте,
// чтобы учётные данные реестров жили в каталоге состояния, а не в /root —
// systemd-юнит закрывает домашние каталоги через ProtectHome. Одно и то же
// значение обязаны видеть и login, и compose, иначе pull не найдёт вход.
func dockerEnv() []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
	}
	if cfg := os.Getenv("DOCKER_CONFIG"); cfg != "" {
		env = append(env, "DOCKER_CONFIG="+cfg)
	}
	// Адрес демона обязан доехать до дочернего docker.
	//
	// Окружение здесь собирается СПИСКОМ, а не наследуется целиком (чтобы
	// секреты приложения не утекали в чужие процессы). Без этой строки агент
	// под непривилегированным пользователем ходил бы мимо своего прокси —
	// прямо в /var/run/docker.sock, которого у него нет, — и всё
	// развёртывание отказывало бы с «permission denied» (ADR-0083).
	if host := os.Getenv("DOCKER_HOST"); host != "" {
		env = append(env, "DOCKER_HOST="+host)
	}
	return env
}

func dockerCompose(ctx context.Context, dir string, args ...string) (string, error) {
	return dockerComposeEnv(ctx, dir, "", args...)
}

// dockerComposeEnv — то же, но с явным путём к .env.
//
// Нужен приложениям из репозитория: compose запускается ИЗ рабочей копии,
// чтобы работали `build: .` и относительные пути, а .env остаётся в служебном
// каталоге — иначе пароли попадали бы под `git clean` и в сборочный контекст
// образа.
//
// --env-file — глобальный флаг и обязан стоять ДО подкоманды.
func dockerComposeEnv(ctx context.Context, dir, envFile string, args ...string) (string, error) {
	cmd := newDockerCmd(ctx, dir, composeArgs(envFile, args)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func composeArgs(envFile string, args []string) []string {
	full := []string{"compose"}
	if envFile != "" {
		full = append(full, "--env-file", envFile)
	}
	return append(full, args...)
}

// dockerComposeParsed — вывод команды БЕЗ примеси stderr.
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ dockerComposeEnv. Для команд, чей вывод мы читаем глазами
// (`up`, `down`, `build`), смешивать потоки правильно: причина отказа чаще
// всего в stderr, и терять её нельзя. Для команд, чей вывод мы РАЗБИРАЕМ, это
// ошибка — и она стоила выката всякому, чей compose вызывает предупреждение.
//
// Docker Compose печатает их в stderr строкой вида
// `time="..." level=warning msg="the attribute version is obsolete"`, а
// `version:` стоит в подавляющем большинстве публичных репозиториев. Склеенный
// вывод начинался с `time=`, разбор JSON спотыкался на втором символе и
// сообщал `invalid character 'i' in literal true` — текст, по которому
// невозможно догадаться ни о причине, ни о том, что дело вообще не в стеке
// клиента.
//
// stderr не выбрасывается: он уходит в текст ошибки, где и полезен.
func dockerComposeParsed(ctx context.Context, dir, envFile string, args ...string) (string, error) {
	cmd := newDockerCmd(ctx, dir, composeArgs(envFile, args)...)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	out, err := cmd.Output()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", err, tail(strings.TrimSpace(errBuf.String()), 400))
	}
	return string(out), nil
}

// dockerComposeStream — вывод команды ПОТОКОМ в w, stderr отдельно.
//
// ЗАЧЕМ ТРЕТИЙ ВАРИАНТ. `dockerComposeEnv` и `dockerComposeParsed` возвращают
// вывод строкой, то есть держат его целиком в памяти. Для `up` и для разбора
// JSON это верно: там вывод короткий. Для `pg_dump` — нет: дамп чужой базы
// может быть в гигабайты, а агент работает на КЛИЕНТСКОМ хосте рядом с его же
// боевыми контейнерами. Съесть там память ради файла, который всё равно уедет
// на диск, — плохой размен.
//
// stderr при этом остаётся отдельно, по той же причине, что и у
// `dockerComposeParsed`: предупреждение docker compose, подмешанное в начало
// файла `.sql`, ломает восстановление, а заметно это становится в тот момент,
// когда восстановление и понадобилось.
func dockerComposeStream(ctx context.Context, dir, envFile string, w io.Writer, args ...string) error {
	return runStreaming(newDockerCmd(ctx, dir, composeArgs(envFile, args)...), w)
}

// runStreaming — вся проводка потоков одной командой: stdout в w, stderr в текст
// ошибки.
//
// ВЫНЕСЕНО ОТ dockerComposeStream РАДИ ПРОВЕРЯЕМОСТИ. Двоичное имя `docker`
// вшито в `newDockerCmd` намеренно (там своя группа процессов и срок), и
// подменять его ради теста значило бы завести шов в бою ради проверки. А
// проверить надо ровно одно: что предупреждение из stderr НЕ попало в файл
// данных. Для этого docker не нужен — нужна любая команда, пишущая в оба
// потока.
func runStreaming(cmd *exec.Cmd, w io.Writer) error {
	var errBuf bytes.Buffer
	cmd.Stdout = w
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, tail(strings.TrimSpace(errBuf.String()), 400))
	}
	return nil
}

// waitStable убеждается, что стек не просто поднялся, а держится.
//
// Это и есть health gate. Один удачный замер ничего не доказывает: сервис без
// healthcheck считается готовым в момент старта, а сервис с проверкой — после
// ПЕРВОЙ удачной пробы. Контейнер, падающий через две секунды, оба этих
// критерия проходит. Именно так в самом Scopework сломанный сервис полтора
// часа крутился в перезапуске, а выкат при этом считался успешным.
//
// Опрос идёт с --all: без него `docker compose ps` показывает только
// работающие контейнеры, и вышедший сервис не давал бы «не running», а просто
// исчезал бы из вывода.
//
// Сами правила «что считать здоровым» живут в checkServiceStates — отдельно,
// потому что внутри цикла, ходящего в docker, они не проверяются тестами.
func waitStable(ctx context.Context, dir, envFile string, spec ApplySpec) error {
	// Набор сервисов берём из самого compose: иначе «сервис не создан вовсе»
	// неотличимо от «сервиса нет в выводе ps».
	expected, err := composeServices(ctx, dir, envFile)
	if err != nil {
		return err
	}
	// Сервисы, которым положено завершиться (миграции, инициализация), — из
	// того же описания: их `exited 0` не отказ, а штатный исход.
	completed := composeCompletedServices(ctx, dir, envFile)

	for i := 0; i < spec.StableChecks; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(spec.StableInterval()):
			}
		}

		out, err := dockerComposeParsed(ctx, dir, envFile, "ps", "--all",
			"--format", "{{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}")
		if err != nil {
			return fmt.Errorf("docker compose ps: %w: %s", err, tail(out, 400))
		}

		if err := checkServiceStates(out, expected, completed); err != nil {
			return err
		}
	}

	return nil
}

// composeServices возвращает имена сервисов из compose-файла.
func composeServices(ctx context.Context, dir, envFile string) ([]string, error) {
	out, err := dockerComposeParsed(ctx, dir, envFile, "config", "--services")
	if err != nil {
		return nil, fmt.Errorf("docker compose config: %w: %s", err, tail(out, 400))
	}
	var services []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			services = append(services, line)
		}
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("в compose нет ни одного сервиса")
	}
	return services, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// tail обрезает вывод команды: в отчёт на сервер не должен уезжать мегабайт
// логов, а в них к тому же могут оказаться значения переменных.
func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// unhealthyServiceRe вытаскивает имя сервиса из отказа compose.
//
// `--wait` печатает `dependency failed to start: container <проект>-<сервис>-N
// is unhealthy` либо `container <...> exited (1)`. Имя контейнера собирает сам
// compose, поэтому разбираем его, а не гадаем по составу стека.
var unhealthyServiceRe = regexp.MustCompile(
	`container ([A-Za-z0-9._-]+) is unhealthy|container ([A-Za-z0-9._-]+) exited`)

// failedServiceLogs дочитывает журнал контейнера, на котором встал подъём.
//
// ЗАЧЕМ. Без этого пользователь получал ровно то, что вернул compose:
// «dependency failed to start: container doc-patients-api-1 is unhealthy». Что
// именно не так с контейнером, compose не знает и знать не может — причина в
// его собственном выводе. Реальный случай: приложение отказывалось стартовать,
// потому что не заданы AUTH_USERS и SECRET_KEY, и говорило об этом прямым
// текстом — в журнал, которого платформа не читала. Человек видел
// «exit status 1» и шёл за причиной по SSH, то есть туда, куда платформа
// обязана была его не пускать.
//
// Хвост, а не весь журнал: причина падения всегда в конце, а стартовый шум
// приложения нам не нужен. Секреты затираются — в журнале приложения бывает
// строка подключения.
//
// Неудача чтения молча возвращает пустую строку: это ДОПОЛНЕНИЕ к отказу, а не
// его условие. Отказ уже есть и уже осмыслен.
func failedServiceLogs(
	ctx context.Context,
	dir, envFile, composeOutput string,
	app DesiredApp,
) string {
	match := unhealthyServiceRe.FindStringSubmatch(composeOutput)
	if match == nil {
		return ""
	}
	container := match[1]
	if container == "" {
		container = match[2]
	}

	cmd := newDockerCmd(ctx, "", "logs", "--tail", "40", container)
	cmd.Env = dockerEnv()
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}

	logs := strings.TrimSpace(redactSecrets(tail(string(out), 1200), app.redactionValues()))
	if logs == "" {
		return ""
	}
	return "\n\nЖурнал " + container + " (последнее):\n" + logs
}
