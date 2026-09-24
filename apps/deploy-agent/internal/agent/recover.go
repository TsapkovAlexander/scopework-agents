package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Самовосстановление: сервис упал — агент поднимает его обратно.
//
// ЗАЧЕМ. До этого «желаемое состояние» означало «конфигурация применена», а не
// «стек работает»: агент сверял идентификатор релиза и отпечаток конфигурации,
// и если они не менялись, не делал ничего. Остановленный ночью контейнер так и
// лежал до утра, а платформа считала, что всё в порядке (проверку здоровья,
// которая этого не замечала, чинили отдельно — она звала `compose ps` без
// --all).
//
// ГРАНИЦЫ. Восстановление — это `docker compose up -d`, то есть ровно то, что
// агент и так делает при выкате: без пересборки образа, без пересоздания
// томов, без изменения конфигурации. Оно поднимает то, чего не хватает, и не
// трогает работающее.
//
// ПОЧЕМУ С ПАУЗАМИ И ПОТОЛКОМ. Приложение падает по двум разным причинам, и
// различить их снаружи нельзя: случайность (OOM, перезагрузка docker) —
// лечится подъёмом; собственная неисправность (падает на старте) — подъёмом не
// лечится, и упорные попытки превращаются в цикл, который жжёт процессор
// клиента, забивает журнал и мешает человеку читать настоящую причину в логах
// контейнера. Поэтому попытки редеют, а после потолка агент перестаёт
// вмешиваться и оставляет отказ видимым.
//
// ПОЧЕМУ КАЖДАЯ ПОПЫТКА ВИДНА. «Оно само починилось» — худший вид отчёта:
// сервис, падающий по три раза за ночь и трижды поднятый, снаружи неотличим от
// работающего без сбоев. Каждая попытка пишется в журнал агента и уезжает в
// подробностях здоровья.

const (
	// Потолок попыток в серии. Дальше агент только сообщает: если пять
	// подъёмов подряд не помогли, шестой не поможет тоже.
	maxRecoveryAttempts = 5
	// Пауза после первой неудачи; дальше удваивается.
	recoveryBaseDelay = 2 * time.Minute
	// Через сколько после последней попытки серия считается законченной и
	// счётчик обнуляется. Иначе одна ночная авария навсегда лишила бы
	// приложение права на восстановление.
	recoveryResetAfter = 6 * time.Hour
)

// recoveryBackoff — пауза перед попыткой номер attempt (нумерация с нуля).
//
// 0 → сразу, 1 → 2 мин, 2 → 4, 3 → 8, 4 → 16. Суммарно серия растягивается на
// полчаса — достаточно, чтобы пережить перезапуск docker или всплеск нагрузки,
// и мало, чтобы не выглядеть зависанием.
func recoveryBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return 0
	}
	delay := recoveryBaseDelay
	for i := 1; i < attempt; i++ {
		delay *= 2
	}
	return delay
}

// RecoveryDecision — что агент собирается сделать с упавшим приложением.
type RecoveryDecision struct {
	Recover bool
	Reason  string
	// Attempt — номер попытки в текущей серии, для отчёта и журнала.
	Attempt int
}

// decideRecovery решает, поднимать ли приложение.
//
// Отдельной чистой функцией: это единственное место, где агент по собственной
// инициативе трогает чужой стек, и проверять его наблюдением за боевым
// сервером — плохая идея.
//
// restoreInterrupted — на хосте стоит флаг восстановления из копии
// (restore.go). Передаётся аргументом, а не читается здесь, по той же причине:
// решение остаётся чистым и проверяется без файловой системы.
func decideRecovery(
	rec AppliedRecord,
	found bool,
	app DesiredApp,
	health HealthStatus,
	now time.Time,
	restoreInterrupted bool,
) RecoveryDecision {
	// Сорвавшееся восстановление — первым, раньше всех прочих причин: тома
	// остались наполовину из копии, и подъём на них выглядел бы работающим
	// приложением, у которого вернуть прежние данные уже нечем. Лежащее честнее.
	// Причина — первой ещё и потому, что человеку важнее всего узнать именно её.
	if restoreInterrupted {
		return RecoveryDecision{
			Reason: "восстановление из копии не завершилось, тома могут быть смешанными: " +
				"стек не поднимается до повторного восстановления или выката",
		}
	}
	// Приложение, которое должно быть снято, поднимать не нужно — это прямо
	// противоположно желаемому состоянию.
	if !app.ShouldRun() {
		return RecoveryDecision{Reason: "приложение снимается"}
	}
	// Никогда не применялось — этим занимается обычный выкат, а не
	// восстановление.
	if !found || rec.ReleaseID == "" {
		return RecoveryDecision{Reason: "ещё не применялось"}
	}
	// Неудачный выкат — тоже не наше дело: там своя пауза и свой повтор,
	// иначе две механики начнут поднимать один стек наперегонки.
	if rec.Status == "failed" {
		return RecoveryDecision{Reason: "выкат не удался, повтором занимается применение"}
	}

	switch health {
	case HealthHealthy:
		return RecoveryDecision{Reason: "здорово"}
	case HealthUnknown:
		// «Не знаем» — не повод трогать чужой стек: состояние без данных
		// бывает у только что развёрнутого приложения и при сбое опроса.
		return RecoveryDecision{Reason: "состояние неизвестно"}
	}

	attempt := rec.RecoveryAttempts
	// Серия давно закончилась — начинаем заново.
	if !rec.LastRecovery.IsZero() && now.Sub(rec.LastRecovery) >= recoveryResetAfter {
		attempt = 0
	}

	if attempt >= maxRecoveryAttempts {
		return RecoveryDecision{
			Attempt: attempt,
			Reason:  "потолок попыток исчерпан, подъём не помогает",
		}
	}

	if wait := recoveryBackoff(attempt); wait > 0 && now.Sub(rec.LastRecovery) < wait {
		return RecoveryDecision{
			Attempt: attempt,
			Reason:  "ждём паузу перед следующей попыткой",
		}
	}

	return RecoveryDecision{Recover: true, Attempt: attempt + 1, Reason: "сервис не работает"}
}

// recoverApp поднимает недостающие контейнеры приложения.
//
// Тем же `up -d`, что и выкат, но БЕЗ пересборки и без ожидания устойчивости:
// здесь мы не меняем конфигурацию, а возвращаем то, что уже было применено.
// Долгое ожидание здесь только задержало бы цикл — результат всё равно увидит
// следующая проверка здоровья.
func recoverApp(ctx context.Context, p Paths, app DesiredApp) error {
	// Проверка slug здесь, а не только у вызывающих.
	//
	// Сегодня сюда не доходит мусор: applyOne отказывается заводить каталог под
	// недопустимым slug, поэтому compose в таком каталоге просто нечему поднять.
	// Но это свойство ЧУЖОЙ функции, а не этой: путь под docker собирается прямо
	// на строке ниже, и безопасность пути должна следовать из кода, который его
	// строит. removeAppDir и applyOne проверяют у себя — здесь пропуск.
	if !safeSlug.MatchString(app.Slug) {
		return fmt.Errorf("недопустимый slug приложения: %q", app.Slug)
	}

	dir := p.appDir(app.Slug)

	// ФАЙЛ ДОЛЖЕН БЫТЬ ТОТ ЖЕ, ЧТО ПРИМЕНЯЛ ВЫКАТ (задача С1.6).
	//
	// Guard проверяет описание стека ПЕРЕД выкатом, и на тот момент оно чистое.
	// Но контейнер, получивший bind внутри своего каталога, может переписать
	// `docker-compose.yml` у себя под ногами — а восстановление поднимает файл
	// с диска, не спрашивая никого. Тогда падение (в том числе вызванное
	// нарочно) превращается в подъём ПОДМЕНЁННОГО стека: с `privileged`, с
	// сокетом докера, с любым томом хоста.
	//
	// Сам bind своего каталога и compose теперь запрещён (`isSelfRewrite`), но
	// это первый рубеж: он действует, пока guard видит описание. Сверка хеша —
	// второй, и она отвечает на другой вопрос: «тот ли файл на диске сейчас».
	//
	// Хеш отсутствует — не повод отказать: так выглядит приложение, применённое
	// версией агента до появления записи. Молчание здесь честнее, чем
	// остановка работающего восстановления.
	if rec, ok := LoadApplied(p).Apps[app.Slug]; ok && rec.ComposeSha256 != "" {
		raw, readErr := os.ReadFile(filepath.Join(dir, "docker-compose.yml"))
		if readErr != nil {
			return fmt.Errorf("описание стека не прочитано: %w", readErr)
		}
		if got := sha256Hex(string(raw)); got != rec.ComposeSha256 {
			return fmt.Errorf(
				"описание стека на диске изменилось после выката (ожидалось %s, на диске %s) — "+
					"восстановление отменено: поднимать подменённый файл нельзя",
				rec.ComposeSha256[:12], got[:12])
		}
	}

	// Поднимаем ровно тот файл, который применял выкат.
	//
	// Раньше для приложения из репозитория здесь подставлялась рабочая копия, то
	// есть СЫРОЕ описание автора: без снятых `ports`, без снятого
	// `container_name`, без подключения к сети прокси и с авторским именем
	// проекта. Любая деградация — вплоть до одной неудачной HTTP-пробы при живых
	// контейнерах — пересоздавала стек по этому описанию: порты уезжали на
	// 0.0.0.0 в обход Caddy и TLS. Подготовленный файл лежит в служебном
	// каталоге и переживает перезапуски, поэтому вариантов здесь быть не должно.
	out, err := dockerComposeEnv(ctx, dir, filepath.Join(dir, ".env"), "up", "-d", "--remove-orphans")
	if err != nil {
		return fmt.Errorf("%w: %s", err,
			explainPullLimit(ctx, p, redactSecrets(tail(out, 400), app.redactionValues())))
	}
	return nil
}

// runRecovery — попытка восстановления по итогам проверки здоровья.
//
// Возвращает обновлённую отметку: счётчик попыток и время последней живут
// рядом с остальным состоянием применения, потому что решение принимается по
// ним обоим.
func runRecovery(
	ctx context.Context,
	p Paths,
	app DesiredApp,
	health HealthStatus,
	rec AppliedRecord,
	found bool,
	now time.Time,
) (AppliedRecord, bool) {
	restoreInterrupted := hasRestoreFlag(p, app.Slug)
	decision := decideRecovery(rec, found, app, health, now, restoreInterrupted)
	if !decision.Recover {
		// Сорвавшееся восстановление — единственный отказ, о котором человек
		// обязан узнать из журнала: стек лежит НАМЕРЕННО, и без этой строки он
		// неотличим от забытого.
		//
		// Остальные причины молчат, и это не упущение: такт идёт раз в минуту,
		// и печать на каждом дала бы строку в минуту на каждое здоровое
		// приложение хоста — настоящая причина аварии утонула бы в ней.
		// Условие «не здорово» — оттуда же: приложение с флагом, которое
		// работает, ни от кого не спрятано, и повторять про него каждую минуту
		// незачем.
		if restoreInterrupted && health != HealthHealthy {
			fmt.Fprintf(os.Stderr, "восстановление %s: %s\n", app.Slug, decision.Reason)
		}

		// Здоровое приложение обнуляет серию: следующая авария начнёт счёт
		// заново, а не продолжит прошлогоднюю.
		if health == HealthHealthy && rec.RecoveryAttempts != 0 {
			rec.RecoveryAttempts = 0
			return rec, true
		}
		return rec, false
	}

	fmt.Fprintf(os.Stderr, "восстановление %s: %s (попытка %d из %d)\n",
		app.Slug, decision.Reason, decision.Attempt, maxRecoveryAttempts)

	rec.RecoveryAttempts = decision.Attempt
	rec.LastRecovery = now

	if err := recoverApp(ctx, p, app); err != nil {
		fmt.Fprintf(os.Stderr, "восстановление %s не удалось: %v\n", app.Slug, err)
	}
	return rec, true
}

// RecoverUnhealthy — поднять то, что должно работать, но не работает.
//
// Вызывается раз в цикл, после отчёта о здоровье. Состояние попыток хранится
// в том же файле, что и отметки применения: решение принимается по ним вместе.
func RecoverUnhealthy(ctx context.Context, p Paths, apps []DesiredApp, health []AppHealth) error {
	status := make(map[string]HealthStatus, len(health))
	for _, h := range health {
		status[h.Slug] = h.Status
	}

	state := LoadApplied(p)

	now := time.Now().UTC()
	changed := false
	for _, app := range apps {
		rec, found := state.Apps[app.Slug]
		updated, dirty := runRecovery(ctx, p, app, status[app.Slug], rec, found, now)
		if dirty {
			if state.Apps == nil {
				state.Apps = map[string]AppliedRecord{}
			}
			state.Apps[app.Slug] = updated
			changed = true
		}
	}

	if !changed {
		return nil
	}
	return SaveApplied(p, state)
}
