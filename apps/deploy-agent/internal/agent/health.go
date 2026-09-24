package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// Постоянный контроль здоровья развёрнутых приложений.
//
// Отличие от проверки при выкате: там мы ждём, пока стек станет здоровым, и
// это разовое событие. Здесь мы опрашиваем состояние на каждом цикле, чтобы
// падение через неделю после успешного выката тоже было замечено.
//
// Именно этого не хватало сегодня утром в самом Scopework: сервис падал в
// бесконечный перезапуск, выкат при этом считался успешным, и полтора часа
// никто не знал, что планировщики стоят.

// HealthStatus — состояние приложения целиком.
type HealthStatus string

const (
	// HealthHealthy — все контейнеры работают и проходят свои проверки.
	HealthHealthy HealthStatus = "healthy"
	// HealthDegraded — часть контейнеров жива, часть нет. Приложение может
	// отвечать, но неполноценно: например, поднялось само, а база упала.
	HealthDegraded HealthStatus = "degraded"
	// HealthDown — не работает ничего.
	HealthDown HealthStatus = "down"
	// HealthUnknown — состояние получить не удалось.
	HealthUnknown HealthStatus = "unknown"
)

// AppHealth — результат опроса одного приложения.
type AppHealth struct {
	Slug   string
	Status HealthStatus
	Detail map[string]any
}

// neverDeployedReason — единая формулировка на оба случая «выката тут не
// было». Разделять их в интерфейсе незачем: человеку нужно одно и то же
// действие — открыть журнал выката, а не разбираться, какого файла не хватило.
const neverDeployedReason = "приложение ещё не разворачивалось на этом сервере"

type containerState struct {
	Service string `json:"service"`
	State   string `json:"state"`
	Health  string `json:"health"`
	// ExitCode вместе с Completed отличает отработавшие миграции от упавшего
	// сервиса: и то и другое docker показывает состоянием `exited`.
	ExitCode  string `json:"exitCode,omitempty"`
	Completed bool   `json:"completed,omitempty"`
}

// CheckHealth опрашивает состояние всех приложений на хосте.
func CheckHealth(ctx context.Context, p Paths, apps []DesiredApp) []AppHealth {
	out := make([]AppHealth, 0, len(apps))
	for _, app := range apps {
		// Остановленное приложение опрашивать незачем: оно и должно быть
		// снято, а отчёт «down» поднял бы ложный инцидент.
		if !app.ShouldRun() || !safeSlug.MatchString(app.Slug) {
			continue
		}
		out = append(out, checkOne(ctx, p, app))
	}
	return out
}

func checkOne(ctx context.Context, p Paths, app DesiredApp) AppHealth {
	slug := app.Slug
	dir := p.appDir(slug)

	// Каталога нет — приложение на этом хосте ещё не разворачивали. Это не
	// «упало», это «пока ничего не было», и путать их нельзя: ложное падение
	// поднимет инцидент на ровном месте.
	if _, err := os.Stat(dir); err != nil {
		return AppHealth{
			Slug:   slug,
			Status: HealthUnknown,
			Detail: map[string]any{"reason": neverDeployedReason},
		}
	}

	// .env нет — то же самое, только выкат успел начаться.
	//
	// Каталог создаётся первым действием применения, а .env пишется последним:
	// после клонирования репозитория и проверки описания стека. Значит «каталог
	// есть, .env нет» однозначно означает прерванный выкат, а не поломку.
	//
	// Без этой проверки docker отвечал «couldn't find env file: /opt/.../.env»,
	// и человек видел на экране приложения упоминание внутреннего файла агента
	// вместо настоящей причины — та лежала в журнале выката строкой выше.
	envPath := filepath.Join(dir, ".env")
	if _, err := os.Stat(envPath); err != nil {
		return AppHealth{
			Slug:   slug,
			Status: HealthUnknown,
			Detail: map[string]any{"reason": neverDeployedReason},
		}
	}

	// Опрашиваем ТОТ ЖЕ каталог, из которого стек поднят.
	//
	// Раньше здесь для приложения из репозитория подставлялась рабочая копия —
	// от времён, когда git-приложения поднимались из неё. Сейчас applyOne
	// запускает compose из служебного каталога (apply.go: runDir := dir) и
	// кладёт туда ПОДГОТОВЛЕННОЕ описание с `name: <slug>`. Опрос из рабочей
	// копии смотрел в проект автора: у репозитория со своим `name:` контейнеров
	// такого проекта на хосте нет, ps возвращал пусто, все сервисы дописывались
	// как missing — и здоровый стек рапортовался как down сразу после зелёного
	// выката.
	psDir := dir

	// --all обязателен. Без него `compose ps` показывает ТОЛЬКО запущенные
	// контейнеры: остановленный сервис не становится нездоровым, он исчезает
	// из отчёта, и стек с двумя лежащими сервисами из десяти отчитывается как
	// полностью здоровый. Проверено на боевом стенде: `docker stop` двух
	// контейнеров Supabase оставил приложение в состоянии healthy.
	raw, err := dockerComposeEnv(ctx, psDir, envPath,
		"ps", "--all", "--format", "{{.Service}}\t{{.State}}\t{{.Health}}\t{{.ExitCode}}")
	if err != nil {
		return AppHealth{
			Slug:   slug,
			Status: HealthUnknown,
			// Вывод уходит на сервер и виден любому участнику проекта — значения
			// переменных приложения из него вычищаем.
			Detail: map[string]any{"error": redactSecrets(tail(raw, 300), app.redactionValues())},
		}
	}

	states := parseContainerStates(raw)

	// Кто из сервисов объявлен завершающимся — читаем из того же описания, из
	// которого стек поднят. Без этого приложение с миграциями числилось бы
	// degraded вечно: контейнер отработал и вышел, а проверка ждала running.
	for name := range composeCompletedServices(ctx, psDir, envPath) {
		for i := range states {
			if states[i].Service == name {
				states[i].Completed = true
			}
		}
	}

	// Контейнера может не быть вовсе — его удалили (`docker rm`), и тогда он
	// не появится даже с --all. Такой сервис обязан считаться упавшим, иначе
	// «удалить контейнер» остаётся способом сделать приложение здоровым.
	states = withMissingServices(ctx, psDir, envPath, states)

	status := summarize(states)
	detail := describe(states)

	// HTTP-проба — только когда контейнеры формально живы: у лежащего стека
	// причина и так видна по их состоянию, а проба лишь дублировала бы отказ.
	if status == HealthHealthy || status == HealthDegraded {
		probe := ProbeApp(ctx, app)
		detail["probe"] = probe.asDetail()

		// Проба строже статусов docker: контейнер может быть running, а
		// приложение — отвечать 502 или не отвечать вовсе. Живой по docker,
		// но не отвечающий стек — это degraded, не healthy. Пропущенная
		// проба (нет порта, контейнер не нашёлся) статус не трогает:
		// отсутствие данных — не отказ.
		if status == HealthHealthy && !probe.OK && probe.Skipped == "" {
			status = HealthDegraded
		}
	}

	return AppHealth{
		Slug:   slug,
		Status: status,
		Detail: detail,
	}
}

func parseContainerStates(raw string) []containerState {
	var states []containerState
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		cs := containerState{Service: fields[0], State: fields[1]}
		if len(fields) > 2 {
			cs.Health = strings.TrimSpace(fields[2])
		}
		if len(fields) > 3 {
			cs.ExitCode = strings.TrimSpace(fields[3])
		}
		states = append(states, cs)
	}
	return states
}

// containerAlive решает, считается ли отдельный контейнер живым.
//
// Тонкость с healthcheck: контейнер без него оценивается только по состоянию,
// и `running` для такого — максимум, что мы знаем. Контейнер с healthcheck в
// состоянии `starting` живым ещё не считается: у стека есть время на запуск,
// но объявлять его здоровым авансом нельзя.
func containerAlive(cs containerState) bool {
	if cs.State != "running" {
		// Отработавшие миграции — не отказ. Признак ставится по описанию стека
		// (depends_on с условием service_completed_successfully), а не по факту
		// выхода: иначе любой упавший с нулём контейнер считался бы здоровым.
		//
		// Состояние ровно `exited` обязательно. У контейнера в состоянии
		// `created` (создан, стартовать не смог) и у `paused` docker отдаёт
		// код выхода 0 — то есть сервис, который не запускался ВООБЩЕ, был бы
		// неотличим от отработавшего, и приложение поднялось бы на
		// неподготовленной базе, отчитавшись здоровым.
		return cs.Completed && cs.State == "exited" && cs.ExitCode == "0"
	}
	switch cs.Health {
	case "", "healthy":
		return true
	default:
		// unhealthy, starting и всё прочее — не живой.
		return false
	}
}

func summarize(states []containerState) HealthStatus {
	if len(states) == 0 {
		// Стек описан, но контейнеров нет вовсе — это остановлено или снесено.
		return HealthDown
	}

	alive := 0
	for _, cs := range states {
		if containerAlive(cs) {
			alive++
		}
	}

	switch {
	case alive == len(states):
		return HealthHealthy
	case alive == 0:
		return HealthDown
	default:
		return HealthDegraded
	}
}

func describe(states []containerState) map[string]any {
	containers := make([]map[string]string, 0, len(states))
	for _, cs := range states {
		health := cs.Health
		if health == "" {
			health = "без проверки"
		}
		entry := map[string]string{
			"service": cs.Service,
			"state":   cs.State,
			"health":  health,
		}
		// Готовый ответ «жив ли сервис» — вместо того чтобы платформа выводила
		// его заново из state и health.
		//
		// Выводила она его неверно дважды: сервис БЕЗ healthcheck попадал в
		// список «не работают» (в поле health у него подпись «без проверки», а
		// фильтр требовал 'healthy' или пустоту), и туда же попадала
		// отработавшая миграция. То есть тревога перечисляла половину здорового
		// стека. Правило «жив» живёт в одном месте — containerAlive.
		if containerAlive(cs) {
			entry["alive"] = "true"
		}
		if cs.Completed && cs.State == "exited" && cs.ExitCode == "0" {
			entry["completed"] = "true"
		}
		if cs.ExitCode != "" {
			entry["exit_code"] = cs.ExitCode
		}
		containers = append(containers, entry)
	}
	return map[string]any{
		"containers": containers,
		"total":      len(states),
	}
}

// withMissingServices дополняет список сервисами, которых в выводе нет вовсе.
//
// Список ожидаемых берётся из самого описания стека: `compose config
// --services`. Если сервис объявлен, а контейнера нет ни живого, ни
// остановленного — это отказ, а не отсутствие данных.
//
// Ошибка чтения конфигурации не должна ронять проверку здоровья: тогда
// возвращаем то, что есть. Здоровье — наблюдение, а не гарантия.
func withMissingServices(ctx context.Context, dir, envFile string, states []containerState) []containerState {
	raw, err := dockerComposeEnv(ctx, dir, envFile, "config", "--services")
	if err != nil {
		return states
	}

	seen := make(map[string]bool, len(states))
	for _, cs := range states {
		seen[cs.Service] = true
	}

	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || seen[name] {
			continue
		}
		states = append(states, containerState{Service: name, State: "missing"})
	}
	return states
}
