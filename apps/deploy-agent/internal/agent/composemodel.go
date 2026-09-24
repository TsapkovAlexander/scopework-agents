package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"tracedocs.ru/deploy-agent/pkg/composeguard"
)

// Нормализованная модель чужого стека и её правка под платформу.
//
// ЗАЧЕМ. Приложение из репозитория должно подниматься как есть. Раньше оно
// обязано было знать о платформе четыре вещи, ни одна из которых нигде не
// написана: входной сервис называется `app`, он подключён к сети
// `tracedocs-edge`, в файле стоит `name: ${APP_SLUG}`, а `ports` запрещены.
// Несовпадение давало зелёный выкат и молчащий домен.
//
// Всё это платформа теперь берёт на себя, а нужное вычитывает из самого файла.
//
// ПОЧЕМУ МОДЕЛЬ, А НЕ ОВЕРЛЕЙ. Первым вариантом был второй `-f` с правками.
// Он отпал на проверке: если сервис своих сетей не объявлял, оверлей с
// `networks: [edge]` ЗАБИРАЕТ у него `default` — стек поднимается, а web
// перестаёт видеть api. Отличить «автор объявил сети» от «compose подставил
// default» по нормализованному виду невозможно, а по сырому YAML — ненадёжно
// (якоря, `extends`, `x-`-фрагменты).
//
// Поэтому правится сама модель, которую строит compose: там сети уже явные, и
// добавление никогда ничего не отнимает.
//
// ПОЧЕМУ `--no-interpolate`. Нормализация со значениями переменных превратила
// бы файл стека в копию секретов на диске. Без неё `${...}` доезжают до `up`
// нетронутыми и раскрываются из .env платформы — как и раньше.
//
// ПОЧЕМУ JSON. У агента нет и не будет зависимостей, а YAML в стандартной
// библиотеке отсутствует. Писать YAML руками для произвольной модели — способ
// однажды сломать чужой стек кавычкой. JSON — надмножество которого YAML и
// является, и `docker compose -f файл.json` его принимает (проверено).

// composeConfigJSON снимает нормализованную модель стека с рабочей копии.
func composeConfigJSON(ctx context.Context, dir, envFile string) ([]byte, error) {
	// stdout БЕЗ stderr.
	//
	// ЭТО И БЫЛО ПРИЧИНОЙ ОТКАЗА «модель стека не читается: invalid character
	// 'i' in literal true». Docker Compose печатает предупреждения в stderr, и
	// самое частое из них — про устаревший ключ `version:`, который стоит в
	// подавляющем большинстве публичных репозиториев. Строка выглядит как
	// `time="..." level=warning msg="..."`, и склеенный вывод начинался с
	// `time=`: разбор JSON спотыкался на втором символе. По такому тексту
	// невозможно догадаться ни о причине, ни даже о том, что дело не в стеке
	// клиента, — а выкат при этом не проходил вовсе.
	out, err := dockerComposeParsed(ctx, dir, envFile,
		"config", "--no-interpolate", "--format", "json")
	if err != nil {
		// Здесь же ловятся ключи вне схемы compose — их пишут чужие панели
		// (`exclude_from_hc` у Coolify). Такой файл compose отвергает целиком,
		// и лучше узнать об этом сейчас, с именем сервиса и ключа в тексте,
		// чем на `up` после остановки прежнего стека.
		return nil, fmt.Errorf("описание стека не разбирается docker compose: %w: %s", err, tail(out, 400))
	}
	return []byte(out), nil
}

func parseComposeModel(raw []byte) (map[string]any, error) {
	var model map[string]any
	if err := json.Unmarshal(raw, &model); err != nil {
		return nil, fmt.Errorf("модель стека не читается: %w", err)
	}
	if _, ok := model["services"].(map[string]any); !ok {
		return nil, fmt.Errorf("в описании стека нет ни одного сервиса")
	}
	return model, nil
}

// parseCompletedServices — сервисы, которым ПОЛОЖЕНО завершиться.
//
// Миграции, инициализация бакетов, seed — обычная часть стека: сервис
// отрабатывает, выходит с кодом 0, а тот, кто от него зависит, объявляет это
// через `depends_on: {condition: service_completed_successfully}`. `docker
// compose up --wait` такой стек принимает штатно.
//
// Наша же проверка устойчивости видела `exited` и роняла выкат — навсегда:
// релиз уходил в failed, через десять минут повторялся и падал ровно так же.
// Приложение с миграциями развернуть было нельзя в принципе.
//
// Признаком считается ТОЛЬКО явное объявление в depends_on. Политика перезапуска
// (`restart: no`) слишком слаба: её ставят и обычным сервисам, а тогда упавший
// контейнер молча считался бы здоровым.
func parseCompletedServices(raw []byte) map[string]bool {
	completed := map[string]bool{}

	model, err := parseComposeModel(raw)
	if err != nil {
		return completed
	}
	services, _ := model["services"].(map[string]any)
	for _, value := range services {
		service, ok := value.(map[string]any)
		if !ok {
			continue
		}
		// Нормализованная модель приводит depends_on к объекту:
		// {"migrate": {"condition": "service_completed_successfully"}}.
		deps, ok := service["depends_on"].(map[string]any)
		if !ok {
			continue
		}
		for name, raw := range deps {
			dep, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if condition, _ := dep["condition"].(string); condition == "service_completed_successfully" {
				completed[name] = true
			}
		}
	}

	return completed
}

// composeCompletedServices снимает тот же список с живого каталога.
//
// Ошибка чтения не должна ронять ни выкат, ни проверку здоровья: пустой список
// означает прежнее поведение, при котором завершившийся сервис считается
// отказом. Ужесточение при сбое безопаснее послабления.
func composeCompletedServices(ctx context.Context, dir, envFile string) map[string]bool {
	raw, err := composeConfigJSON(ctx, dir, envFile)
	if err != nil {
		return map[string]bool{}
	}
	return parseCompletedServices(raw)
}

// publishCandidate — сервис, который по своему описанию хочет наружу.
type publishCandidate struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
}

// portTarget — целевой порт записи `ports` и признак привязки к петле.
//
// Две формы, обе встречаются в реальных файлах. Длинную собирает сам compose;
// строкой запись остаётся, когда в ней переменная — при `--no-interpolate`
// разворачивать её некому:
//
//	${MINIO_API_PORT:-9000}:9000
//	127.0.0.1:${KONG_HTTPS_PORT}:8443/tcp
//
// Привязка к петле — это НЕ публикация, а обслуживание: так в корпусе
// объявлены pgadmin и grafana. Приняв её за намерение выйти наружу, платформа
// вывесила бы панель базы в интернет.
func portTarget(entry any) (port int, loopback bool, ok bool) {
	switch v := entry.(type) {
	case map[string]any:
		target, has := v["target"]
		if !has {
			return 0, false, false
		}
		port = int(toFloat(target))
		if port <= 0 || port > 65535 {
			return 0, false, false
		}
		host, _ := v["host_ip"].(string)
		return port, isLoopbackHost(host), true

	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, false, false
		}
		// Протокол отбрасываем: он не влияет ни на цель, ни на намерение.
		if slash := strings.LastIndex(text, "/"); slash >= 0 {
			text = text[:slash]
		}
		parts := strings.Split(text, ":")
		last := parts[len(parts)-1]
		// Диапазон (`9000-9010:9000-9010`) публикацией одного сервиса не
		// является: цель неоднозначна, а угадывать нельзя.
		if strings.Contains(last, "-") {
			return 0, false, false
		}
		port, err := strconv.Atoi(last)
		if err != nil || port <= 0 || port > 65535 {
			return 0, false, false
		}
		// Адрес привязки есть только в трёхчастной форме.
		if len(parts) >= 3 {
			return port, isLoopbackHost(parts[0]), true
		}
		return port, false, true
	}
	return 0, false, false
}

func isLoopbackHost(host string) bool {
	switch strings.TrimSpace(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(host), "127.")
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case string:
		f, err := strconv.ParseFloat(n, 64)
		if err != nil {
			return 0
		}
		return f
	}
	return 0
}

// injectAddons добавляет сервисы аддонов в чужую модель стека.
//
// СТОЛКНОВЕНИЕ ИМЁН — ОТКАЗ, А НЕ ПЕРЕЗАПИСЬ. Сервис с именем `db` в
// репозитории клиента — не редкость, и молча подменить его нашей базой значит
// подменить данные: приложение продолжит ходить по тому же имени и попадёт в
// чужую базу с чужой схемой. Отказ называет имя и предлагает выход.
func injectAddons(model map[string]any, addons []AddonSpec, published map[string]bool) ([]string, error) {
	services, _ := model["services"].(map[string]any)
	if services == nil {
		return nil, fmt.Errorf("в описании стека нет ни одного сервиса")
	}

	var notes []string
	var needVolumes []string

	for _, a := range addons {
		if _, taken := services[a.Service]; taken {
			return nil, fmt.Errorf(
				"в описании стека уже есть сервис %q, а платформа поднимает под этим именем %s. "+
					"Переименуйте свой сервис либо снимите галку — базу тогда ведёте вы",
				a.Service, a.Kind)
		}

		svc, volume, err := addonServiceModel(a)
		if err != nil {
			return nil, err
		}
		services[a.Service] = svc
		if volume != "" {
			needVolumes = append(needVolumes, volume)
		}
		notes = append(notes, fmt.Sprintf(
			"%s: добавлен сервис %s — платформа ведёт его сама", a.Service, a.Kind))
	}

	// ОПУБЛИКОВАННЫЕ СЕРВИСЫ ЖДУТ ГОТОВНОСТИ АДДОНА.
	//
	// Та же гонка, что была в синтетическом стеке: без связи compose поднимает
	// приложение и базу разом, и миграции на старте бьют в postgres, который
	// ещё не принимает соединения. Ставим `service_healthy` — у аддонов есть
	// проверка здоровья, и ждать надо именно её.
	//
	// АВТОРСКОЕ `depends_on` НЕ ТРОГАЕМ, а дополняем: там могут быть свои
	// зависимости между сервисами клиента, и заменить их своей значило бы
	// сломать порядок, который автор задумал.
	for _, name := range sortedKeys(published) {
		svc, ok := services[name].(map[string]any)
		if !ok {
			continue
		}
		deps, _ := svc["depends_on"].(map[string]any)
		if deps == nil {
			deps = map[string]any{}
			// Список вместо словаря compose нормализует сам, но чужая модель
			// может прийти и такой.
			if list, isList := svc["depends_on"].([]any); isList {
				for _, d := range list {
					if s, ok := d.(string); ok {
						deps[s] = map[string]any{"condition": "service_started"}
					}
				}
			}
		}
		for _, a := range addons {
			if _, already := deps[a.Service]; already {
				continue
			}
			deps[a.Service] = map[string]any{"condition": "service_healthy"}
		}
		svc["depends_on"] = deps
	}

	// Том аддона объявляется наравне с авторскими: имя ему даст наш проект, и
	// между выкатами данные находятся по нему же.
	if len(needVolumes) > 0 {
		vols, _ := model["volumes"].(map[string]any)
		if vols == nil {
			vols = map[string]any{}
		}
		for _, name := range needVolumes {
			if _, taken := vols[name]; taken {
				return nil, fmt.Errorf(
					"в описании стека уже объявлен том %q, а платформа заводит его под тем же именем. "+
						"Переименуйте свой том либо снимите галку", name)
			}
			vols[name] = map[string]any{}
		}
		model["volumes"] = vols
	}

	return notes, nil
}

// sortedKeys — имена по алфавиту: отказ не должен зависеть от порядка обхода
// карты, иначе один и тот же стек жалуется то на один сервис, то на другой.
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// serviceStartBlock — почему сервис НЕ поднимется обычным `docker compose up`.
// Пустая строка — поднимется.
//
// ЗАЧЕМ ЭТО ВООБЩЕ ЕСТЬ. 10.09.2026 на боевом приложении клиента домен вёл в
// сервис `web`, объявленный `profiles: ["full"]`. Обычный `up` профильные
// сервисы не поднимает, поэтому стек встал без него — и агент сообщил
// «контейнера afftor-pro-web-1 на сервере нет». Сообщение верное и совершенно
// непонятное: человек искал ошибку в имени сервиса, а имя было правильным.
//
// Хуже того, `web` предложила сама платформа: кандидатов на публикацию она
// выбирала по одному лишь наличию `ports` и не знала, что запускать этот сервис
// не собирается. Обещание, которое нечем исполнить, — и пять минут сборки до
// того, как это выяснится.
//
// ЗДЕСЬ ТРИ ПРИЧИНЫ, А НЕ ОДНА. Профиль — та, на которой обожглись; `scale: 0`
// и `deploy.replicas: 0` дают ровно тот же исход и разрешены гейтом наравне с
// профилем. Ловить только известный случай значило бы ждать двух следующих.
func serviceStartBlock(svc map[string]any) string {
	if profiles, ok := svc["profiles"].([]any); ok && len(profiles) > 0 {
		names := make([]string, 0, len(profiles))
		for _, raw := range profiles {
			if s, ok := raw.(string); ok && s != "" {
				names = append(names, s)
			}
		}
		if len(names) > 0 {
			return fmt.Sprintf("объявлен под профилем %s — обычный запуск профильные сервисы не поднимает",
				strings.Join(names, ", "))
		}
	}

	if scale, ok := numeric(svc["scale"]); ok && scale == 0 {
		return "объявлен со `scale: 0` — ни одного контейнера не создаётся"
	}

	if deploy, ok := svc["deploy"].(map[string]any); ok {
		if replicas, ok := numeric(deploy["replicas"]); ok && replicas == 0 {
			return "объявлен с `deploy.replicas: 0` — ни одного контейнера не создаётся"
		}
	}

	return ""
}

// numeric — число из модели compose. JSON отдаёт их float64, но чужая модель
// может прийти и строкой: `scale: "0"` compose принимает.
func numeric(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return n, err == nil
	}
	return 0, false
}

// publishCandidates — сервисы, объявившие публикацию, по порядку имён.
//
// Опора — только `ports`. `expose` кандидатом не делает: его объявляют и
// postgres с redis, и намерения выйти наружу он не несёт.
func publishCandidates(model map[string]any) []publishCandidate {
	services, _ := model["services"].(map[string]any)
	var out []publishCandidate

	for name, raw := range services {
		svc, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// Сервис, который платформа не запустит, кандидатом не бывает: домен
		// вёл бы в контейнер, которого не будет никогда.
		if serviceStartBlock(svc) != "" {
			continue
		}

		ports, _ := svc["ports"].([]any)
		for _, entry := range ports {
			port, loopback, ok := portTarget(entry)
			if !ok || loopback {
				continue
			}
			out = append(out, publishCandidate{Service: name, Port: port})
			break
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out
}

// prepareDeployModel приводит модель к тому, что платформа готова поднять.
//
// Возвращает строки для журнала выката: файл клиента мы правим, и человек
// обязан видеть, что именно с ним сделали. Молча изменённый чужой стек — это
// не помощь, а источник разбирательств вида «у меня в репозитории не так».
func prepareDeployModel(model map[string]any, project string, published map[string]bool) []string {
	var notes []string
	services, _ := model["services"].(map[string]any)
	// Прежнее имя проекта нужно ДО правки: по нему отличается имя сети,
	// которое собрал compose, от того, что автор задал сам.
	prev, _ := model["name"].(string)

	names := make([]string, 0, len(services))
	for name := range services {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		svc, ok := services[name].(map[string]any)
		if !ok {
			continue
		}

		// Публикация на хост снимается у всех без исключения. Наружу на этой
		// машине слушает только прокси платформы: иначе обходятся TLS,
		// доменные политики и учёт трафика.
		if ports, has := svc["ports"].([]any); has && len(ports) > 0 {
			var shown []string
			for _, entry := range ports {
				if port, _, ok := portTarget(entry); ok {
					shown = append(shown, strconv.Itoa(port))
				}
			}
			delete(svc, "ports")
			notes = append(notes, fmt.Sprintf(
				"%s: снята публикация портов на хост (%s) — наружу приложение выходит через прокси платформы",
				name, strings.Join(shown, ", ")))
		} else {
			delete(svc, "ports")
		}

		// Имя контейнера задаём мы. С авторским именем контейнер называется
		// не `<проект>-<сервис>-N`, и прокси не находит его никогда — при
		// зелёном выкате. Ссылки внутри стека это не рвёт: сервисы адресуют
		// друг друга по имени сервиса.
		if _, has := svc["container_name"]; has {
			delete(svc, "container_name")
			notes = append(notes, fmt.Sprintf(
				"%s: снято container_name — имя контейнера задаёт платформа", name))
		}

		if !published[name] {
			continue
		}

		nets, ok := svc["networks"].(map[string]any)
		if !ok {
			// Список вместо словаря compose нормализует сам, но чужая модель
			// может прийти и такой — тогда собираем словарь из неё.
			nets = map[string]any{}
			if list, isList := svc["networks"].([]any); isList {
				for _, n := range list {
					if s, ok := n.(string); ok {
						nets[s] = nil
					}
				}
			}
		}
		nets[edgeNetworkKey] = nil
		svc["networks"] = nets
		notes = append(notes, fmt.Sprintf(
			"%s: подключён к сети прокси %s — по нему публикуется домен", name, EdgeNetwork))
	}

	// Верхнеуровневое объявление внешней сети: без него compose откажется
	// стартовать, сославшись на неизвестную сеть.
	nets, _ := model["networks"].(map[string]any)
	if nets == nil {
		nets = map[string]any{}
	}

	// Имена собственных сетей материализованы под ПРЕЖНИМ именем проекта:
	// `config` подставляет `<проект>_<ключ>`, и смена имени проекта их уже не
	// трогает. Оставить как есть — значит отдать двум приложениям, чьи
	// репозитории объявили одинаковое имя, одну сеть на двоих: контейнеры
	// разных клиентов увидели бы друг друга.
	//
	// Убираем ТОЛЬКО собранное самим compose — оно узнаётся по виду
	// `<проект>_<ключ>`. Имя, которое автор задал явно, оставляем: он имел в
	// виду именно его. Внешние сети не трогаем вовсе — там имя и есть точка
	// подключения.
	for key, raw := range nets {
		def, ok := raw.(map[string]any)
		if !ok || def["external"] == true {
			continue
		}
		if name, _ := def["name"].(string); name == prev+"_"+key {
			delete(def, "name")
			nets[key] = def
		}
	}
	nets[edgeNetworkKey] = map[string]any{"external": true, "name": EdgeNetwork}
	model["networks"] = nets

	// Имя проекта задаём ЗДЕСЬ, в самом файле, а не флагом -p.
	//
	// Разница существеннее, чем кажется. Флаг пришлось бы передавать во всех
	// двенадцати местах, где агент зовёт compose: подъём, ожидание, сборка,
	// список образов, снятие стека, резервная копия, guard. Пропущенное место
	// означало бы, что часть команд работает с одним проектом, а часть — с
	// другим: два комплекта контейнеров на одних томах, ровно та беда, от
	// которой защищались в перехвате.
	//
	// Имя в файле такой ошибки не допускает по построению: все команды читают
	// один и тот же файл и не могут разойтись.
	// Имена томов — та же история, что у сетей, но цена ошибки выше.
	//
	// `config` материализует их как `<проект>_<ключ>`, и при чужом имени
	// проекта в файле тома оказываются ВНЕ пространства имён приложения. Это
	// не косметика: под таким именем стек подключился бы к данным соседа, и
	// compose-guard такой стек отклоняет — правильно делает.
	//
	// Поэтому собранное самим compose имя снимаем: том получит имя от нашего
	// проекта. Заданное автором явно оставляем — там он имел в виду именно то,
	// что написал, и отказ guard'а будет по делу.
	//
	// ЦЕНА. Данные, лежащие под прежним именем, к новому тому не переедут:
	// стек поднимется на пустом. Старые тома при этом никуда не деваются —
	// они остаются на диске, и перенести содержимое можно вручную. Молчать об
	// этом нельзя, поэтому строка в журнал выката.
	if vols, ok := model["volumes"].(map[string]any); ok {
		var renamed []string
		for key, raw := range vols {
			def, isMap := raw.(map[string]any)
			if !isMap || def["external"] == true {
				continue
			}
			if name, _ := def["name"].(string); prev != "" && name == prev+"_"+key {
				delete(def, "name")
				vols[key] = def
				renamed = append(renamed, key)
			}
		}
		sort.Strings(renamed)
		if len(renamed) > 0 {
			notes = append(notes, fmt.Sprintf(
				"тома %s переходят в пространство имён приложения (были с префиксом %q) — "+
					"данные под прежними именами остаются на диске и автоматически не переносятся",
				strings.Join(renamed, ", "), prev))
		}
	}

	if prev != "" && prev != project {
		notes = append(notes, fmt.Sprintf(
			"имя проекта %q заменено на %q — под ним платформа находит контейнеры стека", prev, project))
	}
	model["name"] = project

	return notes
}

// edgeNetworkKey — под каким ключом сеть прокси попадает в модель.
//
// Отдельно от EdgeNetwork: ключ живёт в пространстве имён файла, а `name`
// внутри — настоящее имя сети на хосте. Совпадение имён здесь случайно и
// полагаться на него нельзя.
const edgeNetworkKey = "tracedocs-edge"

// prepareRepoCompose — готовое описание стека из репозитория и объяснение
// сделанных правок для журнала выката.
//
// Порядок здесь существенный: кандидаты снимаются ДО правки, потому что она
// удаляет `ports` — то самое объявление, из которого они и берутся.
// preparedCompose — готовое описание стека и всё, что о нём стоит рассказать.
type preparedCompose struct {
	// File — описание, которое агент положит рядом и поднимет.
	File []byte
	// Notes — что именно исправлено в файле автора, для журнала выката.
	Notes []string
	// PreviousProject — имя проекта, под которым стек работал до нас.
	PreviousProject string
	// Candidates — сервисы, объявившие порты. Уезжают платформе: без них
	// человек не знает, из каких имён выбирать домены.
	Candidates []publishCandidate
}

func prepareRepoCompose(
	ctx context.Context,
	p Paths,
	app DesiredApp,
	envPath string,
) (preparedCompose, error) {
	var out preparedCompose

	// Из папки приложения (0284): относительные пути описания стека автор писал
	// относительно него, и разбор из корня монорепо дал бы контексты сборки,
	// указывающие мимо.
	dir, err := repoAppDir(p, app)
	if err != nil {
		return out, err
	}

	// Ссылки на файлы — по тексту репозитория и по модели без чтения env_file
	// (verifyStackFileRefs), обе ДО разбора: разбор ниже
	// исполняет env_file, include и extends, и готовая модель, лёгшая в
	// служебный каталог, несла бы содержимое чужого .env уже как environment —
	// проверять там было бы нечего. Корень — вся рабочая копия, как у guard:
	// монорепо собирается из корня. Свой .env синтетического описания —
	// абсолютный путь, который пишет сам агент (writeSyntheticCompose).
	sf := composeguard.StackFiles{Root: p.repoDir(app.Slug), ProjectDir: dir}
	if app.needsSyntheticCompose() {
		sf.AllowedAbs = []string{filepath.Join(p.appDir(app.Slug), ".env")}
	}
	if err := verifyStackFileRefs(ctx, sf, composeTarget{ProjectDir: dir, EnvFile: envPath}); err != nil {
		return out, err
	}

	raw, err := composeConfigJSON(ctx, dir, envPath)
	if err != nil {
		return out, err
	}
	model, err := parseComposeModel(raw)
	if err != nil {
		return out, err
	}

	candidates := publishCandidates(model)
	prev := previousProject(model, app.Slug)

	published := map[string]bool{}
	for _, r := range effectiveRoutes(app) {
		if r.Service != "" {
			published[r.Service] = true
		}
	}

	notes := prepareDeployModel(model, app.Slug, published)

	// Что автор объявил портами — говорим вслух.
	//
	// Пока маршруты назначает человек, это единственный способ узнать имена
	// сервисов, не читая исходники платформы. Именно их незнание давало
	// зелёный выкат при мёртвом домене.
	if len(candidates) > 0 {
		var shown []string
		for _, c := range candidates {
			shown = append(shown, fmt.Sprintf("%s:%d", c.Service, c.Port))
		}
		notes = append(notes, fmt.Sprintf(
			"наружу по описанию стека смотрят: %s", strings.Join(shown, ", ")))
	}

	// Маршрут есть, а сервиса с таким именем в стеке нет — скажем сразу, не
	// дожидаясь проверки после подъёма: здесь у нас на руках список имён.
	services, _ := model["services"].(map[string]any)
	for service := range published {
		if _, ok := services[service]; !ok {
			notes = append(notes, fmt.Sprintf(
				"домен назначен сервису %q, которого в описании стека нет", service))
		}
	}

	// АДДОНЫ ВЖИВЛЯЮТСЯ В ЧУЖОЙ СТЕК (0186 + 10.09.2026).
	//
	// До этого база рядом полагалась только синтетическим сборкам — по
	// Dockerfile и статике, — а репозиторию со своим compose предлагалось
	// дописать сервис самому. Довод был «чужой файл правим минимально», и он
	// перестал быть верным ровно тогда, когда мы уже правим в нём порты, имя
	// контейнера, сети, имя проекта и имена томов. Отказ выглядел принципом, а
	// был инерцией: человек с готовым compose из двух строк оказывался обязан
	// вести базу руками, хотя платформа умеет её вести.
	//
	// ВЖИВЛЯЕМ ПОСЛЕ ВСЕХ ПРАВОК АВТОРСКИХ СЕРВИСОВ. Иначе аддон попал бы под
	// снятие портов и подключение к сети прокси — а ему ни то, ни другое не
	// нужно: он и не публикуется, и наружу не смотрит.
	if len(app.Addons) > 0 {
		addonNotes, err := injectAddons(model, app.Addons, published)
		if err != nil {
			return out, err
		}
		notes = append(notes, addonNotes...)
	}

	// СЕРВИС ЕСТЬ, НО ПОДНЯТ НЕ БУДЕТ — это ОТКАЗ, а не заметка.
	//
	// Домен, назначенный такому сервису, не заработает ни при каких условиях:
	// контейнера не появится. Продолжать значит собрать образ, поднять стек,
	// подождать здоровья и упасть на проверке маршрута сообщением про
	// несуществующий контейнер — пять минут ради ответа, который известен
	// прямо сейчас. Отказ здесь и называет причину, и экономит их.
	//
	// Отказ, а не молчаливое снятие профиля: `container_name` платформа снимает
	// потому, что он меняет ИМЯ контейнера, а профиль меняет СОСТАВ стека.
	// Запустить то, что автор намеренно исключил из обычного запуска, — не наше
	// решение.
	for _, service := range sortedKeys(published) {
		svc, ok := services[service].(map[string]any)
		if !ok {
			continue
		}
		if block := serviceStartBlock(svc); block != "" {
			return out, fmt.Errorf(
				"домен назначен сервису %q, но он %s. "+
					"Уберите это объявление у сервиса либо опубликуйте другой",
				service, block)
		}
	}

	file, err := renderDeployFile(model)
	if err != nil {
		return out, err
	}

	out.File = file
	out.Notes = notes
	out.PreviousProject = prev
	out.Candidates = candidates
	return out, nil
}

func renderDeployFile(model map[string]any) ([]byte, error) {
	raw, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("не удалось собрать описание стека: %w", err)
	}
	return raw, nil
}

// previousProject — имя проекта, под которым стек работал до нас.
//
// Возвращается отдельно от заметок, потому что по нему выполняется действие:
// стек под прежним именем нужно погасить, иначе на хосте окажутся два
// комплекта контейнеров на одних томах. Пустая строка — гасить нечего.
func previousProject(model map[string]any, project string) string {
	prev, _ := model["name"].(string)
	if prev == "" || prev == project {
		return ""
	}
	return prev
}

// projectBelongsToRepo — принадлежит ли проект с этим именем нашей рабочей копии.
//
// Проверка обязательна: имя проекта — это глобальное пространство имён хоста, и
// совпадение с чужим стеком вполне возможно. Погасив его, платформа остановила
// бы приложение, которого не разворачивала.
//
// Признак — рабочий каталог, объявленный самим docker: он указывает на копию
// репозитория, которую агент клонировал сам.
//
// Сравнение с ВЛОЖЕНИЕМ, а не точным равенством: с папкой приложения (0284)
// compose поднимается из подкаталога рабочей копии, и стек, поднятый до
// переезда на неё, имел бы рабочим каталогом корень копии. Точное сравнение
// перестало бы узнавать собственный стек ровно в момент смены папки — и
// платформа подняла бы второй комплект контейнеров рядом с работающим.
func projectBelongsToRepo(containers []dockerContainer, project, repoDir string) bool {
	if project == "" || repoDir == "" {
		return false
	}
	for _, c := range containers {
		if c.Config.Labels["com.docker.compose.project"] != project {
			continue
		}
		if dirWithin(c.Config.Labels["com.docker.compose.project.working_dir"], repoDir) {
			return true
		}
	}
	return false
}

// dirWithin — путь совпадает с корнем или лежит внутри него.
//
// Отдельной функцией, потому что «внутри» нельзя проверять голым HasPrefix:
// `/repos/web2` начинается с `/repos/web`, и без разделителя соседнее
// приложение считалось бы частью чужой рабочей копии — а по этому признаку
// стеки ГАСЯТ.
func dirWithin(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	clean := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	return clean == cleanRoot || strings.HasPrefix(clean, cleanRoot+string(filepath.Separator))
}

// shutdownPreviousProject гасит стек, работавший под прежним именем проекта.
//
// Молча оставить его нельзя: имя проекта у нас теперь своё, compose увидит
// другой проект и поднимет ВТОРОЙ комплект контейнеров рядом. Два постмастера
// на одном каталоге данных — не конфликт, а порча.
//
// dir — откуда запускается команда (папка приложения), root — рабочая копия
// целиком. Разведены намеренно: принадлежность проверяется по ВСЕЙ копии,
// иначе стек, поднятый до переезда приложения в подпапку, не признавался бы
// своим и остался бы работать вторым комплектом.
func shutdownPreviousProject(ctx context.Context, prev, dir, root string) (bool, error) {
	if prev == "" {
		return false, nil
	}
	containers, err := inspectComposeContainers(ctx)
	if err != nil {
		return false, err
	}
	if !projectBelongsToRepo(containers, prev, root) {
		// Совпадение имён с чужим стеком — не повод его трогать.
		return false, nil
	}
	if out, err := dockerCompose(ctx, dir, "-p", prev, "down", "--remove-orphans"); err != nil {
		return false, fmt.Errorf("не удалось снять стек под прежним именем %q: %w: %s",
			prev, err, tail(out, 300))
	}
	return true, nil
}

// projectsInDir — имена compose-проектов, поднятых из этого каталога.
//
// Нужны при снятии: приложение могло работать под именем, объявленным в самом
// репозитории, а не под нашим. Отличать одно от другого по догадкам нельзя —
// спрашиваем docker.
// Каталог трактуется как корень: стек приложения с папкой внутри репозитория
// (0284) поднят из подкаталога рабочей копии, и снятие обязано найти его тоже —
// иначе удалённое приложение осталось бы работать на хосте.
func projectsInDir(containers []dockerContainer, dir string) []string {
	if dir == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range containers {
		if !dirWithin(c.Config.Labels["com.docker.compose.project.working_dir"], dir) {
			continue
		}
		name := c.Config.Labels["com.docker.compose.project"]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// tearDownProjects — какие проекты снимать у приложения со слагом slug.
//
// Всегда сам слаг: под ним стек поднимает платформа. Плюс всё, что было
// поднято из рабочей копии под другим именем, — наследство того времени, когда
// имя проекта брали из файла репозитория.
func tearDownProjects(containers []dockerContainer, slug, repoDir string) []string {
	out := []string{slug}
	for _, name := range projectsInDir(containers, repoDir) {
		if name != slug {
			out = append(out, name)
		}
	}
	return out
}
