package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Разбор и правка нормализованной модели стека.
//
// Все случаи ниже взяты из корпуса реальных compose-файлов (88 штук с рабочей
// машины), а не придуманы: каждый встречался хотя бы раз, и почти каждый
// ломал бы публикацию молча.

func mustModel(t *testing.T, raw string) map[string]any {
	t.Helper()
	m, err := parseComposeModel([]byte(raw))
	if err != nil {
		t.Fatalf("модель не разобралась: %v", err)
	}
	return m
}

// Порт приезжает двумя формами. Длинную compose собирает сам; строкой запись
// остаётся, когда в ней переменная — при `--no-interpolate` разворачивать её
// некому. В корпусе таких 77 из 303.
func TestPortTargetBothForms(t *testing.T) {
	cases := []struct {
		raw      any
		port     int
		loopback bool
		ok       bool
	}{
		// Длинная форма — то, что compose выдаёт из `"3000:3000"`.
		{map[string]any{"target": float64(3000), "published": "3000", "protocol": "tcp"}, 3000, false, true},
		// Привязка к петле — намерение «только локально», а не публикация.
		{map[string]any{"target": float64(8080), "published": "8080", "host_ip": "127.0.0.1"}, 8080, true, true},
		{map[string]any{"target": float64(5432), "published": "5432", "host_ip": "::1"}, 5432, true, true},
		// Строки из корпуса.
		{"${MINIO_API_PORT:-9000}:9000", 9000, false, true},
		{"${POSTGRES_PORT}:5432", 5432, false, true},
		{"127.0.0.1:${POSTGRES_PORT}:5432", 5432, true, true},
		{"127.0.0.1:${KONG_HTTPS_PORT}:8443/tcp", 8443, true, true},
		{"3000", 3000, false, true},
		{"8000:8000/udp", 8000, false, true},
		// Диапазон портов публикацией одного сервиса не является: цель
		// неоднозначна, и угадывать нельзя.
		{"9000-9010:9000-9010", 0, false, false},
		{"мусор", 0, false, false},
		{map[string]any{"published": "80"}, 0, false, false},
	}

	for _, c := range cases {
		port, loopback, ok := portTarget(c.raw)
		if ok != c.ok || port != c.port || loopback != c.loopback {
			t.Errorf("portTarget(%v) = (%d, петля=%v, ok=%v), ожидалось (%d, %v, %v)",
				c.raw, port, loopback, ok, c.port, c.loopback, c.ok)
		}
	}
}

const corpusModel = `{
  "name": "repo-own-name",
  "services": {
    "web":      {"image": "web:1", "container_name": "my-web",
                 "ports": [{"target": 3000, "published": "3000", "protocol": "tcp"}],
                 "networks": {"default": null}},
    "admin":    {"image": "admin:1",
                 "ports": [{"target": 8080, "published": "8080", "host_ip": "127.0.0.1"}],
                 "networks": {"default": null}},
    "api":      {"image": "api:1", "expose": ["8000"], "networks": {"default": null}},
    "postgres": {"image": "postgres:16", "networks": {"default": null}},
    "isolated": {"image": "x:1", "ports": ["4000:4000"],
                 "networks": {"internal": {"aliases": ["x"]}}}
  },
  "networks": {"default": {"name": "repo-own-name_default"}, "internal": {"name": "repo_internal"}}
}`

func TestPublishCandidatesFromCorpusShapes(t *testing.T) {
	got := publishCandidates(mustModel(t, corpusModel))

	byName := map[string]publishCandidate{}
	for _, c := range got {
		byName[c.Service] = c
	}

	if c, ok := byName["web"]; !ok || c.Port != 3000 {
		t.Errorf("web не стал кандидатом с портом 3000: %+v", byName)
	}
	if c, ok := byName["isolated"]; !ok || c.Port != 4000 {
		t.Errorf("строковая запись порта не распознана: %+v", byName)
	}
	// Привязка к петле — обслуживание. Опубликовав такое, мы вывесили бы
	// наружу панель базы: в корпусе именно так объявлены pgadmin и grafana.
	if _, ok := byName["admin"]; ok {
		t.Error("сервис на 127.0.0.1 принят за публикуемый")
	}
	// expose объявляют и postgres с redis — сам по себе он намерения не несёт.
	if _, ok := byName["api"]; ok {
		t.Error("expose принят за намерение публиковать")
	}
	if _, ok := byName["postgres"]; ok {
		t.Error("сервис без портов принят за публикуемый")
	}
}

func TestPrepareDeployModelStripsAndConnects(t *testing.T) {
	model := mustModel(t, corpusModel)
	notes := prepareDeployModel(model, "doc-patients", map[string]bool{"web": true})

	services := model["services"].(map[string]any)

	// Публикация на хост снимается у ВСЕХ: наружу на этой машине слушает
	// только прокси платформы, иначе обходятся TLS и политики домена.
	for name, raw := range services {
		svc := raw.(map[string]any)
		if _, ok := svc["ports"]; ok {
			t.Errorf("%s: публикация портов не снята", name)
		}
		if _, ok := svc["container_name"]; ok {
			t.Errorf("%s: container_name не снят — маршрут не нашёл бы контейнер", name)
		}
	}

	// Опубликованный получает сеть прокси, не теряя своих.
	web := services["web"].(map[string]any)["networks"].(map[string]any)
	if _, ok := web[edgeNetworkKey]; !ok {
		t.Error("опубликованному сервису не добавлена сеть прокси")
	}
	if _, ok := web["default"]; !ok {
		t.Error("опубликованный сервис потерял default — он перестанет видеть соседей")
	}

	// Чужие сети сохраняются целиком, вместе с алиасами.
	iso := services["isolated"].(map[string]any)["networks"].(map[string]any)
	if _, ok := iso[edgeNetworkKey]; ok {
		t.Error("сеть прокси добавлена неопубликованному сервису")
	}
	if _, ok := iso["internal"]; !ok {
		t.Error("собственная сеть сервиса потеряна")
	}

	// Внешняя сеть объявлена на верхнем уровне — иначе compose откажет.
	nets := model["networks"].(map[string]any)
	edge, ok := nets[edgeNetworkKey].(map[string]any)
	if !ok || edge["external"] != true || edge["name"] != EdgeNetwork {
		t.Errorf("верхнеуровневое объявление сети прокси неверно: %v", nets[edgeNetworkKey])
	}

	// Имя проекта задаётся в самом файле: так все команды compose читают одно
	// и то же и не могут разойтись на два проекта.
	if model["name"] != "doc-patients" {
		t.Errorf("имя проекта не задано платформой: %v", model["name"])
	}

	// Всё снятое обязано быть видно человеку в журнале выката: молча
	// изменённый чужой файл — худший вид «помощи».
	if len(notes) == 0 {
		t.Error("правки не объяснены ни одной строкой")
	}
}

// Модель должна пережить круг через JSON без потерь: именно в этом виде она
// уезжает на хост как файл стека (compose принимает JSON — YAML его надмножество).
func TestDeployModelSurvivesJSONRoundTrip(t *testing.T) {
	model := mustModel(t, corpusModel)
	prepareDeployModel(model, "doc-patients", map[string]bool{"web": true})

	raw, err := renderDeployFile(model)
	if err != nil {
		t.Fatalf("модель не сериализуется: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("сериализованное не читается обратно: %v", err)
	}
	if _, ok := back["services"].(map[string]any)["web"]; !ok {
		t.Error("сервис потерялся при сериализации")
	}
}

// Значения переменных в модель не попадают: `--no-interpolate` оставляет
// ${...} нетронутыми, и файл стека не должен превращаться в копию секретов.
func TestDeployModelKeepsVariablesUnresolved(t *testing.T) {
	model := mustModel(t, `{
      "services": {"api": {"image": "api:1", "environment": {"TOKEN": "${API_TOKEN}"},
                   "networks": {"default": null}}},
      "networks": {"default": {"name": "x_default"}}
    }`)
	prepareDeployModel(model, "x", nil)

	raw, err := renderDeployFile(model)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "${API_TOKEN}") {
		t.Errorf("переменная подставлена или потеряна: %s", raw)
	}
}

// Репозиторий вправе иметь собственную сеть с любым именем, включая `edge`.
// Перезаписав её объявление своим внешним, платформа отключила бы сервисы
// друг от друга — стек поднялся бы и не работал.
func TestPrepareDeployModelKeepsForeignEdgeNetwork(t *testing.T) {
	model := mustModel(t, `{
      "services": {"web": {"image": "web:1", "ports": ["3000:3000"],
                   "networks": {"edge": null}}},
      "networks": {"edge": {"name": "repo_edge"}}
    }`)
	prepareDeployModel(model, "doc-patients", map[string]bool{"web": true})

	nets := model["networks"].(map[string]any)
	own, ok := nets["edge"].(map[string]any)
	if !ok || own["name"] != "repo_edge" {
		t.Errorf("собственная сеть репозитория затёрта: %v", nets["edge"])
	}
	if _, ok := nets[edgeNetworkKey].(map[string]any); !ok {
		t.Error("сеть прокси не объявлена рядом")
	}

	svcNets := model["services"].(map[string]any)["web"].(map[string]any)["networks"].(map[string]any)
	if _, ok := svcNets["edge"]; !ok {
		t.Error("сервис потерял собственную сеть")
	}
	if _, ok := svcNets[edgeNetworkKey]; !ok {
		t.Error("сервис не подключён к сети прокси")
	}
}

// Прежнее имя проекта: под ним стек работает прямо сейчас, и оставить его
// работать значит получить два комплекта контейнеров на одних томах.
func TestPreviousProject(t *testing.T) {
	if got := previousProject(map[string]any{"name": "repo-own"}, "doc-patients"); got != "repo-own" {
		t.Errorf("прежнее имя не распознано: %q", got)
	}
	if got := previousProject(map[string]any{"name": "doc-patients"}, "doc-patients"); got != "" {
		t.Errorf("совпадающее имя принято за прежнее: %q", got)
	}
	if got := previousProject(map[string]any{}, "doc-patients"); got != "" {
		t.Errorf("отсутствующее имя принято за прежнее: %q", got)
	}
}

// Имя проекта — глобальное пространство имён хоста, и совпасть с чужим стеком
// оно может запросто. Погасив его, платформа остановила бы приложение, которого
// не разворачивала.
func TestProjectBelongsToRepoChecksWorkingDir(t *testing.T) {
	mine := dockerContainer{}
	mine.Config.Labels = map[string]string{
		"com.docker.compose.project":             "repo-own",
		"com.docker.compose.project.working_dir": "/opt/tracedocs/deploy/repos/doc-patients",
	}
	foreign := dockerContainer{}
	foreign.Config.Labels = map[string]string{
		"com.docker.compose.project":             "repo-own",
		"com.docker.compose.project.working_dir": "/home/user/своё",
	}

	if !projectBelongsToRepo([]dockerContainer{mine}, "repo-own",
		"/opt/tracedocs/deploy/repos/doc-patients") {
		t.Error("свой стек не признан своим")
	}
	if projectBelongsToRepo([]dockerContainer{foreign}, "repo-own",
		"/opt/tracedocs/deploy/repos/doc-patients") {
		t.Error("чужой стек с тем же именем проекта принят за свой")
	}
	if projectBelongsToRepo(nil, "repo-own", "/opt/tracedocs/deploy/repos/doc-patients") {
		t.Error("отсутствие контейнеров принято за принадлежность")
	}
	if projectBelongsToRepo([]dockerContainer{mine}, "", "/opt") {
		t.Error("пустое имя проекта принято за принадлежность")
	}
}

// Последняя инстанция — сам docker compose.
//
// Наши проверки видят то, о чём мы догадались спросить. Ровно так и вышло с
// перехватом: тест на подстроки пропускал ссылку на необъявленную сеть, и
// отказ вылезал уже на хосте. Здесь результат правки скармливается настоящему
// compose — если он его не примет, тест падает, а не хост.
//
// Пропускается там, где CLI compose нет: демон при этом не нужен, `config`
// разбирает файл, ничего не запуская.
func TestPreparedModelAcceptedByDockerCompose(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker недоступен")
	}
	if err := exec.Command("docker", "compose", "version").Run(); err != nil {
		t.Skip("docker compose недоступен")
	}

	// Форма реального репозитория: своё имя проекта, сервис не `app`, свои
	// сети у одного сервиса и никаких у другого, container_name, порты
	// строкой с переменной и привязка к петле.
	repo := `
name: repo-own-name
services:
  web:
    image: alpine:3.21
    command: ["sleep", "300"]
    container_name: my-web
    ports: ["${WEB_PORT:-3000}:3000"]
    environment:
      TOKEN: ${API_TOKEN}
  api:
    image: alpine:3.21
    command: ["sleep", "300"]
    expose: ["8000"]
  admin:
    image: alpine:3.21
    command: ["sleep", "300"]
    ports: ["127.0.0.1:5050:80"]
    networks:
      internal:
        aliases: [panel]
networks:
  internal:
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(repo), 0o644); err != nil {
		t.Fatal(err)
	}

	raw, err := exec.Command("docker", "compose", "-f",
		filepath.Join(dir, "docker-compose.yml"),
		"config", "--no-interpolate", "--format", "json").Output()
	if err != nil {
		t.Fatalf("исходное описание не разобралось: %v", err)
	}

	model, err := parseComposeModel(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Кандидатами становятся web (3000) и НЕ admin: он привязан к петле.
	cands := publishCandidates(model)
	if len(cands) != 1 || cands[0].Service != "web" || cands[0].Port != 3000 {
		t.Fatalf("кандидаты определены неверно: %+v", cands)
	}

	prepareDeployModel(model, "doc-patients", map[string]bool{"web": true})
	out, err := renderDeployFile(model)
	if err != nil {
		t.Fatal(err)
	}

	deployPath := filepath.Join(dir, "deploy.json")
	if err := os.WriteFile(deployPath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	check := exec.Command("docker", "compose", "-f", deployPath, "config")
	got, err := check.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose отверг подготовленное описание: %v\n%s", err, got)
	}

	text := string(got)
	if !strings.Contains(text, "name: doc-patients") {
		t.Errorf("имя проекта не задано платформой:\n%s", text)
	}
	if strings.Contains(text, "my-web") {
		t.Errorf("container_name уцелел:\n%s", text)
	}
	if strings.Contains(text, "published:") {
		t.Errorf("публикация порта на хост уцелела:\n%s", text)
	}
	// Проверяем ФАЙЛ, а не повторный рендер: контрольная команда выше зовётся
	// без --no-interpolate и подставляет значения сама, как и положено `up`.
	if !strings.Contains(string(out), "${API_TOKEN}") {
		t.Errorf("значение переменной подставлено — файл стал копией секретов:\n%s", out)
	}
	if !strings.Contains(text, "doc-patients_default") {
		t.Errorf("сеть осталась под прежним именем проекта — два приложения делили бы её:\n%s", text)
	}
	if !strings.Contains(text, EdgeNetwork) {
		t.Errorf("сеть прокси не объявлена:\n%s", text)
	}
	// Свои сети чужих сервисов не тронуты.
	if !strings.Contains(text, "panel") {
		t.Errorf("алиас в собственной сети сервиса потерян:\n%s", text)
	}
}

// Порядок: .env пишется ДО чтения описания стека из репозитория.
//
// Описание читает сам docker compose, и ему передаётся `--env-file` с путём к
// нашему .env. Если файла ещё нет, команда падает с «couldn't find env file», и
// выкат обрывается на разборе, не дойдя до подъёма. Ровно это и случилось на
// боевом приложении сразу после выката.
//
// Обычным тестом такое не ловится: обе операции по отдельности исправны, ломает
// их только взаимный порядок. Поэтому проверяется текст — тем же приёмом, каким
// в проекте держится контракт BFF с СУБД.
func TestEnvWrittenBeforeRepoComposeIsRead(t *testing.T) {
	raw, err := os.ReadFile("apply.go")
	if err != nil {
		t.Fatalf("apply.go не читается: %v", err)
	}
	text := string(raw)

	envAt := strings.Index(text, "env := renderEnv(app)")
	readAt := strings.Index(text, "prepareRepoCompose(ctx, p, app, envPath)")
	if envAt < 0 || readAt < 0 {
		t.Skip("ориентиры в apply.go изменились — тест пересобрать")
	}
	if envAt > readAt {
		t.Error("описание стека читается раньше, чем записан .env: " +
			"docker compose откажет с «couldn't find env file»")
	}
}

// Снятие стека по ИМЕНИ ПРОЕКТА, а не по файлу.
//
// Прежде снятие звало compose из каталога с описанием и с `--env-file`. Любая
// пропажа — стёртый .env, изменившийся файл, другое имя проекта в файле — и
// стек не снимался, а уборка повторяла отказ каждую минуту. Именно это и
// случилось на боевом хосте: `не удалось снять стек doc-patients: couldn't
// find env file` двадцать раз подряд.
//
// Имя проекта достаточно: `docker compose -p <имя> down` снимает контейнеры и
// сеть, не читая ни файла, ни переменных.
func TestTearDownProjectsCoversLegacyNames(t *testing.T) {
	repoDir := "/opt/tracedocs/deploy/repos/doc-patients"

	legacy := dockerContainer{}
	legacy.Config.Labels = map[string]string{
		"com.docker.compose.project":             "repo-own-name",
		"com.docker.compose.project.working_dir": repoDir,
	}
	ours := dockerContainer{}
	ours.Config.Labels = map[string]string{
		"com.docker.compose.project":             "doc-patients",
		"com.docker.compose.project.working_dir": repoDir,
	}
	foreign := dockerContainer{}
	foreign.Config.Labels = map[string]string{
		"com.docker.compose.project":             "чужое",
		"com.docker.compose.project.working_dir": "/home/user/своё",
	}

	got := tearDownProjects([]dockerContainer{legacy, ours, foreign}, "doc-patients", repoDir)

	if len(got) != 2 || got[0] != "doc-patients" {
		t.Fatalf("состав снятия неверен: %v", got)
	}
	if got[1] != "repo-own-name" {
		t.Errorf("проект под прежним именем не попал в снятие: %v", got)
	}
	for _, name := range got {
		if name == "чужое" {
			t.Error("чужой проект из другого каталога попал в снятие")
		}
	}

	// Без рабочей копии снимаем только своё имя — и этого достаточно.
	if only := tearDownProjects(nil, "doc-patients", ""); len(only) != 1 || only[0] != "doc-patients" {
		t.Errorf("без рабочей копии состав снятия неверен: %v", only)
	}
}

// Имена томов, собранные compose из ЧУЖОГО имени проекта, уводят стек за
// пределы пространства имён приложения — под таким именем он подключился бы к
// данным соседа. Ровно на этом compose-guard и отклонил боевой выкат:
// «имя тома переопределено на doc-patients_pgdata».
func TestPrepareDeployModelMovesVolumesIntoAppNamespace(t *testing.T) {
	model := mustModel(t, `{
      "name": "doc-patients",
      "services": {"db": {"image": "postgres:16", "networks": {"default": null},
                   "volumes": [{"type": "volume", "source": "pgdata", "target": "/var/lib/postgresql/data"}]}},
      "volumes": {
        "pgdata": {"name": "doc-patients_pgdata"},
        "shared": {"name": "чужой-том-по-воле-автора"},
        "external-one": {"name": "внешний", "external": true}
      },
      "networks": {"default": {"name": "doc-patients_default"}}
    }`)

	notes := prepareDeployModel(model, "doc-patient", map[string]bool{})
	vols := model["volumes"].(map[string]any)

	// Собранное самим compose снято — том получит имя от нашего проекта.
	if _, has := vols["pgdata"].(map[string]any)["name"]; has {
		t.Errorf("имя тома под чужим проектом уцелело: %v", vols["pgdata"])
	}
	// Заданное автором оставлено: он имел в виду именно это, и отказ guard'а
	// на таком томе будет по делу.
	if name := vols["shared"].(map[string]any)["name"]; name != "чужой-том-по-воле-автора" {
		t.Errorf("явно заданное имя тома затёрто: %v", name)
	}
	// Внешний том не трогаем вовсе — там имя и есть точка подключения.
	if name := vols["external-one"].(map[string]any)["name"]; name != "внешний" {
		t.Errorf("имя внешнего тома изменено: %v", name)
	}

	// Потеря данных обязана быть проговорена: том сменил имя, содержимое под
	// прежним осталось на диске и само не переедет.
	var said bool
	for _, n := range notes {
		if strings.Contains(n, "pgdata") && strings.Contains(n, "не переносятся") {
			said = true
		}
	}
	if !said {
		t.Errorf("смена имени тома не объяснена: %v", notes)
	}
}

// Сервисы, которым положено завершиться, читаются из нормализованной модели.
//
// Признак берётся ТОЛЬКО из depends_on: политика перезапуска слишком слаба —
// `restart: no` ставят и обычным сервисам, и по ней упавший контейнер молча
// считался бы отработавшим.
func TestParseCompletedServices(t *testing.T) {
	raw := []byte(`{
	  "services": {
	    "migrate": {"image": "app:1", "restart": "no"},
	    "seed":    {"image": "app:1"},
	    "worker":  {"image": "app:1", "restart": "no"},
	    "app": {
	      "image": "app:1",
	      "depends_on": {
	        "migrate": {"condition": "service_completed_successfully"},
	        "db":      {"condition": "service_healthy"}
	      }
	    },
	    "cron": {
	      "image": "app:1",
	      "depends_on": {"seed": {"condition": "service_completed_successfully"}}
	    },
	    "db": {"image": "postgres:16"}
	  }
	}`)

	completed := parseCompletedServices(raw)

	for _, name := range []string{"migrate", "seed"} {
		if !completed[name] {
			t.Errorf("сервис %s объявлен завершающимся, но не распознан", name)
		}
	}
	for _, name := range []string{"db", "app", "worker", "cron"} {
		if completed[name] {
			t.Errorf("сервис %s ошибочно признан завершающимся", name)
		}
	}
}

// Нечитаемая модель не должна ронять ни выкат, ни проверку здоровья: пустой
// список означает прежнее строгое поведение.
func TestParseCompletedServicesSurvivesGarbage(t *testing.T) {
	for _, raw := range []string{"", "не json", "{}", `{"services": []}`} {
		if got := parseCompletedServices([]byte(raw)); len(got) != 0 {
			t.Errorf("на входе %q получен непустой список: %v", raw, got)
		}
	}
}

// Предупреждение compose не должно попадать в разбираемый JSON.
//
// ДЕФЕКТ, РАДИ КОТОРОГО НАПИСАН ТЕСТ. Агент читал stdout и stderr вместе, а
// docker compose пишет предупреждения в stderr — самое частое из них про
// устаревший ключ `version:`, который стоит в подавляющем большинстве
// публичных репозиториев. Склеенный вывод начинался с `time="..."`, и разбор
// падал с «invalid character 'i' in literal true» — текстом, по которому
// нельзя догадаться ни о причине, ни о том, что дело не в стеке клиента.
// Выкат первого попавшегося публичного проекта не проходил вовсе.
func TestComposeWarningBreaksJSON(t *testing.T) {
	const warning = `time="2026-08-09T12:00:00Z" level=warning ` +
		`msg="docker-compose.yml: the attribute ` + "`version`" + ` is obsolete"`
	const model = `{"services":{"app":{"image":"nginx"}}}`

	// Ровно то, что видел агент: предупреждение и следом модель.
	if _, err := parseComposeModel([]byte(warning + "\n" + model)); err == nil {
		t.Fatal("склеенный вывод разобрался — тест бессмыслен")
	} else if !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("ожидалась та самая ошибка разбора, получено: %v", err)
	}

	// Чистый stdout разбирается.
	parsed, err := parseComposeModel([]byte(model))
	if err != nil {
		t.Fatalf("чистый вывод не разобрался: %v", err)
	}
	if _, ok := parsed["services"]; !ok {
		t.Fatal("в разобранной модели нет сервисов")
	}
}

// Сервис, который платформа не запустит, не бывает кандидатом на публикацию.
//
// Случай с боевого приложения 10.09.2026: `web` объявлен `profiles: ["full"]`,
// домен назначили на него, стек поднялся без него, и агент сообщил про
// несуществующий контейнер. Сервис при этом предложила сама платформа — она
// выбирала кандидатов по одному наличию `ports`.
func TestPublishCandidatesSkipServicesThatWontStart(t *testing.T) {
	cases := map[string]string{
		"профиль":  `{"profiles":["full"],"ports":["3000:3000"]}`,
		"scale 0":  `{"scale":0,"ports":["3000:3000"]}`,
		"replicas": `{"deploy":{"replicas":0},"ports":["3000:3000"]}`,
	}

	for name, svc := range cases {
		raw := `{"services":{"db":{"ports":["5432:5432"]},"web":` + svc + `}}`
		model := mustModel(t, raw)

		got := publishCandidates(model)
		for _, c := range got {
			if c.Service == "web" {
				t.Errorf("%s: web предложен к публикации, хотя не поднимется", name)
			}
		}
		if len(got) != 1 || got[0].Service != "db" {
			t.Errorf("%s: соседний сервис потерян, получили %+v", name, got)
		}
	}
}

// Обычный сервис с портами кандидатом остаётся: проверка не должна отсечь всё.
func TestPublishCandidatesKeepPlainService(t *testing.T) {
	model := mustModel(t, `{"services":{"web":{"ports":["3000:3000"]}}}`)
	got := publishCandidates(model)
	if len(got) != 1 || got[0].Service != "web" || got[0].Port != 3000 {
		t.Fatalf("обычный сервис отсечён: %+v", got)
	}
}

// Пустой список профилей не считается профилем: `profiles: []` compose пишет
// сам, и отказывать из-за него значило бы не поднимать вообще ничего.
func TestServiceStartBlockIgnoresEmptyProfiles(t *testing.T) {
	if block := serviceStartBlock(map[string]any{"profiles": []any{}}); block != "" {
		t.Fatalf("пустой список профилей принят за профиль: %s", block)
	}
	if block := serviceStartBlock(map[string]any{"scale": float64(1)}); block != "" {
		t.Fatalf("scale: 1 принят за отказ: %s", block)
	}
	if block := serviceStartBlock(map[string]any{"deploy": map[string]any{"replicas": float64(2)}}); block != "" {
		t.Fatalf("replicas: 2 принят за отказ: %s", block)
	}
}

// Причина отказа называет, что именно мешает: сообщение читает человек, а не
// платформа, и «не поднимется» без причины отправляет его читать исходники.
func TestServiceStartBlockNamesTheReason(t *testing.T) {
	block := serviceStartBlock(map[string]any{"profiles": []any{"full"}})
	if !strings.Contains(block, "full") {
		t.Fatalf("имя профиля не названо: %s", block)
	}
	if !strings.Contains(serviceStartBlock(map[string]any{"scale": float64(0)}), "scale") {
		t.Fatal("причина scale не названа")
	}
}
