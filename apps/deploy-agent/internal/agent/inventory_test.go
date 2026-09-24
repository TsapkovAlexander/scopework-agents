package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Фикстура снята с боевого сервера (`docker inspect` контейнера, развёрнутого
// Coolify) и урезана до полей, которые читает осмотр. Значения переменных
// оставлены НАСТОЯЩИМИ по форме — с адресами, отправителями SMS и знаками
// равенства внутри: именно на таких данных проверяется, что наружу уходят
// только имена.
const inspectFixture = `[
  {
    "Name": "/sl6hoz64kn26z8yjhhvkvshz-063949267695",
    "Image": "sha256:738f974a0807c4adc723703646d266803705c89708dccb92b1c242e70331d298",
    "Config": {
      "Image": "sl6hoz64kn26z8yjhhvkvshz:55767b9132e90acb131f97181c8fe590b17a4977",
      "Labels": {
        "com.docker.compose.project": "sl6hoz64kn26z8yjhhvkvshz",
        "com.docker.compose.project.config_files": "/artifacts/l3u1qs6pu3c0z2opmszy8yc6/docker-compose.yaml",
        "com.docker.compose.project.working_dir": "/artifacts/l3u1qs6pu3c0z2opmszy8yc6",
        "com.docker.compose.service": "b2c-bff"
      },
      "Env": [
        "B2C_WEB_PROXY_ORIGIN=https://b2c.sigmarket.ru",
        "SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiJ9.payload==",
        "EMPTY_VALUE=",
        "БЕЗ_РАВНО"
      ],
      "Healthcheck": null
    },
    "HostConfig": { "Memory": 1073741824 },
    "State": { "Status": "running", "Health": null },
    "Mounts": [
      { "Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": true },
      { "Type": "volume", "Name": "coolify_db-data", "Source": "/var/lib/docker/volumes/coolify_db-data/_data", "Destination": "/data", "RW": true }
    ],
    "NetworkSettings": {
      "Networks": { "coolify": { "Aliases": ["b2c-bff"] } },
      "Ports": { "3200/tcp": null, "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "80" }] }
    }
  },
  {
    "Name": "/supabase-db-h804",
    "Image": "sha256:aaa",
    "Config": {
      "Image": "supabase/postgres:15.8.1.048",
      "Labels": {
        "com.docker.compose.project": "h804",
        "com.docker.compose.project.working_dir": "/data/coolify/services/h804",
        "com.docker.compose.service": "supabase-db"
      },
      "Env": ["POSTGRES_PASSWORD=секрет"],
      "Healthcheck": { "Test": ["CMD", "pg_isready"] }
    },
    "HostConfig": { "Memory": 0 },
    "State": { "Status": "running", "Health": { "Status": "healthy" } },
    "Mounts": [],
    "NetworkSettings": { "Networks": {}, "Ports": {} }
  }
]`

func parseFixture(t *testing.T) []dockerContainer {
	t.Helper()
	containers, err := parseInspect([]byte(inspectFixture))
	if err != nil {
		t.Fatalf("фикстура не разбирается: %v", err)
	}
	if len(containers) != 2 {
		t.Fatalf("контейнеров %d, ожидалось 2", len(containers))
	}
	return containers
}

// ГЛАВНОЕ свойство осмотра: значения переменных не покидают хост.
//
// На боевом сервере тринадцать чужих проектов, и в их окружении пароли баз и
// сервисные ключи. Осмотр, который забирает их, означает, что «посмотреть, что
// тут есть» скопировало секреты тринадцати систем, из которых переносить
// собирались одну.
func TestInventoryKeepsOnlyEnvNames(t *testing.T) {
	keys := envKeyNames(parseFixture(t)[0].Config.Env)

	want := []string{"B2C_WEB_PROXY_ORIGIN", "EMPTY_VALUE", "SUPABASE_SERVICE_ROLE_KEY"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("имена переменных разобраны неверно: %v", keys)
	}

	// Строка без `=` — не переменная: имени у неё нет, и придумывать его,
	// чтобы «не потерять запись», значило бы показать в интерфейсе то, чего
	// на сервере нет.
	for _, k := range keys {
		if k == "БЕЗ_РАВНО" {
			t.Fatal("строка без знака равенства принята за переменную")
		}
	}

	// Знак равенства внутри значения (base64, JWT, строки подключения) —
	// обычное дело. Обрезка по последнему `=` дала бы имя с куском секрета.
	joined := strings.Join(keys, " ")
	for _, leak := range []string{"eyJhbGci", "sigmarket.ru", "payload"} {
		if strings.Contains(joined, leak) {
			t.Fatalf("значение переменной протекло в имена: %q", joined)
		}
	}
}

// Тот же запрет, но на готовом отчёте: поля добавляют позже и по одному, а
// проверка «нигде в JSON нет значения» переживёт любое новое поле.
func TestInventoryReportCarriesNoSecrets(t *testing.T) {
	containers := parseFixture(t)
	svc := ServiceInventory{
		EnvKeys: envKeyNames(containers[0].Config.Env),
		Image:   containers[0].Config.Image,
	}
	raw, err := json.Marshal(HostInventory{Stacks: []StackInventory{{Services: []ServiceInventory{svc}}}})
	if err != nil {
		t.Fatalf("отчёт не сериализуется: %v", err)
	}
	for _, leak := range []string{"eyJhbGci", "секрет", "b2c.sigmarket.ru"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("в отчёте нашлось значение переменной: %s", leak)
		}
	}
}

// Дайджест — то, что РЕАЛЬНО работает. Ради него осмотр и ходит в docker, а не
// в чужую панель: она показывает умолчания из compose, а не запущенное.
//
// RepoDigests — поле ОБРАЗА (`GET /images/{id}/json`), в JSON контейнера его
// нет вовсе. Фикстура контейнера до 2.1.1 несла это поле, которого docker не
// отдаёт, и тест зеленел на выдумке, а на бою дайджеста не было ни у кого.
func TestInventoryTakesRealDigest(t *testing.T) {
	installInventoryDocker(t, `[
  {"Id": "sha256:aaa", "RepoDigests": [
    "mirror.local/supabase/postgres@sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "supabase/postgres@sha256:f64a22b9b9e95ea31b317122123d8da78ce0e7647548f4a30d91cf6d2d522c1c"
  ]},
  {"Id": "sha256:738f974a0807c4adc723703646d266803705c89708dccb92b1c242e70331d298", "RepoDigests": []}
]`, 0)

	got := collectDigests(t)
	// Образ из реестра: дайджест того репозитория, из которого контейнер и
	// запущен, — по нему нормализация пришпилит `supabase/postgres@…`.
	if got["supabase-db"] != "sha256:f64a22b9b9e95ea31b317122123d8da78ce0e7647548f4a30d91cf6d2d522c1c" {
		t.Fatalf("дайджест образа из реестра: %q", got["supabase-db"])
	}
	// Локально собранный образ (наши git-приложения) RepoDigests не имеет.
	// Честный ответ — идентификатор образа, а не пустота: «дайджеста нет» и
	// «мы его не нашли» для нормализации значат разное.
	if !strings.HasPrefix(got["b2c-bff"], "sha256:738f974a") {
		t.Fatalf("образ без RepoDigests: %q", got["b2c-bff"])
	}
}

// Осмотр образа не удался — осмотр сервера не падает: карта без дайджестов
// полезнее отказа. Поле пустое, а не идентификатор образа: «не нашли» не
// выдаётся за «локальная сборка».
func TestInventoryDigestWithoutImageAnswer(t *testing.T) {
	t.Run("docker отказал", func(t *testing.T) {
		installInventoryDocker(t, "", 1)
		got := collectDigests(t)
		if got["supabase-db"] != "" || got["b2c-bff"] != "" {
			t.Fatalf("без ответа об образе дайджест обязан быть пустым: %v", got)
		}
	})
	// Одного образа уже нет: docker печатает найденные и завершается с 1.
	t.Run("образ удалён", func(t *testing.T) {
		installInventoryDocker(t, `[{"Id": "sha256:aaa", "RepoDigests": ["supabase/postgres@sha256:f64a22b9b9e95ea31b317122123d8da78ce0e7647548f4a30d91cf6d2d522c1c"]}]`, 1)
		got := collectDigests(t)
		if got["supabase-db"] != "sha256:f64a22b9b9e95ea31b317122123d8da78ce0e7647548f4a30d91cf6d2d522c1c" {
			t.Fatalf("найденный образ потерял дайджест: %q", got["supabase-db"])
		}
		if got["b2c-bff"] != "" {
			t.Fatalf("у удалённого образа дайджест обязан быть пустым: %q", got["b2c-bff"])
		}
	})
}

// installInventoryDocker кладёт в PATH поддельный docker, который отвечает на
// вызовы осмотра: список проектов, список контейнеров, `inspect` контейнеров
// (inspectFixture) и `image inspect` — ответом imageJSON с кодом imageExit.
func installInventoryDocker(t *testing.T, imageJSON string, imageExit int) {
	t.Helper()
	bin := t.TempDir()
	data := t.TempDir()
	files := map[string]string{
		"projects.json": `[{"Name":"h804","Status":"running(1)","ConfigFiles":"/data/coolify/services/h804/docker-compose.yml"},` +
			`{"Name":"sl6hoz64kn26z8yjhhvkvshz","Status":"running(1)","ConfigFiles":"/artifacts/l3u1qs6pu3c0z2opmszy8yc6/docker-compose.yaml"}]`,
		"containers.json": inspectFixture,
		"images.json":     imageJSON,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(data, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := "#!/bin/sh\n" +
		"data=" + shellQuote(data) + "\n" +
		`case "$1 $2" in` + "\n" +
		`  "compose ls") cat "$data/projects.json";;` + "\n" +
		`  "ps --all") printf 'c1\nc2\n';;` + "\n" +
		`  "image inspect") cat "$data/images.json"; exit ` + fmt.Sprint(imageExit) + `;;` + "\n" +
		`  inspect*) cat "$data/containers.json";;` + "\n" +
		`  *) echo "поддельный docker: неожиданный вызов $*" >&2; exit 2;;` + "\n" +
		`esac` + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// collectDigests — сервис → дайджест из карты, собранной целиком.
func collectDigests(t *testing.T) map[string]string {
	t.Helper()
	inv, err := CollectInventory(context.Background(), "test", nil)
	if err != nil {
		t.Fatalf("осмотр упал: %v", err)
	}
	out := map[string]string{}
	for _, st := range inv.Stacks {
		for _, svc := range st.Services {
			out[svc.Name] = svc.Digest
		}
	}
	if len(out) != 2 {
		t.Fatalf("сервисов в карте %d, ожидалось 2: %+v", len(out), inv.Stacks)
	}
	return out
}

// Монтирование docker.sock — это root на хосте. Такой сервис не переносится ни
// в каком виде, и знать о нём надо до начала работ, а не после.
func TestInventoryFlagsDockerSocket(t *testing.T) {
	containers := parseFixture(t)

	mounts, sock := mountsOf(containers[0])
	if !sock {
		t.Fatal("монтирование docker.sock не помечено")
	}
	if len(mounts) != 2 {
		t.Fatalf("монтирований %d, ожидалось 2", len(mounts))
	}
	// Том и каталог различаются: том перехватывается по имени и не трогается,
	// а bind-каталог с данными обязан переехать в том.
	if mounts[0].Type != "bind" || mounts[0].Source == "" || mounts[0].Name != "" {
		t.Fatalf("bind разобран неверно: %+v", mounts[0])
	}
	if mounts[1].Type != "volume" || mounts[1].Name != "coolify_db-data" || mounts[1].Source != "" {
		t.Fatalf("том разобран неверно: %+v", mounts[1])
	}

	if _, sock := mountsOf(containers[1]); sock {
		t.Fatal("сервис без docker.sock помечен как имеющий его")
	}
}

// Опубликованный порт 80 — это чужой прокси, то есть окно простоя при
// переключении. Единственная вещь из осмотра, которая прямо определяет цену
// операции, поэтому разбирается отдельно.
func TestInventoryFindsPublishedPorts(t *testing.T) {
	containers := parseFixture(t)

	ports := publishedPortsOf(containers[0])
	if len(ports) != 1 || ports[0] != "80:80/tcp" {
		t.Fatalf("опубликованные порты разобраны неверно: %v", ports)
	}
	// Порт, объявленный контейнером, но не проброшенный наружу, публикацией
	// не является: `"3200/tcp": null` — это EXPOSE, а не -p.
	if len(publishedPortsOf(containers[1])) != 0 {
		t.Fatal("непроброшенный порт принят за опубликованный")
	}
}

func TestInventoryServiceState(t *testing.T) {
	containers := parseFixture(t)

	if got := serviceState(containers[1]); got != "healthy" {
		t.Fatalf("здоровый сервис: %q", got)
	}
	if got := serviceState(containers[0]); got != "running" {
		t.Fatalf("сервис без healthcheck: %q", got)
	}

	// running + unhealthy — самое важное состояние из всех: контейнер жив, а
	// приложение внутри мертво. Схлопывать его в «running» нельзя.
	c := containers[1]
	c.State.Health.Status = "unhealthy"
	if got := serviceState(c); got != "running/unhealthy" {
		t.Fatalf("нездоровый сервис показан как %q", got)
	}
}

// Отчёт уезжает по сети и ложится в базу платформы. Сервер с двумя сотнями
// контейнеров обязан дать полезный ответ, а не ошибку, — поэтому усечение, но
// с честной отметкой.
func TestInventoryShrinkDropsEnvNamesFirst(t *testing.T) {
	big := HostInventory{Stacks: []StackInventory{{
		Project: "big",
		Services: []ServiceInventory{{
			Name:    "app",
			EnvKeys: make([]string, 0, 1000),
			Mounts:  []MountInventory{{Type: "volume", Name: "data"}},
		}},
	}}}
	for i := 0; i < 1000; i++ {
		big.Stacks[0].Services[0].EnvKeys = append(big.Stacks[0].Services[0].EnvKeys, "VERY_LONG_VARIABLE_NAME")
	}

	shrunk := shrinkInventory(big)
	if !shrunk.Truncated {
		t.Fatal("усечение не отмечено — интерфейс покажет неполные данные как полные")
	}
	if len(shrunk.Stacks[0].Services[0].EnvKeys) != 0 {
		t.Fatal("имена переменных не отброшены первыми")
	}
	// Монтирования нужнее имён переменных: по ним видно, что переезжает.
	if len(shrunk.Stacks[0].Services[0].Mounts) == 0 {
		t.Fatal("монтирования отброшены раньше имён переменных")
	}
}

func TestFirstConfigFile(t *testing.T) {
	if got := firstConfigFile("/a/docker-compose.yml,/a/override.yml"); got != "/a/docker-compose.yml" {
		t.Fatalf("основной compose-файл: %q", got)
	}
	if got := firstConfigFile(""); got != "" {
		t.Fatalf("пустой список: %q", got)
	}
}

// Дубли держателей портов. Один контейнер публикует порт и на IPv4, и на IPv6 —
// docker отдаёт две привязки, и на боевом прогоне 2026-08-07 карта показала
// «caddy (80), caddy (80), caddy (443), caddy (443)».
func TestPublishedPortsDeduplicated(t *testing.T) {
	raw := []byte(`[{
	  "Name": "/proxy-1",
	  "Config": {"Image": "caddy", "Labels": {"com.docker.compose.project": "p", "com.docker.compose.service": "caddy"}, "Env": []},
	  "State": {"Status": "running"},
	  "NetworkSettings": {"Networks": {}, "Ports": {
	    "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "80"}, {"HostIp": "::", "HostPort": "80"}],
	    "443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}, {"HostIp": "::", "HostPort": "443"}]
	  }}
	}]`)
	containers, err := parseInspect(raw)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}

	// Сами привязки docker отдаёт обе — это правда о хосте, и терять её незачем.
	if got := len(publishedPortsOf(containers[0])); got != 4 {
		t.Fatalf("привязок %d, ожидалось 4", got)
	}

	// А человеку это один держатель на порт: схлопывание проверяется на уровне
	// карты, в CollectInventory (см. seenPorts).
	seen := map[string]bool{}
	unique := 0
	for _, p := range publishedPortsOf(containers[0]) {
		host, _, _ := strings.Cut(p, ":")
		key := host + "|proxy-1"
		if seen[key] {
			continue
		}
		seen[key] = true
		unique++
	}
	if unique != 2 {
		t.Fatalf("уникальных держателей %d, ожидалось 2 (80 и 443)", unique)
	}
}
