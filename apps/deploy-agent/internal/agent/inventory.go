package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Осмотр сервера: что на нём уже работает.
//
// ЗАЧЕМ. Платформа берёт под управление стеки, которые развернул кто-то другой
// (docs/deploy-adopt-plan.md). Пока она их не видит, перехват остаётся ручной
// операцией: человек ходит по SSH, читает compose, переписывает полсотни
// переменных в форму. Осмотр — первый шаг: карта сервера в интерфейсе.
//
// ЧТО ЗДЕСЬ НЕ ЧИТАЕТСЯ, И ЭТО ГЛАВНОЕ.
//
// Значения переменных окружения. Ни одного. На боевом сервере тринадцать чужих
// проектов, и в их окружении пароли баз, ключи API, токены платёжных систем.
// Осмотр, который забирает их на платформу, означает, что нажатие «посмотреть,
// что тут есть» скопировало секреты тринадцати систем, из которых переносить
// собирались одну. Поэтому значение отбрасывается в момент разбора — не
// маскируется на выходе, а не попадает внутрь вовсе.
//
// Содержимое файлов. Ни compose, ни .env, ни конфигов: берутся путь и факт
// существования. Полный слепок снимается отдельной операцией, для одного
// выбранного стека и по явному подтверждению человека.
//
// ГРАНИЦЫ ЧТЕНИЯ ЗАДАНЫ КОДОМ, А НЕ ЗАДАНИЕМ. Платформа не передаёт сюда ни
// одного пути: агент смотрит туда, куда указывает сам docker (метки
// compose-проектов), и только туда. Иначе «осмотрите сервер» однажды станет
// «прочитайте /etc/shadow» — задание приходит по сети, а агент работает от
// root на чужой машине.
//
// ИСТОЧНИК — DOCKER, А НЕ ЧУЖАЯ ПАНЕЛЬ. Проверено на боевом хосте: панель
// Coolify обещала gotrue v2.174, meta v0.89.3, imgproxy v3.8.0, а работали
// v2.186, v0.96.3 и v3.30.1 — версии приезжают из .env через `${IMAGE:-…}`, и
// в её базе видны только умолчания.

const (
	// Потолки. Превышение — не отказ, а усечение с отметкой: сервер с двумя
	// сотнями контейнеров обязан дать полезный ответ, а не ошибку.
	maxInventoryStacks       = 64
	maxInventoryServices     = 64
	maxInventoryMounts       = 64
	maxInventoryEnvKeys      = 512
	maxInventoryReportBytes  = 512 << 10
	inventoryCommandDeadline = 90 * time.Second
)

// MountInventory — одно монтирование сервиса.
//
// Разделение на том и каталог существенно: именованный том перехватывается по
// имени и не трогается вовсе, а bind-каталог с данными обязан переехать в том
// (иначе его нечем смонтировать: политика платформы запрещает bind на
// произвольные пути хоста).
type MountInventory struct {
	Type string `json:"type"`
	// Name — имя тома docker; пусто у bind.
	Name string `json:"name"`
	// Source — путь на хосте; пусто у именованного тома.
	Source string `json:"source"`
	Target string `json:"target"`
	RW     bool   `json:"rw"`
}

// ServiceInventory — один сервис чужого стека, каким его видит docker.
type ServiceInventory struct {
	Name      string `json:"name"`
	Container string `json:"container"`
	State     string `json:"state"`
	// Image — как записано в конфигурации контейнера (тег или дайджест).
	Image string `json:"image"`
	// Digest — то, что РЕАЛЬНО работает. Нормализация пришпиливает образы
	// именно этими значениями: тег на чужом сервере мог давно уехать.
	Digest string `json:"digest"`
	// PublishedPorts — порты, опубликованные наружу («8080:80/tcp»). Для
	// платформы это запрет: наружу выходят только через прокси. Здесь —
	// предупреждение человеку, а не отказ.
	PublishedPorts []string         `json:"publishedPorts"`
	Networks       []string         `json:"networks"`
	Mounts         []MountInventory `json:"mounts"`
	// EnvKeys — ТОЛЬКО имена. См. комментарий к файлу.
	EnvKeys []string `json:"envKeys"`
	// DockerSock — сервис монтирует /var/run/docker.sock, то есть имеет
	// root-эквивалент на хосте. Такой не переносится ни в каком виде, и вместе
	// с ним уходят его зависимости.
	DockerSock  bool `json:"dockerSock"`
	Healthcheck bool `json:"healthcheck"`
	// MemLimitBytes — 0 означает «без лимита»: нормализация проставит свой.
	MemLimitBytes int64 `json:"memLimitBytes"`
}

// StackInventory — один compose-проект на сервере.
type StackInventory struct {
	Project    string `json:"project"`
	Status     string `json:"status"`
	ConfigFile string `json:"configFile"`
	WorkingDir string `json:"workingDir"`
	// Managed — стек развернула эта платформа. Такой перехватывать не нужно и
	// нельзя: он и так под управлением.
	Managed  bool               `json:"managed"`
	Services []ServiceInventory `json:"services"`
}

// PortHolder — кто занимает порт на хосте.
//
// Отдельным полем, потому что это единственная вещь из осмотра, которая прямо
// определяет цену операции: чужой прокси на 80/443 означает окно простоя на
// переключение, а не просто «ещё один контейнер».
type PortHolder struct {
	Port      int    `json:"port"`
	Container string `json:"container"`
	Project   string `json:"project"`
}

// HostInventory — карта сервера целиком.
type HostInventory struct {
	CollectedAt  string           `json:"collectedAt"`
	AgentVersion string           `json:"agentVersion"`
	Stacks       []StackInventory `json:"stacks"`
	PortHolders  []PortHolder     `json:"portHolders"`
	Truncated    bool             `json:"truncated"`
}

// composeProject — строка вывода `docker compose ls --format json`.
type composeProject struct {
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	ConfigFiles string `json:"ConfigFiles"`
}

// dockerContainer — то, что нам нужно из `docker inspect`. Остальные поля
// игнорируются: разбирать всю схему незачем и хрупко.
type dockerContainer struct {
	Name   string `json:"Name"`
	Config struct {
		Image       string            `json:"Image"`
		Labels      map[string]string `json:"Labels"`
		Env         []string          `json:"Env"`
		Healthcheck *struct {
			Test []string `json:"Test"`
		} `json:"Healthcheck"`
	} `json:"Config"`
	// Image — идентификатор образа (`sha256:…`). RepoDigests здесь нет: это
	// поле образа, а не контейнера, и читается отдельным осмотром образа.
	Image           string `json:"Image"`
	RestartCount    int    `json:"RestartCount"`
	HostConfigBlock struct {
		Memory int64 `json:"Memory"`
	} `json:"HostConfig"`
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			Aliases []string `json:"Aliases"`
		} `json:"Networks"`
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// envKeyNames оставляет от переменных только имена.
//
// Отдельной функцией и с тестом, потому что это то самое место, где секреты
// чужих систем могли бы утечь на платформу: `docker inspect` отдаёт окружение
// строками вида `KEY=значение`, и обрезать надо по ПЕРВОМУ `=` — в значении
// знаков равенства сколько угодно (base64, JWT, строки подключения).
func envKeyNames(env []string) []string {
	keys := make([]string, 0, len(env))
	for _, item := range env {
		name, _, found := strings.Cut(item, "=")
		if !found || name == "" {
			continue
		}
		keys = append(keys, name)
		if len(keys) >= maxInventoryEnvKeys {
			break
		}
	}
	sort.Strings(keys)
	return keys
}

// serviceState — понятное человеку состояние: «работает», «не запущен»,
// «нездоров». Health важнее Status: контейнер бывает running и unhealthy.
func serviceState(c dockerContainer) string {
	if c.State.Health != nil && c.State.Health.Status != "" {
		if c.State.Health.Status == "healthy" {
			return "healthy"
		}
		return c.State.Status + "/" + c.State.Health.Status
	}
	return c.State.Status
}

// dockerImage — то, что нам нужно из осмотра образа.
type dockerImage struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
}

// imageDigest — дайджест образа, из которого запущен контейнер.
//
// images — RepoDigests по идентификатору образа. Образа в ней нет — осмотр
// образа не удался или образ уже удалён: ответ пустой. Выдать за дайджест
// идентификатор значило бы сказать «локальная сборка» про образ из реестра.
func imageDigest(c dockerContainer, images map[string][]string) string {
	repoDigests, known := images[c.Image]
	if !known {
		return ""
	}
	// Образ бывает известен под несколькими репозиториями (зеркало, второй
	// реестр), и дайджесты у них могут различаться. Пришпиливать надо тот,
	// что лежит в репозитории, из которого контейнер запущен: чужой дайджест
	// в этом репозитории не найдётся.
	want := imageRepository(c.Config.Image)
	first := ""
	for _, rd := range repoDigests {
		repo, digest, found := strings.Cut(rd, "@")
		if !found {
			continue
		}
		if repo == want {
			return digest
		}
		if first == "" {
			first = digest
		}
	}
	if first != "" {
		return first
	}
	// Образ без RepoDigests — собранный локально (наши git-приложения именно
	// такие). Тогда честный ответ — идентификатор образа, а не пустота.
	return c.Image
}

// imageRepository — имя образа без тега и дайджеста: `supabase/postgres:15`
// → `supabase/postgres`. Двоеточие до последнего `/` — порт реестра, не тег.
func imageRepository(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
}

func mountsOf(c dockerContainer) ([]MountInventory, bool) {
	out := make([]MountInventory, 0, len(c.Mounts))
	sock := false
	for _, m := range c.Mounts {
		if strings.HasSuffix(m.Source, "/docker.sock") || strings.HasSuffix(m.Destination, "/docker.sock") {
			sock = true
		}
		if len(out) >= maxInventoryMounts {
			continue
		}
		item := MountInventory{Type: m.Type, Target: m.Destination, RW: m.RW}
		if m.Type == "volume" {
			item.Name = m.Name
		} else {
			item.Source = m.Source
		}
		out = append(out, item)
	}
	return out, sock
}

func publishedPortsOf(c dockerContainer) []string {
	var out []string
	for port, bindings := range c.NetworkSettings.Ports {
		for _, b := range bindings {
			if b.HostPort == "" {
				continue
			}
			out = append(out, b.HostPort+":"+port)
		}
	}
	sort.Strings(out)
	return out
}

func networksOf(c dockerContainer) []string {
	out := make([]string, 0, len(c.NetworkSettings.Networks))
	for name := range c.NetworkSettings.Networks {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ManagedRoots — каталоги, стеками в которых распоряжается платформа.
//
// Один список на всех: по нему осмотр помечает стек «наш» и не предлагает его
// к перехвату, и по нему же задания остановки и переноса данных отказываются
// трогать собственные стеки платформы. Две копии этого списка разошлись бы, а
// цена расхождения — остановленный прокси, то есть все домены сервера разом.
func ManagedRoots(p Paths) []string {
	return []string{
		filepath.Join(p.WorkDir, "apps"),
		filepath.Join(p.WorkDir, "repos"),
		// Прокси платформы — тоже наш стек. Без него собственный Caddy
		// показывался бы в интерфейсе как чужой, который стоит перехватить.
		p.proxyDir(),
	}
}

// CollectInventory составляет карту сервера.
//
// managedRoots — каталоги самой платформы: стек, развёрнутый ею, помечается
// managed и в перехват не предлагается. В список входит и каталог прокси:
// без него собственный Caddy платформы показывался бы человеку как чужой
// стек, который стоит перехватить.
func CollectInventory(ctx context.Context, version string, managedRoots []string) (HostInventory, error) {
	ctx, cancel := context.WithTimeout(ctx, inventoryCommandDeadline)
	defer cancel()

	inv := HostInventory{
		CollectedAt:  time.Now().UTC().Format(time.RFC3339),
		AgentVersion: version,
		Stacks:       []StackInventory{},
		PortHolders:  []PortHolder{},
	}

	projects, err := listComposeProjects(ctx)
	if err != nil {
		return inv, err
	}
	if len(projects) > maxInventoryStacks {
		projects = projects[:maxInventoryStacks]
		inv.Truncated = true
	}

	containers, err := inspectComposeContainers(ctx)
	if err != nil {
		return inv, err
	}
	images := inspectImageDigests(ctx, containers)

	// Держателей портов схлопываем по паре «порт + контейнер»: см. ниже.
	type portKey struct {
		port      int
		container string
	}
	seenPorts := map[portKey]bool{}

	byProject := map[string][]dockerContainer{}
	for _, c := range containers {
		project := c.Config.Labels["com.docker.compose.project"]
		if project == "" {
			continue
		}
		byProject[project] = append(byProject[project], c)
	}

	for _, p := range projects {
		stack := StackInventory{
			Project:    p.Name,
			Status:     p.Status,
			ConfigFile: firstConfigFile(p.ConfigFiles),
			Services:   []ServiceInventory{},
		}

		list := byProject[p.Name]
		if len(list) > 0 {
			stack.WorkingDir = list[0].Config.Labels["com.docker.compose.project.working_dir"]
		}
		// Путь чистим здесь же: метка docker приходит как есть, а сравнение
		// префиксом на нечищенном пути даёт ложное «чужой».
		stack.Managed = stack.WorkingDir != "" &&
			withinRoots(filepath.Clean(stack.WorkingDir), managedRoots)

		if len(list) > maxInventoryServices {
			list = list[:maxInventoryServices]
			inv.Truncated = true
		}
		for _, c := range list {
			mounts, sock := mountsOf(c)
			svc := ServiceInventory{
				Name:           c.Config.Labels["com.docker.compose.service"],
				Container:      strings.TrimPrefix(c.Name, "/"),
				State:          serviceState(c),
				Image:          c.Config.Image,
				Digest:         imageDigest(c, images),
				PublishedPorts: publishedPortsOf(c),
				Networks:       networksOf(c),
				Mounts:         mounts,
				EnvKeys:        envKeyNames(c.Config.Env),
				DockerSock:     sock,
				Healthcheck:    c.Config.Healthcheck != nil && len(c.Config.Healthcheck.Test) > 0,
				MemLimitBytes:  c.HostConfigBlock.Memory,
			}
			stack.Services = append(stack.Services, svc)

			// Один контейнер публикует порт и на IPv4, и на IPv6 — docker
			// отдаёт две привязки. Для человека это один держатель одного
			// порта; без схлопывания в интерфейсе выходило «caddy (80),
			// caddy (80), caddy (443), caddy (443)».
			for _, published := range svc.PublishedPorts {
				host, _, _ := strings.Cut(published, ":")
				if host != "80" && host != "443" {
					continue
				}
				port := 80
				if host == "443" {
					port = 443
				}
				if seenPorts[portKey{port: port, container: svc.Container}] {
					continue
				}
				seenPorts[portKey{port: port, container: svc.Container}] = true
				inv.PortHolders = append(inv.PortHolders, PortHolder{
					Port: port, Container: svc.Container, Project: p.Name,
				})
			}
		}

		sort.Slice(stack.Services, func(i, j int) bool {
			return stack.Services[i].Container < stack.Services[j].Container
		})
		inv.Stacks = append(inv.Stacks, stack)
	}

	sort.Slice(inv.Stacks, func(i, j int) bool { return inv.Stacks[i].Project < inv.Stacks[j].Project })
	sort.Slice(inv.PortHolders, func(i, j int) bool {
		if inv.PortHolders[i].Port != inv.PortHolders[j].Port {
			return inv.PortHolders[i].Port < inv.PortHolders[j].Port
		}
		return inv.PortHolders[i].Container < inv.PortHolders[j].Container
	})

	// Последний потолок — по размеру готового отчёта: он уезжает по сети и
	// ложится в базу платформы.
	if raw, err := json.Marshal(inv); err == nil && len(raw) > maxInventoryReportBytes {
		inv = shrinkInventory(inv)
	}
	return inv, nil
}

// shrinkInventory ужимает отчёт, не теряя структуры: имена переменных первыми
// (их больше всего, и для показа списка они не нужны), затем монтирования.
func shrinkInventory(inv HostInventory) HostInventory {
	inv.Truncated = true
	for si := range inv.Stacks {
		for vi := range inv.Stacks[si].Services {
			inv.Stacks[si].Services[vi].EnvKeys = nil
		}
	}
	if raw, err := json.Marshal(inv); err == nil && len(raw) <= maxInventoryReportBytes {
		return inv
	}
	for si := range inv.Stacks {
		for vi := range inv.Stacks[si].Services {
			inv.Stacks[si].Services[vi].Mounts = nil
			inv.Stacks[si].Services[vi].Networks = nil
		}
	}
	return inv
}

// firstConfigFile — путь к первому compose-файлу проекта. Их бывает несколько
// (override), но для карты достаточно основного.
func firstConfigFile(list string) string {
	first, _, _ := strings.Cut(list, ",")
	return strings.TrimSpace(first)
}

func listComposeProjects(ctx context.Context) ([]composeProject, error) {
	cmd := exec.CommandContext(ctx, "docker", "compose", "ls", "--all", "--format", "json")
	cmd.Env = dockerEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить список compose-проектов: %w", err)
	}
	var projects []composeProject
	if err := json.Unmarshal(out, &projects); err != nil {
		return nil, fmt.Errorf("не удалось разобрать список проектов: %w", err)
	}
	return projects, nil
}

// inspectComposeContainers забирает подробности обо ВСЕХ контейнерах
// compose-проектов одним вызовом.
//
// Одним, а не по контейнеру: на боевом сервере их полсотни, и полсотни
// запусков docker — это полминуты нагрузки на чужую машину ради карты.
func inspectComposeContainers(ctx context.Context) ([]dockerContainer, error) {
	list := exec.CommandContext(ctx, "docker", "ps", "--all",
		"--filter", "label=com.docker.compose.project", "--format", "{{.ID}}")
	list.Env = dockerEnv()
	out, err := list.Output()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить список контейнеров: %w", err)
	}

	ids := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}

	inspect := exec.CommandContext(ctx, "docker", append([]string{"inspect"}, ids...)...)
	inspect.Env = dockerEnv()
	raw, err := inspect.Output()
	if err != nil {
		return nil, fmt.Errorf("не удалось осмотреть контейнеры: %w", err)
	}
	return parseInspect(raw)
}

// inspectImageDigests — RepoDigests образов, из которых запущены контейнеры.
//
// Одним вызовом на все образы, по той же причине, что и осмотр контейнеров.
// Ошибка не роняет осмотр: карта без дайджестов полезнее отказа, а у образа,
// о котором docker не ответил, дайджест останется пустым (см. imageDigest).
//
// Docker печатает найденные образы и завершается с ошибкой, если хоть одного
// уже нет (удалён после запуска контейнера), поэтому вывод разбирается и при
// ненулевом коде.
func inspectImageDigests(ctx context.Context, containers []dockerContainer) map[string][]string {
	seen := map[string]bool{}
	ids := []string{}
	for _, c := range containers {
		if c.Image != "" && !seen[c.Image] {
			seen[c.Image] = true
			ids = append(ids, c.Image)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)

	cmd := exec.CommandContext(ctx, "docker", append([]string{"image", "inspect"}, ids...)...)
	cmd.Env = dockerEnv()
	raw, _ := cmd.Output()
	var list []dockerImage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	out := make(map[string][]string, len(list))
	for _, img := range list {
		if img.ID == "" {
			continue
		}
		// Пустой список, а не nil: «образ найден, дайджеста нет» — это
		// локальная сборка, и imageDigest отличает её от «образ не найден».
		if img.RepoDigests == nil {
			img.RepoDigests = []string{}
		}
		out[img.ID] = img.RepoDigests
	}
	return out
}

func parseInspect(raw []byte) ([]dockerContainer, error) {
	var containers []dockerContainer
	if err := json.Unmarshal(raw, &containers); err != nil {
		return nil, fmt.Errorf("не удалось разобрать вывод docker inspect: %w", err)
	}
	return containers, nil
}

// inventoryMarkFile — метка последнего выполненного осмотра.
const inventoryMarkFile = "inventory.json"

type inventoryMark struct {
	// RequestedAt — метка запроса, который агент уже отработал. Сравнение по
	// ней, а не флагом «сделано»: платформа снимает отметку сама, приняв
	// отчёт, но если отчёт не доехал, запрос остаётся — и агент обязан
	// повторить осмотр, а не считать его выполненным.
	RequestedAt string `json:"requested_at"`
}

// RunInventory осматривает сервер, если этот запрос ещё не отрабатывали.
//
// Идемпотентность здесь важнее скорости: отметка о жизни идёт каждую минуту и
// приносит один и тот же запрос до тех пор, пока платформа не примет отчёт.
// Без метки агент перечислял бы контейнеры чужого сервера в бесконечном цикле.
func RunInventory(
	ctx context.Context,
	client *Client,
	id Identity,
	p Paths,
	version string,
	requestedAt string,
) error {
	markPath := filepath.Join(p.StateDir, inventoryMarkFile)

	var mark inventoryMark
	if raw, err := os.ReadFile(markPath); err == nil {
		_ = json.Unmarshal(raw, &mark)
	}
	if mark.RequestedAt == requestedAt {
		return nil
	}

	inv, err := CollectInventory(ctx, version, ManagedRoots(p))
	if err != nil {
		return err
	}
	if err := client.ReportInventory(ctx, id, inv); err != nil {
		return err
	}

	// Метку пишем только ПОСЛЕ успешной отправки: иначе неудачная доставка
	// означала бы, что осмотр «выполнен», а платформа его так и не увидела.
	raw, err := json.Marshal(inventoryMark{RequestedAt: requestedAt})
	if err != nil {
		return err
	}
	fmt.Printf("осмотр сервера: найдено стеков %d\n", len(inv.Stacks))
	return writeFileAtomic(markPath, raw, 0o600)
}
