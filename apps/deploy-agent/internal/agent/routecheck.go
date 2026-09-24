package agent

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Проверка целей маршрутов после подъёма стека.
//
// ЗАЧЕМ. Платформа рапортовала «Работает», пока домен отдавал 502. Стек при
// этом действительно поднят и здоров — просто прокси направлен в контейнер,
// которого нет: маршрут ведёт в сервис `app`, а в репозитории он называется
// `web`. Ни одна проверка этого не замечала, потому что все они смотрят на
// стек, а не на связь стека с прокси.
//
// Это худший из возможных отказов: зелёный выкат, мёртвый домен и ни одной
// строки, по которой можно догадаться. На боевом приложении он стоил часа
// поисков, и найти причину удалось только чтением исходников платформы.
//
// ЧТО ПРОВЕРЯЕМ. Ровно три вещи, каждая — реально случившийся отказ:
//
//	контейнера нет            — маршрут ведёт в несуществующий сервис;
//	контейнер вне сети прокси — Caddy до него не дотянется;
//	порт не отвечает          — процесс слушает не там, где объявлено.
//
// ЧЕГО НЕ ПРОВЕРЯЕМ. Кода ответа: 500 означает, что приложение слушает и
// отвечает, а его собственные ошибки — не предмет выката. Гейт спрашивает
// «дойдёт ли запрос», а не «нравится ли ответ».

// routeCheck — факты об одном маршруте, собранные с хоста.
type routeCheck struct {
	Domain    string
	Service   string
	Container string
	Port      int
	// Found — контейнер существует.
	Found bool
	// OnEdge — контейнер состоит в сети прокси.
	OnEdge bool
	// Reachable — на порт пришёл хоть какой-то ответ.
	Reachable bool
	// Transport — ошибка соединения, если ответа не было.
	Transport string
}

// routeCheckProblem — почему домен не заработает, словами для журнала выката.
// Пустая строка — маршрут исправен.
func routeCheckProblem(c routeCheck) string {
	if !c.Found {
		return fmt.Sprintf(
			"домен %s ведёт в сервис %q, но контейнера %s на сервере нет. "+
				"Проверьте имя сервиса в описании стека: прокси ищет контейнер по нему",
			c.Domain, c.Service, c.Container)
	}
	if !c.OnEdge {
		return fmt.Sprintf(
			"домен %s ведёт в сервис %q, но контейнер %s не подключён к сети прокси %s — "+
				"запрос до него не дойдёт",
			c.Domain, c.Service, c.Container, EdgeNetwork)
	}
	if !c.Reachable {
		return fmt.Sprintf(
			"домен %s ведёт в %s:%d, но порт не отвечает (%s). "+
				"Проверьте, какой порт слушает процесс внутри контейнера",
			c.Domain, c.Service, c.Port, c.Transport)
	}
	return ""
}

// containerNetworks — имена сетей, в которых состоит контейнер.
func containerNetworks(ctx context.Context, container string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f",
		"{{range $k, $_ := .NetworkSettings.Networks}}{{$k}}\n{{end}}", container)
	cmd.Env = dockerEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %s", tail(string(out), 200))
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

func hasNetwork(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// VerifyRoutes проверяет, что каждый опубликованный домен действительно
// доведёт запрос до своего сервиса.
//
// Приложение без доменов проверять нечего — оно и не публикуется.
func VerifyRoutes(ctx context.Context, app DesiredApp) error {
	routes := effectiveRoutes(app)
	if len(routes) == 0 {
		return nil
	}

	var problems []string
	for _, r := range routes {
		if r.Service == "" || r.Port <= 0 {
			continue
		}
		check := routeCheck{
			Domain:    r.Domain,
			Service:   r.Service,
			Port:      r.Port,
			Container: app.Slug + "-" + r.Service + "-1",
		}

		if nets, err := containerNetworks(ctx, check.Container); err == nil {
			check.Found = true
			check.OnEdge = hasNetwork(nets, EdgeNetwork)
		}

		if check.Found && check.OnEdge {
			ip, err := containerIPAddr(ctx, check.Container)
			if err != nil {
				check.Transport = err.Error()
			} else {
				// Любой ответ означает, что порт слушают. Код ответа гейт не
				// разбирает: 500 — это работающее приложение с ошибкой внутри,
				// и валить из-за него выкат платформа не вправе.
				res := probeHTTP(ctx, fmt.Sprintf("http://%s:%d", ip, r.Port), r.Domain, probeTimeout)
				check.Reachable = res.Error == ""
				check.Transport = res.Error
			}
		}

		if problem := routeCheckProblem(check); problem != "" {
			problems = append(problems, problem)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("стек поднялся, но публикация не работает: %s", strings.Join(problems, "; "))
}
