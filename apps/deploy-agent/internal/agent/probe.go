package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// HTTP-проба приложения.
//
// ЗАЧЕМ. Контейнер без HEALTHCHECK агент считает живым по одному факту
// «процесс запущен» (containerAlive). Для большинства git-приложений это
// весь контроль: авторы образов healthcheck объявляют редко. Проба закрывает
// дыру со стороны платформы: агент сам спрашивает приложение по HTTP и
// узнаёт, ОТВЕЧАЕТ ли оно, а не только запущено ли.
//
// КУДА ХОДИМ. На IP контейнера в docker-сети (bridge-адреса маршрутизируются
// с хоста), порт — целевой порт основного опубликованного маршрута, а без
// маршрутов — конвенция app+InternalPort. Ходить на опубликованный домен
// через прокси было бы проверкой заодно и DNS, и Caddy, и внешней сети — а
// вопрос пробы уже: живо ли само приложение.
//
// КРИТЕРИЙ. Любой ответ со статусом < 500 означает «живо»: 401 — работающая
// аутентификация, 301 — работающий редирект, 404 — работающий веб-сервер.
// 5xx — процесс слушает порт, но обслуживать не может.

const probeTimeout = 3 * time.Second

// Сколько тела пробы вычитываем, прежде чем закрыть соединение. Хватает любой
// разумной страницы; всё, что больше, к вопросу «отвечает ли приложение»
// отношения не имеет.
const maxProbeBodyBytes = 64 << 10

// ProbeResult — то, что уезжает в health_detail.probe. Формат читает
// healthDetail.ts в web — менять поля синхронно.
type ProbeResult struct {
	OK      bool   `json:"ok"`
	Status  int    `json:"status,omitempty"`
	Target  string `json:"target,omitempty"`
	Error   string `json:"error,omitempty"`
	Skipped string `json:"skipped,omitempty"`
}

func (r ProbeResult) asDetail() map[string]any {
	out := map[string]any{"ok": r.OK}
	if r.Status != 0 {
		out["status"] = r.Status
	}
	if r.Target != "" {
		out["target"] = r.Target
	}
	if r.Error != "" {
		out["error"] = r.Error
	}
	if r.Skipped != "" {
		out["skipped"] = r.Skipped
	}
	return out
}

// probeTarget выбирает сервис и порт для пробы. false — пробовать нечего.
func probeTarget(app DesiredApp) (service string, port int, ok bool) {
	// Основной опубликованный маршрут точнее конвенции: у шаблона главный
	// вход может жить не на сервисе app.
	for _, r := range app.Routes {
		if r.Domain == app.Domain && r.Service != "" && r.Port > 0 {
			return r.Service, r.Port, true
		}
	}
	if len(app.Routes) > 0 {
		r := app.Routes[0]
		if r.Service != "" && r.Port > 0 {
			return r.Service, r.Port, true
		}
	}
	if app.InternalPort > 0 {
		return "app", app.InternalPort, true
	}
	return "", 0, false
}

// containerIPAddr возвращает адрес контейнера в docker-сети.
func containerIPAddr(ctx context.Context, container string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f",
		"{{range .NetworkSettings.Networks}}{{.IPAddress}}\n{{end}}", container)
	cmd.Env = dockerEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker inspect: %s", tail(string(out), 200))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("у контейнера %s нет адреса в сетях docker", container)
}

// probeHTTP делает один GET и решает, жив ли ответ.
//
// Редиректам не следует: 301 на https://домен ведёт наружу, а вопрос пробы —
// «отвечает ли контейнер», не «работает ли интернет».
func probeHTTP(ctx context.Context, baseURL, hostHeader string, timeout time.Duration) ProbeResult {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return ProbeResult{OK: false, Error: err.Error()}
	}
	// Приложения за прокси часто маршрутизируют по Host: проба без него
	// получала бы 404 от веб-сервера с виртуальными хостами.
	if hostHeader != "" {
		req.Host = hostHeader
	}

	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{OK: false, Error: err.Error()}
	}
	defer resp.Body.Close()

	// Тело вычитываем и выбрасываем.
	//
	// Закрытие соединения посреди ответа прокси считает обрывом и пишет
	// «aborting with incomplete response» — на КАЖДУЮ пробу, то есть каждый
	// такт агента. Зашумлялся ровно тот лог, куда идут смотреть, когда домен
	// не отвечает: настоящая ошибка тонула среди наших же строк.
	//
	// С потолком: приложение вправе отдавать на `/` сколько угодно, а проба
	// спрашивает лишь «отвечает ли оно». Чтение прекращается на лимите —
	// соединение всё равно закрывается штатно, потому что ответ уже прочитан
	// настолько, насколько нам нужно.
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxProbeBodyBytes))

	return ProbeResult{OK: resp.StatusCode < 500, Status: resp.StatusCode}
}

// ProbeApp — полная проба одного приложения: цель, адрес контейнера, GET.
func ProbeApp(ctx context.Context, app DesiredApp) ProbeResult {
	service, port, ok := probeTarget(app)
	if !ok {
		return ProbeResult{OK: false, Skipped: "порт приложения не объявлен"}
	}

	container := app.Slug + "-" + service + "-1"
	target := fmt.Sprintf("%s:%d", service, port)

	ip, err := containerIPAddr(ctx, container)
	if err != nil {
		// Адрес не нашёлся — это уже видно по состоянию контейнеров;
		// дублировать отказом пробы значит показать одну проблему дважды.
		return ProbeResult{OK: false, Target: target, Skipped: "контейнер недоступен для пробы"}
	}

	result := probeHTTP(ctx, fmt.Sprintf("http://%s:%d", ip, port), app.Domain, probeTimeout)
	result.Target = target
	return result
}
