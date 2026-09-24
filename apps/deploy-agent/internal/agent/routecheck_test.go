package agent

import (
	"strings"
	"testing"
)

// Каждый случай ниже — реально случившийся отказ на боевом приложении, при
// котором платформа показывала «Работает», а домен отдавал 502.

func TestRouteCheckProblemNamesTheCause(t *testing.T) {
	base := routeCheck{
		Domain:    "cognistruct.ru",
		Service:   "app",
		Container: "doc-patients-app-1",
		Port:      3000,
	}

	// Сервис в стеке называется иначе — маршрут ведёт в никуда.
	missing := routeCheckProblem(base)
	for _, want := range []string{"cognistruct.ru", "app", "doc-patients-app-1"} {
		if !strings.Contains(missing, want) {
			t.Errorf("в тексте про отсутствующий контейнер нет %q: %s", want, missing)
		}
	}

	// Контейнер есть, но вне сети прокси: Caddy до него не дотянется.
	c := base
	c.Found = true
	offEdge := routeCheckProblem(c)
	if !strings.Contains(offEdge, EdgeNetwork) {
		t.Errorf("в тексте про сеть нет её имени: %s", offEdge)
	}

	// Порт объявлен не тот, что слушает процесс.
	c.OnEdge = true
	c.Transport = "connection refused"
	unreachable := routeCheckProblem(c)
	for _, want := range []string{"3000", "connection refused"} {
		if !strings.Contains(unreachable, want) {
			t.Errorf("в тексте про порт нет %q: %s", want, unreachable)
		}
	}

	// Всё на месте — молчим.
	c.Reachable = true
	c.Transport = ""
	if got := routeCheckProblem(c); got != "" {
		t.Errorf("исправный маршрут объявлен сломанным: %s", got)
	}
}

// Ответ 500 означает, что приложение слушает и отвечает. Его собственная
// ошибка — не предмет выката: гейт спрашивает «дойдёт ли запрос», а не
// «нравится ли ответ». Иначе выкат чинил бы не ту проблему.
func TestRouteCheckIgnoresApplicationErrors(t *testing.T) {
	c := routeCheck{
		Domain: "x.example.com", Service: "web", Container: "app-web-1", Port: 8080,
		Found: true, OnEdge: true, Reachable: true,
	}
	if got := routeCheckProblem(c); got != "" {
		t.Errorf("отвечающий сервис признан сломанным: %s", got)
	}
}

func TestHasNetwork(t *testing.T) {
	nets := []string{"doc-patients_default", EdgeNetwork}
	if !hasNetwork(nets, EdgeNetwork) {
		t.Error("сеть прокси не найдена среди сетей контейнера")
	}
	if hasNetwork([]string{"doc-patients_default"}, EdgeNetwork) {
		t.Error("сеть прокси найдена там, где её нет")
	}
	// Похожее имя — не то же самое: сравнение точное.
	if hasNetwork([]string{EdgeNetwork + "-old"}, EdgeNetwork) {
		t.Error("похожее имя сети принято за нужную")
	}
}
