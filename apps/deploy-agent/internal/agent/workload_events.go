package agent

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Классификация событий контейнеров (ADR-0091, решение 5) — порт сверки
// агента мониторинга: apps/discovery-runner/discovery/monitor-push.sh, вставка
// PY_CONTAINER_EVENTS (exit_kind, event_fingerprint, make_event, diff). Виды,
// правила и ключ — ADR-0061, решение 4. Ключ считается тем же выражением, что
// у Python, байт в байт: у событий общие виды, ключ и уникальность на
// платформе, и два способа считать одно и то же рано или поздно разошлись бы.

const (
	WorkloadEventRestarted = "restarted"
	WorkloadEventCrashed   = "crashed"
	WorkloadEventUnhealthy = "unhealthy"
	WorkloadEventDeployed  = "deployed"
	WorkloadEventStopped   = "stopped"
	WorkloadEventRemoved   = "removed"
)

var workloadEventOrder = map[string]int{
	WorkloadEventRestarted: 0, WorkloadEventCrashed: 1, WorkloadEventUnhealthy: 2,
	WorkloadEventDeployed: 3, WorkloadEventStopped: 4, WorkloadEventRemoved: 5,
}

// 137 без OOM — обычный исход `docker stop` процесса, глухого к SIGTERM
// (ADR-0061, факт 3). Считать его падением значило бы тревожить на каждой
// ручной остановке; убитый снаружи контейнер с политикой перезапуска всё
// равно придёт как restarted.
var workloadCleanExitCodes = []int{0, 130, 137, 143}

const (
	// Базовая линия и её файл ограничены, как у агента мониторинга: остатки
	// `docker run` без --rm не должны раздувать состояние на чужом сервере.
	workloadMaxBaselineContainers = 512
	// Сколько помнить пропавший compose-сервис: `compose down` и `up` с тем же
	// образом через такт — перезапуск стека, а не «новый сервис».
	workloadGoneMemory = 7 * 24 * time.Hour
	// Потолок поля restarts события в контракте платформы.
	workloadMaxEventRestarts = 1_000_000
)

// workloadBaselineContainer — принятое состояние контейнера для сверки.
// Времена — строками inspect: по ним узнаётся «тот же выход», а
// нормализация здесь только добавила бы способ разойтись.
type workloadBaselineContainer struct {
	ID             string `json:"id"`
	Image          string `json:"image,omitempty"`
	ImageID        string `json:"image_id,omitempty"`
	Status         string `json:"status"`
	ExitCode       int    `json:"exit_code"`
	OOMKilled      bool   `json:"oom_killed,omitempty"`
	FinishedAt     string `json:"finished_at,omitempty"`
	RestartCount   int    `json:"restart_count"`
	Health         string `json:"health,omitempty"`
	ComposeProject string `json:"compose_project,omitempty"`
	ComposeService string `json:"compose_service,omitempty"`
	Oneoff         bool   `json:"oneoff,omitempty"`
}

type workloadGoneContainer struct {
	ID      string `json:"id"`
	Image   string `json:"image,omitempty"`
	ImageID string `json:"image_id,omitempty"`
	At      int64  `json:"at"`
}

// workloadEpisode — начало текущего эпизода нездоровья: ключ unhealthy держится
// на нём. Повтор сверки после упавшей записи берёт ту же отметку и тот же
// ключ, а новый эпизод после выздоровления — новую и не теряется как дубль.
type workloadEpisode struct {
	ID, Since string
}

// workloadSelectContainers — кого сверять, если контейнеров больше предела.
// Порядок pick_ids: compose-сервисы, затем работающие, затем остальное —
// иначе долгоживущие сервисы тонули бы под остатками `docker run`.
func workloadSelectContainers(cs []WorkloadObservedContainer) map[string]workloadBaselineContainer {
	rank := func(c WorkloadObservedContainer) int {
		switch {
		case c.ComposeService != "":
			return 0
		case c.State == "exited" || c.State == "created" || c.State == "dead" || c.State == "removing":
			return 2
		}
		return 1
	}
	ordered := slices.Clone(cs)
	slices.SortStableFunc(ordered, func(a, b WorkloadObservedContainer) int { return cmp.Compare(rank(a), rank(b)) })

	out := make(map[string]workloadBaselineContainer, min(len(ordered), workloadMaxBaselineContainers))
	for _, c := range ordered {
		if len(out) == workloadMaxBaselineContainers {
			break
		}
		if c.Name == "" || len(c.Name) > workloadMaxNameBytes {
			continue
		}
		if _, dup := out[c.Name]; dup {
			continue
		}
		out[c.Name] = workloadBaselineContainer{
			ID: c.ID, Image: c.ImageRef, ImageID: c.ImageID, Status: c.State,
			ExitCode: c.ExitCode, OOMKilled: c.OOMKilled, FinishedAt: c.FinishedAt,
			RestartCount: max(c.RestartCount, 0), Health: workloadHealth(c),
			ComposeProject: c.ComposeProject, ComposeService: c.ComposeService, Oneoff: c.ComposeOneoff,
		}
	}
	return out
}

func workloadUpdateEpisodes(known map[string]workloadEpisode, current map[string]workloadBaselineContainer, now time.Time) map[string]workloadEpisode {
	out := map[string]workloadEpisode{}
	for name, c := range current {
		if c.Health != "unhealthy" {
			continue
		}
		if e, ok := known[name]; ok && e.ID == c.ID && e.Since != "" {
			out[name] = e
			continue
		}
		// Случайная часть — чтобы два эпизода в одну секунду не получили один ключ.
		var salt [4]byte
		_, _ = rand.Read(salt[:])
		out[name] = workloadEpisode{ID: c.ID, Since: workloadTimestamp(now) + "#" + hex.EncodeToString(salt[:])}
	}
	return out
}

func workloadExitKind(c workloadBaselineContainer) string {
	if c.OOMKilled || !slices.Contains(workloadCleanExitCodes, c.ExitCode) {
		return WorkloadEventCrashed
	}
	return WorkloadEventStopped
}

// workloadDiff — события перехода prev → current и память о пропавших
// compose-сервисах для новой базовой линии. Порт diff() агента мониторинга.
func workloadDiff(prev map[string]workloadBaselineContainer, gone map[string]workloadGoneContainer,
	current map[string]workloadBaselineContainer, episodes map[string]workloadEpisode, now time.Time,
) ([]WorkloadEvent, map[string]workloadGoneContainer) {
	var events []WorkloadEvent
	nextGone := map[string]workloadGoneContainer{}
	for name, g := range gone {
		if _, alive := current[name]; !alive && now.Unix()-g.At < int64(workloadGoneMemory/time.Second) {
			nextGone[name] = g
		}
	}

	for _, name := range slices.Sorted(maps.Keys(current)) {
		c := current[name]
		p, had := prev[name]
		var pp *workloadBaselineContainer
		if had {
			pp = &p
		}
		same := had && p.ID == c.ID
		exited := workloadExited(c.Status)

		// Сборка: у имени сменился образ, или появился постоянный
		// compose-сервис. Разовые `compose run` и контейнеры без compose
		// сборкой не считаются, а пропавший недавно сервис сравнивается с тем,
		// каким он был: `compose down` и `up` с тем же образом — не сборка.
		if had && p.ImageID != c.ImageID {
			events = append(events, workloadMakeEvent(name, WorkloadEventDeployed, c, pp, 0, false, nil, now))
		} else if !had && c.ComposeService != "" && !c.Oneoff && !exited {
			was, wasGone := gone[name]
			if !wasGone || was.ImageID != c.ImageID {
				var wp *workloadBaselineContainer
				if wasGone {
					wp = &workloadBaselineContainer{ID: was.ID, Image: was.Image, ImageID: was.ImageID}
				}
				events = append(events, workloadMakeEvent(name, WorkloadEventDeployed, c, wp, 0, false, nil, now))
			}
		}

		// Падение с перезапуском — прирост счётчика при том же id. Ручной
		// `docker restart` СБРАСЫВАЕТ счётчик в ноль (ADR-0061, факт 1), и
		// убывание падением не считается.
		prevRestarts := 0
		if same {
			prevRestarts = p.RestartCount
		}
		if c.RestartCount > prevRestarts {
			events = append(events, workloadMakeEvent(name, WorkloadEventRestarted, c, pp, c.RestartCount-prevRestarts, same, nil, now))
		} else if exited && workloadDockerTime(c.FinishedAt) != nil {
			changed := !same || p.FinishedAt != c.FinishedAt || !workloadExited(p.Status)
			kind := workloadExitKind(c)
			// Новый контейнер, вышедший чисто, — разовая работа, сделанная до
			// конца, а не событие.
			if changed && (kind == WorkloadEventCrashed || had) {
				events = append(events, workloadMakeEvent(name, kind, c, pp, 0, same, nil, now))
			}
		}

		if c.Health == "unhealthy" && !(same && p.Health == "unhealthy") {
			var episode *string
			if e, ok := episodes[name]; ok {
				episode = &e.Since
			}
			events = append(events, workloadMakeEvent(name, WorkloadEventUnhealthy, c, pp, 0, same, episode, now))
		}
	}

	for _, name := range slices.Sorted(maps.Keys(prev)) {
		if _, alive := current[name]; alive {
			continue
		}
		was := prev[name]
		// Пропажа постоянного compose-сервиса — событие, а разовый `docker run
		// --rm`, переживший сверку, давал бы «удалён» после каждой задачи.
		if was.ComposeService == "" || was.Oneoff {
			continue
		}
		nextGone[name] = workloadGoneContainer{ID: was.ID, Image: was.Image, ImageID: was.ImageID, At: now.Unix()}
		events = append(events, workloadMakeEvent(name, WorkloadEventRemoved, workloadBaselineContainer{
			ID: was.ID, Image: was.Image, ImageID: was.ImageID,
			ComposeProject: was.ComposeProject, ComposeService: was.ComposeService,
		}, nil, 0, false, nil, now))
	}

	if len(nextGone) > workloadMaxBaselineContainers {
		names := slices.SortedFunc(maps.Keys(nextGone), func(a, b string) int {
			return cmp.Or(cmp.Compare(nextGone[b].At, nextGone[a].At), cmp.Compare(a, b))
		})
		for _, name := range names[workloadMaxBaselineContainers:] {
			delete(nextGone, name)
		}
	}
	slices.SortStableFunc(events, func(a, b WorkloadEvent) int {
		return cmp.Compare(workloadEventOrder[a.Kind], workloadEventOrder[b.Kind])
	})
	return events, nextGone
}

// workloadFingerprint — поля ИМЕННО ЭТОГО перехода (event_fingerprint).
// Лишнее поле ломает ключ в обе стороны: здоровье в ключе сборки дало бы
// второй ключ той же сборке, а unhealthy без отметки эпизода склеил бы два
// эпизода в один.
func workloadFingerprint(name, kind string, c workloadBaselineContainer, p *workloadBaselineContainer, same bool, episode *string) []any {
	switch kind {
	case WorkloadEventDeployed:
		var prevID, prevImage any
		if p != nil {
			prevID, prevImage = p.ID, workloadPyNullable(p.ImageID)
		}
		return []any{name, kind, c.ID, workloadPyNullable(c.ImageID), prevID, prevImage}
	case WorkloadEventRestarted:
		// Отсчёт — от ПРИНЯТОГО состояния; finished_at прежнего различает
		// серии после ручного `docker restart`, обнулившего счётчик.
		if same && p != nil {
			return []any{name, kind, c.ID, p.RestartCount, p.FinishedAt}
		}
		return []any{name, kind, c.ID, 0, nil}
	case WorkloadEventCrashed, WorkloadEventStopped:
		return []any{name, kind, c.ID, c.FinishedAt}
	case WorkloadEventUnhealthy:
		if episode == nil {
			return []any{name, kind, c.ID, nil}
		}
		return []any{name, kind, c.ID, *episode}
	}
	return []any{name, kind, c.ID}
}

func workloadPyNullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func workloadMakeEvent(name, kind string, c workloadBaselineContainer, p *workloadBaselineContainer,
	restarts int, same bool, episode *string, now time.Time,
) WorkloadEvent {
	ev := WorkloadEvent{
		Key:            workloadEventKey(workloadFingerprint(name, kind, c, p, same, episode)),
		Kind:           kind,
		Name:           name,
		ComposeProject: workloadText(c.ComposeProject, workloadMaxLabelBytes),
		ComposeService: workloadText(c.ComposeService, workloadMaxLabelBytes),
		Image:          workloadText(c.Image, workloadMaxRefBytes),
		ImageID:        workloadText(c.ImageID, workloadMaxLabelBytes),
		At:             workloadTimestamp(now),
	}
	if kind == WorkloadEventDeployed && p != nil {
		ev.PrevImage = workloadText(p.Image, workloadMaxRefBytes)
		ev.PrevImageID = workloadText(p.ImageID, workloadMaxLabelBytes)
	}
	switch kind {
	case WorkloadEventCrashed, WorkloadEventStopped, WorkloadEventRestarted:
		if at := workloadDockerTime(c.FinishedAt); at != nil {
			ev.At = *at
		}
	}
	exitKnown := kind == WorkloadEventCrashed || kind == WorkloadEventStopped ||
		(kind == WorkloadEventRestarted && workloadExitKnown(c.Status))
	if exitKnown && c.ExitCode >= math.MinInt32 && c.ExitCode <= math.MaxInt32 {
		code, oom := c.ExitCode, c.OOMKilled
		ev.ExitCode, ev.OOMKilled = &code, &oom
	}
	if kind == WorkloadEventRestarted {
		n := int64(min(restarts, workloadMaxEventRestarts))
		ev.Restarts = &n
	}
	if kind == WorkloadEventUnhealthy {
		ev.Health = workloadText(c.Health, workloadMaxStateBytes)
	}
	return ev
}

// workloadEventKey — первые 32 hex sha256 от json.dumps(fingerprint) Python.
func workloadEventKey(fingerprint []any) string {
	sum := sha256.Sum256([]byte(workloadPyJSON(fingerprint)))
	return hex.EncodeToString(sum[:])[:32]
}

// workloadPyJSON — json.dumps Python с настройками по умолчанию: разделители
// ", " и ": ", ensure_ascii. Отпечаток состоит из строк, целых и None, и
// ничего другого здесь нет намеренно: encoding/json сериализует иначе
// (без пробелов, не-ASCII как есть), и ключ разошёлся бы с эталоном.
func workloadPyJSON(v any) string {
	var b strings.Builder
	workloadPyEncode(&b, v)
	return b.String()
}

func workloadPyEncode(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case string:
		workloadPyString(b, x)
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			workloadPyEncode(b, item)
		}
		b.WriteByte(']')
	default:
		// Других типов workloadFingerprint не порождает. Падать агенту на
		// чужом сервере из-за отпечатка хуже, чем дать null, который тест
		// ключей увидит расхождением с эталоном.
		b.WriteString("null")
	}
}

// workloadPyString — py_encode_basestring_ascii: \" \\ \n \r \t \b \f
// короткими escape, прочее вне 0x20–0x7e — \uXXXX строчными, за пределами
// BMP — суррогатной парой.
func workloadPyString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r >= 0x20 && r <= 0x7e:
				b.WriteRune(r)
			case r > 0xffff:
				hi, lo := utf16.EncodeRune(r)
				fmt.Fprintf(b, `\u%04x\u%04x`, hi, lo)
			default:
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}

// WorkloadHasProblemEvents — среди событий есть такие, ради которых стоит
// разбудить такт (решение 5): crashed, restarted, unhealthy. Остальное уходит
// плановым тактом — такт дорог, и сборка или остановка его не торопят.
func WorkloadHasProblemEvents(events []WorkloadEvent) bool {
	return slices.ContainsFunc(events, func(e WorkloadEvent) bool {
		return e.Kind == WorkloadEventCrashed || e.Kind == WorkloadEventRestarted || e.Kind == WorkloadEventUnhealthy
	})
}
