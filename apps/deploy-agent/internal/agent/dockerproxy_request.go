package agent

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
)

// Рубежи прокси до белого списка: версия API и тело `start`.
//
// ЗАЧЕМ. На демонах v20.10–v24 `POST /v1.23/containers/{id}/start` применяет
// тело запроса как HostConfig — Binds, Privileged, всё, что прокси отбивает в
// `create`. Белый список пропускал `start` по пути и тела не читал, то есть
// root на хосте получался вторым вызовом после безобидного `create`. Демон
// начиная с API 1.24 тело у `start` отвергает сам, но полагаться на демон
// клиента прокси не может: версия демона на чужом сервере — не наша.
//
// Действуют в любом режиме политики: режим наблюдения сужает вызовы до чтения,
// а эти правила закрывают то, что опасно при любом методе.

// dockerMinAPIMinor — первая версия API 1.x, в которой `start` не принимает
// HostConfig в теле. Всё старше отбивается целиком: агенту старый API не
// нужен, а разбирать, какой ещё вызов там устроен иначе, — чинить чёрный
// список.
const dockerMinAPIMinor = 24

// dockerAPIVersionCanonical — префикс версии в том виде, в каком его пишут
// клиенты Docker: `/v1.43`, без ведущих нулей и лишних частей.
var dockerAPIVersionCanonical = regexp.MustCompile(`^/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(/|$)`)

// dockerAPIVersionLike — всё, что демон может принять за префикс версии (его
// маршрут — `/v{version:[0-9.]+}`), включая формы, которых клиенты не пишут.
// `/version` и `/volumes` сюда не попадают: после `v` у них буква.
var dockerAPIVersionLike = regexp.MustCompile(`^/[vV][0-9.]`)

var dockerContainerStartPath = regexp.MustCompile(`^/containers/` + dockerIDPattern + `/start$`)

// refuseDockerRequest — почему запрос отбивается до белого списка; пусто —
// проходит дальше.
func refuseDockerRequest(r *http.Request) string {
	if reason := refuseDockerAPIPath(r.URL); reason != "" {
		return reason
	}
	return refuseContainerStartBody(r)
}

// refuseDockerAPIPath — путь в каноническом виде и версия API не ниже 1.24.
//
// Прокси решает по разобранному пути, а демону уходит путь в том виде, в
// каком пришёл. Всё, где эти два вида могут разойтись, — `%2F`, `%76` вместо
// `v`, `//`, `/./`, `/../`, — отбивается, а не нормализуется: нормализация в
// прокси и в демоне устроены по-разному, и обход живёт ровно в этой разнице.
// Клиенты Docker такие пути не пишут.
func refuseDockerAPIPath(u *url.URL) string {
	p := u.Path
	if u.RawPath != "" {
		return "путь запроса закодирован не так, как его кодируют клиенты Docker"
	}
	if len(p) == 0 || p[0] != '/' || path.Clean(p) != p {
		return "путь запроса не в каноническом виде (//, /./, /../ или / в конце)"
	}
	m := dockerAPIVersionCanonical.FindStringSubmatch(p)
	if m == nil {
		if dockerAPIVersionLike.MatchString(p) {
			return "префикс версии API не в виде /vN.M"
		}
		return "" // путь без версии демон понимает как текущую
	}
	major, errMajor := strconv.Atoi(m[1])
	minor, errMinor := strconv.Atoi(m[2])
	if errMajor != nil || errMinor != nil {
		return "префикс версии API не разбирается"
	}
	if major < 1 || major == 1 && minor < dockerMinAPIMinor {
		return fmt.Sprintf("API Docker v%d.%d старше 1.%d: на нём start принимает HostConfig в теле", major, minor, dockerMinAPIMinor)
	}
	return ""
}

// refuseContainerStartBody — у `start` контейнера тела не бывает.
//
// Читается не больше одного байта: чтобы отказать, достаточно знать, что тело
// есть, а chunked-тело без Content-Length иначе не измерить.
func refuseContainerStartBody(r *http.Request) string {
	if r.Method != http.MethodPost {
		return ""
	}
	if !dockerContainerStartPath.MatchString(dockerAPIVersionPrefix.ReplaceAllString(r.URL.Path, "")) {
		return ""
	}
	if r.Body == nil {
		return ""
	}
	// docker 29 и docker compose v5 шлют start с Content-Length: 0 (проверено
	// 23.09.2026 на фиктивном демоне), поэтому исключений для {} и null нет.
	var probe [1]byte
	n, err := io.ReadFull(r.Body, probe[:])
	if n > 0 {
		return "у start контейнера не бывает тела: старые версии API применяют его как HostConfig"
	}
	if err != nil && err != io.EOF {
		return "тело start не прочитано: " + err.Error()
	}
	r.Body, r.ContentLength, r.TransferEncoding = http.NoBody, 0, nil
	return ""
}
