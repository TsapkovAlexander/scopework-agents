package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// VolumesFrom: контейнер получает всё, что смонтировано у донора.
//
// Решение зависит не от тела, а от того, что уже стоит на хосте, поэтому
// прокси спрашивает демон, и тесты ставят вместо демона подделку на
// unix-сокете: фикстуры inspect — в форме, снятой с живого Docker 29.

// Доноры — только полными ID: compose подставляет полный ID вместо имени
// сервиса, а имя и префикс прокси не принимает (см. checkVolumesFrom).
const goodDonorID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

var (
	goodDonorID2     = strings.Repeat("2", 64)
	foreignDonorID   = strings.Repeat("3", 64)
	unlabeledDonorID = strings.Repeat("4", 64)
	sockDonorID      = strings.Repeat("5", 64)
	etcDonorID       = strings.Repeat("6", 64)
	nfsDonorID       = strings.Repeat("7", 64)
	pipeDonorID      = strings.Repeat("8", 64)
	ghostDonorID     = strings.Repeat("9", 64)
	boomDonorID      = strings.Repeat("b", 64)
	// swappedDonorID — строка, которую демон разрешил в ДРУГОЙ контейнер:
	// inspect отдаёт Id, не совпадающий с запрошенным (64-hex имя контейнера).
	swappedDonorID = strings.Repeat("c", 64)
	dotdotDonorID  = strings.Repeat("d", 64)
)

func donorFixtures() map[string]string {
	withID := func(id, rest string) string { return `{"Id":"` + id + `",` + rest + `}` }
	goodRest := `"Config":{"Labels":{"com.docker.compose.project":"app"}},"Mounts":[` +
		`{"Type":"bind","Source":"/opt/tracedocs/deploy/apps/site/data","Destination":"/h","Mode":"ro","RW":false,"Propagation":"rprivate"},` +
		`{"Type":"volume","Name":"app_named","Source":"/var/lib/docker/volumes/app_named/_data","Destination":"/n","Driver":"local","Mode":"z","RW":true},` +
		`{"Type":"tmpfs","Source":"","Destination":"/x"}]`
	fixtures := map[string]string{
		goodDonorID: withID(goodDonorID, goodRest),
		// Демон разрешает и имя, и уникальный префикс ID — ровно поэтому их
		// нельзя принимать: к create они могут разрешиться в другой контейнер.
		"good":           withID(goodDonorID, goodRest),
		"0123456789ab":   withID(goodDonorID, goodRest),
		goodDonorID2:     withID(goodDonorID2, goodRest),
		swappedDonorID:   withID(goodDonorID, goodRest),
		foreignDonorID:   withID(foreignDonorID, `"Config":{"Labels":{"com.docker.compose.project":"other"}},"Mounts":[]`),
		unlabeledDonorID: withID(unlabeledDonorID, `"Config":{"Labels":{}},"Mounts":[]`),
		sockDonorID: withID(sockDonorID, `"Config":{"Labels":{"com.docker.compose.project":"app"}},"Mounts":[`+
			`{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}]`),
		etcDonorID: withID(etcDonorID, `"Config":{"Labels":{"com.docker.compose.project":"app"}},"Mounts":[`+
			`{"Type":"bind","Source":"/etc","Destination":"/host-etc","RW":false}]`),
		nfsDonorID: withID(nfsDonorID, `"Config":{"Labels":{"com.docker.compose.project":"app"}},"Mounts":[`+
			`{"Type":"volume","Name":"shared","Source":"/var/lib/docker/volumes/shared/_data","Destination":"/s","Driver":"nfs"}]`),
		pipeDonorID: withID(pipeDonorID, `"Config":{"Labels":{"com.docker.compose.project":"app"}},"Mounts":[`+
			`{"Type":"npipe","Source":"\\\\.\\pipe\\docker_engine","Destination":"/p"}]`),
		// Лексически внутри рабочего каталога, а ядро разрешает `..` после
		// ссылки `l`: Source в inspect — ровно то, что записал демон.
		dotdotDonorID: withID(dotdotDonorID, `"Config":{"Labels":{"com.docker.compose.project":"app"}},"Mounts":[`+
			`{"Type":"bind","Source":"/opt/tracedocs/deploy/apps/l/../secret","Destination":"/h","RW":true}]`),
	}
	for _, id := range manyGoodDonorIDs(dockerProxyMaxVolumesFromForTest + 1) {
		fixtures[id] = withID(id, goodRest)
	}
	return fixtures
}

// dockerProxyMaxVolumesFromForTest — предел числом, а не константой прокси:
// тест обязан упасть, если предел молча поднимут.
const dockerProxyMaxVolumesFromForTest = 16

// manyGoodDonorIDs — n хороших доноров своего проекта с различными полными ID.
func manyGoodDonorIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", 0xe00+i)
	}
	return ids
}

type fakeDockerDaemon struct {
	socket   string
	dir      string
	inspects atomic.Int32
	creates  atomic.Int32
}

var fakeInspectPath = regexp.MustCompile(`^(?:/v[0-9]+\.[0-9]+)?/containers/([^/]+)/json$`)

// startFakeDockerDaemon — подделка демона: inspect по фикстурам, create эхом.
//
// Каталог — os.MkdirTemp с коротким именем, а не t.TempDir: путь unix-сокета
// ограничен 104 байтами на macOS, а t.TempDir вкладывает имя теста.
func startFakeDockerDaemon(t *testing.T) *fakeDockerDaemon {
	t.Helper()
	dir, err := os.MkdirTemp("", "dpx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &fakeDockerDaemon{socket: filepath.Join(dir, "d.sock"), dir: dir}
	listener, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatalf("сокет демона: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	fixtures := donorFixtures()
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := dockerAPIVersionPrefix.ReplaceAllString(r.URL.Path, "")
			if m := fakeInspectPath.FindStringSubmatch(r.URL.Path); m != nil && r.Method == "GET" {
				d.inspects.Add(1)
				name := m[1]
				if name == boomDonorID {
					http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
					return
				}
				body, ok := fixtures[name]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, `{"message":"No such container: `+name+`"}`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
				return
			}
			if path == "/containers/create" && r.Method == "POST" {
				d.creates.Add(1)
			}
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "body": string(body)})
		}))
	}()
	return d
}

// volumesFromBody — тело create так, как его шлёт compose: метка проекта в
// Labels, доноры в HostConfig.VolumesFrom.
func volumesFromBody(t *testing.T, project string, volumesFrom any) []byte {
	t.Helper()
	req := map[string]any{"Image": "nginx"}
	if project != "" {
		req["Labels"] = map[string]string{"com.docker.compose.project": project}
	}
	hc := map[string]any{"NetworkMode": "app_default"}
	if volumesFrom != nil {
		hc["VolumesFrom"] = volumesFrom
	}
	req["HostConfig"] = hc
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDockerProxyVolumesFromOtbivaetOpasnyhDonorov(t *testing.T) {
	d := startFakeDockerDaemon(t)
	donors := newUpstreamContainerInspector(d.socket)
	cases := []struct {
		name string
		body []byte
		want string
		// requests — сколько вопросов демону допустимо; -1 — не считаем.
		requests int32
	}{
		{"1 донор из чужого проекта", volumesFromBody(t, "app", []string{foreignDonorID}), "не из этого проекта", 1},
		{"1 донор без метки проекта", volumesFromBody(t, "app", []string{unlabeledDonorID}), "не из этого проекта", 1},
		{"2 донор с сокетом Docker", volumesFromBody(t, "app", []string{sockDonorID}), "сокет Docker", 1},
		{"3 донор с /etc", volumesFromBody(t, "app", []string{etcDonorID}), "вне рабочих каталогов", 1},
		{"4 донора нет", volumesFromBody(t, "app", []string{ghostDonorID}), "не найден", 1},
		{"5 демон ответил 500", volumesFromBody(t, "app", []string{boomDonorID}), "500", 1},
		{"6 один донор из трёх плохой", volumesFromBody(t, "app", []string{goodDonorID, sockDonorID + ":ro", goodDonorID2}), "сокет Docker", 3},
		{"7 суффикс :z", volumesFromBody(t, "app", []string{goodDonorID + ":z"}), "режим", 0},
		{"7 суффикс :ro,z", volumesFromBody(t, "app", []string{goodDonorID + ":ro,z"}), "режим", 0},
		{"7 пустое имя", volumesFromBody(t, "app", []string{":ro"}), "пустое имя", 0},
		{"7 имя с выходом из пути", volumesFromBody(t, "app", []string{"../images"}), "полному ID", 0},
		{"8 тело без метки проекта", volumesFromBody(t, "", []string{goodDonorID}), "метки", 0},
		{"8 метка проекта пустая", []byte(`{"Labels":{"com.docker.compose.project":""},"HostConfig":{"VolumesFrom":["` + goodDonorID + `"]}}`), "метки", 0},
		{"11 донор с томом nfs", volumesFromBody(t, "app", []string{nfsDonorID}), "Driver nfs", 1},
		{"донор с монтированием неизвестного типа", volumesFromBody(t, "app", []string{pipeDonorID}), "не разбирает", 1},
		// Имя и префикс ID демон разрешает в момент create, а не inspect: имя
		// удалили — тот же префикс ведёт в контейнер Coolify с сокетом Docker.
		{"15 донор по имени", volumesFromBody(t, "app", []string{"good"}), "полному ID", 0},
		{"15 донор по имени из hex-знаков", volumesFromBody(t, "app", []string{"0123456789ab"}), "полному ID", 0},
		{"15 донор по префиксу ID", volumesFromBody(t, "app", []string{goodDonorID[:12] + ":ro"}), "полному ID", 0},
		{"15 ID заглавными", volumesFromBody(t, "app", []string{strings.ToUpper(goodDonorID)}), "полному ID", 0},
		{"15 ID длиннее 64", volumesFromBody(t, "app", []string{goodDonorID + "0"}), "полному ID", 0},
		{"15 демон разрешил ID в другой контейнер", volumesFromBody(t, "app", []string{swappedDonorID}), "не совпадает", 1},
		{"16 у донора привязка l/../secret", volumesFromBody(t, "app", []string{dotdotDonorID}), "..", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := d.inspects.Load()
			got := decideDockerProxy("POST", "/v1.44/containers/create", tc.body, proxyRoots, donors)
			if got.Allowed {
				t.Fatalf("прокси пропустил VolumesFrom опасного донора: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
			if n := d.inspects.Load() - before; tc.requests >= 0 && n != tc.requests {
				t.Fatalf("вопросов демону %d, ожидалось %d", n, tc.requests)
			}
		})
	}
}

func TestDockerProxyVolumesFromPuskaetSvoegoDonora(t *testing.T) {
	d := startFakeDockerDaemon(t)
	donors := newUpstreamContainerInspector(d.socket)
	cases := []struct {
		name     string
		body     []byte
		requests int32
	}{
		{"9 донор своего проекта: bind в рабочем каталоге, том local, tmpfs",
			volumesFromBody(t, "app", []string{goodDonorID}), 1},
		{"9 два донора своего проекта", volumesFromBody(t, "app", []string{goodDonorID, goodDonorID2}), 2},
		{"7 суффикс :ro", volumesFromBody(t, "app", []string{goodDonorID + ":ro"}), 1},
		{"7 суффикс :rw", volumesFromBody(t, "app", []string{goodDonorID + ":rw"}), 1},
		// compose при `a` и `a:ro` в одном сервисе шлёт один ID дважды.
		{"дубль донора — один вопрос демону", volumesFromBody(t, "app", []string{goodDonorID, goodDonorID + ":ro"}), 1},
		{"10 VolumesFrom нет", volumesFromBody(t, "app", nil), 0},
		{"10 VolumesFrom null", []byte(`{"Image":"nginx","HostConfig":{"VolumesFrom":null}}`), 0},
		{"10 VolumesFrom пустой", []byte(`{"Image":"nginx","HostConfig":{"VolumesFrom":[]}}`), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := d.inspects.Load()
			got := decideDockerProxy("POST", "/v1.44/containers/create", tc.body, proxyRoots, donors)
			if !got.Allowed {
				t.Fatalf("прокси отбил законный VolumesFrom: %s", got.Reason)
			}
			if n := d.inspects.Load() - before; n != tc.requests {
				t.Fatalf("вопросов демону %d, ожидалось %d", n, tc.requests)
			}
		})
	}
}

// Каждый донор — отдельный inspect с таймаутом 5 с, по очереди: без предела
// одно тело держит create минутами. Отказ — до первого вопроса демону.
func TestDockerProxyVolumesFromPredelDonorov(t *testing.T) {
	d := startFakeDockerDaemon(t)
	donors := newUpstreamContainerInspector(d.socket)
	ids := manyGoodDonorIDs(dockerProxyMaxVolumesFromForTest + 1)

	t.Run("17 доноров — отказ без вопросов демону", func(t *testing.T) {
		before := d.inspects.Load()
		got := decideDockerProxy("POST", "/v1.44/containers/create", volumesFromBody(t, "app", ids), proxyRoots, donors)
		if got.Allowed {
			t.Fatal("прокси пропустил доноров сверх предела")
		}
		if !strings.Contains(got.Reason, "16") {
			t.Fatalf("отказ не называет предел: %q", got.Reason)
		}
		if n := d.inspects.Load() - before; n != 0 {
			t.Fatalf("вопросов демону %d, ожидалось 0", n)
		}
	})

	t.Run("16 своих доноров проходят", func(t *testing.T) {
		before := d.inspects.Load()
		got := decideDockerProxy("POST", "/v1.44/containers/create", volumesFromBody(t, "app", ids[:dockerProxyMaxVolumesFromForTest]), proxyRoots, donors)
		if !got.Allowed {
			t.Fatalf("прокси отбил доноров в пределе: %s", got.Reason)
		}
		if n := d.inspects.Load() - before; n != dockerProxyMaxVolumesFromForTest {
			t.Fatalf("вопросов демону %d, ожидалось %d", n, dockerProxyMaxVolumesFromForTest)
		}
	})
}

// Спросить не у кого — не значит «нарушений нет».
func TestDockerProxyVolumesFromBezOtvetaDemonaOtbit(t *testing.T) {
	body := volumesFromBody(t, "app", []string{goodDonorID})

	t.Run("12 сокета демона нет", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "dpx")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		donors := newUpstreamContainerInspector(filepath.Join(dir, "missing.sock"))
		got := decideDockerProxy("POST", "/v1.44/containers/create", body, proxyRoots, donors)
		if got.Allowed {
			t.Fatal("прокси пропустил VolumesFrom, не дозвавшись демона")
		}
		if !strings.Contains(got.Reason, "демон недоступен") {
			t.Fatalf("отказ не объясняет причину: %q", got.Reason)
		}
	})

	t.Run("13 без инспектора", func(t *testing.T) {
		got := decideDockerProxy("POST", "/v1.44/containers/create", body, proxyRoots)
		if got.Allowed {
			t.Fatal("прокси пропустил VolumesFrom без возможности проверить донора")
		}
		if !strings.Contains(got.Reason, "не у кого") {
			t.Fatalf("отказ не объясняет причину: %q", got.Reason)
		}
	})
}

// 14: прокси целиком. Вопрос о доноре уходит в тот же демон, что и create, а
// плохой донор не даёт create до демона дойти.
func TestDockerProxyVolumesFromSkvoznoj(t *testing.T) {
	d := startFakeDockerDaemon(t)
	proxyPath := filepath.Join(d.dir, "p.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		err := RunDockerProxy(ctx, DockerProxyOptions{
			UpstreamSocket:   d.socket,
			ListenSocket:     proxyPath,
			AllowedBindRoots: proxyRoots,
			SocketUID:        -1,
			SocketGID:        -1,
		})
		if err != nil && ctx.Err() == nil {
			t.Errorf("прокси упал: %v", err)
		}
	}()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", proxyPath)
			},
		},
		Timeout: 10 * time.Second,
	}
	var lastErr error
	for i := 0; i < 100; i++ {
		resp, err := client.Get("http://docker/_ping")
		if err == nil {
			resp.Body.Close()
			lastErr = nil
			break
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("прокси не поднялся: %v", lastErr)
	}

	post := func(body []byte) (int, string) {
		t.Helper()
		resp, err := client.Post("http://docker/v1.44/containers/create", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("запрос через прокси: %v", err)
		}
		defer resp.Body.Close()
		payload, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(payload)
	}

	code, payload := post(volumesFromBody(t, "app", []string{sockDonorID}))
	if code != http.StatusForbidden {
		t.Fatalf("плохой донор получил код %d вместо 403: %s", code, payload)
	}
	if !strings.Contains(payload, "сокет Docker") {
		t.Fatalf("отказ не называет причину: %s", payload)
	}
	if n := d.creates.Load(); n != 0 {
		t.Fatalf("create с плохим донором дошёл до демона (%d раз)", n)
	}

	code, payload = post(volumesFromBody(t, "app", []string{goodDonorID}))
	if code != http.StatusOK {
		t.Fatalf("хороший донор отбит: код %d, %s", code, payload)
	}
	if n := d.creates.Load(); n != 1 {
		t.Fatalf("create с хорошим донором дошёл до демона %d раз вместо одного", n)
	}
}
