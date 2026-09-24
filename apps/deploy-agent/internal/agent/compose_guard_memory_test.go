package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// tmpfs и /dev/shm в описании стека.
//
// Прокси сокета Docker отбивает tmpfs без предела и /dev/shm сверх 2 ГиБ кодом
// 403 на выкате. Guard обязан сказать то же при проверке текста — иначе стек
// проходит проверку и падает посреди `docker compose up`. Формы ниже — ровно
// то, что отдаёт `docker compose config --format json` (compose v5.3.1).

func TestComposeGuardTmpfsTrebuetPredel(t *testing.T) {
	cases := []struct {
		name string
		svc  string
		want string
	}{
		{"короткая форма без опций", `{"tmpfs":["/run"]}`, "tmpfs /run: не задан size"},
		{"короткая форма без size", `{"tmpfs":["/run:mode=1777,noexec"]}`, "не задан size"},
		{"короткая форма size=0", `{"tmpfs":["/run:size=0"]}`, "size=0"},
		{"короткая форма в процентах", `{"tmpfs":["/run:size=50%"]}`, "50%"},
		{"короткая форма сверх предела", `{"tmpfs":["/run:size=2g"]}`, "предел"},
		{"короткая форма: второй size снимает предел", `{"tmpfs":["/run:size=64m,size=0"]}`, "size=0"},
		{"короткая форма с bind", `{"tmpfs":["/t:bind,size=64m"]}`, "bind"},
		{"длинная форма без tmpfs.size", `{"volumes":[{"type":"tmpfs","target":"/y"}]}`, "volumes tmpfs /y: не задан size"},
		{"длинная форма сверх предела", `{"volumes":[{"type":"tmpfs","target":"/y","tmpfs":{"size":"1073741824"}}]}`, "предел"},
		{"длинная форма числом сверх предела", `{"volumes":[{"type":"tmpfs","target":"/y","tmpfs":{"size":1073741824}}]}`, "предел"},
		{"длинная форма size мусором", `{"volumes":[{"type":"tmpfs","target":"/y","tmpfs":{"size":"64m"}}]}`, "не разобран"},
		{"shm_size 3 ГиБ", `{"shm_size":"3221225472"}`, "shm_size"},
		{"shm_size числом 3 ГиБ", `{"shm_size":3221225472}`, "shm_size"},
		{"shm_size вне int64", `{"shm_size":"99999999999999999999"}`, "shm_size не разобран"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := check(t, `{"services":{"app":`+tc.svc+`}}`)
			if len(v) == 0 {
				t.Fatalf("guard пропустил память хоста без предела: %s", tc.svc)
			}
			joined := make([]string, 0, len(v))
			for _, x := range v {
				joined = append(joined, x.String())
			}
			got := strings.Join(joined, "; ")
			if !strings.Contains(got, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got, tc.want)
			}
			if !strings.Contains(got, "сервис app") {
				t.Fatalf("отказ не называет сервис: %q", got)
			}
		})
	}
}

func TestComposeGuardTmpfsVPredeleProhodit(t *testing.T) {
	cases := []struct{ name, svc string }{
		{"короткая форма с size", `{"tmpfs":["/tmp:size=64m,mode=1777","/run:size=512m"]}`},
		{"длинная форма с size", `{"volumes":[{"type":"tmpfs","target":"/x","tmpfs":{"size":"67108864","mode":1777}}]}`},
		{"длинная форма числом", `{"volumes":[{"type":"tmpfs","target":"/x","tmpfs":{"size":67108864}}]}`},
		{"shm_size 256 МиБ", `{"shm_size":"268435456"}`},
		{"shm_size ровно 2 ГиБ", `{"shm_size":"2147483648"}`},
		{"shm_size не задан", `{"image":"nginx"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v := check(t, `{"services":{"app":`+tc.svc+`}}`); len(v) != 0 {
				t.Fatalf("guard отклонил память в пределе: %v", v)
			}
		})
	}
}

// Guard и прокси — одна политика. Для каждой формы: вердикт guard по тексту
// совпадает с вердиктом прокси по телу, которое compose из этого текста
// пошлёт демону (HostConfig.Tmpfs, Mounts[].TmpfsOptions, HostConfig.ShmSize —
// снято с живого compose v5.3.1). Расхождение в любую сторону — либо стек,
// падающий на выкате, либо guard, отбивающий то, что прокси пропустил бы.
func TestComposeGuardPamyatSoglasovanaSProxy(t *testing.T) {
	type form struct {
		name string
		svc  string
		body map[string]any
	}
	var forms []form
	for _, opts := range []string{"", "size=64m", "size=512m", "size=513m", "size=0", "size=50%",
		"mode=1777", "size=64m,size=0", "bind,size=1m", "size=64m,nr_blocks=0"} {
		entry := "/run"
		if opts != "" {
			entry += ":" + opts
		}
		svc, _ := json.Marshal(map[string]any{"tmpfs": []string{entry}})
		forms = append(forms, form{"tmpfs " + entry, string(svc),
			map[string]any{"Tmpfs": map[string]string{"/run": opts}}})
	}
	for _, size := range []int64{0, 1000, 67108864, 536870912, 536870913, 1 << 40} {
		vol := map[string]any{"type": "tmpfs", "target": "/y"}
		mount := map[string]any{"Type": "tmpfs", "Target": "/y"}
		if size != 0 {
			vol["tmpfs"] = map[string]any{"size": memItoa(size)}
			mount["TmpfsOptions"] = map[string]any{"SizeBytes": size}
		}
		svc, _ := json.Marshal(map[string]any{"volumes": []any{vol}})
		forms = append(forms, form{"volumes tmpfs size " + memItoa(size), string(svc),
			map[string]any{"Mounts": []any{mount}}})
	}
	for _, shm := range []int64{0, 268435456, 2147483648, 2147483649, 3221225472} {
		svc, _ := json.Marshal(map[string]any{"shm_size": memItoa(shm)})
		forms = append(forms, form{"shm_size " + memItoa(shm), string(svc),
			map[string]any{"ShmSize": shm}})
	}

	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			guardOK := len(check(t, `{"services":{"app":`+f.svc+`}}`)) == 0
			body, _ := json.Marshal(map[string]any{"Image": "nginx", "HostConfig": f.body})
			proxy := decideDockerProxy("POST", "/v1.44/containers/create", body, proxyRoots)
			if guardOK != proxy.Allowed {
				t.Fatalf("guard и прокси разошлись: guard пропускает=%v, прокси пропускает=%v (%s)",
					guardOK, proxy.Allowed, proxy.Reason)
			}
		})
	}
}

func memItoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
