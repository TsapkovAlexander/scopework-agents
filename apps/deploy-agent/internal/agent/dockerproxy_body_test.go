package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Разбор тела: tmpfs и тома.
//
// Отдельным файлом от dockerproxy_test.go: там живут правила путей и методов,
// здесь — только то, что прокси читает в теле `containers/create` и
// `volumes/create`. Каждый случай ниже — способ, которым контейнер либо
// занимает память хоста без предела, либо монтирует хранилище не с этого
// сервера, либо каталог хоста в обход проверки привязок.

func TestDockerProxyTmpfsTrebuetPredel(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"Tmpfs без опций", `{"HostConfig":{"Tmpfs":{"/run":""}}}`, "size"},
		{"Tmpfs без size", `{"HostConfig":{"Tmpfs":{"/run":"mode=1777,noexec"}}}`, "size"},
		{"Tmpfs size=0", `{"HostConfig":{"Tmpfs":{"/run":"size=0"}}}`, "size=0"},
		{"Tmpfs в процентах", `{"HostConfig":{"Tmpfs":{"/run":"size=50%"}}}`, "50%"},
		{"Tmpfs сверх предела", `{"HostConfig":{"Tmpfs":{"/run":"size=2g"}}}`, "предел"},
		{"Tmpfs сверх предела байтами", `{"HostConfig":{"Tmpfs":{"/run":"size=1073741824"}}}`, "предел"},
		// Ядро берёт последнее значение: первое в пределе, второе снимает его.
		{"Tmpfs второй size снимает предел", `{"HostConfig":{"Tmpfs":{"/run":"size=64m,size=0"}}}`, "size=0"},
		{"Tmpfs через nr_blocks", `{"HostConfig":{"Tmpfs":{"/run":"size=64m,nr_blocks=0"}}}`, "nr_blocks"},
		{"Tmpfs size мусором", `{"HostConfig":{"Tmpfs":{"/run":"size=0x40000000"}}}`, "size"},
		{"Mounts tmpfs без опций", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run"}]}}`, "size"},
		{"Mounts tmpfs SizeBytes 0", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":0}}]}}`, "size"},
		{"Mounts tmpfs сверх предела", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":2147483648}}]}}`, "предел"},
		{"Mounts tmpfs Options снимают предел", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":67108864,"Options":[["size","0"]]}}]}}`, "size=0"},
		{"Mounts TMPFS заглавными", `{"HostConfig":{"Mounts":[{"Type":"TMPFS","Target":"/run"}]}}`, "size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(tc.body), proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил tmpfs без предела: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

func TestDockerProxyTmpfsVPredeleProhodit(t *testing.T) {
	cases := []struct{ name, body string }{
		{"Tmpfs с size", `{"HostConfig":{"Tmpfs":{"/run":"size=64m,mode=1777"}}}`},
		{"Tmpfs ровно на пределе", `{"HostConfig":{"Tmpfs":{"/tmp":"rw,noexec,nosuid,size=512m"}}}`},
		{"Tmpfs в килобайтах", `{"HostConfig":{"Tmpfs":{"/tmp":"size=65536k"}}}`},
		{"Mounts tmpfs с SizeBytes", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"SizeBytes":67108864,"Mode":1777}}]}}`},
		{"Mounts tmpfs size в Options", `{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/run","TmpfsOptions":{"Options":[["size","64m"],["noexec"]]}}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(tc.body), proxyRoots)
			if !got.Allowed {
				t.Fatalf("прокси отбил tmpfs в пределе: %s", got.Reason)
			}
		})
	}
}

// /dev/shm контейнера — тот же tmpfs в памяти хоста, только размер ему задаёт
// ShmSize числом байт, а не опция size.
func TestDockerProxyShmSizeTrebuetPredel(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"ShmSize 3 ГиБ", `{"HostConfig":{"ShmSize":3221225472}}`, "предел"},
		{"ShmSize на байт сверх предела", `{"HostConfig":{"ShmSize":2147483649}}`, "предел"},
		{"ShmSize отрицательный", `{"HostConfig":{"ShmSize":-1}}`, "отрицательн"},
		// Число вне int64 — не «очень большой предел», а нечитаемое тело.
		{"ShmSize вне int64", `{"HostConfig":{"ShmSize":99999999999999999999}}`, "ShmSize"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(tc.body), proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил /dev/shm сверх предела: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

// 0 и отсутствие поля — не безлимит, в отличие от tmpfs: демон подставляет
// штатные 64 МиБ (moby, daemon_unix.go, adaptContainerSettings).
func TestDockerProxyShmSizeVPredeleProhodit(t *testing.T) {
	cases := []struct{ name, body string }{
		{"ShmSize 1 ГиБ", `{"HostConfig":{"ShmSize":1073741824}}`},
		{"ShmSize ровно на пределе", `{"HostConfig":{"ShmSize":2147483648}}`},
		{"ShmSize 0", `{"HostConfig":{"ShmSize":0}}`},
		{"ShmSize не задан", `{"HostConfig":{"Memory":1073741824}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(tc.body), proxyRoots)
			if !got.Allowed {
				t.Fatalf("прокси отбил /dev/shm в пределе: %s", got.Reason)
			}
		})
	}
}

func TestDockerProxyVolumeNeMontiruetChuzhoeHranilishche(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want string
	}{
		// volumes/create.
		{"драйвер nfs", "/v1.44/volumes/create",
			`{"Name":"x","Driver":"nfs"}`, "Driver nfs"},
		{"local с type=nfs", "/v1.44/volumes/create",
			`{"Name":"x","Driver":"local","DriverOpts":{"type":"nfs","o":"addr=192.0.2.5,rw","device":":/export"}}`, "addr="},
		{"local с type=nfs4 без addr", "/v1.44/volumes/create",
			`{"Name":"x","Driver":"local","DriverOpts":{"type":"nfs4","device":"storage.internal:/export"}}`, "nfs4"},
		{"local с type=cifs", "/v1.44/volumes/create",
			`{"Name":"x","Driver":"local","DriverOpts":{"type":"cifs","o":"username=u","device":"//files.internal/share"}}`, "cifs"},
		{"local с addr в опциях bind", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"none","o":"bind,addr=192.0.2.5","device":"/opt/tracedocs/deploy/apps/site/data"}}`, "addr="},
		// overlay с lowerdir=/ — корень хоста в томе, device при этом не путь.
		{"local с type=overlay", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"overlay","o":"lowerdir=/,upperdir=/tmp/u,workdir=/tmp/w","device":"overlay"}}`, "overlay"},
		// Относительный путь демон разрешает от своего рабочего каталога, то
		// есть от корня хоста: `etc` — это /etc.
		{"local bind относительным путём", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"none","o":"bind","device":"etc"}}`, "device"},
		{"local tmpfs без size", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"tmpfs","device":"tmpfs"}}`, "size"},
		{"local tmpfs сверх предела", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"tmpfs","device":"tmpfs","o":"size=4g"}}`, "предел"},
		{"local с неизвестной опцией", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"Type":"nfs"}}`, "Type"},

		// containers/create: тот же том, объявленный прямо в монтировании.
		// Демон заводит его сам, если тома с таким именем ещё нет.
		{"Mounts: драйвер nfs", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"x","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"nfs"}}}]}}`, "Driver nfs"},
		{"Mounts: local с type=nfs", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"x","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"nfs","o":"addr=192.0.2.5","device":":/export"}}}}]}}`, "addr="},
		{"Mounts: local с type=cifs", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"x","Target":"/data","VolumeOptions":{"DriverConfig":{"Options":{"type":"cifs","device":"//files.internal/share"}}}}]}}`, "cifs"},
		{"Mounts: local bind из корня хоста", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"x","Target":"/host","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/"}}}}]}}`, "вне рабочих каталогов"},
		// Именованный том в Binds заводится драйвером из VolumeDriver.
		{"VolumeDriver nfs у Binds", "/v1.44/containers/create",
			`{"HostConfig":{"Binds":["x:/data"],"VolumeDriver":"nfs"}}`, "VolumeDriver nfs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", tc.path, []byte(tc.body), proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил чужое хранилище: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

func TestDockerProxyVolumeObychnyjProhodit(t *testing.T) {
	cases := []struct{ name, path, body string }{
		{"том без драйвера", "/v1.44/volumes/create", `{"Name":"app_data"}`},
		// Так шлёт compose: драйвер назван, опций нет, метки проекта.
		{"том compose", "/v1.44/volumes/create",
			`{"Name":"app_data","Driver":"local","DriverOpts":{},"Labels":{"com.docker.compose.project":"app"}}`},
		{"local tmpfs с size", "/v1.44/volumes/create",
			`{"Name":"cache","Driver":"local","DriverOpts":{"type":"tmpfs","device":"tmpfs","o":"size=64m,uid=1000"}}`},
		{"local tmpfs с size без device", "/v1.44/volumes/create",
			`{"Name":"cache","Driver":"local","DriverOpts":{"type":"tmpfs","o":"size=64m"}}`},
		// Для type=none bind законен: device здесь проверяет checkBindSource.
		{"local bind в каталог агента", "/v1.44/volumes/create",
			`{"Name":"d","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/opt/tracedocs/deploy/apps/site/data"}}`},
		{"Mounts: именованный том", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"app_data","Target":"/data"}]}}`},
		{"Mounts: том с драйвером local", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"app_data","Target":"/data","VolumeOptions":{"NoCopy":true,"DriverConfig":{"Name":"local"}}}]}}`},
		{"Mounts: local bind в каталог агента", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Source":"d","Target":"/data","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/opt/tracedocs/deploy/apps/site/data"}}}}]}}`},
		{"VolumeDriver local", "/v1.44/containers/create",
			`{"HostConfig":{"Binds":["app_data:/data"],"VolumeDriver":"local"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", tc.path, []byte(tc.body), proxyRoots)
			if !got.Allowed {
				t.Fatalf("прокси отбил обычный том: %s", got.Reason)
			}
		})
	}
}

// tmpfs, который на деле привязка каталога хоста.
//
// Драйвер local отдаёт `o` в mount(2) флагами, а при MS_BIND ядро не смотрит
// ни на тип, ни на data: `type=tmpfs,o=bind,device=/` — это корень хоста на
// запись внутри контейнера, а не tmpfs. rbind — то же рекурсивно, move уносит
// чужое монтирование хоста, remount меняет флаги уже смонтированного.
func TestDockerProxyTmpfsNeMontiruetKatalogHosta(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want string
	}{
		{"volumes/create tmpfs+bind device=/", "/v1.44/volumes/create",
			`{"Name":"x","Driver":"local","DriverOpts":{"type":"tmpfs","o":"bind,size=64m","device":"/"}}`, "bind"},
		{"volumes/create tmpfs+rbind device=/etc", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"tmpfs","o":"rbind,size=1m","device":"/etc"}}`, "rbind"},
		{"volumes/create tmpfs+move", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"tmpfs","o":"size=1m,move","device":"tmpfs"}}`, "move"},
		{"volumes/create tmpfs+remount", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"tmpfs","o":"size=1m,remount","device":"tmpfs"}}`, "remount"},
		{"volumes/create tmpfs+BIND верхним регистром", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"TMPFS","o":"size=1m, BIND ","device":"tmpfs"}}`, "BIND"},
		{"volumes/create tmpfs device=/ без bind", "/v1.44/volumes/create",
			`{"Name":"x","DriverOpts":{"type":"tmpfs","o":"size=64m","device":"/"}}`, "device"},
		{"Mounts DriverConfig tmpfs+bind", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/h","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"tmpfs","o":"bind,size=64m","device":"/"}}}}]}}`, "bind"},
		{"HostConfig.Tmpfs с bind", "/v1.44/containers/create",
			`{"HostConfig":{"Tmpfs":{"/t":"bind,size=64m"}}}`, "bind"},
		{"HostConfig.Tmpfs с rbind", "/v1.44/containers/create",
			`{"HostConfig":{"Tmpfs":{"/t":"size=64m,rbind"}}}`, "rbind"},
		{"Mounts tmpfs с bind в Options", "/v1.44/containers/create",
			`{"HostConfig":{"Mounts":[{"Type":"tmpfs","Target":"/t","TmpfsOptions":{"SizeBytes":67108864,"Options":[["bind"]]}}]}}`, "bind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", tc.path, []byte(tc.body), proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил привязку каталога хоста под видом tmpfs: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

// Привязка каталога через символическую ссылку.
//
// Лексически путь лежит внутри рабочего каталога, а ядро при монтировании идёт
// по ссылке: в git-репозитории приложения может лежать `data -> /`. Раскладка
// строится на настоящей файловой системе — подделать раскрытие ссылок нечем.
type bindSymlinkLayout struct {
	tmp, root, outside string
}

func newBindSymlinkLayout(t *testing.T) bindSymlinkLayout {
	t.Helper()
	tmp := t.TempDir()
	l := bindSymlinkLayout{
		tmp:     tmp,
		root:    filepath.Join(tmp, "deploy"),
		outside: filepath.Join(tmp, "outside"),
	}
	for _, dir := range []string{
		filepath.Join(l.root, "apps", "site", "data"),
		filepath.Join(l.root, "fake"),
		l.outside,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Файл с именем сокета внутри рабочего каталога: ссылка на него лексически
	// невинна, раскрытая — ведёт в «сокет Docker».
	if err := os.WriteFile(filepath.Join(l.root, "fake", "docker.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		filepath.Join(l.root, "out"):      l.outside,
		filepath.Join(l.root, "hostroot"): "/",
		filepath.Join(l.root, "varrun"):   "/var/run",
		filepath.Join(l.root, "sock"):     filepath.Join(l.root, "fake", "docker.sock"),
		filepath.Join(l.root, "dangling"): filepath.Join(l.outside, "nope"),
		filepath.Join(l.root, "inner"):    filepath.Join(l.root, "apps", "site"),
		filepath.Join(tmp, "link"):        l.root,
	}
	for link, target := range links {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	return l
}

func bindsBody(t *testing.T, source string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"Image":      "nginx",
		"HostConfig": map[string]any{"Binds": []string{source + ":/data:rw"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDockerProxyBindSymlinkNeVyvoditNaruzhu(t *testing.T) {
	l := newBindSymlinkLayout(t)
	roots := []string{l.root}
	mountsBody := func(source string) []byte {
		body, _ := json.Marshal(map[string]any{
			"HostConfig": map[string]any{"Mounts": []map[string]string{
				{"Type": "bind", "Source": source, "Target": "/data"},
			}},
		})
		return body
	}
	deviceBody := func(device string) []byte {
		body, _ := json.Marshal(map[string]any{
			"Name":       "x",
			"Driver":     "local",
			"DriverOpts": map[string]string{"type": "none", "o": "bind", "device": device},
		})
		return body
	}
	cases := []struct {
		name string
		path string
		body []byte
		want string
	}{
		{"а ссылка наружу", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "out")), "вне рабочих каталогов"},
		{"а ссылка наружу, путь под ней", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "out", "x")), "вне рабочих каталогов"},
		{"б ссылка на корень хоста, /etc", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "hostroot", "etc")), "вне рабочих каталогов"},
		// Хвоста нет на диске: раскрывается существующая часть пути.
		{"б ссылка наружу, несуществующий хвост", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "out", "etc", "nested")), "вне рабочих каталогов"},
		{"в ссылка на /var/run, путь docker.sock", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "varrun", "docker.sock")), "сокет Docker"},
		// Лексически ни рабочий каталог не покинут, ни сокет не назван.
		{"в ссылка на файл docker.sock", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "sock")), "сокет Docker"},
		// Docker создал бы недостающий источник через MkdirAll — по ссылке, наружу.
		{"г висячая ссылка, путь под ней", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "dangling", "sub")), "не раскрывается"},
		{"г висячая ссылка", "/v1.44/containers/create",
			bindsBody(t, filepath.Join(l.root, "dangling")), "не раскрывается"},
		{"з Mounts bind по ссылке наружу", "/v1.44/containers/create",
			mountsBody(filepath.Join(l.root, "out")), "вне рабочих каталогов"},
		{"з volumes/create device по ссылке наружу", "/v1.44/volumes/create",
			deviceBody(filepath.Join(l.root, "out")), "вне рабочих каталогов"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", tc.path, tc.body, roots)
			if got.Allowed {
				t.Fatalf("прокси пропустил привязку по ссылке наружу: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

// Обратная сторона: раскрытие ссылок не должно отбивать законные привязки —
// ни ещё не созданный каталог (Docker создаст его сам), ни рабочий каталог,
// который сам лежит за ссылкой (/var -> /private/var, /opt на своём разделе).
func TestDockerProxyBindSymlinkVnutriProhodit(t *testing.T) {
	l := newBindSymlinkLayout(t)
	cases := []struct {
		name   string
		roots  []string
		source string
	}{
		{"д ссылка внутрь рабочего каталога", []string{l.root}, filepath.Join(l.root, "inner", "data")},
		{"е несуществующий путь внутри", []string{l.root}, filepath.Join(l.root, "apps", "new", "data")},
		{"ж корень через ссылку, источник реальным путём", []string{filepath.Join(l.tmp, "link")},
			filepath.Join(l.root, "apps", "site", "data")},
		{"ж корень реальным путём, источник через ссылку", []string{l.root},
			filepath.Join(l.tmp, "link", "apps", "site", "data")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", bindsBody(t, tc.source), tc.roots)
			if !got.Allowed {
				t.Fatalf("прокси отбил законную привязку %s: %s", tc.source, got.Reason)
			}
		})
	}
}

// Сегмент `..` в источнике привязки.
//
// filepath.Clean убирает `l/..` лексически, а ядро разрешает `..` ПОСЛЕ ссылки:
// при `l -> <вне>/deep` путь `<корень>/l/../secret` ведёт в `<вне>/secret`.
// Демон источник не очищает (вживую Mounts[].Source = `/tmp/zqx/l/../x`), так
// что проверка по очищенной строке смотрела бы не туда, куда смонтирует ядро.
func TestDockerProxyBindDotDotPosleSsylkiOtbit(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "deploy")
	outside := filepath.Join(tmp, "outside")
	for _, dir := range []string{root, filepath.Join(outside, "deep"), filepath.Join(outside, "secret")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(outside, "deep"), filepath.Join(root, "l")); err != nil {
		t.Fatal(err)
	}
	// Строкой, а не filepath.Join: Join очистил бы `..` так же, как прокси.
	src := root + "/l/../secret"
	if _, err := os.Stat(filepath.Join(outside, "secret")); err != nil {
		t.Fatal(err)
	}
	mountsBody, _ := json.Marshal(map[string]any{"HostConfig": map[string]any{"Mounts": []map[string]string{
		{"Type": "bind", "Source": src, "Target": "/h"},
	}}})
	deviceBody, _ := json.Marshal(map[string]any{
		"Name": "x", "Driver": "local",
		"DriverOpts": map[string]string{"type": "none", "o": "bind", "device": src},
	})
	mountDeviceBody, _ := json.Marshal(map[string]any{"HostConfig": map[string]any{"Mounts": []map[string]any{
		{"Type": "volume", "Source": "x", "Target": "/h", "VolumeOptions": map[string]any{
			"DriverConfig": map[string]any{"Name": "local", "Options": map[string]string{"type": "none", "o": "bind", "device": src}},
		}},
	}}})
	cases := []struct {
		name string
		path string
		body []byte
	}{
		{"Binds l/../secret", "/v1.44/containers/create", bindsBody(t, src)},
		{"Mounts bind l/../secret", "/v1.44/containers/create", mountsBody},
		{"volumes/create device l/../secret", "/v1.44/volumes/create", deviceBody},
		{"Mounts volume device l/../secret", "/v1.44/containers/create", mountDeviceBody},
		{"Binds .. в конце", "/v1.44/containers/create", bindsBody(t, root+"/l/..")},
		{"Binds .. со слэшем в конце", "/v1.44/containers/create", bindsBody(t, root+"/l/../")},
		{"Binds .. сразу за корнем ФС", "/v1.44/containers/create", bindsBody(t, "/.."+root)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", tc.path, tc.body, []string{root})
			if got.Allowed {
				t.Fatalf("прокси пропустил источник с `..` после ссылки: %s", tc.body)
			}
			if !strings.Contains(got.Reason, "..") {
				t.Fatalf("отказ не называет `..`: %q", got.Reason)
			}
		})
	}
}

// `..` — сегмент, а не подстрока: имя каталога с двумя точками законно.
func TestDockerProxyBindDvePointsVImeniProhodit(t *testing.T) {
	root := t.TempDir()
	for _, src := range []string{
		root + "/a..b",
		root + "/a..b/data",
		root + "/..hidden",
		root + "/tail..",
		root + "/a/./b",
	} {
		t.Run(src, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", bindsBody(t, src), []string{root})
			if !got.Allowed {
				t.Fatalf("прокси отбил законное имя %s: %s", src, got.Reason)
			}
		})
	}
}

// Поля HostConfig на верхнем уровне тела `create`.
//
// Демоны до 27.0 (moby runconfig.ContainerConfigWrapper) встраивали HostConfig
// в тело без тега: без ключа `HostConfig` весь HostConfig брался с верхнего
// уровня, а с ключом оттуда подмешивались VolumeDriver и ресурсы. Прокси
// читает только `HostConfig`, и тело без него проходило целиком. Совпадение
// ключей — без учёта регистра, как в encoding/json у демона.
func TestDockerProxyHostConfigNaVerhnemUrovneOtbit(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"Binds с корнем хоста", `{"Image":"alpine","Binds":["/:/h"]}`, "Binds"},
		{"Privileged", `{"Image":"alpine","Privileged":true}`, "Privileged"},
		{"binds строчными", `{"Image":"alpine","binds":["/:/h"]}`, "binds"},
		{"VolumesFrom", `{"Image":"alpine","VolumesFrom":["coolify"]}`, "VolumesFrom"},
		{"Mounts", `{"Image":"alpine","Mounts":[{"Type":"bind","Source":"/","Target":"/h"}]}`, "Mounts"},
		{"CapAdd", `{"Image":"alpine","CapAdd":["SYS_ADMIN"]}`, "CapAdd"},
		{"Devices", `{"Image":"alpine","Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/sda"}]}`, "Devices"},
		{"Memory из Resources", `{"Image":"alpine","Memory":1}`, "Memory"},
		{"KernelMemory — поле старых демонов", `{"Image":"alpine","KernelMemory":1}`, "KernelMemory"},
		{"Capabilities — поле 19.03", `{"Image":"alpine","Capabilities":["CAP_SYS_ADMIN"]}`, "Capabilities"},
		// Рядом с HostConfig демоны 20.10–26 подмешивают VolumeDriver сверху
		// во внутренний HostConfig, а прокси проверяет только внутренний.
		{"VolumeDriver рядом с HostConfig", `{"Image":"alpine","VolumeDriver":"nfs","HostConfig":{"Binds":["data:/d"]}}`, "VolumeDriver"},
		// encoding/json сворачивает ſ (U+017F) в s, а K (U+212A) в k.
		{"Binds с длинной s", `{"Image":"alpine","Bindſ":["/:/h"]}`, "Bindſ"},
		// Кельвин задан escape-последовательностью Go: в теле лежат байты
		// U+212A, а не JSON-экранирование.
		{"KernelMemory со знаком Кельвина", "{\"Image\":\"alpine\",\"\u212Aernelmemory\":1}", "\u212Aernelmemory"},
		// JSON-экранирование ключа: в теле нет байтов `Binds`, их даёт разбор.
		{"ключ экранированием", `{"Image":"alpine","\u0042inds":["/:/h"]}`, "Binds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(tc.body), proxyRoots)
			if got.Allowed {
				t.Fatalf("прокси пропустил поле HostConfig на верхнем уровне: %s", tc.body)
			}
			if !strings.Contains(got.Reason, tc.want) || !strings.Contains(got.Reason, "верхнем уровне") {
				t.Fatalf("отказ не объясняет причину: %q не содержит %q", got.Reason, tc.want)
			}
		})
	}
}

// Обратная сторона: тело, снятое с живого compose v5.3.1 (Docker 29.6.2) —
// порты, окружение, метки, healthcheck, том, tmpfs, предел памяти, — и все
// законные поля Config верхнего уровня, включая MacAddress старых API.
// Ложный отказ здесь — это отказ каждого развёртывания.
func TestDockerProxyTeloComposeProhodit(t *testing.T) {
	composeBody := `{"Hostname":"","Domainname":"","User":"","AttachStdin":false,"AttachStdout":true,"AttachStderr":true,` +
		`"ExposedPorts":{"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["APP_ENV=production"],` +
		`"Cmd":["sleep","300"],"Healthcheck":{"Test":["CMD","true"],"Interval":30000000000},"Image":"alpine:latest",` +
		`"Volumes":null,"WorkingDir":"/data","Entrypoint":null,"Labels":{"app.tier":"web",` +
		`"com.docker.compose.config-hash":"5f8d1129f5cd9fa7bd4add205ddc3f2d313a0398eff77665f50266aa031ebf13",` +
		`"com.docker.compose.container-number":"1","com.docker.compose.depends_on":"",` +
		`"com.docker.compose.image":"sha256:33bee74c45f307e3268adc2010c0f55c48e7a6041e12cd12432bb1a46e498e43",` +
		`"com.docker.compose.oneoff":"False","com.docker.compose.project":"app",` +
		`"com.docker.compose.project.config_files":"/opt/tracedocs/deploy/apps/app/compose.yml",` +
		`"com.docker.compose.project.working_dir":"/opt/tracedocs/deploy/apps/app",` +
		`"com.docker.compose.service":"web","com.docker.compose.version":"5.3.1"},` +
		`"HostConfig":{"Binds":["app_data:/data:rw"],"ContainerIDFile":"","LogConfig":{"Type":"","Config":null},` +
		`"NetworkMode":"app_default","PortBindings":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18089"}]},` +
		`"RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"",` +
		`"VolumesFrom":null,"ConsoleSize":[0,0],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"","Dns":null,` +
		`"DnsOptions":null,"DnsSearch":null,"ExtraHosts":[],"GroupAdd":null,"IpcMode":"","Cgroup":"","Links":null,` +
		`"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,` +
		`"SecurityOpt":null,"Tmpfs":{"/run":"size=64m"},"UTSMode":"","UsernsMode":"","ShmSize":0,"Isolation":"",` +
		`"CpuShares":0,"Memory":134217728,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":null,` +
		`"BlkioDeviceReadBps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteIOps":null,` +
		`"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"",` +
		`"Devices":null,"DeviceCgroupRules":null,"DeviceRequests":null,"MemoryReservation":0,"MemorySwap":0,` +
		`"MemorySwappiness":null,"OomKillDisable":false,"PidsLimit":null,"Ulimits":null,"CpuCount":0,"CpuPercent":0,` +
		`"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":null,"ReadonlyPaths":null},` +
		`"NetworkingConfig":{"EndpointsConfig":{"app_default":{"IPAMConfig":null,"Links":null,` +
		`"Aliases":["app-web-1","web"],"DriverOpts":null,"GwPriority":0,"NetworkID":"","EndpointID":"","Gateway":"",` +
		`"IPAddress":"","MacAddress":"","IPPrefixLen":0,"IPv6Gateway":"","GlobalIPv6Address":"",` +
		`"GlobalIPv6PrefixLen":0,"DNSNames":null}}}}`
	// Поля Config (moby api/types/container/config.go, 19.03 — master) и
	// Cpuset — собственное поле обёртки 20.10–26.
	everyConfigField := `{"Hostname":"h","Domainname":"d","User":"1000","AttachStdin":false,"AttachStdout":true,` +
		`"AttachStderr":true,"ExposedPorts":{"80/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,` +
		`"Env":["A=1"],"Cmd":["true"],"Healthcheck":{"Test":["NONE"]},"ArgsEscaped":false,"Image":"alpine",` +
		`"Volumes":{"/data":{}},"WorkingDir":"/","Entrypoint":["sh"],"NetworkDisabled":false,"MacAddress":"",` +
		`"OnBuild":null,"Labels":{"a":"b"},"StopSignal":"SIGTERM","StopTimeout":10,"Shell":["sh","-c"],` +
		`"Cpuset":"","NetworkingConfig":{},"HostConfig":{"NetworkMode":"app_default"}}`

	for name, body := range map[string]string{"тело compose": composeBody, "все поля Config": everyConfigField} {
		t.Run(name, func(t *testing.T) {
			got := decideDockerProxy("POST", "/v1.44/containers/create", []byte(body), proxyRoots)
			if !got.Allowed {
				t.Fatalf("прокси отбил законное тело: %s", got.Reason)
			}
		})
	}
}
