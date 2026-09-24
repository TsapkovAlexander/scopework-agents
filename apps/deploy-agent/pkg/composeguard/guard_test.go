package composeguard

import (
	"strings"
	"testing"
)

const allowedRoot = "/opt/tracedocs/deploy/repos/backend"
const appRoot = "/opt/tracedocs/deploy/apps/backend"

func roots() []string { return []string{allowedRoot, appRoot} }

func check(t *testing.T, json string) []Violation {
	t.Helper()
	return checkAdopting(t, json, nil)
}

// checkAdopting — то же, но с разрешёнными именами томов: так проверяется
// перехват работающего стека (0206).
func checkAdopting(t *testing.T, json string, adopted []string) []Violation {
	t.Helper()
	v, err := Check([]byte(json), Options{Roots: roots(), AdoptedVolumes: adopted})
	if err != nil {
		t.Fatalf("разбор не удался: %v", err)
	}
	return v
}

// Обычный стек из репозитория проходит: именованные тома, зависимости.
// Порты наружу не публикуются — приложение слушает, прокси ходит к нему по
// имени контейнера в сети edge; прямой ports для недоверенного стека запрещён
// (см. TestComposeGuardBlocksPorts).
func TestComposeGuardAllowsOrdinaryStack(t *testing.T) {
	v := check(t, `{"services":{"app":{
		"image":"node:22",
		"volumes":[{"type":"volume","source":"data","target":"/data"}]
	}},"volumes":{"data":{}}}`)
	if len(v) != 0 {
		t.Fatalf("обычный стек отклонён: %v", v)
	}
}

// Относительные пути внутри рабочей копии — законный и частый случай.
func TestComposeGuardAllowsBindInsideProject(t *testing.T) {
	v := check(t, `{"services":{"app":{"volumes":[
		{"type":"bind","source":"`+allowedRoot+`/data","target":"/data"},
		{"type":"bind","source":"`+appRoot+`/.env","target":"/app/.env"}
	]}}}`)
	if len(v) != 0 {
		t.Fatalf("монтирование внутри проекта отклонено: %v", v)
	}
}

// Ровно тот сценарий, ради которого проверка написана: одна строка в compose
// клиента даёт ему ключ агента и токены реестров проекта.
func TestComposeGuardBlocksStateDirMount(t *testing.T) {
	v := check(t, `{"services":{"x":{"volumes":[
		{"type":"bind","source":"/etc/tracedocs/deploy","target":"/s"}
	]}}}`)
	if len(v) != 1 || !strings.Contains(v[0].Reason, "/etc/tracedocs/deploy") {
		t.Fatalf("монтирование каталога состояния не заблокировано: %v", v)
	}
}

// docker.sock — это root на хосте.
func TestComposeGuardBlocksDockerSocket(t *testing.T) {
	v := check(t, `{"services":{"x":{"volumes":[
		{"type":"bind","source":"/var/run/docker.sock","target":"/var/run/docker.sock"}
	]}}}`)
	if len(v) == 0 {
		t.Fatal("монтирование docker.sock не заблокировано")
	}
}

func TestComposeGuardBlocksEscalation(t *testing.T) {
	cases := map[string]string{
		"privileged":   `{"services":{"x":{"privileged":true}}}`,
		"cap_add":      `{"services":{"x":{"cap_add":["SYS_ADMIN"]}}}`,
		"devices":      `{"services":{"x":{"devices":["/dev/sda:/dev/sda"]}}}`,
		"network host": `{"services":{"x":{"network_mode":"host"}}}`,
		"pid host":     `{"services":{"x":{"pid":"host"}}}`,
		"ipc host":     `{"services":{"x":{"ipc":"host"}}}`,
		"userns host":  `{"services":{"x":{"userns_mode":"host"}}}`,
		"seccomp off":  `{"services":{"x":{"security_opt":["seccomp:unconfined"]}}}`,
		"apparmor off": `{"services":{"x":{"security_opt":["apparmor=unconfined"]}}}`,
	}

	for name, body := range cases {
		if v := check(t, body); len(v) == 0 {
			t.Errorf("%s: не заблокировано", name)
		}
	}
}

// Соседнее приложение того же проекта — тоже чужой каталог: если приложение
// скомпрометируют через дыру в нём самом, атакующий не должен получить .env
// соседа с паролем его базы.
func TestComposeGuardBlocksSiblingApp(t *testing.T) {
	v := check(t, `{"services":{"x":{"volumes":[
		{"type":"bind","source":"/opt/tracedocs/deploy/apps/other/.env","target":"/e"}
	]}}}`)
	if len(v) == 0 {
		t.Fatal("монтирование каталога соседнего приложения не заблокировано")
	}
}

// Префикс пути без разделителя пропустил бы каталог с похожим именем.
func TestIsPathAllowedRespectsBoundary(t *testing.T) {
	if IsPathAllowedIn(appRoot+"-evil/x", roots(), nil) {
		t.Error("каталог с похожим именем принят за внутренний")
	}
	if IsPathAllowedIn(appRoot+"/../other/.env", roots(), nil) {
		t.Error("выход через .. не обнаружен")
	}
	if !IsPathAllowedIn(appRoot, roots(), nil) {
		t.Error("сам корень должен быть разрешён")
	}
	if IsPathAllowedIn("", roots(), nil) {
		t.Error("пустой путь принят")
	}
}

// Стек без сервисов до docker доходить не должен: это либо пустой файл, либо
// не тот файл.
func TestComposeGuardRejectsEmptyModel(t *testing.T) {
	if _, err := Check([]byte(`{"services":{}}`), Options{Roots: roots()}); err == nil {
		t.Fatal("стек без сервисов принят")
	}
	if _, err := Check([]byte(`не json`), Options{Roots: roots()}); err == nil {
		t.Fatal("нечитаемый вывод принят")
	}
}

// Нарушение обязано называть сервис: «стек отклонён» без указания, чем именно,
// починить невозможно.
func TestComposeViolationNamesService(t *testing.T) {
	v := check(t, `{"services":{"worker":{"privileged":true}}}`)
	if len(v) != 1 || !strings.Contains(v[0].String(), "worker") {
		t.Fatalf("в тексте нарушения нет имени сервиса: %v", v)
	}
}

// CRITICAL: bind, спрятанный в driver_opts верхнеуровневого тома. Сервис
// ссылается на «именованный» том (в нормализованном виде type=volume), а сам
// том определён как local bind на путь хоста. Без проверки секции volumes
// это монтировало бы / хоста в контейнер — root-эквивалент.
func TestComposeGuardBlocksLocalBindVolume(t *testing.T) {
	v := check(t, `{"services":{"app":{"volumes":[{"type":"volume","source":"hostroot","target":"/host"}]}},
		"volumes":{"hostroot":{"driver":"local","driver_opts":{"type":"none","device":"/","o":"bind"}}}}`)
	if len(v) == 0 {
		t.Fatal("том с driver_opts (local bind) не заблокирован — монтирование пути хоста")
	}
}

// Внешний драйвер тома тоже способен дотянуться до хостовых/сетевых ресурсов.
func TestComposeGuardBlocksExternalAndForeignDriverVolumes(t *testing.T) {
	if v := check(t, `{"services":{"app":{"image":"x"}},"volumes":{"v":{"external":true}}}`); len(v) == 0 {
		t.Error("external-том не заблокирован")
	}
	if v := check(t, `{"services":{"app":{"image":"x"}},"volumes":{"v":{"driver":"some-plugin"}}}`); len(v) == 0 {
		t.Error("том со сторонним драйвером не заблокирован")
	}
	// Обычный именованный том (без driver_opts, локальный) обязан проходить.
	if v := check(t, `{"services":{"app":{"image":"x"}},"volumes":{"data":{"driver":"local"}}}`); len(v) != 0 {
		t.Errorf("обычный локальный том отклонён: %v", v)
	}
	if v := check(t, `{"services":{"app":{"image":"x"}},"volumes":{"data":{}}}`); len(v) != 0 {
		t.Errorf("пустой именованный том отклонён: %v", v)
	}
}

// CRITICAL: подмена тома через поле name верхнеуровневого определения.
//
// Проверка external запрещает том, «определённый вне стека». Поле name даёт
// РОВНО ТО ЖЕ: `stolen: {name: neighbour_db-data}` монтирует данные соседнего
// приложения того же хоста, а запись сервиса при этом нормализуется в
// безобидное `{type: volume, source: stolen}` — по ней отличить нельзя.
//
// Сверка идёт со значением, которое compose проставил бы сам: имя проекта плюс
// ключ тома. Именно так выглядит вывод `docker compose config` — он ВСЕГДА
// пишет name каждому тому, поэтому запретить поле целиком нельзя, можно только
// потребовать, чтобы автор его не переопределил.
func TestComposeGuardBlocksForeignVolumeName(t *testing.T) {
	// Так выглядит нормализованный вид настоящей атаки: data проставлен
	// автоматически, stolen — вручную, на тома соседа.
	v := check(t, `{"name":"backend","services":{"app":{"volumes":[
		{"type":"volume","source":"data","target":"/d"},
		{"type":"volume","source":"stolen","target":"/s"}
	]}},"volumes":{
		"data":{"name":"backend_data"},
		"stolen":{"name":"neighbour_db-data"}
	}}`)
	if len(v) != 1 {
		t.Fatalf("ожидалось ровно одно нарушение (том stolen), получено: %v", v)
	}
	if !strings.Contains(v[0].Reason, "neighbour_db-data") {
		t.Fatalf("в причине нет подставленного имени: %v", v[0])
	}
	if !strings.Contains(v[0].Service, "stolen") {
		t.Fatalf("нарушение приписано не тому тому: %v", v[0])
	}
}

// Имя, которое compose проставляет сам, обязано проходить — иначе отклонялся бы
// КАЖДЫЙ стек: `docker compose config` пишет name всем томам без исключения.
func TestComposeGuardAllowsGeneratedVolumeName(t *testing.T) {
	v := check(t, `{"name":"backend","services":{"app":{"image":"x"}},
		"volumes":{"data":{"name":"backend_data"},"cache":{"name":"backend_cache"}}}`)
	if len(v) != 0 {
		t.Fatalf("автоматически проставленное имя тома отклонено: %v", v)
	}
}

// Имя есть, а имени проекта нет — сверять не с чем. Отказ, а не пропуск:
// «не смогли проверить» не то же самое, что «безопасно».
func TestComposeGuardBlocksVolumeNameWithoutProject(t *testing.T) {
	v := check(t, `{"services":{"app":{"image":"x"}},"volumes":{"data":{"name":"backend_data"}}}`)
	if len(v) != 1 {
		t.Fatalf("имя тома без имени проекта не отклонено: %v", v)
	}
}

// Близкое, но чужое имя: префикс совпадает, приложение другое. Сравнение
// обязано быть точным, а не по префиксу.
func TestComposeGuardBlocksVolumeNameSiblingPrefix(t *testing.T) {
	v := check(t, `{"name":"backend","services":{"app":{"image":"x"}},
		"volumes":{"data":{"name":"backend-evil_data"}}}`)
	if len(v) != 1 {
		t.Fatalf("том соседа с похожим префиксом не отклонён: %v", v)
	}
}

// Перехват работающего стека (0206): подключение к существующим томам по
// имени — это цель операции, а не атака. Разрешение узкое: только имена,
// которые сервер зафиксировал при приёме приложения.
func TestComposeGuardAllowsAdoptedVolumeNames(t *testing.T) {
	adopted := []string{
		"h804o84oc008ko0ko0owocwo_supabase-db-data",
		"h804o84oc008ko0ko0owocwo_supabase-db-config",
	}
	v := checkAdopting(t, `{"name":"sigma-supabase","services":{"db":{"image":"x","volumes":[
		{"type":"volume","source":"db-data","target":"/var/lib/postgresql/data"}
	]}},"volumes":{
		"db-data":{"name":"h804o84oc008ko0ko0owocwo_supabase-db-data"},
		"db-config":{"name":"h804o84oc008ko0ko0owocwo_supabase-db-config"},
		"storage":{"name":"sigma-supabase_storage"}
	}}`, adopted)
	if len(v) != 0 {
		t.Fatalf("тома перехваченного стека отклонены: %v", v)
	}
}

// Главное свойство разрешения: оно распространяется ТОЛЬКО на перечисленные
// имена. Иначе пометка «перехвачен» открывала бы доступ к любым данным хоста, и
// перехват одного стека стал бы ключом ко всем соседним.
func TestComposeGuardBlocksVolumeOutsideAdoptedList(t *testing.T) {
	v := checkAdopting(t, `{"name":"sigma-supabase","services":{"app":{"image":"x"}},"volumes":{
		"mine":{"name":"h804o84oc008ko0ko0owocwo_supabase-db-data"},
		"stolen":{"name":"neighbour_db-data"}
	}}`, []string{"h804o84oc008ko0ko0owocwo_supabase-db-data"})
	if len(v) != 1 {
		t.Fatalf("ожидалось ровно одно нарушение (том stolen), получено: %v", v)
	}
	if !strings.Contains(v[0].Reason, "neighbour_db-data") {
		t.Fatalf("в причине нет подставленного имени: %v", v[0])
	}
}

// Сравнение точное, а не по префиксу и не по регистру: имя, отличающееся одним
// символом, — это другой том. Цена ошибки здесь — чужая база под управлением
// нашего стека.
func TestComposeGuardAdoptedMatchIsExact(t *testing.T) {
	adopted := []string{"coolify_supabase-db-data"}
	for _, name := range []string{
		"coolify_supabase-db-data2",
		"coolify_supabase-db-dat",
		"Coolify_supabase-db-data",
		" coolify_supabase-db-data",
	} {
		v := checkAdopting(t,
			`{"name":"app","services":{"app":{"image":"x"}},"volumes":{"v":{"name":"`+name+`"}}}`,
			adopted)
		if len(v) != 1 {
			t.Errorf("имя %q принято за разрешённое", name)
		}
	}
}

// MEDIUM: ports публикуют контейнер напрямую, мимо прокси — вместе с ним мимо
// TLS и всех политик доступа домена. Для недоверенного compose запрещены.
func TestComposeGuardBlocksPorts(t *testing.T) {
	v := check(t, `{"services":{"app":{"image":"x","ports":[{"target":8080,"published":"8080"}]}}}`)
	if len(v) == 0 {
		t.Fatal("публикация порта не заблокирована — обход прокси и политик домена")
	}
}

// MEDIUM: network_mode/pid/ipc: container:<victim> даёт вход в пространство
// имён соседнего контейнера — форма container: не ловилась проверкой на host.
func TestComposeGuardBlocksContainerNamespace(t *testing.T) {
	for _, body := range []string{
		`{"services":{"x":{"network_mode":"container:victim"}}}`,
		`{"services":{"x":{"pid":"container:victim"}}}`,
		`{"services":{"x":{"ipc":"container:victim"}}}`,
		`{"services":{"x":{"network_mode":"service:victim"}}}`,
	} {
		if v := check(t, body); len(v) == 0 {
			t.Errorf("вход в namespace соседа не заблокирован: %s", body)
		}
	}
}

// volumes_from — устаревшее поле, которое переживает `docker compose config` и
// до 0310 не проверялось. Проверено на живом docker: контейнер с такой записью
// читает файл из тома соседнего контейнера. Имена предсказуемы (`<слаг>-<сервис>-1`),
// а написать эту строку может любой с push в подключённый репозиторий.
func TestComposeGuardBlocksVolumesFromForeignContainer(t *testing.T) {
	v := check(t, `{"services":{"x":{"volumes_from":["container:neighbour-db-1"]}}}`)
	if len(v) == 0 {
		t.Fatal("volumes_from на чужой контейнер не заблокирован")
	}
	if !strings.Contains(v[0].Reason, "volumes_from") {
		t.Fatalf("отказ не про volumes_from: %s", v[0].Reason)
	}
	// Суффикс режима не должен служить обходом.
	if len(check(t, `{"services":{"x":{"volumes_from":["container:neighbour-db-1:ro"]}}}`)) == 0 {
		t.Fatal("volumes_from с суффиксом :ro не заблокирован")
	}
}

// Сервис, которого в стеке нет, — те же чужие данные, только без префикса.
func TestComposeGuardBlocksVolumesFromUnknownService(t *testing.T) {
	if len(check(t, `{"services":{"x":{"volumes_from":["neighbour_db"]}}}`)) == 0 {
		t.Fatal("volumes_from на сервис вне стека не заблокирован")
	}
}

// Ссылка на СВОЙ сервис безопасна: его тома проверены здесь же.
func TestComposeGuardAllowsVolumesFromOwnService(t *testing.T) {
	v := check(t, `{"services":{
		"x":{"volumes_from":["db","db:ro"]},
		"db":{"volumes":[{"type":"volume","source":"data","target":"/var/lib"}]}
	}}`)
	if len(v) != 0 {
		t.Fatalf("ссылка на свой сервис отклонена: %v", v)
	}
}

// device_cgroup_rules — тот же доступ к устройству хоста, что и devices, только
// другим полем. Проверено на живом docker: правило `b 254:0 rwm` без privileged
// и без devices позволяет mknod и чтение сырого диска хоста, а `w` — запись.
// CAP_MKNOD входит в набор docker по умолчанию, поэтому узел контейнер создаёт
// себе сам.
func TestComposeGuardBlocksDeviceCgroupRules(t *testing.T) {
	v := check(t, `{"services":{"x":{"device_cgroup_rules":["b 254:0 rwm"]}}}`)
	if len(v) == 0 {
		t.Fatal("device_cgroup_rules не заблокировано: контейнер получает сырой диск хоста")
	}
	if !strings.Contains(v[0].Reason, "device_cgroup_rules") {
		t.Fatalf("отказ не про device_cgroup_rules: %s", v[0].Reason)
	}
}

// secrets и configs с полем file — тот же файл хоста в контейнере, что и bind,
// только другим полем. Проверено на живом docker: обе записи отдают содержимое
// /etc/tracedocs/deploy/agent.key внутрь контейнера.
func TestComposeGuardBlocksSecretAndConfigFiles(t *testing.T) {
	for _, kind := range []string{"secrets", "configs"} {
		v := check(t, `{"services":{"x":{}},"`+kind+`":{"stolen":{"file":"/etc/tracedocs/deploy/agent.key"}}}`)
		if len(v) == 0 {
			t.Fatalf("%s с файлом хоста не заблокирован", kind)
		}
	}
	// Файл внутри приложения — законный случай.
	ok := check(t, `{"services":{"x":{}},"secrets":{"own":{"file":"`+appRoot+`/secret.txt"}}}`)
	if len(ok) != 0 {
		t.Fatalf("секрет из каталога приложения отклонён: %v", ok)
	}
}

// build.context — каталог, который целиком уезжает демону docker; Dockerfile
// волен скопировать оттуда что угодно в образ.
func TestComposeGuardBlocksForeignBuildContext(t *testing.T) {
	v := check(t, `{"services":{"x":{"build":{"context":"/etc/tracedocs/deploy"}}}}`)
	if len(v) == 0 {
		t.Fatal("build.context вне приложения не заблокирован")
	}
	ok := check(t, `{"services":{"x":{"build":{"context":"`+allowedRoot+`"}}}}`)
	if len(ok) != 0 {
		t.Fatalf("сборка из каталога репозитория отклонена: %v", ok)
	}
}

// env_file проверяется по ИСХОДНОМУ тексту: нормализация его стирает, подставив
// содержимое в environment. Файлы .env соседних приложений лежат рядом и имеют
// ровно тот формат, который env_file и ждёт. Прежние случаи построчной проверки
// — теперь через CheckStackFileRefs (filerefs_test.go — полный набор атак).
func TestComposeGuardBlocksEnvFileOutside(t *testing.T) {
	bad := []string{
		"services:\n  app:\n    env_file: /opt/tracedocs/deploy/apps/other/.env\n",
		"services:\n  app:\n    env_file:\n      - ../other/.env\n",
	}
	for _, text := range bad {
		if len(checkText(t, text)) == 0 {
			t.Fatalf("env_file наружу не заблокирован: %q", text)
		}
	}
	good := []string{
		"services:\n  app:\n    env_file: .env\n",
		"services:\n  app:\n    env_file:\n      - ./config/app.env\n",
		"services:\n  app:\n    volumes:\n      - /var/run/docker.sock:/x\n",
	}
	for _, text := range good {
		if v := checkText(t, text); len(v) != 0 {
			t.Fatalf("законный случай отклонён (%v): %q", v, text)
		}
	}
}

// Внешняя сеть — тот же «определён вне стека», что и внешний том, только для
// связности. Проверено на живом docker: контейнер, подключённый к сети соседа
// по имени, достучался до его сервиса и прочитал ответ.
func TestComposeGuardBlocksForeignExternalNetwork(t *testing.T) {
	v := check(t, `{"services":{"x":{}},"networks":{"stolen":{"external":true,"name":"neighbour-private"}}}`)
	if len(v) == 0 {
		t.Fatal("внешняя сеть соседа не заблокирована")
	}
	// Наша собственная edge — законный случай: её вписывает сама платформа.
	ok := check(t, `{"services":{"x":{}},"networks":{"edge":{"external":true,"name":"`+EdgeNetwork+`"}}}`)
	if len(ok) != 0 {
		t.Fatalf("собственная сеть платформы отклонена: %v", ok)
	}
	// Обычная сеть стека внешней не является и проверку не трогает.
	own := check(t, `{"services":{"x":{}},"networks":{"internal":{"name":"app_internal"}}}`)
	if len(own) != 0 {
		t.Fatalf("своя сеть стека отклонена: %v", own)
	}
}

// Неизвестное поле отклоняется само, без отдельного правила под него. Это и есть
// смысл переворота логики: шесть найденных дыр были полями, о которых не
// подумали, и каждая закрывалась своей строкой уже после находки.
func TestComposeGuardRejectsUnknownFields(t *testing.T) {
	// use_api_socket — реальное поле современного compose: монтирует сокет
	// docker в сборку. Правила под него у нас нет и не было.
	v := check(t, `{"services":{"x":{"use_api_socket":true}}}`)
	if len(v) == 0 {
		t.Fatal("неизвестное поле сервиса пропущено")
	}
	if !strings.Contains(v[0].Reason, "неизвестно") {
		t.Fatalf("отказ не про неизвестное поле: %s", v[0].Reason)
	}
	// Верхний уровень тоже закрыт.
	if len(check(t, `{"services":{"x":{}},"provider":{"y":{}}}`)) == 0 {
		t.Fatal("неизвестное поле верхнего уровня пропущено")
	}
	// Расширения x-* — соглашение самого compose, они данные, а не поведение.
	if n := check(t, `{"services":{"x":{"x-my-note":"текст"}},"x-anchors":{"a":1}}`); len(n) != 0 {
		t.Fatalf("расширение x-* отклонено: %v", n)
	}
}

// Обычный стек не должен упереться в разрешительный список: перечислены все
// поля, которые compose оставляет после нормализации обычного описания.
func TestComposeGuardAllowsOrdinaryFields(t *testing.T) {
	ordinary := `{"services":{"x":{
		"image":"nginx","command":["nginx"],"entrypoint":["/d"],"environment":{"A":"b"},
		"working_dir":"/app","user":"1000:1000","hostname":"h","container_name":"xx",
		"restart":"unless-stopped","depends_on":["y"],"healthcheck":{"test":["CMD","true"]},
		"expose":["8080"],"networks":["default"],"labels":{"a":"b"},"annotations":{"a":"b"},
		"platform":"linux/amd64","pull_policy":"always","stdin_open":true,"tty":true,
		"read_only":true,"stop_grace_period":"10s","stop_signal":"SIGTERM",
		"dns_search":["example.com"],"domainname":"example.com","links":["y"],
		"mac_address":"02:42:ac:11:00:02","mem_limit":"512m","cpus":0.5,
		"pids_limit":100,"isolation":"default","logging":{"driver":"json-file"},
		"cap_drop":["ALL"],"uts":"","init":true
	},"y":{"image":"redis"}}}`
	if v := check(t, ordinary); len(v) != 0 {
		t.Fatalf("обычный стек отклонён: %v", v)
	}
}

// ─── С1.7: сборка образа как дверь к файлам хоста ──────────────────────────
//
// Платформа проверяла у сборки один `context`. Остальные подключи `build`
// разбор молча выбрасывал — и каждый из них ведёт туда же, куда context:
// в образ, который клиент потом скачает.

// additional_contexts — второй context под другим именем. Через него в образ
// уезжает каталог ключей агента, и клиент, собравший такой стек, получает
// закрытый ключ хоста в своём образе.
func TestComposeGuardBlocksAdditionalContexts(t *testing.T) {
	v := check(t, `{"services":{"app":{
		"build":{"context":".","additional_contexts":{"keys":"/etc/tracedocs/deploy"}}
	}}}`)
	if len(v) == 0 {
		t.Fatal("additional_contexts на каталог ключей агента пропущен")
	}
}

// Абсолютный dockerfile читается вне каталога приложения — тот же путь наружу,
// только через инструкцию сборки, а не через её контекст.
func TestComposeGuardBlocksAbsoluteDockerfile(t *testing.T) {
	v := check(t, `{"services":{"app":{
		"build":{"context":".","dockerfile":"/etc/tracedocs/deploy/Dockerfile"}
	}}}`)
	if len(v) == 0 {
		t.Fatal("абсолютный dockerfile пропущен")
	}
}

// network: host на время сборки снимает изоляцию сети: сборка ходит по
// локальным адресам хоста, включая метаданные облака и соседние контейнеры.
func TestComposeGuardBlocksBuildNetworkHost(t *testing.T) {
	v := check(t, `{"services":{"app":{"build":{"context":".","network":"host"}}}}`)
	if len(v) == 0 {
		t.Fatal("build.network host пропущен")
	}
}

// ssh и secrets в сборке — проброс агентского ключа или секрета внутрь
// Dockerfile: то же чтение чужого, только оформленное как возможность buildkit.
func TestComposeGuardBlocksBuildSshAndSecrets(t *testing.T) {
	for _, body := range []string{
		`{"services":{"app":{"build":{"context":".","ssh":["default"]}}}}`,
		`{"services":{"app":{"build":{"context":".","secrets":["agent_key"]}}}}`,
		`{"services":{"app":{"build":{"context":".","entitlements":["security.insecure"]}}}}`,
	} {
		if v := check(t, body); len(v) == 0 {
			t.Fatalf("сборка пропущена: %s", body)
		}
	}
}

// Обычная сборка из каталога приложения остаётся разрешённой: запрет неизвестного
// не должен ломать то, ради чего сборка существует.
func TestComposeGuardAllowsOrdinaryBuild(t *testing.T) {
	v := check(t, `{"services":{"app":{
		"build":{"context":".","dockerfile":"Dockerfile","args":{"NODE_ENV":"production"},"target":"runner"}
	}}}`)
	if len(v) != 0 {
		t.Fatalf("обычная сборка отклонена: %v", v)
	}
}

// Guard стоит на ЛЮБОМ источнике, а не только на клиентском (задача С1.5).
//
// Раньше шаблон каталога и рендер образа считались доверенными: их пишет
// платформа. Но весь план радиуса поражения о том, что платформа может
// оказаться не собой — запись в `deploy.*` даёт произвольный compose на каждом
// сервере. Проверка «это наш источник» защищает ровно до этого момента.
func TestGuardAppliesToPlatformSources(t *testing.T) {
	// Тот же compose, что отбивается у клиента, обязан отбиваться и у шаблона:
	// источник на решение не влияет.
	const json = `{"services":{"app":{"privileged":true}}}`
	v, err := Check([]byte(json), Options{Roots: roots()})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(v) == 0 {
		t.Fatal("privileged прошёл проверку — источник не должен давать послаблений")
	}
}

// Каждое поле, которое разрешительный список пропускает с пометкой «проверяется
// отдельно», обязано иметь правило: иначе пометка молча разрешает поле целиком.
// Так проехали uts и cgroup_parent — список их пропускал, а правила не было.
// Вредное значение подставляется в каждое поле; новое поле в группе без случая
// здесь роняет тест.
func TestComposeGuardCheckedKeysHaveRules(t *testing.T) {
	harmful := map[string]string{
		"volumes":             `{"services":{"x":{"volumes":[{"type":"bind","source":"/etc/tracedocs/deploy","target":"/s"}]}}}`,
		"volumes_from":        `{"services":{"x":{"volumes_from":["container:neighbour-db-1"]}}}`,
		"secrets":             `{"services":{"x":{"secrets":[{"source":"k"}]}},"secrets":{"k":{"file":"/etc/tracedocs/deploy/agent.key"}}}`,
		"configs":             `{"services":{"x":{"configs":[{"source":"k"}]}},"configs":{"k":{"file":"/etc/tracedocs/deploy/agent.key"}}}`,
		"build":               `{"services":{"x":{"build":{"context":"/etc/tracedocs/deploy"}}}}`,
		"ports":               `{"services":{"x":{"ports":[{"target":80,"published":"80"}]}}}`,
		"privileged":          `{"services":{"x":{"privileged":true}}}`,
		"cap_add":             `{"services":{"x":{"cap_add":["SYS_ADMIN"]}}}`,
		"devices":             `{"services":{"x":{"devices":[{"source":"/dev/sda","target":"/dev/sda"}]}}}`,
		"device_cgroup_rules": `{"services":{"x":{"device_cgroup_rules":["b 254:0 rwm"]}}}`,
		"cgroup":              `{"services":{"x":{"cgroup":"host"}}}`,
		"cgroup_parent":       `{"services":{"x":{"cgroup_parent":"/system.slice"}}}`,
		"security_opt":        `{"services":{"x":{"security_opt":["seccomp:unconfined"]}}}`,
		"network_mode":        `{"services":{"x":{"network_mode":"host"}}}`,
		"pid":                 `{"services":{"x":{"pid":"host"}}}`,
		"ipc":                 `{"services":{"x":{"ipc":"host"}}}`,
		"userns_mode":         `{"services":{"x":{"userns_mode":"host"}}}`,
		"uts":                 `{"services":{"x":{"uts":"host"}}}`,
	}
	for key := range checkedServiceKeys {
		body, ok := harmful[key]
		if !ok {
			t.Errorf("%s помечено «проверяется отдельно», а вредного случая для него нет", key)
			continue
		}
		v := check(t, body)
		if len(v) == 0 {
			t.Errorf("%s: вредное значение не отклонено — правила нет", key)
			continue
		}
		for _, one := range v {
			if strings.Contains(one.Reason, "неизвестно") {
				t.Errorf("%s: отклонено как неизвестное поле, а не своим правилом: %s", key, one.Reason)
			}
		}
	}
	for key := range harmful {
		if !checkedServiceKeys[key] || !safeServiceKeys[key] {
			t.Errorf("%s: случай есть, а в группе «проверяется отдельно» поля нет", key)
		}
	}
}

// uts: host — пространство имён UTS хоста. Законного значения у стека клиента
// нет; пустое — норма после нормализации. До выноса в пакет ключ стоял в
// разрешительном списке без правила и в режиме root проходил.
func TestComposeGuardBlocksUtsHost(t *testing.T) {
	v := check(t, `{"services":{"x":{"uts":"host"}}}`)
	if len(v) != 1 || !strings.Contains(v[0].Reason, "uts") {
		t.Fatalf("uts: host не отклонено своим правилом: %v", v)
	}
	if ok := check(t, `{"services":{"x":{"uts":""}}}`); len(ok) != 0 {
		t.Fatalf("пустой uts отклонён: %v", ok)
	}
}

// cgroup_parent выводит контейнер из ветки cgroup docker в произвольную ветку
// хоста — мимо пределов и учёта, которые демон ставит своим контейнерам.
func TestComposeGuardBlocksCgroupParent(t *testing.T) {
	v := check(t, `{"services":{"x":{"cgroup_parent":"/system.slice"}}}`)
	if len(v) != 1 || !strings.Contains(v[0].Reason, "cgroup_parent") {
		t.Fatalf("cgroup_parent не отклонён своим правилом: %v", v)
	}
	if ok := check(t, `{"services":{"x":{"cgroup_parent":""}}}`); len(ok) != 0 {
		t.Fatalf("пустой cgroup_parent отклонён: %v", ok)
	}
}
