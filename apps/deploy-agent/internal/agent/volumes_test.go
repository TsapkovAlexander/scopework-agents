package agent

import (
	"strings"
	"testing"
)

// Определение «том принадлежит этому приложению» решает две операции с
// несопоставимой ценой ошибки: отказ разворачивать (неприятно) и УДАЛЕНИЕ
// данных (необратимо). Поэтому граница проверяется отдельно и придирчиво.

func TestAppVolumesMatchByProjectPrefix(t *testing.T) {
	all := []string{
		"supabase_db-data",
		"supabase_storage-data",
		"n8n_db-data",
		"tracedocs-proxy_caddy-data",
	}

	got := filterAppVolumes(all, "supabase")
	if len(got) != 2 {
		t.Fatalf("нашлось %d томов, ожидалось 2: %v", len(got), got)
	}
	for _, name := range got {
		if name != "supabase_db-data" && name != "supabase_storage-data" {
			t.Fatalf("чужой том попал в выборку: %s", name)
		}
	}
}

// Имя приложения — префикс имени тома, и приложения с похожими именами живут
// на одном хосте. Спутать «supa» и «supabase» значит удалить чужие данные.
func TestAppVolumesDoNotMatchSimilarNames(t *testing.T) {
	all := []string{"supabase_db-data", "supa_db-data", "supabase2_db-data"}

	if got := filterAppVolumes(all, "supa"); len(got) != 1 || got[0] != "supa_db-data" {
		t.Fatalf("выборка для «supa» неверна: %v", got)
	}
	if got := filterAppVolumes(all, "supabase"); len(got) != 1 || got[0] != "supabase_db-data" {
		t.Fatalf("выборка для «supabase» неверна: %v", got)
	}
}

// Разделитель обязателен: том с именем ровно как slug создан не compose и
// приложению не принадлежит.
func TestAppVolumesRequireSeparator(t *testing.T) {
	all := []string{"supabase", "supabasedata", "supabase_db-data"}

	got := filterAppVolumes(all, "supabase")
	if len(got) != 1 || got[0] != "supabase_db-data" {
		t.Fatalf("выборка неверна: %v", got)
	}
}

func TestAppVolumesEmptyInputs(t *testing.T) {
	if got := filterAppVolumes(nil, "supabase"); len(got) != 0 {
		t.Fatalf("на пустом списке вернулось %v", got)
	}
	// Пустой slug совпал бы с префиксом «_» у чего угодно — недопустимо.
	if got := filterAppVolumes([]string{"a_b", "_x"}, ""); len(got) != 0 {
		t.Fatalf("пустой slug дал выборку: %v", got)
	}
}

// Отказ на первом релизе — единственная защита от «развернули заново с тем же
// именем и получили password authentication failed». Проверяем ровно условие,
// при котором он срабатывает.
func TestStaleDataCheck(t *testing.T) {
	cases := []struct {
		name         string
		firstRelease bool
		volumes      []string
		wantRefusal  bool
	}{
		{"первый релиз, данных нет", true, nil, false},
		{"первый релиз, остались данные", true, []string{"supabase_db-data"}, true},
		// Не первый релиз — тома СВОИ и должны сохраниться: это обычный
		// повторный выкат или обновление версии.
		{"повторный выкат при своих данных", false, []string{"supabase_db-data"}, false},
	}

	for _, c := range cases {
		got := staleDataRefusal("supabase", c.firstRelease, false, c.volumes, nil) != nil
		if got != c.wantRefusal {
			t.Fatalf("%s: отказ=%v, ожидалось %v", c.name, got, c.wantRefusal)
		}
	}
}

// Текст отказа обязан объяснять и причину, и выход: без этого пользователь
// видит «не удалось развернуть» и идёт смотреть логи по SSH.
func TestStaleDataRefusalExplainsWayOut(t *testing.T) {
	err := staleDataRefusal("supabase", true, false, []string{"supabase_db-data", "supabase_storage-data"}, nil)
	if err == nil {
		t.Fatal("отказа не было")
	}
	msg := err.Error()
	for _, want := range []string{"supabase_db-data", "удалить данные", "2"} {
		if !contains(msg, want) {
			t.Fatalf("в тексте отказа нет %q:\n%s", want, msg)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// --------------------------------------------------------------------------
// Перехваченный стек: чужой владелец томов
// --------------------------------------------------------------------------
//
// Самый дорогой отказ всей операции перехвата. Перехваченное приложение
// подключается к СУЩЕСТВУЮЩИМ томам, которые прямо сейчас держит чужой стек.
// Если тот не остановлен, `docker compose up` поднимает второй комплект
// сервисов на тех же данных.
//
// Для PostgreSQL это не «конфликт», а порча: замок `postmaster.pid` проверяет,
// жив ли процесс с записанным PID, в СВОЁМ пространстве процессов. У второго
// контейнера пространство своё, старого PID там нет, замок считается протухшим
// — и второй постмастер стартует на живом каталоге данных.
//
// Проверить это на репетиции было нельзя: она шла на пустом хосте, где чужого
// стека не существовало.

func TestForeignVolumeHoldersFindsRunningOwner(t *testing.T) {
	holders := foreignVolumeHolders(
		[]dockerContainerRef{
			{Project: "h804o84oc", Service: "supabase-db", Running: true,
				Volumes: []string{"h804o84oc_supabase-db-data"}},
			{Project: "sigma-supabase", Service: "db", Running: true,
				Volumes: []string{"h804o84oc_supabase-db-data"}},
		},
		"sigma-supabase",
		[]string{"h804o84oc_supabase-db-data", "h804o84oc_storage"},
	)

	if len(holders) != 1 {
		t.Fatalf("ожидался один чужой владелец, получено %d: %+v", len(holders), holders)
	}
	if holders[0].Project != "h804o84oc" {
		t.Errorf("найден не тот проект: %+v", holders[0])
	}
}

// Остановленный чужой контейнер владельцем не считается: ровно в этом
// состоянии стек и находится сразу после переноса данных, и отказ здесь
// заблокировал бы перехват намертво.
func TestForeignVolumeHoldersIgnoresStopped(t *testing.T) {
	holders := foreignVolumeHolders(
		[]dockerContainerRef{
			{Project: "h804o84oc", Service: "supabase-db", Running: false,
				Volumes: []string{"h804o84oc_supabase-db-data"}},
		},
		"sigma-supabase",
		[]string{"h804o84oc_supabase-db-data"},
	)
	if len(holders) != 0 {
		t.Fatalf("остановленный контейнер принят за владельца: %+v", holders)
	}
}

// Свой же стек под своим именем проекта — это повторный выкат, а не чужой
// владелец. Иначе второй выкат перехваченного приложения отказывал бы всегда.
func TestForeignVolumeHoldersIgnoresOwnProject(t *testing.T) {
	holders := foreignVolumeHolders(
		[]dockerContainerRef{
			{Project: "sigma-supabase", Service: "db", Running: true,
				Volumes: []string{"h804o84oc_supabase-db-data"}},
		},
		"sigma-supabase",
		[]string{"h804o84oc_supabase-db-data"},
	)
	if len(holders) != 0 {
		t.Fatalf("собственный стек принят за чужой: %+v", holders)
	}
}

// Тома, которых нет в списке перехвата, нас не касаются: на хосте работают
// девять чужих приложений, и отказывать из-за их томов не за что.
func TestForeignVolumeHoldersIgnoresUnrelatedVolumes(t *testing.T) {
	holders := foreignVolumeHolders(
		[]dockerContainerRef{
			{Project: "чужое-приложение", Service: "db", Running: true,
				Volumes: []string{"другое_db-data"}},
		},
		"sigma-supabase",
		[]string{"h804o84oc_supabase-db-data"},
	)
	if len(holders) != 0 {
		t.Fatalf("чужой том вне списка перехвата вызвал отказ: %+v", holders)
	}
}

func TestAdoptedVolumesRefusalNamesWhatToStop(t *testing.T) {
	err := adoptedVolumesRefusal([]dockerContainerRef{
		{Project: "h804o84oc", Service: "supabase-db", Running: true},
		{Project: "h804o84oc", Service: "supabase-minio", Running: true},
	})
	if err == nil {
		t.Fatal("работающий чужой владелец томов не дал отказа")
	}
	text := err.Error()
	for _, want := range []string{"h804o84oc", "supabase-db"} {
		if !strings.Contains(text, want) {
			t.Errorf("в отказе нет %q: %s", want, text)
		}
	}
	if adoptedVolumesRefusal(nil) != nil {
		t.Error("отказ выдан при отсутствии чужих владельцев")
	}
}

// Перехваченный стек: его тома — не остатки, а причина операции.
//
// Мастер перехвата предзаполняет идентификатор именем чужого compose-проекта, а
// тома у такого стека называются `<проект>_<ключ>` — ровно с тем префиксом, по
// которому ищутся остатки. До исключения первый выкат ЛЮБОГО перехваченного
// стека отвергался, да ещё и с советом снести данные, ради которых всё и
// затевалось.
func TestStaleDataIgnoresAdoptedVolumes(t *testing.T) {
	adopted := []string{"abc123stackid_supabase-db-data", "abc123stackid_storage"}

	if err := staleDataRefusal("abc123stackid", true, false, adopted, adopted); err != nil {
		t.Fatalf("перехваченные тома приняты за остатки: %v", err)
	}

	// Чужой том рядом с перехваченными по-прежнему останавливает выкат:
	// исключение узкое и не превращается в «на первом выкате можно всё».
	mixed := append([]string{"abc123stackid_leftover"}, adopted...)
	if err := staleDataRefusal("abc123stackid", true, false, mixed, adopted); err == nil {
		t.Fatal("посторонний том прошёл вместе с перехваченными")
	} else if !strings.Contains(err.Error(), "abc123stackid_leftover") {
		t.Fatalf("в тексте нет имени постороннего тома: %v", err)
	} else if strings.Contains(err.Error(), "abc123stackid_storage") {
		t.Fatalf("перехваченный том попал в текст отказа: %v", err)
	}
}

// Чужой стек с тем же именем проекта останавливает первый выкат.
//
// Имя compose-проекта равно идентификатору приложения, а мастер подставляет
// его из названия автоматически. Совпадения с `n8n` или `wordpress` достаточно,
// чтобы первый `up -d --remove-orphans` удалил чужие контейнеры как «сироты»:
// метку проекта они несут ту же, а в нашем описании их нет.
func TestForeignProjectRefusal(t *testing.T) {
	foreign := dockerContainer{}
	foreign.Config.Labels = map[string]string{
		"com.docker.compose.project":             "n8n",
		"com.docker.compose.project.working_dir": "/home/user/n8n",
	}
	ours := dockerContainer{}
	ours.Config.Labels = map[string]string{
		"com.docker.compose.project":             "n8n",
		"com.docker.compose.project.working_dir": "/opt/tracedocs/deploy/apps/n8n",
	}
	other := dockerContainer{}
	other.Config.Labels = map[string]string{
		"com.docker.compose.project":             "wordpress",
		"com.docker.compose.project.working_dir": "/srv/wordpress",
	}

	roots := []string{"/opt/tracedocs/deploy", "/etc/tracedocs/deploy"}

	err := foreignProjectRefusal("n8n", []dockerContainer{foreign, other}, roots)
	if err == nil {
		t.Fatal("чужой стек с тем же именем проекта не остановил выкат")
	}
	if !strings.Contains(err.Error(), "/home/user/n8n") {
		t.Fatalf("в тексте нет каталога чужого стека: %v", err)
	}

	// Свой же стек под тем же именем — норма: это повторный выкат.
	if err := foreignProjectRefusal("n8n", []dockerContainer{ours}, roots); err != nil {
		t.Fatalf("собственный стек принят за чужой: %v", err)
	}

	// Другое имя проекта не мешает.
	if err := foreignProjectRefusal("n8n", []dockerContainer{other}, roots); err != nil {
		t.Fatalf("посторонний стек остановил выкат: %v", err)
	}

	// Контейнер без метки рабочего каталога обвинять не в чем.
	blank := dockerContainer{}
	blank.Config.Labels = map[string]string{"com.docker.compose.project": "n8n"}
	if err := foreignProjectRefusal("n8n", []dockerContainer{blank}, roots); err != nil {
		t.Fatalf("контейнер без рабочего каталога принят за чужой стек: %v", err)
	}
}

// Собственные тома упавшего выката повтору не мешают.
//
// ДЕФЕКТ, РАДИ КОТОРОГО НАПИСАН ТЕСТ. «Первый релиз» означает «ни один релиз не
// дошёл до healthy», а не «мы здесь впервые». Первый выкат, упавший ПОСЛЕ
// подъёма базы, оставляет её тома на диске — и отказ срабатывал на каждой
// следующей попытке, включая простую правку переменных. Приложение оказывалось
// заперто: почини и выкати заново нельзя, потому что «остались данные прошлого
// приложения», а данные эти — его собственные, созданные минуту назад.
func TestStaleDataAllowsRetryOfOwnFailedDeploy(t *testing.T) {
	volumes := []string{"shop_pgdata", "shop_redisdata"}

	// Платформа здесь уже разворачивала — тома свои, отказа быть не должно.
	if err := staleDataRefusal("shop", true, true, volumes, nil); err != nil {
		t.Fatalf("повтор своего выката запрещён: %v", err)
	}

	// Каталога нет: приложение с таким идентификатором платформа здесь не
	// разворачивала, а тома лежат — это остатки прошлого одноимённого.
	err := staleDataRefusal("shop", true, false, volumes, nil)
	if err == nil {
		t.Fatal("остатки прошлого приложения пропущены")
	}
	if !strings.Contains(err.Error(), "shop_pgdata") {
		t.Fatalf("в отказе не названы тома: %v", err)
	}
}
