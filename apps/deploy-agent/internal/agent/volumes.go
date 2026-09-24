package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Тома приложения: обнаружение чужих данных и удаление своих.
//
// ЗАЧЕМ. Тома при снятии стека не удаляются намеренно — иначе ошибочное
// удаление приложения означало бы безвозвратную потерю данных. У этого решения
// есть последствие, которое на боевом прогоне стоило часа разбирательств:
//
//   удалили приложение → тома остались → развернули заново с тем же
//   идентификатором → платформа выдала НОВЫЕ пароли → PostgreSQL увидел
//   непустой каталог данных и не выполнил init-скрипты → роли остались со
//   старыми паролями → «FATAL: password authentication failed».
//
// Стек при этом выглядит почти работающим: база здорова, часть сервисов
// поднялась, шлюз ждёт зависимость. Связать это с давним удалением одноимённого
// приложения по логам невозможно.
//
// Отсюда две операции здесь. Отказ разворачиваться поверх чужих данных — и
// удаление своих, когда пользователь этого явно попросил.

// filterAppVolumes отбирает тома, принадлежащие приложению.
//
// Имя тома compose складывает как `<проект>_<том>`, а проектом служит slug.
// Разделитель обязателен: без него «supa» совпал бы с «supabase_db-data», то
// есть с данными ДРУГОГО приложения на том же хосте. Цена такой ошибки —
// удаление чужой базы, поэтому проверка строгая и покрыта тестом.
func filterAppVolumes(all []string, slug string) []string {
	if slug == "" {
		return nil
	}
	prefix := slug + "_"

	var mine []string
	for _, name := range all {
		if strings.HasPrefix(name, prefix) {
			mine = append(mine, name)
		}
	}
	return mine
}

// listAppVolumes спрашивает у docker тома приложения.
func listAppVolumes(ctx context.Context, slug string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "volume", "ls", "--format", "{{.Name}}")
	cmd.Env = dockerEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("не удалось получить список томов: %w", err)
	}

	var all []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			all = append(all, line)
		}
	}
	return filterAppVolumes(all, slug), nil
}

// staleDataRefusal решает, можно ли разворачивать приложение.
//
// Отказ выдаётся ТОЛЬКО на первом релизе: тогда данных с этим именем на хосте
// быть не должно, и их наличие означает остатки прошлого одноимённого
// приложения. На повторных выкатах и обновлениях тома свои — они и должны
// сохраняться, в этом весь смысл постоянного хранилища.
//
// Признак первого релиза приходит с сервера: только он знает историю. Локальные
// отметки агента теряются при переустановке, и «отметки нет» значит «не помню»,
// а не «разворачиваю впервые», — приняв одно за другое, агент отказался бы
// поднимать работающее приложение.
// adopted — тома, которые приложение перехватило вместе со стеком.
//
// Их наличие не «остатки», а смысл операции: платформа берёт под управление
// работающий стек НА ЕГО СОБСТВЕННЫХ данных. Мастер перехвата предзаполняет
// идентификатор именем чужого compose-проекта, а тома у такого стека называются
// `<проект>_<ключ>` — то есть ровно с тем префиксом, по которому ищутся остатки.
// Без этого исключения первый выкат ЛЮБОГО перехваченного стека отвергался, да
// ещё и с советом «удалите приложение с отметкой удалить данные», то есть
// снести то, ради чего перехват и затевался.
func staleDataRefusal(
	slug string,
	firstRelease bool,
	// deployedHere — платформа УЖЕ разворачивала это приложение на этом хосте:
	// служебный каталог стека на месте.
	//
	// ЗАЧЕМ ЭТОТ ПРИЗНАК. «Первый релиз» означает «ни один релиз не дошёл до
	// healthy», а не «мы здесь впервые». Первый выкат, упавший ПОСЛЕ подъёма
	// базы, оставляет её тома на диске — и дальше отказ срабатывает на каждой
	// повторной попытке, включая простую правку переменных. Приложение
	// оказывается заперто: почини и выкати заново нельзя, потому что «остались
	// данные прошлого приложения», а данные эти — его собственные, созданные
	// минуту назад.
	//
	// Отличить одно от другого можно точно. Тома создаёт compose-проект с
	// именем приложения, и если платформа его здесь разворачивала, то в
	// служебном каталоге лежит написанное ею описание стека. Удаление
	// приложения этот каталог сносит (removeAppDir), а тома при отказе от
	// «удалить данные» остаются — то есть каталог без томов и тома без
	// каталога различаются однозначно.
	deployedHere bool,
	volumes []string,
	adopted []string,
) error {
	if !firstRelease || deployedHere {
		return nil
	}

	volumes = withoutVolumes(volumes, adopted)
	if len(volumes) == 0 {
		return nil
	}

	return fmt.Errorf(
		"на сервере остались данные прошлого приложения с идентификатором %q (%d %s: %s). "+
			"Развернуть поверх нельзя: база уже создана со СТАРЫМИ паролями, а платформа выдала новые — "+
			"стек поднимется и не сможет подключиться к своей базе. "+
			"Либо удалите приложение с отметкой «удалить данные», либо выберите другой идентификатор",
		slug, len(volumes), pluralVolumes(len(volumes)), strings.Join(volumes, ", "),
	)
}

// foreignProjectRefusal — на хосте уже работает ЧУЖОЙ стек с таким же именем
// проекта.
//
// Имя compose-проекта у платформы равно идентификатору приложения, а мастер
// подставляет идентификатор из названия автоматически. Достаточно совпасть с
// именем неуправляемого стека (`n8n`, `supabase`, `wordpress` — самые
// вероятные), и первый же `up -d --remove-orphans` удалит его контейнеры как
// «сироты»: в нашем описании их нет, а метку проекта они несут ту же.
//
// Проверка стоит в агенте, потому что только он видит, что на хосте работает
// на самом деле. Осмотр сервера (host_inventory) может быть недельной
// давности, а может не проводиться вовсе.
//
// «Чужой» определяется по рабочему каталогу: стек платформы всегда поднят из
// её каталогов, и совпадение имени с собственным приложением — норма, а не
// повод отказывать.
func foreignProjectRefusal(slug string, containers []dockerContainer, managedRoots []string) error {
	// Имена самой платформы — отдельной веткой и без оглядки на каталоги.
	//
	// Прокси поднимается из WorkDir/proxy, то есть ВНУТРИ managedRoots, и
	// проверка ниже пропустила бы его по построению. А приложение с
	// идентификатором `tracedocs-proxy` даёт то же имя проекта, и первый
	// `up -d --remove-orphans` снёс бы Caddy как сироту — вместе со ВСЕМИ
	// доменами хоста.
	if slug == proxyProjectName || strings.HasPrefix(slug, "tracedocs-") {
		return fmt.Errorf(
			"идентификатор %q занят самой платформой: под этим именем работает её "+
				"собственный стек, и выкат снёс бы его вместе со всеми доменами сервера. "+
				"Выберите другой идентификатор", slug)
	}

	names := map[string]bool{}
	for _, c := range containers {
		if c.Config.Labels["com.docker.compose.project"] != slug {
			continue
		}
		dir := c.Config.Labels["com.docker.compose.project.working_dir"]
		if dir == "" || withinRoots(dir, managedRoots) {
			continue
		}
		names[dir] = true
	}
	if len(names) == 0 {
		return nil
	}

	dirs := make([]string, 0, len(names))
	for dir := range names {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)

	return fmt.Errorf(
		"на сервере уже работает стек с именем проекта %q, развёрнутый не платформой (%s). "+
			"Выкат удалил бы его контейнеры как лишние: docker считает лишним всё, что несёт "+
			"метку проекта и не описано в нашем файле. "+
			"Выберите другой идентификатор приложения либо перехватите этот стек",
		slug, strings.Join(dirs, ", "),
	)
}

// withoutVolumes убирает из списка перечисленные имена.
func withoutVolumes(all []string, drop []string) []string {
	if len(drop) == 0 {
		return all
	}
	skip := make(map[string]bool, len(drop))
	for _, name := range drop {
		skip[name] = true
	}
	kept := make([]string, 0, len(all))
	for _, name := range all {
		if !skip[name] {
			kept = append(kept, name)
		}
	}
	return kept
}

// listVolumeHolders — кто на хосте сейчас держит тома, с точки зрения docker.
func listVolumeHolders(ctx context.Context) ([]dockerContainerRef, error) {
	containers, err := inspectComposeContainers(ctx)
	if err != nil {
		return nil, err
	}
	refs := make([]dockerContainerRef, 0, len(containers))
	for _, c := range containers {
		ref := dockerContainerRef{
			Project: c.Config.Labels["com.docker.compose.project"],
			Service: c.Config.Labels["com.docker.compose.service"],
			Running: c.State.Status == "running",
		}
		for _, m := range c.Mounts {
			if m.Type == "volume" && m.Name != "" {
				ref.Volumes = append(ref.Volumes, m.Name)
			}
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// dockerContainerRef — то немногое о контейнере, что нужно для решения «этот
// том сейчас кто-то держит».
type dockerContainerRef struct {
	Project string
	Service string
	Running bool
	Volumes []string
}

// foreignVolumeHolders — работающие контейнеры ЧУЖОГО стека на наших томах.
//
// Перехваченное приложение подключается к существующим томам, и пока их держит
// стек прежней панели, `docker compose up` поднимает второй комплект сервисов
// на тех же данных. Для PostgreSQL это порча, а не конфликт: замок
// `postmaster.pid` сверяет, жив ли процесс с записанным PID, в собственном
// пространстве процессов контейнера. У второго контейнера пространство своё,
// старого PID там нет — замок считается протухшим, и второй постмастер
// стартует на живом каталоге данных.
//
// Остановленные не считаются: сразу после переноса данных чужой стек именно
// остановлен, и отказ по такому признаку заблокировал бы перехват намертво.
func foreignVolumeHolders(containers []dockerContainerRef, project string, adopted []string) []dockerContainerRef {
	if len(adopted) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(adopted))
	for _, v := range adopted {
		wanted[v] = true
	}

	var holders []dockerContainerRef
	for _, c := range containers {
		if !c.Running || c.Project == project || c.Project == "" {
			continue
		}
		for _, v := range c.Volumes {
			if wanted[v] {
				holders = append(holders, c)
				break
			}
		}
	}
	return holders
}

// adoptedVolumesRefusal — текст отказа с именем того, что надо остановить.
//
// Имя проекта и сервисов обязательны: человек читает это в журнале релиза и
// должен понимать, какую именно команду выполнить, не разбираясь заново, чей
// это стек.
func adoptedVolumesRefusal(holders []dockerContainerRef) error {
	if len(holders) == 0 {
		return nil
	}
	project := holders[0].Project
	var services []string
	for _, h := range holders {
		if h.Service != "" {
			services = append(services, h.Service)
		}
	}
	return fmt.Errorf(
		"тома перехваченного стека сейчас держит работающий проект %q (%s). "+
			"Поднять свой стек поверх нельзя: два комплекта сервисов на одних данных — это не конфликт, "+
			"а порча базы. Остановите прежний стек (`docker compose -p %s stop`) и повторите выкат",
		project, strings.Join(services, ", "), project,
	)
}

func pluralVolumes(n int) string {
	switch {
	case n%10 == 1 && n%100 != 11:
		return "том"
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		return "тома"
	default:
		return "томов"
	}
}

// removeAppVolumes удаляет тома приложения.
//
// Вызывается только при снятии стека с явной отметкой «удалить данные»:
// восстановить их после этого неоткуда, поэтому решение принимает человек, а
// не агент. Результат каждого удаления проверяется отдельно — сообщать об
// успехе по факту запуска команды значит однажды доложить об удалении, которого
// не было, и оставить пользователя с данными, мешающими развернуть заново.
func removeAppVolumes(ctx context.Context, slug string) (removed []string, failed []string) {
	volumes, err := listAppVolumes(ctx, slug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "тома %s: %v\n", slug, err)
		return nil, nil
	}

	for _, name := range volumes {
		cmd := exec.CommandContext(ctx, "docker", "volume", "rm", name)
		cmd.Env = dockerEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "не удалось удалить том %s: %v: %s\n", name, err, tail(string(out), 200))
			failed = append(failed, name)
			continue
		}
		removed = append(removed, name)
	}
	return removed, failed
}

// deployedHere — платформа уже писала описание стека для этого приложения на
// этом хосте.
//
// Признаком служит подготовленный compose в служебном каталоге: его пишет
// applyOne ДО подъёма стека, поэтому он есть и после упавшего выката. Удаление
// приложения каталог сносит целиком (removeAppDir), а тома при отказе от
// «удалить данные» остаются — этим и различаются «свои тома после неудачи» и
// «остатки прошлого одноимённого приложения».
func deployedHere(p Paths, slug string) bool {
	_, err := os.Stat(filepath.Join(p.appDir(slug), "docker-compose.yml"))
	return err == nil
}
