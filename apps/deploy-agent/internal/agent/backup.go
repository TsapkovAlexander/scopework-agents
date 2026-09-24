package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Резервная копия приложения перед обновлением версии.
//
// ЗАЧЕМ ИМЕННО ПЕРЕД ОБНОВЛЕНИЕМ. Миграции схемы необратимы: подняв n8n новой
// версии, мы позволяем ему переписать базу, и старый образ её больше не
// прочитает. Значит «откат» через возврат старого образа не работает —
// вернуться можно только к данным, снятым ДО запуска новой версии.
//
// Без этого слова «безопасное обновление» не означают ничего.
//
// ЧТО ИМЕННО КОПИРУЕТСЯ, знает шаблон, а не агент: какой сервис является базой
// и как она называется — свойство приложения. Задание приходит в желаемом
// состоянии полем backup_spec.
//
// ГРАНИЦА ЧЕСТНО. Мы гарантируем восстановимый снимок и возврат к нему, если
// стек не поднялся здоровым. Мы НЕ гарантируем, что сценарии клиента ведут
// себя после обновления так же — это поведение приложения, а не платформы.

// BackupSpec — что резервировать. Приходит из шаблона через желаемое состояние.
type BackupSpec struct {
	Postgres []PostgresBackup `json:"postgres"`
	// Имена томов КАК В COMPOSE, без префикса проекта. Полное имя тома docker
	// собирает сам: `<проект>_<том>`.
	Volumes []string `json:"volumes"`
	// Stateless — шаблон объявил, что данных у приложения нет (0156, CHECK
	// templates_backup_spec_declared): `{"stateless": true}` вместо пустого
	// задания. deploy_upgrade_app копирует его в релиз дословно, и web отдаёт
	// как есть. Агенту решать по нему нечего — копию он снимает по needsBackup,
	// — но поле обязано быть известным: подписанное состояние разбирается
	// строго, и незнакомое имя здесь отказывало бы всему пакету хоста на
	// каждом обновлении приложения без данных.
	Stateless bool `json:"stateless"`
}

// PostgresBackup — одна база, которую надо выгрузить.
type PostgresBackup struct {
	Service  string `json:"service"`
	User     string `json:"user"`
	Database string `json:"database"`
}

func (s BackupSpec) isEmpty() bool { return len(s.Postgres) == 0 && len(s.Volumes) == 0 }

// safeIdent — имена сервиса, пользователя, базы и тома уезжают в аргументы
// docker. Узко и намеренно: это значения из НАШЕГО каталога, но каталог правят
// люди, и опечатка не должна превращаться в аргумент команды.
var safeIdent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

func (s BackupSpec) validate() error {
	for _, pg := range s.Postgres {
		for name, v := range map[string]string{
			"сервис": pg.Service, "пользователь": pg.User, "база": pg.Database,
		} {
			if !safeIdent.MatchString(v) {
				return fmt.Errorf("недопустимый %s в задании на копию: %q", name, tail(v, 60))
			}
		}
	}
	for _, vol := range s.Volumes {
		if !safeIdent.MatchString(vol) {
			return fmt.Errorf("недопустимое имя тома: %q", tail(vol, 60))
		}
	}
	return nil
}

// Сколько наборов копий держать на хосте. Две: текущая и предыдущая — этого
// хватает, чтобы откатиться, и не хватает, чтобы забить диск клиента.
const backupsToKeep = 2

// Запас сверх размера данных. Архивы сжимаются, но во время создания на диске
// одновременно лежат и данные, и архив.
const backupFreeSpaceFactor = 1.5

// Нижний порог свободного места независимо от размера данных.
const backupMinFreeBytes = 512 << 20

func (p Paths) backupsDir(slug string) string {
	return filepath.Join(p.WorkDir, "backups", slug)
}

// backupSetName — имя набора. Метка времени в UTC, чтобы сортировка строкой
// совпадала с хронологией.
func backupSetName(now time.Time) string { return now.UTC().Format("20060102-150405") }

// safeBackupSet — то же имя, но со стороны разбора: ровно то, что печатает
// backupSetName, и ровно то, что пропускает ограничение в базе (0447).
var safeBackupSet = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}$`)

// validBackupSet — годится ли имя набора, пришедшее с заданием на
// восстановление.
//
// Проверка ВТОРАЯ: формат стережёт и база. Но агент живёт на чужой машине и
// обязан не доверять входу второй раз — имя уезжает в путь на диске, и `..` в
// нём означало бы распаковку архивов мимо рабочего каталога. Та же причина,
// что у safeSlug в apply.go.
func validBackupSet(set string) bool { return safeBackupSet.MatchString(set) }

// CreateBackup снимает копию приложения и возвращает каталог набора.
//
// Копия делается на РАБОТАЮЩЕМ стеке: pg_dump снимает согласованный снимок сам,
// а тома копируются как есть. Останавливать приложение ради копии значило бы
// добавлять простой к каждому обновлению.
func CreateBackup(ctx context.Context, p Paths, app DesiredApp, spec BackupSpec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	if spec.isEmpty() {
		return "", nil
	}
	if !safeSlug.MatchString(app.Slug) {
		return "", fmt.Errorf("недопустимый slug приложения: %q", app.Slug)
	}

	dir := filepath.Join(p.backupsDir(app.Slug), backupSetName(time.Now()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("не удалось создать каталог копии: %w", err)
	}

	if err := ensureFreeSpace(ctx, p, app.Slug, spec, dir); err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	// Compose и .env — часть снимка: без них восстановленные данные не к чему
	// приложить, а откат должен вернуть ровно ту конфигурацию, что работала.
	appDir := p.appDir(app.Slug)
	for _, name := range []string{"docker-compose.yml", ".env"} {
		raw, err := os.ReadFile(filepath.Join(appDir, name))
		if err != nil {
			continue
		}
		if err := writeFileAtomic(filepath.Join(dir, name), raw, 0o600); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("не удалось сохранить %s: %w", name, err)
		}
	}

	for _, pg := range spec.Postgres {
		if err := dumpPostgres(ctx, p, app, pg, dir); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}

	for _, vol := range spec.Volumes {
		if err := archiveVolume(ctx, app.Slug, vol, dir); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}

	pruneBackupsKeeping(p, app.Slug, app.BackupKeep)
	return dir, nil
}

// volumeName — полное имя тома docker. compose приписывает к имени из файла
// имя проекта, а проектом у нас служит slug приложения.
func volumeName(slug, vol string) string { return slug + "_" + vol }

// sqlSink — файл дампа и ответ на вопрос «а не пусто ли там».
//
// Поток вместо строки лишает нас `strings.TrimSpace(out) == ""`, но саму
// проверку терять нельзя: pg_dump, отработавший вхолостую, обязан считаться
// отказом. Иначе набор копий выглядит снятым, а внутри пусто — и выясняется это
// при восстановлении, то есть в худший из возможных моментов.
type sqlSink struct {
	w        io.Writer
	written  int64
	nonSpace bool
}

func (s *sqlSink) Write(p []byte) (int, error) {
	if !s.nonSpace && len(bytes.TrimSpace(p)) > 0 {
		s.nonSpace = true
	}
	n, err := s.w.Write(p)
	s.written += int64(n)
	return n, err
}

func (s *sqlSink) hasContent() bool { return s.nonSpace }

// dumpPostgres выгружает базу ПОТОКОМ в файл.
//
// ДО 10.09.2026 ДАМП ЖИЛ В ПАМЯТИ. `dockerComposeEnv` собирает весь вывод в
// строку — то есть база чужого клиента целиком оказывалась в памяти агента на
// его же хосте, рядом с его боевыми контейнерами. Плюс `CombinedOutput`
// подмешивал stderr в начало файла: одно предупреждение docker compose — и
// `.sql` не восстанавливается, причём узнаётся это при восстановлении.
//
// Файл появляется под конечным именем только целиком: пишем в `.part` и
// переименовываем. Оборванный дамп с правильным именем — это набор копий,
// который выглядит годным и не является им.
func dumpPostgres(ctx context.Context, p Paths, app DesiredApp, pg PostgresBackup, dir string) error {
	path := filepath.Join(dir, "db-"+pg.Service+".sql")
	tmp := path + ".part"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("pg_dump базы %s: не создать файл: %w", pg.Database, err)
	}
	defer os.Remove(tmp)

	sink := &sqlSink{w: f}
	runErr := dockerComposeStream(ctx, p.appDir(app.Slug), filepath.Join(p.appDir(app.Slug), ".env"), sink,
		"exec", "-T", pg.Service,
		"pg_dump", "--clean", "--if-exists", "-U", pg.User, "-d", pg.Database)
	closeErr := f.Close()

	if runErr != nil {
		return fmt.Errorf("pg_dump базы %s: %w", pg.Database, runErr)
	}
	if closeErr != nil {
		return fmt.Errorf("pg_dump базы %s: не дописан на диск: %w", pg.Database, closeErr)
	}
	if !sink.hasContent() {
		return fmt.Errorf("pg_dump базы %s вернул пустой результат", pg.Database)
	}

	return os.Rename(tmp, path)
}

// archiveVolume упаковывает том через временный контейнер: содержимое тома
// живёт в пространстве docker, и напрямую с хоста к нему обращаться нельзя.
func archiveVolume(ctx context.Context, slug, vol, dir string) error {
	full := volumeName(slug, vol)
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", full+":/from:ro",
		"-v", dir+":/to",
		"alpine:3.21",
		"tar", "czf", "/to/vol-"+vol+".tar.gz", "-C", "/from", ".")
	cmd.Env = dockerEnv()

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("архивация тома %s: %w: %s", full, err, tail(string(out), 300))
	}
	return nil
}

// ensureFreeSpace отказывается делать копию, если места заведомо не хватит.
//
// Заполненный под завязку диск — это не только неудачная копия: он ломает и
// работающие приложения. Лучше отказать в обновлении с внятной причиной.
// requiredFreeBytes — сколько места обязано быть свободно под набор.
//
// Множитель применяется к СУММЕ томов и дампов, а не к одним томам: дамп
// ложится на тот же диск, и запас «в полтора раза» без него держался бы лишь
// наполовину. Нижний порог остаётся всегда — забитый под завязку диск ломает
// не только копию, но и работающие приложения.
func requiredFreeBytes(volumesTotal, dumpsTotal int64) int64 {
	return int64(float64(volumesTotal+dumpsTotal)*backupFreeSpaceFactor) + backupMinFreeBytes
}

func ensureFreeSpace(ctx context.Context, p Paths, slug string, spec BackupSpec, dir string) error {
	var total int64
	for _, vol := range spec.Volumes {
		size, err := volumeSize(ctx, slug, vol)
		if err != nil {
			// Размер не измерился — не повод отказывать, но и не повод молчать.
			fmt.Fprintf(os.Stderr, "размер тома %s не измерен: %v\n", vol, err)
			continue
		}
		total += size
	}

	// ДАМПЫ СЧИТАЮТСЯ ОТДЕЛЬНО И ИЗМЕРЕНИЕМ, А НЕ ДОЛЕЙ ОТ ТОМОВ.
	//
	// До 10.09.2026 их не было в расчёте вовсе. Прикинуть их размер по объёму
	// томов нельзя: том базы — это ещё и индексы, и раздутие, а какой из томов
	// принадлежит базе, задание не говорит. Зато сама база знает свой размер
	// точно, и спросить её — один запрос по тому же пути, которым идёт дамп.
	//
	// Оценка получается с запасом в безопасную сторону: плоская выгрузка почти
	// всегда меньше базы на диске — индексы уезжают строкой `CREATE INDEX`, а
	// не данными.
	var dumps int64
	for _, pg := range spec.Postgres {
		size, err := databaseSize(ctx, p, slug, pg)
		if err != nil {
			// Как и с томами: молчать нельзя, но и отказывать в копии из-за
			// неизмеренного размера — хуже, чем сделать её с меньшим запасом.
			fmt.Fprintf(os.Stderr, "размер базы %s не измерен: %v\n", pg.Database, err)
			continue
		}
		dumps += size
	}

	need := requiredFreeBytes(total, dumps)
	free, err := freeBytes(dir)
	if err != nil {
		return fmt.Errorf("не удалось узнать свободное место: %w", err)
	}
	if free < need {
		return fmt.Errorf(
			"недостаточно места для резервной копии: нужно ~%d МБ, свободно %d МБ. "+
				"Освободите место на сервере и повторите обновление",
			need>>20, free>>20)
	}
	return nil
}

func volumeSize(ctx context.Context, slug, vol string) (int64, error) {
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm",
		"-v", volumeName(slug, vol)+":/v:ro", "alpine:3.21",
		"du", "-sb", "/v")
	cmd.Env = dockerEnv()

	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return parseDuBytes(string(out))
}

// databaseSize спрашивает у самой базы, сколько она занимает.
//
// Идёт тем же путём, что и дамп (`compose exec` в тот же сервис), поэтому не
// добавляет ни зависимостей, ни прав: если pg_dump до базы дойдёт, дойдёт и
// этот запрос. Вывод РАЗБИРАЕТСЯ, значит stderr сюда примешивать нельзя — как и
// в дампе, отсюда `dockerComposeParsed`, а не `dockerComposeEnv`.
//
// `-At` — без заголовка и без выравнивания: одна строка с одним числом.
func databaseSize(ctx context.Context, p Paths, slug string, pg PostgresBackup) (int64, error) {
	out, err := dockerComposeParsed(ctx, p.appDir(slug), filepath.Join(p.appDir(slug), ".env"),
		"exec", "-T", pg.Service,
		"psql", "-U", pg.User, "-d", pg.Database, "-At",
		"-c", "SELECT pg_database_size(current_database())")
	if err != nil {
		return 0, err
	}

	size, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("размер базы не разобран из %q: %w", tail(strings.TrimSpace(out), 80), err)
	}
	return size, nil
}

// parseDuBytes достаёт число из вывода `du -sb`: «12345\t/v».
func parseDuBytes(out string) (int64, error) {
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) == 0 {
		return 0, fmt.Errorf("пустой вывод du")
	}
	return strconv.ParseInt(fields[0], 10, 64)
}

// pruneBackups оставляет только последние наборы.
//
// Ошибки только логируем: не убранная старая копия — это лишнее место на диске,
// а прерванное из-за неё обновление — простой приложения. Несоразмерно.
// pruneBackups — прежняя ретенция по умолчанию: два набора.
func pruneBackups(p Paths, slug string) { pruneBackupsKeeping(p, slug, 0) }

// pruneBackupsKeeping оставляет `keep` свежих наборов.
//
// keep <= 0 означает «платформа числа не прислала» — старый сервер рядом с
// новым агентом. Тогда действует прежнее число: молча оставить на диске
// бесконечную историю копий чужого сервера хуже, чем оставить две.
func pruneBackupsKeeping(p Paths, slug string, keep int) {
	if keep <= 0 {
		keep = backupsToKeep
	}
	entries, err := os.ReadDir(p.backupsDir(slug))
	if err != nil {
		return
	}

	var sets []string
	for _, e := range entries {
		if e.IsDir() {
			sets = append(sets, e.Name())
		}
	}
	if len(sets) <= keep {
		return
	}

	// Имена наборов — метки времени в UTC, поэтому лексикографический порядок
	// совпадает с хронологическим.
	sort.Strings(sets)
	for _, old := range sets[:len(sets)-keep] {
		if err := os.RemoveAll(filepath.Join(p.backupsDir(slug), old)); err != nil {
			fmt.Fprintf(os.Stderr, "старая копия %s не удалена: %v\n", old, err)
		}
	}
}

// LatestBackup возвращает самый свежий набор копий приложения.
func LatestBackup(p Paths, slug string) (string, bool) {
	entries, err := os.ReadDir(p.backupsDir(slug))
	if err != nil {
		return "", false
	}
	var sets []string
	for _, e := range entries {
		if e.IsDir() {
			sets = append(sets, e.Name())
		}
	}
	if len(sets) == 0 {
		return "", false
	}
	sort.Strings(sets)
	return filepath.Join(p.backupsDir(slug), sets[len(sets)-1]), true
}

// RestoreBackup возвращает приложение к состоянию из набора копий (ADR-0063).
//
// ВСЁ ПРОВЕРЯЕМОЕ — ДО `down`: годность набора, образ и том базы по описанию из
// копии, целостность архивов. Отказ, найденный после остановки, — уже простой с
// очищенными томами.
//
// БАЗА — ИЗ ДАМПА, А НЕ ИЗ АРХИВА ТОМА. Согласованный снимок есть только в
// дампе: pg_dump снимает его одной транзакцией, а tar читает файлы работающей
// базы в разные моменты. Дамп ложится в ПУСТОЙ каталог данных, а не поверх
// прежней базы: `--clean` снёс бы только объекты из дампа, и таблицы новой
// версии остались бы.
//
// Остальные тома восстанавливаются ЦЕЛИКОМ, с предварительной очисткой: новая
// версия могла добавить файлы, которых в снимке нет, и оставленные, они сбили
// бы с толку старый код. Под работающим контейнером том не трогаем — он держит
// файлы открытыми.
//
// С первого касания стека и до удачного конца стоит флаг восстановления:
// сорвавшееся посреди восстановление самовосстановление не поднимет.
//
// Тексты отказов затираются значениями переменных в одной точке, на выходе: в
// хвостах docker бывают значения переменных, а отказ уезжает в отчёт.
func RestoreBackup(ctx context.Context, p Paths, app DesiredApp, setDir string) (err error) {
	defer func() {
		if err != nil {
			err = errors.New(redactSecrets(err.Error(), app.redactionValues()))
		}
	}()

	if !safeSlug.MatchString(app.Slug) {
		return fmt.Errorf("недопустимый slug приложения: %q", app.Slug)
	}
	spec := app.ApplySpec.normalized()
	appDir := p.appDir(app.Slug)
	envPath := filepath.Join(appDir, ".env")
	databases := app.BackupSpec.Postgres

	archives, err := checkRestoreSet(setDir, app.BackupSpec)
	if err != nil {
		return err
	}

	// Описание стека из набора — той же политикой, что выкат, и до всего, что
	// трогает стек: иначе восстановление и автооткат поднимали бы то, что
	// выкат отверг (ADR-0092, решение 14).
	if err := verifyRestoreSet(ctx, p, app, setDir); err != nil {
		return err
	}

	// Модель набора — только чтобы узнать образ и том базы. Стек из каталога
	// набора не запускается никогда: у Supabase init-скрипты смонтированы с
	// create_host_path, и docker насоздавал бы пустых каталогов на их месте.
	var databaseVolumes []string
	if len(databases) > 0 {
		model, err := composeModelOfSet(ctx, setDir)
		if err != nil {
			return err
		}
		for _, pg := range databases {
			if err := databaseImageRefusal(model, pg); err != nil {
				return err
			}
			vol, err := databaseVolume(model, app.BackupSpec, pg)
			if err != nil {
				return err
			}
			if !slices.Contains(databaseVolumes, vol) {
				databaseVolumes = append(databaseVolumes, vol)
			}
		}
	}

	// Архив тома базы не распаковывается, и читать его незачем.
	for _, archive := range archives {
		if vol, _ := volumeOfArchive(archive); slices.Contains(databaseVolumes, vol) {
			continue
		}
		if err := verifyVolumeArchive(ctx, setDir, archive); err != nil {
			return err
		}
	}

	if err := setRestoreFlag(p, app.Slug, filepath.Base(setDir)); err != nil {
		return fmt.Errorf("флаг восстановления не поставлен, стек не тронут: %w", err)
	}

	if out, err := dockerComposeEnv(ctx, appDir, envPath, "down", "--remove-orphans"); err != nil {
		return fmt.Errorf("не удалось остановить стек перед откатом: %w: %s", err, tail(out, 300))
	}

	// Описание стека — ДО данных: образ базы и пароли ролей, которые читают
	// init-скрипты на пустом каталоге данных, обязаны быть из копии. Прежний
	// довод «прерванный откат оставит старые данные при новом compose» закрывает
	// флаг: сорвавшееся восстановление стек не поднимает.
	for _, name := range []string{"docker-compose.yml", ".env"} {
		raw, err := os.ReadFile(filepath.Join(setDir, name))
		if err != nil {
			continue
		}
		mode := os.FileMode(0o640)
		if name == ".env" {
			mode = 0o600
		}
		if err := writeFileAtomic(filepath.Join(appDir, name), raw, mode); err != nil {
			return fmt.Errorf("не удалось вернуть %s: %w", name, err)
		}
	}

	for _, archive := range archives {
		vol, _ := volumeOfArchive(archive)
		if slices.Contains(databaseVolumes, vol) {
			continue
		}
		if err := restoreVolume(ctx, app.Slug, vol, setDir, archive); err != nil {
			return err
		}
	}

	if len(databases) > 0 {
		// Архив не передаётся: том базы только очищается, чтобы init-скрипты
		// образа выполнились на пустом каталоге и дамп лёг в чистую базу.
		for _, vol := range databaseVolumes {
			if err := restoreVolume(ctx, app.Slug, vol, "", ""); err != nil {
				return err
			}
		}

		var services []string
		for _, pg := range databases {
			if !slices.Contains(services, pg.Service) {
				services = append(services, pg.Service)
			}
		}
		upArgs := append([]string{"up", "-d", "--wait", "--wait-timeout", strconv.Itoa(spec.WaitTimeoutSeconds)},
			services...)
		if out, err := dockerComposeEnv(ctx, appDir, envPath, upArgs...); err != nil {
			return fmt.Errorf("база не поднялась для загрузки дампа: %w: %s", err, tail(out, 500))
		}

		for _, pg := range databases {
			if err := waitDatabaseReady(ctx, appDir, envPath, pg, spec.WaitTimeout()); err != nil {
				return err
			}
			if err := loadDump(ctx, appDir, envPath, setDir, pg, app.redactionValues()); err != nil {
				return err
			}
		}
	}

	// Срок и проверка устойчивости — те же, что у выката: стек стартует
	// одинаково долго, кто бы ни нажал (ADR-0063, решение 5).
	if out, err := dockerComposeEnv(ctx, appDir, envPath, "up", "-d", "--remove-orphans",
		"--wait", "--wait-timeout", strconv.Itoa(spec.WaitTimeoutSeconds)); err != nil {
		return fmt.Errorf("стек не поднялся после отката: %w: %s", err, tail(out, 500))
	}
	if err := waitStable(ctx, appDir, envPath, spec); err != nil {
		return fmt.Errorf("стек не устоял после отката: %w", err)
	}

	// Данные уже возвращены: неснятый флаг не делает восстановление неудачным,
	// и отчёт «не удалось» был бы ложью.
	if err := clearRestoreFlag(p, app.Slug); err != nil {
		fmt.Fprintf(os.Stderr, "восстановление %s удалось, но флаг не снят: %v\n", app.Slug, err)
	}
	return nil
}

// restoreVolume очищает том и распаковывает в него архив из набора.
//
// Пустой archive — только очистка: том базы возвращает дамп, а не архив. Оба
// пути идут через одну функцию, чтобы очистка тома была записана в одном месте.
func restoreVolume(ctx context.Context, slug, vol, setDir, archive string) error {
	full := volumeName(slug, vol)
	args := []string{"run", "--rm", "-v", full + ":/to"}
	// find вместо `rm -rf /to/*`: последнее не трогает файлы, имя которых
	// начинается с точки, а в томе n8n именно такие.
	script := "find /to -mindepth 1 -delete"
	if archive != "" {
		args = append(args, "-v", setDir+":/from:ro")
		script += " && tar xzf /from/" + archive + " -C /to"
	}
	cmd := exec.CommandContext(ctx, "docker", append(args, "alpine:3.21", "sh", "-c", script)...)
	cmd.Env = dockerEnv()

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("восстановление тома %s: %w: %s", full, err, tail(string(out), 300))
	}
	return nil
}

// databaseReadyInterval — пауза между проверками готовности базы.
const databaseReadyInterval = 2 * time.Second

// waitDatabaseReady ждёт, пока база примет подключение ПО TCP.
//
// Проверка здоровья здесь не годится: у n8n и аддона это `pg_isready` через
// сокет, а на пустом каталоге данных сокет слушает временный сервер
// инициализации, который после init-скриптов перезапускается. Дамп, начатый в
// этот момент, оборвался бы. Временный сервер TCP не слушает, поэтому на
// `-h 127.0.0.1` отвечает только настоящий (ADR-0063, решение 1). При выкате
// каталог пуст один раз в жизни приложения, при восстановлении — каждый раз.
func waitDatabaseReady(ctx context.Context, appDir, envPath string, pg PostgresBackup, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		out, err := dockerComposeEnv(ctx, appDir, envPath,
			"exec", "-T", pg.Service, "pg_isready", "-h", "127.0.0.1", "-U", pg.User, "-d", pg.Database)
		if err == nil {
			return nil
		}
		if time.Now().Add(databaseReadyInterval).After(deadline) {
			return fmt.Errorf("база %s не приняла подключение за %d с после подъёма: %s",
				pg.Database, int(timeout.Seconds()), tail(out, 200))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(databaseReadyInterval):
		}
	}
}

// loadDump вливает дамп из набора в базу потоком.
//
// Текст отказа собирается ТОЛЬКО из psqlFailure. runStreaming и
// dockerComposeParsed здесь не годятся: они кладут хвост stderr в текст ошибки,
// а у psql там CONTEXT со строкой данных клиента, и отказ уехал бы в журнал,
// который читает любой участник проекта (ADR-0063, решение 8).
//
// VERBOSITY=terse срезает DETAIL и CONTEXT ещё у psql, и данные клиента не
// попадают даже в память агента; psqlFailure остаётся гарантией. -X — .psqlrc
// образа не меняет поведение. ON_ERROR_STOP с --single-transaction — потому что
// наполовину влитая база выглядит рабочей.
//
// Пользователь и подключение через сокет — те же, что у pg_dump.
func loadDump(ctx context.Context, appDir, envPath, setDir string, pg PostgresBackup, values map[string]string) error {
	dump, err := os.Open(filepath.Join(setDir, "db-"+pg.Service+".sql"))
	if err != nil {
		return fmt.Errorf("дамп базы %s не открылся: %w", pg.Database, err)
	}
	defer dump.Close()

	cmd := newDockerCmd(ctx, appDir, composeArgs(envPath, []string{"exec", "-T", pg.Service,
		"psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=terse", "--single-transaction",
		"-U", pg.User, "-d", pg.Database})...)
	// Хвост, а не весь вывод: при ON_ERROR_STOP причина идёт последней, а
	// сколько psql напечатает до неё, не ограничено ничем — это вывод чужого
	// дампа. NOTICE от `DROP … IF EXISTS` тут ни при чём: дамп сам начинается
	// с `SET client_min_messages = warning`, и их не видно вовсе.
	stderr := newTailBuffer(psqlStderrTailBytes)
	cmd.Stdin = dump
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		reason := psqlFailure(fromFirstFullLine(stderr.Tail(), psqlStderrTailBytes), values)
		if reason == "" {
			reason = fmt.Sprintf("psql завершился с ошибкой (%v)", err)
		}
		return fmt.Errorf("дамп базы %s не влит: %s", pg.Database, reason)
	}
	return nil
}
