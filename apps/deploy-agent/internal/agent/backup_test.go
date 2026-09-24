package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Имена из задания уезжают в аргументы docker. Задание приходит из НАШЕГО
// каталога, но каталог правят люди, и опечатка не должна становиться флагом.
func TestBackupSpecValidate(t *testing.T) {
	bad := []BackupSpec{
		{Postgres: []PostgresBackup{{Service: "-rm", User: "n8n", Database: "n8n"}}},
		{Postgres: []PostgresBackup{{Service: "db", User: "n8n x", Database: "n8n"}}},
		{Postgres: []PostgresBackup{{Service: "db", User: "n8n", Database: "n8n\nDROP"}}},
		{Postgres: []PostgresBackup{{Service: "", User: "n8n", Database: "n8n"}}},
		{Volumes: []string{"../escape"}},
		{Volumes: []string{"-v"}},
		{Volumes: []string{"vol name"}},
	}
	for _, spec := range bad {
		if err := spec.validate(); err == nil {
			t.Errorf("принято недопустимое задание: %+v", spec)
		}
	}

	good := BackupSpec{
		Postgres: []PostgresBackup{{Service: "db", User: "n8n", Database: "n8n"}},
		Volumes:  []string{"db-data", "app-data"},
	}
	if err := good.validate(); err != nil {
		t.Errorf("отвергнуто корректное задание: %v", err)
	}
}

// Задание приходит из БД как jsonb — форма должна разбираться без сюрпризов.
func TestBackupSpecFromJSON(t *testing.T) {
	raw := `{"postgres":[{"service":"db","user":"n8n","database":"n8n"}],"volumes":["db-data","app-data"]}`
	var spec BackupSpec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Postgres) != 1 || spec.Postgres[0].Service != "db" {
		t.Fatalf("база разобралась неверно: %+v", spec)
	}
	if len(spec.Volumes) != 2 {
		t.Fatalf("тома разобрались неверно: %+v", spec)
	}

	// Пустое задание — законное состояние: у приложения может не быть данных.
	var empty BackupSpec
	if err := json.Unmarshal([]byte(`{}`), &empty); err != nil || !empty.isEmpty() {
		t.Fatalf("пустое задание разобралось неверно: %+v, %v", empty, err)
	}
}

// compose приписывает к имени тома имя проекта, а проектом служит slug.
// Ошибка здесь означала бы архивацию чужого тома или пустоты.
func TestVolumeName(t *testing.T) {
	if got := volumeName("n8n", "db-data"); got != "n8n_db-data" {
		t.Errorf("получено %q, ожидалось n8n_db-data", got)
	}
}

func TestParseDuBytes(t *testing.T) {
	got, err := parseDuBytes("123456\t/v\n")
	if err != nil || got != 123456 {
		t.Fatalf("получено %d, ошибка %v", got, err)
	}
	if _, err := parseDuBytes("   \n"); err == nil {
		t.Error("пустой вывод принят")
	}
	if _, err := parseDuBytes("не число /v"); err == nil {
		t.Error("нечисловой вывод принят")
	}
}

// Имя набора — метка времени в UTC, чтобы сортировка строкой совпадала с
// хронологией: на ней держатся и уборка старых копий, и поиск последней.
func TestBackupSetNameSortsChronologically(t *testing.T) {
	early := backupSetName(time.Date(2026, 7, 25, 9, 0, 0, 0, time.UTC))
	late := backupSetName(time.Date(2026, 7, 25, 10, 0, 0, 0, time.UTC))
	if !(early < late) {
		t.Fatalf("порядок нарушен: %s должно быть меньше %s", early, late)
	}

	// Местное время не должно влиять на имя: иначе смена часового пояса на
	// хосте перемешала бы наборы.
	msk := time.FixedZone("MSK", 3*3600)
	same := backupSetName(time.Date(2026, 7, 25, 12, 0, 0, 0, msk))
	if same != backupSetName(time.Date(2026, 7, 25, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("имя зависит от часового пояса: %s", same)
	}
}

func TestPruneBackupsKeepsLatest(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}
	dir := p.backupsDir("n8n")

	names := []string{"20260101-000000", "20260102-000000", "20260103-000000", "20260104-000000"}
	for _, n := range names {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Файл рядом с наборами не должен ни удаляться, ни считаться набором.
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	pruneBackups(p, "n8n")

	left := map[string]bool{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		left[e.Name()] = true
	}

	if left["20260101-000000"] || left["20260102-000000"] {
		t.Errorf("старые наборы не удалены: %v", left)
	}
	if !left["20260103-000000"] || !left["20260104-000000"] {
		t.Errorf("свежие наборы удалены: %v", left)
	}
	if !left["note.txt"] {
		t.Error("посторонний файл удалён")
	}
}

func TestLatestBackup(t *testing.T) {
	p := Paths{WorkDir: t.TempDir()}

	if _, ok := LatestBackup(p, "n8n"); ok {
		t.Error("копия найдена там, где её нет")
	}

	dir := p.backupsDir("n8n")
	for _, n := range []string{"20260101-000000", "20260305-120000", "20260102-000000"} {
		if err := os.MkdirAll(filepath.Join(dir, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	got, ok := LatestBackup(p, "n8n")
	if !ok || filepath.Base(got) != "20260305-120000" {
		t.Fatalf("получено %q", got)
	}
}

// Копия приложения с недопустимым slug не должна создаваться: slug задаёт путь
// на диске.
func TestCreateBackupRejectsBadSlug(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	app := DesiredApp{Slug: "../escape"}
	spec := BackupSpec{Volumes: []string{"db-data"}}

	if _, err := CreateBackup(t.Context(), p, app, spec); err == nil {
		t.Fatal("копия создана для недопустимого slug")
	}
}

// Пустое задание — не ошибка: приложению может быть нечего резервировать.
// Возвращается пустой путь, и обновление продолжается.
func TestCreateBackupEmptySpec(t *testing.T) {
	p := Paths{WorkDir: t.TempDir(), StateDir: t.TempDir()}
	dir, err := CreateBackup(t.Context(), p, DesiredApp{Slug: "n8n"}, BackupSpec{})
	if err != nil || dir != "" {
		t.Fatalf("получено %q, ошибка %v", dir, err)
	}
}

// Свободное место должно измеряться, иначе проверка перед копией бессмысленна.
func TestFreeBytes(t *testing.T) {
	got, err := freeBytes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got <= 0 {
		t.Fatalf("получено %d байт свободно", got)
	}
}

// Запас места обязан учитывать ДАМП, а не только тома.
//
// Дамп пишется на тот же диск, что и архивы томов (backup.go), и до 10.09.2026
// в запас не входил вовсе: место проверялось по сумме томов, а на диск ложилась
// ещё и плоская выгрузка базы. Для копии перед обновлением это уже риск, а для
// проверки восстановлением — тем более: рядом с боевыми данными оживает их
// вторая копия.
func TestRequiredFreeBytesCountsDump(t *testing.T) {
	const gb = int64(1) << 30

	volumesOnly := requiredFreeBytes(10*gb, 0)
	withDump := requiredFreeBytes(10*gb, 4*gb)

	if withDump <= volumesOnly {
		t.Fatalf("дамп не увеличил требование: без дампа %d, с дампом %d", volumesOnly, withDump)
	}

	// Множитель применяется к сумме, а не только к томам: иначе дамп попадал бы
	// в запас без коэффициента, и «в полтора раза» держалось бы лишь наполовину.
	want := int64(float64(14*gb)*backupFreeSpaceFactor) + backupMinFreeBytes
	if withDump != want {
		t.Fatalf("запас посчитан не по сумме: получили %d, ожидали %d", withDump, want)
	}
}

// Пустой набор всё равно требует нижнего порога: диск под завязку ломает и
// работающие приложения, а не только копию.
func TestRequiredFreeBytesKeepsFloor(t *testing.T) {
	if got := requiredFreeBytes(0, 0); got != backupMinFreeBytes {
		t.Fatalf("нижний порог потерян: %d, ожидали %d", got, backupMinFreeBytes)
	}
}

// Дамп льётся в файл ПОТОКОМ, и по дороге отвечает на вопрос «не пусто ли».
//
// Прежняя редакция держала весь дамп в памяти агента на ЧУЖОМ хосте
// (`CombinedOutput`) и проверяла пустоту строкой. Поток снимает и то, и другое,
// но проверку пустоты терять нельзя: pg_dump, отработавший вхолостую, обязан
// считаться отказом, а не «копия снята».
func TestSQLSinkCountsAndDetectsEmpty(t *testing.T) {
	var buf bytes.Buffer
	sink := &sqlSink{w: &buf}

	if _, err := sink.Write([]byte("  \n\t ")); err != nil {
		t.Fatalf("запись пробелов: %v", err)
	}
	if sink.hasContent() {
		t.Fatal("пробельный вывод принят за содержимое")
	}

	if _, err := sink.Write([]byte("CREATE TABLE t();")); err != nil {
		t.Fatalf("запись SQL: %v", err)
	}
	if !sink.hasContent() {
		t.Fatal("настоящий SQL не признан содержимым")
	}
	if buf.String() != "  \n\t CREATE TABLE t();" {
		t.Fatalf("поток исказил данные: %q", buf.String())
	}
	if sink.written != int64(len("  \n\t CREATE TABLE t();")) {
		t.Fatalf("счётчик байт разошёлся: %d", sink.written)
	}
}

// Предупреждение из stderr НЕ попадает в файл данных.
//
// Это критерий приёмки В1.4 плана непрерывности, и он не теоретический:
// docker compose печатает `time="..." level=warning msg="the attribute version
// is obsolete"` в stderr, а `version:` стоит в большинстве публичных compose.
// Прежняя редакция снимала дамп через `CombinedOutput`, то есть такая строка
// оказывалась ПЕРВОЙ в файле `.sql` — и восстановление спотыкалось об неё в тот
// момент, когда оно и понадобилось.
func TestRunStreamingKeepsStderrOutOfData(t *testing.T) {
	var data bytes.Buffer
	sink := &sqlSink{w: &data}

	cmd := exec.Command("sh", "-c",
		`echo 'time="2026-09-10" level=warning msg="the attribute version is obsolete"' >&2; `+
			`echo '-- PostgreSQL database dump'`)

	if err := runStreaming(cmd, sink); err != nil {
		t.Fatalf("команда не отработала: %v", err)
	}
	if got := data.String(); got != "-- PostgreSQL database dump\n" {
		t.Fatalf("в данные попало лишнее: %q", got)
	}
	if !sink.hasContent() {
		t.Fatal("содержимое не распознано")
	}
}

// Отказ команды остаётся объяснимым: stderr не выброшен, он в тексте ошибки.
func TestRunStreamingPutsStderrIntoError(t *testing.T) {
	var data bytes.Buffer
	err := runStreaming(exec.Command("sh", "-c", `echo "role does not exist" >&2; exit 1`), &data)
	if err == nil {
		t.Fatal("отказ команды не поднят")
	}
	if !strings.Contains(err.Error(), "role does not exist") {
		t.Fatalf("причина отказа потеряна: %v", err)
	}
}

// Имя набора приходит С ЗАДАНИЕМ, то есть по сети, и уезжает в путь на диске.
// Формат стережёт и база (0447), но агент живёт на чужой машине: `..` в имени
// означало бы распаковку архивов мимо рабочего каталога.
func TestValidBackupSetRejectsAnythingButTimestamp(t *testing.T) {
	bad := []string{
		"",
		"..",
		"../../etc",
		"20260910-120000/../..",
		"20260910",
		"20260910-12345",
		"20260910-1200000",
		"2026091-120000",
		"20260910_120000",
		"20260910-12000a",
		" 20260910-120000",
		"20260910-120000\n",
	}
	for _, set := range bad {
		if validBackupSet(set) {
			t.Errorf("принято недопустимое имя набора: %q", set)
		}
	}
	if !validBackupSet("20260910-120000") {
		t.Error("отвергнуто корректное имя набора")
	}
}

// Проверка обязана принимать ровно то, что кладёт на диск сам агент.
// Разойдись формат с backupSetName — восстановление отказывало бы на наборе,
// который платформа считает годным, и отказ был бы неотличим от «набора нет».
func TestValidBackupSetAcceptsWhatAgentCreates(t *testing.T) {
	set := backupSetName(time.Date(2026, 9, 10, 3, 4, 5, 0, time.UTC))
	if !validBackupSet(set) {
		t.Fatalf("имя, снятое агентом, не проходит проверку: %q", set)
	}
}
