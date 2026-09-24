package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Отметки о том, что уже применено на этом хосте.
//
// Без них агент на каждом опросе заново поднимал бы все стеки: `up` вхолостую
// раз в минуту, а главное — ожидание устойчивости по три замера на каждое
// приложение. При нескольких проблемных приложениях следующий heartbeat уходил
// бы через минуты, и хост выглядел бы мёртвым, будучи живым.
//
// Файл лежит в StateDir рядом с ключом, а не в рабочем каталоге: это состояние
// агента, а не приложения, и переживать пересоздание стека оно должно.

const appliedFileName = "applied.json"

// Как долго не трогать приложение после неудачной попытки.
//
// Без паузы сломанный стек занимал бы весь цикл агента бесконечно: три замера
// ожидания, отказ, и всё сначала через минуту. Пауза даёт остальным
// приложениям обслуживаться, а сломанному — шанс на повтор, когда причина
// уйдёт сама (недоступный реестр образов, кончившееся место).
const failedRetryDelay = 10 * time.Minute

// AppliedRecord — что и когда мы применили для одного приложения.
type AppliedRecord struct {
	ReleaseID string `json:"release_id"`
	// Хеш пары (compose, env). Релиз может остаться тем же, а переменные
	// смениться — по одному идентификатору релиза это не поймать.
	ConfigHash  string    `json:"config_hash"`
	Status      string    `json:"status"`
	LastAttempt time.Time `json:"last_attempt"`
	// Самовосстановление (recover.go): сколько раз подряд агент поднимал
	// упавшие контейнеры и когда делал это в последний раз. Живут здесь, а не
	// отдельным файлом, потому что решение принимается по ним вместе с
	// остальным состоянием применения.
	RecoveryAttempts int       `json:"recovery_attempts,omitempty"`
	LastRecovery     time.Time `json:"last_recovery,omitempty"`
	// Базовая линия сверки дрейфа (ADR-0078): sha256 ровно тех байтов, что
	// агент записал на диск. ConfigHash для этого не годится — он считается от
	// желаемого, не включает домен git-приложения и не видит, дошла ли запись
	// до диска. Пусто — файл этой версией агента ещё не писался.
	ComposeSha256 string `json:"compose_sha256,omitempty"`
	EnvSha256     string `json:"env_sha256,omitempty"`
}

// AppliedState — отметки по всем приложениям хоста.
type AppliedState struct {
	Apps map[string]AppliedRecord `json:"apps"`
}

func appliedPath(p Paths) string { return filepath.Join(p.StateDir, appliedFileName) }

// PresentSlugs — что РЕАЛЬНО развёрнуто на хосте прямо сейчас.
//
// Нужен серверу, чтобы подтвердить удаление приложения. Присылается полный
// список, а не «я снял вот это»: отчёт теряется при любом сетевом сбое, и
// дельта после потери не восстановится никогда, а полный список идемпотентен —
// следующий цикл доделает.
//
// Читаем ФАЙЛОВУЮ СИСТЕМУ, а не applied.json. Отметки — это память агента о
// том, что он делал, и она может пропасть: файл повреждён, каталог состояния
// пересоздан, агент переустановлен. LoadApplied в таком случае возвращает
// пустое состояние — правильно для решения «применять ли», но как ответ «на
// хосте ничего нет» это ложь, по которой сервер удалил бы все приложения в
// статусе deleting, оставив их работать на хосте. Ровно тот осиротевший стек,
// ради которого удаление и сделали двухфазным.
//
// Возвращает nil, если прочитать каталог не удалось: пустой список — это
// утверждение «здесь пусто», и делать его наугад нельзя.
//
// Порядок фиксирован, чтобы одинаковое состояние давало одинаковый запрос и
// не выглядело в логах сервера как постоянное изменение.
func PresentSlugs(p Paths) []string {
	entries, err := os.ReadDir(filepath.Join(p.WorkDir, "apps"))
	if err != nil {
		if os.IsNotExist(err) {
			// Каталога нет — на хосте действительно ничего не разворачивали.
			return []string{}
		}
		fmt.Fprintf(os.Stderr, "не удалось прочитать каталог приложений: %v\n", err)
		return nil
	}

	slugs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Каталог, созданный не нами, в отчёт не идёт: сервер сверяет по slug,
		// и мусор мог бы помешать удалению настоящего приложения.
		if !safeSlug.MatchString(name) {
			continue
		}
		slugs = append(slugs, name)
	}
	sort.Strings(slugs)
	return slugs
}

// LoadApplied читает отметки. Отсутствие файла — не ошибка: так выглядит
// первый запуск.
func LoadApplied(p Paths) AppliedState {
	state := AppliedState{Apps: map[string]AppliedRecord{}}

	raw, err := os.ReadFile(appliedPath(p))
	if err != nil {
		return state
	}
	if err := json.Unmarshal(raw, &state); err != nil || state.Apps == nil {
		// Повреждённый файл не повод падать: худшее последствие — один лишний
		// прогон применения, после которого файл перезапишется корректным.
		return AppliedState{Apps: map[string]AppliedRecord{}}
	}
	return state
}

// SaveApplied сохраняет отметки атомарно.
func SaveApplied(p Paths, state AppliedState) error {
	if err := os.MkdirAll(p.StateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	// 0600: сами отметки секретов не содержат, но лежат рядом с ключом, и
	// расширять права в этом каталоге незачем.
	return writeFileAtomic(appliedPath(p), data, 0o600)
}

// hashableEnv — то же окружение, но без служебных строк, которые для
// приложения из репозитория ничего не значат.
//
// APP_DOMAIN входит в .env всегда, и для приложения из КАТАЛОГА это правильно:
// в шаблоне Supabase адрес подставлен в переменные сервисов
// (API_EXTERNAL_URL, SUPABASE_PUBLIC_URL), и без пересоздания контейнеров
// новый домен просто не заработает.
//
// А у приложения из репозитория эта переменная не используется ничем: compose
// пишет либо автор, либо агент, и ни один из них про APP_DOMAIN не знает. Тем
// не менее смена домена меняла отпечаток, и агент шёл в полный цикл: FetchRepo,
// `docker compose build`, пересоздание контейнеров, ожидание устойчивости — при
// том что и панель, и ответ API обещают «стек не перезапускается».
//
// Обещание было ложным, и чинить нужно поведение, а не текст: домен читается
// из желаемого состояния на каждом опросе, и прокси перерисовывается без
// участия стека.
func hashableEnv(app DesiredApp) string {
	env := renderEnv(app)
	if !app.FromGit() {
		return env
	}
	lines := strings.Split(env, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, "APP_DOMAIN=") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// configHash считает отпечаток того, что реально уедет на диск.
//
// Берётся именно отрендеренный .env, а не исходная карта переменных: так
// изменение служебных полей (slug) тоже меняет хеш, и приложение
// переприменяется. Исключение — APP_DOMAIN у приложений из репозитория,
// см. hashableEnv.
func configHash(app DesiredApp) string {
	h := sha256.New()
	h.Write([]byte(app.Compose))
	h.Write([]byte{0})
	h.Write([]byte(hashableEnv(app)))
	// Источник тоже в отпечатке: у приложения из репозитория Compose всегда
	// пустой, и без этих полей смена ветки или адреса репозитория не привела
	// бы к переприменению — агент продолжал бы держать стек из старой ветки.
	// Ключ в отпечаток НЕ входит: его ротация кода не меняет, а на диск он
	// каждый раз попадает заново.
	h.Write([]byte{0})
	h.Write([]byte(app.SourceType))
	h.Write([]byte{0})
	h.Write([]byte(app.GitRepo))
	h.Write([]byte{0})
	h.Write([]byte(app.GitBranch))
	// BuildMethod — смена способа сборки (например, с dockerfile на static)
	// не трогает ни Compose (пуст для git в обоих случаях), ни GitRepo, ни
	// GitBranch, поэтому без явного отпечатка агент решил бы, что применять
	// нечего, и продолжил бы держать стек по старому способу.
	h.Write([]byte{0})
	h.Write([]byte(app.BuildMethod))
	// Папка приложения и контекст сборки (0284) — по той же причине: смена
	// `apps/web` на `apps/api` не меняет ни адрес репозитория, ни ветку, ни
	// способ сборки, и без отпечатка агент держал бы стек прежнего сервиса,
	// показывая в панели новый.
	h.Write([]byte{0})
	h.Write([]byte(app.GitBaseDir))
	h.Write([]byte{0})
	if app.GitBuildContextRoot {
		h.Write([]byte{1})
	}

	// Файлы шаблона — часть того, что реально уедет на диск. Без них правка
	// конфига Kong в каталоге без смены версии не доехала бы до хоста никогда:
	// релиз тот же, переменные те же, значит «уже применено».
	//
	// Порядок фиксируем сортировкой: в ответе сервера он может измениться, а
	// изменение отпечатка от одной только перестановки означало бы лишний
	// перезапуск стека на каждом цикле.
	files := append([]DesiredFile(nil), app.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	for _, file := range files {
		h.Write([]byte{0})
		h.Write([]byte(file.Path))
		h.Write([]byte{0})
		h.Write([]byte(file.Mode))
		h.Write([]byte{0})
		h.Write([]byte(file.Content))
	}

	// Сервисы, которым назначены домены.
	//
	// Именно СЕРВИСЫ, а не домены. Для приложения из репозитория членство в
	// сети прокси выводится из маршрутов при подготовке описания: сервис без
	// маршрута к сети не подключается. Значит добавленный маршрут обязан
	// вызвать переприменение — иначе прокси будет направлен в контейнер,
	// который в его сети не состоит, и домен ответит 502 при зелёном
	// приложении.
	//
	// Домены в отпечаток НЕ входят намеренно: смена адреса у того же сервиса
	// членства в сети не меняет, прокси перечитывает её каждый цикл, и
	// перезапускать из-за неё стек незачем — это заявленное свойство.
	services := map[string]bool{}
	for _, r := range effectiveRoutes(app) {
		if r.Service != "" {
			services[r.Service] = true
		}
	}
	published := make([]string, 0, len(services))
	for name := range services {
		published = append(published, name)
	}
	sort.Strings(published)
	for _, name := range published {
		h.Write([]byte{0})
		h.Write([]byte(name))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// needsApply решает, нужно ли трогать приложение.
//
// Возвращает причину — она уходит в лог, и без неё разбираться, почему агент
// «ничего не делает» или «делает постоянно», пришлось бы вслепую.
// composeMissing — признак «описания стека в служебном каталоге нет».
//
// Передаётся отдельным аргументом, а не читается здесь: needsApply — чистое
// решение и проверяется тестами без файловой системы.
func needsApply(
	rec AppliedRecord,
	found bool,
	app DesiredApp,
	now time.Time,
	composeMissing bool,
) (bool, string) {
	if !found {
		return true, "не применялось"
	}
	// Приложение применено прежней версией агента, которая поднимала стек ИЗ
	// РАБОЧЕЙ КОПИИ и в служебный каталог описание не клала. Проверка здоровья,
	// восстановление и уборка теперь работают только оттуда, и без
	// переприменения такое приложение осталось бы без описания навсегда:
	// отпечаток конфигурации не менялся, релиз тот же, причины тронуть его нет.
	// Стек при этом продолжал бы крутиться под прежним именем проекта —
	// осиротевшим.
	if composeMissing {
		return true, "в служебном каталоге нет описания стека"
	}
	if rec.ReleaseID != app.ReleaseID {
		return true, "новый релиз"
	}
	if rec.ConfigHash != configHash(app) {
		return true, "изменились переменные или compose"
	}
	if rec.Status == "failed" {
		if now.Sub(rec.LastAttempt) < failedRetryDelay {
			return false, "недавняя неудача, ждём паузу"
		}
		return true, "повтор после неудачи"
	}
	return false, "уже применено"
}
