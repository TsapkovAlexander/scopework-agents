package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tracedocs.ru/deploy-agent/pkg/stackdir"
)

// Вспомогательные файлы шаблона.
//
// ЗАЧЕМ. До сих пор приложению из каталога агент клал на диск ровно два файла:
// docker-compose.yml и .env. Для n8n этого хватало — весь стек настраивается
// переменными окружения.
//
// Supabase так не собирается: Kong читает маршруты из volumes/api/kong.yml,
// база инициализируется набором SQL в volumes/db/. Без способа доставить эти
// файлы стек из каталога невозможен в принципе, а класть их в образ значило бы
// собирать и хранить собственные образы всего стека.
//
// ГРАНИЦЫ. Файлы приходят с сервера, то есть это недоверенный вход — ровно как
// compose и переменные. Разница в том, что здесь вход задаёт ПУТЬ, а не только
// содержимое, и без ограничений «положить конфиг» превратилось бы в «записать
// куда угодно от имени агента»: в юнит systemd, в authorized_keys, в каталог
// соседнего приложения.
//
// Секретов в этих файлах не бывает: подстановка значений не делается, шаблон
// несёт статический текст. Всё, что зависит от секретов, разворачивается уже
// внутри контейнера из переменных окружения (envsubst в entrypoint Kong).

// DesiredFile — один файл шаблона.
type DesiredFile struct {
	// Path — путь относительно каталога приложения. Только вперёд по дереву.
	Path string `json:"path"`
	// Mode — права в восьмеричном виде ("0644"). Пусто — 0644.
	Mode    string `json:"mode"`
	Content string `json:"content"`
}

const (
	// Потолки на случай ошибки или компрометации control plane: желаемое
	// состояние не должно уметь занять диск клиента конфигурацией.
	maxTemplateFiles      = 64
	maxTemplateFileBytes  = 256 << 10
	maxTemplateTotalBytes = 1 << 20
)

// Правила путей и прав файлов шаблона — в pkg/stackdir: подписант раскладывает
// те же файлы у себя, чтобы нормализовать compose, и путь, принятый им, обязан
// быть принят и здесь. Запись на диск и проверка симлинков остаются у агента.

// resolveTemplateFilePath проверяет путь файла шаблона и возвращает его внутри
// каталога приложения.
func resolveTemplateFilePath(appDir, raw string) (string, error) {
	return stackdir.ResolveFilePath(appDir, raw)
}

// parseFileMode — права файла шаблона; пусто — 0644.
func parseFileMode(raw string) (os.FileMode, error) { return stackdir.ParseFileMode(raw) }

// writeTemplateFiles раскладывает файлы шаблона внутри каталога приложения.
//
// Сначала проверяются ВСЕ записи и только потом пишется хоть что-то: частично
// разложенный набор конфигов хуже, чем неразложенный совсем — стек поднялся бы
// с половиной настроек и вёл себя необъяснимо.
//
// Устаревшие файлы не удаляются. Новая версия шаблона перезаписывает те же
// пути, а файл, выброшенный из шаблона, остаётся лежать неиспользованным:
// удалять с диска клиента по списку, пришедшему по сети, — операция, цена
// ошибки в которой несопоставима с выгодой от чистоты каталога.
// ensureNoSymlinks проверяет каждый компонент пути внутри каталога приложения.
//
// Сам файл проверяется тоже: подмена существующего файла ссылкой — тот же
// выход наружу, только без промежуточного каталога. Несуществующий файл это не
// ошибка: его мы и собираемся создать.
func ensureNoSymlinks(appDir, full string) error {
	rel, err := filepath.Rel(appDir, full)
	if err != nil {
		return fmt.Errorf("путь %s вне каталога приложения", tail(filepath.Base(full), 80))
	}

	current := appDir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			// Дальше по пути ничего нет — создавать будем мы сами.
			return nil
		}
		if err != nil {
			return fmt.Errorf("путь %s не проверить: %w", tail(part, 80), err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("на пути к %s лежит ссылка %s: запись ушла бы за пределы каталога приложения",
				tail(filepath.Base(full), 80), tail(part, 80))
		}
	}
	return nil
}

func writeTemplateFiles(appDir string, files []DesiredFile) error {
	if len(files) == 0 {
		return nil
	}
	if len(files) > maxTemplateFiles {
		return fmt.Errorf("файлов шаблона %d, допустимо не больше %d", len(files), maxTemplateFiles)
	}

	type planned struct {
		path    string
		mode    os.FileMode
		content []byte
	}

	plan := make([]planned, 0, len(files))
	total := 0
	seen := make(map[string]bool, len(files))

	for _, file := range files {
		full, err := resolveTemplateFilePath(appDir, file.Path)
		if err != nil {
			return err
		}
		if seen[full] {
			return fmt.Errorf("файл %q объявлен дважды", tail(file.Path, 80))
		}
		seen[full] = true

		mode, err := parseFileMode(file.Mode)
		if err != nil {
			return err
		}
		if len(file.Content) > maxTemplateFileBytes {
			return fmt.Errorf("файл %q больше %d байт", tail(file.Path, 80), maxTemplateFileBytes)
		}
		total += len(file.Content)
		if total > maxTemplateTotalBytes {
			return fmt.Errorf("суммарный размер файлов шаблона больше %d байт", maxTemplateTotalBytes)
		}

		plan = append(plan, planned{path: full, mode: mode, content: []byte(file.Content)})
	}

	for _, item := range plan {
		// На месте файла может лежать КАТАЛОГ, и это не редкость.
		//
		// Docker при монтировании несуществующего пути создаёт его сам — и
		// создаёт каталогом. Стоит один раз подняться стеку без файлов
		// шаблона ((например, агент был старой версии и поля `files` не знал),
		// и `./volumes/db/roles.sql` превращается в каталог. Дальше атомарная
		// запись отказывает навсегда: rename не заменяет каталог файлом, а
		// приложение остаётся в вечном «не удалось записать roles.sql».
		//
		// Удаляем осознанно: путь уже проверен и лежит внутри каталога
		// приложения, а шаблон объявил его именно файлом.
		if info, err := os.Lstat(item.path); err == nil && info.IsDir() {
			if err := os.RemoveAll(item.path); err != nil {
				return fmt.Errorf("на месте %s каталог, удалить не удалось: %w",
					filepath.Base(item.path), err)
			}
		}

		// 0755 на каталогах: внутрь контейнера уезжает bind-mount, а процессы
		// там работают не от root — 0750 сделало бы каталог непроходимым и
		// конфиг нечитаемым, причём с невнятной ошибкой самого сервиса.
		if err := os.MkdirAll(filepath.Dir(item.path), 0o755); err != nil {
			return fmt.Errorf("не удалось создать каталог для %s: %w", filepath.Base(item.path), err)
		}

		// НИ ОДИН КОМПОНЕНТ ПУТИ НЕ СИМЛИНК (С1.10 плана радиуса поражения).
		//
		// Путь уже проверен от `..` и абсолютных — но проверен как СТРОКА.
		// Контейнер работает в том же каталоге и волен положить туда ссылку:
		// тогда безобидное `volumes/db/roles.sql` пишется по ней, куда укажет
		// он сам. Проверка идёт после MkdirAll: каталоги, созданные нами
		// секунду назад, ссылками быть не могут, а созданные контейнером — да.
		if err := ensureNoSymlinks(appDir, item.path); err != nil {
			return err
		}

		if err := writeFileAtomic(item.path, item.content, item.mode); err != nil {
			return fmt.Errorf("не удалось записать %s: %w", filepath.Base(item.path), err)
		}
	}
	return nil
}
