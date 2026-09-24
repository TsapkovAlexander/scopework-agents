package composeguard

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// Вторая линия проверки ссылок на файлы: по модели самого compose.
//
// ЗАЧЕМ. Первая линия (CheckStackFileRefs) — своя реализация разбора YAML.
// Дважды за круг проверки она расходилась с go-yaml, и каждое расхождение
// было утечкой: compose видел env_file, которого не видела платформа. Здесь
// ссылки берутся из модели, которую построил сам compose, — расхождение
// разборов становится отказом, а не чужим .env в контейнере.
//
// КАК СНИМАТЬ МОДЕЛЬ — ModelRefArgs:
//   - `--no-env-resolution`: env_file остаётся путём и не читается. Без флага
//     compose прочёл бы файл и положил пары в environment — ровно то, от чего
//     защищаемся, и ссылку уже не было бы видно;
//   - `--no-interpolate`: значения переменных в модель не попадают, и
//     `${S}` в пути остаётся видимым как подстановка;
//   - пути разрешены (флага `--no-path-resolution` нет): compose сам
//     приводит их к абсолютным, в том числе у описаний из include, — и
//     проверяется ровно тот файл, который он откроет.
//
// ПОЧЕМУ ТОЛЬКО ПОСЛЕ ПЕРВОЙ ЛИНИИ. include и extends compose исполняет
// чтением файла при любых флагах. Без первой линии этот вызов прочёл бы
// описание соседа от uid подписанта или агента. Первая линия не пускает сюда
// абсолютные пути, `..` и `$`; эта ловит то, что первая пропустила бы из-за
// промаха разбора. Текст нарушения намеренно без путей и имён сервисов: если
// разбор всё же ошибся и compose прочёл чужое описание, имена из него не
// должны уехать в базу и на карточку релиза.
//
// ЧЕГО ЗДЕСЬ НЕ ВИДНО. После разбора в модели нет include и extends: их
// содержимое уже влито в сервисы. Файл переменных include (его env_file и .env
// включённого каталога) влияет только на подстановку и в модели без неё не
// виден. Эти ссылки держит первая линия.

// ModelRefArgs — аргументы `docker compose` для модели второй линии (после
// глобальных флагов вроде --env-file, --project-directory и -f).
var ModelRefArgs = []string{"config", "--no-interpolate", "--no-env-resolution", "--format", "json"}

// CheckModelFileRefs — ссылки на файлы в модели compose, снятой с
// ModelRefArgs: env_file и label_file каждого сервиса обязаны вести внутрь
// корня стека (после раскрытия символьных ссылок), без подстановки
// переменных. include и extends в разобранной модели не остаются; если
// остались — их пути проверяются так же.
func CheckModelFileRefs(model []byte, sf StackFiles) []Violation {
	refuse := func(field string) []Violation {
		return []Violation{{Service: "описание", Reason: "после разбора docker compose поле " + field +
			" ведёт к файлу вне приложения, а разбор платформы этого не увидел: форма записи не поддерживается, запишите описание проще"}}
	}
	var m struct {
		Services map[string]map[string]json.RawMessage `json:"services"`
		Include  json.RawMessage                       `json:"include"`
	}
	if err := json.Unmarshal(model, &m); err != nil {
		return []Violation{{Service: "описание", Reason: "модель docker compose для проверки ссылок на файлы не читается"}}
	}

	root := filepath.Clean(sf.Root)
	resolved, err := filepath.EvalSymlinks(sf.Root)
	if err != nil {
		return []Violation{{Service: "описание", Reason: "каталог стека не читается: " + tail(err.Error(), 200)}}
	}
	w := refWalker{root: resolved}
	allow := map[string]bool{}
	for _, p := range sf.AllowedAbs {
		allow[filepath.Clean(p)] = true
	}
	inside := func(path string) bool {
		if path == "" || strings.Contains(path, "$") {
			return false
		}
		if !filepath.IsAbs(path) {
			// Compose этой версии пути разрешает; относительный путь значит,
			// что модель снята не так, как ожидалось, — база неизвестна.
			if strings.Contains("/"+path+"/", "/../") {
				return false
			}
			path = filepath.Join(sf.ProjectDir, path)
		}
		clean := filepath.Clean(path)
		if allow[clean] {
			return true
		}
		// Лексически внутри корня: несуществующий файл EvalSymlinks не
		// проверит, а у подписанта чужих файлов и нет — путь наружу обязан
		// быть отказом и там, иначе подписанный пакет утечёт уже на хосте.
		lexical := false
		for _, r := range []string{root, resolved} {
			if clean == r || strings.HasPrefix(clean, r+string(filepath.Separator)) {
				lexical = true
			}
		}
		return lexical && w.within(clean)
	}

	fields := map[string]bool{}
	// Имена сервисов по порядку: одинаковая модель — одинаковый текст отказа.
	names := make([]string, 0, len(m.Services))
	for name := range m.Services {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		svc := m.Services[name]
		for _, field := range []string{"env_file", "label_file"} {
			raw, ok := svc[field]
			if !ok {
				continue
			}
			paths, ok := modelPaths(raw, "path")
			if !ok {
				return refuse(field)
			}
			for _, p := range paths {
				if !inside(p) {
					fields[field] = true
				}
			}
		}
		if raw, ok := svc["extends"]; ok {
			var ext struct {
				File string `json:"file"`
			}
			// Строка — имя сервиса в том же файле: файла не читает.
			var service string
			if json.Unmarshal(raw, &service) != nil {
				if err := json.Unmarshal(raw, &ext); err != nil {
					return refuse("extends")
				}
				if ext.File != "" && !inside(ext.File) {
					fields["extends"] = true
				}
			}
		}
	}
	if len(m.Include) > 0 && string(m.Include) != "null" {
		var items []json.RawMessage
		if err := json.Unmarshal(m.Include, &items); err != nil {
			return refuse("include")
		}
		for _, item := range items {
			paths, ok := modelPaths(item, "path")
			if !ok {
				return refuse("include")
			}
			var obj struct {
				EnvFile          json.RawMessage `json:"env_file"`
				ProjectDirectory string          `json:"project_directory"`
			}
			_ = json.Unmarshal(item, &obj)
			if len(obj.EnvFile) > 0 {
				envs, ok := modelPaths(obj.EnvFile, "path")
				if !ok {
					return refuse("include")
				}
				paths = append(paths, envs...)
			}
			if obj.ProjectDirectory != "" {
				paths = append(paths, obj.ProjectDirectory)
			}
			for _, p := range paths {
				if !inside(p) {
					fields["include"] = true
				}
			}
		}
	}

	var out []Violation
	for _, f := range []string{"env_file", "label_file", "extends", "include"} {
		if fields[f] {
			out = append(out, refuse(f)...)
		}
	}
	return out
}

// modelPaths — пути из значения поля модели: строка, объект с ключом key
// (`{path: …}`) или список из них. false — форма, которой compose не выдаёт:
// её лучше отвергнуть, чем истолковать.
func modelPaths(raw json.RawMessage, key string) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}, true
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) != nil {
		list = []json.RawMessage{raw}
	}
	var out []string
	for _, item := range list {
		if json.Unmarshal(item, &one) == nil {
			out = append(out, one)
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(item, &obj) != nil {
			return nil, false
		}
		p, ok := obj[key]
		if !ok {
			return nil, false
		}
		var paths []string
		if json.Unmarshal(p, &one) == nil {
			paths = []string{one}
		} else if json.Unmarshal(p, &paths) != nil {
			return nil, false
		}
		out = append(out, paths...)
	}
	return out, true
}
