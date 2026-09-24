package composeguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Ссылки описания стека на файлы: env_file, label_file, include, extends
// (ADR-0092, решение 5).
//
// ЗАЧЕМ. Эти поля docker compose исполняет САМ, ещё при разборе: читает файл
// и подставляет его содержимое — пары env_file в environment контейнера,
// чужое описание стека через include и extends, файл переменных include для
// подстановки. Рядом лежат .env соседних приложений ровно в том формате, который
// env_file ждёт. `env_file: [{path: ${S}, required: false}]` с секретом S,
// значение которого подписью не покрыто, отдаёт web выбор: какой файл хоста
// приедет паролями в контейнер. Утверждение «взлом платформы не даёт выйти за
// политику» без этой проверки ложно.
//
// ПОЧЕМУ ПО ТЕКСТУ, А НЕ ПО МОДЕЛИ `docker compose config`. Модель снимает сам
// compose, и файлы include и extends он читает при любых флагах: проверено на
// Compose v5 с `--no-interpolate --no-env-resolution --no-path-resolution
// --no-normalize --no-consistency` — include с абсолютным путём разбирается
// из чужого файла. Проверка после разбора опоздала бы: у подписанта файл уже
// прочитан его uid и может попасть в текст ошибки, на хосте — уже в модели.
// Поэтому текст разбирается здесь, без подстановки переменных и ДО первого
// вызова compose, а цель каждой ссылки проверяется на диске с раскрытыми
// символьными ссылками. Разбор — лексический проход по правилам сканера
// go-yaml (yamllex.go): форма, в которой он не уверен, отвергается целиком.
//
// ВТОРАЯ ЛИНИЯ (modelrefs.go). Разбор текста — своя реализация YAML, и её
// промах не должен становиться утечкой. Поэтому после него, но до любого
// вызова compose, который исполняет env_file, модель снимается с
// `--no-env-resolution` и ссылки проверяются уже в ней: там их видит сам
// compose. Первая линия при этом обязательна: она не пускает к compose
// абсолютные пути include и extends, которые он прочёл бы и так.
//
// ПРАВИЛО. Путь — относительный, из букв, цифр и `._/-`, без `..` вовсе и без
// `$`: подстановка переменной в путь — тот же выбор файла значением, которое
// подпись не покрывает. Цель на диске обязана остаться внутри корня стека.
// Формы, которые здесь не разобраны (якоря вместо значения, теги, блочные
// строки, экранирование в ключах, сложные ключи YAML), — отказ, а не пропуск:
// ошибка в сторону отказа стоит разговора, в другую — чужих секретов.

// fileRefKeys — поля, которые compose исполняет чтением файла. Ищутся по
// всему тексту, где бы ни стояли — в сервисе, в `x-`-фрагменте под якорем, в
// элементе include: якорь, развёрнутый слиянием, переносит поле туда, где его
// не ждали, и надёжнее проверить каждое вхождение, чем восстанавливать, куда
// оно попадёт.
var fileRefKeyRe = regexp.MustCompile(`(?:^|[\s{,\[])["']?(env_file|label_file|include|extends)["']?[ \t]*:`)

// Формы YAML, при которых ключ в тексте не совпадает с ключом после разбора:
// явный ключ `? `, псевдоним на месте ключа, экранирование внутри ключа в
// кавычках (`"env\x5ffile"`), директивы (`%TAG` переопределяет теги).
var (
	explicitKeyRe = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)*\?(?:[ \t]|$)`)
	aliasKeyRe    = regexp.MustCompile(`(?:^|[\s{,\[])\*[^\s,\[\]{}]+[ \t]*:`)
	escapedKeyRe  = regexp.MustCompile(`"(?:[^"\\\n]|\\.)*\\(?:[^"\\\n]|\\.)*"[ \t]*:`)
	directiveRe   = regexp.MustCompile(`(?m)^%`)
)

var refPathRe = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// fileRef — ссылка на файл: поле и путь как в тексте.
type fileRef struct {
	Field string
	Path  string
	// Include — цель описывает стек и сама читается дальше (include, extends).
	Include bool
	// ProjectDir — project_directory элемента include: от него compose
	// разрешает пути включённого описания.
	ProjectDir string
}

const maxRefFileBytes = 1 << 20

// maxRefDepth — вложенность include и extends. Глубже законные стеки не
// ходят, а цикл без предела держал бы проверку вечно.
const maxRefDepth = 8

// StackFiles — откуда compose прочтёт описание стека.
type StackFiles struct {
	// Root — каталог, за который не выходит ни одна цель ссылки после
	// раскрытия символьных ссылок: каталог приложения или рабочая копия
	// репозитория.
	Root string
	// ProjectDir — каталог проекта compose: от него разрешаются пути
	// основного описания.
	ProjectDir string
	// Entries — явные файлы описания (`-f`). Пусто — стандартные имена в
	// ProjectDir, включая override: compose подхватывает его сам.
	Entries []string
	// AllowedAbs — абсолютные пути, которые пишет сам агент, а не описание
	// (свой .env в синтетическом compose сборки из Dockerfile).
	AllowedAbs []string
}

// composeEntryNames — имена, которые compose читает без `-f`, включая
// override: файл шаблона или репозитория с таким именем подхватится сам.
var composeEntryNames = []string{
	"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml",
	"compose.override.yaml", "compose.override.yml",
	"docker-compose.override.yaml", "docker-compose.override.yml",
}

// CheckStackFileRefs — ссылки на файлы во всём, что compose прочтёт для
// стека, с обходом include и extends. Звать ДО первого `docker compose`.
func CheckStackFileRefs(sf StackFiles) []Violation {
	root, err := filepath.EvalSymlinks(sf.Root)
	if err != nil {
		return []Violation{{Service: "описание", Reason: "каталог стека не читается: " + tail(err.Error(), 200)}}
	}
	w := refWalker{root: root, allowAbs: map[string]bool{}, seen: map[string]bool{}}
	for _, p := range sf.AllowedAbs {
		w.allowAbs[p] = true
	}

	entries := sf.Entries
	explicit := len(entries) > 0
	if !explicit {
		for _, name := range composeEntryNames {
			path := filepath.Join(sf.ProjectDir, name)
			if _, err := os.Lstat(path); err == nil {
				entries = append(entries, path)
			}
		}
	}
	for _, entry := range entries {
		// Файл, найденный по имени в каталоге, мог принести репозиторий —
		// символьной ссылкой на описание соседа. Явный файл называет агент.
		if !explicit && !w.within(entry) {
			w.out = append(w.out, Violation{Service: "описание", Reason: "файл " + filepath.Base(entry) +
				" ведёт по символьной ссылке за пределы приложения"})
			continue
		}
		// Пути основного описания compose разрешает от каталога проекта, и
		// при явном `-f` из другого каталога (набор копий) — тоже от него.
		w.walk(entry, []string{sf.ProjectDir}, 0)
	}
	return w.out
}

type refWalker struct {
	root     string
	allowAbs map[string]bool
	seen     map[string]bool
	out      []Violation
}

func (w *refWalker) name(path string) string {
	if rel, err := filepath.Rel(w.root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return filepath.Base(path)
}

// within — цель пути после раскрытия ссылок внутри корня. Несуществующий файл
// — внутри: compose либо откажет сам, либо пропустит необязательный.
func (w *refWalker) within(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	return resolved == w.root || strings.HasPrefix(resolved, w.root+string(os.PathSeparator))
}

// walk читает файл описания и проверяет его ссылки. bases — каталоги, от
// которых compose может разрешить относительный путь этого файла; цель
// проверяется от каждого: промах в выборе базы не должен стать пропуском.
func (w *refWalker) walk(file string, bases []string, depth int) {
	if w.seen[file] {
		return
	}
	w.seen[file] = true
	label := w.name(file)
	if depth > maxRefDepth {
		w.out = append(w.out, Violation{Service: "include", Reason: fmt.Sprintf("вложенность описаний глубже %d (%s)", maxRefDepth, label)})
		return
	}
	info, err := os.Stat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil || !info.Mode().IsRegular() {
		w.out = append(w.out, Violation{Service: "описание", Reason: "файл " + label + " не читается как обычный файл"})
		return
	}
	if info.Size() > maxRefFileBytes {
		w.out = append(w.out, Violation{Service: "описание", Reason: "файл " + label + " больше 1 МиБ"})
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		w.out = append(w.out, Violation{Service: "описание", Reason: "файл " + label + " не читается"})
		return
	}

	refs, violations := scanFileRefs(string(raw))
	prefix := ""
	if depth > 0 {
		prefix = "в " + label + ": "
	}
	for _, v := range violations {
		v.Reason = prefix + v.Reason
		w.out = append(w.out, v)
	}
	for _, ref := range refs {
		if w.allowAbs[ref.Path] {
			continue
		}
		if reason := refPathViolation(ref.Path); reason != "" {
			w.out = append(w.out, Violation{Service: ref.Field, Reason: prefix + "путь " + tail(ref.Path, 120) + ": " + reason})
			continue
		}
		for _, base := range bases {
			target := filepath.Join(base, ref.Path)
			if !w.within(target) {
				w.out = append(w.out, Violation{Service: ref.Field, Reason: prefix + "путь " + tail(ref.Path, 120) +
					" ведёт по символьной ссылке за пределы приложения"})
				break
			}
		}
	}
	// Включённые описания — после проверки путей: цель, отвергнутую выше,
	// читать незачем.
	for _, ref := range refs {
		if !ref.Include || w.allowAbs[ref.Path] || refPathViolation(ref.Path) != "" {
			continue
		}
		for _, base := range bases {
			target := filepath.Join(base, ref.Path)
			if !w.within(target) {
				continue
			}
			next := []string{filepath.Dir(target)}
			if ref.ProjectDir != "" && refPathViolation(ref.ProjectDir) == "" {
				pd := filepath.Join(base, ref.ProjectDir)
				next = append(next, pd)
				// Файл переменных включённого проекта по умолчанию — его .env:
				// compose прочтёт его для подстановки и без упоминания.
				if !w.within(filepath.Join(pd, ".env")) {
					w.out = append(w.out, Violation{Service: "include", Reason: prefix + "каталог " + tail(ref.ProjectDir, 120) +
						": .env ведёт по символьной ссылке за пределы приложения"})
				}
			}
			if !w.within(filepath.Join(filepath.Dir(target), ".env")) {
				w.out = append(w.out, Violation{Service: ref.Field, Reason: prefix + "рядом с " + tail(ref.Path, 120) +
					" .env ведёт по символьной ссылке за пределы приложения"})
			}
			w.walk(target, uniqueDirs(append(next, bases...)...), depth+1)
		}
	}
}

func uniqueDirs(dirs ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// refPathViolation — почему путь ссылки недопустим; пусто — допустим.
func refPathViolation(path string) string {
	switch {
	case path == "":
		return "пустой путь"
	case strings.Contains(path, "$"):
		return "подстановка переменной в путь запрещена — значение не подписано и выбирало бы, какой файл хоста прочтёт compose"
	case strings.HasPrefix(path, "/"):
		return "абсолютный путь ведёт наружу приложения"
	case !refPathRe.MatchString(path):
		return "в пути допустимы только буквы, цифры и . _ / -"
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return "выход через .. запрещён"
		}
	}
	return ""
}

// ── разбор текста ───────────────────────────────────────────────────────────

// scanFileRefs — ссылки на файлы в тексте описания и формы, которые не
// разобраны. Без подстановки переменных и без чтения диска.
func scanFileRefs(src string) ([]fileRef, []Violation) {
	// Переводы строки — как их видит go-yaml, которым читает compose: кроме
	// \n это \r, NEL, LS и PS. Не приведи их здесь — ключ после такого
	// разрыва не нашёлся бы, а строка без кавычек не склеилась бы с продолжением.
	// Метка порядка байтов из YAML выпадает и не должна прятать ключ за собой.
	src = strings.NewReplacer("\r\n", "\n", "\r", "\n", "\u0085", "\n", "\u2028", "\n", "\u2029", "\n", "\ufeff", "").Replace(src)
	var out []Violation
	reject := func(field, reason string) { out = append(out, Violation{Service: field, Reason: reason}) }

	p := newYAMLText(src)
	lex, err := lexYAML(src, p)
	if err != nil {
		reject("описание", "форма YAML не разобрана платформой ("+err.Error()+"): запишите описание проще")
	}
	// Прежние проверки по тексту остаются страховкой поверх прохода, но
	// вхождение внутри комментария или строки в кавычках формой YAML не
	// является: `\"ok\":true` в команде healthcheck — не ключ с
	// экранированием. Где проход споткнулся, разметки дальше нет, и
	// вхождение считается настоящим.
	inText := func(re *regexp.Regexp, at func(m []int) int) bool {
		for _, m := range re.FindAllStringIndex(src, -1) {
			if c := lex.class[at(m)]; c != lexComment && c != lexQuoted {
				return true
			}
		}
		return false
	}
	lastByte := func(m []int) int { return m[1] - 1 }
	if inText(explicitKeyRe, func(m []int) int { return m[0] + strings.LastIndexByte(src[m[0]:m[1]], '?') }) {
		reject("описание", "явный ключ YAML (`? `) не разбирается платформой")
	}
	if inText(aliasKeyRe, lastByte) {
		reject("описание", "псевдоним YAML на месте ключа не разбирается платформой")
	}
	if inText(escapedKeyRe, lastByte) {
		reject("описание", "экранирование внутри ключа в кавычках не разбирается платформой")
	}
	if inText(directiveRe, func(m []int) int { return m[0] }) {
		reject("описание", "директивы YAML (%) не разбираются платформой")
	}

	var refs []fileRef
	checked := map[int]bool{}
	check := func(field string, keyAt, valueAt int, inFlow *bool) {
		checked[keyAt] = true
		value, err := p.valueOf(keyAt, valueAt, inFlow)
		if err != nil {
			reject(field, "форма значения не разобрана платформой ("+err.Error()+"): запишите путь строкой или списком строк")
			return
		}
		found, err := refsOf(field, value)
		if err != nil {
			reject(field, err.Error())
			return
		}
		refs = append(refs, found...)
	}
	// Ключи, которые увидел лексический проход, — это ключи и для go-yaml.
	for _, k := range lex.keys {
		if fileRefFields[k.name] {
			check(k.name, k.nameAt, k.colon+1, &k.flow)
		}
	}
	// Страховка поверх прохода: любое вхождение имени поля с двоеточием, кроме
	// комментария и строки в кавычках, разбирается как ключ. Вхождение внутри
	// блочной строки или посреди строки без кавычек ключом не бывает, но
	// лишний отказ здесь дешевле пропуска, если проход в чём-то ошибся.
	// Комментарий и кавычки отсекаются только по разметке прохода: отложенный в
	// комментарий `env_file` — обычное дело в чужих репозиториях, а решение
	// «это комментарий» по началу строки и было тем обходом, который закрыт.
	for _, m := range fileRefKeyRe.FindAllStringSubmatchIndex(src, -1) {
		if checked[m[2]] {
			continue
		}
		if c := lex.class[m[2]]; c == lexComment || c == lexQuoted {
			continue
		}
		check(src[m[2]:m[3]], m[2], m[1], nil)
	}
	return refs, out
}

var fileRefFields = map[string]bool{"env_file": true, "label_file": true, "include": true, "extends": true}

// refsOf — пути из значения поля по его схеме в compose.
func refsOf(field string, value any) ([]fileRef, error) {
	paths := func(v any, sub string) ([]string, error) {
		switch x := v.(type) {
		case nil:
			return nil, nil
		case string:
			return []string{x}, nil
		case []any:
			var out []string
			for _, item := range x {
				s, ok := item.(string)
				if !ok {
					return nil, fmt.Errorf("%s: ожидался путь строкой", sub)
				}
				out = append(out, s)
			}
			return out, nil
		}
		return nil, fmt.Errorf("%s: ожидался путь строкой или списком строк", sub)
	}
	onlyKeys := func(m map[string]any, allowed ...string) error {
		for k := range m {
			if !contains(allowed, k) {
				return fmt.Errorf("ключ %s платформе неизвестен и потому запрещён", tail(k, 40))
			}
		}
		return nil
	}

	var out []fileRef
	switch field {
	case "env_file", "label_file":
		items := []any{value}
		if list, ok := value.([]any); ok {
			items = list
		}
		for _, item := range items {
			switch x := item.(type) {
			case nil:
			case string:
				out = append(out, fileRef{Field: field, Path: x})
			case map[string]any:
				if field == "label_file" {
					return nil, errors.New("ожидался путь строкой")
				}
				if err := onlyKeys(x, "path", "required", "format"); err != nil {
					return nil, err
				}
				ps, err := paths(x["path"], "path")
				if err != nil {
					return nil, err
				}
				for _, p := range ps {
					out = append(out, fileRef{Field: field, Path: p})
				}
			default:
				return nil, errors.New("ожидался путь строкой или списком")
			}
		}
	case "include":
		items := []any{value}
		if list, ok := value.([]any); ok {
			items = list
		}
		for _, item := range items {
			switch x := item.(type) {
			case nil:
			case string:
				out = append(out, fileRef{Field: field, Path: x, Include: true})
			case map[string]any:
				if err := onlyKeys(x, "path", "env_file", "project_directory"); err != nil {
					return nil, err
				}
				pd, ok := x["project_directory"].(string)
				if x["project_directory"] != nil && !ok {
					return nil, errors.New("project_directory: ожидался путь строкой")
				}
				if pd != "" {
					out = append(out, fileRef{Field: "include", Path: pd})
				}
				ps, err := paths(x["path"], "path")
				if err != nil {
					return nil, err
				}
				for _, p := range ps {
					out = append(out, fileRef{Field: field, Path: p, Include: true, ProjectDir: pd})
				}
				envs, err := paths(x["env_file"], "env_file")
				if err != nil {
					return nil, err
				}
				for _, p := range envs {
					out = append(out, fileRef{Field: "include", Path: p})
				}
			default:
				return nil, errors.New("элемент include: ожидался путь строкой или объектом")
			}
		}
	case "extends":
		switch x := value.(type) {
		case nil, string:
			// Строка — имя сервиса в этом же файле: файла не читает.
		case map[string]any:
			if err := onlyKeys(x, "file", "service"); err != nil {
				return nil, err
			}
			file, ok := x["file"].(string)
			if x["file"] != nil && !ok {
				return nil, errors.New("file: ожидался путь строкой")
			}
			if file != "" {
				out = append(out, fileRef{Field: field, Path: file, Include: true})
			}
		default:
			return nil, errors.New("ожидалось имя сервиса или объект {file, service}")
		}
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// yamlText — ровно то подмножество YAML, которым пишут значения этих полей:
// строки (без кавычек, в одинарных, в двойных без экранирования), списки и
// объекты блоком и в скобках. Всё прочее — ошибка, а не догадка.
type yamlText struct {
	src   string
	lines []yamlLine
}

type yamlLine struct {
	start, end int // [start, end) без перевода строки
	indent     int
	blank      bool // пустая или только комментарий
}

func newYAMLText(src string) *yamlText {
	t := &yamlText{src: src}
	start := 0
	for start <= len(src) {
		end := strings.IndexByte(src[start:], '\n')
		if end < 0 {
			end = len(src)
		} else {
			end += start
		}
		line := src[start:end]
		indent := len(line) - len(strings.TrimLeft(line, " "))
		rest := strings.TrimSpace(line)
		t.lines = append(t.lines, yamlLine{start: start, end: end, indent: indent, blank: rest == "" || strings.HasPrefix(rest, "#")})
		if end == len(src) {
			break
		}
		start = end + 1
	}
	return t
}

func (t *yamlText) lineOf(pos int) int {
	return sort.Search(len(t.lines), func(i int) bool { return t.lines[i].end >= pos })
}

var errUnsupported = errors.New("неподдерживаемая форма")

// valueOf — значение ключа, чьё имя начинается в keyAt, а двоеточие кончается
// перед valueAt.
//
// inFlow — ключ внутри скобок по разметке лексического прохода; nil — не
// известно (вхождение, найденное страховочным поиском), и тогда решает текст
// перед ключом.
func (t *yamlText) valueOf(keyAt, valueAt int, inFlow *bool) (any, error) {
	li := t.lineOf(keyAt)
	line := t.lines[li]
	keyCol := keyAt - line.start
	if keyCol > 0 && (t.src[keyAt-1] == '"' || t.src[keyAt-1] == '\'') {
		keyCol--
	}
	// Ключ внутри скобок: перед ним на той же строке `{`, `,` или `[`. В блоке
	// ключ стоит только после отступа или `- `, так что ошибиться в сторону
	// «скобки» нельзя: вне скобок такой «ключ» — часть строки, и compose его
	// ключом не считает.
	before := strings.TrimRight(t.src[line.start:line.start+keyCol], " \t")
	flow := strings.HasSuffix(before, "{") || strings.HasSuffix(before, ",") || strings.HasSuffix(before, "[")
	if inFlow != nil {
		flow = *inFlow
	}
	// В скобках значение может начаться и на следующей строке: там отступ
	// ничего не значит, и разбор блоком (по отступу) дал бы пустое значение
	// вместо пути.
	if flow {
		value, end, err := t.flowValue(valueAt, 0)
		if err != nil {
			return nil, err
		}
		if err := t.tail(end, true); err != nil {
			return nil, err
		}
		return value, nil
	}

	pos, err := t.skipAnchor(t.skipSpaces(valueAt))
	if err != nil {
		return nil, err
	}
	if t.atLineEnd(pos) {
		return t.blockChild(li, keyCol)
	}
	value, end, err := t.inline(pos, false, 0)
	if err != nil {
		return nil, err
	}
	if err := t.tail(end, false); err != nil {
		return nil, err
	}
	if err := t.noDeeper(t.lineOf(end)+1, keyCol); err != nil {
		return nil, err
	}
	return value, nil
}

func (t *yamlText) skipSpaces(pos int) int {
	for pos < len(t.src) && (t.src[pos] == ' ' || t.src[pos] == '\t') {
		pos++
	}
	return pos
}

// skipAnchor пропускает свойства узла, не меняющие его значения: якорь
// `&имя` и теги слияния compose `!reset` и `!override` (значение под ними
// разбирается и проверяется как обычно — осторожнее, чем верить, что
// `!reset` его отбросит). Псевдоним `*имя` не пропускается: его значение
// стоит в другом месте текста. Прочие теги — ошибка разбора ниже.
func (t *yamlText) skipAnchor(pos int) (int, error) {
	for pos < len(t.src) {
		switch {
		case t.src[pos] == '&':
		case strings.HasPrefix(t.src[pos:], "!reset") || strings.HasPrefix(t.src[pos:], "!override"):
			end := pos + len("!reset")
			if t.src[pos+1] == 'o' {
				end = pos + len("!override")
			}
			if end < len(t.src) && !strings.ContainsRune(" \t\n", rune(t.src[end])) {
				return pos, nil
			}
		default:
			return pos, nil
		}
		for pos < len(t.src) && !strings.ContainsRune(" \t\n,[]{}", rune(t.src[pos])) {
			pos++
		}
		pos = t.skipSpaces(pos)
	}
	return pos, nil
}

// atLineEnd — дальше на строке ничего, кроме комментария.
func (t *yamlText) atLineEnd(pos int) bool {
	return pos >= len(t.src) || t.src[pos] == '\n' || t.src[pos] == '#'
}

// tail — после значения на строке только комментарий или, в скобках,
// разделитель следующего элемента. В скобках строка без кавычек может
// продолжиться на следующей строке (YAML склеит `a` и `/../x` в один путь),
// поэтому там после значения обязан идти разделитель, а не что угодно.
func (t *yamlText) tail(end int, flow bool) error {
	if flow {
		pos := t.skipFlowSpace(end)
		if pos >= len(t.src) || strings.ContainsRune(",]}", rune(t.src[pos])) {
			return nil
		}
		return errUnsupported
	}
	if t.atLineEnd(t.skipSpaces(end)) {
		return nil
	}
	return errUnsupported
}

// noDeeper — после значения ключа с колонкой col нет строк глубже неё: такая
// строка продолжила бы строку без кавычек, и путь в YAML был бы длиннее
// разобранного здесь.
func (t *yamlText) noDeeper(li, col int) error {
	if next := t.nextContent(li); next >= 0 && t.lines[next].indent > col {
		return errUnsupported
	}
	return nil
}

// blockChild — блочное значение ключа из строки li с колонкой col: строки
// глубже, либо список `- ` на той же глубине.
func (t *yamlText) blockChild(li, col int) (any, error) {
	next := t.nextContent(li + 1)
	if next < 0 {
		return nil, nil
	}
	line := t.lines[next]
	var (
		v     any
		after int
		err   error
	)
	switch {
	case line.indent > col:
		v, after, err = t.node(next, line.indent, 0)
	case line.indent == col && t.isDash(line.start+col):
		v, after, err = t.seq(next, col, 0)
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := t.noDeeper(after, col); err != nil {
		return nil, err
	}
	return v, nil
}

func (t *yamlText) nextContent(li int) int {
	for ; li < len(t.lines); li++ {
		if !t.lines[li].blank {
			return li
		}
	}
	return -1
}

func (t *yamlText) isDash(pos int) bool {
	return pos < len(t.src) && t.src[pos] == '-' && (pos+1 >= len(t.src) || t.src[pos+1] == ' ' || t.src[pos+1] == '\n')
}

// node — блочный узел, чьё содержимое начинается в строке li с колонки col.
func (t *yamlText) node(li, col, depth int) (any, int, error) {
	if depth > 16 {
		return nil, 0, errUnsupported
	}
	pos := t.lines[li].start + col
	if t.isDash(pos) {
		return t.seq(li, col, depth)
	}
	if _, _, ok := t.mapKey(pos); ok {
		return t.mapping(li, col, depth)
	}
	pos, err := t.skipAnchor(pos)
	if err != nil {
		return nil, 0, err
	}
	v, end, err := t.inline(pos, false, depth)
	if err != nil {
		return nil, 0, err
	}
	if err := t.tail(end, false); err != nil {
		return nil, 0, err
	}
	return v, t.lineOf(end) + 1, nil
}

// seq — блочный список `- ` на колонке col, начиная со строки li.
func (t *yamlText) seq(li, col, depth int) (any, int, error) {
	var items []any
	for {
		li = t.nextContent(li)
		if li < 0 {
			return items, len(t.lines), nil
		}
		line := t.lines[li]
		if line.indent < col || (line.indent == col && !t.isDash(line.start+col)) {
			return items, li, nil
		}
		if line.indent > col {
			return nil, 0, errUnsupported
		}
		pos, err := t.skipAnchor(t.skipSpaces(line.start + col + 1))
		if err != nil {
			return nil, 0, err
		}
		if t.atLineEnd(pos) {
			next := t.nextContent(li + 1)
			if next < 0 || t.lines[next].indent <= col {
				items = append(items, nil)
				li++
				continue
			}
			v, after, err := t.node(next, t.lines[next].indent, depth+1)
			if err != nil {
				return nil, 0, err
			}
			items = append(items, v)
			li = after
			continue
		}
		v, after, err := t.node(li, pos-line.start, depth+1)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, v)
		li = after
	}
}

// mapKey — ключ блочного объекта в pos: строка без кавычек до `: ` или в
// кавычках. Возвращает ключ и позицию сразу за двоеточием.
func (t *yamlText) mapKey(pos int) (string, int, bool) {
	s := t.src
	if pos >= len(s) {
		return "", 0, false
	}
	var key string
	end := pos
	switch s[pos] {
	case '"', '\'':
		quote := s[pos]
		close := strings.IndexByte(s[pos+1:], quote)
		nl := strings.IndexByte(s[pos+1:], '\n')
		if close < 0 || (nl >= 0 && nl < close) {
			return "", 0, false
		}
		key = s[pos+1 : pos+1+close]
		end = pos + close + 2
	default:
		if strings.ContainsRune("-[]{}#&*!|>%@`,?", rune(s[pos])) {
			return "", 0, false
		}
		for end < len(s) && s[end] != '\n' {
			if s[end] == ':' && (end+1 >= len(s) || s[end+1] == ' ' || s[end+1] == '\n' || s[end+1] == '\t') {
				break
			}
			if s[end] == '#' && end > pos && (s[end-1] == ' ' || s[end-1] == '\t') {
				return "", 0, false
			}
			end++
		}
		key = strings.TrimRight(s[pos:end], " \t")
	}
	end = t.skipSpaces(end)
	if end >= len(s) || s[end] != ':' || (end+1 < len(s) && s[end+1] != ' ' && s[end+1] != '\n' && s[end+1] != '\t') {
		return "", 0, false
	}
	return key, end + 1, true
}

// mapping — блочный объект с ключами на колонке col, первый — в строке li.
func (t *yamlText) mapping(li, col, depth int) (any, int, error) {
	m := map[string]any{}
	first := true
	for {
		if !first {
			li = t.nextContent(li)
			if li < 0 {
				return m, len(t.lines), nil
			}
			line := t.lines[li]
			if line.indent < col {
				return m, li, nil
			}
			if line.indent > col {
				return nil, 0, errUnsupported
			}
		}
		line := t.lines[li]
		key, after, ok := t.mapKey(line.start + col)
		if !ok {
			if !first && t.isDash(line.start+col) {
				// Список на той же глубине после объекта — это уже родитель.
				return m, li, nil
			}
			return nil, 0, errUnsupported
		}
		first = false
		pos, err := t.skipAnchor(t.skipSpaces(after))
		if err != nil {
			return nil, 0, err
		}
		if t.atLineEnd(pos) {
			v, err := t.blockChild(li, col)
			if err != nil {
				return nil, 0, err
			}
			m[key] = v
			li = t.afterBlock(li, col)
			continue
		}
		v, end, err := t.inline(pos, false, depth+1)
		if err != nil {
			return nil, 0, err
		}
		if err := t.tail(end, false); err != nil {
			return nil, 0, err
		}
		m[key] = v
		li = t.lineOf(end) + 1
	}
}

// afterBlock — первая строка после блочного значения ключа из строки li.
func (t *yamlText) afterBlock(li, col int) int {
	for i := li + 1; i < len(t.lines); i++ {
		l := t.lines[i]
		if l.blank {
			continue
		}
		if l.indent > col || (l.indent == col && t.isDash(l.start+col)) {
			continue
		}
		return i
	}
	return len(t.lines)
}

// inline — значение в строке: скаляр или скобки (скобки могут занимать
// несколько строк). flow — значение внутри скобок: строка без кавычек там
// кончается на `,`, `]`, `}`.
func (t *yamlText) inline(pos int, flow bool, depth int) (any, int, error) {
	if depth > 16 || pos >= len(t.src) {
		return nil, 0, errUnsupported
	}
	s := t.src
	switch s[pos] {
	case '*':
		return nil, 0, errors.New("псевдоним YAML")
	case '|', '>':
		return nil, 0, errors.New("блочная строка")
	case '&', '!':
		p, err := t.skipAnchor(pos)
		if err != nil {
			return nil, 0, err
		}
		if p == pos {
			return nil, 0, errors.New("тег YAML")
		}
		return t.inline(p, flow, depth+1)
	case '@', '`', '%':
		return nil, 0, errUnsupported
	case '[':
		return t.flowSeq(pos, depth)
	case '{':
		return t.flowMap(pos, depth)
	case '"':
		end := pos + 1
		for end < len(s) && s[end] != '"' {
			if s[end] == '\\' {
				return nil, 0, errors.New("экранирование в строке")
			}
			if s[end] == '\n' {
				return nil, 0, errors.New("многострочная строка")
			}
			end++
		}
		if end >= len(s) {
			return nil, 0, errUnsupported
		}
		return s[pos+1 : end], end + 1, nil
	case '\'':
		var b strings.Builder
		end := pos + 1
		for {
			if end >= len(s) || s[end] == '\n' {
				return nil, 0, errors.New("многострочная строка")
			}
			if s[end] == '\'' {
				if end+1 < len(s) && s[end+1] == '\'' {
					b.WriteByte('\'')
					end += 2
					continue
				}
				return b.String(), end + 1, nil
			}
			b.WriteByte(s[end])
			end++
		}
	}
	end := pos
	for end < len(s) && s[end] != '\n' {
		c := s[end]
		if c == '#' && end > pos && (s[end-1] == ' ' || s[end-1] == '\t') {
			break
		}
		if flow && strings.ContainsRune(",[]{}", rune(c)) {
			break
		}
		if flow && c == ':' && (end+1 >= len(s) || strings.ContainsRune(" \t\n,[]{}", rune(s[end+1]))) {
			break
		}
		end++
	}
	value := strings.TrimRight(s[pos:end], " \t")
	if value == "~" || value == "null" || value == "Null" || value == "NULL" {
		return nil, end, nil
	}
	return value, end, nil
}

// skipFlowSpace — пробелы, переводы строк и комментарии внутри скобок.
func (t *yamlText) skipFlowSpace(pos int) int {
	s := t.src
	for pos < len(s) {
		switch {
		case s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n':
			pos++
		case s[pos] == '#' && (pos == 0 || s[pos-1] == ' ' || s[pos-1] == '\t' || s[pos-1] == '\n'):
			for pos < len(s) && s[pos] != '\n' {
				pos++
			}
		default:
			return pos
		}
	}
	return pos
}

func (t *yamlText) flowSeq(pos, depth int) (any, int, error) {
	items := []any{}
	pos++
	for {
		pos = t.skipFlowSpace(pos)
		if pos >= len(t.src) {
			return nil, 0, errUnsupported
		}
		if t.src[pos] == ']' {
			return items, pos + 1, nil
		}
		v, end, err := t.inline(pos, true, depth+1)
		if err != nil {
			return nil, 0, err
		}
		end = t.skipFlowSpace(end)
		// `[ключ: значение]` — объект из одной пары внутри списка.
		if end < len(t.src) && t.src[end] == ':' {
			key, ok := v.(string)
			if !ok {
				return nil, 0, errUnsupported
			}
			val, after, err := t.flowValue(end+1, depth)
			if err != nil {
				return nil, 0, err
			}
			v, end = map[string]any{key: val}, after
		}
		items = append(items, v)
		switch {
		case end < len(t.src) && t.src[end] == ',':
			pos = end + 1
		case end < len(t.src) && t.src[end] == ']':
			return items, end + 1, nil
		default:
			return nil, 0, errUnsupported
		}
	}
}

func (t *yamlText) flowMap(pos, depth int) (any, int, error) {
	m := map[string]any{}
	pos++
	for {
		pos = t.skipFlowSpace(pos)
		if pos >= len(t.src) {
			return nil, 0, errUnsupported
		}
		if t.src[pos] == '}' {
			return m, pos + 1, nil
		}
		k, end, err := t.inline(pos, true, depth+1)
		if err != nil {
			return nil, 0, err
		}
		key, ok := k.(string)
		if !ok {
			return nil, 0, errUnsupported
		}
		end = t.skipFlowSpace(end)
		var val any
		if end < len(t.src) && t.src[end] == ':' {
			val, end, err = t.flowValue(end+1, depth)
			if err != nil {
				return nil, 0, err
			}
		}
		m[key] = val
		switch {
		case end < len(t.src) && t.src[end] == ',':
			pos = end + 1
		case end < len(t.src) && t.src[end] == '}':
			return m, end + 1, nil
		default:
			return nil, 0, errUnsupported
		}
	}
}

// flowValue — значение пары в скобках; пустое (`{a: , b: 1}`) — null.
func (t *yamlText) flowValue(pos, depth int) (any, int, error) {
	pos = t.skipFlowSpace(pos)
	if pos < len(t.src) && strings.ContainsRune(",]}", rune(t.src[pos])) {
		return nil, pos, nil
	}
	v, end, err := t.inline(pos, true, depth+1)
	if err != nil {
		return nil, 0, err
	}
	return v, t.skipFlowSpace(end), nil
}
