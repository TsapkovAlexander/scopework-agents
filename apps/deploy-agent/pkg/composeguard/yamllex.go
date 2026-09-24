package composeguard

import (
	"fmt"
	"regexp"
	"strings"
)

var anchorNameRe = regexp.MustCompile(`^[0-9A-Za-z_-]+$`)

// Лексический проход по описанию стека: где комментарий, где строка в
// кавычках, где ключ. Первая линия проверки ссылок на файлы (filerefs.go).
//
// ЗАЧЕМ ОТДЕЛЬНЫЙ ПРОХОД. Прежний разбор искал ключи регулярным выражением и
// решал, что строка — комментарий, по `#` в её начале. YAML так не читает:
// строка в кавычках может продолжиться на следующей строке, и тогда `#` в её
// начале — текст строки, а ключ после закрывающей кавычки — настоящий ключ;
// явный ключ `? env_file` внутри скобок с двоеточием на следующей строке
// регулярное выражение не видело вовсе. Оба пути воспроизведены на Compose
// v5.3.1: `.env` соседнего приложения уезжал в контейнер.
//
// ЧТО ДЕЛАЕТ. Проход повторяет сканер go-yaml (libyaml), которым читает
// compose, на уровне лексем: кавычки открываются только в начале значения,
// комментарий — `#` в начале лексемы, скобки считаются, строка без кавычек
// продолжается на следующей строке по тем же правилам отступа, блочная строка
// `|`/`>` занимает ровно те строки, что займёт у go-yaml. Ключ — лексема, за
// которой на той же строке стоит двоеточие-индикатор.
//
// ГЛАВНОЕ ПРАВИЛО: ЧТО НЕ РАЗОБРАНО ОДНОЗНАЧНО — ОТКАЗ. Каждая форма ниже
// отвергается не потому, что опасна сама, а потому, что на ней разбор
// платформы и разбор compose могут разойтись, а расхождение — это ключ,
// которого платформа не увидела:
//   - строка в кавычках, продолжающаяся на следующей строке (для compose
//     экзотика, а на ней и прошёл обход);
//   - явный ключ `?` в любом месте, где go-yaml считает его индикатором;
//   - двоеточие-индикатор без ключа на той же строке (ключ на прошлой строке);
//   - псевдоним, якорь или тег на месте ключа, составной ключ-коллекция;
//   - теги, кроме `!reset` и `!override` у значений (`!!binary` превращает
//     base64 в имя ключа `env_file`, и никакой поиск по тексту его не найдёт);
//   - табуляция в отступе, `,` вне скобок, `- ` внутри скобок, непарные
//     скобки, маркер документа внутри скобок, директивы `%`, символы `@` и
//     `` ` `` в начале значения, явный отступ блочной строки `|2`.
//
// Каждая из этих форм go-yaml либо не принимает вовсе, либо почти не
// встречается в описаниях стеков; отказ стоит разговора, пропуск — чужих
// секретов. Вторая линия — модель самого compose (modelrefs.go) — ловит то,
// что всё же разошлось бы.

// Классы байтов текста.
const (
	lexCode      byte = iota // лексемы YAML
	lexComment               // комментарий
	lexQuoted                // строка в кавычках, включая сами кавычки
	lexBlockText             // содержимое блочной строки `|` / `>`
)

// lexKey — ключ отображения: имя, как его увидит YAML, где оно начинается
// (после кавычки у ключа в кавычках), где стоит двоеточие и в скобках ли он.
type lexKey struct {
	name   string
	nameAt int
	colon  int
	flow   bool // ключ внутри скобок
}

type lexResult struct {
	class []byte
	keys  []lexKey
}

// lexError — форма, которую проход не разбирает однозначно.
type lexError struct {
	line   int
	reason string
}

func (e *lexError) Error() string {
	return fmt.Sprintf("строка %d: %s", e.line+1, e.reason)
}

// Вид лексемы-кандидата в простой ключ.
const (
	candScalar = iota
	candAlias
	candCollection
)

// simpleKey — кандидат в простой ключ, как его сохраняет сканер go-yaml:
// первая лексема узла, начатого там, где ключ разрешён. Ключом он станет,
// только если на той же строке за ним встанет двоеточие-индикатор.
type simpleKey struct {
	ok      bool
	line    int
	col     int
	kind    int
	props   bool // перед узлом якорь или тег
	name    string
	nameAt  int
	escaped bool // в строке в двойных кавычках есть экранирование
}

type yamlLexer struct {
	src string
	t   *yamlText
	res *lexResult

	// flow — стек открытых скобок; cands — кандидат в ключ на каждом уровне
	// скобок (сканер go-yaml хранит их стеком: ключ-коллекция `{a: b}: c`
	// восстанавливается после закрывающей скобки).
	flow  []byte
	cands []simpleKey
	// indents — отступы открытых блочных коллекций; вершина — то, что go-yaml
	// зовёт parser.indent, -1 при пустом стеке.
	indents []int
	allowed bool // простой ключ разрешён в текущей позиции

	// plain — строка без кавычек дошла до конца строки текста и может
	// продолжиться на следующей; plainIndent — минимальная колонка
	// продолжения вне скобок.
	plain       bool
	plainIndent int

	line      int // номер текущей строки текста
	lineStart int
}

// lexYAML — лексический проход. Результат есть и при ошибке: классы до места
// отказа размечены, дальше весь текст считается лексемами (так осторожнее
// для поиска ключей).
func lexYAML(src string, t *yamlText) (*lexResult, error) {
	lx := &yamlLexer{src: src, t: t, res: &lexResult{class: make([]byte, len(src))}}
	lx.cands = []simpleKey{{}}
	err := lx.run()
	return lx.res, err
}

func (lx *yamlLexer) fail(reason string) error {
	return &lexError{line: lx.line, reason: reason}
}

func (lx *yamlLexer) indent() int {
	if len(lx.indents) == 0 {
		return -1
	}
	return lx.indents[len(lx.indents)-1]
}

func (lx *yamlLexer) rollIndent(col int) {
	if len(lx.flow) == 0 && lx.indent() < col {
		lx.indents = append(lx.indents, col)
	}
}

func (lx *yamlLexer) cand() *simpleKey { return &lx.cands[len(lx.cands)-1] }

func (lx *yamlLexer) mark(from, to int, class byte) {
	for i := from; i < to; i++ {
		lx.res.class[i] = class
	}
}

func (lx *yamlLexer) run() error {
	lines := lx.t.lines
	for i := 0; i < len(lines); {
		lx.line, lx.lineStart = i, lines[i].start
		next, err := lx.lexLine(i)
		if err != nil {
			return err
		}
		i = next
	}
	if len(lx.flow) > 0 {
		return lx.fail("скобка не закрыта до конца описания")
	}
	return nil
}

// docMarker — `---` или `...` с первой колонки.
func (lx *yamlLexer) docMarker(start, end int) bool {
	s := lx.src[start:end]
	return (strings.HasPrefix(s, "---") || strings.HasPrefix(s, "...")) && (len(s) == 3 || s[3] == ' ' || s[3] == '\t')
}

// lexLine разбирает строку i и возвращает номер следующей непрочитанной
// (блочная строка забирает несколько).
func (lx *yamlLexer) lexLine(i int) (int, error) {
	ln := lx.t.lines[i]
	start, end := ln.start, ln.end

	// Продолжение строки без кавычек (сканер go-yaml, scan_plain_scalar):
	// пустые строки сворачиваются, строка с `#` её заканчивает, вне скобок
	// продолжение — только глубже parser.indent. Кавычка, скобка или `#` без
	// пробела перед ним в продолжении — просто текст строки.
	if lx.plain && !lx.docMarker(start, end) {
		p := start
		for p < end && (lx.src[p] == ' ' || lx.src[p] == '\t') {
			if lx.src[p] == '\t' && len(lx.flow) == 0 && p-start < lx.plainIndent {
				return 0, lx.fail("табуляция в отступе")
			}
			p++
		}
		if p == end {
			return i + 1, nil
		}
		if lx.src[p] == '#' {
			lx.plain = false
			lx.mark(p, end, lexComment)
			return i + 1, nil
		}
		if len(lx.flow) > 0 || p-start >= lx.plainIndent {
			// Продолжение ключом не бывает: простой ключ в YAML однострочный.
			lx.cand().ok = false
			lx.allowed = false
			p = lx.scanPlain(p, end)
			return lx.tokens(p, end)
		}
	}
	lx.plain = false

	if len(lx.flow) > 0 {
		if lx.docMarker(start, end) || (start < end && lx.src[start] == '%') {
			return 0, lx.fail("маркер документа или директива внутри скобок")
		}
		// В скобках перевод строки простой ключ не разрешает и не запрещает.
		return lx.tokens(start, end)
	}

	if ln.blank {
		if p := strings.IndexByte(lx.src[start:end], '#'); p >= 0 {
			lx.mark(start+p, end, lexComment)
		}
		return i + 1, nil
	}
	if lx.src[start] == '%' {
		return 0, lx.fail("директивы YAML (%) не разбираются платформой")
	}
	lx.allowed = true
	lx.cands = []simpleKey{{}}
	if lx.docMarker(start, end) {
		lx.indents = nil
		return lx.tokens(start+3, end)
	}
	p := start
	for p < end && lx.src[p] == ' ' {
		p++
	}
	if p < end && lx.src[p] == '\t' {
		return 0, lx.fail("табуляция в отступе")
	}
	col := p - start
	for len(lx.indents) > 0 && lx.indent() > col {
		lx.indents = lx.indents[:len(lx.indents)-1]
	}
	return lx.tokens(p, end)
}

func (lx *yamlLexer) blankAt(p int) bool {
	return p >= len(lx.src) || lx.src[p] == ' ' || lx.src[p] == '\t' || lx.src[p] == '\n'
}

// tokens — лексемы строки от pos до конца строки end.
func (lx *yamlLexer) tokens(pos, end int) (int, error) {
	s := lx.src
	for pos < end {
		c := s[pos]
		switch {
		case c == ' ' || c == '\t':
			pos++
		case c == '#':
			// go-yaml считает комментарием `#` в начале лексемы и без пробела
			// перед ним: `"a"#x` — строка и комментарий.
			lx.mark(pos, end, lexComment)
			return lx.line + 1, nil
		case c == '[' || c == '{':
			lx.saveKey(pos, candCollection, "", 0, false)
			lx.flow = append(lx.flow, c)
			lx.cands = append(lx.cands, simpleKey{})
			lx.allowed = true
			pos++
		case c == ']' || c == '}':
			open := byte('[')
			if c == '}' {
				open = '{'
			}
			if len(lx.flow) == 0 || lx.flow[len(lx.flow)-1] != open {
				return 0, lx.fail("непарная скобка " + string(c))
			}
			lx.flow = lx.flow[:len(lx.flow)-1]
			lx.cands = lx.cands[:len(lx.cands)-1]
			lx.allowed = false
			pos++
		case c == ',':
			if len(lx.flow) == 0 {
				return 0, lx.fail("запятая вне скобок в начале значения")
			}
			lx.cand().ok = false
			lx.allowed = true
			pos++
		case c == '-' && lx.blankAt(pos+1):
			if len(lx.flow) > 0 {
				return 0, lx.fail("элемент блочного списка `- ` внутри скобок")
			}
			lx.rollIndent(pos - lx.lineStart)
			lx.cand().ok = false
			lx.allowed = true
			pos++
		case c == '?' && (len(lx.flow) > 0 || lx.blankAt(pos+1)):
			return 0, lx.fail("явный ключ YAML (`?`) не разбирается платформой")
		case c == ':' && (len(lx.flow) > 0 || lx.blankAt(pos+1)):
			if err := lx.value(pos); err != nil {
				return 0, err
			}
			pos++
		case c == '*' || c == '&':
			p := pos + 1
			for p < end && !strings.ContainsRune(" \t,[]{}", rune(s[p])) {
				p++
			}
			// Имя — до пробела или скобки, как в YAML 1.2; go-yaml v3 обрывает
			// его на первом символе вне [0-9A-Za-z_-] (`*k:` у него — псевдоним
			// и двоеточие). Где версии расходятся, решения нет — отказ.
			if name := s[pos+1 : p]; !anchorNameRe.MatchString(name) {
				return 0, lx.fail("имя якоря или псевдонима допустимо только из букв, цифр, _ и -")
			}
			if c == '*' {
				lx.saveKey(pos, candAlias, "", 0, false)
			} else {
				lx.saveProps(pos)
			}
			lx.allowed = false
			pos = p
		case c == '!':
			p := pos + 1
			for p < end && !strings.ContainsRune(" \t,[]{}", rune(s[p])) {
				p++
			}
			// !reset и !override — теги самого compose для слияния описаний;
			// имя ключа они не меняют. Любой другой тег способен превратить
			// значение в ключ, которого в тексте нет (`!!binary`).
			if tag := s[pos:p]; tag != "!reset" && tag != "!override" {
				return 0, lx.fail("тег YAML " + tail(tag, 30) + " не разбирается платформой")
			}
			lx.saveProps(pos)
			lx.allowed = false
			pos = p
		case c == '|' || c == '>':
			if len(lx.flow) > 0 {
				return 0, lx.fail("блочная строка внутри скобок")
			}
			return lx.blockScalar(pos, end)
		case c == '"' || c == '\'':
			p, name, escaped, err := lx.scanQuoted(pos, end)
			if err != nil {
				return 0, err
			}
			lx.mark(pos, p, lexQuoted)
			lx.saveKey(pos, candScalar, name, pos+1, escaped)
			lx.allowed = false
			pos = p
		case c == '%' || c == '@' || c == '`':
			return 0, lx.fail("символ " + string(c) + " не может начинать значение YAML")
		default:
			p := lx.scanPlain(pos, end)
			lx.saveKey(pos, candScalar, strings.TrimRight(s[pos:p], " \t"), pos, false)
			lx.allowed = false
			pos = p
		}
	}
	return lx.line + 1, nil
}

// saveKey — начало узла: если здесь разрешён простой ключ, узел — кандидат.
// Узел после якоря или тега кандидатом не становится: кандидат уже стоит на
// свойстве, как у go-yaml.
func (lx *yamlLexer) saveKey(pos, kind int, name string, nameAt int, escaped bool) {
	if !lx.allowed {
		return
	}
	*lx.cand() = simpleKey{ok: true, line: lx.line, col: pos - lx.lineStart, kind: kind,
		name: name, nameAt: nameAt, escaped: escaped}
}

func (lx *yamlLexer) saveProps(pos int) {
	if !lx.allowed {
		return
	}
	*lx.cand() = simpleKey{ok: true, line: lx.line, col: pos - lx.lineStart, kind: candScalar, props: true}
}

// value — двоеточие-индикатор: ключ перед ним обязан стоять на той же строке и
// быть строкой без свойств.
func (lx *yamlLexer) value(pos int) error {
	k := lx.cand()
	switch {
	case !k.ok || k.line != lx.line:
		return lx.fail("двоеточие без ключа на той же строке не разбирается платформой")
	case k.kind == candAlias:
		return lx.fail("псевдоним YAML на месте ключа не разбирается платформой")
	case k.kind == candCollection:
		return lx.fail("составной ключ не разбирается платформой")
	case k.props:
		return lx.fail("якорь или тег на ключе не разбирается платформой")
	case k.escaped:
		return lx.fail("экранирование внутри ключа в кавычках не разбирается платформой")
	}
	lx.rollIndent(k.col)
	lx.res.keys = append(lx.res.keys, lexKey{name: k.name, nameAt: k.nameAt, colon: pos, flow: len(lx.flow) > 0})
	k.ok = false
	lx.allowed = len(lx.flow) == 0
	return nil
}

// scanPlain — строка без кавычек от pos (правила scan_plain_scalar go-yaml):
// кончается на `: ` и, в скобках, на `,[]{}` и на `:` перед ними; `#` после
// пробела — начало комментария. Дошла до конца строки текста — может
// продолжиться дальше.
//
// `?` внутри строки в скобках — текст: так читает Compose v5
// (`[wget, http://x/?a=b]`). go-yaml v3 в старых compose обрывает там строку,
// но следующая за `?` пара без запятой у него — ошибка разбора, а не ключ.
// `:` перед `[` или `{` Compose v5 не принимает вовсе; разбор здесь видит на
// нём ключ — лишний отказ вместо пропуска.
func (lx *yamlLexer) scanPlain(pos, end int) int {
	s := lx.src
	lx.plain = false
	for pos < end {
		c := s[pos]
		if c == ':' && (lx.blankAt(pos+1) || (len(lx.flow) > 0 && strings.IndexByte(",[]{}", s[pos+1]) >= 0)) {
			return pos
		}
		if len(lx.flow) > 0 && strings.IndexByte(",[]{}", c) >= 0 {
			return pos
		}
		if c == ' ' || c == '\t' {
			q := pos
			for q < end && (s[q] == ' ' || s[q] == '\t') {
				q++
			}
			if q == end {
				break
			}
			if s[q] == '#' {
				return q
			}
			pos = q
			continue
		}
		pos++
	}
	lx.plain = true
	lx.plainIndent = lx.indent() + 1
	return end
}

// scanQuoted — строка в кавычках от pos; кончается на той же строке текста.
func (lx *yamlLexer) scanQuoted(pos, end int) (int, string, bool, error) {
	s := lx.src
	q := s[pos]
	var b strings.Builder
	escaped := false
	for p := pos + 1; p < end; p++ {
		switch {
		case q == '"' && s[p] == '\\':
			escaped = true
			if p+1 >= end {
				return 0, "", false, lx.fail("строка в кавычках продолжается на следующей строке — многострочная строка не разбирается платформой")
			}
			b.WriteByte(s[p])
			p++
			b.WriteByte(s[p])
		case s[p] == q && q == '\'' && p+1 < end && s[p+1] == '\'':
			b.WriteByte('\'')
			p++
		case s[p] == q:
			return p + 1, b.String(), escaped, nil
		default:
			b.WriteByte(s[p])
		}
	}
	return 0, "", false, lx.fail("строка в кавычках продолжается на следующей строке — многострочная строка не разбирается платформой")
}

// blockScalar — `|` или `>` в pos. Строки содержимого — как у
// scan_block_scalar go-yaml: отступ — наибольший из отступа первой непустой
// строки, пустых строк перед ней и parser.indent+1; содержимое идёт, пока
// строка пуста или её отступ не меньше.
func (lx *yamlLexer) blockScalar(pos, end int) (int, error) {
	s := lx.src
	p := pos + 1
	for p < end && (s[p] == '+' || s[p] == '-' || (s[p] >= '0' && s[p] <= '9')) {
		if s[p] != '+' && s[p] != '-' {
			return 0, lx.fail("явный отступ блочной строки не разбирается платформой")
		}
		p++
	}
	for p < end && (s[p] == ' ' || s[p] == '\t') {
		p++
	}
	if p < end && s[p] != '#' {
		return 0, lx.fail("после заголовка блочной строки допустим только комментарий")
	}
	lx.mark(p, end, lexComment)

	lines := lx.t.lines
	spaces := func(li int) (int, string) {
		ln := lines[li]
		n := 0
		for ln.start+n < ln.end && s[ln.start+n] == ' ' {
			n++
		}
		return n, s[ln.start+n : ln.end]
	}
	maxIndent := 0
	for li := lx.line + 1; li < len(lines); li++ {
		n, rest := spaces(li)
		if n > maxIndent {
			maxIndent = n
		}
		if strings.HasPrefix(rest, "\t") {
			return 0, &lexError{line: li, reason: "табуляция в отступе блочной строки"}
		}
		if rest != "" {
			break
		}
	}
	indent := max(maxIndent, lx.indent()+1, 1)

	li := lx.line + 1
	for ; li < len(lines); li++ {
		n, rest := spaces(li)
		if n >= indent {
			lx.mark(lines[li].start, lines[li].end, lexBlockText)
			continue
		}
		if rest == "" {
			continue
		}
		if rest[0] == '\t' {
			return 0, &lexError{line: li, reason: "табуляция в отступе блочной строки"}
		}
		break
	}
	lx.cand().ok = false
	lx.plain = false
	return li, nil
}
