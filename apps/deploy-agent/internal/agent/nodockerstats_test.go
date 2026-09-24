package agent

import (
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Агент не обращается к статистике Docker — ни `docker stats`, ни
// /containers/{id}/stats (ADR-0066, решение 4; ADR-0091, решение 3). Она
// дороже файлов cgroup и держит запрос два цикла сбора; сигналы нагрузок
// читаются из cgroup и /proc. Запрет легко нарушить одной строкой в любом
// месте агента, поэтому он держится проверкой, а не памятью.
//
// Смотрятся строковые литералы и идентификаторы, а не комментарии: объяснение,
// почему статистики нет, — не обращение к ней. Слово целиком: «stats» как
// подкоманда CLI, сегмент пути API или часть строки команды.
var noDockerStatsLiteral = regexp.MustCompile(`\bstats\b`)

// noDockerStatsAllowed — точечные исключения: файл и литерал целиком, а не
// файл. dockerproxy.go — белый список прокси сокета (ADR-0083): правило
// говорит, что прокси пропускает к демону, а не что вызывает агент. Сужать
// его — дело прокси и его гейта test:docker-socket-proxy. Любой ДРУГОЙ
// литерал со stats, в том числе в самом dockerproxy.go, этот тест ловит.
var noDockerStatsAllowed = map[string]string{
	"internal/agent/dockerproxy.go": "/(json|logs|stats|top|changes)$",
}

func TestNoDockerStats(t *testing.T) {
	// Тест идёт из internal/agent; корень модуля — два уровня выше.
	var files []string
	for _, pattern := range []string{"*.go", "../../*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if !strings.HasSuffix(m, "_test.go") {
				files = append(files, m)
			}
		}
	}

	scanned := map[string]bool{}
	allowedSeen := map[string]bool{}
	var violations []string
	for _, path := range files {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.Join("internal/agent", path))), "./")
		scanned[rel] = true

		fset := token.NewFileSet()
		var s scanner.Scanner
		s.Init(fset.AddFile(rel, -1, len(src)), src, func(pos token.Position, msg string) {
			t.Errorf("%s: не разобран: %s", pos, msg)
		}, 0)
		for {
			pos, tok, lit := s.Scan()
			if tok == token.EOF {
				break
			}
			switch tok {
			case token.STRING:
				value, err := strconv.Unquote(lit)
				if err != nil || !noDockerStatsLiteral.MatchString(value) {
					continue
				}
				if noDockerStatsAllowed[rel] == value {
					allowedSeen[rel] = true
					continue
				}
				violations = append(violations, fset.Position(pos).String()+": "+lit)
			case token.IDENT:
				// Метод клиента Docker SDK: обращение к статистике без единой строки «stats».
				if strings.HasPrefix(lit, "ContainerStats") {
					violations = append(violations, fset.Position(pos).String()+": "+lit)
				}
			}
		}
	}

	// «Нарушений нет» не то же самое, что «проверять было нечего»: пустой
	// набор файлов или потерянный main.go дали бы зелёный без проверки.
	for _, must := range []string{"main.go", "cmd_docker_proxy.go", "internal/agent/workload_inspect.go", "internal/agent/dockerproxy.go"} {
		if !scanned[must] {
			t.Fatalf("ПРОВЕРКА НЕ ПРОВЕДЕНА: %s не просканирован (просканировано %d файлов)", must, len(scanned))
		}
	}
	// Исключение читается в обе стороны: литерала больше нет — исключение
	// устарело и молча разрешало бы то, чего уже нет.
	for file, literal := range noDockerStatsAllowed {
		if !allowedSeen[file] {
			t.Errorf("исключение %s %q больше не встречается — убери его из noDockerStatsAllowed", file, literal)
		}
	}
	for _, v := range violations {
		t.Errorf("обращение к статистике Docker (ADR-0066, решение 4): %s", v)
	}
	t.Logf("просканировано %d файлов", len(scanned))
}
