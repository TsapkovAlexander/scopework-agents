package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Дефект, ради которого написан build.go: приложение из репозитория,
// собираемое по Dockerfile, пересобиралось ровно один раз.
//
// Синтетический compose объявляет `build:` без `image:`, поэтому первый
// `docker compose up` собирал образ, а все следующие находили его на месте и
// поднимали контейнер из старого слоя. `git reset --hard` при этом честно
// подтягивал свежий коммит: файлы новые, образ прежний, health gate зелёный.
//
// Здесь заперты ПРАВИЛА — кому нужна сборка и какие образы после неё лишние.
// Сам вызов docker проверяется смоук-тестом (apply_docker_test.go): без демона
// его здесь не воспроизвести, а правила без демона проверяются полностью.
func TestNeedsImageBuild(t *testing.T) {
	cases := []struct {
		name       string
		sourceType string
		method     string
		want       bool
	}{
		{
			name:       "git dockerfile — образ строим мы, без сборки будет старый код",
			sourceType: "git",
			method:     buildMethodDockerfile,
			want:       true,
		},
		{
			name:       "git compose — репозиторий может объявить свой build:, guard его не запрещает",
			sourceType: "git",
			method:     buildMethodCompose,
			want:       true,
		},
		{
			name:       "git static — образ nginx:alpine готовый, файлы монтируются томом",
			sourceType: "git",
			method:     buildMethodStatic,
			want:       false,
		},
		{
			name:       "шаблон каталога — compose пишет платформа, собирать нечего",
			sourceType: "template",
			method:     "",
			want:       false,
		},
		{
			name:       "свой compose — обязательные digest, сборка запрещена политикой",
			sourceType: "compose",
			method:     "",
			want:       false,
		},
		{
			name:       "готовый образ — источник и есть образ",
			sourceType: "image",
			method:     "",
			want:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := DesiredApp{SourceType: tc.sourceType, BuildMethod: tc.method}
			if got := app.needsImageBuild(); got != tc.want {
				t.Fatalf("needsImageBuild() = %v, ожидалось %v", got, tc.want)
			}
		})
	}
}

func TestParseImageIDs(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want []string
	}{
		{
			name: "обычный вывод",
			out:  "a1b2c3d4e5f6\n0f1e2d3c4b5a\n",
			want: []string{"a1b2c3d4e5f6", "0f1e2d3c4b5a"},
		},
		{
			// Два сервиса на одном образе (app и worker из одного Dockerfile)
			// дают одинаковый идентификатор дважды. Без свёртки мы попытались
			// бы удалить его дважды и записали бы ложную вторую ошибку.
			name: "дубликаты сворачиваются",
			out:  "a1b2c3d4e5f6\na1b2c3d4e5f6\n",
			want: []string{"a1b2c3d4e5f6"},
		},
		{
			name: "пустой вывод — стек ещё не поднимался",
			out:  "\n  \n",
			want: nil,
		},
		{
			// Docker при неудаче пишет в тот же поток. Строка, не похожая на
			// идентификатор, обязана быть отброшена: она уехала бы в
			// `docker image rm` аргументом.
			name: "мусор отбрасывается",
			out:  "Cannot connect to the Docker daemon\na1b2c3d4e5f6\n",
			want: []string{"a1b2c3d4e5f6"},
		},
		{
			name: "полный sha256 тоже принимается",
			out:  "sha256:" + strings.Repeat("ab", 32) + "\n",
			want: []string{"sha256:" + strings.Repeat("ab", 32)},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseImageIDs(tc.out)
			if len(got) != len(tc.want) {
				t.Fatalf("parseImageIDs() = %v, ожидалось %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseImageIDs()[%d] = %q, ожидалось %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// Уборка обязана трогать ТОЛЬКО то, что вытеснила эта самая пересборка.
//
// Общий `docker image prune` на хосте клиента снёс бы промежуточные образы
// соседних стеков и чужих сборок — а заодно исказил бы прогноз исчерпания
// диска в мониторинге, который считает тренд по накопленным замерам: разовый
// провал занятости от чужой уборки читается как «место освободилось само».
func TestReplacedImages(t *testing.T) {
	cases := []struct {
		name   string
		before []string
		after  []string
		want   []string
	}{
		{
			name:   "образ заменён — прежний больше не нужен",
			before: []string{"old1"},
			after:  []string{"new1"},
			want:   []string{"old1"},
		},
		{
			name:   "пересборка ничего не изменила — удалять нечего",
			before: []string{"same"},
			after:  []string{"same"},
			want:   nil,
		},
		{
			// Первый выкат: контейнеров ещё не было, список пуст.
			name:   "первый релиз",
			before: nil,
			after:  []string{"new1"},
			want:   nil,
		},
		{
			// Аддон (PostgreSQL, Redis) тянется по digest и не пересобирается —
			// его образ обязан пережить уборку.
			name:   "образ аддона остаётся на месте",
			before: []string{"appold", "pg16"},
			after:  []string{"appnew", "pg16"},
			want:   []string{"appold"},
		},
		{
			// Чтение состояния не удалось — списка «до» нет. Пустой список
			// значит «удалять нечего», а не «удалить всё»: ошибка чтения не
			// повод сносить работающие образы.
			name:   "неизвестное состояние до сборки",
			before: nil,
			after:  nil,
			want:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := replacedImages(tc.before, tc.after)
			if len(got) != len(tc.want) {
				t.Fatalf("replacedImages() = %v, ожидалось %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("replacedImages()[%d] = %q, ожидалось %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// Лимит Docker Hub объясняется, только если зеркало действительно не применено.
//
// Анонимный лимит считается на подсеть провайдера, а установщик на хосте с
// работающими контейнерами записывает зеркало и НЕ перезапускает демон —
// рестарт остановил бы всё, что там крутится. Настройка остаётся записанной и
// недействующей, а человек видит сырое `toomanyrequests` и ищет причину в
// своём приложении.
func TestExplainPullLimit(t *testing.T) {
	const limit = "failed to solve: toomanyrequests: You have reached your pull rate limit"

	ctx := context.Background()
	p := Paths{StateDir: t.TempDir()}

	// Без отметки — текст не меняется: на хосте с применённым зеркалом причина
	// другая, и подсказка увела бы не туда.
	if got := explainPullLimit(ctx, p, limit); got != limit {
		t.Fatalf("подсказка добавлена без отметки: %q", got)
	}

	// Чужая ошибка подсказку не получает даже с отметкой.
	const other = "failed to solve: process /bin/sh -c npm ci did not complete"
	marker := filepath.Join(p.StateDir, "registry-mirror-pending")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := explainPullLimit(ctx, p, other); got != other {
		t.Fatalf("подсказка добавлена к посторонней ошибке: %q", got)
	}

	// Отметка стоит, ошибка та самая — подсказка появляется. Каталог берётся
	// из переданных путей, а не из DefaultPaths(): STATE_DIR переопределяем.
	got := explainPullLimit(ctx, p, limit)
	if !strings.Contains(got, "systemctl restart docker") {
		t.Fatalf("подсказки нет при стоящей отметке: %q", got)
	}
}
