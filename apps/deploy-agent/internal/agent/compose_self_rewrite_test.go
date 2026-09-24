package agent

import "testing"

// Побег через собственный каталог приложения (задача С1.6).
//
// СНАЧАЛА ВОСПРОИЗВЕДЕНО, ПОТОМ ЗАКРЫТО. Guard разрешает bind внутри каталога
// приложения — это и есть законный способ приложения хранить данные. Но в том
// же каталоге лежат `docker-compose.yml` и `.env`, которыми агент этот стек и
// поднимает.
//
// Значит контейнер, получивший bind своего каталога, переписывает файл, по
// которому его запускают, — и следующий подъём (самовосстановление после
// падения, `recover.go`) поднимает уже ПОДМЕНЁННЫЙ стек: с `privileged`, с
// сокетом докера, с любым томом хоста. Guard при этом отработал честно: на
// момент выката файл был чистым.
func TestBindOfOwnComposeIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		source string
	}{
		{"весь каталог приложения", "/opt/tracedocs/apps/demo"},
		{"каталог со слэшем", "/opt/tracedocs/apps/demo/"},
		{"сам файл compose", "/opt/tracedocs/apps/demo/docker-compose.yml"},
		{"compose под другим именем", "/opt/tracedocs/apps/demo/compose.yaml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			json := `{"services":{"app":{"volumes":[{"type":"bind","source":"` +
				tc.source + `","target":"/data"}]}}}`
			v, err := checkComposeSafetyIn([]byte(json), []string{"/opt/tracedocs/apps/demo"}, nil,
				[]string{"/opt/tracedocs/apps/demo"})
			if err != nil {
				t.Fatalf("разбор: %v", err)
			}
			if len(v) == 0 {
				t.Fatalf("bind %q прошёл: контейнер сможет переписать файл, которым его поднимают",
					tc.source)
			}
		})
	}
}

// Обратная сторона: обычный подкаталог данных обязан работать. Иначе правка
// закрывает дыру ценой самой возможности хранить данные.
func TestBindOfDataSubdirStillAllowed(t *testing.T) {
	for _, source := range []string{
		"/opt/tracedocs/apps/demo/data",
		"/opt/tracedocs/apps/demo/data/pg",
		"/opt/tracedocs/apps/demo/uploads",
	} {
		json := `{"services":{"app":{"volumes":[{"type":"bind","source":"` +
			source + `","target":"/data"}]}}}`
		v, err := checkComposeSafetyIn([]byte(json), []string{"/opt/tracedocs/apps/demo"}, nil,
				[]string{"/opt/tracedocs/apps/demo"})
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(v) != 0 {
			t.Fatalf("bind %q отвергнут, а он законный: %v", source, v)
		}
	}
}

// `.env` остаётся разрешённым — это РЕШЕНИЕ, и тест его держит.
//
// Монтировать свой `.env` внутрь контейнера — законный и частый приём, а
// содержимое этого файла приложение и так получает переменными. Запрет сломал
// бы работающие стеки ради того, что у контейнера уже есть.
//
// Разница с compose принципиальная: подмена `.env` меняет переменные того же
// стека, подмена compose даёт `privileged`, сокет докера и любой том хоста.
func TestBindOfOwnEnvStaysAllowed(t *testing.T) {
	const json = `{"services":{"app":{"volumes":[{"type":"bind",` +
		`"source":"/opt/tracedocs/apps/demo/.env","target":"/app/.env"}]}}}`
	v, err := checkComposeSafetyIn([]byte(json), []string{"/opt/tracedocs/apps/demo"}, nil,
		[]string{"/opt/tracedocs/apps/demo"})
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("законное монтирование .env отклонено: %v", v)
	}
}
