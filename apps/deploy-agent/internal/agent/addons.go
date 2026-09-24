package agent

import (
	"fmt"
	"regexp"
)

// Аддоны (0186): postgres/redis рядом с приложением — сервисы в том же
// синтетическом compose, в его же compose-сети. Сервер присылает разрешённый
// список {kind, service, image}; агент рендерит его механически, но каждое
// значение проверяет заново: оно уезжает в YAML, который поднимет root-
// эквивалентный docker.
//
// Негодный аддон — отказ применения целиком, не молчаливый пропуск:
// приложение с DATABASE_URL, указывающим в никуда, упало бы позже и
// непонятнее, чем честная ошибка здесь.

// Образ аддона обязан быть пришпилен дайджестом: каталог сервера прибивает
// версии, и «какой-нибудь postgres» здесь не бывает.
var safePinnedImage = regexp.MustCompile(
	`^([a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?/)?[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?@sha256:[a-f0-9]{64}$`)

type renderedAddons struct {
	// services — YAML-блоки сервисов (той же вложенности, что "  app:").
	services string
	// volumes — верхнеуровневая секция volumes, если аддонам нужны тома.
	volumes string
	// dependsOn — блок `depends_on` для сервиса приложения: он обязан ждать
	// готовности базы, а не просто её запуска.
	dependsOn string
	// dependsOnList — имена сервисов, готовности которых ждём. Собирается по
	// ходу, чтобы порядок совпадал с порядком объявления аддонов.
	dependsOnList []string
}

func renderAddonServices(addons []AddonSpec) (renderedAddons, error) {
	var out renderedAddons
	needVolumes := false

	for _, a := range addons {
		if !safeServiceName.MatchString(a.Service) {
			return renderedAddons{}, fmt.Errorf("аддон %q: недопустимое имя сервиса %q", a.Kind, a.Service)
		}
		if !safePinnedImage.MatchString(a.Image) {
			return renderedAddons{}, fmt.Errorf("аддон %q: образ не пришпилен дайджестом: %q", a.Kind, a.Image)
		}

		switch a.Kind {
		case "postgres":
			// Пароль приходит интерполяцией из .env (${ADDON_POSTGRES_PASSWORD}),
			// который агент пишет рядом, — открытым текстом в YAML его нет.
			out.services += "  " + a.Service + ":\n" +
				"    image: \"" + a.Image + "\"\n" +
				"    restart: unless-stopped\n" +
				"    environment:\n" +
				"      POSTGRES_USER: app\n" +
				"      POSTGRES_DB: app\n" +
				"      POSTGRES_PASSWORD: ${ADDON_POSTGRES_PASSWORD}\n" +
				"    volumes:\n" +
				"      - db-data:/var/lib/postgresql/data\n" +
				"    healthcheck:\n" +
				"      test: [\"CMD-SHELL\", \"pg_isready -U app -d app\"]\n" +
				"      interval: 10s\n      timeout: 5s\n      retries: 5\n" +
				"    security_opt:\n" +
				"      - no-new-privileges:true\n" +
				"    deploy:\n      resources:\n        limits:\n          memory: 512M\n"
			needVolumes = true
			out.dependsOnList = append(out.dependsOnList, a.Service)
		case "redis":
			out.services += "  " + a.Service + ":\n" +
				"    image: \"" + a.Image + "\"\n" +
				"    restart: unless-stopped\n" +
				"    healthcheck:\n" +
				"      test: [\"CMD\", \"redis-cli\", \"ping\"]\n" +
				"      interval: 10s\n      timeout: 5s\n      retries: 5\n" +
				"    security_opt:\n" +
				"      - no-new-privileges:true\n" +
				"    deploy:\n      resources:\n        limits:\n          memory: 256M\n"
			out.dependsOnList = append(out.dependsOnList, a.Service)
		default:
			return renderedAddons{}, fmt.Errorf("неизвестный вид аддона: %q", a.Kind)
		}
	}

	if needVolumes {
		out.volumes = "volumes:\n  db-data: {}\n"
	}

	// ПРИЛОЖЕНИЕ ЖДЁТ ГОТОВНОСТИ АДДОНА, А НЕ ЕГО ЗАПУСКА (11.09.2026).
	//
	// До этого синтетический стек не связывал их вовсе: compose поднимал оба
	// разом, и приложение с миграциями на старте било в postgres, который ещё
	// не принимает соединения. Дальше по-разному: контейнер падал и уходил в
	// цикл перезапуска, `up --wait` признавал стек негодным, а человек читал
	// «стек не поднялся» и шёл искать ошибку в своём коде.
	//
	// `service_healthy`, а не `service_started`: у аддонов есть проверка
	// здоровья (pg_isready, redis-cli ping), и ждать надо именно её. Запуск
	// контейнера postgres ничего не обещает — база инициализируется секунды.
	if out.dependsOnList != nil {
		out.dependsOn = "    depends_on:\n"
		for _, name := range out.dependsOnList {
			out.dependsOn += "      " + name + ":\n        condition: service_healthy\n"
		}
	}

	return out, nil
}

// addonServiceModel — тот же аддон МОДЕЛЬЮ, для стека из репозитория клиента.
//
// ЗАЧЕМ ВТОРАЯ ФОРМА. Синтетический стек агент собирает текстом YAML, а чужой —
// правит разобранной моделью и печатает её обратно. Вживлять сервис в чужой
// файл склейкой строк нельзя: там уже есть авторские отступы, якоря и порядок
// ключей, и текстовая вставка их ломает.
//
// ДВЕ ФОРМЫ — ДВА МЕСТА, ГДЕ ЗНАНИЕ РАЗОЙДЁТСЯ. Поэтому рядом стоит тест
// `TestAddonFormsAgree`: он сверяет обе по существенным полям — образ, база,
// пользователь, том, проверка здоровья. Разъехавшись, они дали бы одному
// клиенту базу с проверкой здоровья, а другому без.
func addonServiceModel(a AddonSpec) (map[string]any, string, error) {
	if !safeServiceName.MatchString(a.Service) {
		return nil, "", fmt.Errorf("аддон %q: недопустимое имя сервиса %q", a.Kind, a.Service)
	}
	if !safePinnedImage.MatchString(a.Image) {
		return nil, "", fmt.Errorf("аддон %q: образ не пришпилен дайджестом: %q", a.Kind, a.Image)
	}

	common := func(extra map[string]any) map[string]any {
		svc := map[string]any{
			"image":   a.Image,
			"restart": "unless-stopped",
			// Тот же запрет повышения прав, что в синтетическом стеке: аддон
			// поднимается рядом с чужим приложением, и послаблений ему не
			// полагается только потому, что compose авторский.
			"security_opt": []any{"no-new-privileges:true"},
		}
		for k, v := range extra {
			svc[k] = v
		}
		return svc
	}

	switch a.Kind {
	case "postgres":
		return common(map[string]any{
			"environment": map[string]any{
				"POSTGRES_USER": "app",
				"POSTGRES_DB":   "app",
				// Пароль интерполяцией из .env, который агент пишет рядом:
				// открытым текстом в описании стека его нет.
				"POSTGRES_PASSWORD": "${ADDON_POSTGRES_PASSWORD}",
			},
			"volumes": []any{addonPostgresVolume + ":/var/lib/postgresql/data"},
			"healthcheck": map[string]any{
				"test":     []any{"CMD-SHELL", "pg_isready -U app -d app"},
				"interval": "10s", "timeout": "5s", "retries": float64(5),
			},
			"deploy": map[string]any{
				"resources": map[string]any{"limits": map[string]any{"memory": "512M"}},
			},
		}), addonPostgresVolume, nil

	case "redis":
		return common(map[string]any{
			"healthcheck": map[string]any{
				"test":     []any{"CMD", "redis-cli", "ping"},
				"interval": "10s", "timeout": "5s", "retries": float64(5),
			},
			"deploy": map[string]any{
				"resources": map[string]any{"limits": map[string]any{"memory": "256M"}},
			},
		}), "", nil
	}

	return nil, "", fmt.Errorf("неизвестный вид аддона: %q", a.Kind)
}

// Имя тома базы. Одно на обе формы — по нему данные и находятся между выкатами.
const addonPostgresVolume = "db-data"
