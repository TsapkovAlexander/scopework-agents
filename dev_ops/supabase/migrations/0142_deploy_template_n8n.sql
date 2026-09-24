-- 0142: первый шаблон каталога — n8n.
--
-- Почему n8n первым, а не Supabase: два контейнера против одиннадцати. Весь
-- путь (подключение хоста → выкат → домен → сертификат) обкатывается на
-- простом стеке, и только потом переносится на сложные.
--
-- ПОДСТАНОВКА ПЕРЕМЕННЫХ. Плейсхолдеры ${VAR} остаются в compose как есть —
-- их разворачивает сам docker compose из файла .env, который агент кладёт
-- рядом с правами 0600. Своего шаблонизатора нет намеренно: чем меньше кода
-- между пользовательским вводом и сгенерированным compose, тем меньше мест,
-- где ввод может из значения превратиться в директиву.
--
-- РЕШЕНИЯ ПО БЕЗОПАСНОСТИ, заложенные в compose:
--   * ни одного `ports:` — наружу приложение попадает только через обратный
--     прокси, который агент держит отдельно. Иначе n8n торчал бы в интернет
--     напрямую, мимо TLS и мимо любых ограничений;
--   * две сети: база доступна только приложению (`internal`), а во внешнюю
--     (`edge`) смотрит лишь само приложение. Скомпрометированный сосед по
--     хосту не увидит порт PostgreSQL;
--   * `no-new-privileges` — процесс внутри контейнера не сможет повысить
--     права через setuid-бинарь;
--   * лимиты памяти: один стек не должен утилизировать хост целиком;
--   * версии образов зафиксированы тегом. Пин по digest появится вместе с
--     собственным registry — тег теоретически можно перевесить, и это
--     осознанный временный компромисс, а не недосмотр.

INSERT INTO deploy.templates (slug, name, description, version, internal_port, vars_schema, compose_template)
VALUES (
  'n8n',
  'n8n',
  'Автоматизация процессов: визуальный конструктор сценариев и интеграций. Разворачивается с собственной базой PostgreSQL.',
  '1.0.0',
  5678,
  jsonb_build_object(
    'type', 'object',
    'required', jsonb_build_array('TZ'),
    'properties', jsonb_build_object(
      'TZ', jsonb_build_object(
        'type', 'string',
        'title', 'Часовой пояс',
        'default', 'Europe/Moscow',
        'description', 'В нём n8n показывает время запусков и считает расписания.'
      )
    ),
    -- Секреты пользователь не вводит: их генерирует сервер при создании
    -- приложения. Спрашивать такое у человека — значит получить слабые
    -- значения и повторы между установками.
    'generatedSecrets', jsonb_build_array('POSTGRES_PASSWORD', 'N8N_ENCRYPTION_KEY')
  ),
  $compose$name: ${APP_SLUG}

services:
  db:
    image: postgres:16.6-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: n8n
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: n8n
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - internal
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U n8n -d n8n"]
      interval: 10s
      timeout: 5s
      retries: 10
    deploy:
      resources:
        limits:
          memory: 512M

  app:
    image: n8nio/n8n:1.72.1
    restart: unless-stopped
    environment:
      DB_TYPE: postgresdb
      DB_POSTGRESDB_HOST: db
      DB_POSTGRESDB_PORT: 5432
      DB_POSTGRESDB_DATABASE: n8n
      DB_POSTGRESDB_USER: n8n
      DB_POSTGRESDB_PASSWORD: ${POSTGRES_PASSWORD}
      N8N_ENCRYPTION_KEY: ${N8N_ENCRYPTION_KEY}
      N8N_HOST: ${APP_DOMAIN}
      N8N_PROTOCOL: https
      N8N_PORT: 5678
      WEBHOOK_URL: https://${APP_DOMAIN}/
      GENERIC_TIMEZONE: ${TZ}
      TZ: ${TZ}
      # Прокси стоит перед приложением, поэтому доверяем его заголовкам —
      # иначе n8n будет строить ссылки на http и внутренний адрес.
      N8N_PROXY_HOPS: 1
      # Телеметрию выключаем: клиентские сценарии — не наши данные.
      N8N_DIAGNOSTICS_ENABLED: "false"
    volumes:
      - app-data:/home/node/.n8n
    networks:
      - internal
      - edge
    depends_on:
      db:
        condition: service_healthy
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:5678/healthz || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 10
      start_period: 60s
    deploy:
      resources:
        limits:
          memory: 1G

volumes:
  db-data:
  app-data:

networks:
  internal:
    internal: true
  edge:
    external: true
    name: tracedocs-edge
$compose$
)
ON CONFLICT (slug) DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  version = EXCLUDED.version,
  internal_port = EXCLUDED.internal_port,
  vars_schema = EXCLUDED.vars_schema,
  compose_template = EXCLUDED.compose_template,
  updated_at = now();

-- Контроль: SELECT slug, version, internal_port FROM deploy.templates;
