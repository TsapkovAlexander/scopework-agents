# Агенты Scopework — открытый код

Здесь код двух программ, которые Scopework ставит на ваш сервер:

- **агент развёртывания** (`apps/deploy-agent`, Go, без внешних зависимостей) —
  выкатывает приложения, снимает копии, следит за здоровьем;
- **агент мониторинга** (`apps/discovery-runner/discovery/monitor-push.sh` и
  соседние файлы) — шлёт метрики и счётчики угроз, команд не исполняет.

Что агенты читают на сервере, что отправляют и какие команды могут получить —
[PROTOCOL.md](PROTOCOL.md). Лицензия — [Apache-2.0](LICENSE).

Основной репозиторий — <https://gitverse.ru/tsapkovalexander/scopework-agents>,
зеркало — <https://github.com/TsapkovAlexander/scopework-agents>. Содержимое и
подписанные выпуски в обоих одинаковые.

Открытый код чего-то стоит, только если бинарь на вашем сервере собран из него.
Поэтому главное в этом репозитории — не чтение, а проверка: собрать выпуск
самому и сравнить хеш с подписанным.

## Собери сам и сравни хеш

Нужны Docker и bash. Сборка идёт в контейнере Go, закреплённом по digest
(`GO_IMAGE` в `scripts/build-deploy-agent.sh`), с `-trimpath`,
`-buildvcs=false`, пустым `-buildid` и без меток времени, поэтому один и тот же
код даёт один и тот же бинарь на любой машине.

```sh
bash scripts/build-deploy-agent.sh build --out /tmp/scopework-release
cat /tmp/scopework-release/deploy-agent/$(cat apps/deploy-agent/VERSION)/SHA256SUMS
```

Сравните строки с `SHA256SUMS` подписанного выпуска той же версии (он приложен
к выпуску в этом репозитории). Или одной командой — пересобрать и сверить
скачанный каталог выпуска:

```sh
bash scripts/build-deploy-agent.sh verify <каталог выпуска>/deploy-agent/<версия>
```

Убедиться, что сборка воспроизводима у вас, — две сборки из разных путей в
чистых контейнерах:

```sh
bash scripts/build-deploy-agent.sh reproduce
```

## Проверь подпись выпуска

Выпуск подписан офлайн-ключом Ed25519, которого нет ни у платформы, ни в её
базе. Открытые ключи лежат в `apps/deploy-agent/trust/release/*.pub` и
вшиваются в агента при сборке. Проверка (Node.js 20+):

```sh
node scripts/deploy/sign-agent-release.mjs verify <каталог выпуска>/deploy-agent/<версия>
```

Отпечаток ключа — первые 16 hex-знаков sha256 сырых 32 байт ключа. Его печатают
`install.sh` при установке и сам агент на сервере:

```sh
scopework-agent version --trust
```

Сверьте его с отпечатком, опубликованным рядом с выпуском. Если ключей в
`trust/release` нет, выпуск неподписанный, и агент подпись обновлений не
проверяет — это видно в той же команде.

## Сверь бинарь на своём сервере

```sh
sha256sum /opt/tracedocs/deploy/bin/tracedocs-deploy-agent   # агент от своего пользователя
sha256sum /usr/local/bin/tracedocs-deploy-agent              # агент от root
```

Хеш обязан совпасть со строкой вашей архитектуры (`linux-amd64` или
`linux-arm64`) в `SHA256SUMS`.

## Проверь, что агенту разрешено и что он получал

- `scopework-agent policy show` — локальная политика, как её понял агент.
  Файл `/etc/tracedocs/agent-policy.conf` пишет только root на сервере, платформа
  его изменить не может.
- `scopework-agent journal verify` и `scopework-agent journal show` — локальный
  журнал всех полученных команд с цепочкой хешей. Как проверить цепочку без
  нашего бинаря, `sha256sum` и `jq`, — в [PROTOCOL.md](PROTOCOL.md).

## Агент мониторинга

Агент ставится бандлом из `push.sh`, `build-snapshot-json.py` и `uninstall.sh`.
Выпуск и sha256 бандла, который подписывается:

```sh
node scripts/sync-monitor-agent-scripts.mjs --print-bundle
node scripts/deploy/sign-agent-release.mjs verify-monitor
```

## Тесты

```sh
cd apps/deploy-agent && go test ./...
```

Нужен Go из `go.mod`. Тесты, которые поднимают настоящие контейнеры, собраны
под меткой `dockersmoke` и в обычный прогон не входят
(`go test -tags dockersmoke ./...` — с запущенным Docker).

## Откуда этот код

Разработка идёт во внутреннем репозитории Scopework; здесь — отражение
выпусков: один выпуск — один коммит и метка `deploy-agent/vX.Y.Z` или
`monitor-agent/vX.Y.Z`. Сообщения о проблемах принимаются здесь, исправления
переносятся во внутренний репозиторий и приходят следующим выпуском.
