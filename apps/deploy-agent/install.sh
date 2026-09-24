#!/usr/bin/env bash
#
# Установка агента платформы развёртывания Scopework.
#
# Ставит бинарь, регистрирует сервер по одноразовому токену и поднимает
# systemd-юнит. Повторный запуск на уже подключённом сервере отказывает: ключ
# перезаписывать нельзя, иначе сервер перестанет узнаваться.
#
# Использование:
#   TRACEDOCS_URL=https://scopework.ru \
#   TRACEDOCS_TOKEN=tdx_... \
#   ACME_EMAIL=ops@example.com \
#   ./install.sh [--mode observe|deploy] [--commands a,b] [--updates manual|no_major|auto|"pinned X.Y.Z"]
#
# Флаги задают политику сервера — файл /etc/tracedocs/agent-policy.conf
# (ADR-0095). Без --mode: новый сервер получает mode=observe, у подключённого
# файл не трогается. Через `bash -c "$(curl …)"` флаги идут после имени:
# `bash -c "$(curl …)" install --mode observe`.
#
# Без --updates обновления агента развёртывания — manual: ручная установка
# получает самое осторожное правило. Команда из окна подключения сервера
# всегда несёт --updates с режимом сервера или компании (ADR-0095, п. 12).
#
set -euo pipefail

STATE_DIR="${STATE_DIR:-/etc/tracedocs/deploy}"
WORK_DIR="${WORK_DIR:-/opt/tracedocs/deploy}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/tracedocs-deploy-agent}"
UNIT_PATH="/etc/systemd/system/tracedocs-deploy.service"
PROXY_UNIT_PATH="/etc/systemd/system/tracedocs-docker-proxy.service"
INTERVAL="${INTERVAL:-60s}"

# Пользователь, от которого работает агент, и сокет прокси Docker (ADR-0083).
#
# До 18.09.2026 агент работал от root с доступом к /var/run/docker.sock — то
# есть был root-эквивалентен, и любая его ошибка стоила чужого сервера
# целиком. Теперь привилегированная часть — только прокси: он один говорит с
# демоном, пропускает перечисленные вызовы и отбивает привилегии в теле.
AGENT_USER="${AGENT_USER:-tracedocs-agent}"
PROXY_SOCKET="${PROXY_SOCKET:-/run/tracedocs/docker-proxy.sock}"
# Бинарь агента лежит ОТДЕЛЬНО от бинаря прокси, хотя файл один и тот же.
#
# Агент обновляет сам себя — значит каталог его бинаря обязан принадлежать
# ему. Прокси при этом остаётся в /usr/local/bin под root и автоматически НЕ
# обновляется вовсе: привилегированная часть не должна меняться по команде
# платформы. Цена названа: новую версию прокси приносит человек, повторяя
# команду установки.
AGENT_BIN_DIR="${AGENT_BIN_DIR:-$WORK_DIR/bin}"
AGENT_BIN="$AGENT_BIN_DIR/tracedocs-deploy-agent"
# Режим: proxy (по умолчанию) или root. root оставлен как явный откат для
# хоста, где прокси почему-то не поднялся.
PRIVILEGE_MODE="${PRIVILEGE_MODE:-proxy}"

# >>> HOST_POLICY_PARSER (границы использует installScript.test.ts — не переименовывать)
# Разбор файла политики сервера (ADR-0095, п. 1) — ПОБАЙТОВАЯ КОПИЯ функций из
# apps/discovery-runner/discovery/monitor-push.sh (блок HOST_POLICY_BLOCK).
#
# Копия, а не общий файл: оба скрипта ставятся на сервер по отдельности и не
# могут подключать друг друга. Разойтись копиям не дают два теста
# installScript.test.ts: функции сверяются с оригиналом байт в байт, и через
# копию проходят все случаи общей фикстуры host-policy.json. Правка — в
# оригинале, затем сюда тем же текстом.
HOST_POLICY_MAX_BYTES=4096
HOST_POLICY_COMMAND_KINDS="apply backup restore export migrate-data start-stack stop-stack inventory"

# MAJOR.MINOR.PATCH без ведущих нулей — та же форма, что у пина в файле.
release_valid() {
  local LC_ALL=C re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
  if [[ "$1" =~ $re ]]; then return 0; fi
  return 1
}

# Негодный файл закрывает всё: владелец писал его, чтобы ограничить, и
# опечатка не должна открывать.
host_policy_close() {
  POLICY_STATE="invalid" POLICY_ERROR="$1" POLICY_MODE="observe" POLICY_COMMANDS=""
  POLICY_DEPLOY_UPDATES="manual" POLICY_MONITOR_UPDATES="manual" POLICY_CONTAINER_LOGS="deny"
}

# Значение ключа обновлений в каноническом виде (pinned — через один пробел)
# в POLICY_VALUE. Код 1 — значение негодно.
host_policy_updates() {
  local v="$1" pin
  case "$v" in
    manual | no_major | auto) POLICY_VALUE="$v"; return 0 ;;
  esac
  [[ "$v" == pinned[$' \t']* ]] || return 1
  pin="${v#pinned}"
  pin="${pin#"${pin%%[!$' \t']*}"}"
  release_valid "$pin" || return 1
  POLICY_VALUE="pinned ${pin}"
}

# Разбор файла политики. Итог — в переменных:
#   POLICY_STATE           absent | valid | invalid
#   POLICY_ERROR           что не так с негодным файлом
#   POLICY_MODE            observe | deploy
#   POLICY_COMMANDS        виды через запятую, в порядке закрытого списка
#   POLICY_DEPLOY_UPDATES, POLICY_MONITOR_UPDATES   manual | no_major | auto | pinned X.Y.Z
#   POLICY_CONTAINER_LOGS  allow | deny
# Файла нет — значения пустые: действует прежнее поведение, а не политика.
read_host_policy() {
  local LC_ALL=C path="$1" size nul line key value seen=" " rest item kind
  local version="" mode="" commands="" have_commands=0 deploy_updates="" monitor_updates="" logs=""
  POLICY_STATE="absent" POLICY_ERROR="" POLICY_MODE="" POLICY_COMMANDS=""
  POLICY_DEPLOY_UPDATES="" POLICY_MONITOR_UPDATES="" POLICY_CONTAINER_LOGS=""
  # Ссылка в никуда — не «файла нет»: владелец её положил, значит хотел политику.
  if [[ ! -e "$path" && ! -L "$path" ]]; then return 0; fi
  if [[ ! -f "$path" || ! -r "$path" ]]; then
    host_policy_close "файл не читается"; return 0
  fi
  size=$(wc -c <"$path" 2>/dev/null) || size=""
  size="${size//[!0-9]/}"
  if [[ -z "$size" ]]; then host_policy_close "файл не читается"; return 0; fi
  if [[ "$size" -gt "$HOST_POLICY_MAX_BYTES" ]]; then
    host_policy_close "больше ${HOST_POLICY_MAX_BYTES} байт"; return 0
  fi
  # read молча выбрасывает нулевые байты: «mo\0de» стало бы «mode», а агент
  # развёртывания ту же строку закрыл бы.
  nul=$(tr -cd '\000' <"$path" 2>/dev/null | wc -c) || nul=""
  nul="${nul//[!0-9]/}"
  if [[ "$nul" != "0" ]]; then host_policy_close "в файле нулевые байты"; return 0; fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="${line%%#*}"
    line="${line#"${line%%[!$' \t']*}"}"
    line="${line%"${line##*[!$' \t']}"}"
    [[ -n "$line" ]] || continue
    if [[ "$line" != *=* ]]; then host_policy_close "строка без «=»"; return 0; fi
    key="${line%%=*}" value="${line#*=}"
    key="${key%"${key##*[!$' \t']}"}"
    value="${value#"${value%%[!$' \t']*}"}"
    case "$key" in
      version | mode | commands | deploy_agent_updates | monitor_agent_updates | container_logs) ;;
      *) host_policy_close "незнакомый ключ «${key}»"; return 0 ;;
    esac
    if [[ "$seen" == *" ${key} "* ]]; then host_policy_close "ключ «${key}» повторён"; return 0; fi
    seen="${seen}${key} "
    case "$key" in
      version) version="$value" ;;
      mode)
        case "$value" in observe | deploy) mode="$value" ;; *) host_policy_close "mode: «${value}»"; return 0 ;; esac
        ;;
      container_logs)
        case "$value" in allow | deny) logs="$value" ;; *) host_policy_close "container_logs: «${value}»"; return 0 ;; esac
        ;;
      deploy_agent_updates | monitor_agent_updates)
        if ! host_policy_updates "$value"; then host_policy_close "${key}: «${value}»"; return 0; fi
        if [[ "$key" == deploy_agent_updates ]]; then deploy_updates="$POLICY_VALUE"; else monitor_updates="$POLICY_VALUE"; fi
        ;;
      commands)
        have_commands=1
        rest="${value},"
        while [[ -n "$rest" ]]; do
          item="${rest%%,*}" rest="${rest#*,}"
          item="${item#"${item%%[!$' \t']*}"}"
          item="${item%"${item##*[!$' \t']}"}"
          [[ -n "$item" ]] || continue
          case "$item" in
            apply | backup | restore | export | migrate-data | start-stack | stop-stack | inventory) ;;
            *) host_policy_close "незнакомый вид команды «${item}»"; return 0 ;;
          esac
          commands="${commands} ${item} "
        done
        ;;
    esac
  done <"$path"

  if [[ "$version" != "1" ]]; then host_policy_close "нет version=1"; return 0; fi
  # Нет ключа — самое строгое значение. Исключение одно: mode=deploy без
  # commands — все виды; mode=deploy и есть явное включение исполнения.
  POLICY_MODE="${mode:-observe}"
  if [[ "$have_commands" -eq 0 && "$POLICY_MODE" == deploy ]]; then commands=" ${HOST_POLICY_COMMAND_KINDS} "; fi
  for kind in $HOST_POLICY_COMMAND_KINDS; do
    if [[ "$commands" == *" ${kind} "* ]]; then POLICY_COMMANDS="${POLICY_COMMANDS:+${POLICY_COMMANDS},}${kind}"; fi
  done
  # Этому агенту не нужен, но разбор отдаёт его целиком: по нему фикстура
  # сверяет, что файл понят так же, как агентом развёртывания.
  # shellcheck disable=SC2034
  POLICY_DEPLOY_UPDATES="${deploy_updates:-manual}"
  POLICY_MONITOR_UPDATES="${monitor_updates:-manual}"
  POLICY_CONTAINER_LOGS="${logs:-deny}"
  POLICY_STATE="valid"
  return 0
}
# <<< HOST_POLICY_PARSER

# >>> POLICY_FLAGS_BLOCK (границы использует installScript.test.ts — не переименовывать)
# Политика сервера: флаги --mode, --updates, --commands (ADR-0095, п. 1 и 7).
#
# ЗАЧЕМ ФАЙЛ, А НЕ НАСТРОЙКА В ИНТЕРФЕЙСЕ. Режим наблюдения, список разрешённых
# команд и запрет самообновления живут в файле root на сервере: настройку в
# базе платформы взломанная платформа переключила бы сама. Файл меняет только
# человек с root — руками или этой командой.
#
# Без --mode (решение владельца 23.09.2026, ADR-0095, «Режим новых установок»):
#   • НОВЫЙ сервер (личности агента ещё нет) получает mode=observe: команда в
#     интерфейсе всегда несёт --mode, а без него пришла команда из старой
#     инструкции — и исполнение на чужом сервере не включается само;
#   • ПОДКЛЮЧЁННЫЙ сервер файл не получает и не меняет: повторный запуск
#     команды — это обновление агента, а не смена политики. Записать observe
#     там, где файла нет, значило бы молча перевести работающий сервер из
#     исполнения в наблюдение;
#   • прежний файл — годный или негодный — не трогается: его писал владелец.
POLICY_FILE="${POLICY_FILE:-/etc/tracedocs/agent-policy.conf}"
POLICY_FLAG_MODE="" POLICY_FLAG_UPDATES="" POLICY_FLAG_COMMANDS=""
POLICY_HAVE_MODE=0 POLICY_HAVE_UPDATES=0 POLICY_HAVE_COMMANDS=0
POLICY_NEW_TEXT="" POLICY_BEFORE="" POLICY_AFTER="" POLICY_NOTE=""

policy_usage() {
  cat <<'USAGE'
Флаги политики сервера (файл /etc/tracedocs/agent-policy.conf):
  --mode observe|deploy        observe — только наблюдение, deploy — исполнение команд
  --commands a,b               разрешённые виды: apply, backup, restore, export,
                               migrate-data, start-stack, stop-stack, inventory
  --updates manual|no_major|auto|"pinned X.Y.Z"
                               самообновление агента развёртывания; без флага —
                               manual
--commands и --updates — только вместе с --mode. Без --mode: новый сервер —
observe, у подключённого файл не меняется.
USAGE
}

set_policy_flag() {
  local name="$1" value="$2"
  case "$name" in
    --mode)
      if [[ "$POLICY_HAVE_MODE" -eq 1 ]]; then echo "--mode указан дважды" >&2; exit 1; fi
      POLICY_FLAG_MODE="$value" POLICY_HAVE_MODE=1
      ;;
    --updates)
      if [[ "$POLICY_HAVE_UPDATES" -eq 1 ]]; then echo "--updates указан дважды" >&2; exit 1; fi
      POLICY_FLAG_UPDATES="$value" POLICY_HAVE_UPDATES=1
      ;;
    --commands)
      if [[ "$POLICY_HAVE_COMMANDS" -eq 1 ]]; then echo "--commands указан дважды" >&2; exit 1; fi
      POLICY_FLAG_COMMANDS="$value" POLICY_HAVE_COMMANDS=1
      ;;
  esac
}

parse_policy_flags() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode | --updates | --commands)
        if [[ $# -lt 2 ]]; then echo "${1}: нет значения" >&2; exit 1; fi
        set_policy_flag "$1" "$2"
        shift 2
        ;;
      --mode=* | --updates=* | --commands=*)
        set_policy_flag "${1%%=*}" "${1#*=}"
        shift
        ;;
      -h | --help)
        policy_usage
        exit 0
        ;;
      *)
        echo "Неизвестный аргумент: ${1}" >&2
        policy_usage >&2
        exit 1
        ;;
    esac
  done
}

# Действующая политика одной строкой — для «было → стало».
describe_host_policy() {
  if [[ "$POLICY_STATE" == absent ]]; then
    echo "политики нет — агенты ведут себя по-прежнему"
    return 0
  fi
  echo "режим ${POLICY_MODE}; команды: ${POLICY_COMMANDS:-нет}; обновления агента развёртывания: ${POLICY_DEPLOY_UPDATES}, агента мониторинга: ${POLICY_MONITOR_UPDATES}; логи контейнеров: ${POLICY_CONTAINER_LOGS}"
}

# Что писать — решается и проверяется ДО любых изменений на хосте: отказ
# посреди установки оставил бы сервер наполовину подключённым.
plan_host_policy() {
  local candidate
  if [[ "$POLICY_HAVE_MODE" -eq 0 ]]; then
    if [[ "$POLICY_HAVE_UPDATES" -eq 1 || "$POLICY_HAVE_COMMANDS" -eq 1 ]]; then
      echo "--updates и --commands меняют политику сервера — только вместе с --mode observe|deploy." >&2
      exit 1
    fi
    read_host_policy "$POLICY_FILE"
    case "$POLICY_STATE" in
      valid) return 0 ;;
      invalid)
        echo "Файл политики ${POLICY_FILE} негоден: ${POLICY_ERROR}. Агенты закрыли всё; установка файл не трогает." >&2
        return 0
        ;;
    esac
    if [[ -f "$STATE_DIR/identity.json" ]]; then
      POLICY_NOTE="политика не задана — прежнее поведение; задать: --mode observe|deploy"
      return 0
    fi
    POLICY_FLAG_MODE="observe" POLICY_HAVE_MODE=1
  fi
  case "$POLICY_FLAG_MODE" in
    observe | deploy) ;;
    *)
      echo "--mode: «${POLICY_FLAG_MODE}» — ожидается observe или deploy" >&2
      exit 1
      ;;
  esac
  # Значения уходят в файл строками «ключ=значение»: перевод строки или #
  # внутри флага дописал бы в файл ключ, которого человек не задавал.
  local commands_re='^[a-z, -]*$'
  if [[ ! "$POLICY_FLAG_COMMANDS" =~ $commands_re ]]; then
    echo "--commands: «${POLICY_FLAG_COMMANDS}» — ожидаются виды через запятую" >&2
    exit 1
  fi
  if [[ "$POLICY_HAVE_UPDATES" -eq 1 ]]; then
    if ! host_policy_updates "$POLICY_FLAG_UPDATES"; then
      echo "--updates: «${POLICY_FLAG_UPDATES}» — ожидается manual, no_major, auto или \"pinned X.Y.Z\"" >&2
      exit 1
    fi
    POLICY_FLAG_UPDATES="$POLICY_VALUE"
  fi

  read_host_policy "$POLICY_FILE"
  if [[ "$POLICY_STATE" == invalid ]]; then
    echo "Файл политики ${POLICY_FILE} негоден: ${POLICY_ERROR}." >&2
    echo "Установка его не перезаписывает: исправьте или удалите файл руками и повторите." >&2
    exit 1
  fi
  POLICY_BEFORE="$(describe_host_policy)"

  # Ключи агента развёртывания задаются флагами ЦЕЛИКОМ: прежний
  # commands=inventory, оставшийся от наблюдения, при переходе в deploy
  # включил бы исполнение и тут же ничего не разрешил. Ключи агента
  # мониторинга — не его: они переносятся из прежнего файла, иначе
  # переустановка агента развёртывания молча выключала бы логи контейнеров.
  POLICY_NEW_TEXT="# Политика сервера для агентов Scopework (ADR-0095). Пишется командой установки с --mode; править можно и руками.
version=1
mode=${POLICY_FLAG_MODE}
"
  if [[ "$POLICY_HAVE_COMMANDS" -eq 1 ]]; then
    POLICY_NEW_TEXT+="commands=${POLICY_FLAG_COMMANDS}
"
  fi
  if [[ "$POLICY_HAVE_UPDATES" -eq 1 ]]; then
    POLICY_NEW_TEXT+="deploy_agent_updates=${POLICY_FLAG_UPDATES}
"
  fi
  if [[ "$POLICY_STATE" == valid ]]; then
    POLICY_NEW_TEXT+="monitor_agent_updates=${POLICY_MONITOR_UPDATES}
container_logs=${POLICY_CONTAINER_LOGS}
"
  fi

  # Итог проверяется тем же разбором, которым его прочтут агенты.
  candidate="$(mktemp -t scopework-agent-policy.XXXXXX)"
  printf '%s' "$POLICY_NEW_TEXT" >"$candidate"
  read_host_policy "$candidate"
  rm -f "$candidate"
  if [[ "$POLICY_STATE" != valid ]]; then
    echo "Политика из флагов негодна: ${POLICY_ERROR}." >&2
    exit 1
  fi
  POLICY_AFTER="$(describe_host_policy)"
}

# Запись атомарно: агенты перечитывают файл каждый такт, и половина файла
# между open и write для них — негодный файл, то есть «закрыто всё».
write_host_policy() {
  local dir tmp
  if [[ -z "$POLICY_NEW_TEXT" ]]; then
    if [[ -n "$POLICY_NOTE" ]]; then echo "· ${POLICY_NOTE}"; fi
    return 0
  fi
  dir="$(dirname "$POLICY_FILE")"
  # Каталог — root 0755: агент проверяет права и файла, и каталога, и
  # доступный на запись каталог делает политику незащищённой.
  mkdir -p "$dir"
  chown root:root "$dir"
  chmod 0755 "$dir"
  tmp="$(mktemp "${dir}/.agent-policy.XXXXXX")"
  printf '%s' "$POLICY_NEW_TEXT" >"$tmp"
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$POLICY_FILE"
  echo "· политика сервера ${POLICY_FILE}"
  echo "  было:  ${POLICY_BEFORE}"
  echo "  стало: ${POLICY_AFTER}"
}
# <<< POLICY_FLAGS_BLOCK

# >>> AGENT_LOCAL_BLOCK (границы использует installScript.test.ts — не переименовывать)
# Локальный журнал команд и отпечатки ключей (ADR-0095, п. 9 и 11).
JOURNAL_PATH="$STATE_DIR/journal.log"

# Атрибут «только дописывание» снимается перед сменой владельца каталога
# состояния: ядро не даёт менять владельца и права файла с +a (EPERM), и
# повторная установка под set -e упала бы на рекурсивном chown.
journal_unseal() {
  if [[ -f "$JOURNAL_PATH" && ! -L "$JOURNAL_PATH" ]] && command -v chattr >/dev/null 2>&1; then
    chattr -a "$JOURNAL_PATH" 2>/dev/null || true
  fi
}

# Журнал пишет агент от своего пользователя, дописыванием. Атрибут +a снять
# может только root: переписать или удалить прежние строки агент не может,
# даже если его подменили.
journal_seal() {
  local owner="$1"
  # Каталог состояния принадлежит пользователю агента: на месте журнала может
  # оказаться ссылка, и chown/chattr от root по ней отдали бы агенту чужой файл.
  if [[ -L "$JOURNAL_PATH" ]] || [[ -e "$JOURNAL_PATH" && ! -f "$JOURNAL_PATH" ]]; then
    echo "  ВНИМАНИЕ: ${JOURNAL_PATH} — не обычный файл; журнал команд не настроен, разберитесь руками." >&2
    return 0
  fi
  # Существующий журнал не усекается и не пересоздаётся: его цепочка и есть
  # то, что проверяет `scopework-agent journal verify`.
  if [[ ! -e "$JOURNAL_PATH" ]]; then
    (umask 077 && : >>"$JOURNAL_PATH")
  fi
  chown -h "${owner}:${owner}" "$JOURNAL_PATH"
  chmod 0600 "$JOURNAL_PATH"
  if command -v chattr >/dev/null 2>&1 && chattr +a "$JOURNAL_PATH" 2>/dev/null; then
    echo "· журнал команд ${JOURNAL_PATH}: только дописывание (chattr +a)"
  else
    echo "· журнал команд ${JOURNAL_PATH}: атрибут «только дописывание» на этой файловой системе не ставится — файл защищён только правами"
  fi
}

# Отпечатки вшитых ключей — чтобы человек сверил их с опубликованными:
# установка доверяет тому, кто отдал этот скрипт, и сверка — единственный
# способ это доверие проверить.
print_agent_trust() {
  local out line version="" release="" roots="" have_roots=0
  if ! out="$("$1" version --trust 2>/dev/null)"; then
    echo "  отпечатки ключей: бинарь не ответил на version --trust"
    return 0
  fi
  while IFS= read -r line; do
    case "$line" in
      version=*) version="${line#version=}" ;;
      release_keys=*) release="${line#release_keys=}" ;;
      state_roots=*) roots="${line#state_roots=}" have_roots=1 ;;
    esac
  done <<<"$out"
  if [[ -z "$version" ]]; then
    echo "  отпечатки ключей: эта версия агента отпечатков не выводит"
    return 0
  fi
  echo "  версия агента: ${version}"
  if [[ -n "$release" ]]; then
    echo "  ключи выпуска: ${release//,/, } — сверьте с опубликованными"
  else
    echo "  ключ выпуска не вшит — подпись обновлений агента не проверяется"
  fi
  # Строку state_roots выводят только сборки с проверкой подписи состояния;
  # без строки молчим, а не говорим «корней нет» — это было бы утверждение.
  if [[ -n "$roots" ]]; then
    echo "  корни подписи состояния: ${roots//,/, }"
  elif [[ "$have_roots" -eq 1 ]]; then
    echo "  корней подписи состояния нет"
  fi
}
# <<< AGENT_LOCAL_BLOCK

# Политика проверяется раньше всего остального, даже раньше чтения токена:
# ошибка в флаге должна остановить установку до первого изменения на хосте.
parse_policy_flags "$@"
plan_host_policy

: "${TRACEDOCS_URL:?нужен TRACEDOCS_URL}"
ACME_EMAIL="${ACME_EMAIL:-}"

# Токен установки читаем из stdin ОДИН РАЗ и здесь, в самом начале.
#
# Аргументом его передавать нельзя: аргументы видны в /proc/<pid>/cmdline и в
# выводе `ps` любому пользователю хоста, включая контейнеры с pid: host.
#
# А читать его позже, прямо перед регистрацией, нельзя по другой причине: между
# началом скрипта и регистрацией выполняются apt-get, curl и docker, и любая из
# этих команд может вычитать stdin — тогда агенту достанется пустая строка, а
# сообщение об ошибке будет говорить совсем не о том.
#
# Переменную намеренно НЕ экспортируем: экспортированная попала бы в окружение
# каждого дочернего процесса и читалась бы через /proc/<pid>/environ.
if [[ -z "${TRACEDOCS_TOKEN:-}" ]]; then
  if [[ -t 0 ]]; then
    echo "Нужен токен установки: передайте его в stdin." >&2
    echo "Команду целиком возьмите в Scopework: раздел «Развёртывание» → «Серверы»." >&2
    exit 1
  fi
  # Ограничиваем чтение: stdin — недоверенный вход. Пробелы и перевод строки
  # срезаем, потому что токен их не содержит, а при копировании прилипают.
  TRACEDOCS_TOKEN="$(head -c 4096 | tr -d '[:space:]')"
fi

if [[ -z "$TRACEDOCS_TOKEN" ]]; then
  echo "Токен установки пуст." >&2
  exit 1
fi

# Где искать бинарь агента.
#
# BASH_SOURCE существует, только когда скрипт запущен КАК ФАЙЛ. Штатный способ
# установки — `bash -c "$(curl …)"`, там кода в файле нет, переменная не
# определена, и под `set -u` обращение к ней роняет установку раньше первого
# осмысленного действия.
#
# Когда файла нет, «рядом со скриптом» не существует как место — значит бинарь
# надо скачать, и пустой AGENT_SRC ниже включает именно эту ветку.
if [[ -z "${AGENT_SRC:-}" ]]; then
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    AGENT_SRC="$(dirname "${BASH_SOURCE[0]}")/deploy-agent"
  else
    AGENT_SRC=""
  fi
fi

if [[ $EUID -ne 0 ]]; then
  echo "Нужны права root: агент ставится в /usr/local/bin и в systemd." >&2
  exit 1
fi

# Политика — первым изменением на хосте: агент, поднятый ниже, не должен ни
# одного такта проработать без неё.
write_host_policy

# ---------------------------------------------------------------------------
# Подготовка хоста: часы
#
# Подпись агентских запросов несёт метку времени, и платформа отвергает метку,
# ушедшую вперёд. У свежего VPS часы уезжают на десяток секунд, и до этой
# проверки происходило вот что: `enroll` подписи не несёт и проходил, хост
# становился «active», а первый же подписанный запрос получал отказ. Пять
# отказов подряд — и агент выходил с кодом 3, который systemd не
# перезапускает. Хост в панели навсегда оставался «active» и молчал.
#
# Ставим синхронизацию сами, как и Docker: «подключите сервер» не должно
# превращаться в список требований к хосту.
# ---------------------------------------------------------------------------
ensure_time_sync() {
  if command -v timedatectl >/dev/null 2>&1; then
    if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi '^yes$'; then
      echo "Часы синхронизированы."
      return 0
    fi
  fi

  # Свой демон синхронизации на хосте уже есть — не трогаем.
  #
  # chrony конфликтует с systemd-timesyncd, и apt при установке второго удалит
  # первый. Попасть сюда легко: сразу после перезагрузки chrony ещё не
  # синхронизировался, NTPSynchronized=no, и без этой проверки установщик снёс
  # бы рабочий демон ради своего.
  for unit in chrony chronyd ntp ntpsec openntpd systemd-timesyncd; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
      echo "Синхронизация времени уже обслуживается службой $unit."
      return 0
    fi
  done

  echo "Часы не синхронизированы — включаю синхронизацию времени."
  if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd'; then
    systemctl enable --now systemd-timesyncd 2>/dev/null || true
  elif command -v apt-get >/dev/null 2>&1; then
    apt-get install -y systemd-timesyncd >/dev/null 2>&1 || true
    systemctl enable --now systemd-timesyncd 2>/dev/null || true
  fi
  timedatectl set-ntp true 2>/dev/null || true

  # Не блокируем установку: часы могут синхронизироваться и через минуту, а
  # отказать в подключении сервера из-за этого — несоразмерно. Но сказать
  # обязаны: если агент потом упрётся в расхождение, причина будет уже названа.
  if command -v timedatectl >/dev/null 2>&1 &&
     ! timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -qi '^yes$'; then
    echo "ВНИМАНИЕ: синхронизация времени не включилась. Если агент сообщит о" >&2
    echo "расхождении часов, настройте NTP (systemd-timesyncd или chrony) вручную." >&2
  fi
}

ensure_time_sync

# ---------------------------------------------------------------------------
# Подготовка хоста: Docker
#
# Ставим сами, а не требуем от пользователя. «Подключите сервер» не должно
# превращаться в инструкцию из десяти шагов — подготовка хоста это работа
# платформы.
#
# Ставим из ОФИЦИАЛЬНОГО репозитория Docker с проверкой подписи пакетов, а не
# через `curl https://get.docker.com | sh`. Разница принципиальная: скачанный
# скрипт выполняется с правами root и его содержимое никем не проверяется, а
# пакеты из репозитория подписаны ключом, который мы фиксируем сами. Тот же
# принцип, по которому мы не даём серверу выполнять произвольные команды.
# ---------------------------------------------------------------------------
# Зеркало реестра образов.
#
# Docker Hub ограничивает анонимные загрузки: 100 запросов в час, причём лимит
# считается не на адрес сервера, а на подсеть провайдера — соседи по хостингу
# выбирают квоту за вас. На первом же прогоне это дало отказ `429 Too Many
# Requests` при загрузке обычного caddy:2.8-alpine, то есть платформа не смогла
# бы поднять даже собственный прокси.
#
# mirror.gcr.io — публичное зеркало Google для официальных образов Docker Hub,
# без такого лимита. Настраивается один раз при подготовке хоста; если у
# пользователя уже есть свой daemon.json, не трогаем его.
#
# ПЕРЕЗАПУСК ДЕМОНА НА ЖИВОМ ХОСТЕ ЗАПРЕЩЁН.
#
# Настройка применяется рестартом docker, а рестарт демона с дефолтным
# live-restore останавливает ВСЕ контейнеры хоста. На пустом сервере это
# ничего не стоит; на сервере, куда платформу подключают к уже работающим
# нагрузкам, это незапланированный простой всего, что там крутится, — в момент,
# который человек считает «просто подключаю сервер».
#
# Поэтому: есть чужие работающие контейнеры — пишем конфиг, но НЕ перезапускаем
# и говорим, что настройка вступит в силу при следующем плановом рестарте.
# Зеркало нужно, чтобы платформа могла тянуть образы; работающему хосту оно не
# нужно прямо сейчас — он свои образы уже скачал.
configure_registry_mirror() {
  local cfg=/etc/docker/daemon.json

  if [[ -f "$cfg" ]]; then
    # Чужой daemon.json не редактируем: он мог быть написан под нагрузку хоста
    # (логи, сети, ulimits), и слить его вслепую без jq — верный способ
    # сломать демон, который сейчас работает.
    #
    # Но и молчать нельзя: это ровно тот сервер, ради которого платформу и
    # подключают, и на нём лимит Docker Hub остаётся в силе. Если зеркала в
    # конфиге нет, ставим отметку — агент допишет причину в текст отказа,
    # когда загрузка образа в него упрётся.
    # Спрашиваем ДЕМОН, а не файл. `grep registry-mirrors` считает настроенным
    # и пустой список `"registry-mirrors": []`, и ключ, дописанный без
    # перезапуска: отметка снималась бы, а подсказка про лимит Docker Hub не
    # появлялась бы никогда — при том что зеркала фактически нет.
    local mirrors=""
    if command -v docker >/dev/null; then
      mirrors="$(docker info --format '{{.RegistryConfig.Mirrors}}' 2>/dev/null || true)"
    fi
    if [[ -n "$mirrors" && "$mirrors" != "[]" ]]; then
      echo "  зеркало реестра уже действует — daemon.json не трогаю"
      rm -f "$STATE_DIR/registry-mirror-pending" 2>/dev/null || true
    else
      mkdir -p "$STATE_DIR" 2>/dev/null || true
      : > "$STATE_DIR/registry-mirror-pending" 2>/dev/null || true
      echo "  daemon.json уже существует — зеркало реестра не настраиваю."
      echo "  Docker Hub ограничивает анонимные загрузки на подсеть провайдера;"
      echo "  если выкат упрётся в лимит, добавьте в $cfg:"
      echo '    "registry-mirrors": ["https://mirror.gcr.io"]'
      echo "  и перезапустите Docker в удобное окно обслуживания."
    fi
    return 0
  fi

  # Чужие работающие контейнеры: всё, что уже поднято на этом хосте. Своих у
  # нас здесь ещё нет по определению — агент только ставится.
  local running=0
  if command -v docker >/dev/null; then
    running="$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"
  fi

  mkdir -p /etc/docker
  cat > "$cfg" <<'JSON'
{
  "registry-mirrors": ["https://mirror.gcr.io"]
}
JSON

  if [[ "$running" -gt 0 ]]; then
    # Отметка для агента: он допишет причину в текст отказа, когда загрузка
    # образа упрётся в лимит Docker Hub. Без неё человек видит сырое
    # `toomanyrequests` и ищет проблему в своём приложении, тогда как лечится
    # это одной командой на хосте.
    mkdir -p "$STATE_DIR" 2>/dev/null || true
    : > "$STATE_DIR/registry-mirror-pending" 2>/dev/null || true

    echo "  зеркало реестра записано, но Docker НЕ перезапущен: на хосте работают"
    echo "  $running контейнер(ов), а рестарт демона остановил бы их все."
    echo "  Настройка вступит в силу при следующем плановом перезапуске Docker."
    echo "  Применить сразу (это остановит все контейнеры): systemctl restart docker"
    return 0
  fi

  echo "  ВНИМАНИЕ: меняю настройку Docker на всём хосте — через зеркало"
  echo "  mirror.gcr.io пойдут и ваши собственные образы (обход лимита Docker"
  echo "  Hub). Отключить: ENABLE_REGISTRY_MIRROR=0"
  systemctl restart docker
  rm -f "$STATE_DIR/registry-mirror-pending" 2>/dev/null || true
  echo "  зеркало реестра: mirror.gcr.io"
}

ensure_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    echo "· Docker уже установлен: $(docker --version | cut -d, -f1)"
    return 0
  fi

  if ! command -v apt-get >/dev/null; then
    echo "Docker не установлен, а автоматическая установка поддержана только для" >&2
    echo "систем с apt (Debian, Ubuntu). Установите Docker вручную и повторите." >&2
    exit 1
  fi

  # Docker есть, нет только плагина compose.
  #
  # Полная установка здесь означала бы `apt-get install docker-ce`, то есть
  # ОБНОВЛЕНИЕ работающего демона и его перезапуск — со всеми контейнерами
  # хоста. Ставим ровно недостающее и демон не трогаем.
  if command -v docker >/dev/null; then
    echo "· Docker есть, не хватает плагина compose — ставлю только его"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    if apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 &&
      docker compose version >/dev/null 2>&1; then
      echo "  установлено: $(docker compose version --short)"
      return 0
    fi
    echo "Плагин docker compose поставить не удалось, а обновлять сам Docker на" >&2
    echo "работающем хосте установщик не станет: это перезапуск демона и простой" >&2
    echo "всех контейнеров. Поставьте docker-compose-plugin вручную и повторите." >&2
    exit 1
  fi

  echo "· Docker не найден, устанавливаю из официального репозитория"

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg >/dev/null

  # Ключ репозитория храним в отдельном файле и привязываем к нему источник:
  # без signed-by ключ доверялся бы всем репозиториям системы.
  install -m 0755 -d /etc/apt/keyrings
  local distro
  distro="$(. /etc/os-release && echo "$ID")"
  case "$distro" in
    ubuntu|debian) ;;
    *)
      echo "Неподдерживаемый дистрибутив: $distro. Установите Docker вручную." >&2
      exit 1
      ;;
  esac

  curl -fsSL "https://download.docker.com/linux/$distro/gpg" \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  # Ключ ЗАКРЕПЛЁН отпечатком, а не принят на веру.
  #
  # Без этой проверки доверие держалось бы только на TLS до download.docker.com:
  # кто способен его подменить — чужой корневой сертификат в хранилище хоста,
  # враждебный прокси или резолвер в сети клиента — подставил бы свой ключ и
  # свои пакеты и получил root. А вместе с root — приватный ключ агента, пароль
  # базы и токены реестров.
  #
  # Отпечаток официального ключа Docker (docker.com/linux). Меняется он раз в
  # много лет; несовпадение — повод остановиться, а не подогнать константу.
  local expect_fpr=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
  local got_fpr
  got_fpr="$(gpg --show-keys --with-colons /etc/apt/keyrings/docker.asc \
    | awk -F: '/^fpr:/{print $10; exit}')"
  if [[ "$got_fpr" != "$expect_fpr" ]]; then
    echo "Отпечаток GPG-ключа Docker не совпал." >&2
    echo "  получено:  ${got_fpr:-<пусто>}" >&2
    echo "  ожидалось: $expect_fpr" >&2
    echo "Установка остановлена: подменённый ключ означает подменённые пакеты." >&2
    rm -f /etc/apt/keyrings/docker.asc
    exit 1
  fi

  local codename
  codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$distro $codename stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y -qq \
    docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null

  systemctl enable --now docker

  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker установлен, но плагин compose недоступен." >&2
    exit 1
  fi

  echo "  установлено: $(docker --version | cut -d, -f1), $(docker compose version --short)"
}

ensure_docker

# git нужен приложениям, которые собираются из репозитория. Ставим заранее, а
# не при первом выкате: иначе первое же такое приложение падало бы с «git: not
# found», и разбираться пришлось бы уже по журналу агента.
ensure_git() {
  if command -v git >/dev/null; then
    return 0
  fi
  if ! command -v apt-get >/dev/null; then
    echo "· git не найден, а поставить автоматически нечем — приложения из"
    echo "  репозитория работать не будут. Установите git вручную."
    return 0
  fi
  echo "· установка git"
  # Неудача здесь не повод рушить установку: под `set -e` любой отказ apt
  # (устаревшие списки пакетов, недоступное зеркало) оборвал бы скрипт ПОСЛЕ
  # подготовки docker и ДО регистрации — сервер остался бы наполовину
  # подключённым. Без git не работают только приложения из репозитория.
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || true
  if ! apt-get install -y -qq git >/dev/null 2>&1; then
    echo "  git поставить не удалось — приложения из репозитория работать не будут"
  fi
}

ensure_git

# Зеркало настраиваем ОТДЕЛЬНО от установки Docker.
#
# Раньше вызов стоял внутри ensure_docker, а та выходит раньше, если Docker уже
# стоит. То есть на хосте с готовым Docker — а это большинство повторных
# подключений — проблема 429, ради которой всё затевалось, не решалась вовсе.
[[ "${ENABLE_REGISTRY_MIRROR:-1}" == "1" ]] && configure_registry_mirror

# Бинаря рядом нет — значит скрипт запущен через curl, и агента надо скачать.
#
# Берём его с той же платформы, к которой подключаемся: другого доверенного
# источника у нас нет, а адрес и так проверен требованием https в самом агенте.
if [[ ! -f "$AGENT_SRC" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) AGENT_ARCH=amd64 ;;
    aarch64|arm64) AGENT_ARCH=arm64 ;;
    *)
      echo "Неподдерживаемая архитектура: $(uname -m). Поддержаны x86_64 и arm64." >&2
      exit 1
      ;;
  esac

  echo "· загрузка агента ($AGENT_ARCH)"
  AGENT_SRC="$(mktemp -t tracedocs-deploy-agent.XXXXXX)"
  # Временный файл удаляем в любом случае: бинарь уже установлен в BIN_PATH,
  # а копия в /tmp никому не нужна.
  trap 'rm -f "$AGENT_SRC"' EXIT

  if ! curl -fsSL "${TRACEDOCS_URL%/}/api/deploy/agent-binary?arch=$AGENT_ARCH" -o "$AGENT_SRC"; then
    echo "Не удалось загрузить агента с ${TRACEDOCS_URL%/}." >&2
    echo "Проверьте, что сервер имеет доступ в интернет, и повторите." >&2
    exit 1
  fi
fi

if [[ ! -s "$AGENT_SRC" ]]; then
  echo "Бинарь агента пуст или не найден: $AGENT_SRC" >&2
  exit 1
fi

# Контрольная сумма бинаря, если её передали.
#
# Бинарь приезжает на хост по сети, а ставится с правами root и получает доступ
# к docker.sock — то есть к машине целиком. Проверка обязательна, когда сумма
# известна; интерфейс показывает её рядом с командой установки.
#
# Сумма выбирается ПО АРХИТЕКТУРЕ: бинарь качается по uname -m этого сервера,
# и одна общая сумма (посчитанная платформой для amd64) гарантированно роняла
# установку на arm64. AGENT_SHA256 без суффикса оставлен как явное
# переопределение и для старых скопированных команд.
EXPECTED_AGENT_SHA="${AGENT_SHA256:-}"
if [[ -z "$EXPECTED_AGENT_SHA" ]]; then
  case "${AGENT_ARCH:-$(uname -m)}" in
    amd64|x86_64) EXPECTED_AGENT_SHA="${AGENT_SHA256_AMD64:-}" ;;
    arm64|aarch64) EXPECTED_AGENT_SHA="${AGENT_SHA256_ARM64:-}" ;;
  esac
fi

if [[ -n "$EXPECTED_AGENT_SHA" ]]; then
  echo "· проверка контрольной суммы бинаря"
  actual_sha="$(sha256sum "$AGENT_SRC" | awk '{print $1}')"
  if [[ "$actual_sha" != "$EXPECTED_AGENT_SHA" ]]; then
    echo "Контрольная сумма бинаря агента не совпала." >&2
    echo "  получено:  $actual_sha" >&2
    echo "  ожидалось: $EXPECTED_AGENT_SHA" >&2
    exit 1
  fi
fi

echo "· установка бинаря"
install -m 0755 "$AGENT_SRC" "$BIN_PATH"

# `scopework-agent journal verify` — проверка журнала команд на сервере.
# Ссылка ведёт на бинарь root в /usr/local/bin: его агент не обновляет и
# переписать не может, так что журнал проверяет не тот, кого проверяют.
ln -sfn "$BIN_PATH" "$(dirname "$BIN_PATH")/scopework-agent"
print_agent_trust "$BIN_PATH"

# Каталог состояния держит приватный ключ — доступ только root.
install -d -m 0700 "$STATE_DIR"
install -d -m 0750 "$WORK_DIR"

# Личность на диске ещё не значит, что платформа её признаёт.
#
# Раньше здесь стояла проверка «файл есть — регистрацию пропускаю», и на
# сервере с ОТОЗВАННОЙ личностью установка молча не делала ничего: агент
# поднимался со старым ключом, немедленно получал отказ и умирал, а в панели
# сервер вечно висел в «ожидает установки». Ни одной подсказки о причине.
#
# Теперь спрашиваем саму платформу. Перерегистрируем только при явном отказе:
# «проверить не удалось» (лежит платформа, нет сети) — не повод выбрасывать
# ключ работающего сервера.
if [[ -f "$STATE_DIR/identity.json" ]]; then
  echo "· сервер уже подключён, проверяю ключ"
  set +e
  "$BIN_PATH" verify --url="$TRACEDOCS_URL" --dir="$STATE_DIR" >/dev/null 2>&1
  verify_code=$?
  set -e

  case "$verify_code" in
    0)
      echo "  ключ признан, регистрацию пропускаю"
      ;;
    3)
      echo "  платформа не признаёт прежний ключ — регистрирую заново"
      printf '%s' "$TRACEDOCS_TOKEN" | "$BIN_PATH" enroll --url="$TRACEDOCS_URL" --dir="$STATE_DIR" --force
      ;;
    *)
      echo "  проверить ключ не удалось (платформа недоступна?) — оставляю прежний" >&2
      echo "  Если сервер подключается впервые, повторите установку, когда платформа ответит." >&2
      ;;
  esac
else
  echo "· регистрация сервера"
  # Токен идёт через stdin, а не аргументом.
  #
  # Аргументы командной строки видны в /proc/<pid>/cmdline и в выводе `ps`
  # ЛЮБОМУ пользователю хоста, включая контейнеры с pid: host. Перехвативший
  # одноразовый токен регистрирует собственного агента со своим ключом и по
  # подписанным запросам получает всё желаемое состояние проекта: пароль базы,
  # ключ шифрования, токены реестров. Заодно ломает установку настоящему
  # администратору — токен одноразовый.
  #
  # Повтор безопасен и доводит дело до конца. Ключ пишется на диск ДО
  # отправки, а платформа (0228) узнаёт незавершённый заход по тройке
  # «токен + ключ + отпечаток» и отвечает тем же успехом. До этого потерянный
  # ответ означал сожжённый токен и хост, который приходилось создавать
  # заново, — поэтому подсказку печатаем явно, а не рассчитываем, что человек
  # догадается попробовать ещё раз.
  set +e
  printf '%s' "$TRACEDOCS_TOKEN" | "$BIN_PATH" enroll --url="$TRACEDOCS_URL" --dir="$STATE_DIR"
  enroll_code=$?
  set -e
  if (( enroll_code != 0 )); then
    echo "  Повторите ту же команду установки — она продолжит с того же места." >&2
    exit "$enroll_code"
  fi
fi

# Токен отработал и больше не нужен. Переменная наследуется дочерними
# процессами и попадает в дампы — держать её дольше незачем.
unset TRACEDOCS_TOKEN

# Значения уезжают в unit-файл без кавычек — так требует синтаксис ExecStart.
# Значит, перевод строки внутри любого из них внедрил бы произвольные
# директивы systemd. Сегодня их задаёт тот, кто и так root, но команда
# установки однажды может начать рендериться не полностью из наших данных.
BIN_DIR="$(dirname "$BIN_PATH")"

for var in STATE_DIR WORK_DIR BIN_PATH BIN_DIR AGENT_BIN_DIR AGENT_BIN PROXY_SOCKET; do
  [[ "${!var}" =~ ^/[A-Za-z0-9._/-]+$ ]] || {
    echo "Недопустимое значение $var: ${!var}" >&2; exit 1; }
done
# Имя пользователя тоже уезжает в unit-файл (User=, Group=).
[[ "$AGENT_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || {
  echo "Недопустимое имя пользователя агента: $AGENT_USER" >&2; exit 1; }
[[ "$PRIVILEGE_MODE" =~ ^(proxy|root)$ ]] || {
  echo "Недопустимый PRIVILEGE_MODE: $PRIVILEGE_MODE (ожидается proxy или root)" >&2; exit 1; }
[[ "$TRACEDOCS_URL" =~ ^https?://[A-Za-z0-9._:/-]+$ ]] || {
  echo "Недопустимый TRACEDOCS_URL: $TRACEDOCS_URL" >&2; exit 1; }
[[ "$INTERVAL" =~ ^[0-9]+[smh]$ ]] || {
  echo "Недопустимый INTERVAL: $INTERVAL (ожидается вид 60s)" >&2; exit 1; }

ACME_ARG=""
if [[ -n "$ACME_EMAIL" ]]; then
  [[ "$ACME_EMAIL" =~ ^[^[:space:]@]+@[A-Za-z0-9.-]+$ ]] || {
    echo "Недопустимый ACME_EMAIL: $ACME_EMAIL" >&2; exit 1; }
  ACME_ARG=" --acme-email=$ACME_EMAIL"
fi

# ---------------------------------------------------------------------------
# Пользователь агента и прокси сокета Docker (ADR-0083)
# ---------------------------------------------------------------------------
setup_agent_user() {
  if id -u "$AGENT_USER" >/dev/null 2>&1; then
    return 0
  fi
  if ! command -v useradd >/dev/null; then
    echo "  useradd не найден — остаюсь на прежнем режиме (агент от root)" >&2
    return 1
  fi
  # Системный пользователь без входа и без дома: ему нужно ровно два каталога,
  # и оба задаёт юнит.
  useradd --system --no-create-home --home-dir "$WORK_DIR" \
    --shell /usr/sbin/nologin "$AGENT_USER" >/dev/null 2>&1 || {
    echo "  не удалось завести пользователя $AGENT_USER" >&2
    return 1
  }
  echo "· заведён пользователь $AGENT_USER"
}

# Проверяем прокси ТЕМ ЖЕ способом, которым им будет пользоваться агент.
#
# Проверка «сокет появился» ничего не стоит: сокет создаётся до первого
# запроса, и с неверными правами он тоже есть. Спрашиваем демона от имени
# пользователя агента — это ровно то, что произойдёт через минуту при выкате.
proxy_works() {
  local i
  for i in $(seq 1 50); do
    [[ -S "$PROXY_SOCKET" ]] && break
    sleep 0.2
  done
  [[ -S "$PROXY_SOCKET" ]] || return 1
  su -s /bin/sh "$AGENT_USER" -c \
    "DOCKER_HOST=unix://$PROXY_SOCKET docker version --format '{{.Server.Version}}'" \
    >/dev/null 2>&1
}

install_proxy_unit() {
  local uid gid
  uid="$(id -u "$AGENT_USER")"
  gid="$(id -g "$AGENT_USER")"

  cat > "$PROXY_UNIT_PATH" <<PROXYUNIT
[Unit]
Description=Scopework docker socket proxy
After=docker.service
Requires=docker.service

[Service]
Type=simple
# Привилегированная половина: единственный процесс, который видит сокет
# демона. Белый список вызовов и разбор тела — в самом бинаре.
ExecStart=$BIN_PATH docker-proxy --listen=$PROXY_SOCKET --upstream=/var/run/docker.sock --allow-bind=$WORK_DIR --socket-uid=$uid --socket-gid=$gid
Restart=always
RestartSec=5
RuntimeDirectory=tracedocs
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
PROXYUNIT
}

write_agent_unit() {
  # $1 — режим: proxy или root.
  local mode="$1" proxy_dep_lines="" service_user_lines="" docker_host_line=""
  if [[ "$mode" == "proxy" ]]; then
    # Зависимость от прокси — ключи [Unit], пользователь службы — ключи
    # [Service]. До 23.09.2026 всё лежало в [Unit]: systemd пропускал User= и
    # Group= с «Unknown key name», и агент работал от root на каждом сервере,
    # хотя установщик печатал «работает от tracedocs-agent».
    proxy_dep_lines="Requires=tracedocs-docker-proxy.service
After=tracedocs-docker-proxy.service"
    service_user_lines="User=$AGENT_USER
Group=$(id -gn "$AGENT_USER")"
    docker_host_line="Environment=DOCKER_HOST=unix://$PROXY_SOCKET
Environment=HOME=$WORK_DIR"
  fi

  local exec_bin="$BIN_PATH"
  local rw_paths="$STATE_DIR $WORK_DIR $BIN_DIR"
  if [[ "$mode" == "proxy" ]]; then
    # Самообновление пишет по пути СВОЕГО бинаря, а /usr/local/bin
    # непривилегированному агенту недоступен — иначе каждое обновление
    # отказывало бы с «permission denied», и парк навсегда застрял бы на
    # версии установки.
    exec_bin="$AGENT_BIN"
    rw_paths="$STATE_DIR $WORK_DIR"
  fi

  cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=Scopework deploy agent
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
$proxy_dep_lines

[Service]
Type=simple
$service_user_lines
$docker_host_line
ExecStart=$exec_bin run --url=$TRACEDOCS_URL --dir=$STATE_DIR --work-dir=$WORK_DIR --interval=$INTERVAL$ACME_ARG
Restart=on-failure
RestartSec=15
# Код 3 — хост отозван. Перезапускать бессмысленно: сам собой он не вернётся,
# и цикл перезапусков только зашумит журнал.
RestartPreventExitStatus=3
# Агент управляет docker и пишет в свои каталоги; остальную систему трогать
# ему незачем.
#
# Каталог бинаря — в списке записи намеренно: агент обновляет САМ СЕБЯ, а
# ProtectSystem=full делает /usr только для чтения. Без этой строки
# самообновление отказывает на каждом цикле («read-only file system»), и парк
# агентов навсегда остаётся на версии, с которой его поставили, — при том что
# платформа исправно объявляет новую цель. Обнаружено 2026-08-07 на боевом
# хосте: агент отставал на десяток сборок и молча пытался обновиться каждую
# минуту.
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=$rw_paths

[Install]
WantedBy=multi-user.target
UNIT
}

echo "· systemd-юнит"

ACTUAL_MODE=root
journal_unseal
if [[ "$PRIVILEGE_MODE" == "proxy" ]] && setup_agent_user; then
  install -d -m 0750 -o "$AGENT_USER" -g "$AGENT_USER" "$AGENT_BIN_DIR"
  install -m 0755 -o "$AGENT_USER" -g "$AGENT_USER" "$BIN_PATH" "$AGENT_BIN"

  # Каталоги состояния и работы переходят к агенту.
  #
  # Данные приложений это НЕ затрагивает: стеки платформы держат данные в
  # именованных томах Docker (за этим следит compose-guard), а в рабочем
  # каталоге лежат описания, .env, клоны репозиториев и копии — всё это
  # создаёт и читает сам агент.
  chown -R "$AGENT_USER:$AGENT_USER" "$STATE_DIR" "$WORK_DIR"
  chmod 0700 "$STATE_DIR"

  install_proxy_unit
  systemctl daemon-reload
  systemctl enable tracedocs-docker-proxy.service >/dev/null 2>&1 || true
  systemctl restart tracedocs-docker-proxy.service || true

  if proxy_works; then
    ACTUAL_MODE=proxy
    echo "  агент работает от $AGENT_USER через прокси сокета Docker"
  else
    # Откат — это не «тихо как было»: хост остаётся рабочим, но обещание
    # непривилегированного агента на нём неверно, и человек должен это
    # прочитать здесь, а не узнать из модели угроз.
    echo "  ВНИМАНИЕ: прокси сокета Docker не отвечает — оставляю прежний режим." >&2
    echo "  Агент будет работать ОТ ROOT с прямым доступом к докеру." >&2
    echo "  Журнал прокси: journalctl -u tracedocs-docker-proxy -n 50" >&2
    systemctl disable --now tracedocs-docker-proxy.service >/dev/null 2>&1 || true
    chown -R root:root "$STATE_DIR" "$WORK_DIR"
  fi
fi

# Журнал принадлежит тому, от кого работает агент: он дописывает, root
# закрепляет атрибутом.
journal_owner=root
if [[ "$ACTUAL_MODE" == proxy ]]; then journal_owner="$AGENT_USER"; fi
journal_seal "$journal_owner"

write_agent_unit "$ACTUAL_MODE"

systemctl daemon-reload
# enable + restart, а не `enable --now`.
#
# `--now` на УЖЕ запущенной службе не делает ничего: процесс продолжает
# работать со старого inode и в старом sandbox. Именно поэтому повторный
# запуск команды подключения — который платформа сама и советует, когда
# самообновление упирается в права, — не помогал: новый бинарь лежал на диске,
# новый unit был прочитан, а работала прежняя версия.
systemctl enable tracedocs-deploy.service
systemctl restart tracedocs-deploy.service

echo
echo "Готово. Режим агента: $ACTUAL_MODE"
if [[ "$ACTUAL_MODE" != "proxy" ]]; then
  echo "Агент работает от root — это прежний режим, он root-эквивалентен."
fi
echo "Состояние службы:"
systemctl --no-pager --lines=0 status tracedocs-deploy.service || true
echo
echo "Журнал: journalctl -u tracedocs-deploy -f"
