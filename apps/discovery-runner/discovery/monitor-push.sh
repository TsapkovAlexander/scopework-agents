#!/usr/bin/env bash
# Scopework server monitoring — collect metrics and POST JSON snapshot with HMAC.
# Requires: bash, curl, openssl, awk, df. Optional: docker, jq (jq preferred).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Путь к конфигу переопределяется, чтобы новую версию скрипта можно было
# прогнать вхолостую из временного каталога с боевым config.env (см. смоук-тест
# в самообновлении ниже). Обычный запуск берёт конфиг рядом с собой.
CONFIG_ENV="${TRACEDOCS_CONFIG_ENV:-${DIR}/config.env}"
# shellcheck disable=SC1090,SC1091
source "$CONFIG_ENV"

: "${TRACEDOCS_INGEST_URL:?TRACEDOCS_INGEST_URL required}"
: "${TRACEDOCS_TOKEN:?TRACEDOCS_TOKEN required}"

HOST_ID="${TRACEDOCS_HOST_ID:-$(hostname -s 2>/dev/null || hostname || echo unknown)}"
STATE_DIR="${DIR}/state"
mkdir -p "$STATE_DIR"

# Один экземпляр за раз: health-чеки могут занять дольше интервала cron, и
# перекрывшиеся запуски упирались бы в rate limit ingest, засоряя лог ошибками
if command -v flock >/dev/null 2>&1; then
  exec 9>"${DIR}/.push.lock"
  flock -n 9 || exit 0
fi

# Лог агента растёт без ограничений, если на хосте нет logrotate
for LOG_FILE in /var/log/tracedocs-monitor.log "${DIR}/push.log"; do
  if [[ -f "$LOG_FILE" ]]; then
    LOG_SIZE=$(stat -c %s "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$LOG_SIZE" =~ ^[0-9]+$ ]] && [[ $LOG_SIZE -gt 5242880 ]]; then
      tail -c 1048576 "$LOG_FILE" >"${LOG_FILE}.rotated" 2>/dev/null &&
        mv "${LOG_FILE}.rotated" "$LOG_FILE" || rm -f "${LOG_FILE}.rotated"
    fi
  fi
done

# >>> HOST_POLICY_BLOCK (границы использует monitorPolicy.test.ts — не переименовывать)
# Локальная политика хоста (ADR-0095, п. 1 и 10).
#
# ЗАЧЕМ. Обновлять ли агента и собирать ли хвосты логов контейнеров, решали
# заголовки ответа ingest, то есть база платформы. Взломанная платформа
# переключает это сама. Файл root на сервере она не перепишет: правит его
# только владелец сервера.
#
# КАК РАЗБИРАЕТСЯ. Файл — данные, а не код: ни source, ни eval. Тот же файл
# читает агент развёртывания (Go), и правила разбора у них общие: разойдись они
# в мелочи — CRLF, хвостовой комментарий, таб после pinned, — один агент
# исполнит файл, а другой по той же строке закроет всё. Совпадение держит
# фикстура packages/deploy-core/fixtures/host-policy.json.
#
# Агенту мониторинга нужны два ключа — monitor_agent_updates и container_logs,
# — но остальные проверяются так же строго: файл, годный для одного агента и
# негодный для другого, и есть то расхождение, от которого фикстура.
#
# Путь — константа, а не переменная окружения: config.env подключается через
# source и приезжает с установщиком платформы, и путь, переопределяемый оттуда,
# платформа увела бы на пустой файл.
HOST_POLICY_FILE="/etc/tracedocs/agent-policy.conf"
HOST_POLICY_MAX_BYTES=4096
HOST_POLICY_COMMAND_KINDS="apply backup restore export migrate-data start-stack stop-stack inventory"

# MAJOR.MINOR.PATCH без ведущих нулей — та же форма, что у пина в файле.
release_valid() {
  local LC_ALL=C re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
  if [[ "$1" =~ $re ]]; then return 0; fi
  return 1
}

# Код 0 — выпуск $1 новее $2. Разряды сравниваются длиной, затем строкой:
# ведущих нулей нет, а арифметика bash переполнилась бы на длинном разряде.
release_newer() {
  local LC_ALL=C a="$1" b="$2" x y i
  if ! release_valid "$a" || ! release_valid "$b"; then return 1; fi
  for i in 1 2 3; do
    x="${a%%.*}" y="${b%%.*}"
    if [[ "${#x}" -ne "${#y}" ]]; then
      if [[ "${#x}" -gt "${#y}" ]]; then return 0; else return 1; fi
    fi
    if [[ "$x" != "$y" ]]; then
      if [[ "$x" > "$y" ]]; then return 0; else return 1; fi
    fi
    a="${a#*.}" b="${b#*.}"
  done
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

# Пускает ли политика обновление с выпуска $2 на выпуск $3. $1 — значение
# monitor_agent_updates, пусто — файла нет и решает платформа, как раньше.
# pinned — только ровно на пин и только вверх: откат снимает уже поставленную
# защиту. no_major — в пределах своего MAJOR; нечитаемый номер с любой
# стороны — отказ: не зная MAJOR, нельзя сказать, что шаг мелкий. Разряд
# сравнивается строкой: ведущих нулей release_valid не пускает.
monitor_update_permitted() {
  local updates="$1" current="$2" target="$3"
  case "$updates" in
    "" | auto) return 0 ;;
    no_major)
      if release_valid "$current" && release_valid "$target" && [[ "${target%%.*}" == "${current%%.*}" ]]; then return 0; fi
      return 1
      ;;
    "pinned "*)
      if [[ "$target" == "${updates#pinned }" ]] && release_newer "$target" "$current"; then return 0; fi
      return 1
      ;;
  esac
  return 1
}

# Действующее правило обновления агента мониторинга (ADR-0095, п. 3 и 10).
# $1 — monitor_agent_updates из файла; пусто — файла нет, решает платформа.
# Без вшитых ключей выпуска подпись бандла не проверяется (verify_bundle_signature
# пропускает всё), а бандл исполняется от root: взломанная платформа отдаст
# свой бандл под любым номером, и он снимет политику целиком. Поэтому без
# ключей pinned и no_major — как manual (граница MAJOR — тоже номер), а auto —
# как manual, если файл хоть что-то ограничивает: observe, неполный список
# commands или container_logs не allow (нет ключа — это deny). Первые два условия общие с агентом развёртывания
# (EffectiveDeployUpdates в localpolicy.go); третье — только здесь: запрет
# логов исполняет сам агент мониторинга, и его неподписанный бандл снял бы
# запрет первым. Держит фикстура host-policy.json, раздел updateCases.
# Нужны POLICY_MODE, POLICY_COMMANDS и POLICY_CONTAINER_LOGS от read_host_policy.
host_policy_effective_updates() {
  local updates="$1" kind
  if [[ -z "$updates" || -n "${SCOPEWORK_RELEASE_KEYS:-}" ]]; then
    printf '%s' "$updates"
    return 0
  fi
  case "$updates" in
    "pinned "* | no_major)
      printf 'manual'
      return 0
      ;;
    auto)
      if [[ "$POLICY_MODE" != deploy || "$POLICY_CONTAINER_LOGS" != allow ]]; then
        printf 'manual'
        return 0
      fi
      for kind in $HOST_POLICY_COMMAND_KINDS; do
        if [[ ",${POLICY_COMMANDS}," != *",${kind},"* ]]; then
          printf 'manual'
          return 0
        fi
      done
      ;;
  esac
  printf '%s' "$updates"
}

# Хвосты логов контейнеров: включает их только строка container_logs=allow в
# файле владельца, заголовок платформы может лишь выключить. $1 — значение
# политики (пусто — файла нет: решает заголовок, как раньше), $2 — флаг
# платформы.
container_logs_flag() {
  if [[ -n "$1" && "$1" != allow ]]; then
    printf '0'
  elif [[ "$2" == "1" ]]; then
    printf '1'
  else
    printf '0'
  fi
}

# Ответ ingest через политику хоста. Отдельной функцией, чтобы тест проверял
# этот порядок, а не его пересказ.
apply_platform_response() {
  # Решение человека о хвостах логов (ADR-0061, решение 6) — применяется со
  # следующего такта. Нет заголовка (платформа старше агента) — выключено: лог
  # не покидает хост, пока платформа явно не сказала «включено».
  container_logs_flag "$POLICY_CONTAINER_LOGS" "$(read_resp_header "X-Scopework-Container-Logs")" \
    >"${STATE_DIR}/container-logs" 2>/dev/null || true

  # manual — цель обновления даже не читается: платформа не решает за
  # владельца ничего, в том числе «что скачать и проверить». Решает
  # ДЕЙСТВУЮЩЕЕ правило: без ключей выпуска pinned и ограничивающий auto — тоже
  # manual.
  local updates
  updates=$(host_policy_effective_updates "$POLICY_MONITOR_UPDATES")
  if [[ "$updates" == manual ]]; then
    if [[ "$POLICY_MONITOR_UPDATES" != manual ]]; then
      echo "самообновление: monitor_agent_updates=${POLICY_MONITOR_UPDATES} без вшитого ключа выпуска исполняется как manual — подпись бандла проверить нечем" >&2
    fi
    return 0
  fi

  # Самообновление — последним делом: пуш уже доставлен, курсоры сдвинуты, и
  # любой сбой обновления не может стоить окна угроз.
  run_self_update "$AGENT_VERSION" "$(read_resp_header "X-Scopework-Agent-Version")" \
    "$(read_resp_header "X-Scopework-Agent-Sha256")" "$updates" || true
}
# <<< HOST_POLICY_BLOCK

# Каждый запуск заново: правка файла действует со следующего такта без
# перезапуска и переустановки.
read_host_policy "$HOST_POLICY_FILE"
if [[ "$POLICY_STATE" == invalid ]]; then
  echo "политика сервера ${HOST_POLICY_FILE}: ${POLICY_ERROR} — обновления агента и логи контейнеров выключены" >&2
fi

# >>> SELF_UPDATE_BLOCK (границы использует selfUpdate.test.ts — не переименовывать)
# Самообновление агента.
#
# ЗАЧЕМ. Возможности агента приезжают вместе с его версией, а обновлялся он
# только руками: «зайдите на каждый сервер и выполните команду установки
# заново». За один день по контролю атак вышло четыре правки этого скрипта, и
# до обхода серверов на них молча не работали исправления: на Debian/Ubuntu
# HTTP-угрозы собирались в ноль, а владелец об этом не знал.
#
# КАК. Платформа объявляет целевую версию и sha256 бандла в заголовках ответа
# ingest. Агент, увидев расхождение, качает бандл С ТОЙ ЖЕ платформы (другого
# доверенного источника у него нет — тот же принцип, что в install.sh), сверяет
# сумму, проверяет содержимое, прогоняет НОВЫЙ скрипт вхолостую и только потом
# атомарно подменяет свои файлы.
#
# ЧЕГО НЕ ДЕЛАЕТ. Не трогает config.env, systemd-юниты и cron. Настройки
# (контроль атак, пути логов, интервал) потерять при обновлении структурно
# невозможно — их файл самообновление не открывает даже на чтение-запись.
# Обратная сторона: смена юнитов или расписания по-прежнему требует
# переустановки, о ней платформа скажет отдельно.
SELF_UPDATE_RETRY_AFTER_SEC=3600
# Сколько запусков даётся новой версии, чтобы доказать работоспособность.
SELF_UPDATE_TRIAL_RUNS=2
SELF_UPDATE_FILES=(push.sh build-snapshot-json.py uninstall.sh)
SU_VERSION_FILE="${DIR}/agent-version"
SU_MARKER="${STATE_DIR}/self-update-marker"
SU_TRIAL="${STATE_DIR}/self-update-trial"
SU_BLOCKED="${STATE_DIR}/self-update-blocked"
SU_BACKUP="${DIR}/.backup"
SU_STAGING="${DIR}/.update"
# Номер выпуска этого скрипта — тот же, что в agent/VERSION платформы
# (генератор agentScripts.generated.ts отказывает, если они разошлись). Файл
# agent-version хранит отпечаток файлов: по нему сверяется бандл, но упорядочить
# два отпечатка нельзя, а пин и запрет отката сравнивают номера.
AGENT_RELEASE="1.1.0"
# Открытые ключи выпуска (ADR-0082): std-base64 сырых 32 байт Ed25519 через
# запятую, в порядке имён файлов apps/deploy-agent/trust/release/*.pub;
# совпадение с каталогом держит гейт test:agent-release. Новый бандл
# проверяется ключами ЭТОГО, уже установленного скрипта: ключи из самого бандла
# подтверждали бы сами себя. Пусто — подпись не проверяется, как до ключей.
# >>> RELEASE_KEYS
SCOPEWORK_RELEASE_KEYS="31JoQyQmXiswynaTFjvn6NUIDx9JjY25hocCQ4VCLKM="
# <<< RELEASE_KEYS

# Однострочные файлы состояния вместо JSON: их читает bash без jq и python3, и
# на диагностике их видно глазами, а не через парсер.
su_read_line() {
  local file="$1" n="${2:-1}" line=""
  if [[ -f "$file" ]]; then
    line=$(sed -n "${n}p" "$file" 2>/dev/null) || line=""
  fi
  line="${line//$'\r'/}"
  printf '%s' "${line// /}"
}

# Заголовок ответа платформы: $1 — имя, $2 — файл заголовков (без него — ответ
# ingest). Имя в HTTP/2 приходит в нижнем регистре, отсюда grep -i.
read_resp_header() {
  local line="" file="${2:-${RESP_HEADERS:-}}"
  [[ -n "$file" ]] || return 0
  line=$(grep -i "^$1:" "$file" 2>/dev/null | tail -1) || line=""
  line="${line#*:}"
  line="${line//$'\r'/}"
  printf '%s' "${line// /}"
}

# Решение «обновляться или нет» — без побочных эффектов, чтобы его можно было
# проверить тестом. Код 0 = обновляться.
should_self_update() {
  local current="$1" target="$2" target_sha="$3"
  local marker_target="$4" marker_age="$5" enabled="$6" blocked="$7"
  if [[ "$enabled" == "0" ]]; then return 1; fi
  # Платформа не объявила цель (сборка без версии) или не дала сумму — сверять
  # нечем, а качать без сверки нельзя.
  if [[ -z "$target" || -z "$target_sha" ]]; then return 1; fi
  if [[ "$current" == "$target" ]]; then return 1; fi
  # Версия, на которой агент уже сломался и откатился, не пробуется больше
  # никогда: платформа объявит следующую — приедет она.
  if [[ -n "$blocked" && "$blocked" == "$target" ]]; then return 1; fi
  # Экран от бесконечного цикла: подменились, а версия так и не совпала с целью
  # (кривая сборка платформы). Час — достаточно редко, чтобы не мешать хосту,
  # и достаточно часто, чтобы шум заметили по логу.
  if [[ -n "$marker_target" && "$marker_target" == "$target" ]]; then
    if [[ ! "$marker_age" =~ ^[0-9]+$ ]]; then return 1; fi
    if [[ "$marker_age" -lt "$SELF_UPDATE_RETRY_AFTER_SEC" ]]; then return 1; fi
  fi
  return 0
}

# Возврат к предыдущей версии. Молчаливо сломанный агент хуже устаревшего,
# поэтому откат ещё и запрещает эту цель навсегда — иначе платформа вернула бы
# ту же битую версию следующим же пушем.
self_update_rollback() {
  local reason="$1" current="$2" prev f
  prev=$(su_read_line "${SU_BACKUP}/agent-version")
  if [[ ! -f "${SU_BACKUP}/push.sh" ]]; then
    printf '%s\n' "$current" >"$SU_BLOCKED" 2>/dev/null || true
    rm -f "$SU_TRIAL"
    echo "ERROR: самообновление: версия ${current} не подтвердилась (${reason}), резервной копии нет — откат невозможен. Переустановите агент." >&2
    return 1
  fi
  for f in "${SELF_UPDATE_FILES[@]}" agent-version; do
    [[ -f "${SU_BACKUP}/${f}" ]] || continue
    if cp "${SU_BACKUP}/${f}" "${DIR}/.rollback-${f}.tmp" 2>/dev/null; then
      chmod 750 "${DIR}/.rollback-${f}.tmp" 2>/dev/null || true
      mv -f "${DIR}/.rollback-${f}.tmp" "${DIR}/${f}" 2>/dev/null || rm -f "${DIR}/.rollback-${f}.tmp"
    fi
  done
  printf '%s\n' "$current" >"$SU_BLOCKED" 2>/dev/null || true
  rm -f "$SU_TRIAL"
  echo "ERROR: самообновление: версия ${current} не подтвердилась (${reason}) — откат к ${prev:-предыдущей версии}. Эта цель больше не повторится." >&2
  return 0
}

# Счётчик испытательных запусков. Тикает В НАЧАЛЕ пуша, снимается в конце —
# после того, как снапшот собран. Отсюда и правило подтверждения: агент
# считается рабочим, когда СОБРАЛ снапшот, а не когда его приняла платформа.
# Иначе три подряд сетевых сбоя откатывали бы исправную версию.
self_update_trial_tick() {
  local current="$1" trial_version trial_runs
  [[ -f "$SU_TRIAL" ]] || return 0
  trial_version=$(su_read_line "$SU_TRIAL" 1)
  trial_runs=$(su_read_line "$SU_TRIAL" 2)
  [[ "$trial_runs" =~ ^[0-9]+$ ]] || trial_runs=0
  # Испытание чужой версии — след переустановки руками или уже случившегося
  # отката: к текущим файлам оно отношения не имеет.
  if [[ "$trial_version" != "$current" ]]; then
    rm -f "$SU_TRIAL"
    return 0
  fi
  trial_runs=$((trial_runs + 1))
  if [[ "$trial_runs" -gt "$SELF_UPDATE_TRIAL_RUNS" ]]; then
    self_update_rollback "снапшот не собрался за ${SELF_UPDATE_TRIAL_RUNS} запуска" "$current" || true
    return 0
  fi
  printf '%s\n%s\n' "$current" "$trial_runs" >"$SU_TRIAL" 2>/dev/null || true
}

# Снимается, когда снапшот собран и проверен.
self_update_confirm() {
  local current="$1"
  [[ -f "$SU_TRIAL" ]] || return 0
  if [[ "$(su_read_line "$SU_TRIAL" 1)" == "$current" ]]; then
    rm -f "$SU_TRIAL"
    # Маркер снимаем только для СВОЕЙ цели: маркер чужой цели всё ещё
    # охраняет от цикла на ней.
    if [[ "$(su_read_line "$SU_MARKER" 1)" == "$current" ]]; then rm -f "$SU_MARKER"; fi
    echo "самообновление: версия ${current} подтверждена" >&2
  fi
}

# Проверки скачанного ДО подмены файлов. Сумма — главное, но дешёвые проверки
# формата диагностируются понятнее: страницу ошибки от прокси видно по первой
# же строке сообщения, а не по несовпадению хешей.
verify_agent_bundle() {
  local file="$1" expected_sha="$2" expected_version="$3" got
  if [[ ! -s "$file" ]]; then
    echo "самообновление: бандл пуст" >&2
    return 1
  fi
  if [[ "$(head -c 1 "$file" 2>/dev/null)" != "{" ]]; then
    echo "самообновление: по адресу бандла отдали не JSON (прокси/страница ошибки?)" >&2
    return 1
  fi
  got=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
  if [[ "$got" != "$expected_sha" ]]; then
    echo "самообновление: сумма не совпала: получено ${got:-?}, ожидалось ${expected_sha}" >&2
    return 1
  fi
  python3 - "$file" "$expected_version" <<'PY_VERIFY' || return 1
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as exc:
    sys.exit("bundle: не разбирается как JSON (%s)" % exc)
if data.get("version") != sys.argv[2]:
    sys.exit("bundle: версия в бандле %r не совпала с объявленной %r"
             % (data.get("version"), sys.argv[2]))
files = data.get("files")
if not isinstance(files, dict):
    sys.exit("bundle: нет карты файлов")
expected = {"push.sh", "build-snapshot-json.py", "uninstall.sh"}
if set(files) != expected:
    sys.exit("bundle: неожиданный состав файлов: %s" % sorted(files))
for name, body in files.items():
    if not isinstance(body, str) or not body.strip():
        sys.exit("bundle: пустой файл %s" % name)
if not files["push.sh"].startswith("#!"):
    sys.exit("bundle: push.sh без shebang")
PY_VERIFY
  return 0
}

# Номер выпуска из бандла. Сумма бандла к этому моменту сверена, так что номер
# — часть проверенного содержимого, а не отдельный заголовок. Пусто — бандл
# платформы, которая номеров выпуска ещё не раздавала.
bundle_release() {
  python3 - "$1" <<'PY_RELEASE' 2>/dev/null || true
import json, re, sys
try:
    release = json.load(open(sys.argv[1], encoding="utf-8")).get("release")
except Exception:
    sys.exit(0)
if isinstance(release, str) and re.match(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z", release):
    sys.stdout.write(release)
PY_RELEASE
}

# Итог проверки подписи — одним словом в state/signature-check:
#   verified     подпись сошлась с одним из ключей выпуска
#   missing      ключи вшиты, а подписи у бандла нет
#   mismatch     подпись не сошлась ни с одним ключом
#   unavailable  проверить нечем: нет ни OpenSSL 3, ни python3
#   no_keys      ключей нет — обновление без подписи, как до ключей
su_signature_state() {
  printf '%s\n' "$1" >"${STATE_DIR}/signature-check" 2>/dev/null || true
}

# Эталон RFC 8032, раздел 7.1, тест 2: ключ, подпись и сообщение «r».
ED25519_PROBE_KEY="PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw="
ED25519_PROBE_SIG="kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA=="

# Одна подпись через openssl: $1 — рабочий каталог, $2 — ключ (base64),
# $3 — файл подписи, $4 — файл сообщения.
openssl_ed25519_verify() {
  local der="${1}/key.der" size
  # Сырой ключ openssl не принимает. SubjectPublicKeyInfo Ed25519 — постоянный
  # префикс и те же 32 байта, собирать PEM незачем.
  {
    printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
    printf '%s' "$2" | openssl base64 -d -A 2>/dev/null
  } >"$der" || return 1
  size=$(wc -c <"$der" 2>/dev/null) || return 1
  size="${size//[!0-9]/}"
  [[ "$size" == "44" ]] || return 1
  if openssl pkeyutl -verify -pubin -inkey "$der" -keyform DER -rawin \
    -in "$4" -sigfile "$3" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# OpenSSL 3 определяется по факту, а не по пути и не по номеру: LibreSSL
# (macOS, BSD) тоже отвечает «3.x», а Ed25519 с -rawin умеет не всякая сборка.
# Решает проверка эталона: не прошла — openssl этой системы не годится.
openssl_ed25519_usable() {
  local work="$1" version major
  command -v openssl >/dev/null 2>&1 || return 1
  version=$(openssl version 2>/dev/null) || return 1
  [[ "$version" == "OpenSSL "* ]] || return 1
  major="${version#OpenSSL }"
  major="${major%%.*}"
  [[ "$major" =~ ^[0-9]+$ && "$major" -ge 3 ]] || return 1
  printf '%s' "$ED25519_PROBE_SIG" | openssl base64 -d -A >"${work}/probe.sig" 2>/dev/null || return 1
  printf 'r' >"${work}/probe.msg" || return 1
  openssl_ed25519_verify "$work" "$ED25519_PROBE_KEY" "${work}/probe.sig" "${work}/probe.msg"
}

# Проверка по RFC 8032 на чистом python3, без сторонних модулей: python3
# самообновлению нужен и так, а модуль cryptography стоит не везде. $1 — ключи
# через запятую, $2 — подпись, $3 — сообщение. Печатает verified или mismatch;
# любой другой исход — проверить не удалось.
python_ed25519_verify() {
  python3 - "$1" "$2" "$3" <<'PY_ED25519' 2>/dev/null
import base64, binascii, hashlib, sys

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def decode_point(raw):
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


# Сложение в расширенных координатах (RFC 8032, 5.1.4).
def add(a, b):
    e1 = (a[1] - a[0]) * (b[1] - b[0]) % P
    e2 = (a[1] + a[0]) * (b[1] + b[0]) % P
    e3 = 2 * a[3] * b[3] * D % P
    e4 = 2 * a[2] * b[2] % P
    e, f, g, h = e2 - e1, e4 - e3, e4 + e3, e2 + e1
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s, point):
    acc = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            acc = add(acc, point)
        point = add(point, point)
        s >>= 1
    return acc


def equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


GY = 4 * pow(5, P - 2, P) % P
GX = recover_x(GY, 0)
G = (GX, GY, 1, GX * GY % P)


def verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = decode_point(public)
    r = decode_point(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return equal(mul(s, G), add(r, mul(h, a)))


def b64(text):
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return b""


signature = b64(sys.argv[2])
message = sys.argv[3].encode("utf-8")
ok = any(verify(b64(key), message, signature) for key in sys.argv[1].split(",") if key)
sys.stdout.write("verified" if ok else "mismatch")
PY_ED25519
}

# Подпись бандла ключом выпуска (ADR-0082, ADR-0095 п. 10). Сумма из заголовка
# ingest доказывает только «скачано то, что объявила платформа»: взломанная
# платформа объявит свой бандл со своей суммой. Подпись ключом, которого у
# платформы нет, доказывает, что бандл выпустил владелец ключа.
# $1 — номер выпуска из бандла, $2 — его sha256, $3 — подпись (base64).
# Код 0 — ставить можно.
verify_bundle_signature() {
  local LC_ALL=C release="$1" sha="$2" signature="$3" message work="" rest key result=""
  if [[ -z "$SCOPEWORK_RELEASE_KEYS" ]]; then
    su_signature_state no_keys
    return 0
  fi
  if [[ -z "$signature" ]]; then
    su_signature_state missing
    echo "самообновление: у бандла нет подписи, а ключи выпуска вшиты — обновление не ставится" >&2
    return 1
  fi
  # Номер выпуска входит в сообщение: без него подпись старого бандла годилась
  # бы для отката на него.
  if ! release_valid "$release" || [[ ! "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    su_signature_state mismatch
    echo "самообновление: у бандла нет номера выпуска — подпись сверять не с чем, обновление не ставится" >&2
    return 1
  fi
  message=$(printf 'monitor-bundle\n%s\n%s' "$release" "$sha")

  work=$(mktemp -d "${TMPDIR:-/tmp}/tracedocs-signature.XXXXXX" 2>/dev/null) || work=""
  if [[ -n "$work" ]] && openssl_ed25519_usable "$work"; then
    result=mismatch
    printf '%s' "$message" >"${work}/message"
    if printf '%s' "$signature" | openssl base64 -d -A >"${work}/bundle.sig" 2>/dev/null; then
      rest="${SCOPEWORK_RELEASE_KEYS},"
      while [[ -n "$rest" ]]; do
        key="${rest%%,*}" rest="${rest#*,}"
        [[ -n "$key" ]] || continue
        if openssl_ed25519_verify "$work" "$key" "${work}/bundle.sig" "${work}/message"; then
          result=verified
          break
        fi
      done
    fi
  elif command -v python3 >/dev/null 2>&1; then
    result=$(python_ed25519_verify "$SCOPEWORK_RELEASE_KEYS" "$signature" "$message") || result=""
  fi
  if [[ -n "$work" ]]; then rm -rf "$work"; fi

  case "$result" in
    verified)
      su_signature_state verified
      return 0
      ;;
    mismatch)
      su_signature_state mismatch
      echo "самообновление: подпись бандла не сошлась ни с одним ключом выпуска — обновление не ставится" >&2
      return 1
      ;;
  esac
  su_signature_state unavailable
  echo "самообновление: подпись не проверяется на этой системе (нет ни OpenSSL 3, ни python3) — обновление только переустановкой" >&2
  return 1
}

# Раскладка бандла во временный каталог. Имена файлов — жёсткий список внутри
# python: путь из данных никогда не участвует в сборке пути на диске.
stage_agent_bundle() {
  local file="$1" staging="$2"
  rm -rf "$staging"
  mkdir -p "$staging" || return 1
  chmod 700 "$staging" 2>/dev/null || true
  python3 - "$file" "$staging" <<'PY_STAGE' || return 1
import json, os, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
out = sys.argv[2]
for name in ("push.sh", "build-snapshot-json.py", "uninstall.sh"):
    path = os.path.join(out, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(data["files"][name])
    os.chmod(path, 0o750)
PY_STAGE
  return 0
}

# Дешёвые проверки синтаксиса. Скрипт с опечаткой не должен доехать до подмены:
# bash читает файл по мере выполнения, и сломанный push.sh не сможет ни
# откатиться, ни пожаловаться.
check_staged_agent() {
  local staging="$1"
  if ! bash -n "${staging}/push.sh" 2>&1; then
    echo "самообновление: новый push.sh не проходит проверку синтаксиса" >&2
    return 1
  fi
  if ! python3 -c 'import py_compile,sys; py_compile.compile(sys.argv[1], doraise=True)' \
    "${staging}/build-snapshot-json.py" >/dev/null 2>&1; then
    echo "самообновление: новый build-snapshot-json.py не компилируется" >&2
    return 1
  fi
  if ! bash -n "${staging}/uninstall.sh" 2>&1; then
    echo "самообновление: новый uninstall.sh не проходит проверку синтаксиса" >&2
    return 1
  fi
  return 0
}

# Главная проверка: новый скрипт целиком собирает снапшот на этом самом хосте,
# с боевым конфигом, и останавливается перед отправкой. Ловит всё, что
# синтаксис не ловит: несовместимый awk, отсутствующую утилиту, обращение к
# незаданной переменной под set -u.
smoke_staged_agent() {
  local staging="$1" out ok=1
  # Пустой массив под `set -u` разворачивается с ошибкой на bash 4.2 (CentOS 7),
  # поэтому две ветки, а не подстановка команды-обёртки.
  if command -v timeout >/dev/null 2>&1; then
    out=$(TRACEDOCS_CONFIG_ENV="$CONFIG_ENV" TRACEDOCS_SELF_CHECK=1 \
      timeout 150 bash "${staging}/push.sh" 2>&1) || ok=0
  else
    out=$(TRACEDOCS_CONFIG_ENV="$CONFIG_ENV" TRACEDOCS_SELF_CHECK=1 \
      bash "${staging}/push.sh" 2>&1) || ok=0
  fi
  if [[ "$ok" -eq 0 ]]; then
    echo "самообновление: холостой прогон новой версии не удался:" >&2
    printf '%s\n' "$out" | tail -5 >&2
    return 1
  fi
  if [[ "$out" != *SELF_CHECK_OK* ]]; then
    echo "самообновление: холостой прогон не дошёл до сборки снапшота" >&2
    printf '%s\n' "$out" | tail -5 >&2
    return 1
  fi
  return 0
}

# Подмена. Временный файл — в ТОМ ЖЕ каталоге (rename между файловыми
# системами не атомарен), затем rename поверх. Работающий сейчас bash
# продолжает читать старый inode — это штатно, новую версию подхватит
# следующий запуск таймера.
swap_agent_files() {
  local staging="$1" version="$2" f
  rm -rf "$SU_BACKUP"
  mkdir -p "$SU_BACKUP" || return 1
  chmod 700 "$SU_BACKUP" 2>/dev/null || true
  for f in "${SELF_UPDATE_FILES[@]}"; do
    [[ -f "${DIR}/${f}" ]] || continue
    cp "${DIR}/${f}" "${SU_BACKUP}/${f}" || return 1
  done
  if [[ -f "$SU_VERSION_FILE" ]]; then
    cp "$SU_VERSION_FILE" "${SU_BACKUP}/agent-version" || return 1
  else
    # Агент, поставленный до появления версий: откатываться есть куда, а
    # записать «неизвестно» честнее, чем оставить файл от новой версии.
    printf '\n' >"${SU_BACKUP}/agent-version"
  fi
  for f in "${SELF_UPDATE_FILES[@]}"; do
    mv -f "${staging}/${f}" "${DIR}/${f}" || return 1
  done
  printf '%s\n' "$version" >"${DIR}/.agent-version.tmp" || return 1
  chmod 600 "${DIR}/.agent-version.tmp" 2>/dev/null || true
  mv -f "${DIR}/.agent-version.tmp" "$SU_VERSION_FILE" || return 1
  return 0
}

# Драйвер: решает, качает, проверяет, подменяет. Никогда не роняет пуш —
# любой сбой это запись в лог и работа дальше старой версией.
run_self_update() {
  # $4 — monitor_agent_updates из политики хоста; пусто — файла нет.
  local current="$1" target="$2" target_sha="$3" updates="${4:-}"
  local marker_target marker_at marker_age blocked bundle_url tmp hdr now release
  marker_target=$(su_read_line "$SU_MARKER" 1)
  marker_at=$(su_read_line "$SU_MARKER" 2)
  blocked=$(su_read_line "$SU_BLOCKED" 1)
  now=$(date +%s)
  marker_age=""
  if [[ "$marker_at" =~ ^[0-9]+$ ]]; then marker_age=$((now - marker_at)); fi

  if ! should_self_update "$current" "$target" "$target_sha" \
    "$marker_target" "$marker_age" "${TRACEDOCS_SELF_UPDATE:-1}" "$blocked"; then
    return 0
  fi

  # Пин не выше своего выпуска не пропустит ни одну цель — качать незачем.
  # Номер цели виден только в бандле, поэтому остальное решается после загрузки.
  if [[ "$updates" == "pinned "* ]] && ! release_newer "${updates#pinned }" "$AGENT_RELEASE"; then
    return 0
  fi

  # Адрес бандла выводим из СВОЕГО ingest-URL, а не берём из ответа: иначе
  # ответ платформы (или того, кто её подменит) мог бы увести агента за файлами
  # на чужой origin.
  if [[ "$TRACEDOCS_INGEST_URL" != */ingest ]]; then
    echo "самообновление: нестандартный TRACEDOCS_INGEST_URL — адрес бандла не вывести, обновление пропущено" >&2
    return 0
  fi
  bundle_url="${TRACEDOCS_INGEST_URL%/ingest}/agent-bundle"

  echo "самообновление: ${current:-без версии} -> ${target}" >&2
  tmp=$(mktemp "${TMPDIR:-/tmp}/tracedocs-bundle.XXXXXX")
  hdr=$(mktemp "${TMPDIR:-/tmp}/tracedocs-bundle-hdr.XXXXXX")
  if ! curl -fsSL --connect-timeout 10 --max-time 60 -D "$hdr" -o "$tmp" "$bundle_url"; then
    echo "самообновление: загрузка бандла не удалась" >&2
    rm -f "$tmp" "$hdr"
    return 0
  fi

  if ! verify_agent_bundle "$tmp" "$target_sha" "$target"; then
    # Помечаем цель неудачной: без этого следующий пуш качал бы тот же
    # битый бандл каждый цикл.
    printf '%s\n%s\n' "$target" "$now" >"$SU_MARKER" 2>/dev/null || true
    rm -f "$tmp" "$hdr"
    return 0
  fi

  # Отказы политики и подписи тоже помечают цель: та же цель пробуется снова
  # через час, а не качается каждым пушем.
  release=$(bundle_release "$tmp")
  if ! monitor_update_permitted "$updates" "$AGENT_RELEASE" "$release"; then
    echo "самообновление: политика сервера (monitor_agent_updates=${updates}) не пускает выпуск ${release:-без номера}" >&2
    printf '%s\n%s\n' "$target" "$now" >"$SU_MARKER" 2>/dev/null || true
    rm -f "$tmp" "$hdr"
    return 0
  fi
  # Подпись отдаёт ручка бандла; сумма в сообщении — уже сверенная с файлом.
  if ! verify_bundle_signature "$release" "$target_sha" \
    "$(read_resp_header "X-Scopework-Agent-Signature" "$hdr")"; then
    printf '%s\n%s\n' "$target" "$now" >"$SU_MARKER" 2>/dev/null || true
    rm -f "$tmp" "$hdr"
    return 0
  fi
  rm -f "$hdr"

  if ! stage_agent_bundle "$tmp" "$SU_STAGING"; then
    echo "самообновление: не удалось разложить бандл" >&2
    rm -f "$tmp"
    rm -rf "$SU_STAGING"
    return 0
  fi
  rm -f "$tmp"

  if ! check_staged_agent "$SU_STAGING" || ! smoke_staged_agent "$SU_STAGING"; then
    printf '%s\n%s\n' "$target" "$now" >"$SU_MARKER" 2>/dev/null || true
    rm -rf "$SU_STAGING"
    return 0
  fi

  # Маркер ставится ДО подмены: если новая версия окажется не той, что
  # объявлена, защита от цикла уже будет на диске.
  printf '%s\n%s\n' "$target" "$now" >"$SU_MARKER" 2>/dev/null || true
  # Испытание — тоже до подмены: следующий запуск начнётся уже новой версией и
  # должен увидеть незакрытое испытание.
  printf '%s\n%s\n' "$target" "0" >"$SU_TRIAL" 2>/dev/null || true

  if ! swap_agent_files "$SU_STAGING" "$target"; then
    echo "ERROR: самообновление: подмена файлов не удалась — возможен смешанный состав, откатываемся" >&2
    self_update_rollback "подмена не завершилась" "$target" || true
    rm -rf "$SU_STAGING"
    return 0
  fi
  rm -rf "$SU_STAGING"
  echo "самообновление: файлы обновлены до ${target}, следующий запуск пойдёт новой версией" >&2
  return 0
}
# <<< SELF_UPDATE_BLOCK

AGENT_VERSION=$(su_read_line "$SU_VERSION_FILE")
self_update_trial_tick "$AGENT_VERSION"

# --- CPU: средняя загрузка за интервал между пушами ---
#
# ПОЧЕМУ НЕ СЕКУНДНАЯ ВЫБОРКА. Раньше здесь стояло два чтения /proc/stat с
# `sleep 1` между ними: снимок описывал одну секунду из ста восьмидесяти, то
# есть полпроцента времени жизни сервера. Реальные всплески в неё почти не
# попадали — за неделю платформа насчитала семнадцать подъёмов выше 80% и ни
# одной тревоги, потому что правило требовало трёх попаданий подряд. Дельта с
# прошлого запуска покрывает ВЕСЬ интервал: пропустить нагрузку она не может.
#
# Учитываем все поля /proc/stat: iowait/irq/steal иначе попадали бы в «занято»
# и давали ложные cpu_high на IO-нагруженных серверах.
read_cpu() {
  read -r _ cu cn cs ci cw cq csq cst _ </proc/stat
  CPU_IDLE=$(( ${ci:-0} + ${cw:-0} ))
  CPU_TOTAL=$(( ${cu:-0} + ${cn:-0} + ${cs:-0} + ${ci:-0} + ${cw:-0} + ${cq:-0} + ${csq:-0} + ${cst:-0} ))
}

CPU_STATE="${STATE_DIR}/cpu-stat"
read_cpu
CPU_IDLE_NOW=$CPU_IDLE
CPU_TOTAL_NOW=$CPU_TOTAL
CPU=""

if [[ -r "$CPU_STATE" ]]; then
  PREV_IDLE=""
  PREV_TOTAL=""
  read -r PREV_IDLE PREV_TOTAL <"$CPU_STATE" 2>/dev/null || true
  if [[ "${PREV_IDLE:-}" =~ ^[0-9]+$ ]] && [[ "${PREV_TOTAL:-}" =~ ^[0-9]+$ ]]; then
    IDLE_DELTA=$((CPU_IDLE_NOW - PREV_IDLE))
    TOTAL_DELTA=$((CPU_TOTAL_NOW - PREV_TOTAL))
    # Отрицательная дельта — счётчики обнулились перезагрузкой: считать по ней
    # нельзя, уходим на разовую выборку ниже.
    if [[ $TOTAL_DELTA -gt 0 ]] && [[ $IDLE_DELTA -ge 0 ]]; then
      CPU=$(awk -v idle="$IDLE_DELTA" -v tot="$TOTAL_DELTA" 'BEGIN { printf "%.1f", (1 - idle/tot) * 100 }')
    fi
  fi
fi

# Первый запуск после установки или перезагрузки: сравнивать не с чем. Разовая
# выборка здесь лучше пустого поля — снимок без CPU выглядит на платформе как
# неисправность сбора.
if [[ -z "$CPU" ]]; then
  IDLE1=$CPU_IDLE_NOW
  TOTAL1=$CPU_TOTAL_NOW
  sleep 1
  read_cpu
  CPU_IDLE_NOW=$CPU_IDLE
  CPU_TOTAL_NOW=$CPU_TOTAL
  IDLE_DELTA=$((CPU_IDLE_NOW - IDLE1))
  TOTAL_DELTA=$((CPU_TOTAL_NOW - TOTAL1))
  CPU="0"
  if [[ $TOTAL_DELTA -gt 0 ]]; then
    CPU=$(awk -v idle="$IDLE_DELTA" -v tot="$TOTAL_DELTA" 'BEGIN { printf "%.1f", (1 - idle/tot) * 100 }')
  fi
fi

# Пишем САМОЕ СВЕЖЕЕ чтение: после разовой выборки счётчики ушли вперёд на
# секунду, и запись доновой пары посчитала бы эту секунду дважды.
printf '%s %s\n' "$CPU_IDLE_NOW" "$CPU_TOTAL_NOW" >"$CPU_STATE" 2>/dev/null || true

# --- Load ---
read -r LOAD1 LOAD5 LOAD15 _ </proc/loadavg

# --- Memory (kB → bytes) ---
MEM_TOTAL_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
MEM_AVAIL_KB=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
MEM_TOTAL=$((MEM_TOTAL_KB * 1024))
MEM_USED=$(( (MEM_TOTAL_KB - MEM_AVAIL_KB) * 1024 ))

# --- Uptime ---
UPTIME=$(cut -d. -f1 /proc/uptime)

# --- Disk mounts (JSON array) ---
# GNU df: -T и --output взаимоисключающие ("options -T and --output are mutually
# exclusive") — fstype берём через --output. BusyBox не знает --output: fallback на df -kT.
collect_df() {
  if df -B1 --output=source,fstype,size,used,avail,pcent,target >/dev/null 2>&1; then
    df -B1 --output=source,fstype,size,used,avail,pcent,target 2>/dev/null | tail -n +2
  else
    df -k -T 2>/dev/null | tail -n +2 |
      awk '{ printf "%s %s %.0f %.0f %.0f %s %s\n", $1, $2, $3*1024, $4*1024, $5*1024, $6, $7 }'
  fi
}

json_num_or_null() {
  local v="${1:-}"
  if [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
    echo "$v"
  else
    echo "null"
  fi
}

DISK_JSON="["
FIRST_DISK=1
DISK_COUNT=0
while read -r fs typ size used avail pcent mount; do
  [[ "$fs" == "Filesystem" ]] && continue
  [[ "$mount" == tmpfs || "$typ" == tmpfs || "$typ" == devtmpfs || "$typ" == squashfs ]] && continue
  [[ "$mount" == /boot* || "$mount" == /snap* ]] && continue
  [[ "$mount" == /var/lib/docker/* ]] && continue
  PCT="${pcent%%%}"
  # Схема ingest принимает максимум 32 маунта — на docker-хосте overlay-точек
  # бывает больше, и превышение отвергло бы весь снапшот
  if [[ $DISK_COUNT -ge 32 ]]; then continue; fi
  DISK_COUNT=$((DISK_COUNT + 1))
  ESC_MOUNT=$(printf '%s' "$mount" | sed 's/\\/\\\\/g; s/"/\\"/g')
  if [[ ${#mount} -gt 256 ]]; then
    mount="${mount:0:256}"
    ESC_MOUNT=$(printf '%s' "$mount" | sed 's/\\/\\\\/g; s/"/\\"/g')
  fi
  # size/used from df -B1
  if [[ $FIRST_DISK -eq 0 ]]; then DISK_JSON+=","; fi
  FIRST_DISK=0
  DISK_JSON+=$(printf '{"mount":"%s","used_percent":%s,"total_bytes":%s,"used_bytes":%s}' \
    "$ESC_MOUNT" "$(json_num_or_null "$PCT")" "$(json_num_or_null "$size")" "$(json_num_or_null "$used")")
done < <(collect_df || true)
DISK_JSON+="]"

# --- Docker (optional) ---
CONTAINERS_JSON="null"
if command -v docker >/dev/null 2>&1; then
  # Демон бывает занят, перезапускается или отвечает не сразу. `2>/dev/null`
  # глушит текст ошибки, но не код возврата, а pipefail протаскивает провал
  # через весь конвейер — и `set -e` убивал ВЕСЬ push, молча и с кодом 1.
  # Снапшот терялся целиком из-за необязательного блока, а курсоры логов при
  # этом не двигались, так что окно угроз переигрывалось следующим запуском.
  TOTAL=$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ') || TOTAL=""
  RUNNING=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ') || RUNNING=""
  RESTARTING=$(docker ps --filter status=restarting -q 2>/dev/null | wc -l | tr -d ' ') || RESTARTING=""
  # Нездоровые по healthcheck — вместе с перезапускающимися решают, закрывать ли
  # инцидент падений контейнеров (ADR-0061, решение 7).
  UNHEALTHY=$(docker ps --filter health=unhealthy -q 2>/dev/null | wc -l | tr -d ' ') || UNHEALTHY=""
  if [[ "$TOTAL" =~ ^[0-9]+$ && "$RUNNING" =~ ^[0-9]+$ && "$RESTARTING" =~ ^[0-9]+$ && "$UNHEALTHY" =~ ^[0-9]+$ ]]; then
    CONTAINERS_JSON=$(printf '{"running":%s,"total":%s,"restarting":%s,"unhealthy":%s}' \
      "$RUNNING" "$TOTAL" "$RESTARTING" "$UNHEALTHY")
  else
    # Молчать нельзя: снаружи «докера нет» и «докер не ответил» выглядят
    # одинаково — счётчик контейнеров просто пропадает из снапшота.
    echo "WARNING: docker не ответил — контейнеры в этом снапшоте пропущены" >&2
  fi
fi

# --- События контейнеров (ADR-0061) ---
# Падения, перезапуски, новые сборки: снимок docker inspect сравнивается с
# состоянием прошлого ПРИНЯТОГО такта. Не `docker events`: healthcheck даёт три
# события на каждую проверку, и буфер истории демона за такт теряет начало окна.
#
# Сборщик — вставка, а не отдельный файл: поставленные агенты проверяют состав
# бандла строго (verify_agent_bundle) и отвергли бы обновление с новым файлом
# навсегда.
#
# Новое состояние пишется в containers.pending.json и становится текущим только
# после ответа 204 (commit_container_state) — как курсоры угроз. Прежний pending
# удаляется ДО сбора: сборщик, упавший на этом такте, иначе оставил бы на
# фиксацию снимок одного из прошлых тактов, и состояние откатилось бы назад.
CONTAINER_EVENTS_JSON="null"
if command -v docker >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  rm -f "${STATE_DIR}/containers.pending.json"
  # Хвосты логов — только по решению человека на платформе, которое приезжает
  # заголовком ответа и хранится здесь; нет файла — выключено.
  CONTAINER_LOGS_FLAG=$(head -c 1 "${STATE_DIR}/container-logs" 2>/dev/null) || CONTAINER_LOGS_FLAG="0"
  # Флаг на диске записан по прошлому ответу платформы. Запрет владельца,
  # поставленный между тактами, действует с этого такта, а не со следующего.
  CONTAINER_LOGS_FLAG=$(container_logs_flag "$POLICY_CONTAINER_LOGS" "$CONTAINER_LOGS_FLAG")
  if _CONTAINER_EVENTS=$(TRACEDOCS_CONTAINER_LOGS="$CONTAINER_LOGS_FLAG" \
    python3 - "$STATE_DIR" 2>"${STATE_DIR}/container-events.err" <<'PY_CONTAINER_EVENTS'
import hashlib
import json
import os
import re
import subprocess
import sys
import time

STATE_DIR = sys.argv[1]
STATE_PATH = os.path.join(STATE_DIR, "containers.json")
PENDING_PATH = os.path.join(STATE_DIR, "containers.pending.json")
EPISODES_PATH = os.path.join(STATE_DIR, "health-episodes.json")
LOGS_ENABLED = os.environ.get("TRACEDOCS_CONTAINER_LOGS", "").strip() == "1"

STATE_VERSION = 1
MAX_CONTAINERS = 512
# Сколько помнить пропавший compose-сервис: `compose down` и `up` с тем же
# образом через такт — это перезапуск стека, а не «новый сервис».
GONE_MEMORY_SEC = 7 * 24 * 3600
# Потолки такта держат тело снимка в пределе приёма (64 КиБ) вместе с окном
# угроз: 20 событий по сотне-другой байт и 5 хвостов по 2 КиБ.
MAX_EVENTS = 20
# Список контейнеров в снимке (ADR-0061, решение 10): последний снимок того,
# что крутится, без истории. Сотни записей по ~200 байт в пределе приёма не
# помещаются вместе с окном угроз.
MAX_INVENTORY = 100
MAX_TAILS = 5
TAIL_LINES = 40
TAIL_BYTES = 2048
LINE_CHARS = 400
# Сколько знаков строки вообще смотрят регулярки вырезания.
LINE_SCAN_CHARS = 4 * LINE_CHARS
DOCKER_TIMEOUT_SEC = 30
LOGS_TIMEOUT_SEC = 10
# 137 без OOM — обычный исход `docker stop` процесса, глухого к SIGTERM
# (проверено 11.09.2026). Считать его падением значило бы тревожить на каждой
# ручной остановке; убитый снаружи контейнер с политикой перезапуска всё равно
# придёт как restarted.
CLEAN_EXIT_CODES = (0, 130, 137, 143)
PROBLEM_KINDS = ("restarted", "crashed", "unhealthy")
KIND_ORDER = {"restarted": 0, "crashed": 1, "unhealthy": 2, "deployed": 3, "stopped": 4, "removed": 5}

# Поля перечислены поимённо: Config.Env в процесс агента не попадает вовсе, и
# значения переменных контейнеров не могут утечь даже ошибкой ниже.
#
# Только поля, которые есть у КАЖДОГО контейнера, и никаких условий в шаблоне.
# Первая редакция читала `{{if .State.Health}}`: Docker 29 на контейнере без
# healthcheck отвечает «map has no entry for key Health», и все такие
# контейнеры молча выпадали из снимка (найдено прогоном на живом Docker
# 11.09.2026). Проверка берётся из `.State` целиком уже здесь, в Python.
INSPECT_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},'
    '"image_id":{{json .Image}},"restart_count":{{json .RestartCount}},'
    '"state":{{json .State}},"labels":{{json .Config.Labels}}}'
)

TIME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Вырезание секретов — на хосте, до отправки (ADR-0061, решение 6). Порядок
# важен: схема авторизации снимается раньше пары «ключ: значение», иначе от
# `Authorization: Bearer x` вырезалось бы только слово Bearer.
SECRET_PATTERNS = [
    # Имя пользователя необязательно: у Redis пароль идёт без него (`redis://:pw@`).
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]{0,32}://)([^\s:/@]{0,128}):([^\s@/]{1,512})@"), r"\1\2:***@"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/\-]+=*"), r"\1 ***"),
    (
        re.compile(
            # Квантификаторы ограничены намеренно: `[\w.\-]*` по обе стороны
            # словаря давал катастрофический перебор — строка в 64 КБ
            # разбиралась 428 с (аудит 11.09.2026). Имя ключа длиннее 64 знаков
            # с каждой стороны не встречается.
            #
            # `pass` и `key` — только последним сегментом имени (`SMTP_PASS`,
            # `APP_KEY`) или целым словом: иначе `key_count` и `monkey`
            # вырезались бы вместе со значением.
            r"""(?i)((?:[\w.\-]{0,64}(?:passw(?:or)?d|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credential|session[_\-]?id|cookie|authorization|dsn)[\w.\-]{0,64}|[\w.\-]{0,64}[_.\-](?:pass|key)|\b(?:pass|key)))(["']?\s{0,8}[:=]\s{0,8})("[^"]{0,512}"|'[^']{0,512}'|[^\s,;&"'}\]]{1,512})"""
        ),
        r"\1\2***",
    ),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "***"),
    (
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_\-]{20,}|[sprk]k_(?:live|test)_[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_\-]{20,}|xox[abprs]-[A-Za-z0-9\-]{10,}"
            r"|AKIA[0-9A-Z]{16}|td_mon_[A-Za-z0-9_\-]{8,})"
        ),
        "***",
    ),
    # Токен бота Telegram: число, двоеточие, длинный хвост.
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_\-]{30,}"), "***"),
    # Адрес почты — персональные данные пользователей чужого приложения; домен
    # оставляем, по нему видно, чей это вход.
    (re.compile(r"[A-Za-z0-9._%+\-]+@((?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})\b"), r"***@\1"),
    # Длинная строка из букв и цифр вперемешку — ключ, которого нет в списке.
    (
        re.compile(r"(?<![A-Za-z0-9_\-+=/])(?=[A-Za-z0-9_\-+=]*\d)(?=[A-Za-z0-9_\-+=]*[A-Za-z])[A-Za-z0-9_\-+=]{32,}"),
        "***",
    ),
]


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + ".000Z"


NOW = now_iso()


def iso_time(raw):
    """Время Docker с наносекундами — в ISO с миллисекундами; нулевое — None."""
    match = TIME_RE.match(raw or "")
    if not match or raw.startswith("0001-"):
        return None
    return "%s.%sZ" % (match.group(1), (match.group(2) or "").ljust(3, "0")[:3])


def int_or_none(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def docker(args, timeout, tolerate_missing=False):
    proc = subprocess.Popen(["docker"] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError("docker %s: нет ответа за %s с" % (args[0], timeout))
    if proc.returncode != 0:
        # inspect отвечает ненулевым кодом, если контейнер удалили между ps и
        # inspect, а остальных печатает — такой такт не должен пропадать
        # целиком. Любую ДРУГУЮ ошибку терпеть нельзя: так уже пропадали все
        # контейнеры без healthcheck, и снаружи это выглядело как «падений нет».
        errors = [line for line in err.decode("utf-8", "replace").splitlines() if line.strip()]
        only_missing = errors and all("No such" in line for line in errors)
        if not (tolerate_missing and only_missing):
            raise RuntimeError("docker %s: код %s: %s" % (args[0], proc.returncode, " | ".join(errors)[:300]))
    return out.decode("utf-8", "replace")


PS_FORMAT = '{{.ID}}\t{{.Status}}\t{{.Label "com.docker.compose.service"}}'


def pick_ids(ps_output):
    """Кого осматривать, если контейнеров больше потолка.

    `docker ps -a` отдаёт сначала новые, и срез первых N выкидывал бы самые
    старые — то есть как раз долгоживущие compose-сервисы, погребённые под
    остатками `docker run` без --rm. Порядок: compose-сервисы, затем
    работающие, затем остальное.
    """
    rows = []
    for line in ps_output.splitlines():
        parts = line.split("\t")
        cid = parts[0].strip()
        if not cid:
            continue
        status = parts[1] if len(parts) > 1 else ""
        service = parts[2].strip() if len(parts) > 2 else ""
        down = status.startswith(("Exited", "Created", "Dead", "Removal"))
        rank = 0 if service else (1 if not down else 2)
        rows.append((rank, len(rows), cid))
    rows.sort()
    return [cid for _, _, cid in rows[:MAX_CONTAINERS]]


def read_containers():
    ids = pick_ids(docker(["ps", "-a", "--no-trunc", "--format", PS_FORMAT], DOCKER_TIMEOUT_SEC))
    current = {}
    if not ids:
        return current
    raw = docker(["inspect", "--format", INSPECT_FORMAT] + ids, DOCKER_TIMEOUT_SEC, tolerate_missing=True)
    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").lstrip("/")[:256]
        if not name:
            continue
        labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
        state = item.get("state") if isinstance(item.get("state"), dict) else {}
        health = state.get("Health") if isinstance(state.get("Health"), dict) else {}
        current[name] = {
            "id": str(item.get("id") or ""),
            "image": str(item.get("image") or "")[:512] or None,
            "image_id": str(item.get("image_id") or "")[:128] or None,
            "status": str(state.get("Status") or ""),
            "exit_code": int_or_none(state.get("ExitCode")),
            "oom_killed": state.get("OOMKilled") is True,
            "started_at": str(state.get("StartedAt") or ""),
            "finished_at": str(state.get("FinishedAt") or ""),
            "restart_count": int_or_none(item.get("restart_count")) or 0,
            # Без healthcheck у Docker бывает и «нет ключа», и Status "none". У
            # неработающего контейнера Docker хранит ПОСЛЕДНИЙ статус проверки,
            # которая давно не выполняется: вышедший контейнер числился бы
            # «не проходит проверку» (найдено на стенде 11.09.2026).
            "health": health.get("Status")
            if isinstance(health.get("Status"), str)
            and health.get("Status") not in ("", "none")
            and str(state.get("Status") or "") in ("running", "restarting", "paused")
            else None,
            "compose_project": (str(labels.get("com.docker.compose.project") or "")[:128] or None),
            "compose_service": (str(labels.get("com.docker.compose.service") or "")[:128] or None),
            "oneoff": labels.get("com.docker.compose.oneoff") == "True",
        }
    return current


def load_state():
    """Состояние прошлого принятого такта: (контейнеры, пропавшие); None — точка отсчёта."""
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("v") != STATE_VERSION or not isinstance(data.get("containers"), dict):
        return None
    gone = data.get("gone") if isinstance(data.get("gone"), dict) else {}
    return data["containers"], gone


def load_episodes():
    try:
        with open(EPISODES_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def update_episodes(episodes, current):
    """Когда начался текущий эпизод нездоровья каждого контейнера.

    Пишется КАЖДЫЙ такт, а не после принятого пуша: ключ события unhealthy
    держится на этой отметке. Неудачный пуш пересчитает переход на следующем
    такте — отметка та же, ключ тот же, платформа узнает повтор. А новый эпизод
    после выздоровления получает новую отметку и не теряется как дубль первого.
    """
    result = {}
    for name, c in current.items():
        if c["health"] != "unhealthy":
            continue
        known = episodes.get(name)
        if isinstance(known, dict) and known.get("id") == c["id"] and isinstance(known.get("since"), str):
            result[name] = known
        else:
            # Случайная часть — чтобы два эпизода в одну секунду не получили
            # один ключ. Повтор ключа при неудачном пуше держится на этом файле,
            # а не на времени.
            result[name] = {"id": c["id"], "since": "%s#%s" % (NOW, os.urandom(4).hex())}
    return result


def exit_kind(c):
    if c["oom_killed"] or c["exit_code"] not in CLEAN_EXIT_CODES:
        return "crashed"
    return "stopped"


def event_fingerprint(name, kind, c, p, same, episode):
    """Ключ события — из полей ИМЕННО ЭТОГО перехода.

    Лишнее поле ломает ключ в обе стороны: состояние проверки здоровья в ключе
    сборки давало второй ключ той же сборке, когда контейнер успевал из
    starting стать healthy между потерянным ответом и повтором; а у unhealthy без
    отметки эпизода второй провал проверки получал ключ первого и молча
    отбрасывался платформой как повтор.
    """
    prev = p or {}
    if kind == "deployed":
        return [name, kind, c["id"], c["image_id"], prev.get("id"), prev.get("image_id")]
    if kind == "restarted":
        # Отсчёт — от ПРИНЯТОГО состояния: повтор после потерянного ответа даёт
        # тот же ключ. `finished_at` прежнего состояния различает серии после
        # ручного `docker restart`, который сбрасывает счётчик в ноль.
        return [name, kind, c["id"], int_or_none(prev.get("restart_count")) or 0 if same else 0,
                prev.get("finished_at") if same else None]
    if kind in ("crashed", "stopped"):
        return [name, kind, c["id"], c["finished_at"]]
    if kind == "unhealthy":
        return [name, kind, c["id"], episode]
    return [name, kind, c["id"]]


def make_event(name, kind, c, p, restarts=None, same=False, episode=None):
    exit_known = kind in ("crashed", "stopped") or (
        kind == "restarted" and c["status"] in ("restarting", "exited", "dead")
    )
    at = iso_time(c["finished_at"]) if kind in ("crashed", "stopped", "restarted") else None
    prev = p or {}
    fingerprint = event_fingerprint(name, kind, c, p, same, episode)
    return {
        "key": hashlib.sha256(json.dumps(fingerprint).encode("utf-8")).hexdigest()[:32],
        "kind": kind,
        "name": name,
        "compose_project": c.get("compose_project"),
        "compose_service": c.get("compose_service"),
        "image": c.get("image"),
        "image_id": c.get("image_id"),
        "prev_image": prev.get("image") if kind == "deployed" else None,
        "prev_image_id": prev.get("image_id") if kind == "deployed" else None,
        "exit_code": c.get("exit_code") if exit_known else None,
        "oom_killed": c.get("oom_killed") if exit_known else None,
        "restarts": restarts,
        "health": c.get("health") if kind == "unhealthy" else None,
        "at": at or NOW,
        "_container": c,
    }


def diff(prev, gone, current, episodes, now_epoch):
    """События такта и память о пропавших compose-сервисах для состояния."""
    events = []
    next_gone = {
        name: entry for name, entry in gone.items()
        if isinstance(entry, dict) and name not in current
        and now_epoch - (int_or_none(entry.get("at")) or 0) < GONE_MEMORY_SEC
    }
    for name in sorted(current):
        c = current[name]
        p = prev.get(name) if isinstance(prev.get(name), dict) else None
        same = p is not None and p.get("id") == c["id"]
        exited = c["status"] in ("exited", "dead")

        # Сборка: у имени сменился образ, или появился постоянный compose-сервис.
        # Разовые `compose run` и контейнеры без compose сборкой не считаются —
        # иначе каждая миграция и каждый `docker run --rm` будили бы человека.
        # Сервис, пропавший недавно, сравнивается с тем, каким он был: `compose
        # down` и `up` с тем же образом — не сборка.
        if p is not None and p.get("image_id") != c["image_id"]:
            events.append(make_event(name, "deployed", c, p))
        elif p is None and c["compose_service"] and not c["oneoff"] and not exited:
            was = gone.get(name) if isinstance(gone.get(name), dict) else None
            if was is None or was.get("image_id") != c["image_id"]:
                events.append(make_event(name, "deployed", c, was))

        # Падение с перезапуском — прирост счётчика при том же id. Ручной
        # `docker restart` СБРАСЫВАЕТ счётчик в ноль (проверено 11.09.2026), и
        # убывание падением не считается.
        prev_restarts = int_or_none(p.get("restart_count")) or 0 if same else 0
        if c["restart_count"] > prev_restarts:
            events.append(make_event(name, "restarted", c, p, restarts=c["restart_count"] - prev_restarts, same=same))
        elif exited and iso_time(c["finished_at"]):
            changed = (not same) or p.get("finished_at") != c["finished_at"] or p.get("status") not in ("exited", "dead")
            kind = exit_kind(c)
            # Новый контейнер, вышедший чисто, — это разовая работа, сделанная
            # до конца, а не событие.
            if changed and (kind == "crashed" or p is not None):
                events.append(make_event(name, kind, c, p, same=same))

        if c["health"] == "unhealthy" and not (same and p.get("health") == "unhealthy"):
            episode = (episodes.get(name) or {}).get("since")
            events.append(make_event(name, "unhealthy", c, p, same=same, episode=episode))

    for name in sorted(prev):
        if name not in current and isinstance(prev[name], dict):
            was = prev[name]
            # То же правило, что у сборки: пропажа постоянного compose-сервиса —
            # событие, а разовый `docker run --rm`, переживший такт, давал бы
            # «удалён» после каждой задачи по расписанию.
            if not was.get("compose_service") or was.get("oneoff"):
                continue
            next_gone[name] = {"id": was.get("id"), "image": was.get("image"), "image_id": was.get("image_id"), "at": now_epoch}
            events.append(make_event(name, "removed", {
                "id": str(was.get("id") or ""),
                "image": was.get("image"),
                "image_id": was.get("image_id"),
                "status": "",
                "exit_code": None,
                "oom_killed": False,
                "started_at": "",
                "finished_at": "",
                "restart_count": 0,
                "health": None,
                "compose_project": was.get("compose_project"),
                "compose_service": was.get("compose_service"),
            }, None))
    if len(next_gone) > MAX_CONTAINERS:
        newest = sorted(next_gone.items(), key=lambda item: -(int_or_none(item[1].get("at")) or 0))
        next_gone = dict(newest[:MAX_CONTAINERS])
    return events, next_gone


def sanitize(raw):
    lines = []
    in_key = False
    for line in raw.splitlines():
        # Обрезка ДО регулярок — предел их работы на строку. Итоговая строка
        # всё равно не длиннее LINE_CHARS, и секрет, разрезанный здесь, в хвост
        # не попадает: после вырезания строка режется ещё короче.
        line = CTRL_RE.sub("", ANSI_RE.sub("", line[:LINE_SCAN_CHARS]))
        if "-----BEGIN" in line and "PRIVATE KEY" in line:
            in_key = "-----END" not in line
            lines.append("[закрытый ключ вырезан]")
            continue
        if in_key:
            if "-----END" in line:
                in_key = False
            continue
        for pattern, replacement in SECRET_PATTERNS:
            line = pattern.sub(replacement, line)
        # Обрезка — ПОСЛЕ вырезания: секрет, разрезанный пополам, вырезанию уже
        # не узнаваем.
        lines.append(line[:LINE_CHARS])
    lines = lines[-TAIL_LINES:]
    while lines and len("\n".join(lines).encode("utf-8")) > TAIL_BYTES:
        lines.pop(0)
    text = "\n".join(lines).strip("\n")
    return text or None


def read_tail(c, kind):
    args = ["logs", "--timestamps", "--tail", str(TAIL_LINES)]
    # Контейнер уже поднялся заново: последние строки лога — это новый запуск, а
    # причина падения — до него.
    if kind == "restarted" and c["status"] == "running" and iso_time(c["started_at"]):
        args += ["--until", c["started_at"]]
    args.append(c["id"])
    try:
        proc = subprocess.Popen(["docker"] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = proc.communicate(timeout=LOGS_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None
    except OSError:
        return None
    # Драйвер логов none/syslog читать не даёт — событие уходит без хвоста.
    if proc.returncode != 0:
        return None
    return sanitize(out.decode("utf-8", "replace"))


def inventory(current):
    """Список контейнеров для платформы: только то, что видно в `docker ps`.

    Меток, переменных, команд и томов здесь нет намеренно — список видят все
    участники проекта, а в метках живут правила маршрутов и внутренние адреса.
    Порядок — «что сейчас крутится» сверху: работающие раньше остановленных,
    внутри — compose-сервисы раньше остальных. Остановленные стеки вперемешку с
    работающими прятали главное (снимок стенда 11.09.2026).
    """
    def rank(item):
        name, c = item
        down = c["status"] in ("exited", "dead", "created")
        return (1 if down else 0, 0 if c["compose_service"] else 1, name)

    rows = []
    for name, c in sorted(current.items(), key=rank):
        exited = c["status"] in ("exited", "dead")
        rows.append({
            "name": name,
            "compose_project": c.get("compose_project"),
            "compose_service": c.get("compose_service"),
            "image": c.get("image"),
            "status": c["status"][:32],
            "health": c.get("health"),
            "restarts": c["restart_count"],
            "started_at": iso_time(c["started_at"]),
            "exit_code": c.get("exit_code") if exited else None,
        })
    return rows[:MAX_INVENTORY], max(0, len(rows) - MAX_INVENTORY)


def write_json_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    os.replace(tmp, path)


def main():
    # umask агента выставляется ниже по скрипту, а этот блок идёт раньше.
    os.umask(0o077)
    try:
        current = read_containers()
    except (RuntimeError, OSError) as exc:
        sys.stderr.write("%s\n" % exc)
        return 2
    state = load_state()
    baseline = state is None
    episodes = update_episodes(load_episodes(), current)
    write_json_atomic(EPISODES_PATH, episodes)
    if baseline:
        events, gone = [], {}
    else:
        events, gone = diff(state[0], state[1], current, episodes, int(time.time()))
    events.sort(key=lambda e: KIND_ORDER[e["kind"]])
    kept = events[:MAX_EVENTS]
    tails = 0
    for event in kept:
        c = event.pop("_container")
        if LOGS_ENABLED and event["kind"] in PROBLEM_KINDS and tails < MAX_TAILS:
            tails += 1
            tail = read_tail(c, event["kind"])
            if tail:
                event["log_tail"] = tail
    write_json_atomic(PENDING_PATH, {"v": STATE_VERSION, "containers": current, "gone": gone})
    listed, omitted = inventory(current)
    json.dump(
        {
            "baseline": baseline,
            "dropped": len(events) - len(kept),
            "events": kept,
            "containers": listed,
            "containers_omitted": omitted,
        },
        sys.stdout,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return 0


sys.exit(main())
PY_CONTAINER_EVENTS
  ); then
    CONTAINER_EVENTS_JSON="$_CONTAINER_EVENTS"
  else
    echo "WARNING: события контейнеров не собраны: $(tail -c 300 "${STATE_DIR}/container-events.err" 2>/dev/null)" >&2
  fi
fi

# Состояние контейнеров становится текущим только после принятого пуша.
commit_container_state() {
  if [[ -f "${STATE_DIR}/containers.pending.json" ]]; then
    mv -f "${STATE_DIR}/containers.pending.json" "${STATE_DIR}/containers.json" 2>/dev/null || true
  fi
}

# --- Network totals ---
RX=$(awk '/^[[:space:]]*(eth|en|ens|eno|wlan)/ {rx+=$2; tx+=$10} END {print rx+0}' /proc/net/dev)
TX=$(awk '/^[[:space:]]*(eth|en|ens|eno|wlan)/ {rx+=$2; tx+=$10} END {print tx+0}' /proc/net/dev)
NETWORK_JSON=$(printf '{"rx_bytes":%s,"tx_bytes":%s}' "${RX:-0}" "${TX:-0}")

# --- Health checks ---
CHECKS_JSON="["
FIRST_CHECK=1
HEALTH_URLS_RAW="${TRACEDOCS_HEALTH_URLS:-[]}"
# Parse simple JSON array of strings without jq if needed
URLS=()
if command -v jq >/dev/null 2>&1; then
  while IFS= read -r u; do
    [[ -n "$u" ]] && URLS+=("$u")
  done < <(echo "$HEALTH_URLS_RAW" | jq -r '.[]?' 2>/dev/null || true)
else
  # crude: strip brackets/quotes/commas
  CLEAN=$(echo "$HEALTH_URLS_RAW" | tr -d '[]"' | tr ',' '\n')
  while IFS= read -r u; do
    u=$(echo "$u" | xargs)
    [[ -n "$u" ]] && URLS+=("$u")
  done <<<"$CLEAN"
fi

for url in "${URLS[@]:-}"; do
  [[ -z "$url" ]] && continue
  # Представляемся: без заголовка наш же health-check уходит на публичный
  # адрес, возвращается через nginx как внешний запрос и попадает в счётчик
  # подозрительной активности этого же сервера. Проверено на боевом хосте: в
  # тихом окне верхним источником трафика оказалась сама платформа.
  OUT=$(curl -sS -o /dev/null -w "%{http_code} %{time_total}" \
    -A "ScopeworkHealth/1.0" \
    --connect-timeout 5 --max-time 15 "$url" 2>/dev/null || echo "000 0")
  CODE=$(echo "$OUT" | awk '{print $1}')
  # curl failure → "000"; leading zeros are invalid in JSON (JSON.parse rejects 000)
  if [[ "$CODE" =~ ^[0-9]+$ ]]; then
    CODE=$((10#$CODE))
  else
    CODE=0
  fi
  SECS=$(echo "$OUT" | awk '{print $2}')
  LAT_MS=$(awk -v s="${SECS:-0}" 'BEGIN { printf "%.0f", s * 1000 }')
  OK=false
  if [[ "$CODE" =~ ^2[0-9][0-9]$ ]]; then OK=true; fi
  ESC_URL=$(printf '%s' "$url" | sed 's/\\/\\\\/g; s/"/\\"/g')
  if [[ $FIRST_CHECK -eq 0 ]]; then CHECKS_JSON+=","; fi
  FIRST_CHECK=0
  CHECKS_JSON+=$(printf '{"url":"%s","ok":%s,"status_code":%s,"latency_ms":%s}' \
    "$ESC_URL" "$OK" "${CODE:-0}" "${LAT_MS:-0}")
done
CHECKS_JSON+="]"

# --- Host posture (schema v2) ---
# Цена угрозы зависит от того, можно ли ею воспользоваться: перебор SSH на
# сервере с входом только по ключу — фон, на сервере с открытым паролем — риск.
# Платформа без этих фактов будила владельца одинаково в обоих случаях.
#
# Не смогли определить — отдаём null. «Не знаем» не должно читаться как
# «защищено»: при неизвестном состоянии severity не понижается.
POSTURE_PASSWORD_AUTH="null"
POSTURE_ROOT_LOGIN="null"
POSTURE_FAIL2BAN="null"

if command -v sshd >/dev/null 2>&1; then
  # sshd -T печатает итоговый конфиг со всеми Include и Match — именно то, что
  # реально применяется. Чтение sshd_config глазами врёт: на Ubuntu значение из
  # sshd_config.d перебивает главный файл, мы на это уже наступали.
  SSHD_EFFECTIVE=$(sshd -T 2>/dev/null || true)
  if [[ -n "$SSHD_EFFECTIVE" ]]; then
    case "$(printf '%s' "$SSHD_EFFECTIVE" | awk '$1=="passwordauthentication"{print $2; exit}')" in
    yes) POSTURE_PASSWORD_AUTH="true" ;;
    no) POSTURE_PASSWORD_AUTH="false" ;;
    esac
    ROOT_LOGIN_RAW=$(printf '%s' "$SSHD_EFFECTIVE" | awk '$1=="permitrootlogin"{print $2; exit}')
    case "$ROOT_LOGIN_RAW" in
    yes|no|prohibit-password|forced-commands-only) POSTURE_ROOT_LOGIN="\"${ROOT_LOGIN_RAW}\"" ;;
    without-password) POSTURE_ROOT_LOGIN='"prohibit-password"' ;;
    esac
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  # is-active выходит с ненулевым кодом, когда сервис не запущен, — это не ошибка
  F2B_STATE=$(systemctl is-active fail2ban 2>/dev/null || true)
  case "$F2B_STATE" in
  active) POSTURE_FAIL2BAN="true" ;;
  inactive|failed|activating|deactivating) POSTURE_FAIL2BAN="false" ;;
  esac
fi

POSTURE_JSON=$(printf '{"ssh_password_auth":%s,"ssh_root_login":%s,"fail2ban_active":%s}' \
  "$POSTURE_PASSWORD_AUTH" "$POSTURE_ROOT_LOGIN" "$POSTURE_FAIL2BAN")

# --- Threat pulse (schema v2, optional) ---
TRACEDOCS_THREATS="${TRACEDOCS_THREATS:-1}"
THREAT_WINDOW_SEC="${TRACEDOCS_PUSH_INTERVAL_SEC:-180}"
MAX_THREAT_LINES=10000
# Сколько байт с хвоста access.log брать до обрезки по строкам (нагруженные VPS).
THREAT_TAIL_BYTES="${TRACEDOCS_THREAT_TAIL_BYTES:-8388608}"
# incremental (default) — хвост N строк, в awk только строки новее last_log_key в cursor.
# tail — устаревший: каждый push пересчитывает весь хвост (дубли в pulse).
# cursor — байтовый offset (тихие хосты).
# TRACEDOCS_THREAT_BOOTSTRAP=1 — один раз: только сдвинуть last_log_key, угрозы не считать.
THREAT_READ_MODE="${TRACEDOCS_THREAT_READ_MODE:-incremental}"
# Пустое окно — той же схемы v2, что и окно из awk: оно же затравка слияния, и
# окно v1 в начале свёртки подписало бы v1 всё, что сольётся следом.
THREAT_EMPTY_JSON='{"schema_version":2,"window_sec":'"$THREAT_WINDOW_SEC"',"totals":{"parsed":0,"suspicious":0,"auth_failures":0},"categories":{},"top_ips":[],"top_paths":[],"top_talker":null,"samples":[],"probe_outcomes":{"refused":0,"redirected":0,"served":0,"failed":0},"served_probes":[],"auth_attempts":[],"auth_paths":[],"truncated":false}'
THREATS_JSON="$THREAT_EMPTY_JSON"
# Урезание окна под предел тела приёма. $excess — на сколько байт тело больше.
#
# Режутся списки с путями до 512 символов, с хвоста и по порядку цены потери:
# samples (примеры, всё посчитано в счётчиках), top_paths (для глаз, не для
# судьи), auth_attempts/auth_paths поочерёдно (первые элементы — наибольшие
# концентрации — уходят последними) и ПОСЛЕДНИМ served_probes: это
# доказательство отданного секрета, без него судья не скажет «получил». Счётчики
# окна не трогаются никогда. length считает символы, а байтов в теле не
# меньше: снятых символов ≥ $excess значит снятых байтов тоже ≥ $excess.
THREAT_TRIM_JQ=$(cat <<'JQ_TRIM_EOF'
def n($f): ($f // []) | length;
(tojson | length) as $start
| until(
    ($start - (tojson | length)) >= $excess
      or (n(.samples) + n(.top_paths) + n(.auth_attempts) + n(.auth_paths) + n(.served_probes)) == 0;
    if n(.samples) > 0 then .samples |= .[:-1]
    elif n(.top_paths) > 0 then .top_paths |= .[:-1]
    elif n(.auth_attempts) + n(.auth_paths) > 0 then
      (if n(.auth_attempts) >= n(.auth_paths) then .auth_attempts |= .[:-1] else .auth_paths |= .[:-1] end)
    else .served_probes |= .[:-1]
    end
  )
JQ_TRIM_EOF
)

# Курсоры логов записываются только после успешного ingest — иначе строки,
# не доехавшие из-за сетевого сбоя, уходили бы за курсор безвозвратно.
PENDING_CURSOR_FILES=()
PENDING_CURSOR_JSON=()
commit_threat_cursors() {
  local i
  for i in "${!PENDING_CURSOR_FILES[@]}"; do
    printf '%s\n' "${PENDING_CURSOR_JSON[$i]}" >"${PENDING_CURSOR_FILES[$i]}" 2>/dev/null || true
  done
}

# state/ хранит отпечатки логов и последний pulse — не для чужих глаз на хосте
umask 077
chmod 700 "$STATE_DIR" 2>/dev/null || true

# grep -c печатает "0" И выходит с кодом 1, когда совпадений нет. Из-за этого
# конструкция $(grep -c .) || echo 0 давала в переменной ДВЕ строки ("0\n0"),
# и следующее же [[ -ge ]] падало с arithmetic syntax error на любом пустом логе.
count_nonempty_lines() {
  local n
  n=$(printf '%s' "${1:-}" | grep -c . 2>/dev/null) || n=0
  [[ "$n" =~ ^[0-9]+$ ]] || n=0
  printf '%s' "$n"
}

json_valid() {
  if command -v jq >/dev/null 2>&1; then
    echo "$1" | jq empty 2>/dev/null
    return $?
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s' "$1" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null
    return $?
  fi
  return 0
}

if [[ "$TRACEDOCS_THREATS" != "0" ]]; then
  if ! command -v jq >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "WARNING: jq/python3 not found — threat log parsing disabled (install jq for Threat Analytics)" >&2
    TRACEDOCS_THREATS=0
  fi
fi

if [[ "$TRACEDOCS_THREATS" != "0" ]]; then
  THREAT_LOG_PATHS_RAW="${TRACEDOCS_THREAT_LOG_PATHS:-}"
  THREAT_LOGS=()
  THREAT_UNREADABLE=0
  if [[ -n "$THREAT_LOG_PATHS_RAW" ]]; then
    IFS=',' read -ra _TL <<<"$THREAT_LOG_PATHS_RAW"
    for _p in "${_TL[@]}"; do
      _p=$(echo "$_p" | xargs)
      [[ -f "$_p" ]] || continue
      # Файл есть, но не читается — типично, когда агент крутится не от root.
      # Молча пропустить нельзя: снаружи это неотличимо от «на сервере тихо».
      if [[ -r "$_p" ]]; then THREAT_LOGS+=("$_p"); else THREAT_UNREADABLE=1; fi
    done
  else
    # Лог собственного прокси платформы (Caddy, format json) — в списке по
# умолчанию: без него ветка разбора `ts` не выполнялась бы никогда, а именно
# ради неё разбор и добавлен. Файл читается через тот же гейт `-r`, поэтому на
# хостах без нашего прокси строка ничего не меняет.
for _p in /var/log/nginx/access.log /var/log/traefik/access.log \
          /opt/tracedocs/deploy/proxy/logs/access.json /var/log/auth.log; do
      [[ -f "$_p" ]] || continue
      if [[ -r "$_p" ]]; then THREAT_LOGS+=("$_p"); else THREAT_UNREADABLE=1; fi
    done
  fi

  # Причина уезжает в payload и показывается в интерфейсе рядом с блоком угроз
  THREAT_REASON="ok"
  if [[ ${#THREAT_LOGS[@]} -eq 0 ]]; then
    if [[ "$THREAT_UNREADABLE" -eq 1 ]]; then
      THREAT_REASON="no_read_access"
      echo "WARNING: логи найдены, но недоступны на чтение — угрозы не собираются" >&2
    else
      THREAT_REASON="no_logs"
      echo "WARNING: не найден ни один лог для анализа угроз (TRACEDOCS_THREAT_LOG_PATHS)" >&2
    fi
  fi

  THREAT_AWK=$(mktemp)
  # Локальное время, не UTC: syslog пишет в локальной зоне хоста, и 31 декабря
  # в UTC+3 расхождение дало бы неверный год у всех строк auth.log.
  LOG_YEAR=$(date +%Y)
  LOG_MONTH=$(date +%m)
  cat >"$THREAT_AWK" <<'AWK_EOF'
BEGIN {
  # slice_capped приходит через -v: срез упёрся в лимит строк. Само по себе это
  # ещё не потеря — в инкрементальном режиме мы и так читаем хвост. Потеря есть
  # только если курсор НЕ попал внутрь среза (ни одной уже виденной строки).
  parsed=0; suspicious=0; auth_fail=0; seen_old=0;
  max_log_key = last_log_key
  # Списки имён — массивами через split, а не регулярками: регулярка с
  # двумя десятками альтернатив нечитаема и тянет к интервалам {n}, которых
  # mawk на Debian/Ubuntu не понимает (см. тест против интервалов).
  #
  # file_ext — расширения, при которых путь считается файлом, а не входом
  # (ADR-0060 §4). secret_ext — расширения копий и ключей, по которым путь
  # считается пробой секрета. hidden_secret — скрытые имена, в которых лежат
  # секреты: любой скрытый сегмент был бы шире, и сырой
  # /o/r/raw/main/.github/workflows/ci.yml у Gitea с text/plain поднимал бы
  # тревогу об утечке.
  split("json txt log yml yaml xml ini conf cfg rb py bak old orig save swp sql sqlite db pem key crt p12 pfx zip gz tgz tar rar 7z csv", _names, " ")
  for (_i in _names) file_ext[_names[_i]] = 1
  split("bak old orig save swp sql sqlite db pem key p12 pfx env", _names, " ")
  for (_i in _names) secret_ext[_names[_i]] = 1
  split(".git .git-credentials .svn .hg .bzr .aws .ssh .docker .kube .gnupg .htpasswd .npmrc .pgpass .netrc .vault-token .bash_history .zsh_history .mysql_history .psql_history .s3cfg .boto .pypirc .dockercfg", _names, " ")
  for (_i in _names) hidden_secret[_names[_i]] = 1
}
function month_num(m) {
  if (m == "Jan") return "01"
  if (m == "Feb") return "02"
  if (m == "Mar") return "03"
  if (m == "Apr") return "04"
  if (m == "May") return "05"
  if (m == "Jun") return "06"
  if (m == "Jul") return "07"
  if (m == "Aug") return "08"
  if (m == "Sep") return "09"
  if (m == "Oct") return "10"
  if (m == "Nov") return "11"
  if (m == "Dec") return "12"
  return "00"
}
function log_key_nginx(line,   seg, d, a, sec) {
  if (!match(line, /\[[0-9][0-9]\/[A-Za-z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) return ""
  # RLENGTH считает открывающую «[», закрывающей в шаблоне нет: минус один символ.
  # Было RLENGTH-2 — ключ терял последнюю цифру секунд, и всё в пределах десятка
  # секунд считалось уже посчитанным (бёрст на границе окна пропадал целиком).
  seg = substr(line, RSTART + 1, RLENGTH - 1)
  split(seg, a, ":")
  split(a[1], d, "/")
  if (length(d) < 3 || length(a) < 4) return ""
  sec = a[4]
  sub(/[^0-9].*/, "", sec)
  return sprintf("%s%s%s%s%s%s", d[3], month_num(d[2]), d[1], a[2], a[3], sec)
}
function log_key_auth(line,   mon, mnum, day, a, t, s, y) {
  # RFC3339 — формат journald/rsyslog нового образца, год в строке есть
  if (match(line, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
    s = substr(line, RSTART, RLENGTH)
    return substr(s,1,4) substr(s,6,2) substr(s,9,2) substr(s,12,2) substr(s,15,2) substr(s,18,2)
  }
  if (!match(line, /^[A-Z][a-z][a-z] +[0-9][0-9]? [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) return ""
  mon = substr(line, 1, 3)
  mnum = month_num(mon)
  if (mnum == "00") return ""
  if (!match(line, /[0-9][0-9]? [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) return ""
  s = substr(line, RSTART, RLENGTH)
  split(s, a, " ")
  day = a[1]
  split(a[2], t, ":")
  if (length(t) < 3) return ""
  if (length(day) == 1) day = "0" day
  y = log_year + 0
  # Классический syslog года не пишет. Строка с месяцем «из будущего» — это хвост
  # прошлого года: 1 января курсор от декабрьской строки иначе улетал бы в 2027-й
  # и отбрасывал весь январь.
  if (log_month != "" && mnum + 0 > log_month + 0) y = y - 1
  return sprintf("%04d%s%s%s%s%s", y, mnum, day, t[1], t[2], t[3])
}
function log_key_json(line,   raw, y, mo, d, h, mi, s, ts) {
  # StartUTC — время начала запроса у Traefik. Берём его РАНЬШЕ "time", хотя
  # traefik пишет и то и другое: "time" у него локальное, и перевод часов назад
  # осенью двинул бы ключ курсора вспять — час логов ушёл бы молча. Тот же
  # класс, что граница года в syslog, только повторяется дважды в год.
  raw = extract_json_string(line, "StartUTC")
  if (raw == "") raw = extract_json_string(line, "time")
  if (raw == "") raw = extract_json_string(line, "@timestamp")
  if (raw == "") raw = extract_json_string(line, "timestamp")
  if (raw == "") {
    # Caddy с `format json` — а это НАШ СОБСТВЕННЫЙ прокси (proxy.go) — пишет
    # время ЧИСЛОМ в поле "ts": {"ts":1754654761.123,...}. Ни одна ветка выше
    # его не видела, ключ выходил пустым, и дальше accept_line пропускал такую
    # строку насквозь КАЖДЫЙ пуш, не двигая курсор. То есть на всех хостах с
    # нашим прокси инкрементальности не было вовсе: каждое окно пересчитывало
    # весь хвост, и суточные счётчики раздувались в сотни раз.
    # Caddy пишет "ts" ПЕРВЫМ полем — берём его якорем, чтобы вложенное
    # `{"meta":{"ts":10},...}` не перебило настоящее время строки. Общий поиск
    # оставлен запасным: другие форматы порядок полей не гарантируют.
    if (match(line, /^\{[[:space:]]*"ts"[[:space:]]*:[[:space:]]*"?[0-9]+/)) {
      ts = extract_json_epoch(line, "ts")
      if (ts > 0) return epoch_key(ts)
    }
    ts = extract_json_epoch(line, "ts")
    if (ts > 0) return epoch_key(ts)
    # nginx с JSON-логом обычно пишет $time_local: "08/Aug/2026:12:06:01 +0300".
    # time_iso8601 — канонический вариант у nginx, и он ЧАЩЕ time_local в
    # современных конфигурациях. Его отсутствие означало бы, что смена
    # log_format молча выключает сбор по этому логу.
    raw = extract_json_string(line, "time_iso8601")
    if (raw != "") {
      if (match(raw, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        return substr(raw,1,4) substr(raw,6,2) substr(raw,9,2) substr(raw,12,2) substr(raw,15,2) substr(raw,18,2)
      }
    }
    raw = extract_json_string(line, "time_local")
    if (raw != "") return log_key_clf(raw)
    return ""
  }
  if (!match(raw, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) return ""
  y = substr(raw, 1, 4)
  mo = substr(raw, 6, 2)
  d = substr(raw, 9, 2)
  h = substr(raw, 12, 2)
  mi = substr(raw, 15, 2)
  s = substr(raw, 18, 2)
  return y mo d h mi s
}
# Секунды эпохи → ключ YYYYMMDDHHMMSS в UTC.
#
# Своими руками, без strftime: mawk (Debian по умолчанию) его не имеет, и
# использование strftime молча выключило бы разбор на половине парка.
function epoch_key(ts,   days, rem, y, mo, d, h, mi, sec, leap, dim) {
  # Миллисекунды вместо секунд — обычная ошибка формата лога. Без этой ветки
  # цикл по годам крутился бы 55 тысяч итераций на строку: замер дал 2,16 с на
  # 200 строк, то есть около двух минут на срез в 10 000. Наверху скрипта стоит
  # `flock -n`, поэтому зависший пуш блокирует все следующие — мониторинг
  # умирает целиком и молча.
  if (ts > 100000000000) ts = int(ts / 1000)

  # Санитарные границы: 2000-01-01 .. 2100-01-01.
  #
  # Без них одно испорченное число отравляло курсор НАВСЕГДА: %04d не обрезает,
  # год 57610 даёт пятнадцатизначный ключ, сравнение строковое, и «5…» больше
  # любого настоящего «20…». Ни одна последующая строка курсор уже не
  # превысит, а причина остаётся `ok` — снаружи это выглядит как «сервер
  # тихий». Лечилось только ротацией лога.
  if (ts < 946684800 || ts > 4102444800) return ""

  days = int(ts / 86400)
  rem = ts - days * 86400
  h = int(rem / 3600)
  mi = int((rem - h * 3600) / 60)
  sec = int(rem - h * 3600 - mi * 60)

  y = 1970
  while (1) {
    leap = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 366 : 365
    if (days < leap) break
    days = days - leap
    y = y + 1
  }
  leap = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) ? 1 : 0
  split("31 28 31 30 31 30 31 31 30 31 30 31", dim, " ")
  dim[2] = 28 + leap
  mo = 1
  while (days >= dim[mo]) {
    days = days - dim[mo]
    mo = mo + 1
  }
  d = days + 1
  return sprintf("%04d%02d%02d%02d%02d%02d", y, mo, d, h, mi, sec)
}
# "08/Aug/2026:12:06:01 +0300" → ключ. Формат common log, он же $time_local.
function log_key_clf(raw,   a, off, sign, oh, om, ts) {
  if (!match(raw, /^[0-9][0-9]?[\/][A-Z][a-z][a-z][\/][0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) return ""
  split(substr(raw, RSTART, RLENGTH), a, /[\/:]/)
  if (length(a) < 6) return ""

  # Ключ приводится к UTC.
  #
  # Локальное время в ключе — тот же класс, из-за которого StartUTC берётся
  # раньше "time" у Traefik: перевод часов назад осенью двинул бы курсор
  # вспять, и час логов ушёл бы в seen_old молча. Смещение в строке есть
  # ("+0300"), надо просто его вычесть.
  ts = days_from_civil(a[3] + 0, month_num(a[2]) + 0, a[1] + 0) * 86400 \
       + a[4] * 3600 + a[5] * 60 + a[6]
  if (match(raw, /[+-][0-9][0-9][0-9][0-9]/)) {
    off = substr(raw, RSTART, RLENGTH)
    sign = substr(off, 1, 1) == "-" ? -1 : 1
    oh = substr(off, 2, 2) + 0
    om = substr(off, 4, 2) + 0
    ts = ts - sign * (oh * 3600 + om * 60)
  }
  return epoch_key(ts)
}
# Дней от 1970-01-01 до указанной даты (алгоритм Хиннанта, без циклов).
function days_from_civil(y, m, d,   era, yoe, doy, doe) {
  y = (m <= 2) ? y - 1 : y
  era = int((y >= 0 ? y : y - 399) / 400)
  yoe = y - era * 400
  doy = int((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  doe = yoe * 365 + int(yoe / 4) - int(yoe / 100) + doy
  return era * 146097 + doe - 719468
}
# Числовое поле с дробной частью: {"ts":1754654761.123}. extract_json_number
# обрезает по первому не-цифре и для целой части годится, но здесь нужно
# отличать «поля нет» от «ноль».
function extract_json_epoch(line, key,   pat, rest) {
  # Кавычка после двоеточия необязательна: часть форматов пишет число строкой,
  # ровно как со `status` в extract_json_number.
  pat = "\"" key "\"[[:space:]]*:[[:space:]]*\"?"
  if (!match(line, pat)) return 0
  rest = substr(line, RSTART + RLENGTH)
  if (!match(rest, /^[0-9]+/)) return 0
  return substr(rest, RSTART, RLENGTH) + 0
}
function line_log_key(line) {
  if (mode == "auth") return log_key_auth(line)
  if (line ~ /^\{/) return log_key_json(line)
  return log_key_nginx(line)
}
function accept_line(line,   k) {
  if (use_ts_filter + 0 == 0) return 1
  k = line_log_key(line)
  if (k == "") {
    # Строка, время которой мы не распознали.
    #
    # Раньше она принималась молча — и это было худшим из вариантов: ключ не
    # растёт, курсор не двигается, а строка попадает в счёт КАЖДЫЙ пуш. Ровно
    # так суточные счётчики раздувались в сотни раз на логах, формат времени
    # которых не поддержан.
    #
    # Пока курсора нет (первый проход), считаем как раньше: иначе первое окно
    # на неизвестном формате оказалось бы пустым и молчаливым. Как только
    # курсор появился, нераспознанная строка отбрасывается, а её количество
    # уходит наружу — по нему видно, что формат надо поддержать.
    # Считаем только фактически отброшенные: на первом проходе строка
    # принимается, и включать её в счётчик потерь значило бы завышать потерю.
    if (last_log_key == "") return 1
    unkeyed++
    return 0
  }
  if (last_log_key != "" && k <= last_log_key) {
    # Хотя бы одна уже виденная строка в срезе означает, что курсор попал
    # внутрь среза — значит ничего не потеряно, каким бы срез ни был.
    seen_old++
    return 0
  }
  if (k > max_log_key) max_log_key = k
  return 1
}
function is_auth_word(w) {
  return (w == "login" || w == "signin" || w == "sign-in" || w == "auth" || w == "admin" \
    || w == "session" || w == "token" || w == "password" || w == "verify-password" || w == "verify_password")
}
# Файл со словом входа в имени — файл, а не вход (ADR-0060 §4).
#
# Ночью 10.09.2026 сканер секретов запросил /auth.json, /token.txt, /.vault-token
# по разу; общий предел nginx ответил им 429, а классификатор, найдя в именах
# слово из списка входа, записал разведку в подбор пароля. Разбудила человека
# ошибочная тревога, верная категория ушла в шум.
#
# PHP расширением файла не считается: /admin/index.php — страница входа, и
# подбор на ней отличает концентрация попыток, а не имя.
function is_file_like_path(pl,   n, i, parts, ext) {
  n = split(pl, parts, "/")
  for (i = 1; i <= n; i++) {
    if (substr(parts[i], 1, 1) == ".") return 1
  }
  ext = last_segment_ext(pl)
  return (ext != "" && (ext in file_ext))
}
# Расширение ПОСЛЕДНЕГО НЕПУСТОГО сегмента — как filter(Boolean) в classify.ts.
#
# По последнему элементу split косая в конце превращала файл в «каталог без
# расширения», и /auth.json/ под пределом 429 снова становился подбором
# пароля. Точка в начале сегмента расширением не считается (".env" — имя).
function last_segment_ext(pl,   n, i, parts) {
  n = split(pl, parts, "/")
  for (i = n; i >= 1; i--) {
    if (parts[i] == "") continue
    if (match(parts[i], /\.[^.]*$/) && RSTART > 1) return substr(parts[i], RSTART + 1)
    return ""
  }
  return ""
}
function has_env_fragment(pl) {
  return (index(pl, "/.env") || index(pl, "/.git/") || index(pl, "/wp-config") \
    || index(pl, "/.aws/") || index(pl, "/actuator/"))
}
function has_cms_fragment(pl) {
  return (index(pl, "/wp-admin") || index(pl, "/wp-login") || index(pl, "/xmlrpc.php") \
    || index(pl, "/phpmyadmin") || index(pl, "/administrator/"))
}
# Проба (ADR-0060 §3, probe_outcomes): фрагмент env или CMS, любой скрытый
# сегмент, кроме ровно .well-known, или расширение копии/ключа.
function is_probe_path(pl,   n, i, parts, ext) {
  if (has_env_fragment(pl) || has_cms_fragment(pl)) return 1
  n = split(pl, parts, "/")
  for (i = 1; i <= n; i++) {
    if (substr(parts[i], 1, 1) == "." && parts[i] != ".well-known") return 1
  }
  ext = last_segment_ext(pl)
  return (ext != "" && (ext in secret_ext))
}
# Секретный путь (served_probes): то, отдача чего и есть утечка. Уже пробы: без
# CMS (страница входа WordPress секретом не бывает) и без actuator целиком —
# /actuator/health отвечает 200 законно, а env, heapdump и configprops отдают
# ключи. Скрытые сегменты — только из списка hidden_secret или .env с
# продолжением через . _ - (.env.local, .env_copy).
function is_secret_path(pl,   n, i, parts, seg, c, ext) {
  if (index(pl, "/wp-config") || index(pl, "/actuator/env") || index(pl, "/actuator/heapdump") \
      || index(pl, "/actuator/configprops")) return 1
  n = split(pl, parts, "/")
  for (i = 1; i <= n; i++) {
    seg = parts[i]
    if (seg == "") continue
    if (seg in hidden_secret) return 1
    if (substr(seg, 1, 4) == ".env") {
      if (length(seg) == 4) return 1
      c = substr(seg, 5, 1)
      if (c == "." || c == "_" || c == "-") return 1
    }
  }
  ext = last_segment_ext(pl)
  return (ext != "" && (ext in secret_ext))
}
function is_auth_path(pl,   n, i, parts, seg, m, j, words) {
  if (is_file_like_path(pl)) return 0
  # Слово, а не подстрока, и ровно так же, как isSensitiveAuthPath в classify.ts:
  # сегмент целиком или его слова через - _ . Подстрочный матч записывал в
  # брутфорс любой 401/403 на путях вроде /api/products/authentic-goods, а
  # прежняя регулярка с разделителями по краям считала входом /sign-in-page,
  # которого TS и Go входом не считают.
  n = split(pl, parts, "/")
  for (i = 1; i <= n; i++) {
    seg = parts[i]
    if (seg == "") continue
    if (is_auth_word(seg)) return 1
    m = split(seg, words, /[-_.]/)
    for (j = 1; j <= m; j++) {
      if (is_auth_word(words[j])) return 1
    }
  }
  return 0
}
# Расширения статики: 404 на битой картинке — не перебор путей, а мусор,
# который раздувал счётчик подозрительных событий на каждом сайте.
function is_static_asset(pl) {
  return pl ~ /\.(jpg|jpeg|png|gif|webp|avif|svg|ico|bmp|css|js|mjs|map|woff|woff2|ttf|eot|otf|mp4|webm|mp3|pdf|zip)$/
}
# Сканер представляется сам — признак сильнее любого пути.
function is_scanner_ua(ua) {
  return ua ~ /nikto|sqlmap|zgrab|masscan|nmap|acunetix|dirbuster|gobuster|wpscan|nuclei/
}
# Собственные зонды платформы: health-check, проверка доступности, краулер
# аудита. Список обязан совпадать с apps/web/src/lib/deploy/platformUserAgent.ts —
# два несогласованных разъедутся на первой правке.
function is_own_probe(ul) {
  # tracedocs-deploy-agent — такт агента развёртывания. Он идёт в обратную
  # сторону, с сервера на платформу, и попадает в лог САМОЙ платформы, которая
  # тоже является наблюдаемым сервером. Раз в минуту с каждого подключённого
  # сервера — этого хватает, чтобы стать «самым активным адресом» в сводке и
  # вытеснить оттуда настоящего атакующего.
  # Оба имени: на серверах ещё стоят агенты и зонды, поставленные до
  # переименования, и они представляются прежним UA до переустановки.
  return ul ~ /(scopework|tracedocs)(health|uptime|siteauditbot)/ || ul ~ /(scopework|tracedocs)-deploy-agent/
}
function classify_http(ip, path, status, ua,   pl, ul) {
  pl = tolower(path)
  ul = tolower(ua)
  # Свои запросы не события. Health-check, бьющий в отсутствующий URL, иначе
  # давал до 480 «событий перебора путей» в сутки — на пустом месте.
  if (ua != "" && is_own_probe(ul)) return ""
  if (ua != "" && is_scanner_ua(ul)) return "scanner_ua"
  # Фрагменты — подстрокой через index(), как `includes` в classify.ts, а не
  # регуляркой. Регулярка разошлась с TS дважды: якорь ^ у wp-admin пропускал
  # вложенный WordPress (/blog/wp-admin/…), а wp-config без ведущей косой
  # записывал в разведку секретов любой путь с этим словом внутри.
  if (has_env_fragment(pl)) return "env_probe"
  if (has_cms_fragment(pl)) return "cms_scan"
  if (is_auth_path(pl)) {
    if (status == 429) return "rate_limited"
    if (status == 401 || status == 403) return "auth_brute"
  }
  if (status == 404 && !is_static_asset(pl)) return "api_fuzz"
  return ""
}
# Приватные и служебные адреса — это наш собственный прокси и контейнеры.
# В «самом активном IP» им не место: внутренний трафик и порог всплеска
# перешагнёт, и настоящего атакующего из этого поля вытеснит.
function is_internal_ip(ip) {
  if (ip ~ /^127\./ || ip ~ /^10\./ || ip ~ /^192\.168\./ || ip ~ /^169\.254\./) return 1
  if (ip ~ /^172\.(1[6-9]|2[0-9]|3[01])\./) return 1
  if (ip == "::1" || ip ~ /^[fF][cCdD]/ || ip ~ /^[fF][eE]80:/) return 1
  return 0
}
# Все запросы на IP, а не только подозрительные: без этого объёмная атака
# (флуд 200 OK) не видна ни в одном счётчике.
# raw — путь запроса вместе с query: признак предзагрузки Next.js живёт там.
function note_request(ip, raw, status) {
  if (ip == "" || is_internal_ip(ip)) return
  reqc[ip]++
  if (is_background(raw, status)) bgc[ip]++
}
# Фоновый запрос браузера, а не действие человека: предзагрузка страниц
# Next.js (?_rsc=) и 304 на статику и манифест. Правило и причина —
# isBackgroundRequest в packages/threat-analytics/src/classify.ts; судья
# считает такие запросы во всплеске с весом четверть, а не вычёркивает.
function is_background(raw, status,   q, pl) {
  q = index(raw, "?")
  if (q > 0 && ("&" substr(raw, q + 1)) ~ /&_rsc=/) return 1
  if (status != 304) return 0
  pl = tolower(raw)
  sub(/\?.*/, "", pl)
  return is_static_asset(pl) || pl ~ /\.webmanifest$/
}
# path — сырой путь без query: по нему классифицируют и дедуплицируют.
# Наружу (top_paths, samples, served_probes, auth_attempts, auth_paths) уходит
# только маскированная копия — см. mask_path_secrets.
function note(cat, ip, path, status,   key, opath) {
  if (cat == "") return
  # Один и тот же 404 с одного IP — это одна находка, а не сотня: битая ссылка
  # на сайте иначе раздувала «подозрительные события» и роняла health score.
  # Ключ — сырой путь, как у Go-агента: маска свела бы в одну находку перебор
  # десятков разных токенов /share/<token>.
  if (cat == "api_fuzz") {
    key = ip SUBSEP substr(path, 1, 512)
    if (seen_fuzz[key]) return
    seen_fuzz[key] = 1
  }
  suspicious++
  cats[cat]++
  if (cat == "auth_brute" || cat == "rate_limited") auth_fail++
  # Пустые ключи не копим: у ssh_brute пути нет, а запись {"path":""} проваливала
  # схему на платформе и уносила с собой весь блок threats.
  if (ip != "") {
    ipc[ip]++
    ipc_cat[ip SUBSEP cat]++
  }
  # Сначала маска, потом обрезка: обрезанный посередине токен короче порога
  # маски и уехал бы наружу своим началом.
  opath = (path != "") ? substr(mask_path_secrets(path), 1, 512) : ""
  if (opath != "") pathc[opath]++
  if (sample_n < 10) {
    sample_n++
    samples[sample_n] = ip SUBSEP opath SUBSEP status SUBSEP cat
  }
  if ((cat == "auth_brute" || cat == "rate_limited") && ip != "" && opath != "") note_auth_attempt(ip, opath)
}
# Исход пробы (ADR-0060 §3): отказали, перенаправили, отдали. Всё, что не
# 2xx/3xx/5xx, — отказ: 4xx, 444 nginx, 0 оборванного Caddy.
#
# По СВОЙСТВУ ПУТИ и до категории, а не по категории. По категории исход
# терялся ровно там, где он важнее всего: сканер, назвавшийся zgrab, получает
# scanner_ua, и его /backup.sql с ответом 200 не попадал ни в исход, ни в
# served_probes; /.ssh/id_rsa без такого UA — api_fuzz, а не env_probe.
# Коды ответов на пробы до этого не хранились нигде, кроме десяти образцов, и
# на вопрос «получил ли он что-нибудь» человек отвечал себе сам, в логах.
function note_probe_outcome(path, status, bytes, ct,   pl) {
  pl = tolower(path)
  if (!is_probe_path(pl)) return
  if (status >= 200 && status <= 299) {
    probe_served++
    if (is_secret_path(pl)) note_served(path, status, bytes, ct)
  } else if (status >= 300 && status <= 399) {
    probe_redirected++
  } else if (status >= 500 && status <= 599) {
    probe_failed++
  } else {
    probe_refused++
  }
}
# served_probes — доказательство, что секрет отдали. Три правила против того,
# чтобы доказательство вытеснил шум:
# - HTML в список не попадает (в исход считается): это страница приложения —
#   SPA-оболочка, 404 с кодом 200, форма входа, — а не файл. Десяток таких проб
#   занимал все десять мест, и отданный следом настоящий .git/config в список
#   уже не влезал.
# - не больше трёх путей одного размера: трёх хватает судье, чтобы узнать общую
#   заглушку, остальные места остаются под разные ответы.
# - повтор пути второго места не занимает: размер — наибольший из известных
#   (HEAD даёт 0 байт, GET того же пути — файл), тип дополняется, если его не было.
# Путь маскированный: «один элемент на путь» — на тот путь, который увидит
# платформа, иначе в списке встали бы два одинаковых /share/<token>.
function note_served(path, status, bytes, ct,   c, opath, i, same) {
  c = ct
  sub(/^[[:space:]]+/, "", c)
  sub(/[[:space:]]+$/, "", c)
  if (tolower(substr(c, 1, 9)) == "text/html") return
  c = substr(c, 1, 100)
  opath = substr(mask_path_secrets(path), 1, 512)
  if (opath == "") return
  if (opath in served_idx) {
    i = served_idx[opath]
    if (bytes != "" && (served_bytes[i] == "" || bytes + 0 > served_bytes[i] + 0)) served_bytes[i] = bytes
    if (served_ct[i] == "" && c != "") served_ct[i] = c
    return
  }
  if (served_n >= 10) return
  if (bytes != "") {
    same = 0
    for (i = 1; i <= served_n; i++) {
      if (served_bytes[i] == bytes) same++
    }
    if (same >= 3) return
  }
  served_n++
  served_idx[opath] = served_n
  served_path[served_n] = opath
  served_status[served_n] = status
  served_bytes[served_n] = bytes
  served_ct[served_n] = c
}
# Пары (адрес, путь) среди попыток входа (ADR-0060 §5): подбор пароля — это
# концентрация на одном пути, а не сумма. Двадцать разных файлов по разу под
# общим пределом 429 выглядели суммой как подбор и будили человека.
#
# auth_paths — то же по пути через все адреса, с числом разных адресов:
# шестьдесят адресов по девять попыток на /login не набирают порог пары ни у
# одного из них, и распределённый подбор без этого поля не виден вовсе.
function note_auth_attempt(ip, opath,   key) {
  key = ip SUBSEP opath
  if (!(opath in path_count)) {
    path_n++
    path_list[path_n] = opath ""
  }
  path_count[opath]++
  if (!(key in pair_count)) {
    pair_n++
    # Конкатенация с "" — строка, а не число: адрес из $1 awk считает
    # числоподобным, и сравнение при сортировке ушло бы в арифметику.
    pair_ip[pair_n] = ip ""
    pair_path[pair_n] = opath ""
    pair_key[pair_n] = key
    path_ips[opath]++
  }
  pair_count[key]++
}
# Порядок auth_attempts: count по убыванию, затем path, затем ip по возрастанию —
# тот же, что в фикстуре window-cases.json, иначе при равных счётчиках три
# реализации отдали бы разные первые пять.
function pair_before(a, b,   ca, cb) {
  ca = pair_count[pair_key[a]]
  cb = pair_count[pair_key[b]]
  if (ca != cb) return ca > cb
  if (pair_path[a] != pair_path[b]) return pair_path[a] < pair_path[b]
  return pair_ip[a] < pair_ip[b]
}
# Порядок auth_paths: count по убыванию, затем path по возрастанию.
function path_before(a, b,   ca, cb) {
  ca = path_count[path_list[a]]
  cb = path_count[path_list[b]]
  if (ca != cb) return ca > cb
  return path_list[a] < path_list[b]
}
# Число из лога — строкой, без ведущих нулей и без округления.
#
# Через +0 и %d mawk печатает целые больше 2^31 в виде 5e+09, а ведущий ноль
# («0412») делает JSON окна невалидным. Больше 15 цифр — не размер ответа, а
# мусор: считаем неизвестным.
function norm_count(s) {
  if (s !~ /^[0-9]+$/) return ""
  sub(/^0+/, "", s)
  if (s == "") s = "0"
  if (length(s) > 15) return ""
  return s
}
function extract_json_string(line, key,   pat, rest) {
  pat = "\"" key "\"[[:space:]]*:[[:space:]]*\""
  if (!match(line, pat)) return ""
  rest = substr(line, RSTART + RLENGTH)
  if (!match(rest, /^[^"]+/)) return ""
  return substr(rest, RSTART, RLENGTH)
}
# Строка или ПЕРВЫЙ элемент массива строк: {"k":"v"} и {"k":["v",…]}.
#
# Caddy пишет заголовки массивами — "User-Agent":["sqlmap/1.7"]. Поиск плоской
# строки на его логе не находил User-Agent вовсе, и на всех хостах с нашим
# прокси не работали ни scanner_ua, ни исключение собственных зондов: краулер
# аудита платформы записывался в разведку.
function extract_json_first_string(line, key,   pat, rest) {
  pat = "\"" key "\"[[:space:]]*:[[:space:]]*(\\[[[:space:]]*)?\""
  if (!match(line, pat)) return ""
  rest = substr(line, RSTART + RLENGTH)
  if (!match(rest, /^[^"]+/)) return ""
  return substr(rest, RSTART, RLENGTH)
}
# Тип содержимого ОТВЕТА у Caddy — только внутри resp_headers.
#
# У POST-запроса свой Content-Type лежит раньше, в request.headers, и первое
# совпадение по всей строке выдало бы тип того, что прислал клиент. Подменить
# ключ "resp_headers" нельзя: кавычка внутри JSON-строки экранирована, а имена
# заголовков Caddy канонизирует с заглавной буквы.
function resp_content_type(line,   i) {
  i = index(line, "\"resp_headers\"")
  if (i == 0) return ""
  return extract_json_first_string(substr(line, i), "Content-Type")
}
# Счётчик, отличающий «поля нет» ("") от «ноль» ("0") — в отличие от
# extract_json_number, которому ноль и отсутствие безразличны.
function extract_json_count(line, key,   pat, rest) {
  pat = "\"" key "\"[[:space:]]*:[[:space:]]*\"?"
  if (!match(line, pat)) return ""
  rest = substr(line, RSTART + RLENGTH)
  if (!match(rest, /^[0-9]+/)) return ""
  return norm_count(substr(rest, RSTART, RLENGTH))
}
function extract_json_number(line, key,   pat, rest) {
  # Кавычка после двоеточия необязательна: nginx в JSON-логе пишет "status":"200"
  # (у него все переменные — строки), и без этого допуска статус читался нулём,
  # то есть 401 и 404 не классифицировались вообще. Строки при этом считались
  # разобранными — снаружи выглядело как «трафик есть, атак нет».
  pat = "\"" key "\"[[:space:]]*:[[:space:]]*\"?"
  if (!match(line, pat)) return 0
  rest = substr(line, RSTART + RLENGTH)
  if (!match(rest, /^[0-9]+/)) return 0
  return substr(rest, RSTART, RLENGTH) + 0
}
function mask_path_secrets(path,   n, i, parts, out, seg, prev) {
  # Ключ доступа у нас живёт В ПУТИ, а не в query. Query здесь режется давно и
  # с объяснением; на путь то же рассуждение не распространили, а все ссылки
  # платформы устроены как /share/<токен>, /meet/<токен>, /g/<токен>,
  # /w/<токен>, /acceptance/<токен>.
  #
  # ПОЧЕМУ ЭТО НЕ ТЕОРИЯ. 404 по ДЕЙСТВУЮЩЕМУ токену — штатное событие: у
  # отменённой встречи страница отвечает 404, а подпись ссылки остаётся годной
  # (срока жизни у неё нет по замыслу). Такой 404 классифицируется как api_fuzz
  # и уезжает в pathc/samples, оттуда в threat_snapshots на 30 дней и в панель
  # «Угрозы», которую видит любой участник проекта. То есть рабочий ключ от
  # чужой встречи показывался посторонним внутри интерфейса.
  #
  # ДВА ПРАВИЛА, А НЕ ОДНО. По имени раздела — точное, ловит и короткий токен.
  # По длине и алфавиту — на вырост: новый раздел с ключом в пути закроется сам,
  # без правки этого места.
  #
  # МАСКА ТОЛЬКО НА ВЫХОДЕ. Классификация идёт по сырому пути: словарные пути
  # оказались не всегда короткими — /.env.production.local.backup длиннее
  # порога, маска превращала его в /<token>, и проба секрета уходила в перебор
  # путей. Маскируется лишь то, что покидает сервер: top_paths, samples,
  # served_probes, auth_attempts.
  #
  # БЕЗ ИНТЕРВАЛОВ {n} В РЕГУЛЯРКАХ: на Debian/Ubuntu awk — это mawk, он их не
  # понимает, и проверка длины идёт через length(), а не шаблоном.
  n = split(path, parts, "/")
  out = ""
  for (i = 1; i <= n; i++) {
    seg = parts[i]
    prev = (i > 1 ? parts[i - 1] : "")
    if (seg != "" && (prev == "share" || prev == "meet" || prev == "g" || prev == "w" || prev == "acceptance")) {
      seg = "<token>"
    } else if (length(seg) >= 24 && seg ~ /^[A-Za-z0-9_.-]+$/) {
      seg = "<token>"
    }
    out = out (i > 1 ? "/" : "") seg
  }
  return out
}
function parse_json_line(line,   ip, path, raw, status, cat, ua, bytes, ct) {
  # Гейт по ЛЮБОМУ известному полю статуса. Раньше здесь стоял только
  # /"status"/, а Traefik пишет DownstreamStatus — и все его строки отсекались
  # ДО parsed++, так что в снапшоте не оставалось даже следа: ноль угроз при
  # нулевом parsed неотличим от «атак не было». На инфраструктуре под Coolify
  # traefik стоит на каждом хосте, то есть слепым был весь парк.
  if (line !~ /"status"/ && line !~ /"DownstreamStatus"/ && line !~ /"OriginStatus"/) return
  ip = extract_json_string(line, "remote_ip")
  if (ip == "") ip = extract_json_string(line, "remote_addr")
  # ClientHost — адрес без порта; ClientAddr у traefik идёт вместе с портом и
  # для группировки по IP не годится.
  if (ip == "") ip = extract_json_string(line, "ClientHost")
  path = extract_json_string(line, "uri")
  if (path == "") path = extract_json_string(line, "request_uri")
  if (path == "") path = extract_json_string(line, "RequestPath")
  status = extract_json_number(line, "status")
  # DownstreamStatus — то, что увидел клиент, и именно он определяет цену
  # события: 401 от приложения, превращённый прокси в 200, перебором не был.
  # OriginStatus — запасной вариант, когда downstream не записан.
  if (status == 0) status = extract_json_number(line, "DownstreamStatus")
  if (status == 0) status = extract_json_number(line, "OriginStatus")
  if (path == "") return
  raw = path
  # Query режем до классификации и до попадания в счётчики: /reset-password?token=…
  # иначе уложил бы токен в top_paths, а оттуда в БД на 30 дней и в письмо.
  sub(/\?.*/, "", path)
  if (path == "") return
  parsed++
  note_request(ip, raw, status)
  ua = extract_json_first_string(line, "User-Agent")
  if (ua == "") ua = extract_json_string(line, "request_User-Agent")
  # Размер тела ответа: size у Caddy, body_bytes_sent у nginx в JSON,
  # DownstreamContentSize у Traefik. Без размера платформа не отличит общую
  # заглушку SPA (одинаковый размер у всех проб) от отданного файла.
  bytes = extract_json_count(line, "size")
  if (bytes == "") bytes = extract_json_count(line, "body_bytes_sent")
  if (bytes == "") bytes = extract_json_count(line, "DownstreamContentSize")
  ct = resp_content_type(line)
  if (!(ua != "" && is_own_probe(tolower(ua)))) note_probe_outcome(path, status, bytes, ct)
  cat = classify_http(ip, path, status, ua)
  note(cat, ip, path, status)
}
# nginx: классический combined, прежний формат tracedocs (xff, host) и текущий,
# где между host и User-Agent стоит ct="$sent_http_content_type". Новые поля
# вставляются перед User-Agent, потому что он читается как ПОСЛЕДНЕЕ
# закавыченное поле строки (docs/runbooks/threat-analytics.md).
function parse_combined(line,   ip, path, raw, status, cat, rest, ua, bytes, ct) {
  # Гейт по структуре записи, а не по шаблону IPv4: на dual-stack хосте
  # (listen [::]:443 — дефолт у Hetzner/DO) весь IPv6-трафик был невидим,
  # причём выход происходил до parsed++, так что и следа в снапшоте не оставалось.
  ip = $1
  if (ip !~ /^[0-9a-fA-F:.]+$/) return
  if (!match(line, /"[A-Z]+ [^"]+"/)) return
  rest = substr(line, RSTART + 1, RLENGTH - 2)
  sub(/^[^ ]+ /, "", rest)
  sub(/ HTTP.*/, "", rest)
  path = rest
  raw = rest
  # Query режем до классификации: /reset-password?token=… иначе клало бы токен
  # в top_paths и samples, а оттуда — в БД на 30 дней и в письмо.
  sub(/\?.*/, "", path)
  if (path == "") return
  if (!match(line, /HTTP\/[0-9.]+" [0-9][0-9][0-9]/)) return
  status = substr(line, RSTART + RLENGTH - 3, 3) + 0
  # $body_bytes_sent идёт сразу за статусом; «-» (так пишет apache при нуле)
  # считаем неизвестным, а не нулём.
  bytes = ""
  rest = substr(line, RSTART + RLENGTH)
  if (match(rest, /^ [0-9]+/)) bytes = norm_count(substr(rest, 2, RLENGTH - 1))
  # Сырая кавычка в строке nginx бывает только разделителем полей: внутри
  # значений он пишет её как \x22. Поэтому « ct="» не подделать ни путём, ни
  # referer'ом. «-» — заголовка не было.
  ct = ""
  if (match(line, / ct="[^"]*"/)) {
    ct = substr(line, RSTART + 5, RLENGTH - 6)
    if (ct == "-") ct = ""
  }
  # User-Agent в combined — последнее поле в кавычках
  ua = ""
  if (match(line, /"[^"]*"[[:space:]]*$/)) {
    ua = substr(line, RSTART + 1, RLENGTH - 2)
    sub(/[[:space:]]+$/, "", ua)
  }
  parsed++
  note_request(ip, raw, status)
  if (!(ua != "" && is_own_probe(tolower(ua)))) note_probe_outcome(path, status, bytes, ct)
  cat = classify_http(ip, path, status, ua)
  note(cat, ip, path, status)
}
function parse_auth(line,   ip, cat, user, key, msg, pair) {
  # Подмена адреса текстом, который выбирает подключающийся.
  #
  # Имя пользователя и причина разрыва попадают в строку дословно, с пробелами:
  # логин `x from 198.51.100.7` даёт «Invalid user x from 198.51.100.7 from
  # 203.0.113.5 port 22», а причина разрыва — целое «Invalid user a1 from
  # 198.51.100.7 port 1» внутри «Received disconnect from …». Разбор по первому
  # или просто последнему `from` засчитывал попытку адресу, выбранному
  # атакующим. Счётчик адреса участвует в автоблоке — посторонний с доступом к
  # порту 22 закрывал бы сайт клиента другому человеку.
  #
  # Поэтому два якоря, которые подключающийся не двигает:
  # - сообщение начинается СРАЗУ после ПЕРВОГО тега sshd[pid]: — всё, что до
  #   него, пишет syslog, а подделанный тег внутри причины разрыва уже не первый;
  #   sshd-session — имя процесса у OpenSSH 9.8+, без него на свежих Debian и
  #   Ubuntu попытки не считались бы вовсе;
  # - пара « from <адрес> port <число>» стоит в КОНЦЕ строки (sshd дописывает
  #   её сам после имени; допустим только его хвост « ssh2»). Строки процесса до
  #   входа несут « [preauth]» и под якорь не попадают.
  if (!match(line, /sshd(-session)?\[[0-9]+\]: /)) return
  msg = substr(line, RSTART + RLENGTH)
  if (substr(msg, 1, 20) != "Failed password for " && substr(msg, 1, 13) != "Invalid user ") return
  if (!match(msg, / from [0-9a-fA-F:.]+ port [0-9]+( ssh2)?[[:space:]]*$/)) return
  pair = substr(msg, RSTART, RLENGTH)
  user = substr(msg, 1, RSTART - 1)
  ip = pair
  sub(/^ from /, "", ip)
  sub(/ port .*$/, "", ip)
  if (ip == "") return

  # Одна попытка входа — одно событие, а не столько, сколько строк написал sshd.
  #
  # Неудачный вход несуществующим пользователем даёт как минимум две строки:
  # «Invalid user admin from …» и «Failed password for invalid user admin
  # from …», а с PAM и preauth — четыре. Счёт по строкам завышал брутфорс в
  # два-четыре раза, и именно поэтому «1726 событий за сутки» выглядели
  # катастрофой там, где была обычная фоновая долбёжка.
  #
  # Ключ дедупликации — пара (адрес, пользователь) в пределах окна. Секунду в
  # ключ не берём: sshd пишет строки одной попытки с разными метками времени,
  # и с секундой дедупликация не сработала бы вовсе.
  # Имя пользователя стоит непосредственно перед " from <адрес>" во всех трёх
  # формах sshd: «for root from …», «for invalid user admin from …»,
  # «Invalid user admin from …». Брать по слову «user» нельзя: в самой частой
  # строке («Failed password for root from») этого слова нет вовсе, и все
  # попытки с одного адреса схлопывались бы в одну. Слово берётся перед той же
  # концевой парой, из которой взят адрес. Пустое имя («Invalid user  from»,
  # два пробела) даёт пустое слово, и попытка всё равно считается.
  sub(/.* /, "", user)
  key = ip SUBSEP user
  if (auth_seen[key]) {
    # Строку всё равно считаем разобранной: она не потеряна, просто уже учтена.
    parsed++
    return
  }
  auth_seen[key] = 1

  parsed++
  note_request(ip, "", 0)
  cat = "ssh_brute"
  note(cat, ip, "", 0)
}
function json_escape(s) {
  gsub(/\\/, "\\\\", s)
  gsub(/"/, "\\\"", s)
  # [[:cntrl:]] вместо \x00-\x1f: \x-эскейпы в регулярках — расширение gawk,
  # на mawk/busybox агента они не работают, а управляющий символ в пути
  # (их шлют сканеры) делает JSON окна невалидным.
  gsub(/[[:cntrl:]]/, "", s)
  return s
}
function emit_sample(i,   p, spath, sip, wrote) {
  split(samples[i], p, SUBSEP)
  if (i > 1) printf ","
  sip = json_escape(p[1])
  spath = json_escape(p[2])
  printf "{"
  wrote = 0
  if (sip != "") { printf "\"ip\":\"%s\"", sip; wrote = 1 }
  # Пустые поля не печатаем: схема на платформе требует непустой path,
  # и запись {"path":""} отбраковывала бы всё окно.
  if (spath != "") { if (wrote) printf ","; printf "\"path\":\"%s\"", spath; wrote = 1 }
  if (wrote) printf ","
  printf "\"status\":%s,\"category\":\"%s\"}", p[3], p[4]
}
# Факты исхода окна v2. Пустые списки печатаются всегда: наличие
# auth_attempts — признак агента v2, и судья по нему выбирает правило подбора
# (концентрация на пути вместо суммы по окну).
function emit_outcome_facts(   i, r, best, emitted, taken, taken_path) {
  printf ",\"probe_outcomes\":{\"refused\":%d,\"redirected\":%d,\"served\":%d,\"failed\":%d}", \
    probe_refused, probe_redirected, probe_served, probe_failed
  printf ",\"served_probes\":["
  for (i = 1; i <= served_n; i++) {
    if (i > 1) printf ","
    printf "{\"path\":\"%s\",\"status\":%d,\"bytes\":%s,\"content_type\":%s}", \
      json_escape(served_path[i]), served_status[i], (served_bytes[i] == "" ? "null" : served_bytes[i]), \
      (served_ct[i] == "" ? "null" : "\"" json_escape(served_ct[i]) "\"")
  }
  # Первые пять — выбором наибольшего пять раз, а не сортировкой: пар и путей
  # бывает столько же, сколько разных путей в срезе (до 10 000), и квадратичная
  # сортировка на mawk заняла бы секунды на каждом пуше.
  printf "],\"auth_attempts\":["
  emitted = 0
  for (r = 1; r <= 5; r++) {
    best = 0
    for (i = 1; i <= pair_n; i++) {
      if (i in taken) continue
      if (best == 0 || pair_before(i, best)) best = i
    }
    if (best == 0) break
    taken[best] = 1
    if (emitted > 0) printf ","
    emitted++
    printf "{\"ip\":\"%s\",\"path\":\"%s\",\"count\":%d}", \
      json_escape(pair_ip[best]), json_escape(pair_path[best]), pair_count[pair_key[best]]
  }
  printf "],\"auth_paths\":["
  emitted = 0
  for (r = 1; r <= 5; r++) {
    best = 0
    for (i = 1; i <= path_n; i++) {
      if (i in taken_path) continue
      if (best == 0 || path_before(i, best)) best = i
    }
    if (best == 0) break
    taken_path[best] = 1
    if (emitted > 0) printf ","
    emitted++
    printf "{\"path\":\"%s\",\"count\":%d,\"ips\":%d}", \
      json_escape(path_list[best]), path_count[path_list[best]], path_ips[path_list[best]]
  }
  printf "]"
}
{
  if (bootstrap + 0) {
    k = line_log_key($0)
    if (k != "" && k > max_log_key) max_log_key = k
    next
  }
  if (!accept_line($0)) next
  if (mode == "auth") { parse_auth($0); next }
  if ($0 ~ /^\{/) { parse_json_line($0); next }
  parse_combined($0)
}
END {
  if (max_key_file != "") {
    print max_log_key > max_key_file
    close(max_key_file)
    # Сколько строк отброшено без распознанного времени — ОТДЕЛЬНЫМ ФАЙЛОМ,
    # рядом с max_log_key.
    #
    # В stderr писать бесполезно: вызов awk перенаправляет его в файл, который
    # читается только под флагом отладки и тут же удаляется. То есть «наружу»
    # не уходило ничего. А число это единственный признак неподдержанного
    # формата после первого прохода: отсутствие ключа проверить нельзя —
    # NEW_LOG_KEY засеян прежним значением и пустым уже не бывает.
    print unkeyed + 0 > (max_key_file ".unkeyed")
    close(max_key_file ".unkeyed")
  }
  if (bootstrap + 0) exit 0
  printf "{\"schema_version\":2,\"window_sec\":%d,\"totals\":{\"parsed\":%d,\"suspicious\":%d,\"auth_failures\":%d},\"categories\":{", window_sec, parsed, suspicious, auth_fail
  first=1
  for (c in cats) {
    if (!first) printf ","
    first=0
    printf "\"%s\":%d", c, cats[c]
  }
  printf "},\"top_ips\":["
  n=0
  for (ip in ipc) {
    if (ip == "") continue
    order[n]=ip; cnt[n]=ipc[ip]; n++
  }
  for (i=0; i<n-1; i++) for (j=i+1; j<n; j++) if (cnt[j]>cnt[i]) { t=order[i]; order[i]=order[j]; order[j]=t; t=cnt[i]; cnt[i]=cnt[j]; cnt[j]=t }
  lim = (n>10)?10:n
  emitted=0
  for (i=0; i<lim; i++) {
    esc = json_escape(order[i])
    if (esc == "") continue
    if (emitted>0) printf ","
    emitted++
    printf "{\"ip\":\"%s\",\"count\":%d}", esc, cnt[i]
  }
  printf "],\"top_paths\":["
  n=0
  for (p in pathc) {
    if (p == "") continue
    order[n]=p; cnt[n]=pathc[p]; n++
  }
  for (i=0; i<n-1; i++) for (j=i+1; j<n; j++) if (cnt[j]>cnt[i]) { t=order[i]; order[i]=order[j]; order[j]=t; t=cnt[i]; cnt[i]=cnt[j]; cnt[j]=t }
  lim = (n>10)?10:n
  emitted=0
  for (i=0; i<lim; i++) {
    esc = json_escape(order[i])
    if (esc == "") continue
    if (emitted>0) printf ","
    emitted++
    printf "{\"path\":\"%s\",\"count\":%d}", esc, cnt[i]
  }
  printf "],\"top_talker\":"
  # Выбор по взвешенному счёту (фоновые — четвертью, в четвертях без дробей),
  # как у судьи: по сырому счёту человек с 600 запросами, из которых 510
  # фоновые, вытеснял бы из поля бота с 520.
  talker_ip = ""; talker_score = 0
  for (ip in reqc) {
    score = 4 * (reqc[ip] - bgc[ip]) + bgc[ip]
    if (score > talker_score) { talker_score = score; talker_ip = ip }
  }
  if (talker_ip != "") {
    printf "{\"ip\":\"%s\",\"requests\":%d,\"background\":%d}", json_escape(talker_ip), reqc[talker_ip], bgc[talker_ip] + 0
  } else {
    printf "null"
  }
  printf ",\"samples\":["
  for (i=1; i<=sample_n; i++) emit_sample(i)
  printf "]"
  emit_outcome_facts()
  printf ",\"truncated\":%s}", ((slice_capped + 0 && seen_old + 0 == 0) ? "true" : "false")
}
AWK_EOF

  # Слияние окон нескольких логов — отдельной программой, а не строкой внутри
  # вызова jq: тест (threatAwk.test.ts) извлекает её отсюда и гоняет на
  # настоящих окнах. Правило для каждого поля — то же, что внутри одного лога:
  # счётчики складываются, списки объединяются по ключу и режутся теми же
  # пределами. Поле, забытое здесь, терялось бы молча на любом хосте, где логов
  # больше одного, — а это почти каждый: access.log и auth.log.
  THREAT_MERGE_JQ=$(cat <<'JQ_MERGE_EOF'
def add_counts($x; $y):
  reduce ($y | keys_unsorted[]) as $k ($x; .[$k] = ((.[$k] // 0) + ($y[$k] // 0)));
# served_probes — те же правила, что в awk (note_served): HTML не входит, повтор
# пути уточняет размер и тип, не больше трёх путей одного размера, всего десять.
# Иначе второй лог возвращал бы в список заглушки, которые первый отсеял.
def merge_served($list):
  reduce $list[] as $p ([];
    if ($p.content_type != null and ($p.content_type | ascii_downcase | startswith("text/html"))) then .
    elif any(.[]; .path == $p.path) then
      map(if .path == $p.path then
            .bytes = (if $p.bytes != null and (.bytes == null or $p.bytes > .bytes) then $p.bytes else .bytes end)
            | .content_type = (.content_type // $p.content_type)
          else . end)
    elif length >= 10 then .
    elif $p.bytes != null and ([.[] | select(.bytes == $p.bytes)] | length) >= 3 then .
    else . + [$p]
    end);
.[0] as $a | .[1] as $b |
{
  schema_version: 2,
  # Большее из двух: логи читаются с разными курсорами, и подписать
  # объединённое окно коротким значением значило бы вернуть тот же
  # завышенный порог, от которого уходим.
  window_sec: ([$a.window_sec, $b.window_sec] | map(select(. != null)) | max),
  totals: {
    parsed: (($a.totals.parsed // 0) + ($b.totals.parsed // 0)),
    suspicious: (($a.totals.suspicious // 0) + ($b.totals.suspicious // 0)),
    auth_failures: (($a.totals.auth_failures // 0) + ($b.totals.auth_failures // 0))
  },
  categories: add_counts(($a.categories // {}); ($b.categories // {})),
  # Счётчики одного IP из разных логов складываются, а не теряются при
  # срезе: раньше списки просто склеивались и обрезались по первым 10,
  # из-за чего один и тот же атакующий выглядел слабее, чем он есть.
  top_ips: (
    (($a.top_ips // []) + ($b.top_ips // []))
    | group_by(.ip)
    | map({ip: .[0].ip, count: (map(.count) | add)})
    | sort_by(-.count)
  )[0:20],
  top_paths: (
    (($a.top_paths // []) + ($b.top_paths // []))
    | group_by(.path)
    | map({path: .[0].path, count: (map(.count) | add)})
    | sort_by(-.count)
  )[0:20],
  top_talker: (
    [$a.top_talker, $b.top_talker]
    | map(select(. != null))
    # Тот же взвешенный счёт, что в awk; у окна без background — сырой.
    | sort_by(-(4 * (.requests - (.background // 0)) + (.background // 0)))
    | first
  ),
  samples: (($a.samples // []) + ($b.samples // []))[0:10],
  probe_outcomes: add_counts(
    add_counts({refused: 0, redirected: 0, served: 0, failed: 0}; ($a.probe_outcomes // {}));
    ($b.probe_outcomes // {})
  ),
  # Порядок первого появления: окно, слитое первым, раньше и по времени чтения.
  served_probes: merge_served(($a.served_probes // []) + ($b.served_probes // [])),
  # Пара с одного адреса на один путь из двух логов — одна пара: иначе подбор,
  # размазанный между nginx и Caddy, не набирал бы порог концентрации.
  auth_attempts: (
    (($a.auth_attempts // []) + ($b.auth_attempts // []))
    | group_by([.ip, .path])
    | map({ip: .[0].ip, path: .[0].path, count: (map(.count) | add)})
    | sort_by(-.count, .path, .ip)
  )[0:5],
  # ips при слиянии — БОЛЬШЕЕ из двух, а не сумма и не пересчёт. Сырых пар в
  # окне нет (auth_attempts — только первые пять), и пересечения адресов между
  # логами не видно. Сумма посчитала бы дважды адрес, чей запрос записали и
  # nginx, и прокси за ним, — и один подбирающий выглядел бы распределённым
  # подбором. Максимум — честная нижняя граница: адресов не меньше.
  auth_paths: (
    (($a.auth_paths // []) + ($b.auth_paths // []))
    | group_by(.path)
    | map({path: .[0].path, count: (map(.count) | add), ips: (map(.ips) | max)})
    | sort_by(-.count, .path)
  )[0:5],
  truncated: (($a.truncated // false) or ($b.truncated // false))
}
JQ_MERGE_EOF
)

  for LOG_PATH in "${THREAT_LOGS[@]:-}"; do
    # Флаг обрезки — на каждый лог свой. Одна общая переменная означала, что
    # длинный auth.log помечал обрезанными и данные nginx, которые не резались.
    THREAT_TRUNC=0
    [[ -f "$LOG_PATH" ]] || continue
    CURSOR_FILE="${STATE_DIR}/threat-cursor-$(echo -n "$LOG_PATH" | sha256sum 2>/dev/null | awk '{print $1}' || echo "$(basename "$LOG_PATH")").json"
    OFF=0
    FP=""
    FPLEN=0
    LAST_LOG_KEY=""
    BOOTSTRAPPED=""
    COMMITTED_AT=0
    # Курсор читается и без jq: python3 всё равно обязателен для сборки снапшота
    # (см. проверку ниже), а раньше на хосте без jq курсор не читался никогда —
    # last_log_key оставался пустым, агент вечно уходил в bootstrap и слал нули.
    if [[ -f "$CURSOR_FILE" ]]; then
      if command -v jq >/dev/null 2>&1; then
        OFF=$(jq -r '.offset // 0' "$CURSOR_FILE" 2>/dev/null || echo 0)
        FP=$(jq -r '.fp // ""' "$CURSOR_FILE" 2>/dev/null || echo "")
        FPLEN=$(jq -r '.fpLen // 0' "$CURSOR_FILE" 2>/dev/null || echo 0)
        LAST_LOG_KEY=$(jq -r '.last_log_key // ""' "$CURSOR_FILE" 2>/dev/null || echo "")
        BOOTSTRAPPED=$(jq -r 'if .bootstrapped then "true" else "" end' "$CURSOR_FILE" 2>/dev/null || echo "")
        COMMITTED_AT=$(jq -r '.committed_at // 0' "$CURSOR_FILE" 2>/dev/null || echo 0)
      elif command -v python3 >/dev/null 2>&1; then
        _CUR=$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
print(d.get("offset") or 0)
print(d.get("fp") or "")
print(d.get("fpLen") or 0)
print(d.get("last_log_key") or "")
print("true" if d.get("bootstrapped") else "")
print(d.get("committed_at") or 0)
' "$CURSOR_FILE" 2>/dev/null || true)
        if [[ -n "$_CUR" ]]; then
          OFF=$(sed -n 1p <<<"$_CUR")
          FP=$(sed -n 2p <<<"$_CUR")
          FPLEN=$(sed -n 3p <<<"$_CUR")
          LAST_LOG_KEY=$(sed -n 4p <<<"$_CUR")
          BOOTSTRAPPED=$(sed -n 5p <<<"$_CUR")
          COMMITTED_AT=$(sed -n 6p <<<"$_CUR")
        fi
      fi
    fi
    [[ "$OFF" =~ ^[0-9]+$ ]] || OFF=0
    [[ "$FPLEN" =~ ^[0-9]+$ ]] || FPLEN=0
    FILE_SIZE=$(stat -c %s "$LOG_PATH" 2>/dev/null || echo 0)
    if [[ ! "$FILE_SIZE" =~ ^[0-9]+$ ]]; then FILE_SIZE=0; fi
    NEW_FP=""
    if [[ "$FILE_SIZE" -gt 0 ]]; then
      NEW_FP=$(head -c 256 "$LOG_PATH" 2>/dev/null | sha256sum | awk '{print $1}')
    fi
    if [[ -n "$FP" && "$NEW_FP" != "$FP" ]]; then
      OFF=0
      LAST_LOG_KEY=""
      BOOTSTRAPPED=""
      COMMITTED_AT=0
    fi
    if [[ "$OFF" -gt "$FILE_SIZE" ]]; then OFF=0; fi

    # Длительность окна — ФАКТИЧЕСКАЯ, а не из конфига.
    #
    # Раньше в снапшот уезжал настроенный интервал пуша, и после любого
    # пропуска (сбой сети, перезагрузка, платформа отвечала 5xx) окно,
    # покрывающее час логов, подписывалось как 180 секунд. Пороги детекции
    # масштабируются именно по этому числу — то есть после каждого перерыва
    # платформа объявляла всплеском обычного поисковика.
    #
    # Границы те же, что у Go-агента (windowSecondsSince): не меньше минуты и
    # не больше суток.
    [[ "$COMMITTED_AT" =~ ^[0-9]+$ ]] || COMMITTED_AT=0
    LOG_WINDOW_SEC=$THREAT_WINDOW_SEC
    if [[ "$COMMITTED_AT" -gt 0 ]]; then
      LOG_WINDOW_SEC=$(( $(date +%s) - COMMITTED_AT ))
      if [[ "$LOG_WINDOW_SEC" -lt 60 ]]; then LOG_WINDOW_SEC=60; fi
      if [[ "$LOG_WINDOW_SEC" -gt 86400 ]]; then LOG_WINDOW_SEC=86400; fi
    fi

    MODE="http"
    [[ "$LOG_PATH" == *auth.log* ]] && MODE="auth"
    USE_TS_FILTER=0
    [[ "$THREAT_READ_MODE" == "incremental" ]] && USE_TS_FILTER=1
    THREAT_BOOTSTRAP=0
    if [[ "${TRACEDOCS_THREAT_BOOTSTRAP:-0}" == "1" ]]; then
      THREAT_BOOTSTRAP=1
    elif [[ "$THREAT_READ_MODE" == "incremental" && -z "$LAST_LOG_KEY" && "$BOOTSTRAPPED" != "true" ]]; then
      # Флаг, а не пустой last_log_key: у пустого лога ключ времени взять
      # неоткуда, и по старому условию такой лог оставался «в первичной
      # синхронизации» вечно — на каждом пуше, до первой строки в файле.
      THREAT_BOOTSTRAP=1
    fi
    NEW_OFF=$OFF
    if [[ "$THREAT_READ_MODE" == "cursor" ]]; then
      SLICE=$(tail -c +$((OFF + 1)) "$LOG_PATH" 2>/dev/null | head -n "$MAX_THREAT_LINES" || true)
      LINES_READ=$(count_nonempty_lines "$SLICE")
      if [[ "$LINES_READ" -ge "$MAX_THREAT_LINES" ]]; then THREAT_TRUNC=1; fi
    else
      if [[ "$FILE_SIZE" -gt "$THREAT_TAIL_BYTES" ]]; then
        SLICE=$(tail -c "$THREAT_TAIL_BYTES" "$LOG_PATH" 2>/dev/null | tail -n "$MAX_THREAT_LINES" || true)
      else
        SLICE=$(tail -n "$MAX_THREAT_LINES" "$LOG_PATH" 2>/dev/null || true)
      fi
      LINES_READ=$(count_nonempty_lines "$SLICE")
      if [[ "$LINES_READ" -ge "$MAX_THREAT_LINES" ]]; then THREAT_TRUNC=1; fi
      NEW_OFF=$FILE_SIZE
    fi

    MAX_KEY_FILE=$(mktemp)
    PART=$(echo "$SLICE" | awk -v mode="$MODE" -v window_sec="$LOG_WINDOW_SEC" -v slice_capped="$THREAT_TRUNC" \
      -v last_log_key="$LAST_LOG_KEY" -v use_ts_filter="$USE_TS_FILTER" -v log_year="$LOG_YEAR" \
      -v log_month="$LOG_MONTH" \
      -v bootstrap="$THREAT_BOOTSTRAP" -v max_key_file="$MAX_KEY_FILE" -f "$THREAT_AWK" 2>"${STATE_DIR}/threat-awk.err" || echo "")
    NEW_LOG_KEY="$LAST_LOG_KEY"
    if [[ -s "$MAX_KEY_FILE" ]]; then
      _nk=$(tr -d '\n' <"$MAX_KEY_FILE" 2>/dev/null || true)
      if [[ -n "$_nk" && ( -z "$LAST_LOG_KEY" || "$_nk" > "$LAST_LOG_KEY" ) ]]; then
        NEW_LOG_KEY="$_nk"
      fi
    fi
    UNKEYED=0
    if [[ -s "${MAX_KEY_FILE}.unkeyed" ]]; then
      UNKEYED=$(tr -d '\n' <"${MAX_KEY_FILE}.unkeyed" 2>/dev/null || echo 0)
      [[ "$UNKEYED" =~ ^[0-9]+$ ]] || UNKEYED=0
    fi
    rm -f "$MAX_KEY_FILE" "${MAX_KEY_FILE}.unkeyed"
    if [[ "${TRACEDOCS_THREAT_DEBUG:-0}" == "1" ]]; then
      echo "threat debug: log=${LOG_PATH} mode=${THREAT_READ_MODE} bootstrap=${THREAT_BOOTSTRAP} slice_lines=${LINES_READ} last_log_key=${LAST_LOG_KEY} new_log_key=${NEW_LOG_KEY} awk_err=$(tr '\n' ' ' <"${STATE_DIR}/threat-awk.err" 2>/dev/null || true)" >&2
      if [[ -n "$PART" ]]; then
        echo "threat debug: part=$(echo "$PART" | head -c 240)" >&2
      fi
    fi
    rm -f "${STATE_DIR}/threat-awk.err" 2>/dev/null || true

    # Формат времени не распознан.
    #
    # Признак — ФАКТ отбрасывания строк, а не пустой ключ. По пустому ключу
    # проверить нельзя: NEW_LOG_KEY засеян прежним значением (см. выше) и после
    # первого прохода пустым не бывает никогда — то есть предупреждение
    # физически не могло сработать повторно. А ситуация реальна: человек
    # меняет log_format у nginx и делает reload, файл тот же, отпечаток тот же,
    # курсор сохраняется — и все новые строки отбрасываются бессрочно.
    if [[ "$UNKEYED" -gt 0 || ( -z "$NEW_LOG_KEY" && "$LINES_READ" -gt 0 && "$THREAT_READ_MODE" != "cursor" ) ]]; then
      THREAT_REASON="unknown_time_format"
      echo "WARNING: не распознан формат времени в ${LOG_PATH}" >&2
      echo "         отброшено строк: ${UNKEYED}; сбор по этому логу остановлен" >&2
    fi

    if [[ "$THREAT_BOOTSTRAP" -eq 1 ]]; then
      if [[ "$THREAT_REASON" == "ok" ]]; then
        # Пометка на окно, а не на лог: снимем ниже, если хоть один лог дал данные.
        THREAT_REASON="bootstrap"
      fi
      if [[ "${TRACEDOCS_THREAT_DEBUG:-0}" == "1" ]]; then
        echo "threat debug: bootstrap — cursor advanced, threat counts skipped for ${LOG_PATH}" >&2
      fi
    elif [[ -z "$PART" || "$PART" != "{"* ]]; then
      # Молчаливая потеря окна — то, из-за чего дефекты сбора были невидимы.
      if [[ "$LINES_READ" -gt 0 ]]; then
        echo "WARNING: awk не вернул корректный JSON по ${LOG_PATH} — окно угроз пропущено" >&2
      fi
    else
      if command -v jq >/dev/null 2>&1; then
        if echo "$PART" | jq empty 2>/dev/null; then
          MERGED=$(jq -c -s "$THREAT_MERGE_JQ" <(echo "$THREATS_JSON") <(echo "$PART") 2>/dev/null || true)
          if [[ -n "$MERGED" ]] && echo "$MERGED" | jq empty 2>/dev/null; then
            THREATS_JSON="$MERGED"
          fi
        fi
      else
        THREATS_JSON="$PART"
      fi
    fi

    if [[ "$THREAT_READ_MODE" == "cursor" ]]; then
      NEW_OFF=$((OFF + $(printf '%s' "$SLICE" | wc -c | tr -d ' ')))
    fi
    NEW_FPLEN=$((FILE_SIZE < 256 ? FILE_SIZE : 256))
    # Курсор сдвигаем ТОЛЬКО после успешного пуша (см. commit_threat_cursors ниже):
    # при сетевом сбое или 5xx на платформе строки иначе уходили за курсор
    # безвозвратно — их уже не перечитать.
    PENDING_CURSOR_FILES+=("$CURSOR_FILE")
    # bootstrapped остаётся жёстким true и это НЕ упущение.
    #
    # У пустого лога ключ времени взять неоткуда, и признак «синхронизация
    # закончена», выведенный из непустого last_log_key, оставлял бы такой лог в
    # первичной синхронизации вечно — а причина одна на все логи, поэтому
    # интерфейс писал бы «идёт синхронизация» при исправно работающем auth.log.
    # Это уже чинили; предупреждение о нераспознанном формате вынесено из ветки
    # первого запуска отдельно (см. ниже).
    PENDING_CURSOR_JSON+=("$(printf '{"offset":%s,"fpLen":%s,"fp":"%s","last_log_key":"%s","bootstrapped":true,"committed_at":%s}' \
      "${NEW_OFF:-0}" "$NEW_FPLEN" "${NEW_FP:-}" "${NEW_LOG_KEY:-}" "$(date +%s)")")
  done
  rm -f "$THREAT_AWK"

  # «Первичная синхронизация» — это про окно целиком, а не про отдельный лог.
  # THREAT_REASON одна на все логи, поэтому пустой access.log помечал bootstrap
  # всё окно, хотя auth.log в это же время исправно отдавал угрозы: интерфейс
  # говорил «идёт синхронизация» при работающем сборе. Если данные есть —
  # синхронизация закончилась, чем бы ни был занят второй лог.
  if [[ "$THREAT_REASON" == "bootstrap" ]] && command -v jq >/dev/null 2>&1; then
    _PARSED=$(echo "$THREATS_JSON" | jq -r '.totals.parsed // 0' 2>/dev/null || echo 0)
    [[ "$_PARSED" =~ ^[0-9]+$ ]] || _PARSED=0
    if [[ "$_PARSED" -gt 0 ]]; then THREAT_REASON="ok"; fi
  fi

  # Состояние сборщика — часть окна: без него пустой pulse и сломанный агент
  # выглядят в интерфейсе одинаково, и «тихо» неотличимо от «не работает».
  if [[ "$THREATS_JSON" != "null" && "$THREATS_JSON" == "{"* ]]; then
    THREAT_COLLECTOR_OK=false
    [[ "$THREAT_REASON" == "ok" ]] && THREAT_COLLECTOR_OK=true
    if command -v jq >/dev/null 2>&1; then
      _WITH_COLLECTOR=$(echo "$THREATS_JSON" | jq -c \
        --argjson ok "$THREAT_COLLECTOR_OK" --arg reason "$THREAT_REASON" \
        '. + {collector: {ok: $ok, reason: $reason}}' 2>/dev/null || true)
      [[ -n "$_WITH_COLLECTOR" ]] && THREATS_JSON="$_WITH_COLLECTOR"
    else
      THREATS_JSON="${THREATS_JSON%\}},\"collector\":{\"ok\":${THREAT_COLLECTOR_OK},\"reason\":\"${THREAT_REASON}\"}}"
    fi
  fi

  if [[ "$THREATS_JSON" != "null" ]]; then
    if ! json_valid "$THREATS_JSON"; then
      echo "WARNING: threats JSON invalid after log parse — omitting threats block" >&2
      THREATS_JSON="null"
    fi
  fi
  if [[ "$THREATS_JSON" != "null" ]]; then
    echo "$THREATS_JSON" >"${STATE_DIR}/threat-last-pulse.json" 2>/dev/null || true
  fi
fi

SCHEMA_VERSION=1
if [[ "$THREATS_JSON" != "null" ]]; then SCHEMA_VERSION=2; fi

RECORDED_AT=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

SNAPSHOT_THREATS_EXPORT="null"
if [[ "$THREATS_JSON" != "null" ]]; then
  SNAPSHOT_THREATS_EXPORT="$THREATS_JSON"
fi

export SNAPSHOT_HOST_ID="$HOST_ID"
export SNAPSHOT_RECORDED_AT="$RECORDED_AT"
export SNAPSHOT_CPU="$CPU"
export SNAPSHOT_LOAD1="$LOAD1"
export SNAPSHOT_LOAD5="$LOAD5"
export SNAPSHOT_LOAD15="$LOAD15"
export SNAPSHOT_MEM_USED="$MEM_USED"
export SNAPSHOT_MEM_TOTAL="$MEM_TOTAL"
export SNAPSHOT_UPTIME="$UPTIME"
export SNAPSHOT_DISK_JSON="$DISK_JSON"
export SNAPSHOT_CHECKS_JSON="$CHECKS_JSON"
export SNAPSHOT_CONTAINERS_JSON="$CONTAINERS_JSON"
export SNAPSHOT_CONTAINER_EVENTS_JSON="$CONTAINER_EVENTS_JSON"
export SNAPSHOT_NETWORK_JSON="$NETWORK_JSON"
export SNAPSHOT_THREATS_JSON="$SNAPSHOT_THREATS_EXPORT"
export SNAPSHOT_HOST_POSTURE_JSON="$POSTURE_JSON"
export SNAPSHOT_AGENT_VERSION="$AGENT_VERSION"

BUILDER="${DIR}/build-snapshot-json.py"
if [[ ! -x "$BUILDER" && ! -f "$BUILDER" ]]; then
  echo "ERROR: отсутствует ${BUILDER} — переустановите агент (curl install.sh | bash)" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: требуется python3 (apt-get install -y python3)" >&2
  exit 1
fi

if ! BODY=$(python3 "$BUILDER" 2>"${STATE_DIR}/build-snapshot.err"); then
  echo "ERROR: не удалось собрать JSON снапшота:" >&2
  cat "${STATE_DIR}/build-snapshot.err" >&2 || true
  exit 1
fi
BODY_BYTES=$(printf '%s' "$BODY" | wc -c | tr -d ' ')

# Не влезли в предел приёма — урезаем списки окна и собираем тело заново.
# Отказ ниже роняет пуш целиком, а вместе с ним метрики и всё окно угроз;
# хвосты списков стоят дешевле (порядок и причина — у THREAT_TRIM_JQ).
if [[ "$BODY_BYTES" -gt 65536 && "$SNAPSHOT_THREATS_JSON" != "null" ]] && command -v jq >/dev/null 2>&1; then
  _TRIMMED=$(printf '%s' "$SNAPSHOT_THREATS_JSON" | jq -c --argjson excess "$((BODY_BYTES - 65536))" "$THREAT_TRIM_JQ" 2>/dev/null || true)
  if [[ -n "$_TRIMMED" ]]; then
    export SNAPSHOT_THREATS_JSON="$_TRIMMED"
    if _BODY=$(python3 "$BUILDER" 2>"${STATE_DIR}/build-snapshot.err"); then
      BODY="$_BODY"
      BODY_BYTES=$(printf '%s' "$BODY" | wc -c | tr -d ' ')
      echo "WARNING: снапшот больше 64 КиБ — списки окна угроз урезаны до ${BODY_BYTES} байт" >&2
    fi
  fi
fi
echo "$BODY" >"${STATE_DIR}/last-body.json" 2>/dev/null || true

# Preflight: must parse as JSON and fit ingest limit (64 KiB)
if ! printf '%s' "$BODY" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  echo "ERROR: snapshot JSON invalid after build (${BODY_BYTES} bytes)" >&2
  exit 1
fi
if [[ "$BODY_BYTES" -gt 65536 ]]; then
  echo "ERROR: snapshot too large (${BODY_BYTES} bytes > 65536) — set TRACEDOCS_THREATS=0 or reduce log window" >&2
  exit 1
fi

# Испытание новой версии закрывается здесь, а не после успешного ingest:
# «агент работает» — это «собрал снапшот». Недоступная сеть или 5xx на
# платформе не вина агента, и откатывать из-за них исправную версию нельзя.
self_update_confirm "$AGENT_VERSION"

# Холостой прогон: собрать снапшот и остановиться перед отправкой. Так
# самообновление проверяет новую версию ДО подмены файлов — на этом самом
# хосте, с его awk, python3 и конфигом.
if [[ "${TRACEDOCS_SELF_CHECK:-0}" == "1" ]]; then
  echo "SELF_CHECK_OK ${BODY_BYTES} bytes"
  exit 0
fi

TS=$(date +%s)
SIG=$(printf '%s' "${TS}.${BODY}" | openssl dgst -sha256 -hmac "$TRACEDOCS_TOKEN" | awk '{print $NF}')

CURL_EXTRA=()
if [[ "${TRACEDOCS_INSTALL_PUSH:-0}" == "1" ]]; then
  CURL_EXTRA+=(-H "X-Scopework-Install-Push: 1")
fi

# Ответ пишем в приватный временный файл: фиксированный путь в /tmp мог
# принадлежать другому пользователю хоста (подмена и чтение ответа платформы).
RESP_FILE=$(mktemp "${TMPDIR:-/tmp}/tracedocs-monitor-resp.XXXXXX")
RESP_HEADERS=$(mktemp "${TMPDIR:-/tmp}/tracedocs-monitor-hdr.XXXXXX")
trap 'rm -f "$RESP_FILE" "$RESP_HEADERS"' EXIT

HTTP_CODE=$(curl -sS -o "$RESP_FILE" -D "$RESP_HEADERS" -w "%{http_code}" \
  -X POST "$TRACEDOCS_INGEST_URL" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${TRACEDOCS_TOKEN}" \
  -H "X-Scopework-Timestamp: ${TS}" \
  -H "X-Scopework-Signature: sha256=${SIG}" \
  "${CURL_EXTRA[@]}" \
  --connect-timeout 10 --max-time 30 \
  -d "$BODY" || echo "000")

if [[ "$HTTP_CODE" != "204" && "$HTTP_CODE" != "200" ]]; then
  echo "ingest failed HTTP ${HTTP_CODE}" >&2
  SCHEMA_VER=$(printf '%s' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("schema_version","?"))' 2>/dev/null || echo '?')
  # Отпечаток вместо префикса токена: 15 символов секрета в логе агента —
  # это утечка секрета в файл, который читают при диагностике и присылают в поддержку.
  TOKEN_FP=$(printf '%s' "$TRACEDOCS_TOKEN" | sha256sum 2>/dev/null | cut -c1-12 || echo "?")
  echo "Диагностика: token_sha256=${TOKEN_FP} schema=${SCHEMA_VER} bytes=${BODY_BYTES}" >&2
  echo "  last-body: ${STATE_DIR}/last-body.json" >&2
  if [[ "$HTTP_CODE" == "404" ]]; then
    echo "  404 = auth / invalid payload / stale recorded_at." >&2
    echo "  Логи web: docker logs obsidian-like-web 2>&1 | grep 'monitoring ingest rejected' | tail -3" >&2
  fi
  # Курсоры НЕ сдвигаем: следующий пуш перечитает те же строки и угрозы не потеряются
  exit 1
fi

commit_threat_cursors
commit_container_state

# Целевая версия и флаг логов приезжают заголовками ответа ingest, а не телом:
# агент и раньше проверял в ответе только код, поэтому старые агенты на серверах
# новые заголовки просто не замечают — код ответа остался 204 и контракт не
# изменился. Что из них исполнять, решает политика хоста.
apply_platform_response

exit 0
