#!/usr/bin/env bash
# Scopework server monitoring — ручная установка агента.
# Scopework не подключается к серверу: команду выполняет администратор сам.
# Использование:
#   curl -fsSL <origin>/api/monitoring/v1/install.sh | sudo bash -s -- --token td_mon_... [опции]
# Опции:
#   --token TOKEN       (обязательно) ingest-токен из мастера подключения
#   --interval-sec N    интервал push в секундах (default 180)
#   --health-urls JSON  JSON-массив URL health-чеков, напр. '["https://example.com/health"]'
#   --host-id NAME      метка хоста (default: hostname -s)
#   --ingest-url URL    переопределить ingest URL
#   --threats 0|1       контроль атак (default: 1)
#   --threat-logs PATHS пути логов через запятую (default: автопоиск)
#   --self-update 0|1   самообновление агента (default: 1)
set -euo pipefail

INGEST_URL='__TRACEDOCS_INGEST_URL__'
AGENT_VERSION='__TRACEDOCS_AGENT_VERSION__'
TOKEN=""
INTERVAL="180"
HEALTH_URLS="[]"
HOST_ID=""
THREATS="1"
THREAT_LOGS=""
# Выключатель для тех, кто держит сервер под конфиг-менеджментом и не хочет,
# чтобы файлы в /opt/tracedocs/monitor менялись мимо его playbook'а.
SELF_UPDATE="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
  --token) TOKEN="${2:-}"; shift 2 ;;
  --interval-sec) INTERVAL="${2:-180}"; shift 2 ;;
  --health-urls) HEALTH_URLS="${2:-[]}"; shift 2 ;;
  --host-id) HOST_ID="${2:-}"; shift 2 ;;
  --ingest-url) INGEST_URL="${2:-$INGEST_URL}"; shift 2 ;;
  --threats) THREATS="${2:-1}"; shift 2 ;;
  --threat-logs) THREAT_LOGS="${2:-}"; shift 2 ;;
  --self-update) SELF_UPDATE="${2:-1}"; shift 2 ;;
  *) echo "ERROR: неизвестная опция: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: --token обязателен (выдаётся в мастере подключения Scopework)" >&2
  exit 1
fi
case "$TOKEN" in
td_mon_*) ;;
*) echo "ERROR: токен должен начинаться с td_mon_" >&2; exit 1 ;;
esac
if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: нужен root — запустите команду через sudo" >&2
  exit 1
fi
# jq обязателен: без него курсор логов читается урезанно, а мердж нескольких
# логов вырождается в «последний побеждает» — угрозы собираются неверно.
for dep in curl openssl awk df python3 jq; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    echo "ERROR: требуется ${dep} (например: apt-get install -y ${dep})" >&2
    exit 1
  fi
done
case "$THREATS" in
0|1) ;;
*) echo "ERROR: --threats принимает только 0 или 1" >&2; exit 1 ;;
esac
case "$SELF_UPDATE" in
0|1) ;;
*) echo "ERROR: --self-update принимает только 0 или 1" >&2; exit 1 ;;
esac
# config.env выполняется агентом через source — принимаем только абсолютные пути
# из безопасного алфавита, иначе строка отсюда стала бы исполняемым кодом
if [[ -n "$THREAT_LOGS" ]] && ! [[ "$THREAT_LOGS" =~ ^/[A-Za-z0-9._/-]+(,/[A-Za-z0-9._/-]+)*$ ]]; then
  echo "ERROR: --threat-logs: ожидаются абсолютные пути через запятую" >&2
  exit 1
fi
if [[ ! "$INTERVAL" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --interval-sec должен быть числом (секунды)" >&2
  exit 1
fi

HOST_ID="${HOST_ID:-$(hostname -s 2>/dev/null || hostname || echo host)}"

INSTALL_DIR="/opt/tracedocs/monitor"
CRON_FILE="/etc/cron.d/tracedocs-monitor"

# Interval minutes for cron (round up, 1..15) — как в monitor-install.sh
MINUTES=$(( (INTERVAL + 59) / 60 ))
if [[ $MINUTES -lt 1 ]]; then MINUTES=1; fi
if [[ $MINUTES -gt 15 ]]; then MINUTES=15; fi

mkdir -p "$INSTALL_DIR"

cat >"$INSTALL_DIR/push.sh" <<'__TRACEDOCS_PUSH_SH__'
__TRACEDOCS_PUSH_SH_BODY__
__TRACEDOCS_PUSH_SH__
chmod 750 "$INSTALL_DIR/push.sh"

cat >"$INSTALL_DIR/build-snapshot-json.py" <<'__TRACEDOCS_BUILD_SNAPSHOT_PY__'
__TRACEDOCS_BUILD_SNAPSHOT_PY_BODY__
__TRACEDOCS_BUILD_SNAPSHOT_PY__
chmod 750 "$INSTALL_DIR/build-snapshot-json.py"

cat >"$INSTALL_DIR/uninstall.sh" <<'__TRACEDOCS_UNINSTALL_SH__'
__TRACEDOCS_UNINSTALL_SH_BODY__
__TRACEDOCS_UNINSTALL_SH__
chmod 750 "$INSTALL_DIR/uninstall.sh"

# Escape single quotes for env file
escape_sq() { printf "%s" "$1" | sed "s/'/'\\\\''/g"; }

cat >"$INSTALL_DIR/config.env" <<EOF
TRACEDOCS_INGEST_URL='$(escape_sq "$INGEST_URL")'
TRACEDOCS_TOKEN='$(escape_sq "$TOKEN")'
TRACEDOCS_HEALTH_URLS='$(escape_sq "$HEALTH_URLS")'
TRACEDOCS_HOST_ID='$(escape_sq "$HOST_ID")'
TRACEDOCS_PUSH_INTERVAL_SEC='${INTERVAL}'
TRACEDOCS_THREATS='${THREATS}'
TRACEDOCS_THREAT_LOG_PATHS='${THREAT_LOGS}'
TRACEDOCS_SELF_UPDATE='${SELF_UPDATE}'
EOF
chmod 600 "$INSTALL_DIR/config.env"

# Версия скриптов агента. Её же агент отдаёт в снапшоте и сравнивает с целью,
# объявленной платформой в ответе ingest. Файл, а не строка внутри push.sh:
# самообновление подменяет скрипты и версию одной и той же операцией.
printf '%s\n' "$AGENT_VERSION" >"$INSTALL_DIR/agent-version"
chmod 600 "$INSTALL_DIR/agent-version"
# След прошлого самообновления не должен пережить установку руками: иначе
# запрет на «сломанную» версию остался бы висеть после того, как её починили.
rm -f "$INSTALL_DIR/state/self-update-blocked" "$INSTALL_DIR/state/self-update-trial" \
  "$INSTALL_DIR/state/self-update-marker" 2>/dev/null || true
rm -rf "$INSTALL_DIR/.update" "$INSTALL_DIR/.backup"

mkdir -p "$INSTALL_DIR/state"
# В state лежат отпечатки логов и последний pulse — не для чужих глаз на хосте
chmod 700 "$INSTALL_DIR" "$INSTALL_DIR/state"


cat >/etc/systemd/system/tracedocs-monitor.service <<EOF
[Unit]
Description=Scopework server monitoring push
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=${INSTALL_DIR}/config.env
ExecStart=/usr/bin/timeout 120 /bin/bash ${INSTALL_DIR}/push.sh
StandardOutput=append:/var/log/tracedocs-monitor.log
StandardError=append:/var/log/tracedocs-monitor.log
EOF

cat >/etc/systemd/system/tracedocs-monitor.timer <<EOF
[Unit]
Description=Scopework monitor push timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${INTERVAL}s
Unit=tracedocs-monitor.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload 2>/dev/null || true
USE_SYSTEMD=0
if systemctl enable tracedocs-monitor.timer 2>/dev/null && systemctl start tracedocs-monitor.timer 2>/dev/null; then
  USE_SYSTEMD=1
fi

echo "# Scopework server monitoring — managed by install; do not edit" >"$CRON_FILE"
echo "SHELL=/bin/bash" >>"$CRON_FILE"
echo "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" >>"$CRON_FILE"
# Push: только systemd timer ИЛИ cron — не оба (иначе rate limit 30s на ingest).
if [[ "${USE_SYSTEMD:-0}" != "1" ]]; then
  echo "*/${MINUTES} * * * * root /bin/bash ${INSTALL_DIR}/push.sh >> /var/log/tracedocs-monitor.log 2>&1" >>"$CRON_FILE"
fi
chmod 644 "$CRON_FILE"
touch /var/log/tracedocs-monitor.log
chmod 644 /var/log/tracedocs-monitor.log

echo "Агент установлен в ${INSTALL_DIR} (push: $([ "$USE_SYSTEMD" = "1" ] && echo "systemd timer ${INTERVAL}s" || echo "cron каждые ${MINUTES} мин"))."
echo "Выполняем первый push…"
if TRACEDOCS_INSTALL_PUSH=1 /bin/bash "$INSTALL_DIR/push.sh"; then
  echo "OK: первый снапшот отправлен — статус в Scopework обновится в течение минуты."
else
  echo "WARNING: первый push не прошёл — проверьте сеть и токен. Cron продолжит попытки; лог: /var/log/tracedocs-monitor.log" >&2
fi
echo "Удаление агента: sudo ${INSTALL_DIR}/uninstall.sh"
exit 0
