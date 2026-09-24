#!/usr/bin/env bash
# Remove Scopework monitor agent files and cron entry.
set -euo pipefail

INSTALL_DIR="/opt/tracedocs/monitor"
CRON_FILE="/etc/cron.d/tracedocs-monitor"

if [[ "$(id -u)" -eq 0 ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop tracedocs-monitor.timer 2>/dev/null || true
    systemctl disable tracedocs-monitor.timer 2>/dev/null || true
    rm -f /etc/systemd/system/tracedocs-monitor.service /etc/systemd/system/tracedocs-monitor.timer
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$CRON_FILE"
  rm -rf "$INSTALL_DIR"
  rm -f /var/log/tracedocs-monitor.log
else
  crontab -l 2>/dev/null | grep -v 'tracedocs/monitor/push.sh' | crontab - || true
  rm -rf "$INSTALL_DIR"
fi

echo "UNINSTALLED"
exit 0
