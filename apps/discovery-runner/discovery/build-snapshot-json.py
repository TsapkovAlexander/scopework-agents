#!/usr/bin/env python3
"""Assemble monitor-agent snapshot JSON (schema v1/v2) from SNAPSHOT_* env vars."""
from __future__ import annotations

import json
import os
import sys
from typing import Any


def _num(raw: str | None) -> int | float | None:
    if raw is None:
        return None
    s = raw.strip()
    if not s or s.lower() == "null":
        return None
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        return None


def _json_load(name: str, default: Any) -> Any:
    raw = os.environ.get(name, "")
    if not raw or raw.strip() in ("", "null"):
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def main() -> int:
    host_id = os.environ.get("SNAPSHOT_HOST_ID", "unknown").strip() or "unknown"
    recorded_at = os.environ.get("SNAPSHOT_RECORDED_AT", "").strip()
    if not recorded_at:
        print("SNAPSHOT_RECORDED_AT required", file=sys.stderr)
        return 1

    disk = _json_load("SNAPSHOT_DISK_JSON", [])
    checks = _json_load("SNAPSHOT_CHECKS_JSON", [])
    containers = _json_load("SNAPSHOT_CONTAINERS_JSON", None)
    network = _json_load("SNAPSHOT_NETWORK_JSON", None)
    threats = _json_load("SNAPSHOT_THREATS_JSON", None)
    posture = _json_load("SNAPSHOT_HOST_POSTURE_JSON", None)

    if not isinstance(disk, list):
        disk = []
    sanitized_disk = []
    for item in disk[:32]:
        if not isinstance(item, dict):
            continue
        mount = str(item.get("mount", ""))[:256]
        if not mount:
            continue
        sanitized_disk.append({**item, "mount": mount})
    disk = sanitized_disk
    if not isinstance(checks, list):
        checks = []

    metrics: dict[str, Any] = {
        "cpu_percent": _num(os.environ.get("SNAPSHOT_CPU")),
        "load_1m": _num(os.environ.get("SNAPSHOT_LOAD1")),
        "load_5m": _num(os.environ.get("SNAPSHOT_LOAD5")),
        "load_15m": _num(os.environ.get("SNAPSHOT_LOAD15")),
        "mem_used_bytes": _num(os.environ.get("SNAPSHOT_MEM_USED")),
        "mem_total_bytes": _num(os.environ.get("SNAPSHOT_MEM_TOTAL")),
        "disk": disk,
        "uptime_seconds": _num(os.environ.get("SNAPSHOT_UPTIME")),
        "containers": containers if isinstance(containers, dict) else None,
        "network": network if isinstance(network, dict) else None,
    }

    # Состояние хоста — часть схемы v2. Оно полезно и без телеметрии угроз:
    # владелец должен видеть открытый парольный вход, даже если сбор угроз выключен.
    schema_version = 2 if (threats is not None or isinstance(posture, dict)) else 1
    payload: dict[str, Any] = {
        "schema_version": schema_version,
        "host_id": host_id[:128],
        "recorded_at": recorded_at[:48],
        "metrics": metrics,
        "checks": checks[:20],
    }
    # Версия скриптов агента. Не привязана к schema_version: платформе она нужна,
    # чтобы показать «агент устарел», а не чтобы разбирать снапшот иначе.
    # Пустая — агент поставлен до появления версий, платформа это отличает от
    # «версия неизвестна» и бейдж не рисует.
    agent_version = os.environ.get("SNAPSHOT_AGENT_VERSION", "").strip()
    if agent_version:
        payload["agent_version"] = agent_version[:64]
    if schema_version == 2 and isinstance(threats, dict):
        payload["threats"] = threats
    if schema_version == 2 and isinstance(posture, dict):
        payload["host_posture"] = posture
    # События контейнеров (ADR-0061). Как agent_version — вне schema_version:
    # старая платформа незнакомое поле отбрасывает, и снимок принимается.
    container_events = _json_load("SNAPSHOT_CONTAINER_EVENTS_JSON", None)
    if isinstance(container_events, dict):
        payload["container_events"] = container_events

    json.dump(payload, sys.stdout, separators=(",", ":"), ensure_ascii=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
