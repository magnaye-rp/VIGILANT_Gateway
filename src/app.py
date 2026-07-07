import os
import sqlite3
import time
from pathlib import Path

import psutil
from flask import Flask, jsonify, render_template, request
from jinja2 import TemplateNotFound


app = Flask(__name__, static_folder="static")

SERVER_IP = "192.168.10.1"
DB_PATH = Path(os.getenv("VIGILANT_DB_PATH", "/home/vigilant_admin/vigilant/logs/vigilant.db"))

CONFIG_DEFAULTS = {
    "block_harmful": True,
    "block_distracting": False,
    "throttle_enabled": True,
    "velocity_threshold": 30,
}

CONFIG_BOOL_KEYS = {"block_harmful", "block_distracting", "throttle_enabled"}
CONFIG_INT_KEYS = {"velocity_threshold"}
ALLOWED_CONFIG_KEYS = set(CONFIG_DEFAULTS)
CONFIG_QUERY_KEYS = tuple(CONFIG_DEFAULTS.keys())

TRAFFIC_CATEGORIES = ("Educational", "Productive", "Distracting", "Harmful")


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _format_uptime() -> str:
    uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    return f"{hours}h {minutes}m"


def _service_statuses() -> dict:
    current_pid = os.getpid()
    proxy_active = False
    dashboard_active = False

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            info = proc.info
            pid = info.get("pid")
            name = (info.get("name") or "").lower()
            cmdline = " ".join(str(item).lower() for item in (info.get("cmdline") or []))

            if not proxy_active and ("mitmdump" in name or "mitmdump" in cmdline):
                proxy_active = True

            if (
                not dashboard_active
                and pid != current_pid
                and ("app.py" in name or "app.py" in cmdline)
            ):
                dashboard_active = True

            if proxy_active and dashboard_active:
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return {
        "vigilant_proxy": "active" if proxy_active else "offline",
        "vigilant_dashboard": "active" if dashboard_active else "offline",
        "vigilant_firewall": "active",
    }


def _read_traffic_stats() -> dict:
    stats = {
        "connected_devices": 0,
        "total_requests": 0,
        "traffic_distribution": {
            category: {"count": 0, "percentage": 0.0} for category in TRAFFIC_CATEGORIES
        },
    }

    if not DB_PATH.exists():
        return stats

    with sqlite3.connect(DB_PATH) as connection:
        if not _table_exists(connection, "traffic_log"):
            return stats

        window_start = int(time.time()) - 86400

        try:
            row = connection.execute(
                """
                SELECT COUNT(DISTINCT client_ip)
                FROM traffic_log
                WHERE timestamp > ?
                """,
                (window_start,),
            ).fetchone()
            stats["connected_devices"] = int(row[0] or 0)
        except sqlite3.Error:
            stats["connected_devices"] = 0

        total_row = connection.execute("SELECT COUNT(*) FROM traffic_log").fetchone()
        total_requests = int(total_row[0] or 0)
        stats["total_requests"] = total_requests

        category_rows = connection.execute(
            """
            SELECT LOWER(TRIM(category)) AS normalized_category, COUNT(*) AS request_count
            FROM traffic_log
            GROUP BY LOWER(TRIM(category))
            """
        ).fetchall()

        counts = {str(row[0] or ""): int(row[1] or 0) for row in category_rows}

        for category in TRAFFIC_CATEGORIES:
            count = counts.get(category.lower(), 0)
            percentage = round((count / total_requests) * 100, 2) if total_requests else 0.0
            stats["traffic_distribution"][category] = {
                "count": count,
                "percentage": percentage,
            }

    return stats


def _load_runtime_config() -> dict:
    config = dict(CONFIG_DEFAULTS)

    if not DB_PATH.exists():
        return config

    with sqlite3.connect(DB_PATH) as connection:
        if not _table_exists(connection, "config_settings"):
            return config

        rows = connection.execute(
            "SELECT key, value FROM config_settings WHERE key IN (?, ?, ?, ?)",
            CONFIG_QUERY_KEYS,
        ).fetchall()

    for key, raw_value in rows:
        if key not in ALLOWED_CONFIG_KEYS:
            continue

        try:
            if key in CONFIG_BOOL_KEYS:
                if isinstance(raw_value, bool):
                    config[key] = raw_value
                else:
                    lowered = str(raw_value).strip().lower()
                    if lowered in {"1", "true", "yes", "on"}:
                        config[key] = True
                    elif lowered in {"0", "false", "no", "off"}:
                        config[key] = False
                    else:
                        raise ValueError
            elif key in CONFIG_INT_KEYS:
                value = int(raw_value)
                if value < 0:
                    raise ValueError
                config[key] = value
        except (TypeError, ValueError):
            config[key] = CONFIG_DEFAULTS[key]

    return config


def _ensure_config_table(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS config_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at REAL
        )
        """
    )


def _write_runtime_config(updates: dict) -> None:
    now_ts = time.time()
    with sqlite3.connect(DB_PATH) as connection:
        _ensure_config_table(connection)
        connection.executemany(
            """
            INSERT INTO config_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            [(key, str(value), now_ts) for key, value in updates.items()],
        )
        connection.commit()


def _coerce_config_value(key: str, value):
    if key in CONFIG_BOOL_KEYS:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        raise ValueError(f"Invalid boolean value for {key}")

    if key in CONFIG_INT_KEYS:
        if isinstance(value, bool):
            raise ValueError(f"Invalid integer value for {key}")
        integer_value = int(value)
        if integer_value < 0:
            raise ValueError(f"{key} must be >= 0")
        return integer_value

    raise ValueError(f"Unsupported config key: {key}")


def _normalize_config_payload(payload: dict) -> tuple[dict, list, list]:
    valid_updates = {}
    ignored_keys = []
    validation_errors = []

    for key, raw_value in payload.items():
        if key not in ALLOWED_CONFIG_KEYS:
            ignored_keys.append(key)
            continue

        try:
            valid_updates[key] = _coerce_config_value(key, raw_value)
        except (TypeError, ValueError) as exc:
            validation_errors.append(str(exc))

    return valid_updates, ignored_keys, validation_errors


@app.route("/")
def index():
    try:
        return render_template("pages/dashboard.html", server_ip=SERVER_IP)
    except TemplateNotFound as exc:
        print(f"[index] TemplateNotFound while rendering pages/dashboard.html: {exc}")
        app.logger.exception("Dashboard template missing for index route")
        message = (
            "Dashboard template unavailable: "
            "pages/dashboard.html could not be located, so the unified layout cannot render."
        )
        return message, 500


@app.route("/api/stats")
def api_stats():
    try:
        traffic_stats = _read_traffic_stats()
        payload = {
            "server_ip": SERVER_IP,
            "server_status": _service_statuses(),
            "connected_devices": traffic_stats["connected_devices"],
            "online_duration": _format_uptime(),
            "traffic_distribution": traffic_stats["traffic_distribution"],
            "total_requests": traffic_stats["total_requests"],
            "tracking_model": {
                "client_visibility": "passive_dns_and_tls_clienthello_sni",
                "https_decryption": False,
                "custom_root_certificate_required": False,
            },
            "generated_at": int(time.time()),
        }
        return jsonify(payload)
    except Exception as exc:
        app.logger.exception("Failed to build /api/stats payload")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        return jsonify(_load_runtime_config())

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object payload is required"}), 400

    valid_updates, ignored_keys, validation_errors = _normalize_config_payload(payload)

    if validation_errors:
        return jsonify({"error": "Invalid configuration values", "details": validation_errors}), 400

    if not valid_updates:
        return (
            jsonify(
                {
                    "error": "No valid runtime configuration keys supplied",
                    "allowed_keys": sorted(ALLOWED_CONFIG_KEYS),
                    "ignored_keys": ignored_keys,
                }
            ),
            400,
        )

    _write_runtime_config(valid_updates)
    response = _load_runtime_config()
    if ignored_keys:
        response["ignored_keys"] = ignored_keys
    return jsonify(response)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)