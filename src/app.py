import os
import sqlite3
import time
from pathlib import Path

import psutil
from flask import Flask, jsonify, render_template, render_template_string, request
from jinja2 import TemplateNotFound

try:
    from flask_cors import CORS
except ImportError:
    def CORS(app):
        return app


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
app = Flask(
    __name__,
    static_folder=str(STATIC_DIR),
    template_folder=str(TEMPLATE_DIR),
)
CORS(app)

SERVER_IP = "192.168.10.1"
DB_PATH = Path(os.getenv("VIGILANT_DB_PATH", "/home/vigilant_admin/vigilant/logs/vigilant.db"))

CONFIG_DEFAULTS = {
    "block_harmful": True,
    "block_distracting": False,
    "throttle_enabled": True,
    "velocity_threshold": 30,
}

ALLOWED_CONFIG_KEYS = set(CONFIG_DEFAULTS)
BOOLEAN_CONFIG_KEYS = {"block_harmful", "block_distracting", "throttle_enabled"}
INTEGER_CONFIG_KEYS = {"velocity_threshold"}
TRAFFIC_CATEGORIES = ("Educational", "Productive", "Distracting", "Harmful")


def _ensure_directory(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def _open_db() -> sqlite3.Connection:
    _ensure_directory(DB_PATH)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def query_db(query: str, args=(), one: bool = False):
    if not DB_PATH.exists():
        return None if one else []

    try:
        with sqlite3.connect(DB_PATH) as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(query, args)
            rows = cursor.fetchall()
            if one:
                return rows[0] if rows else None
            return rows
    except sqlite3.Error as exc:
        app.logger.warning("query_db failed: %s", exc)
        return None if one else []


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise ValueError("Invalid boolean value")


def _coerce_int(value):
    if isinstance(value, bool):
        raise ValueError("Invalid integer value")
    integer_value = int(value)
    if integer_value < 0:
        raise ValueError("Integer value must be non-negative")
    return integer_value


def _coerce_config_value(key: str, value):
    if key in BOOLEAN_CONFIG_KEYS:
        return _coerce_bool(value)
    if key in INTEGER_CONFIG_KEYS:
        return _coerce_int(value)
    raise ValueError(f"Unsupported configuration key: {key}")


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


def _format_uptime() -> str:
    uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    return f"{hours}h {minutes}m"


def _total_request_count() -> int:
    if not DB_PATH.exists():
        return 0
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return 0
            row = connection.execute("SELECT COUNT(*) FROM traffic_log").fetchone()
            return int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return 0


def _blocked_request_count() -> int:
    if not DB_PATH.exists():
        return 0
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return 0
            row = connection.execute("SELECT COUNT(*) FROM traffic_log WHERE flagged = 1").fetchone()
            return int(row[0] or 0) if row else 0
    except sqlite3.Error:
        return 0


def _get_recent_logs(limit: int = 10) -> list:
    if not DB_PATH.exists():
        return []
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return []
            rows = connection.execute(
                "SELECT timestamp, client_ip, host, category, flagged FROM traffic_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error:
        return []


def _traffic_percentage_metrics() -> dict:
    distribution = {category: 0.0 for category in TRAFFIC_CATEGORIES}

    if not DB_PATH.exists():
        return distribution

    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return distribution

            total_row = connection.execute("SELECT COUNT(*) FROM traffic_log").fetchone()
            total_logs = int(total_row[0] or 0) if total_row else 0
            if total_logs <= 0:
                return distribution

            category_rows = connection.execute(
                """
                SELECT LOWER(TRIM(category)) AS normalized_category, COUNT(*) AS category_count
                FROM traffic_log
                WHERE category IS NOT NULL AND TRIM(category) != ''
                GROUP BY LOWER(TRIM(category))
                """
            ).fetchall()

            category_counts = {str(row[0] or ""): int(row[1] or 0) for row in category_rows}

            for category in TRAFFIC_CATEGORIES:
                count = category_counts.get(category.lower(), 0)
                distribution[category] = (count / total_logs) * 100.0

    except sqlite3.Error as exc:
        app.logger.warning("traffic percentage metrics unavailable: %s", exc)

    return distribution


def _connected_device_count() -> int:
    if not DB_PATH.exists():
        return 0

    window_start = int(time.time()) - 86400

    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return 0

            row = connection.execute(
                """
                SELECT COUNT(DISTINCT client_ip)
                FROM traffic_log
                WHERE timestamp > ?
                """,
                (window_start,),
            ).fetchone()
            return int(row[0] or 0) if row else 0
    except sqlite3.Error as exc:
        app.logger.warning("connected device scan failed: %s", exc)
        return 0


def init_config_db() -> None:
    with _open_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS config_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at REAL
            )
            """
        )

        now_ts = time.time()
        for key, value in CONFIG_DEFAULTS.items():
            connection.execute(
                """
                INSERT INTO config_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, str(value), now_ts),
            )

        connection.commit()


def load_config() -> dict:
    config = dict(CONFIG_DEFAULTS)

    if not DB_PATH.exists():
        return config

    try:
        with _open_db() as connection:
            if not _table_exists(connection, "config_settings"):
                return config

            rows = connection.execute(
                "SELECT key, value FROM config_settings WHERE key IN (?, ?, ?, ?)",
                tuple(CONFIG_DEFAULTS.keys()),
            ).fetchall()

        for row in rows:
            key = str(row[0])
            if key not in ALLOWED_CONFIG_KEYS:
                continue

            raw_value = row[1]
            try:
                config[key] = _coerce_config_value(key, raw_value)
            except (TypeError, ValueError):
                config[key] = CONFIG_DEFAULTS[key]
    except sqlite3.Error as exc:
        app.logger.warning("load_config failed: %s", exc)

    return config


def save_config(updates: dict) -> None:
    if not isinstance(updates, dict):
        return

    filtered_updates = {}
    for key, value in updates.items():
        if key not in ALLOWED_CONFIG_KEYS:
            continue
        try:
            filtered_updates[key] = _coerce_config_value(key, value)
        except (TypeError, ValueError) as exc:
            app.logger.warning("save_config rejected %s: %s", key, exc)

    if not filtered_updates:
        return

    with _open_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS config_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at REAL
            )
            """
        )

        now_ts = time.time()
        for key, value in filtered_updates.items():
            connection.execute(
                """
                INSERT INTO config_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, str(value), now_ts),
            )

        connection.commit()


def _config_payload_from_request(payload: dict) -> tuple[dict, list[str]]:
    valid_updates = {}
    ignored_keys = []

    for key, value in payload.items():
        if key not in ALLOWED_CONFIG_KEYS:
            ignored_keys.append(key)
            continue

        valid_updates[key] = value

    return valid_updates, ignored_keys


@app.route("/")
@app.route('/index.html')
def dashboard():
    try:
        status_data = _service_statuses()
        # Correcting the alignment key to look for 'vigilant_proxy'
        proxy_active = status_data.get("vigilant_proxy") == "active"
        
        return render_template("dashboard.html", proxy_active=proxy_active)
    except Exception as e:
        import traceback
        error_msg = f"<h3>Jinja2 Error Details</h3><pre>{traceback.format_exc()}</pre>"
        return error_msg, 500


@app.route('/api/stats')
def get_stats():
    try:
        total_reqs = _total_request_count()
        blocked_reqs = _blocked_request_count()
        active_clients = _connected_device_count()
        raw_categories = _traffic_percentage_metrics()
        
        formatted_counts = [
            {"category": cat, "count": count} 
            for cat, count in raw_categories.items()
        ]
        
        raw_logs = _get_recent_logs(limit=10)
        formatted_recent = []
        for log in raw_logs:
            # Transform UNIX epoch safely if stored as numeric float/int from addon.py
            log_time = log.get("timestamp")
            if isinstance(log_time, (int, float)):
                log_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log_time))
            else:
                log_time = str(log_time or "Just Now")

            formatted_recent.append({
                "time": log_time,
                "client_ip": log.get("client_ip") or "0.0.0.0",
                "host": log.get("host") or "unknown",
                "category": log.get("category", "Unclassified"),
                "flagged": bool(log.get("flagged", 0))
            })

        active_throttles = [] 

        return jsonify({
            "total": total_reqs,
            "flagged": blocked_reqs,
            "clients": active_clients,
            "throttles": active_throttles,
            "counts": formatted_counts,
            "recent": formatted_recent
        })

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route('/api/settings', methods=['POST'])
def save_dashboard_settings():
    try:
        settings_data = request.json or {}
        return jsonify({"status": "success", "message": "Settings updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        return jsonify(load_config())

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object payload is required"}), 400

    valid_updates, ignored_keys = _config_payload_from_request(payload)

    if not valid_updates and not ignored_keys:
        return jsonify({"error": "No configuration keys supplied"}), 400

    if valid_updates:
        coerced_updates = {}
        validation_errors = []
        for key, value in valid_updates.items():
            try:
                coerced_updates[key] = _coerce_config_value(key, value)
            except (TypeError, ValueError) as exc:
                validation_errors.append(f"{key}: {exc}")

        if validation_errors:
            return jsonify({"error": "Invalid configuration values", "details": validation_errors}), 400

        save_config(coerced_updates)

    return jsonify(load_config())


def _compile_config_integrity() -> None:
    init_config_db()
    current_config = load_config()
    missing_defaults = {
        key: value for key, value in CONFIG_DEFAULTS.items() if key not in current_config
    }
    if missing_defaults:
        save_config(missing_defaults)


if __name__ == "__main__":
    _compile_config_integrity()
    app.run(host="0.0.0.0", port=5000, debug=False)