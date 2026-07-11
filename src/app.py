import os
import sqlite3
import time
from pathlib import Path

import psutil
from flask import Flask, jsonify, render_template, request

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
# Environment-aware DB path: production path via env var, fallback to local development path
PRODUCTION_DB_PATH = Path("/home/vigilant_admin/vigilant/logs/vigilant.db")
LOCAL_DB_PATH = BASE_DIR / "logs" / "vigilant.db"

# Use production path if it exists and is writable, otherwise use local development path
if PRODUCTION_DB_PATH.exists() and os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
    DB_PATH = PRODUCTION_DB_PATH
else:
    DB_PATH = LOCAL_DB_PATH

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


def _get_recent_logs(limit: int = 10, offset: int = 0) -> list:
    if not DB_PATH.exists():
        return []
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return []
            rows = connection.execute(
                "SELECT timestamp, client_ip, host, category, flagged FROM traffic_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error:
        return []


def _format_recent_log_entry(log: dict) -> dict:
    timestamp_value = log.get("timestamp")
    if isinstance(timestamp_value, (int, float)):
        formatted_time = time.strftime('%H:%M:%S', time.localtime(timestamp_value))
    else:
        formatted_time = str(timestamp_value or "Just Now")

    return {
        "time": formatted_time,
        "client_ip": log.get("client_ip") or "0.0.0.0",
        "host": log.get("host") or "unknown",
        "category": log.get("category", "Unclassified"),
        "flagged": bool(log.get("flagged", 0)),
    }


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
    proxy_active = _service_statuses().get("vigilant_proxy") == "active"
    return render_template("dashboard.html", proxy_active=proxy_active)


@app.route('/api/stats')
def get_stats():
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Validate pagination parameters
        page = max(1, page)
        per_page = max(1, min(per_page, 100))  # Cap at 100 per page
        
        offset = (page - 1) * per_page
        
        total_reqs = _total_request_count()
        blocked_reqs = _blocked_request_count()
        active_clients = _connected_device_count()
        raw_categories = _traffic_percentage_metrics()

        formatted_counts = [
            {"category": category, "count": count}
            for category, count in raw_categories.items()
        ]

        raw_logs = _get_recent_logs(limit=per_page, offset=offset)
        formatted_recent = [_format_recent_log_entry(log) for log in raw_logs]
        
        # Calculate pagination metadata
        total_pages = (total_reqs + per_page - 1) // per_page if total_reqs > 0 else 1
        
        # System metrics using psutil
        cpu_usage = psutil.cpu_percent(interval=0.1)
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage('/').percent

        return jsonify({
            "total": total_reqs,
            "flagged": blocked_reqs,
            "clients": active_clients,
            "counts": formatted_counts,
            "recent": formatted_recent,
            "uptime": _format_uptime(),
            "statuses": _service_statuses(),
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "total_items": total_reqs
            },
            "system_metrics": {
                "cpu_percent": cpu_usage,
                "memory_percent": memory_usage,
                "disk_percent": disk_usage
            }
        })

    except Exception as exc:
        app.logger.error("Failed to compile /api/stats payload: %s", exc)
        return jsonify({"error": str(exc)}), 500

@app.route('/api/settings', methods=['POST'])
def save_dashboard_settings():
    try:
        settings_data = request.get_json(silent=True) or {}
        if not isinstance(settings_data, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        save_config(settings_data)
        return jsonify({"status": "success", "message": "Settings updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/reset", methods=["POST"])
def api_reset():
    try:
        save_config(CONFIG_DEFAULTS)
        return jsonify({"status": "success", "message": "Settings reset to defaults"})
    except Exception as exc:
        app.logger.error("Failed to reset configuration: %s", exc)
        return jsonify({"error": str(exc)}), 500


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


def _init_traffic_db() -> None:
    """Initialize traffic_log table with schema matching vigilant_addon.py"""
    with _open_db() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL,
                client_ip   TEXT,
                host        TEXT,
                path        TEXT,
                method      TEXT,
                category    TEXT,
                flagged     INTEGER DEFAULT 0,
                entities    TEXT
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS throttle_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL,
                client_ip   TEXT,
                host        TEXT,
                rpm_current REAL,
                rpm_baseline REAL,
                action      TEXT
            )
            """
        )
        connection.commit()


def _populate_mock_traffic_data() -> None:
    """Populate traffic_log with 25 rows of mock data for local development"""
    import random
    
    mock_categories = ["Educational", "Productive", "Distracting", "Harmful", "Uncategorized"]
    mock_hosts = [
        "wikipedia.org", "github.com", "reddit.com", "twitter.com", 
        "youtube.com", "stackoverflow.com", "docs.python.org", "khanacademy.org",
        "notion.so", "slack.com", "tiktok.com", "instagram.com", "facebook.com"
    ]
    mock_client_ips = ["192.168.10.15", "192.168.10.20", "192.168.10.25", "192.168.10.30", "192.168.10.35"]
    mock_methods = ["GET", "POST", "GET", "GET", "GET", "PUT", "DELETE"]
    mock_paths = ["/api/data", "/home", "/user/profile", "/search", "/video/watch", "/settings", "/dashboard"]
    
    with _open_db() as connection:
        # Check if table is empty
        count = connection.execute("SELECT COUNT(*) FROM traffic_log").fetchone()[0]
        if count > 0:
            return  # Already has data
        
        # Insert 25 mock rows
        now = time.time()
        for i in range(25):
            timestamp = now - (i * 300)  # Stagger timestamps by 5 minutes
            client_ip = random.choice(mock_client_ips)
            host = random.choice(mock_hosts)
            path = random.choice(mock_paths)
            method = random.choice(mock_methods)
            category = random.choice(mock_categories)
            flagged = 1 if category == "Harmful" else 0
            entities = "[]"
            
            connection.execute(
                """
                INSERT INTO traffic_log (timestamp, client_ip, host, path, method, category, flagged, entities)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (timestamp, client_ip, host, path, method, category, flagged, entities)
            )
        connection.commit()


def _compile_config_integrity() -> None:
    _init_traffic_db()
    _populate_mock_traffic_data()
    init_config_db()
    current_config = load_config()
    missing_defaults = {
        key: value for key, value in CONFIG_DEFAULTS.items() if key not in current_config
    }
    if missing_defaults:
        save_config(missing_defaults)


if __name__ == "__main__":
    _compile_config_integrity()
    # Use port 5002 for local development to avoid conflicts
    app.run(host="0.0.0.0", port=5002, debug=False)