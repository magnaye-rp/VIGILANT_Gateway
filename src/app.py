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


app = Flask(__name__, static_folder="static", template_folder="templates")
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


def _dashboard_fallback_html(server_ip: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VIGILANT GATEWAY</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #07111f;
      --panel: rgba(8, 18, 32, 0.9);
      --panel-border: rgba(145, 188, 255, 0.18);
      --text: #e7eef8;
      --muted: #9fb0c7;
      --accent: #7dd3fc;
      --accent-2: #22c55e;
      --danger: #fb7185;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(125, 211, 252, 0.18), transparent 30%),
        radial-gradient(circle at top right, rgba(34, 197, 94, 0.12), transparent 25%),
        linear-gradient(180deg, #07111f 0%, #050a12 100%);
      color: var(--text);
      min-height: 100vh;
    }}
    .shell {{ max-width: 1120px; margin: 0 auto; padding: 28px 18px 44px; }}
    .hero {{
      padding: 28px;
      border: 1px solid var(--panel-border);
      background: var(--panel);
      border-radius: 24px;
      box-shadow: 0 24px 72px rgba(0, 0, 0, 0.35);
      backdrop-filter: blur(16px);
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(125, 211, 252, 0.12);
      color: var(--accent);
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 14px;
    }}
    h1 {{ margin: 0; font-size: clamp(2rem, 4vw, 3.6rem); line-height: 1.05; }}
    .lede {{ max-width: 72ch; color: var(--muted); font-size: 1.02rem; line-height: 1.7; margin: 16px 0 0; }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
      margin-top: 18px;
    }}
    .card {{
      padding: 18px;
      border-radius: 20px;
      border: 1px solid var(--panel-border);
      background: rgba(5, 10, 18, 0.7);
      min-height: 150px;
    }}
    .card h2 {{ margin: 0 0 8px; font-size: 1.08rem; }}
    .card p, .card li {{ color: var(--muted); line-height: 1.65; }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 8px;
      padding: 7px 11px;
      border-radius: 999px;
      background: rgba(34, 197, 94, 0.14);
      color: #c7f9d3;
      font-size: 0.92rem;
    }}
    .tabs {{ margin-top: 22px; }}
    .tab-strip {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }}
    .tab-strip div {{
      padding: 12px 14px;
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      font-weight: 600;
    }}
    .tab-panel {{
      margin-top: 12px;
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }}
    .pill {{
      padding: 12px 14px;
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.04);
      border: 1px dashed rgba(125, 211, 252, 0.25);
      color: var(--text);
    }}
    code {{ color: var(--accent); }}
    @media (max-width: 900px) {{
      .grid, .tab-strip, .tab-panel {{ grid-template-columns: 1fr; }}
      .hero {{ padding: 20px; }}
    }}
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="eyebrow">VIGILANT Gateway staging shell</div>
      <h1>Secure gateway control surface</h1>
      <p class="lede">The dashboard template is unavailable, so the backend is serving a safe inline view at server IP <code>{server_ip}</code>. This fallback keeps the production route online while the full templates are staged.</p>
      <div class="badge">200 OK fallback active</div>
    </section>

    <section class="grid" aria-label="dashboard overview">
      <article class="card">
        <h2>Tab 1: Dashboard</h2>
        <p>Live status, uptime, connected device count, and traffic percentages are exposed through <code>/api/stats</code>.</p>
      </article>
      <article class="card">
        <h2>Tab 2: Configurations</h2>
        <p>Basic Mode and Advanced Mode share a strict whitelist. Only the mobile-safe and web-safe settings are accepted.</p>
      </article>
      <article class="card">
        <h2>Tab 3: Setup Guide</h2>
        <p>Use the setup guide to finish deployment wiring, confirm database seeding, and validate the gateway listener.</p>
      </article>
    </section>

    <section class="tabs" aria-label="tab structure">
      <div class="tab-strip">
        <div>Tab 1 - Dashboard</div>
        <div>Tab 2 - Configurations [Basic / Advanced Toggle]</div>
        <div>Tab 3 - Setup Guide</div>
      </div>
      <div class="tab-panel">
        <div class="pill">Server IP: <strong>{server_ip}</strong></div>
        <div class="pill">Basic Mode: block harmful + distracting content</div>
        <div class="pill">Advanced Mode: throttle enabled + velocity threshold</div>
      </div>
    </section>
  </main>
</body>
</html>"""


@app.route("/")
def index():
    try:
        return render_template("pages/dashboard.html", server_ip=SERVER_IP)
    except TemplateNotFound as exc:
        print(f"TemplateNotFound while rendering pages/dashboard.html: {exc}")
        app.logger.exception("Dashboard template missing; serving inline fallback")
        return render_template_string(_dashboard_fallback_html(SERVER_IP)), 200


@app.route("/api/stats")
def api_stats():
    try:
        payload = {
            "server_status": _service_statuses(),
            "connected_devices": _connected_device_count(),
            "online_duration": _format_uptime(),
            "percentage_metrics": _traffic_percentage_metrics(),
        }
        return jsonify(payload)
    except Exception as exc:
        app.logger.exception("Failed to build /api/stats payload")
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