import os
import re
import sqlite3
import time
import importlib
import importlib.util
import platform
import json
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None
yaml = importlib.import_module("yaml") if importlib.util.find_spec("yaml") else None
from flask import Flask, jsonify, render_template, request

try:
    from flask_cors import CORS
except ImportError:
    def CORS(app):
        return app


# Environment detector: Production server vs local MacBook Air development
IS_PRODUCTION = (platform.system() == "Linux" and os.path.exists("/home/vigilant_admin"))

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
    "upstream_interface": "enp0s31f6",
    "distribution_interface": "wlp1s0",
    "gateway_ip": "192.168.10.1",
    "dhcp_start": "192.168.10.10",
    "dhcp_end": "192.168.10.50",
    "dns_servers": "8.8.8.8,8.8.4.4",
}

ALLOWED_CONFIG_KEYS = set(CONFIG_DEFAULTS)
BOOLEAN_CONFIG_KEYS = {"block_harmful", "block_distracting", "throttle_enabled"}
INTEGER_CONFIG_KEYS = {"velocity_threshold"}
STRING_CONFIG_KEYS = {"upstream_interface", "distribution_interface", "gateway_ip", "dhcp_start", "dhcp_end", "dns_servers"}
TRAFFIC_CATEGORIES = ("Educational", "Productive", "Distracting", "Harmful")
DEFAULT_SYSTEM_METRICS = {
    "cpu_percent": 0.0,
    "memory_percent": 0.0,
    "disk_percent": 52.0,
}


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
    if key in STRING_CONFIG_KEYS:
        return str(value).strip()
    raise ValueError(f"Unsupported configuration key: {key}")


def _service_statuses() -> dict:
    if psutil is None:
        return {
            "vigilant_proxy": "offline",
            "vigilant_dashboard": "offline",
            "vigilant_firewall": "active",
        }

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
    if psutil is None:
        return "0h 0m"

    try:
        uptime_seconds = max(0, int(time.time() - psutil.boot_time()))
    except Exception:
        return "0h 0m"

    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    return f"{hours}h {minutes}m"


def _system_metrics() -> dict:
    if psutil is None:
        return dict(DEFAULT_SYSTEM_METRICS)

    try:
        return {
            "cpu_percent": float(psutil.cpu_percent(interval=0.1)),
            "memory_percent": float(psutil.virtual_memory().percent),
            "disk_percent": float(psutil.disk_usage('/').percent),
        }
    except Exception as exc:
        app.logger.warning("system metrics unavailable: %s", exc)
        return dict(DEFAULT_SYSTEM_METRICS)


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


def _parse_dnsmasq_config() -> dict:
    """Parse dnsmasq.conf to extract network settings"""
    config_path = BASE_DIR / "config" / "dnsmasq.conf"
    if not config_path.exists():
        config_path = Path("/etc/dnsmasq.conf")
    
    settings = {
        "interface": "wlp1s0",
        "listen_address": "192.168.10.1",
        "dhcp_start": "192.168.10.10",
        "dhcp_end": "192.168.10.50",
        "dns_servers": ["8.8.8.8", "8.8.4.4"]
    }
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("interface="):
                        settings["interface"] = line.split("=", 1)[1].strip()
                    elif line.startswith("listen-address="):
                        settings["listen_address"] = line.split("=", 1)[1].strip()
                    elif line.startswith("dhcp-range="):
                        dhcp_range = line.split("=", 1)[1].strip()
                        parts = dhcp_range.split(",")
                        if len(parts) >= 2:
                            settings["dhcp_start"] = parts[0].strip()
                            settings["dhcp_end"] = parts[1].strip()
                    elif line.startswith("server="):
                        dns = line.split("=", 1)[1].strip()
                        if dns not in settings["dns_servers"]:
                            settings["dns_servers"].append(dns)
        except Exception as exc:
            app.logger.warning("Failed to parse dnsmasq.conf: %s", exc)
    
    return settings


def _parse_netplan_config() -> dict:
    """Parse netplan-config.yaml to extract interface settings"""
    config_path = BASE_DIR / "config" / "netplan-config.yaml"
    if not config_path.exists():
        config_path = Path("/etc/netplan/00-installer-config.yaml")
    
    settings = {
        "upstream_interface": "enp0s31f6",
        "distribution_interface": "wlp1s0",
        "lan_address": "192.168.10.1/24"
    }
    
    if yaml is None or not config_path.exists():
        return settings

    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                netplan_config = yaml.safe_load(f)
                if netplan_config and "network" in netplan_config:
                    ethernets = netplan_config["network"].get("ethernets", {})
                    for iface_name, iface_config in ethernets.items():
                        if iface_config.get("dhcp4") == True:
                            settings["upstream_interface"] = iface_name
                        elif "addresses" in iface_config:
                            settings["distribution_interface"] = iface_name
                            settings["lan_address"] = iface_config["addresses"][0] if iface_config["addresses"] else "192.168.10.1/24"
        except Exception as exc:
            app.logger.warning("Failed to parse netplan-config.yaml: %s", exc)
    
    return settings


def _get_network_config() -> dict:
    """Get network configuration from config files or use dev defaults"""
    if IS_PRODUCTION:
        # Production: Parse actual config files
        dnsmasq_settings = _parse_dnsmasq_config()
        netplan_settings = _parse_netplan_config()
        
        # Merge settings, preferring netplan for interfaces
        return {
            "upstream_interface": netplan_settings.get("upstream_interface", "enp0s31f6"),
            "distribution_interface": dnsmasq_settings.get("interface", netplan_settings.get("distribution_interface", "wlp1s0")),
            "gateway_ip": dnsmasq_settings.get("listen_address", "192.168.10.1"),
            "dhcp_start": dnsmasq_settings.get("dhcp_start", "192.168.10.10"),
            "dhcp_end": dnsmasq_settings.get("dhcp_end", "192.168.10.50"),
            "dns_servers": ",".join(dnsmasq_settings.get("dns_servers", ["8.8.8.8", "8.8.4.4"]))
        }
    else:
        # Local MacBook Air development: Hardcoded mock configuration
        return {
            "upstream_interface": "en0",
            "distribution_interface": "wlp1s0",
            "gateway_ip": "192.168.10.1",
            "dhcp_start": "192.168.10.10",
            "dhcp_end": "192.168.10.50",
            "dns_servers": "8.8.8.8,8.8.4.4"
        }


def _get_network_interfaces() -> list:
    """Get list of available network interfaces from system"""
    if IS_PRODUCTION:
        # Production: Use psutil to detect actual hardware interfaces
        if psutil is not None:
            try:
                interfaces = list(psutil.net_if_addrs().keys())
                # Filter out loopback and virtual interfaces for cleaner list
                filtered = [iface for iface in interfaces if not iface.startswith('lo') and not iface.startswith('veth') and not iface.startswith('docker')]
                if filtered:
                    return sorted(filtered)
            except Exception as exc:
                app.logger.warning("Failed to get network interfaces via psutil: %s", exc)
        return []
    else:
        # Local MacBook Air development: Hardcoded mock interfaces
        return ["en0", "wlp1s0", "lo0"]


def _get_dev_mock_data() -> dict:
    """Return mock data for local development environment"""
    return {
        "upstream_interface": "en0",
        "distribution_interface": "wlp1s0",
        "gateway_ip": "192.168.10.1",
        "dhcp_start": "192.168.10.10",
        "dhcp_end": "192.168.10.50",
        "dns_servers": "8.8.8.8,8.8.4.4",
        "cpu_percent": 12.5,
        "memory_percent": 45.2,
        "disk_percent": 62.8,
        "available_interfaces": ["en0", "wlp1s0", "lo0"]
    }


def init_config_db() -> None:
    try:
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
    except sqlite3.Error as exc:
        app.logger.debug(
            "init_config_db: could not create or seed config_settings table "
            "(access violation or locked database) — %s",
            exc,
        )


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
        
        system_metrics = _system_metrics()

        # Network configuration from config files
        network_config = _get_network_config()
        
        # Add available network interfaces
        network_config["available_interfaces"] = _get_network_interfaces()
        
        # Use dev mock data if in local development environment
        is_dev_env = DB_PATH == LOCAL_DB_PATH
        if is_dev_env:
            dev_data = _get_dev_mock_data()
            network_config.update(dev_data)
            system_metrics.update({
                "cpu_percent": dev_data.get("cpu_percent", system_metrics["cpu_percent"]),
                "memory_percent": dev_data.get("memory_percent", system_metrics["memory_percent"]),
                "disk_percent": dev_data.get("disk_percent", system_metrics["disk_percent"]),
            })

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
                "cpu_percent": system_metrics["cpu_percent"],
                "memory_percent": system_metrics["memory_percent"],
                "disk_percent": system_metrics["disk_percent"]
            },
            "network_config": network_config
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


@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    """Clear all traffic logs and vacuum the database"""
    try:
        if not DB_PATH.exists():
            return jsonify({"status": "success", "message": "No logs to clear (database doesn't exist)"})

        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return jsonify({"status": "success", "message": "No logs to clear (table doesn't exist)"})

            connection.execute("DELETE FROM traffic_log")
            connection.commit()

            try:
                connection.execute("VACUUM")
            except sqlite3.Error as vacuum_exc:
                app.logger.warning("VACUUM skipped after clearing logs: %s", vacuum_exc)
        
        app.logger.info("Traffic logs cleared successfully")
        return jsonify({"status": "success", "message": "Traffic logs cleared successfully"})
    except sqlite3.Error as exc:
        app.logger.error("Failed to clear logs: %s", exc)
        return jsonify({"error": str(exc)}), 500
    except Exception as exc:
        app.logger.error("Unexpected error clearing logs: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        config = load_config()
        # Add network configuration from config files
        network_config = _get_network_config()
        
        # Add available network interfaces
        network_config["available_interfaces"] = _get_network_interfaces()
        
        # Use dev mock data if in local development environment
        is_dev_env = DB_PATH == LOCAL_DB_PATH
        if is_dev_env:
            dev_data = _get_dev_mock_data()
            network_config.update(dev_data)
        
        # Merge network config into response
        config.update(network_config)
        return jsonify(config)

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
        
        # If in local development, also save to dev_config.json for simulation
        if not IS_PRODUCTION:
            dev_config_path = BASE_DIR / "dev_config.json"
            try:
                current_config = load_config()
                current_config.update(coerced_updates)
                with open(dev_config_path, 'w') as f:
                    json.dump(current_config, f, indent=2)
                app.logger.info(f"Configuration saved to {dev_config_path}")
            except Exception as exc:
                app.logger.warning(f"Failed to save dev_config.json: {exc}")

    config = load_config()
    network_config = _get_network_config()
    is_dev_env = DB_PATH == LOCAL_DB_PATH
    if is_dev_env:
        dev_data = _get_dev_mock_data()
        network_config.update(dev_data)
    config.update(network_config)
    return jsonify(config)


def _init_traffic_db() -> None:
    """Initialize traffic_log table with schema matching vigilant_addon.py"""
    try:
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
    except sqlite3.Error as exc:
        app.logger.debug(
            "_init_traffic_db: could not create traffic_log or throttle_events table "
            "(access violation or locked database) — %s",
            exc,
        )


def _populate_mock_traffic_data() -> None:
    """Populate traffic_log with 35 rows of mock data for local development"""
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
        
        # Insert 35 mock rows
        now = time.time()
        for i in range(35):
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
    try:
        _init_traffic_db()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: _init_traffic_db skipped — %s", exc)

    try:
        _populate_mock_traffic_data()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: _populate_mock_traffic_data skipped — %s", exc)

    try:
        init_config_db()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: init_config_db skipped — %s", exc)

    try:
        current_config = load_config()
        missing_defaults = {
            key: value for key, value in CONFIG_DEFAULTS.items() if key not in current_config
        }
        if missing_defaults:
            save_config(missing_defaults)
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: default config backfill skipped — %s", exc)


if __name__ == "__main__":
    _compile_config_integrity()
    # Use port 5002 for local development to avoid conflicts
    app.run(host="0.0.0.0", port=5002, debug=False)