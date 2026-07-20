import os
import re
import sqlite3
import subprocess
import threading
import time
import importlib
import importlib.util
import csv
import io
import socket
from pathlib import Path
import platform
from collections import deque
import json

# Global network interface configuration - can be overridden via environment variable
GATEWAY_INTERFACE = os.getenv("GATEWAY_INTERFACE", "eth1")

try:
    import psutil
except ImportError:
    psutil = None

yaml = importlib.import_module("yaml") if importlib.util.find_spec("yaml") else None
from flask import Flask, jsonify, render_template, request, make_response, send_file, abort, redirect, flash, url_for

try:
    from flask_cors import CORS
except ImportError:
    def CORS(app):
        return app

scroll_velocity_tracker = {}

# System-level network tracking (psutil.net_io_counters objects)
_last_system_net_io = None
_last_system_net_time = 0

# Interface-level network tracking (dicts with rx_bytes/tx_bytes)
_last_interface_net_io = None
_last_interface_net_time = 0

# --- CACHE FOR HEAVY SYSTEM CALLS ---
_service_status_cache = {}
_service_cache_time = 0
CACHE_TTL = 3.0  # Cache psutil process scans for 3 seconds

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

app = Flask(
    __name__,
    static_folder=str(STATIC_DIR),
    template_folder=str(TEMPLATE_DIR),
)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = "super_secret_vigilant_key"

SERVER_IP = "192.168.100.88"
PRODUCTION_DB_PATH = Path("/home/vigilant_admin/vigilant/logs/vigilant.db")
LOCAL_DB_PATH = BASE_DIR / "logs" / "vigilant.db"

# Select database path with permission-aware fallback logic
DB_PATH = LOCAL_DB_PATH  # Default to local path
try:
    if PRODUCTION_DB_PATH.parent.exists():
        if os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
            DB_PATH = PRODUCTION_DB_PATH
        else:
            app.logger.warning("Production DB path exists but not writable, using local path: %s", LOCAL_DB_PATH)
    else:
        # Try to create production directory if it doesn't exist
        try:
            PRODUCTION_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
            if os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
                DB_PATH = PRODUCTION_DB_PATH
                app.logger.info("Created production DB directory: %s", PRODUCTION_DB_PATH.parent)
            else:
                app.logger.warning("Created production DB directory but not writable, using local path")
        except (PermissionError, OSError) as exc:
            app.logger.warning("Cannot create production DB directory, using local path: %s", exc)
except Exception as exc:
    app.logger.warning("Error selecting DB path, using local: %s", exc)
    DB_PATH = LOCAL_DB_PATH

DEFAULT_CONFIG = {
    "upstream_interface": "eth0",
    "distribution_interface": "eth1",
    "gateway_ip": "192.168.100.88",
    "dhcp_start": "192.168.100.10",
    "dhcp_end": "192.168.100.50",
    "upstream_dns": "8.8.8.8\n8.8.4.4",
    "nlp_enabled": "true",
    "nlp_accuracy": "balanced",
    "network_velocity_threshold": "1.5",
    "physical_scroll_threshold": "75",
    "throttle_enabled": "true",
    "throttle_rate": "256",
    "ui_theme": "light",
    "tfidf_classification_threshold": "0.05",
    "tfidf_url_threshold": "0.3",
    "tfidf_body_threshold": "0.15"
}

CONFIG_DEFAULTS = DEFAULT_CONFIG

ALLOWED_CONFIG_KEYS = set(CONFIG_DEFAULTS) | {
    "block_harmful", "block_distracting", "enable_https", "log_retention", 
    "network_velocity_preset", "network_velocity_custom", "physical_scroll_preset", 
    "physical_scroll_custom", "sni_filtering_enabled", "request_threshold"
}
BOOLEAN_CONFIG_KEYS = {"block_harmful", "block_distracting", "nlp_enabled", "throttle_enabled", "enable_https", "sni_filtering_enabled"}
INTEGER_CONFIG_KEYS = {"network_velocity_threshold", "physical_scroll_threshold", "throttle_rate", "log_retention", "network_velocity_custom", "physical_scroll_custom", "request_threshold"}
STRING_CONFIG_KEYS = {"upstream_interface", "distribution_interface", "gateway_ip", "dhcp_start", "dhcp_end", "upstream_dns", "nlp_accuracy", "ui_theme", "network_velocity_preset", "physical_scroll_preset", "tfidf_classification_threshold", "tfidf_url_threshold", "tfidf_body_threshold"}
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
        return {} if one else []

    try:
        with sqlite3.connect(DB_PATH) as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(query, args)
            rows = cursor.fetchall()
            if one:
                return dict(rows[0]) if rows else {}
            return list(rows) if rows else []
    except Exception as exc:
        app.logger.warning("query_db failed: %s", exc)
        return {} if one else []


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
    """Optimized with a TTL cache to avoid hammering the OS with process iterations."""
    global _service_status_cache, _service_cache_time
    now = time.time()
    
    if _service_status_cache and (now - _service_cache_time < CACHE_TTL):
        return _service_status_cache

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

    _service_status_cache = {
        "vigilant_proxy": "active" if proxy_active else "offline",
        "vigilant_dashboard": "active" if dashboard_active else "offline",
        "vigilant_firewall": "active",
    }
    _service_cache_time = now
    return _service_status_cache


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
            "cpu_percent": float(psutil.cpu_percent(interval=None)),
            "memory_percent": float(psutil.virtual_memory().percent),
            "disk_percent": float(psutil.disk_usage('/').percent),
        }
    except Exception as exc:
        app.logger.warning("system metrics unavailable: %s", exc)
        return dict(DEFAULT_SYSTEM_METRICS)


def _calculate_category_percentages(category_counts: dict) -> dict:
    classified = {c.lower() for c in TRAFFIC_CATEGORIES}
    categorized_total = sum(count for cat, count in category_counts.items() if cat.lower() in classified)

    percentages = {}
    for cat in TRAFFIC_CATEGORIES:
        count = category_counts.get(cat, 0)
        if categorized_total > 0:
            percentages[cat] = round((count / categorized_total) * 100, 1)
        else:
            percentages[cat] = 0.0
    return percentages


def _parse_dnsmasq_config() -> dict:
    config_path = Path("/home/vigilant_admin/vigilant/src/config/dnsmasq.conf")
    if not config_path.exists():
        config_path = Path("/etc/dnsmasq.conf")
    
    settings = {
        "interface": "eth1",
        "listen_address": "192.168.100.88",
        "dhcp_start": "192.168.100.10",
        "dhcp_end": "192.168.100.50",
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
    config_path = Path("/home/vigilant_admin/vigilant/src/config/netplan-config.yaml")
    if not config_path.exists():
        config_path = Path("/etc/netplan/00-installer-config.yaml")
    
    settings = {
        "upstream_interface": "eth0",
        "distribution_interface": "eth1",
        "lan_address": "192.168.100.88/24"
    }
    
    if yaml is None or not config_path.exists():
        return settings

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
    dnsmasq_settings = _parse_dnsmasq_config()
    netplan_settings = _parse_netplan_config()
    return {
        "upstream_interface": netplan_settings.get("upstream_interface", "eth0"),
        "distribution_interface": dnsmasq_settings.get("interface", netplan_settings.get("distribution_interface", "eth1")),
        "gateway_ip": dnsmasq_settings.get("listen_address", "192.168.10.1"),
        "dhcp_start": dnsmasq_settings.get("dhcp_start", "192.168.10.10"),
        "dhcp_end": dnsmasq_settings.get("dhcp_end", "192.168.10.50"),
        "upstream_dns": "\n".join(dnsmasq_settings.get("dns_servers", ["8.8.8.8", "8.8.4.4"]))
    }


def _write_dnsmasq_config(config: dict) -> bool:
    config_path = Path("/home/vigilant_admin/vigilant/src/config/dnsmasq.conf")
    fallback_path = Path("/etc/dnsmasq.conf")
    
    # Try primary path first, check if directory exists and is writable
    if config_path.parent.exists() and os.access(config_path.parent, os.W_OK):
        target_path = config_path
    elif fallback_path.parent.exists() and os.access(fallback_path.parent, os.W_OK):
        target_path = fallback_path
    else:
        # Try to create the primary directory if it doesn't exist
        try:
            _ensure_directory(config_path)
            if os.access(config_path.parent, os.W_OK):
                target_path = config_path
            else:
                target_path = fallback_path
        except (PermissionError, OSError) as exc:
            app.logger.warning("Cannot create config directory, using fallback: %s", exc)
            target_path = fallback_path
    
    try:
        new_config = []
        dns_servers = config.get("upstream_dns", "8.8.8.8\n8.8.4.4").split("\n")
        
        new_config.append("# VIGILANT Gateway dnsmasq configuration\n")
        new_config.append(f"interface={config.get('distribution_interface', 'eth1')}\n")
        new_config.append(f"dhcp-range={config.get('dhcp_start', '192.168.100.10')},{config.get('dhcp_end', '192.168.100.50')},12h\n")
        new_config.append(f"dhcp-option=3,{config.get('gateway_ip', '192.168.100.88')}\n")
        new_config.append(f"dhcp-option=6,{config.get('gateway_ip', '192.168.100.88')}\n")
        new_config.append(f"listen-address={config.get('gateway_ip', '192.168.100.88')}\n")
        for dns in dns_servers:
            new_config.append(f"server={dns.strip()}\n")
        new_config.append("cache-size=1000\n")
        
        _ensure_directory(target_path)
        with open(target_path, 'w') as f:
            f.writelines(new_config)
        app.logger.info("Successfully wrote dnsmasq config to %s", target_path)
        return True
    except PermissionError as exc:
        app.logger.error("Permission denied writing dnsmasq.conf to %s: %s", target_path, exc)
        return False
    except (OSError, IOError) as exc:
        app.logger.error("IO error writing dnsmasq.conf to %s: %s", target_path, exc)
        return False
    except Exception as exc:
        app.logger.warning("Failed to write dnsmasq.conf: %s", exc)
        return False


def _write_netplan_config(config: dict) -> bool:
    config_path = Path("/home/vigilant_admin/vigilant/src/config/netplan-config.yaml")
    fallback_path = Path("/etc/netplan/00-installer-config.yaml")
    if yaml is None:
        app.logger.warning("PyYAML not available, cannot write netplan config")
        return False
    
    # Try primary path first, check if directory exists and is writable
    if config_path.parent.exists() and os.access(config_path.parent, os.W_OK):
        target_path = config_path
    elif fallback_path.parent.exists() and os.access(fallback_path.parent, os.W_OK):
        target_path = fallback_path
    else:
        # Try to create the primary directory if it doesn't exist
        try:
            _ensure_directory(config_path)
            if os.access(config_path.parent, os.W_OK):
                target_path = config_path
            else:
                target_path = fallback_path
        except (PermissionError, OSError) as exc:
            app.logger.warning("Cannot create config directory, using fallback: %s", exc)
            target_path = fallback_path
    
    try:
        netplan_config = {
            "network": {
                "version": 2,
                "ethernets": {
                    config.get("upstream_interface", "eth0"): {"dhcp4": True, "dhcp4-overrides": {"use-dns": False}},
                    config.get("distribution_interface", "eth1"): {"addresses": [f"{config.get('gateway_ip', '192.168.100.88')}/24"], "dhcp4": False}
                }
            }
        }
        _ensure_directory(target_path)
        with open(target_path, 'w') as f:
            yaml.dump(netplan_config, f, default_flow_style=False)
        app.logger.info("Successfully wrote netplan config to %s", target_path)
        return True
    except PermissionError as exc:
        app.logger.error("Permission denied writing netplan-config.yaml to %s: %s", target_path, exc)
        return False
    except (OSError, IOError) as exc:
        app.logger.error("IO error writing netplan-config.yaml to %s: %s", target_path, exc)
        return False
    except Exception as exc:
        app.logger.warning("Failed to write netplan-config.yaml: %s", exc)
        return False


def get_system_interfaces() -> list:
    try:
        interfaces = socket.if_nameindex()
        iface_names = [name for index, name in interfaces]
        filtered = [iface for iface in iface_names if not iface.startswith(('lo', 'veth', 'docker'))]
        if filtered:
            return sorted(filtered)
    except Exception as exc:
        app.logger.warning("Failed to get network interfaces: %s", exc)
        return ['eth0', 'eth1', 'enp0s3', 'enp1s0']
    return []


def _get_network_interfaces() -> list:
    if psutil is not None:
        try:
            interfaces = list(psutil.net_if_addrs().keys())
            filtered = [iface for iface in interfaces if not iface.startswith(('lo', 'veth', 'docker'))]
            if filtered:
                return sorted(filtered)
        except Exception as exc:
            app.logger.warning("Failed to get network interfaces via psutil: %s", exc)
    return []


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
                    "INSERT OR IGNORE INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, str(value), now_ts),
                )
            connection.commit()
    except sqlite3.Error as exc:
        app.logger.debug("init_config_db missing permissions or locked: %s", exc)
    init_category_hints_db()


def init_category_hints_db() -> None:
    try:
        with _open_db() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS category_hints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    domain TEXT NOT NULL UNIQUE,
                    action TEXT DEFAULT 'throttle'
                )
                """
            )
            count = connection.execute("SELECT COUNT(*) FROM category_hints").fetchone()[0]
            if count > 0:
                return

            default_hints = [
                ("Educational", "wikipedia.org"), ("Educational", "khanacademy.org"),
                ("Educational", "coursera.org"), ("Educational", "edx.org"),
                ("Educational", "scholar.google.com"), ("Educational", "researchgate.net"),
                ("Educational", "academia.edu"), ("Educational", "jstor.org"),
                ("Educational", "pubmed.ncbi.nlm.nih.gov"), ("Educational", "stackoverflow.com"),
                ("Educational", "docs.python.org"), ("Educational", "arxiv.org"),
                ("Productive", "github.com"), ("Productive", "gitlab.com"),
                ("Productive", "notion.so"), ("Productive", "trello.com"),
                ("Productive", "slack.com"), ("Productive", "linear.app"),
                ("Productive", "jira.atlassian.com"), ("Productive", "drive.google.com"),
                ("Productive", "docs.google.com"), ("Productive", "sheets.google.com"),
                ("Distracting", "reddit.com"), ("Distracting", "twitter.com"),
                ("Distracting", "x.com"), ("Distracting", "tiktok.com"),
                ("Distracting", "instagram.com"), ("Distracting", "facebook.com"),
                ("Distracting", "youtube.com"), ("Distracting", "twitch.tv"),
                ("Distracting", "9gag.com"), ("Distracting", "buzzfeed.com"),
            ]
            for category, domain in default_hints:
                connection.execute("INSERT OR IGNORE INTO category_hints (category, domain, action) VALUES (?, ?, 'throttle')", (category, domain))
            connection.commit()
    except sqlite3.Error as exc:
        app.logger.debug("init_category_hints_db issue: %s", exc)


def load_config() -> dict:
    config = dict(CONFIG_DEFAULTS)
    if not DB_PATH.exists():
        return config
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "config_settings"):
                return config
            rows = connection.execute("SELECT key, value FROM config_settings").fetchall()

        for row in rows:
            key = str(row[0])
            if key not in ALLOWED_CONFIG_KEYS:
                continue
            try:
                config[key] = _coerce_config_value(key, row[1])
            except (TypeError, ValueError):
                config[key] = CONFIG_DEFAULTS.get(key, row[1])
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
        now_ts = time.time()
        for key, value in filtered_updates.items():
            connection.execute(
                """
                INSERT INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, str(value), now_ts),
            )
        connection.commit()


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


# ==========================================
#       OPTIMIZED BULK STATS ENDPOINT
# ==========================================

@app.route('/api/stats')
def get_stats():
    """Optimized metrics controller utilizing a single database workflow block."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 100, type=int)
        category_filter = request.args.get('category', '').strip()
        search_filter = request.args.get('search', '').strip()
        
        page = max(1, page)
        per_page = max(1, min(per_page, 100))
        offset = (page - 1) * per_page
        
        total_reqs = 0
        blocked_reqs = 0
        active_clients = 0
        formatted_counts = [{"category": c, "count": 0} for c in TRAFFIC_CATEGORIES]
        category_percentages = {c: 0.0 for c in TRAFFIC_CATEGORIES}
        formatted_recent = []
        
        if DB_PATH.exists():
            with _open_db() as connection:
                if _table_exists(connection, "traffic_log"):
                    where_clauses = ["1=1"]
                    params = []

                    if category_filter and category_filter.upper() != 'ALL':
                        where_clauses.append("category = ?")
                        params.append(category_filter)

                    if search_filter:
                        where_clauses.append("(host LIKE ? OR client_ip LIKE ?)")
                        params.extend([f"%{search_filter}%", f"%{search_filter}%"])

                    where_sql = " AND ".join(where_clauses)

                    # Query Total Request Count
                    count_query = f"SELECT COUNT(*) FROM traffic_log WHERE {where_sql}"
                    total_reqs = connection.execute(count_query, tuple(params)).fetchone()[0] or 0

                    # Blocked Request Count
                    blocked_reqs = connection.execute("SELECT COUNT(*) FROM traffic_log WHERE flagged = 1").fetchone()[0] or 0
                    
                    # Active clients (last 24 hours)
                    window_start = int(time.time()) - 86400
                    active_clients = connection.execute("SELECT COUNT(DISTINCT client_ip) FROM traffic_log WHERE timestamp > ?", (window_start,)).fetchone()[0] or 0
                    
                    # Category breakdown
                    category_rows = connection.execute(
                        """
                        SELECT LOWER(TRIM(category)) AS normalized_category, COUNT(*) AS category_count
                        FROM traffic_log
                        WHERE category IS NOT NULL AND LOWER(TRIM(category)) IN ('educational', 'productive', 'distracting', 'harmful')
                        GROUP BY LOWER(TRIM(category))
                        """
                    ).fetchall()
                    
                    raw_categories = {row[0]: row[1] for row in category_rows}
                    formatted_counts = [{"category": cat, "count": raw_categories.get(cat.lower(), 0)} for cat in TRAFFIC_CATEGORIES]
                    
                    denom = sum(raw_categories.values())
                    if denom > 0:
                        category_percentages = {cat: round((raw_categories.get(cat.lower(), 0) / denom) * 100, 1) for cat in TRAFFIC_CATEGORIES}

                    # Paginated Traffic Logs
                    log_query = f"SELECT timestamp, client_ip, host, category, flagged FROM traffic_log WHERE {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                    log_params = params + [per_page, offset]
                    
                    rows = connection.execute(log_query, tuple(log_params)).fetchall()
                    formatted_recent = [_format_recent_log_entry(dict(r)) for r in rows]

        # Calculate Total Pages Safely
        total_pages = max(1, (total_reqs + per_page - 1) // per_page) if total_reqs > 0 else 1
        
        system_metrics = _system_metrics()
        network_config = _get_network_config()
        network_config["available_interfaces"] = _get_network_interfaces()

        return jsonify({
            "total": total_reqs,
            "flagged": blocked_reqs,
            "clients": active_clients,
            "counts": formatted_counts,
            "percentage_metrics": category_percentages,
            "recent": formatted_recent,
            "uptime": _format_uptime(),
            "statuses": _service_statuses(),
            "pagination": {"page": page, "per_page": per_page, "total_pages": total_pages, "total_items": total_reqs},
            "system_metrics": system_metrics,
            "network_config": network_config
        })
    except Exception as exc:
        app.logger.error("Failed to compile /api/stats: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/")
@app.route('/index.html')
def dashboard():
    proxy_active = _service_statuses().get("vigilant_proxy") == "active"
    return render_template("dashboard.html", proxy_active=proxy_active)


@app.route("/api/dashboard/summary")
def dashboard_summary():
    global _last_system_net_io, _last_system_net_time
    
    cpu_usage = 0.0
    ram_usage_gb = 0.0
    ram_total_gb = 8.0
    disk_usage = 0.0
    rx_mbps = 0.0
    tx_mbps = 0.0

    if psutil:
        try:
            cpu_usage = float(psutil.cpu_percent(interval=None))
            mem = psutil.virtual_memory()
            ram_usage_gb = round(mem.used / (1024**3), 1)
            ram_total_gb = round(mem.total / (1024**3), 1)
            disk_usage = float(psutil.disk_usage('/').percent)

            current_time = time.time()
            current_io = psutil.net_io_counters()
            if _last_system_net_io and _last_system_net_time:
                time_diff = max(0.001, current_time - _last_system_net_time)
                rx_bytes = max(0, current_io.bytes_recv - _last_system_net_io.bytes_recv)
                tx_bytes = max(0, current_io.bytes_sent - _last_system_net_io.bytes_sent)
                rx_mbps = round((rx_bytes * 8) / (1024 * 1024 * time_diff), 1)
                tx_mbps = round((tx_bytes * 8) / (1024 * 1024 * time_diff), 1)

            _last_system_net_io = current_io
            _last_system_net_time = current_time
        except Exception as e:
            app.logger.debug("Error fetching psutil metrics: %s", e)
            
    services_state = _service_statuses()
    services = {
        "mitmproxy": services_state.get("vigilant_proxy", "offline"),
        "dnsmasq": "active"
    }

    total_connected = 0
    throttled_count = 0
    recent_alerts = 0
    recent_entries = []
    dhcp_allocations = []
    
    if DB_PATH.exists():
        try:
            with _open_db() as conn:
                window_start = int(time.time()) - 86400
                if _table_exists(conn, "traffic_log"):
                    row = conn.execute("SELECT COUNT(DISTINCT client_ip) FROM traffic_log WHERE timestamp > ?", (window_start,)).fetchone()
                    total_connected = int(row[0] or 0) if row else 0
                    
                    row = conn.execute("SELECT COUNT(*) FROM traffic_log WHERE flagged = 1 AND timestamp > ?", (window_start,)).fetchone()
                    recent_alerts = int(row[0] or 0) if row else 0
                    
                    rows = conn.execute("SELECT timestamp, client_ip, host, category, flagged FROM traffic_log ORDER BY timestamp DESC LIMIT 10").fetchall()
                    recent_entries = [_format_recent_log_entry(dict(r)) for r in rows]
                
                if _table_exists(conn, "network_devices"):
                    row = conn.execute("SELECT COUNT(*) FROM network_devices WHERE policy = 'blacklist'").fetchone()
                    throttled_count = int(row[0] or 0) if row else 0
                    
                    device_rows = conn.execute("SELECT ip_address, mac_address, hostname, custom_name, last_seen FROM network_devices ORDER BY last_seen DESC").fetchall()
                    for row in device_rows:
                        dhcp_allocations.append({
                            "ip_address": row[0], "mac_address": row[1],
                            "hostname": row[2] or "Unknown", "custom_name": row[3], "last_seen": row[4]
                        })
        except sqlite3.Error as e:
            app.logger.warning(f"DB Error in summary: {e}")

    config = load_config()
    nlp_enabled = _coerce_bool(config.get("nlp_enabled", "true"))
    theme_mode = config.get("ui_theme", "dark")
    
    try:
        net_vel = float(config.get("network_velocity_threshold", "1.5"))
    except ValueError:
        net_vel = 1.5
    net_preset = "Low" if net_vel >= 2.0 else ("Medium" if net_vel >= 1.5 else "High")
    
    try:
        scroll_vel = int(config.get("physical_scroll_threshold", "75"))
    except ValueError:
        scroll_vel = 75
    scroll_preset = "Low" if scroll_vel >= 120 else ("Medium" if scroll_vel >= 75 else "High")

    network_config = _get_network_config()

    return jsonify({
        "system": {"cpu_usage": cpu_usage, "ram_usage_gb": ram_usage_gb, "ram_total_gb": ram_total_gb, "disk_usage": disk_usage, "services": services, "throughput_rx_mbps": max(0.0, rx_mbps), "throughput_tx_mbps": max(0.0, tx_mbps)},
        "devices": {"total_connected": total_connected, "throttled_count": throttled_count},
        "logs": {"recent_alerts": recent_alerts, "recent_entries": recent_entries},
        "active_config": {"nlp_enabled": nlp_enabled, "network_velocity_preset": net_preset, "physical_scroll_preset": scroll_preset, "theme_mode": theme_mode},
        "network_config": network_config,
        "dhcp_allocations": dhcp_allocations
    })


@app.route('/api/reset', methods=["POST"])
def api_reset_redirect():
    return api_config_reset()


@app.route("/api/config/reset", methods=["POST"])
def api_config_reset():
    try:
        with _open_db() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS config_settings (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
            connection.execute("BEGIN TRANSACTION")
            try:
                if _table_exists(connection, "config_settings"):
                    connection.execute("DELETE FROM config_settings")
                now_ts = time.time()
                for key, value in CONFIG_DEFAULTS.items():
                    connection.execute("INSERT INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)", (key, str(value), now_ts))
                connection.commit()
            except Exception as tx_exc:
                connection.rollback()
                return jsonify({"error": str(tx_exc)}), 500
        
        _write_dnsmasq_config(CONFIG_DEFAULTS)
        _write_netplan_config(CONFIG_DEFAULTS)
        return jsonify({"status": "success", "message": "Configuration restored to defaults"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    try:
        if not DB_PATH.exists():
            return jsonify({"status": "success", "message": "No database found"})
        with _open_db() as connection:
            if _table_exists(connection, "traffic_log"):
                connection.execute("DELETE FROM traffic_log")
                connection.commit()
                try:
                    connection.execute("VACUUM")
                except sqlite3.Error:
                    pass
        return jsonify({"status": "success", "message": "Traffic logs cleared successfully"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route('/api/logs/export')
def export_logs():
    try:
        logs = query_db("SELECT timestamp, client_ip, host, category, flagged FROM traffic_log WHERE category NOT IN ('DNS_TRACKED', 'NON-HTML') ORDER BY timestamp DESC")
        if not isinstance(logs, list):
            logs = []
            
        text_stream = io.StringIO()
        cw = csv.writer(text_stream)
        cw.writerow(['Time', 'Client IP', 'Domain', 'Category', 'Status'])
        
        for log in logs:
            ts = log.get('timestamp')
            try:
                if isinstance(ts, (int, float)):
                    formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
                else:
                    formatted_time = str(ts or "N/A")
            except Exception:
                formatted_time = "N/A"
                
            cw.writerow([
                formatted_time, 
                log.get('client_ip', '0.0.0.0'), 
                log.get('host', 'unknown'), 
                log.get('category', 'Unclassified'), 
                'Blocked' if log.get('flagged') else 'Allowed'
            ])
        
        byte_stream = io.BytesIO(text_stream.getvalue().encode('utf-8'))
        text_stream.close()
        return send_file(byte_stream, as_attachment=True, download_name='traffic_logs.csv', mimetype='text/csv')
    except Exception as e:
        app.logger.error("Failed to export logs: %s", e, exc_info=True)
        return abort(500, description="Failed to export logs")


@app.route('/api/config/setup/export')
def export_config():
    try:
        kw_rows = query_db("SELECT keyword FROM keyword_blacklist")
        keywords = [row['keyword'] for row in kw_rows] if isinstance(kw_rows, list) else []

        wl_rows = query_db("SELECT mac_address FROM network_devices WHERE policy = 'whitelist'")
        whitelist = [row['mac_address'] for row in wl_rows] if isinstance(wl_rows, list) else []

        st_rows = query_db("SELECT key, value FROM config_settings")
        settings_dict = {row['key']: row['value'] for row in st_rows} if isinstance(st_rows, list) else {}

        config_data = {
            "backup_version": "1.0",
            "blocked_keywords": keywords,
            "mac_whitelist": whitelist,
            "settings": settings_dict
        }
        
        response = make_response(json.dumps(config_data, indent=4))
        response.headers["Content-Disposition"] = "attachment; filename=vigilant_config.json"
        response.headers["Content-Type"] = "application/json"
        return response
    except Exception as exc:
        app.logger.error("Failed to export config: %s", exc, exc_info=True)
        return jsonify({"error": "Failed to export configuration"}), 500


@app.route('/api/config/setup/import', methods=['POST'])
def import_config():
    if 'config_file' not in request.files:
        return redirect(url_for('dashboard'))
    file = request.files['config_file']
    if file.filename == '':
        return redirect(url_for('dashboard'))
    try:
        config_data = json.loads(file.read().decode('utf-8'))
        with _open_db() as connection:
            # Ensure tables exist before operations
            connection.execute("CREATE TABLE IF NOT EXISTS keyword_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, keyword TEXT NOT NULL UNIQUE)")
            connection.execute("CREATE TABLE IF NOT EXISTS config_settings (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
            
            connection.execute("DELETE FROM keyword_blacklist")
            for kw in config_data.get("blocked_keywords", []):
                connection.execute("INSERT OR IGNORE INTO keyword_blacklist (keyword) VALUES (?)", (kw,))
            if "settings" in config_data:
                connection.execute("DELETE FROM config_settings")
                now_ts = time.time()
                for k, v in config_data["settings"].items():
                    connection.execute("INSERT INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)", (k, str(v), now_ts))
            connection.commit()
        flash("Import successful", "success")
    except json.JSONDecodeError as e:
        app.logger.error(f"Failed to parse config file: {e}")
        flash("Invalid config file format", "error")
    except sqlite3.Error as e:
        app.logger.error(f"Database error during import: {e}")
        flash("Database error during import", "error")
    except Exception as e:
        flash(f"Import failed: {str(e)}", "error")
    return redirect(url_for('dashboard'))


@app.route("/api/config/ui-theme", methods=["POST"])
def save_ui_theme():
    payload = request.get_json(silent=True) or {}
    theme = str(payload.get("theme", "")).strip().lower()
    if theme not in ["light", "dark"]:
        return jsonify({"error": "Invalid theme"}), 400
    save_config({"ui_theme": theme})
    return jsonify({"status": "success"})


@app.route("/api/config", methods=["GET"])
def api_config():
    config = load_config()
    network_config = _get_network_config()
    network_config["available_interfaces"] = get_system_interfaces()
    config.update(network_config)
    return jsonify(config)


@app.route("/api/config/setup", methods=["GET", "POST"])
def api_config_setup():
    if request.method == "GET":
        config = load_config()
        config.update(_get_network_config())
        config["available_interfaces"] = get_system_interfaces()
        return jsonify(config)

    payload = request.get_json(silent=True) or {}
    save_config(payload)
    return jsonify({"status": "success", "message": "Configuration saved successfully"})


@app.route("/api/keywords", methods=["GET", "POST"])
def handle_keywords():
    if request.method == "GET":
        rows = query_db("SELECT id, keyword FROM keyword_blacklist ORDER BY keyword") or []
        return jsonify([{"id": r[0], "keyword": r[1]} for r in rows])
        
    payload = request.get_json(silent=True) or {}
    kw = payload.get("keyword", "").strip().lower()
    if not kw:
        return jsonify({"error": "Keyword required"}), 400
    try:
        with _open_db() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS keyword_blacklist (id INTEGER PRIMARY KEY AUTOINCREMENT, keyword TEXT NOT NULL UNIQUE)")
            cursor = conn.execute("INSERT INTO keyword_blacklist (keyword) VALUES (?)", (kw,))
            conn.commit()
            return jsonify({"id": cursor.lastrowid, "keyword": kw}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Duplicate entry"}), 409


@app.route("/api/keywords/<int:keyword_id>", methods=["DELETE"])
def delete_keyword(keyword_id):
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "keyword_blacklist"):
                return jsonify({"error": "Not found"}), 404
            cursor = connection.execute("DELETE FROM keyword_blacklist WHERE id = ?", (keyword_id,))
            connection.commit()
            return jsonify({"status": "success"}) if cursor.rowcount > 0 else (jsonify({"error": "Not found"}), 404)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── CATEGORY HINTS API ENDPOINTS ───────────────────────────────────

@app.route("/api/categories/hints", methods=["GET", "POST"])
def manage_category_hints():
    if request.method == "GET":
        try:
            with _open_db() as conn:
                if not _table_exists(conn, "category_hints"):
                    return jsonify([])
                    
                # Try with action column first, fallback without it
                try:
                    cursor = conn.execute("SELECT id, category, domain, action FROM category_hints")
                    hints = [{"id": row[0], "category": row[1], "domain": row[2], "action": row[3]} for row in cursor.fetchall()]
                except sqlite3.OperationalError:
                    # Fallback for old schema without action column
                    cursor = conn.execute("SELECT id, category, domain FROM category_hints")
                    hints = [{"id": row[0], "category": row[1], "domain": row[2], "action": "throttle"} for row in cursor.fetchall()]
                return jsonify(hints)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    elif request.method == "POST":
        try:
            data = request.get_json(silent=True) or {}
            category = data.get("category")
            domain = data.get("domain")
            action = data.get("action", "throttle")
            
            if not category or not domain:
                return jsonify({"error": "Category and domain are required"}), 400

            with _open_db() as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS category_hints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        category TEXT,
                        domain TEXT,
                        action TEXT DEFAULT 'throttle'
                    )
                """)
                # Try inserting with action column, fallback without it
                try:
                    cursor = conn.execute("INSERT INTO category_hints (category, domain, action) VALUES (?, ?, ?)", (category, domain, action))
                except sqlite3.OperationalError:
                    # Fallback for old schema without action column
                    cursor = conn.execute("INSERT INTO category_hints (category, domain) VALUES (?, ?)", (category, domain))
                conn.commit()
                new_id = cursor.lastrowid
                return jsonify({"id": new_id, "category": category, "domain": domain, "action": action}), 201
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/categories/hints/<int:hint_id>", methods=["DELETE"])
def delete_category_hint(hint_id):
    try:
        with _open_db() as conn:
            if not _table_exists(conn, "category_hints"):
                return jsonify({"error": "Not found"}), 404
            cursor = conn.execute("DELETE FROM category_hints WHERE id = ?", (hint_id,))
            conn.commit()
            if cursor.rowcount > 0:
                return jsonify({"success": True}), 200
            return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/behavioral", methods=["GET", "POST"])
def handle_behavioral_config():
    if request.method == "GET":
        config = load_config()
        return jsonify({
            "network_velocity_preset": config.get("network_velocity_preset", "Medium"),
            "network_velocity_custom": int(config.get("network_velocity_custom", 150)),
            "physical_scroll_preset": config.get("physical_scroll_preset", "Medium"),
            "physical_scroll_custom": int(config.get("physical_scroll_custom", 75))
        })
    payload = request.get_json(silent=True) or {}
    
    # When preset changes, update the corresponding threshold value
    if "network_velocity_preset" in payload:
        preset = payload["network_velocity_preset"]
        if preset == "High":
            payload["network_velocity_threshold"] = "2.0"
        elif preset == "Medium":
            payload["network_velocity_threshold"] = "1.5"
        else:  # Low
            payload["network_velocity_threshold"] = "1.0"
    
    if "physical_scroll_preset" in payload:
        preset = payload["physical_scroll_preset"]
        if preset == "High":
            payload["physical_scroll_threshold"] = "120"
        elif preset == "Medium":
            payload["physical_scroll_threshold"] = "75"
        else:  # Low
            payload["physical_scroll_threshold"] = "50"
    
    # When custom value changes, update the threshold
    if "network_velocity_custom" in payload:
        payload["network_velocity_threshold"] = str(payload["network_velocity_custom"])
    
    if "physical_scroll_custom" in payload:
        payload["physical_scroll_threshold"] = str(payload["physical_scroll_custom"])
    
    save_config(payload)
    return jsonify({"status": "success"})


@app.route("/api/devices", methods=["GET"])
def get_devices():
    return jsonify({"devices": _discover_network_devices()})


@app.route("/api/devices/policy", methods=["POST"])
def set_device_policy():
    """Set device filtering policy (whitelist/blacklist/none)"""
    try:
        payload = request.get_json(silent=True) or {}
        mac_address = payload.get("mac_address")
        ip_address = payload.get("ip_address")
        policy = payload.get("policy", "none")
        custom_name = payload.get("custom_name")
        
        if not mac_address and not ip_address:
            return jsonify({"error": "Either mac_address or ip_address required"}), 400
        
        if policy not in ("whitelist", "blacklist", "none"):
            return jsonify({"error": "Invalid policy. Must be whitelist, blacklist, or none"}), 400
        
        with _open_db() as connection:
            # Ensure network_devices table exists
            connection.execute("CREATE TABLE IF NOT EXISTS network_devices (ip_address TEXT PRIMARY KEY, mac_address TEXT, hostname TEXT, custom_name TEXT, policy TEXT DEFAULT 'none', first_seen REAL, last_seen REAL, updated_at REAL)")
            
            if mac_address:
                # Update by MAC address
                cursor = connection.execute(
                    "UPDATE network_devices SET policy = ?, custom_name = COALESCE(?, custom_name), updated_at = ? WHERE mac_address = ?",
                    (policy, custom_name, time.time(), mac_address)
                )
                if cursor.rowcount == 0:
                    # Device doesn't exist, insert it
                    connection.execute(
                        "INSERT INTO network_devices (ip_address, mac_address, policy, custom_name, first_seen, last_seen, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (ip_address or "", mac_address, policy, custom_name, time.time(), time.time(), time.time())
                    )
            else:
                # Update by IP address
                cursor = connection.execute(
                    "UPDATE network_devices SET policy = ?, custom_name = COALESCE(?, custom_name), updated_at = ? WHERE ip_address = ?",
                    (policy, custom_name, time.time(), ip_address)
                )
                if cursor.rowcount == 0:
                    # Device doesn't exist, insert it
                    connection.execute(
                        "INSERT INTO network_devices (ip_address, mac_address, policy, custom_name, first_seen, last_seen, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (ip_address, mac_address or "", policy, custom_name, time.time(), time.time(), time.time())
                    )
            
            connection.commit()
        
        return jsonify({"status": "success", "policy": policy})
    except Exception as exc:
        app.logger.error(f"Error setting device policy: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/system/control", methods=["POST"])
def system_control():
    """Execute system control commands (restart services, reload configs)"""
    try:
        payload = request.get_json(silent=True) or {}
        action = payload.get("action")
        
        if not action:
            return jsonify({"error": "Action required"}), 400
        
        valid_actions = ["restart_proxy", "reload_config", "reload_firewall", "restart_dnsmasq"]
        if action not in valid_actions:
            return jsonify({"error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"}), 400
        
        result = {"status": "success", "message": ""}
        
        if action == "restart_proxy":
            # Restart mitmproxy service
            try:
                subprocess.run(["sudo", "systemctl", "restart", "vigilant-proxy"], check=True, capture_output=True, timeout=10)
                result["message"] = "Proxy service restarted successfully"
            except subprocess.TimeoutExpired:
                result["status"] = "warning"
                result["message"] = "Proxy restart timed out but may be completing"
            except subprocess.CalledProcessError as e:
                result["status"] = "error"
                result["message"] = f"Failed to restart proxy: {e.stderr.decode() if e.stderr else str(e)}"
            except FileNotFoundError:
                # Fallback for non-systemctl systems
                try:
                    subprocess.run(["sudo", "pkill", "-f", "mitmdump"], check=True, timeout=5)
                    result["message"] = "Proxy process terminated (manual restart required)"
                except Exception as e2:
                    result["status"] = "error"
                    result["message"] = f"Failed to control proxy: {str(e2)}"
        
        elif action == "restart_dnsmasq":
            # Reload dnsmasq configuration
            try:
                subprocess.run(["sudo", "systemctl", "reload", "dnsmasq"], check=True, capture_output=True, timeout=10)
                result["message"] = "DNS service reloaded successfully"
            except subprocess.TimeoutExpired:
                result["status"] = "warning"
                result["message"] = "DNS reload timed out but may be completing"
            except subprocess.CalledProcessError as e:
                result["status"] = "error"
                result["message"] = f"Failed to reload DNS: {e.stderr.decode() if e.stderr else str(e)}"
            except FileNotFoundError:
                try:
                    subprocess.run(["sudo", "pkill", "-HUP", "dnsmasq"], check=True, timeout=5)
                    result["message"] = "DNS service signaled to reload"
                except Exception as e2:
                    result["status"] = "error"
                    result["message"] = f"Failed to reload DNS: {str(e2)}"
        
        elif action == "reload_config":
            # Reload dashboard configuration (no-op for now, just acknowledge)
            result["message"] = "Configuration reloaded successfully"
        
        elif action == "reload_firewall":
            # Reload firewall rules
            try:
                subprocess.run(["sudo", "iptables-restore", "/etc/iptables/rules.v4"], check=True, capture_output=True, timeout=10)
                result["message"] = "Firewall rules reloaded successfully"
            except subprocess.TimeoutExpired:
                result["status"] = "warning"
                result["message"] = "Firewall reload timed out but may be completing"
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                result["status"] = "error"
                result["message"] = f"Failed to reload firewall: {str(e)}"
        
        return jsonify(result)
    except Exception as exc:
        app.logger.error(f"System control error: {exc}")
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/api/interface/throughput", methods=["GET"])
def get_interface_throughput():
    """Get real-time throughput statistics for the gateway interface"""
    try:
        throughput = _get_interface_throughput(GATEWAY_INTERFACE)
        return jsonify({
            "interface": GATEWAY_INTERFACE,
            "rx_mbps": throughput['rx_mbps'],
            "tx_mbps": throughput['tx_mbps'],
            "timestamp": time.time()
        })
    except Exception as exc:
        app.logger.error("Failed to get interface throughput: %s", exc)
        return jsonify({
            "interface": GATEWAY_INTERFACE,
            "rx_mbps": 0.0,
            "tx_mbps": 0.0,
            "timestamp": time.time(),
            "error": str(exc)
        }), 500


def _read_proc_net_dev() -> dict:
    """Read network interface statistics from /proc/net/dev"""
    stats = {}
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()[2:]  # Skip header lines
            for line in lines:
                parts = line.split()
                if len(parts) >= 17:
                    interface = parts[0].rstrip(':')
                    stats[interface] = {
                        'rx_bytes': int(parts[1]),
                        'rx_packets': int(parts[2]),
                        'tx_bytes': int(parts[9]),
                        'tx_packets': int(parts[10])
                    }
    except Exception as exc:
        app.logger.warning("Failed to read /proc/net/dev: %s", exc)
    return stats


def _read_dnsmasq_leases() -> list:
    """Read DHCP leases from dnsmasq lease files"""
    leases = []
    lease_paths = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/home/vigilant_admin/vigilant/logs/dnsmasq.leases"
    ]
    
    for lease_path in lease_paths:
        path = Path(lease_path)
        if path.exists():
            try:
                with open(path, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            leases.append({
                                'timestamp': int(parts[0]),
                                'mac_address': parts[1],
                                'ip_address': parts[2],
                                'hostname': parts[3] if len(parts) > 3 else 'Unknown',
                                'client_id': parts[4] if len(parts) > 4 else None
                            })
                break
            except Exception as exc:
                app.logger.warning("Failed to read %s: %s", lease_path, exc)
    return leases


def _read_arp_table() -> dict:
    """Read ARP table to get MAC addresses for IPs"""
    arp = {}
    try:
        with open('/proc/net/arp', 'r') as f:
            lines = f.readlines()[1:]  # Skip header
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 6 and parts[3] != "00:00:00:00:00:00":
                    arp[parts[0]] = {
                        'mac_address': parts[3],
                        'device': parts[5]
                    }
    except Exception as exc:
        app.logger.warning("Failed to read /proc/net/arp: %s", exc)
    return arp


def _get_interface_throughput(interface: str) -> dict:
    """Get current throughput statistics for a specific interface"""
    global _last_interface_net_io, _last_interface_net_time
    
    stats = _read_proc_net_dev()
    if interface not in stats:
        return {'rx_mbps': 0.0, 'tx_mbps': 0.0}
    
    current_io = stats[interface]
    current_time = time.time()
    
    if _last_interface_net_io and _last_interface_net_time:
        time_diff = max(0.001, current_time - _last_interface_net_time)
        rx_bytes = max(0, current_io['rx_bytes'] - _last_interface_net_io.get('rx_bytes', 0))
        tx_bytes = max(0, current_io['tx_bytes'] - _last_interface_net_io.get('tx_bytes', 0))
        rx_mbps = round((rx_bytes * 8) / (1024 * 1024 * time_diff), 2)
        tx_mbps = round((tx_bytes * 8) / (1024 * 1024 * time_diff), 2)
    else:
        rx_mbps = 0.0
        tx_mbps = 0.0
    
    _last_interface_net_io = current_io
    _last_interface_net_time = current_time
    
    return {'rx_mbps': rx_mbps, 'tx_mbps': tx_mbps}


def _discover_network_devices() -> list:
    now = time.time()
    discovered_devices = {}
    
    dnsmasq_leases_list = _read_dnsmasq_leases()
    arp_table = _read_arp_table()
    
    for lease in dnsmasq_leases_list:
        ip = lease['ip_address']
        discovered_devices[ip] = {
            'ip_address': ip,
            'mac_address': lease['mac_address'],
            'hostname': lease['hostname'],
            'last_seen': now,
            'bytes': 0
        }
    
    for ip, arp_data in arp_table.items():
        if ip in discovered_devices:
            discovered_devices[ip]['mac_address'] = arp_data['mac_address']
            discovered_devices[ip]['device'] = arp_data['device']
        else:
            discovered_devices[ip] = {
                'ip_address': ip,
                'mac_address': arp_data['mac_address'],
                'hostname': 'Unknown',
                'last_seen': now,
                'bytes': 0,
                'device': arp_data['device']
            }
        
    try:
        with _open_db() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS network_devices (ip_address TEXT PRIMARY KEY, mac_address TEXT, hostname TEXT, custom_name TEXT, policy TEXT DEFAULT 'none', first_seen REAL, last_seen REAL, updated_at REAL)")
            rows = connection.execute("SELECT ip_address, mac_address, hostname, custom_name, policy, first_seen, last_seen FROM network_devices").fetchall()
            
            for row in rows:
                ip = row[0]
                if ip in discovered_devices:
                    discovered_devices[ip].update({'custom_name': row[3], 'policy': row[4], 'first_seen': row[5]})
                else:
                    discovered_devices[ip] = {'ip_address': ip, 'mac_address': row[1], 'hostname': row[2], 'custom_name': row[3], 'policy': row[4], 'first_seen': row[5], 'last_seen': row[6], 'active': False}
                    
            for ip, info in discovered_devices.items():
                if info.get('active', True):
                    connection.execute(
                        "INSERT INTO network_devices (ip_address, mac_address, hostname, custom_name, policy, first_seen, last_seen, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ip_address) DO UPDATE SET last_seen = excluded.last_seen",
                        (ip, info.get('mac_address'), info.get('hostname'), info.get('custom_name'), info.get('policy', 'none'), info.get('first_seen', now), now, now)
                    )
            connection.commit()
    except sqlite3.Error as e:
        app.logger.warning(f"Device storage failed: {e}")
    return list(discovered_devices.values())


def _init_traffic_db() -> None:
    """Creates database structures along with highly critical target column indexes."""
    try:
        with _open_db() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS traffic_log (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, client_ip TEXT, host TEXT, path TEXT, method TEXT, category TEXT, flagged INTEGER DEFAULT 0, entities TEXT)")
            connection.execute("CREATE TABLE IF NOT EXISTS config_settings (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
            
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_category ON traffic_log(category)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_flagged ON traffic_log(flagged)")
            connection.commit()
    except sqlite3.Error as exc:
        app.logger.debug("Database initialization encountered index locking: %s", exc)


if __name__ == "__main__":
    _init_traffic_db()
    init_config_db()
    app.run(host='0.0.0.0', port=5000, debug=False)