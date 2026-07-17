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

try:
    import psutil
except ImportError:
    psutil = None
yaml = importlib.import_module("yaml") if importlib.util.find_spec("yaml") else None
from flask import Flask, jsonify, render_template, request, make_response, send_file, abort, redirect, flash, url_for
import json

try:
    from flask_cors import CORS
except ImportError:
    def CORS(app):
        return app

scroll_velocity_tracker = {}
_last_net_io = None
_last_net_time = 0




BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
app = Flask(
    __name__,
    static_folder=str(STATIC_DIR),
    template_folder=str(TEMPLATE_DIR),
)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.secret_key = "super_secret_vigilant_key"

SERVER_IP = "192.168.10.1"
# Environment-aware DB path: production path via env var, fallback to local development path
PRODUCTION_DB_PATH = Path("/home/vigilant_admin/vigilant/logs/vigilant.db")
LOCAL_DB_PATH = BASE_DIR / "logs" / "vigilant.db"

# Use production path if it exists and is writable, otherwise use local development path
if PRODUCTION_DB_PATH.exists() and os.access(PRODUCTION_DB_PATH.parent, os.W_OK):
    DB_PATH = PRODUCTION_DB_PATH
else:
    DB_PATH = LOCAL_DB_PATH

DEFAULT_CONFIG = {
    "upstream_interface": "enp0s31f6",
    "distribution_interface": "wlp1s0",
    "gateway_ip": "192.168.10.1",
    "dhcp_start": "192.168.10.10",
    "dhcp_end": "192.168.10.50",
    "upstream_dns": "8.8.8.8\n8.8.4.4",
    "nlp_enabled": "true",
    "nlp_accuracy": "balanced",
    "network_velocity_threshold": "1.5",
    "physical_scroll_threshold": "75",
    "throttle_enabled": "true",
    "throttle_rate": "256",
    "ui_theme": "light"
}

# Maintain backward compatibility
CONFIG_DEFAULTS = DEFAULT_CONFIG

ALLOWED_CONFIG_KEYS = set(CONFIG_DEFAULTS)
BOOLEAN_CONFIG_KEYS = set()
INTEGER_CONFIG_KEYS = set()
STRING_CONFIG_KEYS = {"upstream_interface", "distribution_interface", "gateway_ip", "dhcp_start", "dhcp_end", "upstream_dns", "nlp_accuracy", "network_velocity_threshold", "physical_scroll_threshold", "throttle_rate", "nlp_enabled", "throttle_enabled", "ui_theme"}
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


def _total_request_count(category_filter: str = '', search_filter: str = '') -> int:
    """Get total count of requests matching the same filters as _get_recent_logs"""
    if not DB_PATH.exists():
        return 0
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return 0
            
            query = "SELECT COUNT(*) FROM traffic_log WHERE 1=1"
            params = []
            
            if category_filter and category_filter != 'ALL':
                query += " AND category = ?"
                params.append(category_filter)
            
            if search_filter:
                query += " AND (host LIKE ? OR client_ip LIKE ?)"
                params.append(f"%{search_filter}%")
                params.append(f"%{search_filter}%")
            
            row = connection.execute(query, tuple(params)).fetchone()
            return int(row[0] or 0) if row else 0
    except sqlite3.Error as exc:
        app.logger.warning(f"Failed to get total request count: {exc}")
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


def _get_recent_logs(limit: int = 10, offset: int = 0, category_filter: str = '', search_filter: str = '') -> list:
    """Get recent traffic logs with proper pagination and filtering"""
    if not DB_PATH.exists():
        return []
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return []
            
            # Ensure limit and offset are valid integers
            try:
                limit = max(1, min(int(limit), 1000))  # Cap at 1000 to prevent excessive queries
                offset = max(0, int(offset))
            except (ValueError, TypeError):
                limit = 10
                offset = 0
            
            query = "SELECT timestamp, client_ip, host, category, flagged FROM traffic_log WHERE 1=1"
            params = []
            
            if category_filter and category_filter != 'ALL':
                query += " AND category = ?"
                params.append(category_filter)
            
            if search_filter:
                query += " AND (host LIKE ? OR client_ip LIKE ?)"
                params.append(f"%{search_filter}%")
                params.append(f"%{search_filter}%")
            
            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            rows = connection.execute(query, tuple(params)).fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as exc:
        app.logger.warning(f"Failed to get recent logs: {exc}")
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
    """Return actual counts per category (not percentages). Only classified categories are counted."""
    distribution = {category: 0 for category in TRAFFIC_CATEGORIES}

    if not DB_PATH.exists():
        return distribution

    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return distribution

            # Strictly count only our four classified categories.
            # Noise rows (Non-HTML, DNS_Tracked, Uncategorized, etc.) are excluded
            # by the LOWER(TRIM(...)) IN (...) guard to prevent them from inflating counts.
            category_rows = connection.execute(
                """
                SELECT LOWER(TRIM(category)) AS normalized_category, COUNT(*) AS category_count
                FROM traffic_log
                WHERE category IS NOT NULL
                  AND TRIM(category) != ''
                  AND LOWER(TRIM(category)) IN ('educational', 'productive', 'distracting', 'harmful')
                GROUP BY LOWER(TRIM(category))
                """
            ).fetchall()

            category_counts = {str(row[0] or ""): int(row[1] or 0) for row in category_rows}

            for category in TRAFFIC_CATEGORIES:
                count = category_counts.get(category.lower(), 0)
                distribution[category] = count

    except sqlite3.Error as exc:
        app.logger.warning("traffic count metrics unavailable: %s", exc)

    return distribution


def _calculate_category_percentages(category_counts: dict) -> dict:
    """Calculate percentages using ONLY the four classified categories as the denominator.
    Non-HTML, DNS_Tracked, Uncategorized and any other noise keys are excluded so the
    four real categories always sum to exactly 100%%.
    """
    # The canonical set of categories that should ever appear in the denominator.
    classified = {c.lower() for c in TRAFFIC_CATEGORIES}  # {'educational','productive','distracting','harmful'}

    # Denominator: sum of classified category counts only.
    categorized_total = sum(
        count for cat, count in category_counts.items()
        if cat.lower() in classified
    )

    percentages = {}
    for cat, count in category_counts.items():
        if cat.lower() not in classified:
            # Any residual noise key is zeroed out and hidden from the chart.
            percentages[cat] = 0
        elif categorized_total > 0:
            percentages[cat] = round((count / categorized_total) * 100, 1)
        else:
            percentages[cat] = 0

    return percentages


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
    config_path = Path("/home/vigilant_admin/vigilant/src/config/dnsmasq.conf")
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
    config_path = Path("/home/vigilant_admin/vigilant/src/config/netplan-config.yaml")
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
    """Get network configuration from config files"""
    dnsmasq_settings = _parse_dnsmasq_config()
    netplan_settings = _parse_netplan_config()
    
    # Merge settings, preferring netplan for interfaces
    return {
        "upstream_interface": netplan_settings.get("upstream_interface", "enp0s31f6"),
        "distribution_interface": dnsmasq_settings.get("interface", netplan_settings.get("distribution_interface", "wlp1s0")),
        "gateway_ip": dnsmasq_settings.get("listen_address", "192.168.10.1"),
        "dhcp_start": dnsmasq_settings.get("dhcp_start", "192.168.10.10"),
        "dhcp_end": dnsmasq_settings.get("dhcp_end", "192.168.10.50"),
        "upstream_dns": "\n".join(dnsmasq_settings.get("dns_servers", ["8.8.8.8", "8.8.4.4"]))
    }


def _write_dnsmasq_config(config: dict) -> bool:
    """Write dnsmasq configuration file"""
    config_path = Path("/home/vigilant_admin/vigilant/src/config/dnsmasq.conf")
    fallback_path = Path("/etc/dnsmasq.conf")
    
    # Use fallback path for local development
    if not config_path.parent.exists():
        config_path = fallback_path
    
    try:
        # Parse existing config to preserve comments and structure
        existing_lines = []
        if config_path.exists():
            with open(config_path, 'r') as f:
                existing_lines = f.readlines()
        
        # Build new config content
        new_config = []
        dns_servers = config.get("upstream_dns", "8.8.8.8\n8.8.4.4").split("\n")
        
        new_config.append(f"# VIGILANT Gateway dnsmasq configuration\n")
        new_config.append(f"# Auto-generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        new_config.append(f"\n")
        new_config.append(f"# Network interface\n")
        new_config.append(f"interface={config.get('distribution_interface', 'wlp1s0')}\n")
        new_config.append(f"\n")
        new_config.append(f"# DHCP settings\n")
        new_config.append(f"dhcp-range={config.get('dhcp_start', '192.168.10.10')},{config.get('dhcp_end', '192.168.10.50')},12h\n")
        new_config.append(f"dhcp-option=3,{config.get('gateway_ip', '192.168.10.1')}\n")
        new_config.append(f"dhcp-option=6,{config.get('gateway_ip', '192.168.10.1')}\n")
        new_config.append(f"\n")
        new_config.append(f"# DNS settings\n")
        new_config.append(f"listen-address={config.get('gateway_ip', '192.168.10.1')}\n")
        for dns in dns_servers:
            new_config.append(f"server={dns.strip()}\n")
        new_config.append(f"\n")
        new_config.append(f"# Cache settings\n")
        new_config.append(f"cache-size=1000\n")
        
        # Write to file
        _ensure_directory(config_path)
        with open(config_path, 'w') as f:
            f.writelines(new_config)
        
        app.logger.info("Successfully wrote dnsmasq.conf")
        return True
        
    except Exception as exc:
        app.logger.warning("Failed to write dnsmasq.conf: %s", exc)
        return False


def _write_netplan_config(config: dict) -> bool:
    """Write netplan configuration file"""
    config_path = Path("/home/vigilant_admin/vigilant/src/config/netplan-config.yaml")
    fallback_path = Path("/etc/netplan/00-installer-config.yaml")
    
    # Use fallback path for local development
    if not config_path.parent.exists():
        config_path = fallback_path
    
    if yaml is None:
        app.logger.warning("PyYAML not available, skipping netplan config write")
        return False
    
    try:
        # Build netplan configuration
        netplan_config = {
            "network": {
                "version": 2,
                "ethernets": {
                    config.get("upstream_interface", "enp0s31f6"): {
                        "dhcp4": True,
                        "dhcp4-overrides": {
                            "use-dns": False
                        }
                    },
                    config.get("distribution_interface", "wlp1s0"): {
                        "addresses": [f"{config.get('gateway_ip', '192.168.10.1')}/24"],
                        "dhcp4": False
                    }
                }
            }
        }
        
        # Write to file
        _ensure_directory(config_path)
        with open(config_path, 'w') as f:
            yaml.dump(netplan_config, f, default_flow_style=False)
        
        app.logger.info("Successfully wrote netplan-config.yaml")
        return True
        
    except Exception as exc:
        app.logger.warning("Failed to write netplan-config.yaml: %s", exc)
        return False


def get_system_interfaces() -> list:
    """Get list of available network interfaces using socket.if_nameindex()"""
    try:
        interfaces = socket.if_nameindex()
        # Extract interface names from (index, name) tuples
        iface_names = [name for index, name in interfaces]
        # Filter out loopback and virtual interfaces for cleaner list
        filtered = [iface for iface in iface_names if not iface.startswith('lo') and not iface.startswith('veth') and not iface.startswith('docker')]
        if filtered:
            return sorted(filtered)
    except Exception as exc:
        app.logger.warning("Failed to get network interfaces via socket.if_nameindex: %s", exc)
        # Fallback to common interface names
        return ['eth0', 'wlan0', 'enp0s3', 'wlp1s0']
    return []


def _get_network_interfaces() -> list:
    """Get list of available network interfaces from system"""
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
                    INSERT OR IGNORE INTO config_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
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

    # Initialize category hints table with default domain mappings
    init_category_hints_db()


def init_category_hints_db() -> None:
    """Initialize category_hints table with default domain mappings"""
    try:
        with _open_db() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS category_hints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    domain TEXT NOT NULL UNIQUE
                )
                """
            )

            # Check if table is empty
            count = connection.execute("SELECT COUNT(*) FROM category_hints").fetchone()[0]
            if count > 0:
                return  # Already has data

            # Default category hints from vigilant_addon.py
            default_hints = [
                ("Educational", "wikipedia.org"),
                ("Educational", "khanacademy.org"),
                ("Educational", "coursera.org"),
                ("Educational", "edx.org"),
                ("Educational", "scholar.google.com"),
                ("Educational", "researchgate.net"),
                ("Educational", "academia.edu"),
                ("Educational", "jstor.org"),
                ("Educational", "pubmed.ncbi.nlm.nih.gov"),
                ("Educational", "stackoverflow.com"),
                ("Educational", "docs.python.org"),
                ("Educational", "arxiv.org"),
                ("Productive", "github.com"),
                ("Productive", "gitlab.com"),
                ("Productive", "notion.so"),
                ("Productive", "trello.com"),
                ("Productive", "slack.com"),
                ("Productive", "linear.app"),
                ("Productive", "jira.atlassian.com"),
                ("Productive", "drive.google.com"),
                ("Productive", "docs.google.com"),
                ("Productive", "sheets.google.com"),
                ("Distracting", "reddit.com"),
                ("Distracting", "twitter.com"),
                ("Distracting", "x.com"),
                ("Distracting", "tiktok.com"),
                ("Distracting", "instagram.com"),
                ("Distracting", "facebook.com"),
                ("Distracting", "youtube.com"),
                ("Distracting", "twitch.tv"),
                ("Distracting", "9gag.com"),
                ("Distracting", "buzzfeed.com"),
            ]

            for category, domain in default_hints:
                connection.execute(
                    "INSERT OR IGNORE INTO category_hints (category, domain) VALUES (?, ?)",
                    (category, domain)
                )

            connection.commit()
            app.logger.info("Initialized category_hints table with default mappings")
    except sqlite3.Error as exc:
        app.logger.debug(
            "init_category_hints_db: could not create or seed category_hints table "
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
                "SELECT key, value FROM config_settings",
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

        # Write missing default keys to database
        missing_keys = set(CONFIG_DEFAULTS.keys()) - set(config.keys())
        if missing_keys:
            with _open_db() as connection:
                now_ts = time.time()
                for key in missing_keys:
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO config_settings (key, value, updated_at)
                        VALUES (?, ?, ?)
                        """,
                        (key, str(CONFIG_DEFAULTS[key]), now_ts),
                    )
                connection.commit()
                app.logger.info("Wrote missing default config keys: %s", missing_keys)

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

@app.route("/api/dashboard/summary")
def dashboard_summary():
    """Unified state endpoint - compiles all dashboard data in under 50ms"""
    global _last_net_io, _last_net_time
    start_time = time.time()
    
    # 1. System Metrics via psutil - use non-blocking calls for speed
    cpu_usage = 0.0
    ram_usage_gb = 0.0
    ram_total_gb = 8.0
    disk_usage = 0.0
    rx_mbps = 0.0
    tx_mbps = 0.0

    if psutil:
        try:
            # Non-blocking CPU sample (returns last computed value)
            cpu_usage = float(psutil.cpu_percent(interval=None))
            mem = psutil.virtual_memory()
            ram_usage_gb = round(mem.used / (1024**3), 1)
            ram_total_gb = round(mem.total / (1024**3), 1)
            disk_usage = float(psutil.disk_usage('/').percent)

            # Fast throughput calculation using last saved counters if available
            current_time = time.time()
            current_io = psutil.net_io_counters()
            if _last_net_io and _last_net_time:
                time_diff = max(0.001, current_time - _last_net_time)
                rx_bytes = max(0, current_io.bytes_recv - _last_net_io.bytes_recv)
                tx_bytes = max(0, current_io.bytes_sent - _last_net_io.bytes_sent)
                rx_mbps = round((rx_bytes * 8) / (1024 * 1024 * time_diff), 1)
                tx_mbps = round((tx_bytes * 8) / (1024 * 1024 * time_diff), 1)

            _last_net_io = current_io
            _last_net_time = current_time
        except Exception as e:
            app.logger.debug("Error fetching psutil stats (continuing with defaults): %s", e)
            
    # Service statuses
    services_state = _service_statuses()
    services = {
        "mitmproxy": services_state.get("vigilant_proxy", "offline"),
        "hostapd": "active", 
        "dnsmasq": "active"
    }

    # 2. Database metrics (single connection for speed)
    total_connected = 0
    throttled_count = 0
    recent_alerts = 0
    recent_entries = []
    dhcp_allocations = []
    
    if DB_PATH.exists():
        try:
            with _open_db() as conn:
                # Connected devices (distinct IPs in last 24h)
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
                    
                    # Get DHCP allocations with simulated throughput
                    device_rows = conn.execute("""
                        SELECT ip_address, mac_address, hostname, custom_name, last_seen
                        FROM network_devices
                        ORDER BY last_seen DESC
                    """).fetchall()
                    
                    import random
                    for row in device_rows:
                        ip = row[0]
                        mac = row[1]
                        host = row[2] or "Unknown"
                        cname = row[3]
                        last = row[4]
                        
                        # Simulate active throughput values for display
                        base_rx = random.uniform(0.5, 5.0)
                        base_tx = random.uniform(0.2, 2.0)
                        
                        dhcp_allocations.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": host,
                            "custom_name": cname,
                            "last_seen": last,
                            "rx_mbps": round(base_rx, 2),
                            "tx_mbps": round(base_tx, 2)
                        })
        except sqlite3.Error as e:
            app.logger.warning(f"DB Error in summary: {e}")

    # 3. Active Config
    config = load_config()
    nlp_enabled = _coerce_bool(config.get("nlp_enabled", "true"))
    theme_mode = config.get("theme_mode", "dark")
    
    # Map threshold to preset
    try:
        net_vel = float(config.get("network_velocity_threshold", "1.5"))
    except ValueError:
        net_vel = 1.5
    if net_vel >= 2.0: net_preset = "Low"
    elif net_vel >= 1.5: net_preset = "Medium"
    else: net_preset = "High"
    
    try:
        scroll_vel = int(config.get("physical_scroll_threshold", "75"))
    except ValueError:
        scroll_vel = 75
    if scroll_vel >= 120: scroll_preset = "Low"
    elif scroll_vel >= 75: scroll_preset = "Medium"
    else: scroll_preset = "High"

    # Log performance
    elapsed_ms = (time.time() - start_time) * 1000
    if elapsed_ms > 50:
        app.logger.warning(f"dashboard_summary took {elapsed_ms:.2f}ms (target: <50ms)")

    return jsonify({
        "system": {
            "cpu_usage": cpu_usage,
            "ram_usage_gb": ram_usage_gb,
            "ram_total_gb": ram_total_gb,
            "disk_usage": disk_usage,
            "services": services,
            "throughput_rx_mbps": max(0.0, rx_mbps),
            "throughput_tx_mbps": max(0.0, tx_mbps)
        },
        "devices": {
            "total_connected": total_connected,
            "throttled_count": throttled_count
        },
        "logs": {
            "recent_alerts": recent_alerts,
            "recent_entries": recent_entries
        },
        "active_config": {
            "nlp_enabled": nlp_enabled,
            "network_velocity_preset": net_preset,
            "physical_scroll_preset": scroll_preset,
            "theme_mode": theme_mode
        },
        "dhcp_allocations": dhcp_allocations
    })


@app.route('/api/stats')
def get_stats():
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Filter parameters
        category_filter = request.args.get('category', '').strip()
        search_filter = request.args.get('search', '').strip()
        
        # Validate pagination parameters
        page = max(1, page)
        per_page = max(1, min(per_page, 100))  # Cap at 100 per page
        
        offset = (page - 1) * per_page
        
        total_reqs = _total_request_count(category_filter=category_filter, search_filter=search_filter)
        blocked_reqs = _blocked_request_count()
        active_clients = _connected_device_count()
        raw_categories = _traffic_percentage_metrics()

        # Calculate percentages excluding UNCATEGORIZED from total
        category_percentages = _calculate_category_percentages(raw_categories)

        formatted_counts = [
            {"category": category, "count": int(count)}
            for category, count in raw_categories.items()
        ]

        raw_logs = _get_recent_logs(limit=per_page, offset=offset, category_filter=category_filter, search_filter=search_filter)
        formatted_recent = [_format_recent_log_entry(log) for log in raw_logs]
        
        # Calculate pagination metadata
        total_pages = (total_reqs + per_page - 1) // per_page if total_reqs > 0 else 1
        
        system_metrics = _system_metrics()

        # Network configuration from config files
        network_config = _get_network_config()
        
        # Add available network interfaces
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
        print(f"STATS ENDPOINT CRASH: {exc}")
        app.logger.error("Failed to compile /api/stats payload: %s", exc)
        # Return safe fallback JSON with all zeroes to prevent UI lockup
        return jsonify({
            "total": 0,
            "flagged": 0,
            "clients": 0,
            "counts": [
                {"category": "Educational", "count": 0},
                {"category": "Productive", "count": 0},
                {"category": "Distracting", "count": 0},
                {"category": "Harmful", "count": 0}
            ],
            "percentage_metrics": {
                "Educational": 0.0,
                "Productive": 0.0,
                "Distracting": 0.0,
                "Harmful": 0.0
            },
            "recent": [],
            "uptime": "0h 0m",
            "statuses": _service_statuses(),
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_pages": 1,
                "total_items": 0
            },
            "system_metrics": {
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "disk_percent": 0.0
            },
            "network_config": _get_network_config()
        })




@app.route("/api/config/reset", methods=["POST"])
def api_config_reset():
    """Reset configuration to factory defaults"""
    try:
        # Clear existing config and restore defaults with robust transaction
        with _open_db() as connection:
            # Ensure config_settings table exists
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS config_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at REAL
                )
                """
            )
            
            # Start transaction
            connection.execute("BEGIN TRANSACTION")
            
            try:
                # Clear existing config
                if _table_exists(connection, "config_settings"):
                    connection.execute("DELETE FROM config_settings")
                
                # Insert factory defaults
                now_ts = time.time()
                for key, value in CONFIG_DEFAULTS.items():
                    connection.execute(
                        """
                        INSERT INTO config_settings (key, value, updated_at)
                        VALUES (?, ?, ?)
                        """,
                        (key, str(value), now_ts)
                    )
                
                connection.commit()
                app.logger.info("Configuration reset to factory defaults")
            except Exception as tx_exc:
                connection.rollback()
                app.logger.error(f"Reset transaction failed, rolled back: {tx_exc}")
                return jsonify({"error": f"Database transaction failed: {tx_exc}"}), 500
        
        # Write network configuration files with defaults
        try:
            _write_dnsmasq_config(CONFIG_DEFAULTS)
            _write_netplan_config(CONFIG_DEFAULTS)
        except Exception as file_exc:
            app.logger.warning(f"Failed to write network config files during reset: {file_exc}")
        
        return jsonify({"status": "success", "message": "Configuration reset to factory defaults"})
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


@app.route('/api/logs/export')
def export_logs():
    """Export traffic logs as CSV file using BytesIO for Flask 2.x/3.x compatibility"""
    try:
        # Fetch logs from SQLite database via query_db helper.
        # Exclude non-web noise categories 'DNS_TRACKED' and 'NON-HTML' for clean export.
        logs = query_db(
            "SELECT timestamp, client_ip, host, category, flagged "
            "FROM traffic_log "
            "WHERE category NOT IN ('DNS_TRACKED', 'NON-HTML') "
            "ORDER BY timestamp DESC"
        )

        # Create in-memory text stream
        text_stream = io.StringIO()
        cw = csv.writer(text_stream)

        # Write CSV Headers
        cw.writerow(['Time', 'Client IP', 'Domain', 'Category', 'Status'])

        # Write rows
        for log in logs:
            formatted_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(log['timestamp']))
            status = 'Blocked' if log['flagged'] else 'Allowed'
            cw.writerow([formatted_time, log['client_ip'], log['host'], log['category'], status])

        # Convert the text stream to binary BytesIO encoded in UTF-8
        byte_stream = io.BytesIO()
        byte_stream.write(text_stream.getvalue().encode('utf-8'))
        byte_stream.seek(0)  # Rewind the stream pointer to the beginning

        text_stream.close()

        app.logger.info(f"Exported {len(logs)} traffic log entries to CSV")

        return send_file(
            byte_stream,
            as_attachment=True,
            download_name='traffic_logs.csv',
            mimetype='text/csv'
        )

    except Exception as e:
        # Log the internal error safely
        print(f"Export Error: {e}")
        app.logger.error("Unexpected error exporting logs: %s", e)
        return abort(500, description="Failed to generate CSV export")


@app.route('/api/config/setup/export')
def export_config():
    try:
        keywords = [row['keyword'] for row in query_db("SELECT keyword FROM keyword_blacklist")]
    except sqlite3.Error:
        keywords = []
        
    try:
        whitelist = [row['mac_address'] for row in query_db("SELECT mac_address FROM network_devices WHERE policy = 'whitelist'")]
    except sqlite3.Error:
        whitelist = []
        
    try:
        system_settings = query_db("SELECT key, value FROM config_settings", one=False)
        settings_dict = {row['key']: row['value'] for row in system_settings}
    except sqlite3.Error:
        settings_dict = {}
        
    config_data = {
        "backup_version": "1.0",
        "blocked_keywords": keywords,
        "mac_whitelist": whitelist,
        "settings": settings_dict
    }
    
    json_str = json.dumps(config_data, indent=4)
    response = make_response(json_str)
    response.headers["Content-Disposition"] = "attachment; filename=vigilant_config.json"
    response.headers["Content-Type"] = "application/json"
    return response


@app.route('/api/config/setup/import', methods=['POST'])
def import_config():
    if 'config_file' not in request.files:
        flash("No file uploaded", "error")
        return redirect(url_for('dashboard'))
        
    file = request.files['config_file']
    if file.filename == '':
        flash("No selected file", "error")
        return redirect(url_for('dashboard'))
        
    try:
        config_data = json.loads(file.read().decode('utf-8'))
        
        # Validation Check
        if "blocked_keywords" not in config_data or "mac_whitelist" not in config_data:
            raise ValueError("Invalid configuration file format.")
            
        with _open_db() as connection:
            connection.execute("DELETE FROM keyword_blacklist")
            for kw in config_data["blocked_keywords"]:
                connection.execute("INSERT OR IGNORE INTO keyword_blacklist (keyword) VALUES (?)", (kw,))
                
            connection.execute("UPDATE network_devices SET policy = 'none' WHERE policy = 'whitelist'")
            for mac in config_data["mac_whitelist"]:
                if mac:
                    connection.execute(
                        "UPDATE network_devices SET policy = 'whitelist' WHERE mac_address = ?", 
                        (mac,)
                    )
            
            if "settings" in config_data:
                connection.execute("DELETE FROM config_settings")
                now_ts = time.time()
                for k, v in config_data["settings"].items():
                    connection.execute(
                        "INSERT INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)",
                        (k, str(v), now_ts)
                    )
            
            connection.commit()
            
        flash("Configuration imported successfully!", "success")
    except Exception as e:
        app.logger.error("Failed to import config: %s", e)
        flash(f"Failed to import config: {str(e)}", "error")
        
    return redirect(url_for('dashboard'))
@app.route("/api/config/ui-theme", methods=["POST"])
def save_ui_theme():
    """Save the UI theme preference (light/dark)"""
    try:
        payload = request.get_json(silent=True) or {}
        theme = str(payload.get("theme", "")).strip().lower()
        
        if theme not in ["light", "dark"]:
            return jsonify({"error": "Invalid theme. Must be 'light' or 'dark'"}), 400
            
        save_config({"ui_theme": theme})
        return jsonify({"status": "success", "message": "Theme preference saved"})
    except Exception as exc:
        app.logger.error("Failed to save ui-theme: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/config", methods=["GET"])
def api_config():
    """Standardized configuration API endpoint - returns unified config with fallback defaults"""
    try:
        config = load_config()
        
        # Ensure required keys exist with fallback defaults
        fallback_config = {
            "nlp_enabled": True,
            "keywords": "tiktok, instagram, facebook, scroll, short",
            "network_velocity_preset": "Medium",
            "network_velocity_custom": 150,
            "physical_scroll_preset": "Medium",
            "physical_scroll_custom": 75,
            "sni_filtering_enabled": True,
            "upstream_interface": "eth0",
            "distribution_interface": "wlan0",
            "theme_mode": "dark"
        }
        
        # Merge fallback values for missing keys
        for key, value in fallback_config.items():
            if key not in config or config[key] is None:
                config[key] = value
        
        # Add network configuration from config files
        network_config = _get_network_config()
        
        # Add available network interfaces using the new socket-based function
        network_config["available_interfaces"] = get_system_interfaces()
        
        # Merge network config into response
        config.update(network_config)
        
        # Write missing defaults to database to prevent future 404s
        missing_keys = {k: v for k, v in fallback_config.items() if k not in config or config.get(k) is None}
        if missing_keys:
            try:
                with _open_db() as connection:
                    now_ts = time.time()
                    for key, value in missing_keys.items():
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO config_settings (key, value, updated_at)
                            VALUES (?, ?, ?)
                            """,
                            (key, str(value), now_ts)
                        )
                    connection.commit()
                    app.logger.info(f"Wrote missing config defaults: {list(missing_keys.keys())}")
            except sqlite3.Error as db_exc:
                app.logger.warning(f"Failed to write missing config defaults: {db_exc}")
        
        return jsonify(config)
    except Exception as exc:
        app.logger.error("Failed to load config: %s", exc)
        # Return safe fallback with all required defaults
        fallback_config = {
            "nlp_enabled": True,
            "keywords": "tiktok, instagram, facebook, scroll, short",
            "network_velocity_preset": "Medium",
            "network_velocity_custom": 150,
            "physical_scroll_preset": "Medium",
            "physical_scroll_custom": 75,
            "sni_filtering_enabled": True,
            "upstream_interface": "eth0",
            "distribution_interface": "wlan0",
            "theme_mode": "dark",
            "available_interfaces": get_system_interfaces()
        }
        return jsonify(fallback_config)


@app.route("/api/config/setup", methods=["GET", "POST"])
def api_config_setup():
    if request.method == "GET":
        config = load_config()
        # Add network configuration from config files
        network_config = _get_network_config()
        
        # Add available network interfaces
        network_config["available_interfaces"] = get_system_interfaces()
        
        # Merge network config into response
        config.update(network_config)
        return jsonify(config)

    payload = request.get_json(silent=True)
    print(f"INCOMING SAVE PAYLOAD: {payload}")
    if not isinstance(payload, dict):
        return jsonify({"error": "JSON object payload is required"}), 400

    # Check if this is a setup request (only contains allowed setup keys)
    allowed_setup_keys = {"upstream_interface", "distribution_interface", "theme_mode"}
    payload_keys = set(payload.keys())
    
    # If payload only contains setup keys, use secure setup handler
    if payload_keys.issubset(allowed_setup_keys) and payload_keys:
        setup_updates = {}
        validation_errors = []
        
        for key in allowed_setup_keys:
            if key in payload:
                value = payload[key]
                if key == "theme_mode":
                    # Validate theme_mode
                    theme_value = str(value).strip().lower()
                    if theme_value not in ["light", "dark"]:
                        validation_errors.append(f"Invalid {key}. Must be 'light' or 'dark'")
                    else:
                        setup_updates[key] = theme_value
                else:
                    # Validate interface names
                    interface_value = str(value).strip()
                    if not interface_value or len(interface_value) > 15:
                        validation_errors.append(f"Invalid {key}. Interface name must be 1-15 characters")
                    else:
                        setup_updates[key] = interface_value

        if validation_errors:
            return jsonify({"error": "Invalid configuration values", "details": validation_errors}), 400

        if not setup_updates:
            return jsonify({"error": "No valid setup configuration keys provided"}), 400

        # Write configuration directly to SQLite database with robust transaction
        try:
            with _open_db() as connection:
                # Ensure config_settings table exists with all required columns
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS config_settings (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        updated_at REAL
                    )
                    """
                )
                
                # Check for missing columns and add them if needed (defensive ALTER TABLE)
                cursor = connection.execute("PRAGMA table_info(config_settings)")
                existing_columns = {row[1] for row in cursor.fetchall()}
                
                # Start transaction
                connection.execute("BEGIN TRANSACTION")
                
                try:
                    now_ts = time.time()
                    for key, value in setup_updates.items():
                        connection.execute(
                            """
                            INSERT INTO config_settings (key, value, updated_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(key) DO UPDATE SET
                                value = excluded.value,
                                updated_at = excluded.updated_at
                            """,
                            (key, str(value), now_ts)
                        )
                    
                    connection.commit()
                    app.logger.info(f"Setup configuration saved: {list(setup_updates.keys())}")
                except Exception as tx_exc:
                    connection.rollback()
                    app.logger.error(f"Transaction failed, rolled back: {tx_exc}")
                    return jsonify({"error": f"Database transaction failed: {tx_exc}"}), 500
                
        except sqlite3.Error as db_exc:
            app.logger.error(f"Failed to save setup configuration to database: {db_exc}")
            return jsonify({"error": f"Database error: {db_exc}"}), 500

        # If network interfaces were updated, also write to config files
        if "upstream_interface" in setup_updates or "distribution_interface" in setup_updates:
            try:
                full_config = load_config()
                full_config.update(setup_updates)
                
                dnsmasq_written = _write_dnsmasq_config(full_config)
                netplan_written = _write_netplan_config(full_config)
                
                if not dnsmasq_written:
                    app.logger.warning("Failed to write dnsmasq.conf during setup")
                if not netplan_written:
                    app.logger.warning("Failed to write netplan-config.yaml during setup")
                    
            except Exception as file_exc:
                app.logger.warning(f"Failed to write network config files during setup: {file_exc}")

        # Return explicit success response as requested
        return jsonify({
            "status": "success",
            "message": "Setup configuration saved successfully",
            "saved_keys": list(setup_updates.keys())
        })

    # Otherwise, use the general configuration handler
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
        
        # Write network configuration files if network settings changed
        network_keys = {"upstream_interface", "distribution_interface", "gateway_ip", "dhcp_start", "dhcp_end", "upstream_dns"}
        if any(key in coerced_updates for key in network_keys):
            # Get full config for file writing
            full_config = load_config()
            full_config.update(coerced_updates)
            
            # Write dnsmasq and netplan configs
            dnsmasq_written = _write_dnsmasq_config(full_config)
            netplan_written = _write_netplan_config(full_config)
            
            if not dnsmasq_written:
                app.logger.warning("Failed to write dnsmasq.conf, configuration saved to database only")
            if not netplan_written:
                app.logger.warning("Failed to write netplan-config.yaml, configuration saved to database only")

    config = load_config()
    network_config = _get_network_config()
    config.update(network_config)
    return jsonify({"status": "success", "message": "Configuration applied successfully", "config": config})


@app.route("/api/keywords", methods=["GET"])
def get_keywords():
    """Get all keywords from blacklist"""
    try:
        if not DB_PATH.exists():
            return jsonify([])

        with _open_db() as connection:
            if not _table_exists(connection, "keyword_blacklist"):
                return jsonify([])

            rows = connection.execute(
                "SELECT id, keyword FROM keyword_blacklist ORDER BY keyword"
            ).fetchall()

            keywords = [{"id": row[0], "keyword": row[1]} for row in rows]
            return jsonify(keywords)
    except sqlite3.Error as exc:
        app.logger.error("Failed to get keywords: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/keywords", methods=["POST"])
def add_keyword():
    """Add a keyword to blacklist"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        keyword = payload.get("keyword", "").strip()
        if not keyword:
            return jsonify({"error": "Keyword is required"}), 400

        keyword = keyword.lower()

        with _open_db() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS keyword_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    keyword TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            try:
                cursor = connection.execute(
                    "INSERT INTO keyword_blacklist (keyword) VALUES (?)",
                    (keyword,)
                )
                connection.commit()
                return jsonify({"id": cursor.lastrowid, "keyword": keyword}), 201
            except sqlite3.IntegrityError:
                return jsonify({"error": "Keyword already exists"}), 409

    except sqlite3.Error as exc:
        app.logger.error("Failed to add keyword: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/keywords/<int:keyword_id>", methods=["DELETE"])
def delete_keyword(keyword_id):
    """Delete a keyword from blacklist"""
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "keyword_blacklist"):
                return jsonify({"error": "Keyword blacklist table does not exist"}), 404

            cursor = connection.execute(
                "DELETE FROM keyword_blacklist WHERE id = ?",
                (keyword_id,)
            )
            connection.commit()

            if cursor.rowcount == 0:
                return jsonify({"error": "Keyword not found"}), 404

            return jsonify({"status": "success", "message": "Keyword deleted"}), 200

    except sqlite3.Error as exc:
        app.logger.error("Failed to delete keyword: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/config/filtering", methods=["GET"])
def get_filtering_config():
    """Get content filtering configuration parameters with keyword processing"""
    try:
        config = load_config()
        
        # Get keywords from database with fallback to defaults
        keywords = ["tiktok", "instagram", "facebook"]
        try:
            if DB_PATH.exists():
                with _open_db() as connection:
                    if _table_exists(connection, "keyword_blacklist"):
                        rows = connection.execute("SELECT keyword FROM keyword_blacklist").fetchall()
                        if rows:
                            # Return a list of cleaned keywords
                            keywords = [row[0].strip() for row in rows if row[0]]
                        else:
                            # Initialize with defaults if table is empty
                            default_keywords = ["tiktok", "instagram", "facebook"]
                            for kw in default_keywords:
                                connection.execute(
                                    "INSERT OR IGNORE INTO keyword_blacklist (keyword) VALUES (?)",
                                    (kw,)
                                )
                            connection.commit()
                            keywords = list(default_keywords)
        except sqlite3.Error as db_exc:
            app.logger.warning(f"Failed to load keywords from database: {db_exc}")
        
        filtering_config = {
            "nlp_enabled": config.get("nlp_enabled", "true"),
            "nlp_accuracy": config.get("nlp_accuracy", "balanced"),
            "keywords": keywords
        }
        return jsonify(filtering_config)
    except Exception as exc:
        app.logger.error("Failed to get filtering config: %s", exc)
        # Return safe fallback with defaults
        return jsonify({
            "nlp_enabled": "true",
            "nlp_accuracy": "balanced",
            "keywords": "tiktok, instagram, facebook"
        })


@app.route("/api/config/filtering", methods=["POST"])
def save_filtering_config():
    """Save content filtering configuration parameters with keyword processing"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        config_updates = {}
        validation_errors = []

        if "nlp_enabled" in payload:
            nlp_enabled = str(payload["nlp_enabled"]).strip().lower()
            if nlp_enabled in ["true", "false", "1", "0"]:
                config_updates["nlp_enabled"] = nlp_enabled
            else:
                validation_errors.append("Invalid nlp_enabled value")

        if "nlp_accuracy" in payload:
            nlp_mode = str(payload["nlp_accuracy"]).strip()
            if nlp_mode in ["fast", "balanced", "strict"]:
                config_updates["nlp_accuracy"] = nlp_mode
            else:
                validation_errors.append("Invalid nlp_accuracy")

        # Process keywords if provided - accept list or comma-separated string
        if "keywords" in payload:
            raw = payload["keywords"]
            if isinstance(raw, list):
                keywords_list = [str(k).strip().lower() for k in raw if str(k).strip()]
            else:
                keywords_raw = str(raw or "").strip()
                keywords_list = [kw.strip().lower() for kw in keywords_raw.split(",") if kw.strip()]

            if keywords_list:
                try:
                    with _open_db() as connection:
                        # Ensure keyword_blacklist table exists
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS keyword_blacklist (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                keyword TEXT NOT NULL UNIQUE,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                            """
                        )

                        # Clear existing keywords
                        connection.execute("DELETE FROM keyword_blacklist")

                        # Insert new keywords
                        for keyword in keywords_list:
                            connection.execute(
                                "INSERT OR IGNORE INTO keyword_blacklist (keyword) VALUES (?)",
                                (keyword,)
                            )

                        connection.commit()
                        app.logger.info(f"Updated {len(keywords_list)} keywords in blacklist")
                except sqlite3.Error as db_exc:
                    app.logger.warning(f"Failed to update keywords in database: {db_exc}")
                    validation_errors.append(f"Failed to save keywords: {db_exc}")

        if validation_errors:
            return jsonify({"error": "Invalid configuration values", "details": validation_errors}), 400

        if not config_updates and "keywords" not in payload:
            return jsonify({"error": "No valid filtering configuration parameters provided"}), 400

        save_config(config_updates)
        return jsonify({"status": "success", "message": "Filtering configuration updated successfully"})

    except Exception as exc:
        app.logger.error("Failed to save filtering config: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/config/behavioral", methods=["GET"])
def get_behavioral_config():
    """Get behavioral configuration parameters"""
    try:
        config = load_config()
        behavioral_config = {
            "network_velocity_preset": config.get("network_velocity_preset", "Medium"),
            "network_velocity_custom": int(config.get("network_velocity_custom", 150)),
            "physical_scroll_preset": config.get("physical_scroll_preset", "Medium"),
            "physical_scroll_custom": int(config.get("physical_scroll_custom", 75)),
            "sni_filtering_enabled": config.get("sni_filtering_enabled", "true") in ["true", True, "1", 1]
        }
        return jsonify(behavioral_config)
    except Exception as exc:
        app.logger.error("Failed to get behavioral config: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/config/behavioral", methods=["POST"])
def save_behavioral_config():
    """Save behavioral configuration parameters with preset mapping logic"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        config_updates = {}
        
        # Handle network velocity preset and custom value
        if "network_velocity_preset" in payload:
            preset = str(payload["network_velocity_preset"])
            config_updates["network_velocity_preset"] = preset
            
            # When preset is Custom, save the custom integer value
            if preset == "Custom" and "network_velocity_custom" in payload:
                try:
                    config_updates["network_velocity_custom"] = int(payload["network_velocity_custom"])
                except ValueError:
                    return jsonify({"error": "network_velocity_custom must be an integer"}), 400
            elif preset != "Custom":
                # Map preset to default integer values
                preset_map = {"Low": 100, "Medium": 150, "High": 200}
                config_updates["network_velocity_custom"] = preset_map.get(preset, 150)
            
        # Handle physical scroll preset and custom value
        if "physical_scroll_preset" in payload:
            preset = str(payload["physical_scroll_preset"])
            config_updates["physical_scroll_preset"] = preset
            
            # When preset is Custom, save the custom integer value
            if preset == "Custom" and "physical_scroll_custom" in payload:
                try:
                    config_updates["physical_scroll_custom"] = int(payload["physical_scroll_custom"])
                except ValueError:
                    return jsonify({"error": "physical_scroll_custom must be an integer"}), 400
            elif preset != "Custom":
                # Map preset to default integer values
                preset_map = {"Low": 40, "Medium": 75, "High": 120}
                config_updates["physical_scroll_custom"] = preset_map.get(preset, 75)
                
        if "sni_filtering_enabled" in payload:
            config_updates["sni_filtering_enabled"] = str(payload["sni_filtering_enabled"]).lower()
            
        if not config_updates:
            return jsonify({"error": "No valid behavioral configuration parameters provided"}), 400

        save_config(config_updates)
        return jsonify({"status": "success", "message": "Behavioral settings updated successfully"})

    except Exception as exc:
        app.logger.error("Failed to save behavioral config: %s", exc)
        return jsonify({"error": str(exc)}), 500



@app.route("/api/categories/hints", methods=["GET"])
def get_category_hints():
    """Get all category hints mappings"""
    try:
        if not DB_PATH.exists():
            return jsonify([])

        with _open_db() as connection:
            if not _table_exists(connection, "category_hints"):
                return jsonify([])

            rows = connection.execute(
                "SELECT id, category, domain FROM category_hints ORDER BY category, domain"
            ).fetchall()

            hints = [{"id": row[0], "category": row[1], "domain": row[2]} for row in rows]
            return jsonify(hints)
    except sqlite3.Error as exc:
        app.logger.error("Failed to get category hints: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/categories/hints", methods=["POST"])
def add_category_hint():
    """Add a category hint mapping"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        category = payload.get("category", "").strip()
        domain = payload.get("domain", "").strip().lower()

        if not category:
            return jsonify({"error": "Category is required"}), 400
        if not domain:
            return jsonify({"error": "Domain is required"}), 400

        valid_categories = ["Educational", "Productive", "Distracting", "Harmful"]
        if category not in valid_categories:
            return jsonify({"error": f"Invalid category. Must be one of: {', '.join(valid_categories)}"}), 400

        with _open_db() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS category_hints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    domain TEXT NOT NULL UNIQUE
                )
                """
            )

            try:
                cursor = connection.execute(
                    "INSERT INTO category_hints (category, domain) VALUES (?, ?)",
                    (category, domain)
                )
                connection.commit()
                return jsonify({"id": cursor.lastrowid, "category": category, "domain": domain}), 201
            except sqlite3.IntegrityError:
                return jsonify({"error": "Domain already exists in category hints"}), 409

    except sqlite3.Error as exc:
        app.logger.error("Failed to add category hint: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/categories/hints/<int:hint_id>", methods=["DELETE"])
def delete_category_hint(hint_id):
    """Delete a category hint mapping"""
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "category_hints"):
                return jsonify({"error": "Category hints table does not exist"}), 404

            cursor = connection.execute(
                "DELETE FROM category_hints WHERE id = ?",
                (hint_id,)
            )
            connection.commit()

            if cursor.rowcount == 0:
                return jsonify({"error": "Category hint not found"}), 404

            return jsonify({"status": "success", "message": "Category hint deleted"}), 200

    except sqlite3.Error as exc:
        app.logger.error("Failed to delete category hint: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/devices/filter", methods=["POST"])
def set_device_filter():
    """Set device filter policy (whitelist/blacklist/none)"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        mac_address = payload.get("mac", "").strip()
        action = payload.get("action", "").strip().lower()

        if not mac_address:
            return jsonify({"error": "MAC address is required"}), 400

        if action not in ["whitelist", "blacklist", "none"]:
            return jsonify({"error": "Action must be 'whitelist', 'blacklist', or 'none'"}), 400

        with _open_db() as connection:
            # Ensure network_devices table exists with policy column
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS network_devices (
                    ip_address TEXT PRIMARY KEY,
                    mac_address TEXT,
                    hostname TEXT,
                    custom_name TEXT,
                    policy TEXT DEFAULT 'none',
                    first_seen REAL,
                    last_seen REAL,
                    updated_at REAL
                )
                """
            )

            # Check if device exists by MAC address
            device = connection.execute(
                "SELECT ip_address FROM network_devices WHERE mac_address = ?",
                (mac_address,)
            ).fetchone()

            if device:
                # Update existing device policy
                connection.execute(
                    "UPDATE network_devices SET policy = ?, updated_at = ? WHERE mac_address = ?",
                    (action, time.time(), mac_address)
                )
            else:
                # Device not found, return error
                return jsonify({"error": "Device with MAC address not found"}), 404

            connection.commit()
            app.logger.info(f"Device {mac_address} policy set to {action}")
            return jsonify({"status": "success", "message": f"Device policy set to {action}"})

    except sqlite3.Error as exc:
        app.logger.error(f"Failed to set device filter: {exc}")
        return jsonify({"error": str(exc)}), 500
    except Exception as exc:
        app.logger.error(f"Unexpected error setting device filter: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/categories/hints/<int:hint_id>", methods=["DELETE"])
def delete_category_hint(hint_id):
    """Delete a category hint mapping"""
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "category_hints"):
                return jsonify({"error": "Category hints table does not exist"}), 404

            cursor = connection.execute(
                "DELETE FROM category_hints WHERE id = ?",
                (hint_id,)
            )
            connection.commit()

            if cursor.rowcount == 0:
                return jsonify({"error": "Category hint not found"}), 404

            return jsonify({"status": "success", "message": "Category hint deleted"}), 200

    except sqlite3.Error as exc:
        app.logger.error("Failed to delete category hint: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/network/throughput", methods=["GET"])
def get_network_throughput():
    """Get actual network throughput by reading /proc/net/dev for active interfaces"""
    try:
        # Get active interfaces from config
        config = load_config()
        upstream_interface = config.get("upstream_interface", "enp0s31f6")
        distribution_interface = config.get("distribution_interface", "wlp1s0")
        
        # Global state for tracking last readings
        global _last_net_io, _last_net_time
        
        # Read /proc/net/dev
        proc_net_dev = "/proc/net/dev"
        if not os.path.exists(proc_net_dev):
            return jsonify({"rx_mbps": 0.0, "tx_mbps": 0.0, "error": "proc/net/dev not found"})
        
        current_time = time.time()
        interface_stats = {}
        
        with open(proc_net_dev, 'r') as f:
            # Skip header lines
            lines = f.readlines()
            for line in lines[2:]:  # Skip first 2 header lines
                parts = line.split()
                if len(parts) >= 10:
                    interface_name = parts[0].rstrip(':')
                    if interface_name in [upstream_interface, distribution_interface]:
                        rx_bytes = int(parts[1])
                        tx_bytes = int(parts[9])
                        interface_stats[interface_name] = {
                            "rx_bytes": rx_bytes,
                            "tx_bytes": tx_bytes
                        }
        
        # Calculate throughput if we have previous readings
        rx_mbps = 0.0
        tx_mbps = 0.0
        
        if _last_net_io and _last_net_time:
            time_diff = max(0.001, current_time - _last_net_time)
            
            total_rx_bytes = 0
            total_tx_bytes = 0
            
            for iface, stats in interface_stats.items():
                if iface in _last_net_io:
                    rx_diff = max(0, stats["rx_bytes"] - _last_net_io[iface]["rx_bytes"])
                    tx_diff = max(0, stats["tx_bytes"] - _last_net_io[iface]["tx_bytes"])
                    total_rx_bytes += rx_diff
                    total_tx_bytes += tx_diff
            
            # Convert to Mbps (bytes * 8 / 1,000,000 / time_diff)
            rx_mbps = round((total_rx_bytes * 8) / (1024 * 1024 * time_diff), 2)
            tx_mbps = round((total_tx_bytes * 8) / (1024 * 1024 * time_diff), 2)
        
        # Update global state
        _last_net_io = interface_stats
        _last_net_time = current_time
        
        return jsonify({
            "rx_mbps": rx_mbps,
            "tx_mbps": tx_mbps,
            "interfaces": list(interface_stats.keys())
        })
        
    except Exception as exc:
        app.logger.error(f"Failed to get network throughput: {exc}")
        return jsonify({"rx_mbps": 0.0, "tx_mbps": 0.0, "error": str(exc)})


@app.route("/api/system/control", methods=["POST"])
def api_system_control():
    """Execute system control commands for service management"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        action = payload.get("action", "").strip()
        
        # Detect if running in local development (macOS) vs production (Linux)
        is_production = os.path.exists("/home/vigilant_admin")
        
        if not is_production:
            # Mock mode for local macOS development
            print(f"[MOCK] System control action: {action}")
            if action == "restart_proxy":
                print("[MOCK] Would execute: sudo systemctl restart vigilant-proxy.service")
            elif action == "reload_config":
                print("[MOCK] Would execute: sudo systemctl restart vigilant-dashboard.service")
            elif action == "reload_firewall":
                print("[MOCK] Would execute: sudo netplan apply")
            else:
                return jsonify({"error": f"Unknown action: {action}"}), 400
            
            return jsonify({
                "status": "success",
                "message": f"Action '{action}' executed (mock mode)",
                "mock": True
            })
        
        # Production mode - execute actual systemctl commands
        if action == "restart_proxy":
            try:
                result = subprocess.run(
                    ["sudo", "systemctl", "restart", "vigilant-proxy.service"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                print(f"Proxy restart successful: {result.stdout}")
                return jsonify({
                    "status": "success",
                    "message": "Proxy service restarted successfully"
                })
            except subprocess.TimeoutExpired:
                return jsonify({"error": "Proxy restart timed out"}), 500
            except subprocess.CalledProcessError as e:
                print(f"Proxy restart failed: {e.stderr}")
                return jsonify({"error": f"Proxy restart failed: {e.stderr}"}), 500
            except Exception as e:
                print(f"Proxy restart error: {str(e)}")
                return jsonify({"error": f"Proxy restart error: {str(e)}"}), 500
                
        elif action == "reload_config":
            # Use delayed background thread to allow Flask to send response before restart
            def delayed_dashboard_restart():
                try:
                    time.sleep(1.5)  # Give Flask time to send response
                    result = subprocess.run(
                        ["sudo", "systemctl", "restart", "vigilant-dashboard.service"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    print(f"Dashboard restart successful: {result.stdout}")
                except subprocess.TimeoutExpired:
                    print("Dashboard restart timed out")
                except subprocess.CalledProcessError as e:
                    print(f"Dashboard restart failed: {e.stderr}")
                except Exception as e:
                    print(f"Dashboard restart error: {str(e)}")
            
            try:
                threading.Thread(target=delayed_dashboard_restart, daemon=True).start()
                return jsonify({
                    "status": "success",
                    "message": "Dashboard reload scheduled successfully"
                })
            except Exception as e:
                print(f"Failed to schedule dashboard restart: {str(e)}")
                return jsonify({"error": f"Failed to schedule dashboard restart: {str(e)}"}), 500
                
        elif action == "reload_firewall":
            try:
                result = subprocess.run(
                    ["sudo", "netplan", "apply"],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                print(f"Firewall reload successful: {result.stdout}")
                return jsonify({
                    "status": "success",
                    "message": "Network configuration reloaded successfully"
                })
            except subprocess.TimeoutExpired:
                return jsonify({"error": "Firewall reload timed out"}), 500
            except subprocess.CalledProcessError as e:
                print(f"Firewall reload failed: {e.stderr}")
                return jsonify({"error": f"Firewall reload failed: {e.stderr}"}), 500
            except Exception as e:
                print(f"Firewall reload error: {str(e)}")
                return jsonify({"error": f"Firewall reload error: {str(e)}"}), 500
        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400
            
    except Exception as exc:
        print(f"System control endpoint error: {exc}")
        return jsonify({"error": f"System control error: {str(exc)}"}), 500


@app.route("/api/devices", methods=["GET"])
def get_devices():
    """Get all network devices with live discovery"""
    try:
        devices = _discover_network_devices()
        return jsonify({"devices": devices})
    except Exception as exc:
        app.logger.error("Failed to get devices: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/devices/policy", methods=["POST"])
def update_device_policy():
    """Update device policy (custom name, whitelist/blacklist)"""
    try:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON object payload is required"}), 400

        ip_address = payload.get("ip_address", "").strip()
        custom_name = payload.get("custom_name", "").strip()
        policy = payload.get("policy", "none").strip()

        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400

        if policy not in ["none", "whitelist", "blacklist"]:
            return jsonify({"error": "Policy must be one of: none, whitelist, blacklist"}), 400

        with _open_db() as connection:
            if not _table_exists(connection, "network_devices"):
                return jsonify({"error": "Network devices table does not exist"}), 404

            now = time.time()
            connection.execute(
                """
                INSERT INTO network_devices (ip_address, custom_name, policy, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    custom_name = excluded.custom_name,
                    policy = excluded.policy,
                    updated_at = excluded.updated_at
                """,
                (ip_address, custom_name, policy, now)
            )
            connection.commit()

        # Apply firewall rules if policy changed to blacklist
        if policy == "blacklist":
            _apply_firewall_block(ip_address)
        elif policy == "whitelist":
            _remove_firewall_block(ip_address)

        app.logger.info(f"Updated device policy for {ip_address}: {policy}")
        return jsonify({"status": "success", "message": "Device policy updated successfully"})

    except sqlite3.Error as exc:
        app.logger.error("Failed to update device policy: %s", exc)
        return jsonify({"error": str(exc)}), 500
    except Exception as exc:
        app.logger.error("Unexpected error updating device policy: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/restraints/registry", methods=["GET"])
def get_restraints_registry():
    """Get active network blocks/restraints registry"""
    try:
        restraints = []
        
        if DB_PATH.exists():
            with _open_db() as connection:
                if _table_exists(connection, "network_devices"):
                    rows = connection.execute(
                        """
                        SELECT ip_address, mac_address, hostname, custom_name, policy, first_seen, last_seen
                        FROM network_devices
                        WHERE policy = 'blacklist'
                        ORDER BY last_seen DESC
                        """
                    ).fetchall()
                    
                    for row in rows:
                        restraints.append({
                            "ip_address": row[0],
                            "mac_address": row[1],
                            "hostname": row[2] or "Unknown",
                            "custom_name": row[3],
                            "policy": row[4],
                            "first_seen": row[5],
                            "last_seen": row[6]
                        })
        
        return jsonify({"restraints": restraints})
    except Exception as exc:
        app.logger.error(f"Failed to get restraints registry: {exc}")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/restraints/release", methods=["POST"])
def release_restraint():
    """Release IP restriction from restraints registry"""
    try:
        data = request.get_json(silent=True) or {}
        ip_address = data.get("ip_address")
        
        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400
        
        with _open_db() as connection:
            if not _table_exists(connection, "network_devices"):
                return jsonify({"error": "Network devices table does not exist"}), 404
            
            now = time.time()
            connection.execute(
                """
                UPDATE network_devices
                SET policy = 'none', updated_at = ?
                WHERE ip_address = ?
                """,
                (now, ip_address)
            )
            connection.commit()
            app.logger.info(f"Released restraint for IP: {ip_address}")
        
        # Remove firewall block
        _remove_firewall_block(ip_address)
        
        return jsonify({"status": "success", "message": f"Released restraint for {ip_address}"})
    except Exception as exc:
        app.logger.error(f"Failed to release restraint: {exc}")
        return jsonify({"error": str(exc)}), 500


def _init_network_devices_db() -> None:
    """Initialize network_devices table for device management"""
    try:
        with _open_db() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS network_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    mac_address TEXT,
                    hostname TEXT,
                    custom_name TEXT,
                    policy TEXT DEFAULT 'none',
                    first_seen REAL,
                    last_seen REAL,
                    updated_at REAL
                )
                """
            )
            connection.commit()
    except sqlite3.Error as exc:
        app.logger.debug(
            "_init_network_devices_db: could not create network_devices table "
            "(access violation or locked database) — %s",
            exc,
        )


def _parse_dnsmasq_leases() -> dict:
    """Parse dnsmasq.leases file to get DHCP client information"""
    leases = {}
    lease_paths = [
        Path("/var/lib/misc/dnsmasq.leases"),
        Path("/var/lib/dnsmasq/dnsmasq.leases"),
        Path("/home/vigilant_admin/vigilant/logs/dnsmasq.leases"),
    ]
    
    for lease_path in lease_paths:
        if lease_path.exists():
            try:
                with open(lease_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        # Format: timestamp mac_address ip_address hostname
                        parts = line.split()
                        if len(parts) >= 4:
                            timestamp = float(parts[0]) if parts[0].isdigit() else 0
                            mac_address = parts[1]
                            ip_address = parts[2]
                            hostname = parts[3] if len(parts) > 3 else ""
                            leases[ip_address] = {
                                'mac_address': mac_address,
                                'hostname': hostname,
                                'timestamp': timestamp
                            }
                app.logger.info(f"Parsed dnsmasq leases from {lease_path}")
                break
            except Exception as exc:
                app.logger.warning(f"Failed to parse {lease_path}: {exc}")
    
    return leases


def _parse_arp_table() -> dict:
    """Parse /proc/net/arp to get active ARP entries"""
    arp_entries = {}
    arp_path = Path("/proc/net/arp")
    
    if not arp_path.exists():
        return arp_entries
    
    try:
        with open(arp_path, 'r') as f:
            lines = f.readlines()
            # Skip header line
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                # Format: IP address HW type Flags HW address Mask Device
                parts = line.split()
                if len(parts) >= 6:
                    ip_address = parts[0]
                    mac_address = parts[3]
                    device = parts[5]
                    # Skip incomplete entries
                    if mac_address != "00:00:00:00:00:00":
                        arp_entries[ip_address] = {
                            'mac_address': mac_address,
                            'device': device
                        }
    except Exception as exc:
        app.logger.warning(f"Failed to parse ARP table: {exc}")
    
    return arp_entries


def _apply_firewall_block(ip_address: str) -> bool:
    """Apply iptables rule to block traffic from IP address"""
    is_production = os.path.exists("/home/vigilant_admin")
    
    if not is_production:
        # Mock mode for local macOS development
        print(f"[MOCK] Would execute: sudo iptables -A INPUT -s {ip_address} -j DROP")
        print(f"[MOCK] Would execute: sudo iptables -A FORWARD -s {ip_address} -j DROP")
        app.logger.info(f"[MOCK] Firewall block applied for {ip_address}")
        return True
    
    try:
        # Remove existing rules for this IP to avoid duplicates
        _remove_firewall_block(ip_address)
        
        # Add new DROP rules for INPUT and FORWARD chains
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        subprocess.run(
            ["sudo", "iptables", "-A", "FORWARD", "-s", ip_address, "-j", "DROP"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        app.logger.info(f"Firewall block applied for {ip_address}")
        return True
    except subprocess.TimeoutExpired:
        app.logger.error(f"Firewall block timeout for {ip_address}")
        return False
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Firewall block failed for {ip_address}: {e.stderr}")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error applying firewall block for {ip_address}: {str(e)}")
        return False


def _remove_firewall_block(ip_address: str) -> bool:
    """Remove iptables rules blocking traffic from IP address"""
    is_production = os.path.exists("/home/vigilant_admin")
    
    if not is_production:
        # Mock mode for local macOS development
        print(f"[MOCK] Would execute: sudo iptables -D INPUT -s {ip_address} -j DROP")
        print(f"[MOCK] Would execute: sudo iptables -D FORWARD -s {ip_address} -j DROP")
        app.logger.info(f"[MOCK] Firewall block removed for {ip_address}")
        return True
    
    try:
        # Remove DROP rules from INPUT and FORWARD chains
        # Use -D to delete, ignore errors if rule doesn't exist
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=10
        )
        subprocess.run(
            ["sudo", "iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=10
        )
        app.logger.info(f"Firewall block removed for {ip_address}")
        return True
    except subprocess.TimeoutExpired:
        app.logger.error(f"Firewall removal timeout for {ip_address}")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error removing firewall block for {ip_address}: {str(e)}")
        return False


def _get_device_throughput(ip_address: str) -> dict:
    """Get device throughput data from /proc/net/dev or iptables, with fallback to simulated values"""
    try:
        # Try to read from /proc/net/dev for actual interface statistics
        proc_net_dev = Path("/proc/net/dev")
        if proc_net_dev.exists():
            try:
                with open(proc_net_dev, 'r') as f:
                    lines = f.readlines()
                    # Skip header lines
                    for line in lines[2:]:
                        parts = line.split()
                        if len(parts) >= 10:
                            interface = parts[0].rstrip(':')
                            # Get RX and TX bytes
                            rx_bytes = int(parts[1])
                            tx_bytes = int(parts[9])
                            
                            # Calculate rates (simplified - would need historical data for accurate rates)
                            # For now, return current byte counts as throughput indicators
                            return {
                                "rx_bytes": rx_bytes,
                                "tx_bytes": tx_bytes,
                                "rx_rate_kb_s": round(rx_bytes / 1024, 2),
                                "tx_rate_kb_s": round(tx_bytes / 1024, 2)
                            }
            except Exception as exc:
                app.logger.warning(f"Failed to parse /proc/net/dev: {exc}")
        
        # Try iptables byte counters for specific IP
        is_production = os.path.exists("/home/vigilant_admin")
        if is_production:
            try:
                # Query iptables for byte counters for this IP
                result = subprocess.run(
                    ["sudo", "iptables", "-L", "INPUT", "-v", "-n", "-x"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip_address in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                bytes_val = int(parts[1])
                                return {
                                    "rx_bytes": bytes_val,
                                    "tx_bytes": 0,
                                    "rx_rate_kb_s": round(bytes_val / 1024, 2),
                                    "tx_rate_kb_s": 0.0
                                }
            except Exception as exc:
                app.logger.warning(f"Failed to query iptables for {ip_address}: {exc}")
        
        # Fallback to simulated fluctuating values if interface is idling
        import random
        base_rx_kb = random.uniform(50, 200)
        base_tx_kb = random.uniform(20, 80)
        rx_bytes = int(base_rx_kb * 1024)
        tx_bytes = int(base_tx_kb * 1024)
        rx_mbps = round((base_rx_kb / 1024), 2)
        tx_mbps = round((base_tx_kb / 1024), 2)
        return {
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_rate_kb_s": round(base_rx_kb, 2),
            "tx_rate_kb_s": round(base_tx_kb, 2),
            # Provide friendly keys expected by frontend
            "rx_mbps": rx_mbps,
            "tx_mbps": tx_mbps,
            "rx": rx_mbps,
            "tx": tx_mbps
        }
        
    except Exception as exc:
        app.logger.warning(f"Failed to get throughput for {ip_address}: {exc}")
        # Safe fallback
        return {
            "rx_bytes": 0,
            "tx_bytes": 0,
            "rx_rate_kb_s": 0.0,
            "tx_rate_kb_s": 0.0
        }


def _discover_network_devices() -> list:
    """Discover network devices by merging dnsmasq leases and ARP table with database records"""
    now = time.time()
    discovered_devices = {}
    
    # Get data from system files
    dnsmasq_leases = _parse_dnsmasq_leases()
    arp_entries = _parse_arp_table()
    
    # Merge data from both sources
    all_ips = set(dnsmasq_leases.keys()) | set(arp_entries.keys())
    
    for ip_address in all_ips:
        device_info = {
            'ip_address': ip_address,
            'mac_address': None,
            'hostname': None,
            'last_seen': now
        }
        
        # Prefer dnsmasq data for hostname and MAC
        if ip_address in dnsmasq_leases:
            device_info['mac_address'] = dnsmasq_leases[ip_address]['mac_address']
            device_info['hostname'] = dnsmasq_leases[ip_address]['hostname']
        
        # Fallback to ARP for MAC address
        if not device_info['mac_address'] and ip_address in arp_entries:
            device_info['mac_address'] = arp_entries[ip_address]['mac_address']
        
        # Add throughput data
        throughput = _get_device_throughput(ip_address)
        # Normalize throughput keys for frontend compatibility
        throughput_summary = {
            'rx_bytes': int(throughput.get('rx_bytes', 0) or 0),
            'tx_bytes': int(throughput.get('tx_bytes', 0) or 0),
            'rx_mbps': float(throughput.get('rx_mbps', throughput.get('rx_rate_kb_s', 0) / 1024 if throughput.get('rx_rate_kb_s') else 0)) or 0.0,
            'tx_mbps': float(throughput.get('tx_mbps', throughput.get('tx_rate_kb_s', 0) / 1024 if throughput.get('tx_rate_kb_s') else 0)) or 0.0,
        }
        # Also provide short keys used by legacy JS
        throughput_summary['rx'] = throughput_summary['rx_mbps']
        throughput_summary['tx'] = throughput_summary['tx_mbps']

        device_info['throughput'] = throughput_summary
        
        discovered_devices[ip_address] = device_info
    
    # Merge with existing database records
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "network_devices"):
                return list(discovered_devices.values())
            
            existing_devices = connection.execute(
                "SELECT ip_address, mac_address, hostname, custom_name, policy, first_seen, last_seen FROM network_devices"
            ).fetchall()
            
            for row in existing_devices:
                ip_address = row[0]
                if ip_address in discovered_devices:
                    # Update existing device with live data
                    discovered_devices[ip_address]['custom_name'] = row[3]
                    discovered_devices[ip_address]['policy'] = row[4]
                    discovered_devices[ip_address]['first_seen'] = row[5]
                    discovered_devices[ip_address]['last_seen'] = now
                    # Refresh throughput for known devices
                    discovered_devices[ip_address]['throughput'] = _get_device_throughput(ip_address)
                else:
                    # Keep device in database even if not currently active
                    discovered_devices[ip_address] = {
                        'ip_address': ip_address,
                        'mac_address': row[1],
                        'hostname': row[2],
                        'custom_name': row[3],
                        'policy': row[4],
                        'first_seen': row[5],
                        'last_seen': row[6],
                        'active': False,
                        'throughput': _get_device_throughput(ip_address)
                    }
            
            # Update database with discovered devices
            for ip_address, device_info in discovered_devices.items():
                if device_info.get('active', True):
                    connection.execute(
                        """
                        INSERT INTO network_devices (ip_address, mac_address, hostname, custom_name, policy, first_seen, last_seen, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(ip_address) DO UPDATE SET
                            mac_address = excluded.mac_address,
                            hostname = excluded.hostname,
                            last_seen = excluded.last_seen,
                            updated_at = excluded.updated_at
                        """,
                        (
                            ip_address,
                            device_info.get('mac_address'),
                            device_info.get('hostname'),
                            device_info.get('custom_name'),
                            device_info.get('policy', 'none'),
                            device_info.get('first_seen', now),
                            device_info.get('last_seen', now),
                            now
                        )
                    )
            
            connection.commit()
            
    except sqlite3.Error as exc:
        app.logger.warning(f"Failed to merge devices with database: {exc}")
    
    return list(discovered_devices.values())


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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS keyword_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    keyword TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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


def _cleanup_unwanted_categories() -> None:
    """Remove noise/telemetry category rows from traffic_log on startup.

    Catches ALL case variants of the three noise category families:
      - Non-HTML  / NON-HTML  / non-html
      - DNS_Tracked / DNS_TRACKED / dns_tracked / DNS / DNS_QUERY
      - Uncategorized / UNCATEGORIZED / uncategorized
      - Mobile_Bypass / MOBILE_BYPASS
    """
    NOISE_CATEGORY_KEYS = (
        "non-html",
        "dns_tracked",
        "dns",
        "dns_query",
        "uncategorized",
        "mobile_bypass",
        "system",
        "telemetry",
    )
    try:
        with _open_db() as connection:
            if not _table_exists(connection, "traffic_log"):
                return

            placeholders = ",".join(["?" for _ in NOISE_CATEGORY_KEYS])
            cursor = connection.execute(
                f"DELETE FROM traffic_log WHERE LOWER(TRIM(category)) IN ({placeholders})",
                NOISE_CATEGORY_KEYS,
            )
            deleted_count = cursor.rowcount
            connection.commit()

            if deleted_count > 0:
                app.logger.info(
                    "Startup cleanup: removed %d noise/telemetry log entries from database",
                    deleted_count,
                )
    except sqlite3.Error as exc:
        app.logger.debug(
            "_cleanup_unwanted_categories: could not clean up noise categories — %s",
            exc,
        )


def auto_categorize(domain: str) -> str:
    """Auto-categorize domains based on keyword matching rules"""
    domain_lower = domain.lower()
    
    # Educational keywords
    if any(kwd in domain_lower for kwd in ["github", "stackoverflow", "docs", "edu", "wikipedia", "classroom", "khan", "coursera", "edx", "scholar", "researchgate", "academia", "jstor", "pubmed"]):
        return "EDUCATIONAL"
    
    # Productive keywords
    if any(kwd in domain_lower for kwd in ["jira", "slack", "trello", "zoom", "meet", "notion", "linear", "drive", "docs", "sheets", "asana", "monday", "basecamp"]):
        return "PRODUCTIVE"
    
    # Distracting keywords
    if any(kwd in domain_lower for kwd in ["youtube", "facebook", "instagram", "tiktok", "netflix", "reddit", "twitter", "x.com", "twitch", "9gag", "buzzfeed", "pinterest", "snapchat"]):
        return "DISTRACTING"
    
    # Harmful keywords
    if any(kwd in domain_lower for kwd in ["gamble", "casino", "torrent", "bet", "porn", "xxx", "adult", "drugs", "illegal"]):
        return "HARMFUL"
    
    return "UNCATEGORIZED"  # Fallback if nothing matches


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


def init_traffic_shaping(interface=None):
    if platform.system() == "Darwin":
        app.logger.info("[MOCK] Init traffic shaping on %s (macOS detected)", interface)
        return
        
    if not interface:
        config = load_config()
        interface = config.get("distribution_interface", "wlan0")

    app.logger.info("Initializing traffic shaping on %s", interface)
    subprocess.run(f"sudo tc qdisc del dev {interface} root", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run(f"sudo tc qdisc add dev {interface} root handle 1: htb default 1", shell=True)
    subprocess.run(f"sudo tc class add dev {interface} parent 1: classid 1:1 htb rate 1000mbit", shell=True)
    subprocess.run(f"sudo tc class add dev {interface} parent 1: classid 1:10 htb rate 128kbit ceil 128kbit", shell=True)
    subprocess.run(f"sudo tc filter add dev {interface} protocol ip parent 1:0 prio 1 handle 10 fw flowid 1:10", shell=True)


def trigger_ip_throttle(ip, interface=None):
    if platform.system() == "Darwin":
        app.logger.info("[MOCK] Throttling IP %s on %s (macOS detected)", ip, interface)
        return
        
    check_rule = f"sudo iptables -t mangle -C POSTROUTING -d {ip} -j MARK --set-mark 10"
    result = subprocess.run(check_rule, shell=True, stderr=subprocess.DEVNULL)
    
    if result.returncode != 0:
        subprocess.run(f"sudo iptables -t mangle -A POSTROUTING -d {ip} -j MARK --set-mark 10", shell=True)
        app.logger.info("[SHAPER] IP %s has been successfully throttled.", ip)


def clear_ip_throttle(ip, interface=None):
    if platform.system() == "Darwin":
        app.logger.info("[MOCK] Lifting throttle for IP %s on %s (macOS detected)", ip, interface)
        return
        
    subprocess.run(f"sudo iptables -t mangle -D POSTROUTING -d {ip} -j MARK --set-mark 10", shell=True, stderr=subprocess.DEVNULL)
    app.logger.info("[SHAPER] IP %s throttle lifted.", ip)


@app.route('/api/dashboard/stats', methods=['GET'])
def mobile_dashboard_stats():
    """Mobile-optimized endpoint for dashboard metrics with balanced 100% data structures"""
    try:
        total_reqs = _total_request_count()
        blocked_reqs = _blocked_request_count()
        active_clients = _connected_device_count()
        raw_categories = _traffic_percentage_metrics()
        category_percentages = _calculate_category_percentages(raw_categories)

        # Format category data for mobile consumption
        mobile_categories = [
            {
                "name": category,
                "count": int(raw_categories.get(category, 0)),
                "percentage": float(category_percentages.get(category, 0.0))
            }
            for category in TRAFFIC_CATEGORIES
        ]

        system_metrics = _system_metrics()
        service_statuses = _service_statuses()

        return jsonify({
            "success": True,
            "data": {
                "total_requests": int(total_reqs),
                "blocked_requests": int(blocked_reqs),
                "active_devices": int(active_clients),
                "categories": mobile_categories,
                "system_metrics": {
                    "cpu_percent": float(system_metrics["cpu_percent"]),
                    "memory_percent": float(system_metrics["memory_percent"]),
                    "disk_percent": float(system_metrics["disk_percent"])
                },
                "service_status": service_statuses,
                "uptime": _format_uptime()
            }
        })

    except Exception as exc:
        app.logger.error("Failed to compile mobile dashboard stats: %s", exc)
        return jsonify({
            "success": False,
            "error": str(exc),
            "data": {
                "total_requests": 0,
                "blocked_requests": 0,
                "active_devices": 0,
                "categories": [
                    {"name": cat, "count": 0, "percentage": 0.0}
                    for cat in TRAFFIC_CATEGORIES
                ],
                "system_metrics": {
                    "cpu_percent": 0.0,
                    "memory_percent": 0.0,
                    "disk_percent": 0.0
                },
                "service_status": _service_statuses(),
                "uptime": "0h 0m"
            }
        }), 500


@app.route('/api/devices/active', methods=['GET'])
def mobile_active_devices():
    """Mobile endpoint for active devices with scroll velocity telemetry per IP"""
    try:
        devices = _discover_network_devices()
        
        # Enhance device data with scroll velocity telemetry
        mobile_devices = []
        for device in devices:
            ip_address = device.get('ip_address')
            device_data = {
                "ip_address": ip_address,
                "mac_address": device.get('mac_address'),
                "hostname": device.get('hostname'),
                "custom_name": device.get('custom_name'),
                "policy": device.get('policy', 'none'),
                "active": device.get('active', True),
                "scroll_velocity": {
                    "is_tracking": ip_address in scroll_velocity_tracker,
                    "scroll_count": len(scroll_velocity_tracker.get(ip_address, [])),
                    "is_throttled": False
                }
            }
            
            # Check if device is currently being throttled based on scroll velocity
            if ip_address in scroll_velocity_tracker:
                history = scroll_velocity_tracker[ip_address]
                if len(history) >= 5:
                    config = load_config()
                    limit = int(config.get("request_threshold", 90))
                    max_allowed_gap = 60.0 / limit if limit > 0 else 0.1
                    gaps = [history[i] - history[i-1] for i in range(1, len(history))]
                    avg_gap = sum(gaps) / len(gaps)
                    device_data["scroll_velocity"]["is_throttled"] = avg_gap < max_allowed_gap
                    device_data["scroll_velocity"]["current_velocity"] = 60.0 / avg_gap if avg_gap > 0 else 0
            
            mobile_devices.append(device_data)

        return jsonify({
            "success": True,
            "data": {
                "total_devices": len(mobile_devices),
                "devices": mobile_devices
            }
        })

    except Exception as exc:
        app.logger.error("Failed to get active devices for mobile: %s", exc)
        return jsonify({
            "success": False,
            "error": str(exc),
            "data": {
                "total_devices": 0,
                "devices": []
            }
        }), 500


@app.route('/api/devices/throttle', methods=['POST', 'DELETE'])
def mobile_device_throttle():
    """Mobile endpoint for manual IP throttling control"""
    try:
        if request.method == 'POST':
            # Add throttle rule for IP
            payload = request.get_json(silent=True) or {}
            if not isinstance(payload, dict):
                return jsonify({"success": False, "error": "JSON object payload is required"}), 400

            ip_address = payload.get("ip_address", "").strip()
            if not ip_address:
                return jsonify({"success": False, "error": "IP address is required"}), 400

            # Apply throttle
            trigger_ip_throttle(ip_address)
            
            # Log throttle event to database
            with _open_db() as connection:
                connection.execute(
                    """
                    INSERT INTO throttle_events (timestamp, client_ip, host, rpm_current, rpm_baseline, action)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (time.time(), ip_address, "manual_mobile", 0, 0, "manual_throttle")
                )
                connection.commit()

            app.logger.info(f"Manual throttle applied for {ip_address} via mobile API")
            return jsonify({
                "success": True,
                "message": f"Throttle applied to {ip_address}",
                "data": {
                    "ip_address": ip_address,
                    "action": "throttle_applied"
                }
            })

        elif request.method == 'DELETE':
            # Remove throttle rule for IP
            payload = request.get_json(silent=True) or {}
            if not isinstance(payload, dict):
                return jsonify({"success": False, "error": "JSON object payload is required"}), 400

            ip_address = payload.get("ip_address", "").strip()
            if not ip_address:
                return jsonify({"success": False, "error": "IP address is required"}), 400

            # Clear throttle
            clear_ip_throttle(ip_address)
            
            # Clear scroll tracking for this IP
            if ip_address in scroll_velocity_tracker:
                scroll_velocity_tracker[ip_address].clear()
            
            # Log throttle removal event to database
            with _open_db() as connection:
                connection.execute(
                    """
                    INSERT INTO throttle_events (timestamp, client_ip, host, rpm_current, rpm_baseline, action)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (time.time(), ip_address, "manual_mobile", 0, 0, "manual_throttle_cleared")
                )
                connection.commit()

            app.logger.info(f"Manual throttle cleared for {ip_address} via mobile API")
            return jsonify({
                "success": True,
                "message": f"Throttle cleared for {ip_address}",
                "data": {
                    "ip_address": ip_address,
                    "action": "throttle_cleared"
                }
            })

    except Exception as exc:
        app.logger.error("Failed to process mobile throttle request: %s", exc)
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.route('/api/report-scroll', methods=['POST'])
def report_scroll():
    client_ip = request.remote_addr
    now = time.time()
    
    if client_ip not in scroll_velocity_tracker:
        scroll_velocity_tracker[client_ip] = deque(maxlen=5)
        
    scroll_velocity_tracker[client_ip].append(now)
    history = scroll_velocity_tracker[client_ip]
    
    config = load_config()
    limit = int(config.get("request_threshold", 90))
    enabled = config.get("throttle_enabled", True)
    
    # Calculate max allowed time gap (e.g., 60 / 90 = 0.67 seconds)
    max_allowed_gap = 60.0 / limit if limit > 0 else 0.1
    
    throttled = False
    
    # We need at least 4 intervals (5 scroll events) to reliably calculate velocity
    if len(history) == 5 and enabled:
        # Calculate gaps between consecutive scrolls
        gaps = [history[i] - history[i-1] for i in range(1, len(history))]
        avg_gap = sum(gaps) / len(gaps)
        
        # If average time gap is smaller than the threshold, they are scrolling too fast!
        if avg_gap < max_allowed_gap:
            throttled = True
            trigger_ip_throttle(client_ip)
            
    if not throttled:
        clear_ip_throttle(client_ip)
        
    return jsonify({
        "status": "ok",
        "throttled": throttled,
        "scroll_count_sampled": len(history)
    })



def _compile_config_integrity() -> None:
    try:
        _init_network_devices_db()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: _init_network_devices_db skipped — %s", exc)

    try:
        init_traffic_shaping()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: init_traffic_shaping skipped — %s", exc)

    try:
        _init_traffic_db()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: _init_traffic_db skipped — %s", exc)

    try:
        _cleanup_unwanted_categories()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: _cleanup_unwanted_categories skipped — %s", exc)

    try:
        _populate_mock_traffic_data()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: _populate_mock_traffic_data skipped — %s", exc)

    try:
        init_config_db()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: init_config_db skipped — %s", exc)

    try:
        init_category_hints_db()
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: init_category_hints_db skipped — %s", exc)

    try:
        current_config = load_config()
        missing_defaults = {
            key: value for key, value in CONFIG_DEFAULTS.items() if key not in current_config
        }
        if missing_defaults:
            save_config(missing_defaults)
    except Exception as exc:
        app.logger.debug("_compile_config_integrity: default config backfill skipped — %s", exc)


def auto_cooldown_task():
    while True:
        try:
            now = time.time()
            for ip, history in list(scroll_velocity_tracker.items()):
                if history:
                    last_scroll = history[-1]
                    if now - last_scroll > 10:
                        clear_ip_throttle(ip)
                        history.clear()
        except Exception as e:
            app.logger.error("Cooldown task error: %s", e)
        time.sleep(10)

if __name__ == "__main__":
    _compile_config_integrity()
    threading.Thread(target=auto_cooldown_task, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)