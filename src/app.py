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
import ipaddress
from contextlib import contextmanager
from pathlib import Path
import platform
from collections import deque
import json
from flask import Flask, jsonify, render_template, request, make_response, send_file, abort, redirect, flash, url_for

# Global network interface configuration - can be overridden via environment variable
GATEWAY_INTERFACE = os.getenv("GATEWAY_INTERFACE", "eth1")

try:
    import psutil
except ImportError:
    psutil = None

yaml = importlib.import_module("yaml") if importlib.util.find_spec("yaml") else None

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
if BASE_DIR.name == "src":
    BASE_DIR = BASE_DIR.parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(
    __name__,
    static_folder=str(STATIC_DIR),
    template_folder=str(TEMPLATE_DIR),
)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = "super_secret_vigilant_key"

SERVER_IP = "192.168.10.1"
PRODUCTION_DB_PATH = Path("/home/vigilant-admin/vigilant_gateway/logs/vigilant.db")
LOCAL_DB_PATH = LOG_DIR / "vigilant.db"
DB_TIMEOUT = 30.0

DB_PATH = str(LOG_DIR / "vigilant.db")
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
    "throttle_duration": "300",
    "ui_theme": "light",
    "tfidf_classification_threshold": "0.05",
    "tfidf_url_threshold": "0.3",
    "tfidf_body_threshold": "0.15",
    "sni_filtering_enabled": "true"
}

CONFIG_DEFAULTS = DEFAULT_CONFIG

ALLOWED_CONFIG_KEYS = set(CONFIG_DEFAULTS) | {
    "block_harmful", "block_distracting", "enable_https", "log_retention", 
    "network_velocity_preset", "network_velocity_custom", "physical_scroll_preset", 
    "physical_scroll_custom", "sni_filtering_enabled", "request_threshold"
}
BOOLEAN_CONFIG_KEYS = {"block_harmful", "block_distracting", "nlp_enabled", "throttle_enabled", "enable_https", "sni_filtering_enabled"}
FLOAT_CONFIG_KEYS = {"network_velocity_threshold", "tfidf_classification_threshold", "tfidf_url_threshold", "tfidf_body_threshold"}
INTEGER_CONFIG_KEYS = {"physical_scroll_threshold", "throttle_rate", "throttle_duration", "log_retention", "network_velocity_custom", "physical_scroll_custom", "request_threshold"}
STRING_CONFIG_KEYS = {"upstream_interface", "distribution_interface", "gateway_ip", "dhcp_start", "dhcp_end", "upstream_dns", "nlp_accuracy", "ui_theme", "network_velocity_preset", "physical_scroll_preset"}
TRAFFIC_CATEGORIES = ("Educational", "Productive", "Distracting", "Harmful")
L4_TRAFFIC_CATEGORIES = ("DNS_TRACKED", "SNI_PASSTHROUGH")
DEFAULT_THROTTLE_DURATION = 300
DEFAULT_SYSTEM_METRICS = {
    "cpu_percent": 0.0,
    "memory_percent": 0.0,
    "disk_percent": 52.0,
}

def _coerce_float(val, default=0.0):
    try:
        v = float(val)
        return v if v >= 0 else default
    except (TypeError, ValueError):
        return default

def _coerce_config_value(key, val):
    if key in FLOAT_CONFIG_KEYS:
        return str(_coerce_float(val))
    elif key in INTEGER_CONFIG_KEYS:
        return str(_coerce_int(val))
    return str(val)


def _ensure_directory(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


def _signal_rule_cache_reload() -> None:
    """Signal the mitmproxy addon to refresh its in-memory rule cache."""
    try:
        reload_file = Path(DB_PATH).parent / ".rule_cache_reload"
        _ensure_directory(reload_file)
        reload_file.write_text(str(time.time()))
    except OSError as exc:
        app.logger.warning("Failed to signal proxy rule cache reload: %s", exc)


def _open_db() -> sqlite3.Connection:
    _ensure_directory(DB_PATH)
    connection = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA synchronous=NORMAL;")
    return connection


@contextmanager
def get_db_connection():
    connection = _open_db()
    try:
        yield connection
    finally:
        connection.close()


def init_db() -> None:
    """Initialize database tables and enable WAL mode for concurrent access."""
    try:
        with get_db_connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL;")
            connection.execute("PRAGMA synchronous=NORMAL;")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS traffic_log ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, client_ip TEXT, "
                "host TEXT, path TEXT, method TEXT, category TEXT, flagged INTEGER DEFAULT 0, entities TEXT)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS config_settings (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS network_devices ("
                "ip_address TEXT PRIMARY KEY, mac_address TEXT, hostname TEXT, custom_name TEXT, "
                "policy TEXT DEFAULT 'none', first_seen REAL, last_seen REAL, updated_at REAL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS throttle_events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, client_ip TEXT, host TEXT, "
                "rpm_current REAL, rpm_baseline REAL, action TEXT, reason TEXT)"
            )
            if not _column_exists(connection, "throttle_events", "reason"):
                connection.execute("ALTER TABLE throttle_events ADD COLUMN reason TEXT")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_category ON traffic_log(category)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_flagged ON traffic_log(flagged)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_traffic_client_ip ON traffic_log(client_ip)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_throttle_timestamp ON throttle_events(timestamp DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_throttle_client_ip ON throttle_events(client_ip)")
            connection.commit()
    except sqlite3.Error as exc:
        app.logger.debug("Database initialization encountered locking: %s", exc)


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


def _column_exists(connection: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    if not _table_exists(connection, table_name):
        return False
    columns = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(str(column[1]) == column_name for column in columns)


def query_db(query: str, args=(), one: bool = False):
    if not DB_PATH.exists():
        return {} if one else []

    try:
        with sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL;")
            connection.execute("PRAGMA synchronous=NORMAL;")
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


def _coerce_float(value):
    if isinstance(value, bool):
        raise ValueError("Invalid float value")
    try:
        float_value = float(value)
    except (TypeError, ValueError):
        raise ValueError("Invalid float value")
    if float_value < 0.0:
        raise ValueError("Float value must be non-negative")
    return float_value


def _coerce_config_value(key: str, value):
    if key in BOOLEAN_CONFIG_KEYS:
        return _coerce_bool(value)
    if key in INTEGER_CONFIG_KEYS:
        return _coerce_int(value)
    if key in FLOAT_CONFIG_KEYS:
        return _coerce_float(value)
    if key in STRING_CONFIG_KEYS:
        return str(value).strip()
    raise ValueError(f"Unsupported configuration key: {key}")


def _extract_ipv4_prefix(value) -> str | None:
    raw_value = str(value or "").strip()
    if not raw_value:
        return None
    try:
        address = ipaddress.ip_address(raw_value.split("/", 1)[0])
    except ValueError:
        return None
    if address.version != 4:
        return None
    octets = str(address).split(".")
    return ".".join(octets[:3]) + ".%"


def _managed_ip_prefix(config: dict | None = None, connection: sqlite3.Connection | None = None) -> str:
    config = config or load_config(connection)
    for key in ("dhcp_start", "gateway_ip", "dhcp_end"):
        prefix = _extract_ipv4_prefix(config.get(key))
        if prefix:
            return prefix

    fallback_network = _get_network_config()
    for key in ("dhcp_start", "gateway_ip", "dhcp_end"):
        prefix = _extract_ipv4_prefix(fallback_network.get(key))
        if prefix:
            return prefix

    return "192.168.10.%"


def _matches_managed_prefix(ip_address: str, managed_prefix: str | None = None, connection: sqlite3.Connection | None = None) -> bool:
    prefix = (managed_prefix or _managed_ip_prefix(connection=connection)).rstrip("%")
    return bool(ip_address) and str(ip_address).startswith(prefix)


def _current_throttle_duration(config: dict | None = None, connection: sqlite3.Connection | None = None) -> int:
    config = config or load_config(connection)
    try:
        return max(60, int(config.get("throttle_duration", DEFAULT_THROTTLE_DURATION)))
    except (TypeError, ValueError):
        return DEFAULT_THROTTLE_DURATION


def _l7_traffic_filter_sql(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    quoted = ", ".join(f"'{category}'" for category in L4_TRAFFIC_CATEGORIES)
    return (
        f"({prefix}category IS NULL OR UPPER(TRIM({prefix}category)) NOT IN ({quoted}))"
    )


def _l4_tracking_filter_sql(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    quoted = ", ".join(f"'{category}'" for category in L4_TRAFFIC_CATEGORIES)
    return f"UPPER(TRIM({prefix}category)) IN ({quoted})"


def _normalize_service_state(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"active", "running", "online", "enabled"}:
        return "active"
    if normalized in {"inactive", "failed", "dead", "offline", "stopped", "unknown"}:
        return "offline"
    return "offline"


def _systemctl_service_state(unit_name: str) -> str | None:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", unit_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=1.5,
        )
        if result.returncode == 0:
            stdout = (result.stdout or "").strip().lower()
            if _normalize_service_state(stdout) == "active":
                return "active"
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    return None


_psutil_failed_logged = False


def _process_service_state(*markers: str, exclude_current_pid: bool = False) -> str:
    global _psutil_failed_logged
    if psutil is None:
        return "offline"

    current_pid = os.getpid()
    lowered_markers = tuple(marker.lower() for marker in markers if marker)

    try:
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                info = proc.info
                if exclude_current_pid and info.get("pid") == current_pid:
                    continue

                searchable = " ".join(
                    [
                        str(info.get("name") or "").lower(),
                        " ".join(str(item).lower() for item in (info.get("cmdline") or [])),
                    ]
                )
                if any(marker in searchable for marker in lowered_markers):
                    return "active"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception as exc:
        if not _psutil_failed_logged:
            app.logger.debug("Failed to iterate processes via psutil: %s", exc)
            _psutil_failed_logged = True
        return "offline"

    return "offline"


def _get_service_state(service_name: str, systemd_unit: str, *process_markers: str) -> str:
    # 1. Environment override check
    env_keys = [f"VIGILANT_{service_name.upper()}_STATE"]
    if service_name.upper() == "DNSMASQ":
        env_keys.append("VIGILANT_DNS_STATE")
    for env_key in env_keys:
        if env_key in os.environ:
            val = os.environ[env_key].strip().lower()
            if val in {"active", "inactive", "offline", "failed"}:
                return val
            
    # 2. Systemd check
    state = _systemctl_service_state(systemd_unit)
    if state == "active":
        return "active"
        
    # 3. Process check
    if process_markers:
        proc_state = _process_service_state(*process_markers)
        if proc_state == "active":
            return "active"
            
    # 4. Fallback for dashboard
    if service_name == "dashboard":
        return "active"
        
    return "offline"


def _service_statuses() -> dict:
    """Return cached service states with environment overrides, systemd checks, and process fallbacks."""
    global _service_status_cache, _service_cache_time
    now = time.time()
    
    if _service_status_cache and (now - _service_cache_time < CACHE_TTL):
        return _service_status_cache

    proxy_state = _get_service_state("proxy", "vigilant-proxy", "mitmdump", "mitmproxy", "vigilant_addon")
    dashboard_state = _get_service_state("dashboard", "vigilant-dashboard", "app.py", "vigilant-dashboard")
    firewall_state = _get_service_state("firewall", "vigilant-firewall", "iptables", "nftables", "ufw")
    dns_state = _get_service_state("dnsmasq", "dnsmasq", "dnsmasq")

    _service_status_cache = {
        "vigilant_proxy": proxy_state,
        "mitmproxy": proxy_state,
        "vigilant_dashboard": dashboard_state,
        "dashboard": dashboard_state,
        "vigilant_firewall": firewall_state,
        "firewall": firewall_state,
        "dnsmasq": dns_state,
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
    config_path = Path("/home/vigilant_admin/vigilant/src/config/netplan-config.yaml")
    if not config_path.exists():
        config_path = Path("/etc/netplan/00-installer-config.yaml")
    
    settings = {
        "upstream_interface": "eth0",
        "distribution_interface": "eth1",
        "lan_address": "192.168.10.1/24"
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
        new_config.append(f"dhcp-range={config.get('dhcp_start', '192.168.10.10')},{config.get('dhcp_end', '192.168.10.50')},12h\n")
        new_config.append(f"dhcp-option=3,{config.get('gateway_ip', '192.168.10.1')}\n")
        new_config.append(f"dhcp-option=6,{config.get('gateway_ip', '192.168.10.1')}\n")
        new_config.append(f"listen-address={config.get('gateway_ip', '192.168.10.1')}\n")
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
                    config.get("distribution_interface", "eth1"): {"addresses": [f"{config.get('gateway_ip', '192.168.10.1')}/24"], "dhcp4": False}
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
    """Retrieve system network interfaces, excluding loopback, virtual, and docker interfaces."""
    iface_names = []
    # Method 1: Use standard library socket (no external dependency, very fast)
    try:
        interfaces = socket.if_nameindex()
        iface_names = [name for index, name in interfaces]
    except Exception as exc:
        app.logger.debug("Failed to get network interfaces via socket: %s", exc)

    # Method 2: Fallback to psutil if socket failed or returned empty
    if not iface_names and psutil is not None:
        try:
            iface_names = list(psutil.net_if_addrs().keys())
        except Exception as exc:
            app.logger.debug("Failed to get network interfaces via psutil: %s", exc)

    # Filter interfaces
    if iface_names:
        filtered = [iface for iface in iface_names if not iface.startswith(('lo', 'veth', 'docker'))]
        if filtered:
            return sorted(filtered)

    # Static fallback if both methods failed to return any non-filtered interfaces
    return ['eth0', 'eth1', 'enp0s3', 'enp1s0']


def _get_network_interfaces() -> list:
    return get_system_interfaces()


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


def load_config(connection: sqlite3.Connection | None = None) -> dict:
    config = dict(CONFIG_DEFAULTS)
    if DB_PATH.exists():
        try:
            if connection:
                if _table_exists(connection, "config_settings"):
                    rows = connection.execute("SELECT key, value FROM config_settings").fetchall()
                    for row in rows:
                        key = str(row[0])
                        if key not in ALLOWED_CONFIG_KEYS:
                            continue
                        try:
                            config[key] = _coerce_config_value(key, row[1])
                        except (TypeError, ValueError):
                            config[key] = CONFIG_DEFAULTS.get(key, row[1])
            else:
                with _open_db() as conn:
                    if _table_exists(conn, "config_settings"):
                        rows = conn.execute("SELECT key, value FROM config_settings").fetchall()
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

    for k in list(config.keys()):
        if k in BOOLEAN_CONFIG_KEYS:
            try:
                config[k] = _coerce_bool(config[k])
            except ValueError:
                config[k] = True
        elif k in INTEGER_CONFIG_KEYS:
            try:
                config[k] = _coerce_int(config[k])
            except ValueError:
                pass
        elif k in FLOAT_CONFIG_KEYS:
            try:
                config[k] = _coerce_float(config[k])
            except ValueError:
                pass
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


def _format_timestamp_fields(timestamp_value) -> tuple[str, str]:
    if isinstance(timestamp_value, (int, float)):
        return (
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp_value)),
            time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(timestamp_value)),
        )
    fallback = str(timestamp_value or "N/A")
    return fallback, fallback


def _decorate_traffic_log_row(row: sqlite3.Row | dict) -> dict:
    log_dict = dict(row) if hasattr(row, "keys") else dict(row)
    formatted_time, iso_timestamp = _format_timestamp_fields(log_dict.get("timestamp"))
    log_dict["flagged"] = bool(log_dict.get("flagged", 0))
    log_dict["formatted_time"] = formatted_time
    log_dict["iso_timestamp"] = iso_timestamp
    return log_dict


def _decorate_throttle_event_row(row: sqlite3.Row | dict) -> dict:
    event = dict(row) if hasattr(row, "keys") else dict(row)
    formatted_time, iso_timestamp = _format_timestamp_fields(event.get("timestamp"))
    action = str(event.get("action") or "THROTTLE_EVENT")
    reason = str(event.get("reason") or "").strip()
    event.update(
        {
            "source": "throttle_events",
            "event_type": "throttle",
            "category": action,
            "flagged": True,
            "formatted_time": formatted_time,
            "iso_timestamp": iso_timestamp,
            "reason": reason or action.replace("_", " ").title(),
        }
    )
    return event


def _collect_policy_blacklist_devices(connection: sqlite3.Connection, managed_prefix: str) -> dict:
    devices = {}
    if not _table_exists(connection, "network_devices"):
        return devices

    rows = connection.execute(
        """
        SELECT ip_address, mac_address, hostname, custom_name, policy, last_seen
        FROM network_devices
        WHERE policy = 'blacklist' AND ip_address LIKE ?
        """,
        (managed_prefix,),
    ).fetchall()

    for row in rows:
        devices[row[0]] = {
            "client_ip": row[0],
            "ip_address": row[0],
            "mac_address": row[1],
            "hostname": row[2] or row[3] or "Unknown",
            "custom_name": row[3],
            "current_rpm": 0,
            "baseline_rpm": 0,
            "is_throttled": True,
            "last_active_domain": "Manual policy",
            "timestamp": row[5] or time.time(),
            "throttle_action": "POLICY_BLACKLIST",
            "reason": "Manual blacklist policy",
            "policy": row[4] or "blacklist",
            "source": "network_devices",
        }
    return devices


def _collect_dynamic_throttle_devices(
    connection: sqlite3.Connection,
    active_since: float,
    managed_prefix: str,
) -> dict:
    devices = {}
    if not _table_exists(connection, "throttle_events"):
        return devices

    select_reason = "reason" if _column_exists(connection, "throttle_events", "reason") else "NULL AS reason"
    rows = connection.execute(
        f"""
        SELECT client_ip, host, rpm_current, rpm_baseline, action, timestamp, {select_reason}
        FROM throttle_events
        WHERE timestamp > ? AND client_ip LIKE ?
        ORDER BY timestamp DESC
        """,
        (active_since, managed_prefix),
    ).fetchall()

    for row in rows:
        client_ip = row[0]
        if not client_ip or client_ip in devices:
            continue
        devices[client_ip] = {
            "client_ip": client_ip,
            "ip_address": client_ip,
            "current_rpm": row[2] or 0,
            "baseline_rpm": row[3] or 0,
            "is_throttled": True,
            "last_active_domain": row[1] or "Unknown",
            "timestamp": row[5],
            "throttle_action": row[4] or "THROTTLE_APPLIED",
            "reason": row[6] or row[4] or "Dynamic throttle triggered",
            "source": "throttle_events",
        }
    return devices


def _apply_device_metadata(connection: sqlite3.Connection, devices: dict) -> None:
    if not devices or not _table_exists(connection, "network_devices"):
        return

    placeholders = ",".join("?" for _ in devices)
    rows = connection.execute(
        f"""
        SELECT ip_address, mac_address, hostname, custom_name, policy, last_seen
        FROM network_devices
        WHERE ip_address IN ({placeholders})
        """,
        tuple(devices.keys()),
    ).fetchall()

    for row in rows:
        entry = devices.get(row[0])
        if not entry:
            continue
        entry["mac_address"] = row[1] or entry.get("mac_address")
        entry["hostname"] = row[2] or row[3] or entry.get("hostname", "Unknown")
        entry["custom_name"] = row[3] or entry.get("custom_name")
        entry["policy"] = row[4] or entry.get("policy", "none")
        entry["last_seen"] = row[5] or entry.get("last_seen")


def _get_current_throttled_devices(connection: sqlite3.Connection, config: dict | None = None) -> list[dict]:
    config = config or load_config(connection)
    managed_prefix = _managed_ip_prefix(config, connection)
    active_since = time.time() - _current_throttle_duration(config, connection)

    devices = _collect_dynamic_throttle_devices(connection, active_since, managed_prefix)
    devices.update({k: v for k, v in _collect_policy_blacklist_devices(connection, managed_prefix).items() if k not in devices})
    _apply_device_metadata(connection, devices)

    throttled_devices = sorted(
        devices.values(),
        key=lambda item: float(item.get("timestamp") or 0),
        reverse=True,
    )

    for device in throttled_devices:
        ts = device.get("timestamp")
        formatted_time, iso_timestamp = _format_timestamp_fields(ts)
        device["formatted_time"] = formatted_time
        device["timestamp"] = iso_timestamp

    return throttled_devices


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
        throttled_devices = []
        managed_prefix = ""
        config = None
        
        if DB_PATH.exists():
            with _open_db() as connection:
                config = load_config(connection)
                managed_prefix = _managed_ip_prefix(config, connection)
                throttled_devices = _get_current_throttled_devices(connection, config)
                if _table_exists(connection, "traffic_log"):
                    where_clauses = [_l7_traffic_filter_sql()]
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
                    blocked_reqs = connection.execute(
                        f"SELECT COUNT(*) FROM traffic_log WHERE {_l7_traffic_filter_sql()} AND flagged = 1"
                    ).fetchone()[0] or 0
                    
                    # Active clients (last 24 hours) for managed subnet only
                    window_start = int(time.time()) - 86400
                    active_clients = connection.execute(
                        f"""
                        SELECT COUNT(DISTINCT client_ip) FROM traffic_log
                        WHERE {_l7_traffic_filter_sql()} AND timestamp > ? AND client_ip LIKE ?
                        """,
                        (window_start, managed_prefix),
                    ).fetchone()[0] or 0
                    
                    # Category breakdown
                    category_rows = connection.execute(
                        f"""
                        SELECT LOWER(TRIM(category)) AS normalized_category, COUNT(*) AS category_count
                        FROM traffic_log
                        WHERE {_l7_traffic_filter_sql()} AND category IS NOT NULL
                          AND LOWER(TRIM(category)) IN ('educational', 'productive', 'distracting', 'harmful')
                        GROUP BY LOWER(TRIM(category))
                        """
                    ).fetchall()
                    
                    raw_categories = {row[0]: row[1] for row in category_rows}
                    formatted_counts = [{"category": cat, "count": raw_categories.get(cat.lower(), 0)} for cat in TRAFFIC_CATEGORIES]
                    
                    denom = sum(raw_categories.values())
                    if denom > 0:
                        category_percentages = {cat: round((raw_categories.get(cat.lower(), 0) / denom) * 100, 1) for cat in TRAFFIC_CATEGORIES}

                    # Paginated Traffic Logs
                    log_query = (
                        "SELECT timestamp, client_ip, host, category, flagged "
                        f"FROM traffic_log WHERE {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
                    )
                    log_params = params + [per_page, offset]
                    
                    rows = connection.execute(log_query, tuple(log_params)).fetchall()
                    formatted_recent = [_format_recent_log_entry(dict(r)) for r in rows]

        # Calculate Total Pages Safely
        total_pages = max(1, (total_reqs + per_page - 1) // per_page) if total_reqs > 0 else 1
        
        system_metrics = _system_metrics()
        network_config = _get_network_config()
        network_config["available_interfaces"] = get_system_interfaces()

        return jsonify({
            "total": total_reqs,
            "flagged": blocked_reqs,
            "clients": active_clients,
            "counts": formatted_counts,
            "percentage_metrics": category_percentages,
            "recent": formatted_recent,
            "throttles": throttled_devices,
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
    return render_template("dashboard.html", proxy_active=proxy_active, time=time)


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
        "mitmproxy": services_state.get("mitmproxy", "offline"),
        "dnsmasq": services_state.get("dnsmasq", "offline"),
        "firewall": services_state.get("firewall", "offline"),
        "dashboard": services_state.get("dashboard", "offline"),
    }

    total_connected = 0
    throttled_count = 0
    recent_alerts = 0
    recent_entries = []
    dhcp_allocations = []
    config = None
    managed_prefix = ""
    throttled_devices = []
    
    if DB_PATH.exists():
        try:
            with _open_db() as conn:
                config = load_config(conn)
                managed_prefix = _managed_ip_prefix(config, conn)
                window_start = int(time.time()) - 86400
                active_since = time.time() - _current_throttle_duration(config, conn)
                throttled_devices = _get_current_throttled_devices(conn, config)
                throttled_count = len(throttled_devices)

                if _table_exists(conn, "traffic_log"):
                    row = conn.execute(
                        f"""
                        SELECT COUNT(DISTINCT client_ip) FROM traffic_log
                        WHERE {_l7_traffic_filter_sql()} AND timestamp > ? AND client_ip LIKE ?
                        """,
                        (window_start, managed_prefix),
                    ).fetchone()
                    total_connected = int(row[0] or 0) if row else 0
                    
                    l7_alerts = conn.execute(
                        f"SELECT COUNT(*) FROM traffic_log WHERE {_l7_traffic_filter_sql()} AND flagged = 1 AND timestamp > ?",
                        (window_start,),
                    ).fetchone()
                    recent_alerts = int(l7_alerts[0] or 0) if l7_alerts else 0

                    if _table_exists(conn, "throttle_events"):
                        throttle_alerts = conn.execute(
                            "SELECT COUNT(*) FROM throttle_events WHERE timestamp > ?",
                            (active_since,),
                        ).fetchone()
                        recent_alerts += int(throttle_alerts[0] or 0) if throttle_alerts else 0
                    
                    rows = conn.execute(
                        f"""
                        SELECT timestamp, client_ip, host, category, flagged
                        FROM traffic_log
                        WHERE {_l7_traffic_filter_sql()}
                        ORDER BY timestamp DESC LIMIT 10
                        """
                    ).fetchall()
                    recent_entries = [_format_recent_log_entry(dict(r)) for r in rows]
                
                if _table_exists(conn, "network_devices"):
                    device_rows = conn.execute(
                        """
                        SELECT ip_address, mac_address, hostname, custom_name, policy, last_seen
                        FROM network_devices
                        WHERE ip_address LIKE ?
                        ORDER BY last_seen DESC
                        """,
                        (managed_prefix,),
                    ).fetchall()
                    for row in device_rows:
                        dhcp_allocations.append({
                            "ip_address": row[0], "mac_address": row[1],
                            "hostname": row[2] or row[3] or "Unknown",
                            "custom_name": row[3],
                            "policy": row[4] or "none",
                            "last_seen": row[5],
                        })
        except sqlite3.Error as e:
            app.logger.warning(f"DB Error in summary: {e}")

    if config is None:
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
        "devices": {"total_connected": total_connected, "throttled_count": throttled_count, "throttled_devices": throttled_devices},
        "logs": {"recent_alerts": recent_alerts, "recent_entries": recent_entries},
        "active_config": {
            "nlp_enabled": nlp_enabled,
            "network_velocity_preset": net_preset,
            "physical_scroll_preset": scroll_preset,
            "theme_mode": theme_mode,
            "sni_filtering_enabled": _coerce_bool(config.get("sni_filtering_enabled", "true")),
            "throttle_enabled": _coerce_bool(config.get("throttle_enabled", "true")),
            "throttle_rate": config.get("throttle_rate", CONFIG_DEFAULTS["throttle_rate"]),
            "throttle_duration": _current_throttle_duration(config),
        },
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
            if _table_exists(connection, "throttle_events"):
                connection.execute("DELETE FROM throttle_events")
            connection.commit()
            try:
                connection.execute("VACUUM")
            except sqlite3.Error:
                pass
        return jsonify({"status": "success", "message": "Traffic and throttling logs cleared successfully"})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route('/api/logs/traffic', methods=["GET"])
def get_traffic_logs():
    """Fetch traffic logs with optional filtering and pagination support."""
    try:
        # Parse query parameters
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        client_ip = request.args.get('client_ip', '').strip()
        category = request.args.get('category', '').strip()
        search = request.args.get('search', '').strip()
        status = request.args.get('status', '').strip()  # 'flagged' or 'allowed'
        since_id = request.args.get('since_id', type=int)  # Get logs newer than this ID
        since_timestamp = request.args.get('since_timestamp', type=float)  # Get logs newer than this timestamp
        
        # Validate and sanitize parameters
        limit = max(1, min(limit, 1000))  # Cap at 1000 to prevent excessive loads
        offset = max(0, offset)
        
        where_clauses = [_l7_traffic_filter_sql()]
        params = []
        
        # Add filters
        if client_ip:
            where_clauses.append("client_ip = ?")
            params.append(client_ip)

        if category and category.upper() != "ALL":
            where_clauses.append("category = ?")
            params.append(category)

        if search:
            where_clauses.append("(host LIKE ? OR path LIKE ? OR client_ip LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        
        if status.lower() == 'flagged':
            where_clauses.append("flagged = 1")
        elif status.lower() == 'allowed':
            where_clauses.append("flagged = 0")
        
        if since_id:
            where_clauses.append("id > ?")
            params.append(since_id)
        
        if since_timestamp:
            where_clauses.append("timestamp > ?")
            params.append(since_timestamp)
        
        where_sql = " AND ".join(where_clauses)
        
        logs = []
        total_count = 0
        
        if DB_PATH.exists():
            with _open_db() as connection:
                if _table_exists(connection, "traffic_log"):
                    # Get total count for pagination
                    count_query = f"SELECT COUNT(*) FROM traffic_log WHERE {where_sql}"
                    total_count = connection.execute(count_query, tuple(params)).fetchone()[0] or 0
                    
                    # Fetch logs with pagination
                    log_query = f"""
                        SELECT id, timestamp, client_ip, host, path, method, category, flagged, entities
                        FROM traffic_log
                        WHERE {where_sql}
                        ORDER BY timestamp DESC
                        LIMIT ? OFFSET ?
                    """
                    log_params = params + [limit, offset]
                    
                    rows = connection.execute(log_query, tuple(log_params)).fetchall()
                    logs = [_decorate_traffic_log_row(row) for row in rows]
        
        return jsonify({
            "status": "success",
            "logs": logs,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total_count": total_count,
                "has_more": (offset + limit) < total_count
            }
        })
    except sqlite3.Error as e:
        app.logger.error("Database error in get_traffic_logs: %s", e, exc_info=True)
        return jsonify({"error": "Database error", "details": str(e)}), 500
    except Exception as e:
        app.logger.error("Error in get_traffic_logs: %s", e, exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/api/logs/traffic/refresh', methods=["GET"])
def refresh_traffic_logs():
    """Lightweight endpoint for real-time log refresh using since_id or since_timestamp."""
    try:
        since_id = request.args.get('since_id', type=int)
        since_timestamp = request.args.get('since_timestamp', type=float)
        limit = request.args.get('limit', 50, type=int)
        
        limit = max(1, min(limit, 500))  # Cap at 500 for refresh endpoint
        
        where_clauses = [_l7_traffic_filter_sql()]
        params = []
        
        if since_id:
            where_clauses.append("id > ?")
            params.append(since_id)
        elif since_timestamp:
            where_clauses.append("timestamp > ?")
            params.append(since_timestamp)
        else:
            # If no filter provided default to last 5 minutes
            where_clauses.append("timestamp > ?")
            params.append(time.time() - 300)
        
        where_sql = " AND ".join(where_clauses)
        
        logs = []
        
        if DB_PATH.exists():
            with _open_db() as connection:
                if _table_exists(connection, "traffic_log"):
                    log_query = f"""
                        SELECT id, timestamp, client_ip, host, path, method, category, flagged, entities
                        FROM traffic_log
                        WHERE {where_sql}
                        ORDER BY timestamp DESC
                        LIMIT ?
                    """
                    log_params = params + [limit]
                    
                    rows = connection.execute(log_query, tuple(log_params)).fetchall()
                    logs = [_decorate_traffic_log_row(row) for row in rows]
        
        return jsonify({
            "status": "success",
            "logs": logs,
            "count": len(logs),
            "refresh_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        })
    except sqlite3.Error as e:
        app.logger.error("Database error in refresh_traffic_logs: %s", e, exc_info=True)
        return jsonify({"error": "Database error", "details": str(e)}), 500
    except Exception as e:
        app.logger.error("Error in refresh_traffic_logs: %s", e, exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route('/api/logs/throttling', methods=["GET"])
def get_throttling_logs():
    """Fetch L4 passthrough tracking and behavioral throttling events."""
    try:
        limit = max(1, min(request.args.get('limit', 100, type=int), 1000))
        offset = max(0, request.args.get('offset', 0, type=int))
        client_ip = request.args.get('client_ip', '').strip()
        search = request.args.get('search', '').strip()
        since_timestamp = request.args.get('since_timestamp', type=float)

        throttle_logs = []
        tracking_logs = []

        if DB_PATH.exists():
            with _open_db() as connection:
                if _table_exists(connection, "throttle_events"):
                    select_reason = "reason" if _column_exists(connection, "throttle_events", "reason") else "NULL AS reason"
                    where_clauses = ["1=1"]
                    params = []
                    if client_ip:
                        where_clauses.append("client_ip = ?")
                        params.append(client_ip)
                    if search:
                        where_clauses.append("(host LIKE ? OR action LIKE ? OR reason LIKE ? OR client_ip LIKE ?)")
                        params.extend([f"%{search}%", f"%{search}%", f"%{search}%", f"%{search}%"])
                    if since_timestamp:
                        where_clauses.append("timestamp > ?")
                        params.append(since_timestamp)

                    rows = connection.execute(
                        f"""
                        SELECT id, timestamp, client_ip, host, rpm_current, rpm_baseline, action, {select_reason}
                        FROM throttle_events
                        WHERE {" AND ".join(where_clauses)}
                        ORDER BY timestamp DESC
                        """,
                        tuple(params),
                    ).fetchall()
                    throttle_logs = [_decorate_throttle_event_row(row) for row in rows]

                if _table_exists(connection, "traffic_log"):
                    where_clauses = [_l4_tracking_filter_sql()]
                    params = []
                    if client_ip:
                        where_clauses.append("client_ip = ?")
                        params.append(client_ip)
                    if search:
                        where_clauses.append("(host LIKE ? OR path LIKE ? OR client_ip LIKE ?)")
                        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
                    if since_timestamp:
                        where_clauses.append("timestamp > ?")
                        params.append(since_timestamp)

                    rows = connection.execute(
                        f"""
                        SELECT id, timestamp, client_ip, host, path, method, category, flagged, entities
                        FROM traffic_log
                        WHERE {" AND ".join(where_clauses)}
                        ORDER BY timestamp DESC
                        """,
                        tuple(params),
                    ).fetchall()
                    tracking_logs = []
                    for row in rows:
                        event = _decorate_traffic_log_row(row)
                        event["source"] = "traffic_log"
                        event["event_type"] = "l4_tracking"
                        tracking_logs.append(event)

        merged_logs = sorted(
            throttle_logs + tracking_logs,
            key=lambda item: float(item.get("timestamp") or 0),
            reverse=True,
        )
        total_count = len(merged_logs)
        page_logs = merged_logs[offset:offset + limit]

        return jsonify({
            "status": "success",
            "logs": page_logs,
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total_count": total_count,
                "has_more": (offset + limit) < total_count,
            },
        })
    except sqlite3.Error as exc:
        app.logger.error("Database error in get_throttling_logs: %s", exc, exc_info=True)
        return jsonify({"error": "Database error", "details": str(exc)}), 500
    except Exception as exc:
        app.logger.error("Error in get_throttling_logs: %s", exc, exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(exc)}), 500


@app.route('/api/logs/export')
def export_logs():
    """Export L7 traffic logs or throttling/L4 tracking logs to CSV."""
    try:
        export_type = str(request.args.get("type", "traffic")).strip().lower() or "traffic"
        text_stream = io.StringIO()
        cw = csv.writer(text_stream)
        download_name = "traffic_logs_export.csv"

        with _open_db() as connection:
            if export_type == "throttling":
                cw.writerow(['ID', 'Time', 'Source', 'Client IP', 'Domain', 'Action', 'Reason', 'Current RPM', 'Baseline RPM'])
                throttle_rows = []
                if _table_exists(connection, "throttle_events"):
                    select_reason = "reason" if _column_exists(connection, "throttle_events", "reason") else "NULL AS reason"
                    rows = connection.execute(
                        f"""
                        SELECT id, timestamp, client_ip, host, rpm_current, rpm_baseline, action, {select_reason}
                        FROM throttle_events
                        ORDER BY timestamp DESC
                        """
                    ).fetchall()
                    throttle_rows.extend(_decorate_throttle_event_row(row) for row in rows)

                if _table_exists(connection, "traffic_log"):
                    rows = connection.execute(
                        f"""
                        SELECT id, timestamp, client_ip, host, path, method, category, flagged, entities
                        FROM traffic_log
                        WHERE {_l4_tracking_filter_sql()}
                        ORDER BY timestamp DESC
                        """
                    ).fetchall()
                    for row in rows:
                        event = _decorate_traffic_log_row(row)
                        event["source"] = "traffic_log"
                        event["event_type"] = "l4_tracking"
                        event["reason"] = str(event.get("category") or "").replace("_", " ").title()
                        throttle_rows.append(event)

                for event in sorted(throttle_rows, key=lambda item: float(item.get("timestamp") or 0), reverse=True):
                    cw.writerow([
                        event.get("id", ""),
                        event.get("formatted_time", "N/A"),
                        event.get("source", ""),
                        event.get("client_ip", "0.0.0.0"),
                        event.get("host", "unknown"),
                        event.get("action") or event.get("category", ""),
                        str(event.get("reason", "")).replace('\n', ' ').replace('"', "'"),
                        event.get("rpm_current", ""),
                        event.get("rpm_baseline", ""),
                    ])
                download_name = "throttling_logs_export.csv"
            else:
                cw.writerow(['ID', 'Time', 'Client IP', 'Domain', 'Path', 'Method', 'Category', 'Status', 'Entities'])
                rows = []
                if _table_exists(connection, "traffic_log"):
                    rows = connection.execute(
                        f"""
                        SELECT id, timestamp, client_ip, host, path, method, category, flagged, entities
                        FROM traffic_log
                        WHERE {_l7_traffic_filter_sql()}
                        ORDER BY timestamp DESC
                        """
                    ).fetchall()

                for log in (_decorate_traffic_log_row(row) for row in rows):
                    entities = str(log.get('entities') or '').replace('\n', ' ').replace('"', "'")
                    status = 'Blocked' if log.get('flagged') else 'Allowed'
                    cw.writerow([
                        log.get('id', ''),
                        log.get('formatted_time', 'N/A'),
                        log.get('client_ip', '0.0.0.0'),
                        log.get('host', 'unknown'),
                        log.get('path', ''),
                        log.get('method', ''),
                        log.get('category', 'Unclassified'),
                        status,
                        entities,
                    ])

        byte_stream = io.BytesIO(text_stream.getvalue().encode('utf-8'))
        text_stream.close()
        
        return send_file(
            byte_stream,
            as_attachment=True,
            download_name=download_name,
            mimetype='text/csv'
        )
    except sqlite3.Error as e:
        app.logger.error("Database error during CSV export: %s", e, exc_info=True)
        return jsonify({"error": "Database error during export", "details": str(e)}), 500
    except Exception as e:
        app.logger.error("Failed to export logs: %s", e, exc_info=True)
        return jsonify({"error": "Failed to export logs", "details": str(e)}), 500


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
        _signal_rule_cache_reload()
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
        _signal_rule_cache_reload()
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
        _signal_rule_cache_reload()
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
            _signal_rule_cache_reload()
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
                _signal_rule_cache_reload()
                return jsonify({"success": True}), 200
            return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config/behavioral", methods=["GET", "POST"])
def handle_behavioral_config():
    if request.method == "GET":
        with _open_db() as conn:
            config = load_config(connection=conn)
            
            try:
                custom_net = config.get("network_velocity_custom")
                if custom_net is not None:
                    net_custom = int(float(custom_net))
                else:
                    threshold_val = float(config.get("network_velocity_threshold", 1.5))
                    net_custom = int(threshold_val * 100)
            except (TypeError, ValueError):
                net_custom = 150

            try:
                custom_scroll = config.get("physical_scroll_custom")
                if custom_scroll is not None:
                    scroll_custom = int(float(custom_scroll))
                else:
                    scroll_custom = int(float(config.get("physical_scroll_threshold", 75)))
            except (TypeError, ValueError):
                scroll_custom = 75

            return jsonify({
                "network_velocity_preset": config.get("network_velocity_preset", "Medium"),
                "network_velocity_custom": net_custom,
                "physical_scroll_preset": config.get("physical_scroll_preset", "Medium"),
                "physical_scroll_custom": scroll_custom,
                "sni_filtering_enabled": _coerce_bool(config.get("sni_filtering_enabled", "true")),
                "throttle_enabled": _coerce_bool(config.get("throttle_enabled", "true")),
                "throttle_rate": int(config.get("throttle_rate", CONFIG_DEFAULTS["throttle_rate"])),
                "throttle_duration": _current_throttle_duration(config, connection=conn),
            })
            
    # POST / PUT request handling
    payload = request.get_json(silent=True) or {}
    
    # When preset changes, update the corresponding threshold value
    if "network_velocity_preset" in payload:
        preset = payload["network_velocity_preset"]
        if preset == "High":
            payload["network_velocity_threshold"] = "1.1"
        elif preset == "Medium":
            payload["network_velocity_threshold"] = "1.5"
        elif preset == "Low":
            payload["network_velocity_threshold"] = "2.0"
    
    if "physical_scroll_preset" in payload:
        preset = payload["physical_scroll_preset"]
        if preset == "High":
            payload["physical_scroll_threshold"] = "40"
        elif preset == "Medium":
            payload["physical_scroll_threshold"] = "75"
        elif preset == "Low":
            payload["physical_scroll_threshold"] = "120"
    
    # When custom value changes, update the threshold
    if "network_velocity_custom" in payload:
        try:
            payload["network_velocity_threshold"] = str(float(payload["network_velocity_custom"]) / 100.0)
        except (TypeError, ValueError):
            payload["network_velocity_threshold"] = "1.5"
    
    if "physical_scroll_custom" in payload:
        payload["physical_scroll_threshold"] = str(payload["physical_scroll_custom"])
    
    save_config(payload)
    return jsonify({"status": "success"})

@app.route("/api/devices", methods=["GET"])
def get_devices():
    return jsonify({"devices": _discover_network_devices()})


@app.route("/api/devices/active", methods=["GET"])
def get_active_devices():
    """Get currently active devices from traffic_log (last 1 minute)"""
    try:
        active_devices = []
        managed_prefix = _managed_ip_prefix()
        
        if DB_PATH.exists():
            with _open_db() as conn:
                window_start = time.time() - 60
                if _table_exists(conn, "traffic_log"):
                    rows = conn.execute(
                        """
                        SELECT DISTINCT client_ip, MAX(timestamp) as last_seen
                        FROM traffic_log
                        WHERE client_ip LIKE ? AND timestamp > ?
                        GROUP BY client_ip
                        ORDER BY last_seen DESC
                        """,
                        (managed_prefix, window_start)
                    ).fetchall()
                    
                    for row in rows:
                        ip_address = row[0]
                        last_seen = row[1]
                        
                        # Try to get device info from network_devices
                        hostname = "Unknown Device"
                        mac_address = "—"
                        if _table_exists(conn, "network_devices"):
                            device_row = conn.execute(
                                "SELECT hostname, custom_name, mac_address FROM network_devices WHERE ip_address = ?",
                                (ip_address,)
                            ).fetchone()
                            if device_row:
                                hostname = device_row[0] or device_row[1] or "Unknown Device"
                                mac_address = device_row[2] or "—"
                        
                        active_devices.append({
                            "ip_address": ip_address,
                            "hostname": hostname,
                            "mac_address": mac_address,
                            "last_seen": last_seen
                        })
        
        return jsonify({"devices": active_devices})
    except Exception as exc:
        app.logger.error("Failed to get active devices: %s", exc)
        return jsonify({"devices": []})


@app.route("/api/devices/throttled", methods=["GET"])
def get_throttled_devices():
    """Get list of currently throttled devices with their metrics."""
    try:
        if not DB_PATH.exists():
            return jsonify({
                "status": "success",
                "throttled_devices": []
            })
        
        with _open_db() as connection:
            config = load_config(connection)
            throttled_devices = _get_current_throttled_devices(connection, config)
        
        return jsonify({
            "status": "success",
            "throttled_devices": throttled_devices
        })
    except sqlite3.Error as e:
        app.logger.error("Database error in get_throttled_devices: %s", e, exc_info=True)
        return jsonify({"error": "Database error", "details": str(e)}), 500
    except Exception as e:
        app.logger.error("Error in get_throttled_devices: %s", e, exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/api/devices/policy", methods=["POST"])
def set_device_policy():
    data = request.json or {}
    ip_address = data.get("ip_address")
    mac_address = data.get("mac_address", "")
    policy = data.get("policy", "standard")
    custom_name = data.get("custom_name", "")

    try:
        with get_db_connection() as conn:
            if not ip_address and mac_address:
                existing_row = conn.execute(
                    "SELECT ip_address FROM network_devices WHERE mac_address = ? ORDER BY last_seen DESC LIMIT 1",
                    (mac_address,),
                ).fetchone()
                if existing_row:
                    ip_address = existing_row[0]

            if not ip_address:
                return jsonify({"error": "ip_address is required"}), 400

            conn.execute('''
                INSERT INTO network_devices (ip_address, mac_address, policy, custom_name, first_seen, last_seen, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    policy=excluded.policy,
                    custom_name=COALESCE(NULLIF(excluded.custom_name, ''), network_devices.custom_name),
                    mac_address=COALESCE(NULLIF(excluded.mac_address, ''), network_devices.mac_address),
                    updated_at=excluded.updated_at
            ''', (ip_address, mac_address, policy, custom_name, time.time(), time.time(), time.time()))
            conn.commit()
        return jsonify({"status": "success", "message": "Device policy updated successfully"})
    except Exception as e:
        app.logger.error("Error setting device policy: %s", e)
        return jsonify({"error": "Failed to update device policy", "details": str(e)}), 500


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
            _signal_rule_cache_reload()
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
        config = load_config()
        interface_name = config.get("distribution_interface") or _get_network_config().get("distribution_interface") or GATEWAY_INTERFACE
        throughput = _get_interface_throughput(interface_name)
        return jsonify({
            "interface": interface_name,
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


@app.route("/api/nerve-center/metrics", methods=["GET"])
def get_nerve_center_metrics():
    """Get accurate metrics for VIGILANT Nerve Center display"""
    try:
        active_count = 0
        throttled_count = 0
        config = load_config()
        managed_prefix = _managed_ip_prefix(config)
        
        if DB_PATH.exists():
            with _open_db() as conn:
                window_start = time.time() - 60
                if _table_exists(conn, "traffic_log"):
                    row = conn.execute(
                        f"""
                        SELECT COUNT(DISTINCT client_ip) FROM traffic_log
                        WHERE {_l7_traffic_filter_sql()} AND client_ip LIKE ? AND timestamp > ?
                        """,
                        (managed_prefix, window_start)
                    ).fetchone()
                    active_count = int(row[0] or 0) if row else 0
                throttled_count = len(_get_current_throttled_devices(conn, config))
        
        nlp_enabled = _coerce_bool(config.get("nlp_enabled", "true"))
        nlp_status = "Active" if nlp_enabled else "Idle"
        
        return jsonify({
            "active_count": active_count,
            "throttled_count": throttled_count,
            "nlp_status": nlp_status
        })
    except Exception as exc:
        app.logger.error("Failed to get nerve center metrics: %s", exc)
        return jsonify({
            "active_count": 0,
            "throttled_count": 0,
            "nlp_status": "Unknown"
        })


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


if __name__ == "__main__":
    init_db()
    init_config_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
