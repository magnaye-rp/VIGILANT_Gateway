import sqlite3
import time
import json
import os
import psutil
import threading
from flask import Flask, render_template, jsonify, request, send_from_directory
from datetime import datetime, timedelta

app = Flask(__name__, static_folder='static')
DB_PATH = "/home/vigilant_admin/vigilant/logs/vigilant.db"
CONFIG_PATH = "/home/vigilant_admin/vigilant/config.json"

# ─── Database Initialization ─── 
def init_config_db():
    """Initialize config table in SQLite"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS config_settings (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at REAL
            )
        """)
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Config DB init failed: {e}")

# ─── Config Management ─── 
def load_config():
    """Load configuration from database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT key, value FROM config_settings")
        rows = c.fetchall()
        conn.close()
        
        config = {}
        for key, value in rows:
            # Try to parse JSON values
            try:
                config[key] = json.loads(value)
            except:
                config[key] = value
        return config
    except:
        return get_default_config()

def get_default_config():
    """Return default configuration"""
    return {
        "gateway_ip": "192.168.10.1",
        "dhcp_start": "192.168.10.10",
        "dhcp_end": "192.168.10.50",
        "wan_interface": "enp0s5",
        "lan_interface": "enp0s6",
        "dns_servers": ["8.8.8.8", "8.8.4.4"],
        "nlp_model": "en_core_web_sm",
        "nlp_mode": "balanced",
        "block_harmful": True,
        "block_distracting": False,
        "throttle_enabled": True,
        "velocity_threshold": 30,
        "throttle_duration": 60,
        "throttle_rate": 256,
        "target_domains": [
            "facebook.com", "twitter.com", "x.com", "tiktok.com",
            "instagram.com", "reddit.com", "youtube.com", "twitch.tv"
        ],
        "https_enabled": True,
        "log_retention": 30,
    }

def save_config(config):
    """Save configuration to database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        for key, value in config.items():
            c.execute(
                "INSERT OR REPLACE INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)",
                (key, json.dumps(value) if not isinstance(value, str) else value, time.time())
            )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERROR] Config save failed: {e}")
        return False

# ─── Database Queries ─── 
def query_db(sql, args=()):
    """Execute SELECT query and return results as list of dicts"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except Exception as e:
        print(f"[ERROR] Query failed: {e}")
        return []

# ─── System Monitoring ─── 
def get_system_stats():
    """Get current system resource usage"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Calculate uptime
        boot_time = psutil.boot_time()
        uptime_seconds = time.time() - boot_time
        uptime_hours = int(uptime_seconds / 3600)
        uptime_minutes = int((uptime_seconds % 3600) / 60)
        
        return {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent,
            "memory_mb": memory.used / 1024 / 1024,
            "disk_percent": disk.percent,
            "uptime": f"{uptime_hours}h {uptime_minutes}m",
            "timestamp": time.time()
        }
    except Exception as e:
        print(f"[ERROR] System stats failed: {e}")
        return {}

# ─── Routes: Dashboard & Stats ─── 
@app.route("/")
def dashboard():
    """Serve the modern dashboard"""
    return render_template("pages/dashboard.html")

@app.route("/system")
def system():
    """System status page"""
    return render_template("pages/system.html")

@app.route("/network")
def network():
    """Network overview page"""
    return render_template("pages/network.html")

@app.route("/interfaces")
def interfaces():
    """Network interfaces page"""
    return render_template("pages/interfaces.html")

@app.route("/firewall")
def firewall():
    """Firewall configuration page"""
    return render_template("pages/firewall.html")

@app.route("/dhcp")
def dhcp():
    """DHCP configuration page"""
    return render_template("pages/dhcp.html")

@app.route("/dns")
def dns():
    """DNS configuration page"""
    return render_template("pages/dns.html")

@app.route("/routing")
def routing():
    """Routing table page"""
    return render_template("pages/routing.html")

@app.route("/vpn")
def vpn():
    """VPN configuration page"""
    return render_template("pages/vpn.html")

@app.route("/ssh")
def ssh():
    """SSH configuration page"""
    return render_template("pages/ssh.html")

@app.route("/users")
def users():
    """User management page"""
    return render_template("pages/users.html")

@app.route("/logs")
def logs():
    """System logs page"""
    return render_template("pages/logs.html")

@app.route("/services")
def services():
    """Service management page"""
    return render_template("pages/services.html")

@app.route("/storage")
def storage():
    """Storage management page"""
    return render_template("pages/storage.html")

@app.route("/updates")
def updates():
    """System updates page"""
    return render_template("pages/updates.html")

@app.route("/backup")
def backup():
    """Backup and restore page"""
    return render_template("pages/backup.html")

@app.route("/monitoring")
def monitoring():
    """Monitoring page"""
    return render_template("pages/monitoring.html")

@app.route("/security")
def security():
    """Security settings page"""
    return render_template("pages/security.html")

@app.route("/settings")
def settings():
    """Settings page"""
    return render_template("pages/settings.html")

@app.route("/api/stats")
def stats():
    """Get traffic statistics and recent events"""
    try:
        counts = query_db("""
            SELECT category, COUNT(*) as count
            FROM traffic_log
            GROUP BY category
            ORDER BY count DESC
        """)
        
        recent = query_db("""
            SELECT 
                strftime('%Y-%m-%d %H:%M:%S', datetime(timestamp, 'unixepoch')) as time,
                client_ip, host, category, flagged
            FROM traffic_log
            ORDER BY id DESC LIMIT 50
        """)
        
        throttles = query_db("""
            SELECT 
                strftime('%Y-%m-%d %H:%M:%S', datetime(timestamp, 'unixepoch')) as time,
                client_ip, host,
                ROUND(rpm_current, 1) as rpm,
                ROUND(rpm_baseline, 1) as baseline,
                action
            FROM throttle_events
            ORDER BY id DESC LIMIT 20
        """)
        
        total = query_db("SELECT COUNT(*) as n FROM traffic_log")
        flagged = query_db("SELECT COUNT(*) as n FROM traffic_log WHERE flagged=1")
        clients = query_db("SELECT COUNT(DISTINCT client_ip) as n FROM traffic_log")
        
        return jsonify({
            "counts": counts,
            "recent": recent,
            "throttles": throttles,
            "total": total[0]["n"] if total else 0,
            "flagged": flagged[0]["n"] if flagged else 0,
            "clients": clients[0]["n"] if clients else 0,
        })
    except Exception as e:
        print(f"[ERROR] Stats endpoint failed: {e}")
        return jsonify({"error": str(e)}), 500

# ─── Routes: Configuration Management ─── 
@app.route("/api/config", methods=["GET", "POST"])
def config():
    """Get or save configuration"""
    if request.method == "GET":
        return jsonify(load_config())
    
    elif request.method == "POST":
        try:
            data = request.get_json()
            config = load_config()
            config.update(data)
            
            if save_config(config):
                return jsonify({"status": "success", "message": "Configuration saved"})
            else:
                return jsonify({"error": "Failed to save config"}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route("/api/settings", methods=["POST"])
def settings():
    """Update advanced settings"""
    try:
        data = request.get_json()
        config = load_config()
        config.update(data)
        
        if save_config(config):
            return jsonify({"status": "success", "message": "Settings saved"})
        else:
            return jsonify({"error": "Failed to save settings"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/defaults", methods=["POST"])
def reset_to_defaults():
    """Reset configuration to factory defaults"""
    try:
        default_config = get_default_config()
        if save_config(default_config):
            return jsonify({"status": "success", "message": "Reset to defaults"})
        else:
            return jsonify({"error": "Failed to reset"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ─── Routes: Log Management ─── 
@app.route("/api/clear", methods=["POST"])
def clear_logs():
    """Clear all traffic and throttle logs"""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM traffic_log")
            conn.execute("DELETE FROM throttle_events")
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/reset", methods=["POST"])
def reset_system():
    """Complete system reset to factory defaults"""
    try:
        # Clear logs
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM traffic_log")
            conn.execute("DELETE FROM throttle_events")
            conn.execute("DELETE FROM config_settings")
        
        # Reset to defaults
        default_config = get_default_config()
        save_config(default_config)
        
        return jsonify({"status": "reset"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/traffic", methods=["GET"])
def traffic_log():
    """Get traffic log with optional filters"""
    try:
        client_filter = request.args.get('client', '')
        domain_filter = request.args.get('domain', '')
        category_filter = request.args.get('category', '')
        
        query = "SELECT * FROM traffic_log WHERE 1=1"
        params = []
        
        if client_filter:
            query += " AND client_ip LIKE ?"
            params.append(f"%{client_filter}%")
        
        if domain_filter:
            query += " AND host LIKE ?"
            params.append(f"%{domain_filter}%")
        
        if category_filter:
            query += " AND category = ?"
            params.append(category_filter)
        
        query += " ORDER BY id DESC LIMIT 100"
        
        results = query_db(query, params)
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Routes: System Monitoring ─── 
@app.route("/api/system")
def system_stats():
    """Get system resource usage statistics"""
    try:
        stats = get_system_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/services")
def services_status():
    """Get status of VIGILANT services"""
    try:
        # This would integrate with systemctl in production
        return jsonify({
            "proxy": {
                "name": "vigilant-proxy",
                "status": "running",
                "uptime": "12h 45m"
            },
            "dashboard": {
                "name": "vigilant-dashboard",
                "status": "running",
                "uptime": "12h 45m"
            },
            "firewall": {
                "name": "vigilant-firewall",
                "status": "active",
                "uptime": "12h 45m"
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Routes: Backup & Export ─── 
@app.route("/api/export", methods=["GET"])
def export_config():
    """Export configuration as JSON"""
    try:
        config = load_config()
        response = jsonify(config)
        response.headers["Content-Disposition"] = "attachment;filename=vigilant-config.json"
        return response
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/import", methods=["POST"])
def import_config():
    """Import configuration from JSON"""
    try:
        data = request.get_json()
        if save_config(data):
            return jsonify({"status": "success"})
        else:
            return jsonify({"error": "Failed to import"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ─── Error Handlers ─── 
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Server error"}), 500

# ─── Application Initialization ─── 
if __name__ == "__main__":
    # Initialize database
    init_config_db()
    
    # Load or create default config
    if not load_config():
        save_config(get_default_config())
    
    # Run Flask app
    app.run(host="0.0.0.0", port=5000, debug=False)