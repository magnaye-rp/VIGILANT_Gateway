import sqlite3
import time
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
DB_PATH = "/home/vigilant_admin/vigilant/logs/vigilant.db"

def query_db(sql, args=()):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, args).fetchall()]

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/stats")
def stats():
    counts = query_db("""
        SELECT category, COUNT(*) as count
        FROM traffic_log
        GROUP BY category
        ORDER BY count DESC
    """)
    recent = query_db("""
        SELECT datetime(timestamp,'unixepoch') as time,
               client_ip, host, category, flagged
        FROM traffic_log
        ORDER BY id DESC LIMIT 50
    """)
    throttles = query_db("""
        SELECT datetime(timestamp,'unixepoch') as time,
               client_ip, host,
               ROUND(rpm_current,1) as rpm,
               ROUND(rpm_baseline,1) as baseline,
               action
        FROM throttle_events
        ORDER BY id DESC LIMIT 20
    """)
    total   = query_db("SELECT COUNT(*) as n FROM traffic_log")[0]["n"]
    flagged = query_db("SELECT COUNT(*) as n FROM traffic_log WHERE flagged=1")[0]["n"]
    clients = query_db("SELECT COUNT(DISTINCT client_ip) as n FROM traffic_log")[0]["n"]
    return jsonify({
        "counts": counts,
        "recent": recent,
        "throttles": throttles,
        "total": total,
        "flagged": flagged,
        "clients": clients,
    })

@app.route("/api/clear", methods=["POST"])
def clear_logs():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM traffic_log")
        conn.execute("DELETE FROM throttle_events")
    return jsonify({"status": "cleared"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
