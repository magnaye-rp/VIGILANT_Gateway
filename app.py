"""
V.I.G.I.L.A.N.T. - Web Admin Interface
Controls routing and provides certificates to clients.
"""
from flask import Flask, render_template_string, request, send_from_directory
import subprocess
import os

app = Flask(__name__)

# CONFIGURATION - Update 'wlan0' if your Wi-Fi interface name is different
WIFI_IFACE = "wlan0"
CERT_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>VIGILANT Admin</title>
    <style>body{background:#121212; color:white;} .card{background:#1e1e1e; border:none;}</style>
</head>
<body class="container py-5 text-center">
    <h1 class="mb-4">🛡️ V.I.G.I.L.A.N.T.</h1>
    <div class="card p-4 shadow-lg">
        <h3>Filter Status: <span class="text-info">{{ status }}</span></h3>
        <hr class="bg-secondary">
        <form method="POST" action="/toggle">
            <button name="action" value="enable" class="btn btn-success btn-lg w-100 mb-3">Enable AI Shield</button>
            <button name="action" value="disable" class="btn btn-outline-danger btn-lg w-100 mb-3">Bypass (Off)</button>
        </form>
        <a href="/download-cert" class="btn btn-sm btn-secondary mt-3">Download SSL Certificate</a>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    check = subprocess.run("sudo iptables -t nat -L PREROUTING", shell=True, capture_output=True, text=True)
    status = "ACTIVE" if "REDIRECT" in check.stdout else "DISABLED"
    return render_template_string(HTML_TEMPLATE, status=status)

@app.route('/toggle', methods=['POST'])
def toggle():
    action = request.form.get('action')
    if action == "enable":
        subprocess.run(f"sudo iptables -t nat -A PREROUTING -i {WIFI_IFACE} -p tcp --dport 80 -j REDIRECT --to-port 8080", shell=True)
        subprocess.run(f"sudo iptables -t nat -A PREROUTING -i {WIFI_IFACE} -p tcp --dport 443 -j REDIRECT --to-port 8080", shell=True)
    else:
        subprocess.run("sudo iptables -t nat -F PREROUTING", shell=True)
    return """<script>window.location.href='/';</script>"""

@app.route('/download-cert')
def download():
    return send_from_directory(os.path.dirname(CERT_PATH), os.path.basename(CERT_PATH), as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)