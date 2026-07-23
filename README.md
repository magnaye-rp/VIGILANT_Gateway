# V.I.G.I.L.A.N.T. 🛡️

**Versatile Infrastructure for Guided Inspection and Logical Analysis of Network Traffic**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/platform-Ubuntu%20Server-orange)
![AI Model](https://img.shields.io/badge/AI-spaCy%20NLP-green)

---

## 📖 Overview

V.I.G.I.L.A.N.T. is a hardware-integrated security gateway designed for the **Lenovo ThinkCentre M710q**. It addresses the "Brain Rot" phenomenon by using **Deep Packet Inspection (DPI)** and **Natural Language Processing (NLP)** to analyze content metadata in real-time. Unlike traditional firewalls, V.I.G.I.L.A.N.T. scores the linguistic complexity of incoming traffic to protect user cognitive health.

---

## 🛠️ Hardware Specifications

- **Host:** Lenovo ThinkCentre M710q (x86 Tiny PC)
- **Storage:** 120Gb NVMe (Internal)
- **Network:** \* **WAN:** Integrated Intel Gigabit Ethernet (Internet In)
  - **LAN:** Internal M.2 A+E Key Wi-Fi Card (Access Point Out)
- **OS:** Ubuntu Server 24.04 LTS (Headless)

---

## 🚀 Step-by-Step Installation Guide

### Phase 1: Hardware Setup

1. Open your Lenovo M710q and install a compatible **M.2 Wi-Fi card** (e.g., MediaTek or Atheros) into the A+E slot.
2. Ensure the antennas are properly connected for maximum range.
3. Plug in your **WAN Ethernet cable** to provide internet to the gateway.

### Phase 2: Software Installation

Run the following commands to transform your Ubuntu Server into the VIGILANT appliance:

# VIGILANT GATEWAY

> **Intelligent network gateway for protecting vulnerable users with AI-powered content filtering, doomscroll detection, and transparent proxy monitoring.**

---

## 🎯 What is VIGILANT?

VIGILANT is a transparent network gateway that monitors, categorizes, and intelligently throttles web traffic using:

- **NLP-based content categorization** (Educational, Productive, Distracting, Harmful)
- **Velocity detection** to catch doomscroll behavior on social media
- **SSL/TLS interception** via mitmproxy for deep packet inspection
- **Real-time dashboard** showing all network activity
- **Automatic service management** with systemd

Perfect for:

- Parental controls on shared networks
- Workplace productivity monitoring
- Research environments with vulnerable users
- Network administrators who need visibility

---

## ⚡ Quick Start (5 minutes)

### Prerequisites

- **Ubuntu 24.04 LTS Server** (headless recommended)
- **2 network interfaces** (WAN + LAN, e.g., enp0s5 + enp0s6)
- **8GB+ RAM**, **30GB+ disk**
- **Root/sudo access**

### One-Command Setup

```bash
# 1. Clone the repo
git clone https://github.com/magnaye-rp/vigilant-gateway.git
cd vigilant-gateway

# 2. Run setup (automated, all 11 stages)
sudo bash setup.sh

# 3. Done! Dashboard is ready at:
# http://192.168.10.1:5000
```

That's it. The `setup.sh` script handles everything:

- ✅ Install dependencies
- ✅ Create user & directories
- ✅ Setup Python virtual environment + spaCy
- ✅ Configure networking (netplan + dnsmasq)
- ✅ Deploy firewall rules (iptables)
- ✅ Generate mitmproxy certificates
- ✅ Install & start systemd services
- ✅ Verify all components

---

## 📊 What You Get

### Real-Time Dashboard

```
http://192.168.10.1:5000
```

Live stats for:

- Total requests processed
- Blocked harmful content
- Active clients on network
- Category breakdown (pie chart style)
- Recent traffic log
- Throttle events

### Transparent Proxy

```
mitmproxy @ 127.0.0.1:8080 (transparent)
```

- All HTTP/HTTPS traffic from LAN automatically redirected
- No client-side configuration needed
- SSL certificates installed in system root

### Database Logging

```
SQLite @ /home/vigilant_admin/vigilant/logs/vigilant.db
```

Tracks:

- Every request with timestamp
- Client IP, host, path, method
- Content category & entities
- Throttle events & velocity metrics

---

## 🏗️ Architecture

```
┌─────────────────────┐
│   Client VMs on     │
│    LAN (Network)    │
└──────────┬──────────┘
           │
           ↓ (all traffic)
┌─────────────────────────────────────────────────────────────┐
│                   VIGILANT GATEWAY                          │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  iptables (Firewall Rules)                                   │
│  ↓ Redirects port 80/443 → 8080                              │
│                                                              │
│  mitmproxy (Transparent Proxy)                               │
│  ↓ Intercepts all HTTPS, decrypts with CA cert               │
│                                                              │
│  VIGILANT Addon (Python)                                     │
│  ├─ NLP Text Categorization (spaCy)                          │
│  ├─ Velocity Detection (doomscroll)                          │
│  ├─ Threat Analysis                                          │
│  └─ Database Logging (SQLite)                                │
│                                                              │
│  Flask Dashboard (Backend)                                   │
│  ↓ REST API @ localhost:5000/api/*                           │
│                                                              │
│  HTML Dashboard (Frontend)                                   │
│  ↓ Auto-refresh every 5 seconds                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
           ↑
           ↓ (filtered, throttled, monitored)
┌──────────────────────┐
│   Internet / WAN     │
│   (enp0s5)           │
└──────────────────────┘
```

---

## 📁 Repository Structure

```
vigilant-gateway/
├── setup.sh                      ← Run this once (automated)
├── requirements.txt              ← Python dependencies
├── README.md                     ← You are here
│
├── src/
│   ├── app.py                   ← Flask backend
│   ├── vigilant_addon.py        ← mitmproxy addon with NLP
│   ├── templates/
│   │   └── dashboard.html       ← Web UI
│   ├── scripts/
│   │   └── setup-iptables.sh    ← Firewall rules
│   ├── config/
│   │   ├── dnsmasq.conf         ← DNS/DHCP template
│   │   └── netplan-config.yaml  ← Network config
│   └── systemd/
│       ├── vigilant-firewall.service
│       ├── vigilant-proxy.service
│       └── vigilant-dashboard.service
│
├── docs/
│   ├── SETUP_GUIDE.md           ← Detailed walkthrough
│   ├── TROUBLESHOOTING.md       ← Common issues
│   ├── ARCHITECTURE.md          ← Deep dive
│   └── NETWORK_DIAGRAM.md       ← Visual reference
│
└── .gitignore
```

---

## 🔧 Manual Control

### Check Status

```bash
# All services
sudo systemctl status vigilant-firewall vigilant-proxy vigilant-dashboard

# Individual services
sudo systemctl status vigilant-proxy
sudo systemctl status vigilant-dashboard
```

### View Logs

```bash
# Real-time proxy logs
sudo journalctl -u vigilant-proxy -f

# Real-time dashboard logs
sudo journalctl -u vigilant-dashboard -f

# Past 50 lines
sudo journalctl -u vigilant-proxy -n 50 --no-pager
```

### Stop/Start

```bash
# Stop all
sudo systemctl stop vigilant-firewall vigilant-proxy vigilant-dashboard

# Start all
sudo systemctl start vigilant-firewall vigilant-proxy vigilant-dashboard

# Restart proxy (if code changes)
sudo systemctl restart vigilant-proxy
```

### Clear Logs

```bash
# Via dashboard
# → Click "Clear all logs" button @ http://192.168.10.1:5000

# Or via terminal
sqlite3 /home/vigilant_admin/vigilant/logs/vigilant.db << EOF
DELETE FROM traffic_log;
DELETE FROM throttle_events;
EOF
```

---

## ⚙️ Configuration

### Network Interfaces

Edit `/etc/netplan/00-installer-config.yaml`:

```yaml
enp0s5: # WAN interface (gets DHCP)
enp0s6: # LAN interface (192.168.10.1/24)
```

### DNS/DHCP

Edit `/etc/dnsmasq.conf`:

- Gateway IP: 192.168.10.1
- DHCP range: 192.168.10.100-200
- Default route points to gateway

### Firewall Rules

Edit `~/vigilant/scripts/setup-iptables.sh`:

- Transparent proxy port: 8080
- NAT interface: enp0s5

### Content Categories

Edit `src/vigilant_addon.py`:

```python
DOMAIN_HINTS = {
    "Educational":  {"wikipedia.org", ...},
    "Productive":   {"github.com", ...},
    "Distracting":  {"reddit.com", ...},
    "Harmful":      {...},
}

CATEGORY_KEYWORDS = {
    "Educational":  {"learn", "study", ...},
    ...
}
```

---

## 🔍 Monitoring

### Dashboard Metrics

| Metric                 | Meaning                                   |
| ---------------------- | ----------------------------------------- |
| **Total Requests**     | All HTTP/HTTPS flows processed            |
| **Harmful Blocked**    | Requests blocked due to content or threat |
| **Active Clients**     | Unique IPs on network                     |
| **Category Breakdown** | Pie chart of request types                |
| **RPM (Requests/Min)** | Velocity metric for doomscroll detection  |

### Alert Thresholds

```python
# Doomscroll detection triggered when:
# RPM > (baseline_RPM × 1.5) on social media domains

VELOCITY_THRESHOLD = 1.5
VELOCITY_WINDOW = 60  # seconds
MIN_REQUESTS_BASELINE = 10
```

---

## 🚨 Troubleshooting

### Dashboard shows "No data"

```bash
# Check if proxy is running
sudo systemctl status vigilant-proxy

# View logs
sudo journalctl -u vigilant-proxy -n 50 --no-pager

# Check database
sqlite3 /home/vigilant_admin/vigilant/logs/vigilant.db "SELECT COUNT(*) FROM traffic_log;"
```

### Network interfaces not connecting

```bash
# Check interfaces exist
ip link show

# Manual netplan apply
sudo netplan generate
sudo netplan apply

# Check IP assignments
ip addr show
```

### mitmproxy errors

```bash
# Regenerate certificates
rm -rf ~/.mitmproxy
sudo -u vigilant_admin bash -c "source ~/vigilant/venv/bin/activate && mitmdump --version"
```

### Firewall rules not applied

```bash
# Re-run iptables script
sudo bash ~/vigilant/scripts/setup-iptables.sh

# Verify rules
sudo iptables -t nat -L -n -v
```

See **docs/TROUBLESHOOTING.md** for more.

---

## 📚 Documentation

| File                   | Purpose                                       |
| ---------------------- | --------------------------------------------- |
| **SETUP_GUIDE.md**     | Step-by-step walkthrough of all 11 stages     |
| **ARCHITECTURE.md**    | Deep dive into components & how they interact |
| **TROUBLESHOOTING.md** | Common issues & solutions                     |
| **NETWORK_DIAGRAM.md** | Visual flowcharts                             |

---

## 🛠️ Customization

### Change DHCP Range

```bash
sudo nano /etc/dnsmasq.conf
# Edit dhcp-range line
sudo systemctl restart dnsmasq
```

### Change Dashboard Port

```bash
# In: /etc/systemd/system/vigilant-dashboard.service
ExecStart=python3 /path/to/app.py --port 5000

sudo systemctl daemon-reload
sudo systemctl restart vigilant-dashboard
```

### Add Custom Categories

```bash
# Edit: src/vigilant_addon.py
# Add to DOMAIN_HINTS and CATEGORY_KEYWORDS
# Redeploy: sudo systemctl restart vigilant-proxy
```

---

## 📊 Performance Specs

Tested on:

- **CPU:** 2 cores (Intel Xeon)
- **RAM:** 4GB (but 8GB+ recommended)
- **Disk:** 30GB SSD
- **Throughput:** ~100 Mbps per client

**Latency impact:** +2-5ms per request (HTTPS decryption)

---

## 🔐 Security Notes

- **Root CA Certificate** generated on first run (stored in `~/.mitmproxy/`)
- **Database** contains all URLs accessed (store securely!)
- **HTTPS decryption** requires installing root CA on clients
- **No encryption** of traffic logs themselves (add encryption if needed)

---

## 📝 License

MIT License - See LICENSE file

---

## 🤝 Contributing

Issues & PRs welcome!

```bash
git clone https://github.com/yourusername/vigilant-gateway.git
cd vigilant-gateway
git checkout -b feature/your-feature
```

---

## 💬 Support

- **Issues:** GitHub Issues tab
- **Docs:** See `/docs` folder
- **Logs:** `sudo journalctl -u vigilant-* -f`

---

## 🚀 Deploy to Production

For larger deployments:

```bash
# On multiple gateways
for gateway in gw1 gw2 gw3; do
    ssh root@$gateway "git clone ... && cd vigilant-gateway && bash setup.sh"
done

# Centralized monitoring
# → Add each dashboard to monitoring system
# → Parse logs for alerting
```

---

**Made with ❤️ for network safety**

Last updated: 2024
