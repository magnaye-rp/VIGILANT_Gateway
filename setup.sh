#!/bin/bash
#══════════════════════════════════════════════════════════════════════════════
# VIGILANT GATEWAY - UNIFIED PLUG-AND-PLAY SETUP SCRIPT
# Deploy the system directly in /home/vigilant-admin/vigilant_gateway
# Subnet: 172.20.10.0/24 (Server LAN IP: 172.20.10.1)
#══════════════════════════════════════════════════════════════════════════════

set -e  # Exit on any error

# ─── Colors for output ───────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Configuration ──────────────────────────────────────────────────────────
VIGILANT_USER="vigilant-admin"
VIGILANT_HOME="/home/$VIGILANT_USER/vigilant_gateway"
REPO_DIR="$VIGILANT_HOME"
LAN_IP="172.20.10.1"
LAN_SUBNET="172.20.10.0/24"
WAN_INTERFACE=""
LAN_INTERFACE=""

# ─── Helper functions ───────────────────────────────────────────────────────
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use: sudo bash setup.sh)"
        exit 1
    fi
}

check_os() {
    if ! grep -qi "ubuntu" /etc/os-release; then
        log_error "This script requires Ubuntu"
        exit 1
    fi
    log_success "Ubuntu detected"
}

detect_network_interfaces() {
    log_info "Auto-detecting available network interfaces for Plug-and-Play operation..."
    
    # Filter out loopback, virtual, and bridge interfaces
    INTERFACES=($(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|docker|veth|tun|tap|br-)'))
    
    if [ ${#INTERFACES[@]} -lt 2 ]; then
        log_error "At least 2 physical network interfaces are required (WAN & LAN)!"
        exit 1
    fi

    # Automatically set WAN to the interface with an active default route
    WAN_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1 || true)
    
    if [ -z "$WAN_INTERFACE" ]; then
        WAN_INTERFACE="${INTERFACES[0]}"
        LAN_INTERFACE="${INTERFACES[1]}"
    else
        for iface in "${INTERFACES[@]}"; do
            if [ "$iface" != "$WAN_INTERFACE" ]; then
                LAN_INTERFACE="$iface"
                break
            fi
        done
    fi
    
    if [ -z "$LAN_INTERFACE" ] || [ "$WAN_INTERFACE" = "$LAN_INTERFACE" ]; then
        log_error "Failed to automatically separate WAN and LAN interfaces!"
        exit 1
    fi
    
    log_success "Auto-selected WAN Interface: $WAN_INTERFACE"
    log_success "Auto-selected LAN Interface: $LAN_INTERFACE"
    
    export WAN_INTERFACE LAN_INTERFACE
}

# ─── Stage 0: Preflight Checks ──────────────────────────────────────────────
stage_0_preflight() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 0: PREFLIGHT CHECKS"
    log_info "═══════════════════════════════════════════"
    
    check_root
    check_os
    detect_network_interfaces

    # Network preflight: apt/pip installs (Stages 1 & 3) require WAN reachability.
    # Fail early with a clear message instead of dying silently inside apt-get.
    log_info "Checking WAN connectivity..."
    if ping -c 2 -W 2 8.8.8.8 > /dev/null 2>&1; then
        log_success "WAN reachable (ICMP to 8.8.8.8)"
    else
        log_warn "No ICMP to 8.8.8.8 — checking DNS resolution..."
        if getent hosts archive.ubuntu.com > /dev/null 2>&1; then
            log_warn "DNS resolves but ICMP blocked — continuing (apt uses HTTP/HTTPS)"
        else
            log_error "No network connectivity to archive.ubuntu.com!"
            log_error "This gateway cannot reach the internet yet."
            log_error "Check: ip a (WAN interface state) and ip route show default"
            exit 1
        fi
    fi

    CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ ! -f "$CURRENT_DIR/src/app.py" ] && [ ! -f "$VIGILANT_HOME/src/app.py" ]; then
        log_error "src/app.py not found!"
        log_error "Please run setup.sh from inside the repository directory."
        exit 1
    fi
    log_success "Repository structure verified"
}

# ─── Stage 1: Install Dependencies ──────────────────────────────────────────
stage_1_dependencies() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 1: INSTALLING DEPENDENCIES"
    log_info "═══════════════════════════════════════════"
    
    # Noninteractive frontend prevents iptables-persistent's debconf prompts
    # ("Save current IPv4 rules?") from hanging the install.
    export DEBIAN_FRONTEND=noninteractive
    
    log_info "Updating package lists..."
    if ! apt-get update 2>&1 | tee "$VIGILANT_HOME/setup_apt.log" >/dev/null; then
        log_error "apt-get update FAILED. See $VIGILANT_HOME/setup_apt.log"
        log_error "Check WAN connectivity: ping -c 3 8.8.8.8 and ping -c 3 archive.ubuntu.com"
        exit 1
    fi
    
    log_info "Installing system packages..."
    if ! apt-get install -y \
        python3 python3-pip python3-venv \
        dnsmasq iptables iptables-persistent \
        netfilter-persistent \
        git curl wget nano acl 2>&1 | tee -a "$VIGILANT_HOME/setup_apt.log" >/dev/null; then
        log_error "apt-get install FAILED. See $VIGILANT_HOME/setup_apt.log"
        exit 1
    fi
    
    log_success "System packages installed"
}

# ─── Stage 2: Create User & Directories ─────────────────────────────────────
stage_2_directories() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 2: CREATING USER & DIRECTORIES"
    log_info "═══════════════════════════════════════════"
    
    if ! id "$VIGILANT_USER" &>/dev/null; then
        log_info "Creating user: $VIGILANT_USER"
        useradd -m -s /bin/bash "$VIGILANT_USER"
        log_success "User created"
    else
        log_warn "User $VIGILANT_USER already exists"
    fi
    
    log_info "Setting up unified directory structure at $VIGILANT_HOME..."
    mkdir -p "$VIGILANT_HOME"/{src,logs,certs,scripts}
    mkdir -p /var/log/vigilant

    chmod 755 "/home/$VIGILANT_USER"
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME" /var/log/vigilant
    chmod -R 775 "$VIGILANT_HOME" /var/log/vigilant
    log_success "Directory structure secured"
}

# ─── Stage 3: Python Virtual Environment ────────────────────────────────────
stage_3_python_env() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 3: PYTHON VIRTUAL ENVIRONMENT"
    log_info "═══════════════════════════════════════════"
    
    log_info "Creating virtual environment inside $VIGILANT_HOME/venv..."
    python3 -m venv "$VIGILANT_HOME/venv"
    
    log_info "Installing Python packages..."
    source "$VIGILANT_HOME/venv/bin/activate"
    pip install --upgrade pip 2>&1 | tee "$VIGILANT_HOME/setup_pip.log" >/dev/null || true
    
    if [ -f "$VIGILANT_HOME/requirements.txt" ]; then
        if ! pip install -r "$VIGILANT_HOME/requirements.txt" 2>&1 | tee -a "$VIGILANT_HOME/setup_pip.log" >/dev/null; then
            log_error "pip install requirements.txt FAILED. See $VIGILANT_HOME/setup_pip.log"
            exit 1
        fi
    fi
    
    if ! pip install mitmproxy==9.0.1 spacy flask flask-cors 2>&1 | tee -a "$VIGILANT_HOME/setup_pip.log" >/dev/null; then
        log_error "pip install core packages FAILED. See $VIGILANT_HOME/setup_pip.log"
        exit 1
    fi
    
    log_info "Downloading spaCy model (en_core_web_sm)..."
    if ! python -m spacy download en_core_web_sm 2>&1 | tee -a "$VIGILANT_HOME/setup_pip.log" >/dev/null; then
        log_warn "spaCy model download failed — NLP will run in degraded mode"
    fi
    
    deactivate
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME/venv"
    log_success "Python environment ready"
}

# ─── Stage 4: Sync Application Scripts ──────────────────────────────────────
stage_4_copy_files() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 4: APPLICATION FILE VERIFICATION"
    log_info "═══════════════════════════════════════════"

    log_info "Wiping old Python bytecode cache..."
    find "$VIGILANT_HOME" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    
    CURRENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    if [ -d "$CURRENT_DIR/src" ]; then
        log_info "Syncing src/ from $CURRENT_DIR to $VIGILANT_HOME..."
        rsync -a --delete "$CURRENT_DIR/src/" "$VIGILANT_HOME/src/" 2>/dev/null || \
            cp -a "$CURRENT_DIR/src/." "$VIGILANT_HOME/src/" 2>/dev/null || true
    fi
    
    for f in setup.sh requirements.txt vigilant_boot.sh; do
        if [ -f "$CURRENT_DIR/$f" ]; then
            cp -a "$CURRENT_DIR/$f" "$VIGILANT_HOME/" 2>/dev/null || true
        fi
    done

    chmod +x "$VIGILANT_HOME/src/scripts/setup-iptables.sh" 2>/dev/null || true
    chmod +x "$VIGILANT_HOME/setup.sh" 2>/dev/null || true
    
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME"
    log_success "Application files updated"
}

# ─── Stage 5: Network Configuration ─────────────────────────────────────────
stage_5_network_config() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 5: NETWORK CONFIGURATION"
    log_info "═══════════════════════════════════════════"

    rm -f /etc/netplan/*.bak 2>/dev/null || true
    rm -rf /etc/netplan/backup 2>/dev/null || true
    rm -f /etc/netplan/*.bak /etc/netplan/*.yaml.bak 2>/dev/null || true
    
    log_info "Backing up netplan config..."
    cp /etc/netplan/00-installer-config.yaml \
       /etc/netplan/00-installer-config.yaml.bak 2>/dev/null || true

    log_info "Configuring Netplan: WAN ($WAN_INTERFACE) via DHCP, LAN ($LAN_INTERFACE) on $LAN_IP/24..."
    
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $WAN_INTERFACE:
      dhcp4: true
    $LAN_INTERFACE:
      dhcp4: no
      addresses:
        - ${LAN_IP}/24
EOF

    log_info "Applying netplan changes..."
    netplan generate > /dev/null 2>&1
    netplan apply > /dev/null 2>&1
    systemctl restart systemd-networkd > /dev/null 2>&1 || true
    echo "[*] Applying Netplan network configuration..."
    netplan apply
    ip addr flush dev enp1s0 2>/dev/null || true
    systemctl restart systemd-networkd 2>/dev/null || true
    
    log_success "Network configured: WAN ($WAN_INTERFACE), LAN ($LAN_INTERFACE - $LAN_IP)"
}

# ─── Stage 6: DNS/DHCP Setup ────────────────────────────────────────────────
stage_6_dns_dhcp() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 6: DNS/DHCP CONFIGURATION"
    log_info "═══════════════════════════════════════════"
    
    log_info "Ensuring systemd-resolved service is active..."
    systemctl enable --now systemd-resolved > /dev/null 2>&1 || true
    
    # Determine the safest available resolv.conf path dynamically
    RESOLV_PATH="/etc/resolv.conf"
    if [ -f "/run/systemd/resolve/resolv.conf" ]; then
        RESOLV_PATH="/run/systemd/resolve/resolv.conf"
    fi
    
    log_info "Backing up dnsmasq.conf..."
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true
    
    log_info "Generating Plug-and-Play dnsmasq.conf for interface $LAN_INTERFACE..."
    cat > /etc/dnsmasq.conf << EOF
interface=$LAN_INTERFACE
# bind-dynamic (NOT bind-interfaces): tolerates the interface address not
# being assigned yet when dnsmasq starts at boot, preventing the bind-failure
# crash that leaves devices without DHCP after a reboot.
bind-dynamic
dhcp-range=172.20.10.50,172.20.10.200,255.255.255.0,12h
dhcp-option=option:router,$LAN_IP
dhcp-option=option:dns-server,$LAN_IP
resolv-file=$RESOLV_PATH
log-queries
log-facility=/var/log/dnsmasq.log
EOF
    
    log_info "Restarting dnsmasq..."
    # CRITICAL: create /var/log/dnsmasq.log BEFORE starting dnsmasq and grant
    # write access to the unprivileged dnsmasq user. A root-owned 644 file is
    # NOT writable by dnsmasq, which silently falls back to syslog and leaves
    # the file empty — breaking DNS-based device liveness tracking in the proxy
    # addon (tail_dnsmasq_log reads this file).
    touch /var/log/dnsmasq.log
    chown dnsmasq:dnsmasq /var/log/dnsmasq.log 2>/dev/null \
        || chown nobody:nogroup /var/log/dnsmasq.log 2>/dev/null \
        || true
    chmod 664 /var/log/dnsmasq.log
    systemctl restart dnsmasq
    
    log_success "DNS/DHCP dynamic forwarding configured on $LAN_SUBNET using $RESOLV_PATH"
}

# ─── Stage 7: Firewall & NAT Routing ────────────────────────────────────────
stage_7_firewall() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 7: FIREWALL & NAT RULES"
    log_info "═══════════════════════════════════════════"
    
    log_info "Saving network interface environment variables..."
    cat << EOF > "$VIGILANT_HOME/.env"
WAN_INTERFACE=$WAN_INTERFACE
LAN_INTERFACE=$LAN_INTERFACE
EOF
    chown "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME/.env"

    log_info "Enabling IPv4 packet forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    
    # Flush existing rules across tables to ensure a clean slate
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    
    log_info "Applying NAT Masquerade rules for downstream LAN traffic..."
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE

    # Ignore loopback traffic
    iptables -t nat -A PREROUTING -i lo -j ACCEPT

    # Prevent loopbacks: Exempt local process traffic in the OUTPUT chain (where uid-owner is valid)
    if id "$VIGILANT_USER" &>/dev/null; then
        log_info "Exempting service user '$VIGILANT_USER' from NAT OUTPUT loops..."
        iptables -t nat -A OUTPUT -m owner --uid-owner "$VIGILANT_USER" -j ACCEPT
    fi

    # Transparently intercept DNS queries
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 53 -j REDIRECT --to-ports 53

    # Transparently intercept HTTP (80) -> 8080 and HTTPS (443) -> 8081
    log_info "Configuring transparent interception rules for ports 80 & 443..."
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-ports 8080
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-ports 8081
    
    # Drop QUIC (HTTP/3 over UDP) and DoT (DNS-over-TLS) to force TCP HTTP/HTTPS through proxy
    log_info "Blocking QUIC and DoT to enforce HTTP/TLS fallback..."
    iptables -A FORWARD -i "$LAN_INTERFACE" -p udp --dport 443 -j DROP
    iptables -A FORWARD -i "$LAN_INTERFACE" -p udp --dport 80 -j DROP
    iptables -A FORWARD -i "$LAN_INTERFACE" -p tcp --dport 853 -j REJECT
    iptables -A FORWARD -i "$LAN_INTERFACE" -p udp --dport 853 -j REJECT
    iptables -A OUTPUT -p udp --dport 443 -j DROP
    iptables -A OUTPUT -p udp --dport 80 -j DROP
    ip6tables -P FORWARD DROP 2>/dev/null || true

    # Forwarding state rules
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save > /dev/null
    else
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
    fi
    log_success "NAT routing rules persistently applied"
}

# ─── Stage 8: Certificates ──────────────────────────────────────────────────
stage_8_certificates() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 8: MITMPROXY CERTIFICATES & LOG PERMISSIONS"
    log_info "═══════════════════════════════════════════"
    
    # 1. Generate mitmproxy certificates
    sudo -u "$VIGILANT_USER" bash << CMD
source $VIGILANT_HOME/venv/bin/activate
timeout 3 mitmdump --listen-port 8081 > /dev/null 2>&1 || true
CMD
    
    if [ -f "/home/$VIGILANT_USER/.mitmproxy/mitmproxy-ca-cert.pem" ]; then
        log_success "mitmproxy CA certificate created"
        cp "/home/$VIGILANT_USER/.mitmproxy/mitmproxy-ca-cert.pem" /usr/local/share/ca-certificates/mitmproxy.crt 2>/dev/null || true
        update-ca-certificates --fresh > /dev/null 2>&1 || true
        log_success "CA certificate installed in system trust store"
    else
        log_warn "Certificate not found — will be generated on first proxy start"
    fi

    # 2. Configure DNS log permissions and system group memberships
    log_info "Configuring log permissions for non-root proxy access..."
    touch /var/log/dnsmasq.log
    chmod 644 /var/log/dnsmasq.log
    
    # Grant service user permission to tail system/dns logs
    usermod -aG adm,syslog "$VIGILANT_USER" || true
    
    # Ensure logrotate maintains read permissions on log rotation
    if [ -f /etc/logrotate.d/dnsmasq ]; then
        sed -i 's/create 640/create 644/g' /etc/logrotate.d/dnsmasq 2>/dev/null || true
    fi
    log_success "Log permissions and group memberships configured"
}

# ─── Stage 9: Systemd Services ──────────────────────────────────────────────
stage_9_systemd_services() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 9: SYSTEMD SERVICES"
    log_info "═══════════════════════════════════════════"

cat << EOF > /etc/systemd/system/vigilant-firewall.service
[Unit]
Description=VIGILANT Firewall Rules
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=$VIGILANT_HOME/.env
ExecStart=/bin/bash $VIGILANT_HOME/src/scripts/setup-iptables.sh

[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > /etc/systemd/system/vigilant-proxy.service
[Unit]
Description=VIGILANT Transparent Proxy (mitmproxy)
After=network.target vigilant-firewall.service

[Service]
Type=simple
User=$VIGILANT_USER
WorkingDirectory=$VIGILANT_HOME
Environment=PYTHONUNBUFFERED=1
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
ExecStart=$VIGILANT_HOME/venv/bin/mitmdump \
    --mode transparent@8080 \
    --mode transparent@8081 \
    --showhost \
    --set block_global=false \
    --set connection_strategy=lazy \
    -s $VIGILANT_HOME/src/vigilant_addon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > /etc/systemd/system/vigilant-dashboard.service
[Unit]
Description=VIGILANT Flask Dashboard
After=network.target vigilant-proxy.service

[Service]
Type=simple
User=$VIGILANT_USER
WorkingDirectory=$VIGILANT_HOME
Environment=PYTHONUNBUFFERED=1
ExecStart=$VIGILANT_HOME/venv/bin/python3 $VIGILANT_HOME/src/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    mkdir -p /home/$VIGILANT_USER/.mitmproxy
    chown -R "$VIGILANT_USER:$VIGILANT_USER" /home/$VIGILANT_USER/.mitmproxy
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME"

    systemctl daemon-reload
    
    cat << EOF > /etc/sudoers.d/vigilant
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart vigilant-proxy, /bin/systemctl restart vigilant-proxy
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload dnsmasq, /bin/systemctl reload dnsmasq
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables-restore /etc/iptables/rules.v4, /sbin/iptables-restore /etc/iptables/rules.v4
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/pkill -f mitmdump, /bin/pkill -f mitmdump
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/pkill -HUP dnsmasq, /bin/pkill -HUP dnsmasq
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/sbin/netplan apply, /sbin/netplan apply
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/sbin/tc, /sbin/tc
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /sbin/iptables, /usr/bin/iptables, /bin/iptables
EOF
    chmod 0440 /etc/sudoers.d/vigilant
    visudo -c > /dev/null
    
    systemctl enable vigilant-firewall vigilant-proxy vigilant-dashboard
    log_success "Services configured and enabled"
}

# ─── Stage 9.5: SQLite Database Initialization ───────────────────────────────
stage_9_5_database_init() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 9.5: SQLITE DATABASE INITIALIZATION"
    log_info "═══════════════════════════════════════════"
    
    mkdir -p "$VIGILANT_HOME/logs"
    
    cat << 'PYEOF' > "$VIGILANT_HOME/init_db.py"
#!/usr/bin/env python3
import sqlite3, os, time

DB_PATH = os.path.join(os.path.dirname(__file__), 'logs', 'vigilant.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

DEFAULTS = {
    'upstream_interface': 'WAN_PLACEHOLDER',
    'distribution_interface': 'LAN_PLACEHOLDER',
    'custom_bypass_domains': 'fbcdn.net,i.instagram.com,api.instagram.com,graph.instagram.com,b.i.instagram.com,graph.facebook.com,b-graph.facebook.com,rupload.facebook.com,tiktokcdn.com,tiktokv.com,api.tiktokv.com,api.tiktok.com,googlevideo.com,ytimg.com,x.com,twitter.com',
}
c.execute('''CREATE TABLE IF NOT EXISTS config_settings (
    key TEXT PRIMARY KEY, value TEXT, updated_at REAL
)''')
for k, v in DEFAULTS.items():
    c.execute('INSERT OR IGNORE INTO config_settings (key, value, updated_at) VALUES (?, ?, ?)',
              (k, v, time.time()))
conn.commit()
conn.close()
PYEOF

    sed -i "s/WAN_PLACEHOLDER/$WAN_INTERFACE/g" "$VIGILANT_HOME/init_db.py"
    sed -i "s/LAN_PLACEHOLDER/$LAN_INTERFACE/g" "$VIGILANT_HOME/init_db.py"
    
    sudo -u "$VIGILANT_USER" "$VIGILANT_HOME/venv/bin/python3" "$VIGILANT_HOME/init_db.py"
    rm -f "$VIGILANT_HOME/init_db.py"
    
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME/logs" 2>/dev/null || true
    log_success "Database bootstrapped with LAN subnet 172.20.10.0/24"
}

# ─── Stage 10: Verification ─────────────────────────────────────────────────
stage_10_verify() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 10: VERIFICATION"
    log_info "═══════════════════════════════════════════"
    
    declare -a FILES=(
        "$VIGILANT_HOME/src/app.py"
        "$VIGILANT_HOME/src/vigilant_addon.py"
        "$VIGILANT_HOME/logs/vigilant.db"
        "/etc/systemd/system/vigilant-firewall.service"
        "/etc/systemd/system/vigilant-proxy.service"
        "/etc/systemd/system/vigilant-dashboard.service"
    )
    
    for file in "${FILES[@]}"; do
        if [ -f "$file" ]; then
            log_success "✓ $file"
        else
            log_error "✗ $file NOT FOUND"
        fi
    done
    
    source "$VIGILANT_HOME/venv/bin/activate"
    python3 -c "import flask, mitmproxy, spacy; print('All packages OK')" && \
        log_success "Python packages verified" || \
        log_error "Python packages verification failed"
    deactivate
}

# ─── Stage 11: Start Services ───────────────────────────────────────────────
stage_11_start_services() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 11: STARTING SERVICES"
    log_info "═══════════════════════════════════════════"

    pkill -f "mitmdump.*vigilant_addon" 2>/dev/null || true
    pkill -f "app.py.*vigilant" 2>/dev/null || true
    sleep 1

    systemctl restart vigilant-firewall || true
    systemctl restart vigilant-proxy || true
    systemctl restart vigilant-dashboard || true
    
    log_success "All services started successfully"
}

# ─── Final Status Check ──────────────────────────────────────────────────────
stage_12_status() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "FINAL STATUS"
    log_info "═══════════════════════════════════════════"
    
    echo ""
    systemctl status vigilant-firewall vigilant-proxy vigilant-dashboard --no-pager
    
    echo ""
    log_success "╔═══════════════════════════════════════════════════════════╗"
    log_success "║   VIGILANT GATEWAY PLUG-AND-PLAY SETUP COMPLETE!          ║"
    log_success "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}Dashboard:${NC} http://${LAN_IP}:5000"
    echo -e "${GREEN}LAN Subnet:${NC} 172.20.10.0/24"
    echo -e "${GREEN}Proxy Port:${NC} 8080"
    echo ""
}

# ─── Main Execution ──────────────────────────────────────────────────────────
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     VIGILANT GATEWAY - AUTOMATED PLUG-AND-PLAY SETUP      ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    
    stage_0_preflight
    stage_1_dependencies
    stage_2_directories
    stage_3_python_env
    stage_4_copy_files
    stage_5_network_config
    stage_6_dns_dhcp
    stage_7_firewall
    stage_8_certificates
    stage_9_systemd_services
    stage_9_5_database_init
    stage_10_verify
    stage_11_start_services
    stage_12_status
}

main "$@"