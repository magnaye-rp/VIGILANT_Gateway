#!/bin/bash
#══════════════════════════════════════════════════════════════════════════════
# VIGILANT GATEWAY - AUTOMATED SETUP SCRIPT
# One command to deploy the entire system
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
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
    log_info "Detecting available network interfaces..."
    
    # Get list of non-loopback interfaces
    INTERFACES=($(ip link show | grep "^[0-9]:" | grep -v "lo" | awk -F: '{print $2}' | tr -d ' '))
    
    if [ ${#INTERFACES[@]} -eq 0 ]; then
        log_error "No network interfaces found!"
        exit 1
    fi
    
    log_info "Available network interfaces:"
    for i in "${!INTERFACES[@]}"; do
        iface="${INTERFACES[$i]}"
        state=$(ip link show "$iface" | grep -oP '(?<=state )\w+' || echo "unknown")
        ip_addr=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "none")
        echo "  [$i] $iface - State: $state - IP: $ip_addr"
    done
    
    echo ""
    log_info "Select the WAN/Internet-facing interface (connects to upstream router/modem):"
    read -p "Enter interface number or name: " wan_selection
    
    if [[ "$wan_selection" =~ ^[0-9]+$ ]] && [ "$wan_selection" -ge 0 ] && [ "$wan_selection" -lt ${#INTERFACES[@]} ]; then
        WAN_INTERFACE="${INTERFACES[$wan_selection]}"
    elif [[ " ${INTERFACES[@]} " =~ " ${wan_selection} " ]]; then
        WAN_INTERFACE="$wan_selection"
    else
        log_error "Invalid selection: $wan_selection"
        exit 1
    fi
    
    log_info "Select the LAN/Client-facing interface (PCIe Ethernet for clients):"
    read -p "Enter interface number or name: " lan_selection
    
    if [[ "$lan_selection" =~ ^[0-9]+$ ]] && [ "$lan_selection" -ge 0 ] && [ "$lan_selection" -lt ${#INTERFACES[@]} ]; then
        LAN_INTERFACE="${INTERFACES[$lan_selection]}"
    elif [[ " ${INTERFACES[@]} " =~ " ${lan_selection} " ]]; then
        LAN_INTERFACE="$lan_selection"
    else
        log_error "Invalid selection: $lan_selection"
        exit 1
    fi
    
    if [ "$WAN_INTERFACE" = "$LAN_INTERFACE" ]; then
        log_error "WAN and LAN interfaces cannot be the same!"
        exit 1
    fi
    
    log_success "WAN Interface: $WAN_INTERFACE"
    log_success "LAN Interface: $LAN_INTERFACE"
    
    # Export for child processes
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
    
    log_info "Verifying setup.sh is in correct location..."
    if [ ! -f "$REPO_DIR/src/app.py" ]; then
        log_error "src/app.py not found at $REPO_DIR/src/"
        log_error "Make sure you're running setup.sh from the repo root"
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
    
    log_info "Updating package lists..."
    apt-get update > /dev/null 2>&1
    
    log_info "Installing system packages..."
    apt-get install -y \
        python3 python3-pip python3-venv \
        dnsmasq iptables iptables-persistent \
        netfilter-persistent \
        git curl wget nano acl \
        > /dev/null 2>&1
    
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
    
    log_info "Creating directory structure..."
    mkdir -p "$VIGILANT_HOME"/{addons,templates,static,scripts,logs,certs}
    
    # Secure permissions across operational system accounts
    REAL_SUDO_USER="${SUDO_USER:-$USER}"
    log_info "Setting cross-user directory access configurations for /home/${REAL_SUDO_USER}..."
    chmod 755 "/home/${REAL_SUDO_USER}" 2>/dev/null || true
    chmod 755 "/home/${REAL_SUDO_USER}/vigilant_gateway" 2>/dev/null || true
    chmod 755 "/home/${REAL_SUDO_USER}/vigilant_gateway/src" 2>/dev/null || true
    
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME"
    chmod -R 755 "$VIGILANT_HOME"
    log_success "Directories and home parameters secured"
}

# ─── Stage 3: Python Virtual Environment ────────────────────────────────────
stage_3_python_env() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 3: PYTHON VIRTUAL ENVIRONMENT"
    log_info "═══════════════════════════════════════════"
    
    log_info "Creating virtual environment..."
    python3 -m venv "$VIGILANT_HOME/venv"
    
    log_info "Installing Python packages..."
    source "$VIGILANT_HOME/venv/bin/activate"
    pip install --upgrade pip > /dev/null 2>&1
    
    # Only copy requirements.txt if repo and home paths differ
    if [ "$REPO_DIR" != "$VIGILANT_HOME" ]; then
        cp "$REPO_DIR/requirements.txt" "$VIGILANT_HOME/requirements.txt"
    fi
    
    # Install from requirements file
    pip install -r "$VIGILANT_HOME/requirements.txt" > /dev/null 2>&1
    
    # Install additional packages not in requirements.txt
    pip install mitmproxy==9.0.1 spacy > /dev/null 2>&1
    
    log_info "Downloading spaCy model (en_core_web_sm)..."
    python -m spacy download en_core_web_sm > /dev/null 2>&1
    
    deactivate
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME/venv"
    log_success "Python environment ready"
}

# ─── Stage 4: Copy Application Files ────────────────────────────────────────
stage_4_copy_files() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 4: COPYING APPLICATION FILES"
    log_info "═══════════════════════════════════════════"

    log_info "Wiping old Python bytecode cache to force code reload..."
    find "$VIGILANT_HOME" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find "$REPO_DIR" -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    
    log_info "Copying Python files..."
    cp "$REPO_DIR/src/app.py" "$VIGILANT_HOME/"
    
    # Establish operational symlink from active work tree
    SRC_ADDON="$REPO_DIR/src/vigilant_addon.py"
    if [ ! -f "$SRC_ADDON" ]; then
        log_error "Source addon file not found at $SRC_ADDON!"
        exit 1
    fi
    chmod 644 "$SRC_ADDON"
    rm -f "$VIGILANT_HOME/addons/vigilant_addon.py"
    ln -s "$SRC_ADDON" "$VIGILANT_HOME/addons/vigilant_addon.py"
    log_success "Dynamic engine symlink mapped to repository source target"
    
    log_info "Copying templates..."
    cp -a "$REPO_DIR/src/templates/." "$VIGILANT_HOME/templates/"

    log_info "Copying static assets..."
    cp -a "$REPO_DIR/src/static/." "$VIGILANT_HOME/static/"
    
    log_info "Copying scripts..."
    cp "$REPO_DIR/src/scripts/setup-iptables.sh" "$VIGILANT_HOME/scripts/"
    chmod +x "$VIGILANT_HOME/scripts/setup-iptables.sh"
    
    log_info "Copying configuration templates..."
    cp "$REPO_DIR/src/config/dnsmasq.conf" "$VIGILANT_HOME/scripts/"
    cp "$REPO_DIR/src/config/netplan-config.yaml" "$VIGILANT_HOME/scripts/"
    
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME"
    log_success "Files copied"
}

# ─── Stage 5: Network Configuration ─────────────────────────────────────────
stage_5_network_config() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 5: NETWORK CONFIGURATION"
    log_info "═══════════════════════════════════════════"
    
    log_info "Backing up netplan config..."
    cp /etc/netplan/00-installer-config.yaml \
       /etc/netplan/00-installer-config.yaml.bak 2>/dev/null || true

    log_info "Configuring Netplan for WAN ($WAN_INTERFACE) and LAN ($LAN_INTERFACE)..."
    
    # Netplan handles both ethernet and wifi interfaces under the hood for static assignment
    cat > /etc/netplan/00-installer-config.yaml << EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $WAN_INTERFACE:
      dhcp4: true
EOF

    # If LAN is Wi-Fi, set under wifis section; if Ethernet, set under ethernets
    if [[ "$LAN_INTERFACE" == wl* ]]; then
        cat >> /etc/netplan/00-installer-config.yaml << EOF
  wifis:
    $LAN_INTERFACE:
      dhcp4: no
      addresses:
        - 192.168.10.1/24
      ignore-carrier: true
EOF
    else
        cat >> /etc/netplan/00-installer-config.yaml << EOF
    $LAN_INTERFACE:
      dhcp4: no
      addresses:
        - 192.168.10.1/24
      ignore-carrier: true
EOF
    fi

    log_info "Applying netplan changes..."
    netplan generate > /dev/null 2>&1
    netplan apply > /dev/null 2>&1
    systemctl restart systemd-networkd > /dev/null 2>&1 || true
    
    log_success "Network configured: $WAN_INTERFACE (DHCP WAN), $LAN_INTERFACE (Static 192.168.10.1 LAN)"
}

# ─── Stage 6: DNS/DHCP Setup ────────────────────────────────────────────────
stage_6_dns_dhcp() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 6: DNS/DHCP CONFIGURATION"
    log_info "═══════════════════════════════════════════"
    
    log_info "Backing up dnsmasq.conf..."
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak 2>/dev/null || true
    
    log_info "Generating dnsmasq.conf with dynamic interface..."
    sed "s/interface=enp0s6/interface=$LAN_INTERFACE/g" "$REPO_DIR/src/config/dnsmasq.conf" > /tmp/dnsmasq-vigilant.conf
    cat /tmp/dnsmasq-vigilant.conf > /etc/dnsmasq.conf
    rm /tmp/dnsmasq-vigilant.conf
    
    log_info "Restarting dnsmasq..."
    systemctl restart dnsmasq
    
    log_info "Setting up dnsmasq log with proper permissions for VIGILANT addon..."
    touch /var/log/dnsmasq.log
    chmod 644 /var/log/dnsmasq.log
    log_success "dnsmasq.log permissions set (644)"
    
    log_info "Configuring logrotate for dnsmasq with automatic permission management..."
    cat > /etc/logrotate.d/dnsmasq << 'EOF'
/var/log/dnsmasq.log {
    daily
    copytruncate
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        if [ -f /var/log/dnsmasq.log ]; then
            chmod 644 /var/log/dnsmasq.log
        fi
        systemctl reload dnsmasq > /dev/null 2>&1 || true
    endscript
}
EOF
    log_success "Logrotate configuration created at /etc/logrotate.d/dnsmasq"
    
    log_info "Validating logrotate configuration..."
    if logrotate -d /etc/logrotate.d/dnsmasq > /dev/null 2>&1; then
        log_success "Logrotate configuration validated"
    else
        log_warn "Logrotate configuration validation failed (may be non-critical)"
    fi
    
    log_success "DNS/DHCP configured with logrotate permission management"
}

# ─── Stage 7: Firewall Setup ────────────────────────────────────────────────
stage_7_firewall() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 7: FIREWALL RULES"
    log_info "═══════════════════════════════════════════"
    
    log_info "Saving network interface environment variables for systemd..."
    cat << EOF > "$VIGILANT_HOME/.env"
WAN_INTERFACE=$WAN_INTERFACE
LAN_INTERFACE=$LAN_INTERFACE
EOF
    chown "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME/.env"

    log_info "Applying iptables rules with dynamic interfaces..."
    WAN_INTERFACE="$WAN_INTERFACE" LAN_INTERFACE="$LAN_INTERFACE" bash "$VIGILANT_HOME/scripts/setup-iptables.sh"
    log_success "Firewall rules applied"
    
    log_info "Enabling IPv4 packet forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    log_success "IPv4 forwarding enabled and persistent"
    
    log_info "Applying NAT routing rules..."
    iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE

    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 53 -j REDIRECT --to-ports 53

    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 80 -j REDIRECT --to-ports 8080
    iptables -t nat -A PREROUTING -i "$LAN_INTERFACE" -p tcp --dport 443 -j REDIRECT --to-ports 8080
    
    iptables -A FORWARD -i "$LAN_INTERFACE" -p udp --dport 443 -j DROP
    iptables -A FORWARD -i "$LAN_INTERFACE" -p udp --dport 80 -j DROP
    iptables -A FORWARD -i "$LAN_INTERFACE" -p tcp --dport 853 -j REJECT
    iptables -A FORWARD -i "$LAN_INTERFACE" -p udp --dport 853 -j REJECT
    iptables -A OUTPUT -p udp --dport 443 -j DROP
    iptables -A OUTPUT -p udp --dport 80 -j DROP
    ip6tables -P FORWARD DROP

    iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$LAN_INTERFACE" -o "$WAN_INTERFACE" -j ACCEPT

    log_info "Saving iptables rules persistently..."
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
    else
        iptables-save > /etc/iptables/rules.v4
    fi
    log_success "NAT routing rules applied and saved persistently"
}

# ─── Stage 8: Certificates ──────────────────────────────────────────────────
stage_8_certificates() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 8: MITMPROXY CERTIFICATES"
    log_info "═══════════════════════════════════════════"
    
    log_info "Generating mitmproxy certificates..."
    sudo -u "$VIGILANT_USER" bash -c "
        source $VIGILANT_HOME/venv/bin/activate
        mitmdump --version > /dev/null 2>&1 || true
    "
    log_success "Certificates generated"
}

# ─── Stage 9: Systemd Services ──────────────────────────────────────────────
stage_9_systemd_services() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 9: SYSTEMD SERVICES"
    log_info "═══════════════════════════════════════════"
    
    log_info "Generating custom systemd service files dynamically..."

    log_info "Creating vigilant-firewall.service..."
    cat << EOF > /etc/systemd/system/vigilant-firewall.service
[Unit]
Description=VIGILANT Firewall Rules
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=$VIGILANT_HOME/.env
ExecStart=/usr/bin/bash $VIGILANT_HOME/scripts/setup-iptables.sh

[Install]
WantedBy=multi-user.target
EOF

    log_info "Creating vigilant-proxy.service..."
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
    --mode transparent \
    --showhost \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --set block_global=false \
    --set connection_strategy=lazy \
    -s $VIGILANT_HOME/src/vigilant_addon.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    log_info "Creating vigilant-dashboard.service..."
    cat << EOF > /etc/systemd/system/vigilant-dashboard.service
[Unit]
Description=VIGILANT Flask Dashboard
After=network.target vigilant-proxy.service

[Service]
Type=simple
User=$VIGILANT_USER
WorkingDirectory=$VIGILANT_HOME
Environment=PYTHONUNBUFFERED=1
ExecStart=$VIGILANT_HOME/venv/bin/python3 $VIGILANT_HOME/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    log_info "Syncing the latest backend app.py into the runtime directory..."
    cp "$REPO_DIR/src/app.py" "$VIGILANT_HOME/app.py"

    log_info "Validating security context permissions for $VIGILANT_USER..."
    mkdir -p /home/$VIGILANT_USER/.mitmproxy
    chown -R "$VIGILANT_USER:$VIGILANT_USER" /home/$VIGILANT_USER/.mitmproxy
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME"

    log_info "Forcing systemd daemon config reload..."
    systemctl daemon-reload
    
    log_info "Configuring passwordless systemctl permissions for dashboard management..."
    cat << EOF > /etc/sudoers.d/vigilant-dashboard
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart vigilant-proxy
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload dnsmasq
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables-restore /etc/iptables/rules.v4
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/pkill -f mitmdump
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/bin/pkill -HUP dnsmasq
$VIGILANT_USER ALL=(ALL) NOPASSWD: /usr/sbin/netplan apply
$VIGILANT_USER ALL=(ALL) NOPASSWD: /sbin/tc
$VIGILANT_USER ALL=(ALL) NOPASSWD: /sbin/iptables
EOF
    chmod 0440 /etc/sudoers.d/vigilant-dashboard
    visudo -c
    log_success "Passwordless sudo permissions configured"
    
    log_info "Enabling services for auto-start..."
    systemctl enable vigilant-firewall vigilant-proxy vigilant-dashboard

    log_info "Restarting services so the updated backend is loaded immediately..."
    systemctl restart vigilant-firewall || true
    systemctl restart vigilant-proxy || true
    systemctl restart vigilant-dashboard || true

    log_success "Services installed and enabled dynamically"
}

# ─── Stage 9.5: SQLite Database Initialization ───────────────────────────────
stage_9_5_database_init() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 9.5: SQLITE DATABASE INITIALIZATION"
    log_info "═══════════════════════════════════════════"
    
    log_info "Running Python bootstrap routine to initialize database..."
    
    cat << 'EOF' > "$VIGILANT_HOME/init_db.py"
#!/usr/bin/env python3
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'logs', 'vigilant.db')

def init_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS config_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at REAL
        )
    ''')
    default_configs = {
        'nlp_enabled': 'true',
        'keywords': 'tiktok, instagram, facebook, scroll, short',
        'network_velocity_preset': 'Medium',
        'network_velocity_custom': '150',
        'physical_scroll_preset': 'Medium',
        'physical_scroll_custom': '75',
        'sni_filtering_enabled': 'true',
        'upstream_interface': 'eth0',
        'distribution_interface': 'wlan0',
        'theme_mode': 'dark',
        'tfidf_classification_threshold': '0.05',
        'tfidf_url_threshold': '0.3',
        'tfidf_body_threshold': '0.15'
    }
    for key, value in default_configs.items():
        cursor.execute('''
            INSERT OR IGNORE INTO config_settings (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', (key, value, 0))
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keyword_blacklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('SELECT COUNT(*) FROM keyword_blacklist')
    if cursor.fetchone()[0] == 0:
        default_keywords = ['tiktok', 'instagram', 'facebook']
        for kw in default_keywords:
            cursor.execute('INSERT OR IGNORE INTO keyword_blacklist (keyword) VALUES (?)', (kw,))
    cursor.execute('''
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
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            client_ip TEXT,
            host TEXT,
            category TEXT,
            flagged INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully with default configurations")

if __name__ == '__main__':
    init_database()
EOF
    
    chmod +x "$VIGILANT_HOME/init_db.py"
    
    sudo -u "$VIGILANT_USER" bash -c "
        source $VIGILANT_HOME/venv/bin/activate
        python3 $VIGILANT_HOME/init_db.py
    "
    rm "$VIGILANT_HOME/init_db.py"
    log_success "SQLite database initialized with default configurations"
}

# ─── Stage 10: Verification ─────────────────────────────────────────────────
stage_10_verify() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 10: VERIFICATION"
    log_info "═══════════════════════════════════════════"
    
    log_info "Verifying file placements..."
    declare -a FILES=(
        "$VIGILANT_HOME/app.py"
        "$VIGILANT_HOME/addons/vigilant_addon.py"
        "$VIGILANT_HOME/templates/dashboard.html"
        "$VIGILANT_HOME/scripts/setup-iptables.sh"
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
    
    log_info "Verifying Python packages..."
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

    log_info "Force-killing old ghost proxy and dashboard instances..."
    # This ensures any hanging zombie python/mitm processes are entirely wiped from memory
    sudo killall mitmdump python3 2>/dev/null || true
    sleep 1

    log_info "Reloading systemd and restarting updated engines..."
    sudo systemctl daemon-reload
    sudo systemctl restart vigilant-firewall
    sudo systemctl restart vigilant-proxy
    sudo systemctl restart vigilant-dashboard
        
    log_info "Starting firewall service..."
    systemctl start vigilant-firewall
    sleep 1
    
    log_info "Starting proxy service..."
    systemctl start vigilant-proxy
    sleep 2
    
    log_info "Starting dashboard service..."
    systemctl start vigilant-dashboard
    sleep 1
    
    log_success "All services started"
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
    log_success "║         VIGILANT GATEWAY SETUP COMPLETE!                 ║"
    log_success "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}Dashboard:${NC} http://192.168.10.1:5000"
    echo -e "${GREEN}Proxy:${NC} 127.0.0.1:8080"
    echo -e "${GREEN}Admin User:${NC} $VIGILANT_USER"
    echo -e "${GREEN}Install Path:${NC} $VIGILANT_HOME"
    echo ""
    echo "View logs:"
    echo "  $ sudo journalctl -u vigilant-proxy -f"
    echo "  $ sudo journalctl -u vigilant-dashboard -f"
    echo ""
}

# ─── Main Execution ──────────────────────────────────────────────────────────
main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║     VIGILANT GATEWAY - AUTOMATED SETUP                   ║"
    echo "║     https://github.com/magnaye-rp/vigilant-gateway       ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo ""
    
    read -p "Continue with setup? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Setup cancelled"
        exit 1
    fi
    
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