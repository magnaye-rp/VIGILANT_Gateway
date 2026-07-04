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
VIGILANT_USER="vigilant_admin"
VIGILANT_HOME="/home/$VIGILANT_USER/vigilant"
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
    
    log_info "Select the LAN/Client-facing interface (hosts DHCP clients/hostapd):"
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
        dnsmasq iptables netfilter-persistent \
        git curl wget nano \
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
    mkdir -p "$VIGILANT_HOME"/{addons,templates,scripts,logs,certs}
    chown -R "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME"
    chmod -R 755 "$VIGILANT_HOME"
    log_success "Directories created"
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
    pip install \
        flask \
        mitmproxy \
        spacy \
        > /dev/null 2>&1
    
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
    
    log_info "Copying Python files..."
    cp "$REPO_DIR/src/app.py" "$VIGILANT_HOME/"
    cp "$REPO_DIR/src/vigilant_addon.py" "$VIGILANT_HOME/addons/"
    
    log_info "Copying templates..."
    cp "$REPO_DIR/src/templates/dashboard.html" "$VIGILANT_HOME/templates/"
    
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
    
    log_info "Applying netplan configuration..."
    cp "$REPO_DIR/src/config/netplan-config.yaml" /etc/netplan/00-installer-config.yaml
    
    log_info "Applying netplan changes..."
    netplan generate > /dev/null 2>&1
    netplan apply > /dev/null 2>&1
    log_success "Network configured"
}

# ─── Stage 6: DNS/DHCP Setup ────────────────────────────────────────────────
stage_6_dns_dhcp() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 6: DNS/DHCP CONFIGURATION"
    log_info "═══════════════════════════════════════════"
    
    log_info "Backing up dnsmasq.conf..."
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
    
    log_info "Generating dnsmasq.conf with dynamic interface..."
    sed "s/interface=enp0s6/interface=$LAN_INTERFACE/g" "$REPO_DIR/src/config/dnsmasq.conf" > /tmp/dnsmasq-vigilant.conf
    cat /tmp/dnsmasq-vigilant.conf > /etc/dnsmasq.conf
    rm /tmp/dnsmasq-vigilant.conf
    
    log_info "Restarting dnsmasq..."
    systemctl restart dnsmasq
    
    log_info "Configuring logrotate for dnsmasq..."
    cat > /etc/logrotate.d/dnsmasq << 'EOF'
/var/log/dnsmasq.log {
    daily
    copytruncate
    rotate 7
    compress
    missingok
    notifempty
}
EOF
    
    log_info "Validating logrotate configuration..."
    if logrotate -d /etc/logrotate.d/dnsmasq > /dev/null 2>&1; then
        log_success "Logrotate configuration validated"
    else
        log_warn "Logrotate configuration validation failed (may be non-critical)"
    fi
    
    log_success "DNS/DHCP configured"
}

# ─── Stage 7: Firewall Setup ────────────────────────────────────────────────
stage_7_firewall() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 7: FIREWALL RULES"
    log_info "═══════════════════════════════════════════"
    
    # FIX: Save the chosen interfaces to an environment file for Systemd to read later
    log_info "Saving network interface environment variables for systemd..."
    cat << EOF > "$VIGILANT_HOME/.env"
WAN_INTERFACE=$WAN_INTERFACE
LAN_INTERFACE=$LAN_INTERFACE
EOF
    chown "$VIGILANT_USER:$VIGILANT_USER" "$VIGILANT_HOME/.env"

    log_info "Applying iptables rules with dynamic interfaces..."
    WAN_INTERFACE="$WAN_INTERFACE" LAN_INTERFACE="$LAN_INTERFACE" bash "$VIGILANT_HOME/scripts/setup-iptables.sh"
    log_success "Firewall rules applied"
}

stage_7_5_hostapd() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 7.5: HOSTAPD ACCESS POINT SETUP"
    log_info "═══════════════════════════════════════════"
    
    log_info "Creating hostapd configuration file..."
    cat << 'EOF' > /etc/hostapd/hostapd.conf
interface=wlp1s0
driver=nl80211
ssid=VIGILANT_GATEWAY
hw_mode=g
channel=6
wmm_enabled=1
macaddr_acl=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=VigilantGateway2026
EOF

    log_info "Updating system default hostapd daemon reference..."
    if [ -f /etc/default/hostapd ]; then
        sed -i 's|^#\?DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
    else
        echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' > /etc/default/hostapd
    fi

    log_info "Unmasking, enabling, and kickstarting hostapd broadcast..."
    systemctl unmask hostapd >/dev/null 2>&1
    systemctl daemon-reload
    systemctl enable hostapd
    systemctl restart hostapd
    
    log_success "Hostapd Access Point is live!"
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
        mitmdump --version > /dev/null
    "
    log_success "Certificates generated"
}

# ─── Stage 9: Systemd Services ──────────────────────────────────────────────
stage_9_systemd_services() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 9: SYSTEMD SERVICES"
    log_info "═══════════════════════════════════════════"
    
    log_info "Installing systemd services..."
    cp "$REPO_DIR/src/systemd/vigilant-firewall.service" /etc/systemd/system/
    cp "$REPO_DIR/src/systemd/vigilant-proxy.service" /etc/systemd/system/
    cp "$REPO_DIR/src/systemd/vigilant-dashboard.service" /etc/systemd/system/
    
    # FIX: Inject the EnvironmentFile dependency directly into the firewall service definition
    log_info "Configuring environment dependencies for vigilant-firewall.service..."
    sed -i "/\[Service\]/a EnvironmentFile=$VIGILANT_HOME/.env" /etc/systemd/system/vigilant-firewall.service

    log_info "Reloading systemd daemon..."
    systemctl daemon-reload
    
    log_info "Enabling services for auto-start..."
    systemctl enable vigilant-firewall vigilant-proxy vigilant-dashboard
    log_success "Services installed and enabled"
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
    stage_10_verify
    stage_11_start_services
    stage_12_status
}

main "$@"
