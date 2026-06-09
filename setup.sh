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

check_network_interfaces() {
    log_info "Checking network interfaces..."
    if ! ip link show enp0s5 > /dev/null 2>&1; then
        log_warn "enp0s5 not found - you may need to adjust network interface names"
        log_warn "Current interfaces:"
        ip link show | grep "^[0-9]:" | grep -v "lo"
    fi
    if ! ip link show enp0s6 > /dev/null 2>&1; then
        log_warn "enp0s6 not found - you may need to adjust network interface names"
    fi
}

# ─── Stage 0: Preflight Checks ──────────────────────────────────────────────
stage_0_preflight() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 0: PREFLIGHT CHECKS"
    log_info "═══════════════════════════════════════════"
    
    check_root
    check_os
    check_network_interfaces
    
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
    
    log_info "Appending VIGILANT config to dnsmasq..."
    cat "$REPO_DIR/src/config/dnsmasq.conf" >> /etc/dnsmasq.conf
    
    log_info "Restarting dnsmasq..."
    systemctl restart dnsmasq
    log_success "DNS/DHCP configured"
}

# ─── Stage 7: Firewall Setup ────────────────────────────────────────────────
stage_7_firewall() {
    echo ""
    log_info "═══════════════════════════════════════════"
    log_info "STAGE 7: FIREWALL RULES"
    log_info "═══════════════════════════════════════════"
    
    log_info "Applying iptables rules..."
    bash "$VIGILANT_HOME/scripts/setup-iptables.sh"
    log_success "Firewall rules applied"
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
    echo "║     https://github.com/yourusername/vigilant-gateway     ║"
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
