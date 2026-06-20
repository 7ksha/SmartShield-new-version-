#!/usr/bin/env bash
# ============================================================================
# SmartShield Factory Installation Script
# ============================================================================
# Installs SmartShield on a bare-metal Ubuntu 22.04 / 24.04 server that
# will be placed at the IT/OT network boundary (DMZ).
#
# Run as root:
#   chmod +x install/install_factory.sh
#   sudo ./install/install_factory.sh
#
# What this script does:
#   1. Installs system dependencies (Zeek 8, Python 3, Redis, iptables)
#   2. Copies SmartShield to /opt/smartshield
#   3. Installs Python requirements
#   4. Creates persistent storage directories
#   5. Sets up systemd service
#   6. Prompts for interface name and credentials
#   7. Enables and starts the service
# ============================================================================

set -euo pipefail

INSTALL_DIR="/opt/smartshield"
CONFIG_DIR="/etc/smartshield"
DATA_DIR="/var/lib/smartshield"
LOG_DIR="/var/log/smartshield"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${BLUE}[INFO]${RESET} $*"; }
success() { echo -e "${GREEN}[OK]${RESET}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERR]${RESET}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; \
            echo -e "${BOLD}  $*${RESET}"; \
            echo -e "${BOLD}${BLUE}══════════════════════════════════════════${RESET}"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && error "Please run as root: sudo $0"

header "SmartShield Factory Installation"

# ── 1. System dependencies ───────────────────────────────────────────────────
info "Installing system packages..."
apt-get update -q
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    iptables iptables-persistent \
    curl wget git unzip \
    libpcap-dev tcpdump \
    lsb-release software-properties-common \
    net-tools iproute2 \
    redis-server \
    2>/dev/null

# ── 2. Zeek 8 ────────────────────────────────────────────────────────────────
if ! command -v zeek &>/dev/null && ! command -v bro &>/dev/null; then
    info "Installing Zeek 8..."
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        | tee /etc/apt/sources.list.d/security:zeek.list
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor \
        | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    apt-get update -q
    apt-get install -y zeek-8.0 2>/dev/null
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek 2>/dev/null || true
    ln -sf /opt/zeek/bin/zeek /usr/local/bin/bro 2>/dev/null || true
    success "Zeek installed: $(zeek --version 2>&1 | head -1)"
else
    success "Zeek already installed: $(zeek --version 2>&1 | head -1)"
fi

# ── 3. Zeek OT packages ──────────────────────────────────────────────────────
info "Installing Zeek OT protocol packages via zkg..."
if command -v zkg &>/dev/null; then
    zkg install zeek/DINA-community/ICS-Passive-Discovery 2>/dev/null || warn "zkg install failed (non-fatal)"
else
    warn "zkg not found — Zeek OT packages not installed. Conn.log-based OT detection still active."
fi

# ── 4. Create directories ─────────────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR/redis" "$DATA_DIR/output" "$LOG_DIR"
chmod 700 "$CONFIG_DIR"

# ── 5. Copy SmartShield ───────────────────────────────────────────────────────
info "Copying SmartShield to $INSTALL_DIR ..."
rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    "$SCRIPT_DIR/" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/smartshield.py"

# ── 6. Python requirements ───────────────────────────────────────────────────
info "Installing Python requirements..."
pip3 install --no-cache-dir --upgrade pip -q
pip3 install --no-cache-dir -r "$INSTALL_DIR/install/requirements.txt" -q \
    || warn "Some Python packages may have failed — check manually"
pip3 install --no-cache-dir requests flask flask-login -q

# ── 7. Redis configuration ────────────────────────────────────────────────────
info "Configuring Redis (with persistence)..."
cp "$INSTALL_DIR/config/redis.conf" /etc/redis/redis.conf
chown redis:redis /etc/redis/redis.conf
systemctl enable redis-server 2>/dev/null || true
systemctl restart redis-server
success "Redis configured with AOF persistence"

# ── 8. Gather deployment info from user ──────────────────────────────────────
header "Factory Configuration"

# Network interface
echo ""
info "Available network interfaces:"
ip -o link show | awk -F': ' '{print "  " $2}' | grep -v lo
echo ""
read -rp "$(echo -e "${BOLD}Enter the SPAN/TAP interface name${RESET} (e.g. eth1): ")" IFACE
[[ -z "$IFACE" ]] && error "Interface name cannot be empty"
ip link show "$IFACE" &>/dev/null || warn "Interface $IFACE not found — verify after install"

# Web credentials
echo ""
read -rp "$(echo -e "${BOLD}Web interface username${RESET} [admin]: ")" WEB_USER
WEB_USER="${WEB_USER:-admin}"
while true; do
    read -rsp "$(echo -e "${BOLD}Web interface password${RESET} (min 12 chars): ")" WEB_PASS
    echo ""
    [[ ${#WEB_PASS} -ge 12 ]] && break
    warn "Password must be at least 12 characters."
done

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# ── 9. Write environment file ─────────────────────────────────────────────────
info "Writing environment config to $CONFIG_DIR/environment ..."
cat > "$CONFIG_DIR/environment" <<EOF
# SmartShield factory environment — generated by install_factory.sh
# DO NOT commit to git.
SMARTSHIELD_INTERFACE=${IFACE}
SMARTSHIELD_WEB_USER=${WEB_USER}
SMARTSHIELD_WEB_PASSWORD=${WEB_PASS}
SMARTSHIELD_SECRET_KEY=${SECRET_KEY}
EOF
chmod 600 "$CONFIG_DIR/environment"

# ── 10. OT config reminder ───────────────────────────────────────────────────
echo ""
warn "ACTION REQUIRED: Edit these files with your factory's actual device IPs:"
echo "  $INSTALL_DIR/config/ot_protected_devices.conf"
echo "  $INSTALL_DIR/config/modbus_authorized_masters.conf"
echo "  $INSTALL_DIR/config/whitelist.conf"

# ── 11. Symlink config to /etc/smartshield ───────────────────────────────────
cp "$INSTALL_DIR/config/smartshield.yaml" "$CONFIG_DIR/smartshield.yaml"
info "Config copied to $CONFIG_DIR/smartshield.yaml"

# ── 12. Install systemd service ──────────────────────────────────────────────
info "Installing systemd service..."
cp "$INSTALL_DIR/install/smartshield.service" /etc/systemd/system/smartshield.service
systemctl daemon-reload
systemctl enable smartshield

# ── 13. iptables persistence ─────────────────────────────────────────────────
info "Enabling iptables persistence..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
systemctl enable netfilter-persistent 2>/dev/null || true

# ── 14. Start ────────────────────────────────────────────────────────────────
echo ""
read -rp "$(echo -e "${BOLD}Start SmartShield now?${RESET} [Y/n]: ")" START_NOW
if [[ "${START_NOW:-y}" =~ ^[Yy]$ ]]; then
    systemctl start smartshield
    sleep 3
    if systemctl is-active --quiet smartshield; then
        success "SmartShield is running!"
    else
        warn "SmartShield may not have started cleanly. Check: journalctl -u smartshield -f"
    fi
fi

header "Installation Complete"
echo ""
echo -e "  ${BOLD}Web interface:${RESET}     http://$(hostname -I | awk '{print $1}'):55000"
echo -e "  ${BOLD}Logs:${RESET}              journalctl -u smartshield -f"
echo -e "  ${BOLD}Status:${RESET}            systemctl status smartshield"
echo -e "  ${BOLD}Restart:${RESET}           systemctl restart smartshield"
echo -e "  ${BOLD}Stop:${RESET}              systemctl stop smartshield"
echo -e "  ${BOLD}OT config:${RESET}         $INSTALL_DIR/config/ot_protected_devices.conf"
echo ""
echo -e "${YELLOW}  Remember: add your factory's OT device IPs to ot_protected_devices.conf${RESET}"
echo -e "${YELLOW}  before enabling blocking in production.${RESET}"
echo ""
