#!/bin/bash
# WireGuard + Hidden API Installer / Manager
# Ubuntu/Debian - with menu + command-line support

set -e

# ────────────────────────────────────────────────
# Default configuration
# ────────────────────────────────────────────────
WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.66.0/24"
API_PORT=3000
API_DIR="/opt/wg-api"
API_SERVICE="wg-api.service"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
OUT_IFACE=""   # will be auto-detected

# ────────────────────────────────────────────────
# Parse command-line arguments
# ────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port=*)
                WG_PORT="${1#*=}"
                shift
                ;;
            --api-port=*)
                API_PORT="${1#*=}"
                shift
                ;;
            --uninstall|-u|--remove)
                ACTION="uninstall"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use --help for usage."
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat <<EOF
Usage: sudo $0 [options]

Options (non-interactive mode):
  --port=51830            Set WireGuard UDP port (default: 51820)
  --api-port=8080         Set API HTTP port (default: 3000)
  --uninstall             Uninstall WireGuard + API (non-interactive)
  --help                  Show this help message

When run without arguments: shows interactive menu.

Examples:
  sudo $0                             # Interactive menu
  sudo $0 --port=51830 --api-port=8080  # Install with custom ports
  sudo $0 --uninstall                 # Uninstall everything
EOF
}

# ────────────────────────────────────────────────
# Helper functions
# ────────────────────────────────────────────────

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi
}

detect_out_iface() {
    OUT_IFACE=$(ip -4 route show default | awk '{print $5; exit}')
    if [ -z "$OUT_IFACE" ]; then
        echo "Warning: Could not detect outbound interface. Using 'eth0' fallback."
        OUT_IFACE="eth0"
    fi
}

install() {
    detect_out_iface
    echo "Detected outbound interface: $OUT_IFACE"

    echo "Installing required packages..."
    apt update -y
    apt install -y wireguard iptables iptables-persistent nodejs npm curl openssl

    echo "Generating server keys..."
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

    mkdir -p /etc/wireguard
    cat > "$WG_CONFIG" <<EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = true
EOF
    chmod 600 "$WG_CONFIG"

    # IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    sed -i 's/^#\{0,1\}net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

    # Firewall
    echo "Setting up firewall rules..."
    iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -A INPUT -p tcp --dport "$API_PORT" -j ACCEPT
    iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
    iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE
    netfilter-persistent save

    systemctl enable --now wg-quick@"$WG_INTERFACE"

    # API Server
    echo "Setting up Hidden API..."
    mkdir -p "$API_DIR"
    cd "$API_DIR" || exit 1

    npm init -y >/dev/null 2>&1
    npm install express >/dev/null 2>&1

    SERVER_IP=$(curl -s ifconfig.me || echo "your-public-ip")
    API_SECRET=$(openssl rand -hex 16)

    cat > server.js <<'EOF'
const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const app = express();
app.use(express.json());

const WG_INTERFACE = "$WG_INTERFACE";
const WG_CONFIG = "$WG_CONFIG";
const SERVER_IP = "$SERVER_IP";
const SERVER_PUBLIC_KEY = "$SERVER_PUBLIC_KEY";
const WG_PORT = "$WG_PORT";
const BASE_IP = "10.66.66.";
const API_SECRET = "$API_SECRET";

function getNextIP() {
  const config = fs.readFileSync(WG_CONFIG, 'utf8');
  const matches = config.match(/10\\.66\\.66\\.(\\d+)/g) || [];
  const used = matches.map(ip => parseInt(ip.split('.').pop()));
  const next = used.length ? Math.max(...used) + 1 : 2;
  if (next > 254) throw new Error("IP range exhausted (10.66.66.2-254)");
  return BASE_IP + next;
}

app.post('/api/' + API_SECRET, (req, res) => {
  const { action, publicKey } = req.body;
  try {
    if (action === "create") {
      const privateKey = execSync('wg genkey').toString().trim();
      const publicKey = execSync(`echo ${privateKey} | wg pubkey`).toString().trim();
      const clientIP = getNextIP();

      const peerBlock = `
[Peer]
PublicKey = ${publicKey}
AllowedIPs = ${clientIP}/32
`;
      fs.appendFileSync(WG_CONFIG, peerBlock);
      execSync(`wg set ${WG_INTERFACE} peer ${publicKey} allowed-ips ${clientIP}/32`);

      const clientConfig = `
[Interface]
PrivateKey = ${privateKey}
Address = ${clientIP}/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${SERVER_IP}:${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`.trim();

      return res.json({ success: true, config: clientConfig });
    }

    if (action === "remove" && publicKey) {
      execSync(`wg set ${WG_INTERFACE} peer ${publicKey} remove`);
      return res.json({ success: true });
    }

    return res.status(400).json({ error: "Invalid action or missing publicKey" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.listen($API_PORT, () => {
  console.log(`API listening on port $API_PORT`);
});
EOF

    cat > "/etc/systemd/system/$API_SERVICE" <<EOF
[Unit]
Description=WireGuard Hidden API
After=network.target

[Service]
ExecStart=/usr/bin/node $API_DIR/server.js
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$API_SERVICE"

    cat <<EOF


==========================================
 WireGuard + Hidden API Installed!
==========================================

API Endpoint:
http://$SERVER_IP:$API_PORT/api/$API_SECRET

Create client example:
curl -X POST http://$SERVER_IP:$API_PORT/api/$API_SECRET -H "Content-Type: application/json" -d '{"action":"create"}'

Keep /api/$API_SECRET secret!
Consider adding HTTPS + auth in production.
EOF
}

uninstall() {
    echo "Uninstalling WireGuard + Hidden API..."

    systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    systemctl disable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    systemctl stop "$API_SERVICE" 2>/dev/null || true
    systemctl disable "$API_SERVICE" 2>/dev/null || true

    rm -f "/etc/systemd/system/$API_SERVICE"
    rm -rf "$API_DIR"
    rm -f "$WG_CONFIG"

    iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D INPUT -p tcp --dport "$API_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null || true

    netfilter-persistent save 2>/dev/null || true

    systemctl daemon-reload

    echo "Uninstall complete."
    echo "Packages (wireguard, nodejs, etc.) are still installed."
    echo "Remove manually if desired: apt remove wireguard nodejs npm iptables-persistent"
}

show_usage() {
    cat <<EOF

Usage Examples:

Interactive mode (recommended for first use):
    sudo ./install-wg.sh

Direct install with custom ports (non-interactive):
    sudo ./install-wg.sh --port=51830 --api-port=8080

Direct uninstall (non-interactive):
    sudo ./install-wg.sh --uninstall

Show this help:
    sudo ./install-wg.sh --help

Note: 
- All commands require root privileges (sudo)
- Custom ports are only applied during install
- The API secret is randomly generated each install

EOF
}

# ────────────────────────────────────────────────
# Interactive Menu
# ────────────────────────────────────────────────

show_menu() {
    clear
    echo "======================================"
    echo "     Welcome to WireGuard Manager     "
    echo "======================================"
    echo ""
    echo "1) Install WireGuard server + Hidden API"
    echo "2) Uninstall WireGuard server + API"
    echo "3) Usage"
    echo "0) Exit"
    echo ""
    echo -n "Choose an option: "
}

# ────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────

check_root
parse_args "$@"

# Non-interactive mode if arguments provided
if [ -n "$ACTION" ]; then
    if [ "$ACTION" = "uninstall" ]; then
        uninstall
    else
        install
    fi
    exit 0
fi

# Interactive loop
while true; do
    show_menu
    read -r choice

    case "$choice" in
        1)
            install
            echo -e "\nPress Enter to continue..."
            read -r
            ;;
        2)
            uninstall
            echo -e "\nPress Enter to continue..."
            read -r
            ;;
        3)
            show_usage
            echo -e "\nPress Enter to continue..."
            read -r
            ;;
        0)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice."
            sleep 1
            ;;
    esac
done
