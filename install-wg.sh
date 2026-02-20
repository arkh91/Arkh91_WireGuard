#!/bin/bash
# WireGuard + Secure HTTPS API Installer / Manager (Production-ready, modular)
# Ubuntu/Debian - menu + CLI + Caddy + Bearer token

set -e

# ────────────────────────────────────────────────
# Configuration / Globals
# ────────────────────────────────────────────────
WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.66.0/24"
API_PORT_INTERNAL=3001           # Node.js localhost port
API_DIR="/opt/wg-api"
API_SERVICE="wg-api.service"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
OUT_IFACE=""
DOMAIN=""
CADDY_PORT=443

# ────────────────────────────────────────────────
# CLI Argument Parsing
# ────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port=*)           WG_PORT="${1#*=}" ; shift ;;
            --api-port=*)       API_PORT_INTERNAL="${1#*=}" ; shift ;;
            --uninstall|-u|--remove) ACTION="uninstall" ; shift ;;
            --help|-h)          show_help ; exit 0 ;;
            *) echo "Unknown: $1" ; echo "Use --help" ; exit 1 ;;
        esac
    done
}

show_help() {
    cat <<EOF
Usage: sudo $0 [options]

Options:
  --port=51830          WireGuard UDP port
  --api-port=4000       Internal Node.js port (localhost)
  --uninstall           Remove setup
  --help                This message

No args → interactive menu
EOF
}

# ────────────────────────────────────────────────
# Utility Helpers
# ────────────────────────────────────────────────

check_root() {
    [ "$EUID" -ne 0 ] && { echo "Must run as root."; exit 1; }
}

detect_out_iface() {
    OUT_IFACE=$(ip -4 route show default | awk '{print $5; exit}' || echo "eth0")
    echo "→ Outbound interface: $OUT_IFACE"
}

ask_for_domain() {
    echo ""
    echo "HTTPS requires a domain (e.g. api.vpn.yourdomain.com)"
    echo "Make sure A record points to this server's public IP."
    echo ""
    read -rp "Domain: " DOMAIN
    [[ -z "$DOMAIN" ]] && { echo "Domain required. Aborting."; exit 1; }
}

# ────────────────────────────────────────────────
# Installation Steps (Modular Functions)
# ────────────────────────────────────────────────

install_packages() {
    echo "→ Updating package list and installing dependencies..."
    apt update -y
    apt install -y wireguard iptables iptables-persistent nodejs npm curl openssl
}

install_caddy() {
    echo "→ Installing Caddy (automatic HTTPS)..."
    install -m 0755 -d /etc/apt/keyrings
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    apt update -y
    apt install -y caddy
}

setup_wireguard_keys_and_config() {
    echo "→ Generating WireGuard server keys and config..."
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
}

enable_ip_forwarding() {
    echo "→ Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    sed -i 's/^#\{0,1\}net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
}

setup_firewall_rules() {
    echo "→ Configuring iptables rules..."
    iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
    iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE
    netfilter-persistent save
}

start_wireguard() {
    echo "→ Enabling and starting WireGuard..."
    systemctl enable --now wg-quick@"$WG_INTERFACE"
}

create_api_user() {
    echo "→ Creating non-root API user (wgapi)..."
    id wgapi 2>/dev/null || useradd -r -s /usr/sbin/nologin wgapi
}

setup_api_directory_and_npm() {
    echo "→ Setting up API directory and installing npm packages..."
    mkdir -p "$API_DIR"
    chown wgapi:wgapi "$API_DIR"
    cd "$API_DIR" || exit 1

    npm init -y >/dev/null 2>&1
    npm install express express-rate-limit helmet >/dev/null 2>&1
}

generate_api_token() {
    API_TOKEN=$(openssl rand -hex 32)
    echo "→ Generated API Bearer token: $API_TOKEN"
}

write_api_server_js() {
    echo "→ Writing secure Node.js API server (localhost only)..."
    SERVER_IP=$(curl -s ifconfig.me || echo "your-public-ip")

    cat > server.js <<EOF
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { execSync } = require('child_process');
const fs = require('fs');

const app = express();
app.use(helmet());
app.use(express.json());

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,
  message: { error: 'Too many requests' }
}));

// Bearer token authentication
const API_TOKEN = '$API_TOKEN';
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || auth !== \`Bearer \${API_TOKEN}\`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

const WG_INTERFACE = '$WG_INTERFACE';
const WG_CONFIG = '$WG_CONFIG';
const SERVER_IP = '$SERVER_IP';
const SERVER_PUBLIC_KEY = '$SERVER_PUBLIC_KEY';
const WG_PORT = '$WG_PORT';
const BASE_IP = '10.66.66.';

function getNextIP() {
  const config = fs.readFileSync(WG_CONFIG, 'utf8');
  const matches = config.match(/10\\.66\\.66\\.(\\d+)/g) || [];
  const used = matches.map(ip => parseInt(ip.split('.').pop()));
  const next = used.length ? Math.max(...used) + 1 : 2;
  if (next > 254) throw new Error('IP range exhausted');
  return BASE_IP + next;
}

app.post('/create', (req, res) => {
  try {
    const privateKey = execSync('wg genkey').toString().trim();
    const publicKey = execSync(\`echo \${privateKey} | wg pubkey\`).toString().trim();
    const clientIP = getNextIP();

    const peerBlock = \`
[Peer]
PublicKey = \${publicKey}
AllowedIPs = \${clientIP}/32
\`;
    fs.appendFileSync(WG_CONFIG, peerBlock);
    execSync(\`wg set \${WG_INTERFACE} peer \${publicKey} allowed-ips \${clientIP}/32\`);

    const clientConfig = \`
[Interface]
PrivateKey = \${privateKey}
Address = \${clientIP}/32
DNS = 1.1.1.1

[Peer]
PublicKey = \${SERVER_PUBLIC_KEY}
Endpoint = \${SERVER_IP}:\${WG_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
\`.trim();

    res.json({ success: true, config: clientConfig });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/remove', (req, res) => {
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error: 'publicKey required' });
  try {
    execSync(\`wg set \${WG_INTERFACE} peer \${publicKey} remove\`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen($API_PORT_INTERNAL, '127.0.0.1', () => {
  console.log('API running on localhost:$API_PORT_INTERNAL');
});
EOF

    chown -R wgapi:wgapi "$API_DIR"
}

create_api_systemd_service() {
    echo "→ Creating systemd service for API (non-root)..."
    cat > "/etc/systemd/system/$API_SERVICE" <<EOF
[Unit]
Description=WireGuard Secure API
After=network.target

[Service]
ExecStart=/usr/bin/node $API_DIR/server.js
Restart=always
User=wgapi
Group=wgapi
WorkingDirectory=$API_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now "$API_SERVICE"
}

configure_caddy() {
    echo "→ Configuring Caddy reverse proxy + automatic HTTPS..."
    cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    reverse_proxy 127.0.0.1:$API_PORT_INTERNAL

    log {
        output file /var/log/caddy/api.log
    }

    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
EOF

    systemctl reload-or-restart caddy
}

print_final_instructions() {
    cat <<EOF


==========================================
       SECURE WireGuard API READY
==========================================

Domain:          https://$DOMAIN
Bearer Token:    $API_TOKEN

Create client:
curl -X POST https://$DOMAIN/create \\
  -H "Authorization: Bearer $API_TOKEN" \\
  -H "Content-Type: application/json"

Remove client:
curl -X POST https://$DOMAIN/remove \\
  -H "Authorization: Bearer $API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"publicKey": "your-public-key-here"}'

Features:
- HTTPS (Let's Encrypt auto-renew)
- Bearer token auth
- Rate limiting
- Security headers
- Non-root execution
- Localhost-only Node.js

Keep token secret. Logs: /var/log/caddy/api.log + journalctl -u $API_SERVICE
EOF
}

# ────────────────────────────────────────────────
# Main Install Orchestrator
# ────────────────────────────────────────────────

install() {
    echo "Starting secure WireGuard + HTTPS API installation..."

    detect_out_iface
    ask_for_domain

    install_packages
    install_caddy
    setup_wireguard_keys_and_config
    enable_ip_forwarding
    setup_firewall_rules
    start_wireguard
    create_api_user
    setup_api_directory_and_npm
    generate_api_token
    write_api_server_js
    create_api_systemd_service
    configure_caddy
    print_final_instructions

    echo ""
    echo "Installation completed successfully."
}

# ────────────────────────────────────────────────
# Uninstall (kept simple for now)
# ────────────────────────────────────────────────

uninstall() {
    echo "Uninstalling WireGuard + Secure API..."

    systemctl stop wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    systemctl disable wg-quick@"$WG_INTERFACE" 2>/dev/null || true
    systemctl stop "$API_SERVICE" 2>/dev/null || true
    systemctl disable "$API_SERVICE" 2>/dev/null || true
    systemctl stop caddy 2>/dev/null || true

    rm -f "/etc/systemd/system/$API_SERVICE"
    rm -rf "$API_DIR"
    rm -f "$WG_CONFIG"
    rm -f /etc/caddy/Caddyfile

    iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$WG_INTERFACE" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null || true

    netfilter-persistent save 2>/dev/null || true
    systemctl daemon-reload

    echo "Uninstall finished."
    echo "Packages (caddy, wireguard, nodejs, ...) still present."
}

# ────────────────────────────────────────────────
# Menu
# ────────────────────────────────────────────────

show_menu() {
    clear
    echo "======================================"
    echo "     Secure WireGuard Manager        "
    echo "======================================"
    echo ""
    echo "1) Install WireGuard + Secure HTTPS API"
    echo "2) Uninstall"
    echo "3) Usage"
    echo "0) Exit"
    echo ""
    read -rp "Choose: " choice

    case "$choice" in
        1) install ; read -rp "Press Enter..." ;;
        2) uninstall ; read -rp "Press Enter..." ;;
        3) show_help ; read -rp "Press Enter..." ;;
        0) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid."; sleep 1 ;;
    esac
}

# ─── Entry Point ───
check_root
parse_args "$@"

if [ -n "$ACTION" ]; then
    [ "$ACTION" = "uninstall" ] && uninstall || install
    exit 0
fi

while true; do
    show_menu
done
