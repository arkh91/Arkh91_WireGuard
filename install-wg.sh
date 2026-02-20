#!/bin/bash
# WireGuard + Secure Hidden API Installer / Manager (Production-ready with HTTPS)
# Ubuntu/Debian - menu + CLI + Caddy HTTPS + Bearer token auth

set -e

# ────────────────────────────────────────────────
# Defaults
# ────────────────────────────────────────────────
WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.66.0/24"
API_PORT_INTERNAL=3001           # Node listens here (localhost only)
API_DIR="/opt/wg-api"
API_SERVICE="wg-api.service"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
OUT_IFACE=""
CADDY_PORT=443                   # public HTTPS port
DOMAIN=""                        # will ask during install

# ────────────────────────────────────────────────
# Parse CLI args
# ────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port=*) WG_PORT="${1#*=}" ; shift ;;
            --api-port=*) API_PORT_INTERNAL="${1#*=}" ; shift ;;
            --uninstall|-u|--remove) ACTION="uninstall" ; shift ;;
            --help|-h) show_help ; exit 0 ;;
            *) echo "Unknown option: $1" ; echo "Use --help" ; exit 1 ;;
        esac
    done
}

show_help() {
    cat <<EOF
Usage: sudo $0 [options]

Options (non-interactive):
  --port=51830              WireGuard UDP port
  --api-port=8080           Internal API port (Node.js)
  --uninstall               Uninstall
  --help                    This help

Without args → interactive menu

Examples:
  sudo $0
  sudo $0 --port=51830
  sudo $0 --uninstall
EOF
}

# ────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────

check_root() {
    [ "$EUID" -ne 0 ] && { echo "Run as root."; exit 1; }
}

detect_out_iface() {
    OUT_IFACE=$(ip -4 route show default | awk '{print $5; exit}')
    [ -z "$OUT_IFACE" ] && OUT_IFACE="eth0"
    echo "Outbound interface: $OUT_IFACE"
}

ask_domain() {
    echo ""
    echo "For production HTTPS you NEED a domain (e.g. api.vpn.yourdomain.com)"
    echo "Point A record to this server's public IP."
    echo ""
    read -rp "Enter your domain for the API: " DOMAIN
    if [[ -z "$DOMAIN" ]]; then
        echo "Domain is required for secure install. Aborting."
        exit 1
    fi
}

install() {
    check_root
    detect_out_iface

    if [[ -z "$DOMAIN" ]]; then
        ask_domain
    fi

    echo "Installing packages (WireGuard + Node + Caddy)..."
    apt update -y
    apt install -y wireguard iptables iptables-persistent nodejs npm curl openssl

    # Install Caddy (official repo method 2025+)
    install -m 0755 -d /etc/apt/keyrings
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /etc/apt/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
    apt update -y
    apt install -y caddy

    # WireGuard server setup (same as before)
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

    sysctl -w net.ipv4.ip_forward=1
    sed -i 's/^#\{0,1\}net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

    iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
    iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE
    netfilter-persistent save

    systemctl enable --now wg-quick@"$WG_INTERFACE"

    # ─── Secure API ───
    echo "Setting up secure API (localhost only + Bearer auth)..."

    # Create non-root user
    id wgapi 2>/dev/null || useradd -r -s /usr/sbin/nologin wgapi

    mkdir -p "$API_DIR"
    chown wgapi:wgapi "$API_DIR"
    cd "$API_DIR"

    npm init -y >/dev/null 2>&1
    npm install express express-rate-limit helmet >/dev/null 2>&1

    SERVER_IP=$(curl -s ifconfig.me || echo "your-public-ip")
    API_TOKEN=$(openssl rand -hex 32)   # Strong Bearer token

    cat > server.js <<EOF
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { execSync } = require('child_process');
const fs = require('fs');
const app = express();

app.use(helmet());
app.use(express.json());

// Rate limit: 60 req / 15 min per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { error: 'Too many requests, try again later.' }
});
app.use(limiter);

// Bearer token auth
const API_TOKEN = '$API_TOKEN';
app.use((req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || auth !== \`Bearer \${API_TOKEN}\`) {
    return res.status(401).json({ error: 'Unauthorized - invalid or missing token' });
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
  console.log('Secure API running on localhost:$API_PORT_INTERNAL');
});
EOF

    chown -R wgapi:wgapi "$API_DIR"

    # Systemd service (non-root)
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

    # ─── Caddy reverse proxy + automatic HTTPS ───
    cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
    reverse_proxy 127.0.0.1:$API_PORT_INTERNAL

    # Optional: log requests
    log {
        output file /var/log/caddy/api.log
    }

    # Optional: security headers (already using helmet in Express, but extra layer)
    header {
        Strict-Transport-Security "max-age=31536000;"
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
    }
}
EOF

    systemctl reload-or-restart caddy

    # Final output
    cat <<EOF


==========================================
       SECURE WireGuard API Installed!
==========================================

Domain:          https://$DOMAIN
API Token (Bearer):   $API_TOKEN

Create client:
curl -X POST https://$DOMAIN/create \\
  -H "Authorization: Bearer $API_TOKEN" \\
  -H "Content-Type: application/json"

Remove client (example):
curl -X POST https://$DOMAIN/remove \\
  -H "Authorization: Bearer $API_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"publicKey": "abc...xyz="}'

Security features:
- HTTPS automatic (Let's Encrypt via Caddy)
- Bearer token auth (no secret path)
- Rate limiting
- Helmet security headers
- Runs as non-root user
- Node listens only on localhost

Keep the token secret!
Renewal is automatic via Caddy.

EOF
}

uninstall() {
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

    echo "Uninstall complete."
    echo "Caddy, WireGuard, Node packages still installed."
    echo "Remove manually if desired: apt remove caddy wireguard nodejs npm iptables-persistent"
}

show_usage() {
    cat <<EOF

Usage Examples:

Interactive:
    sudo ./install-wg.sh

Direct install (custom ports):
    sudo ./install-wg.sh --port=51830

Uninstall:
    sudo ./install-wg.sh --uninstall

Note: During first install you'll be asked for a domain name for HTTPS.
EOF
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
        3) show_usage ; read -rp "Press Enter..." ;;
        0) echo "Goodbye!"; exit 0 ;;
        *) echo "Invalid."; sleep 1 ;;
    esac
}

# ─── Main ───
check_root
parse_args "$@"

if [ -n "$ACTION" ]; then
    [ "$ACTION" = "uninstall" ] && uninstall || install
    exit 0
fi

while true; do
    show_menu
done
