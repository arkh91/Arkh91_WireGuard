#!/bin/bash
# WireGuard + Secure HTTPS API Installer / Manager
# Ubuntu/Debian – modular, production-ready with Caddy + Bearer token
# Version: re-done clean – February 2025 style

set -e

# ────────────────────────────────────────────────
# Configuration defaults
# ────────────────────────────────────────────────

WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.66.0/24"
API_PORT_INTERNAL=4242           # Node.js listens here (localhost only)
API_DIR="/opt/wg-api"
API_SERVICE="wg-api.service"
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
OUT_IFACE=""
DOMAIN=""
CADDY_PORT=443

# ────────────────────────────────────────────────
# Utility functions
# ────────────────────────────────────────────────

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi
}

detect_outbound_interface() {
    OUT_IFACE=$(ip -4 route show default | awk '{print $5; exit}' || echo "eth0")
    echo "→ Detected outbound interface: $OUT_IFACE"
}

ask_domain() {
    echo ""
    echo "For automatic HTTPS (Let's Encrypt via Caddy) you need a domain."
    echo "Example: vpn-api.yourdomain.com"
    echo "The A record must point to this server's public IP."
    echo ""
    read -r -p "Enter domain: " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo "Domain is required for secure installation. Aborting."
        exit 1
    fi
}

# ────────────────────────────────────────────────
# Installation steps – each in its own function
# ────────────────────────────────────────────────

step_install_packages() {
    echo "→ Installing required packages..."
    apt update -y
    #apt install -y wireguard iptables iptables-persistent nodejs npm curl openssl
    apt install -y \
        wireguard \
        iptables \
        iptables-persistent \
        nodejs \
        npm \
        curl \
        openssl \
        gnupg \
        sudo
}

step_install_caddy() {
    echo "→ Installing Caddy web server..."

    # Detect OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
    else
        echo "✗ Unable to detect Linux distribution"
        return 1
    fi

    case "$ID" in
        ubuntu|debian|linuxmint|pop|kali|raspbian)
            apt update

            apt install -y \
                debian-keyring \
                debian-archive-keyring \
                apt-transport-https \
                curl \
                gnupg

            # Add Caddy repository - FIXED VERSION
            if [ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
                curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
                    | gpg --dearmor \
                    -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            fi

            # CORRECTED: Use the proper .list file URL, not .deb
            if [ ! -f /etc/apt/sources.list.d/caddy-stable.list ]; then
                echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/ubuntu $(lsb_release -cs) main" > /etc/apt/sources.list.d/caddy-stable.list
            fi

            apt update
            apt install -y caddy
            ;;

        rocky|almalinux|rhel|centos)
            dnf install -y epel-release
            dnf install -y caddy
            ;;

        fedora)
            dnf install -y caddy
            ;;

        arch|manjaro)
            pacman -Sy --noconfirm caddy
            ;;

        opensuse-leap|opensuse-tumbleweed|opensuse)
            zypper --non-interactive refresh
            zypper --non-interactive install caddy
            ;;

        alpine)
            apk add --no-cache caddy
            ;;

        *)
            echo "✗ Unsupported Linux distribution:"
            echo "  $PRETTY_NAME"
            echo
            echo "Falling back to direct package install..."
            apt install -y caddy || dnf install -y caddy || pacman -S --noconfirm caddy || echo "Please install Caddy manually from https://caddyserver.com/download"
            ;;
    esac

    # Verify binary exists
    if ! command -v caddy >/dev/null 2>&1; then
        echo "✗ Caddy binary not found after installation"
        echo "Attempting alternative installation method..."
        
        # Alternative: Download directly from Caddy's website
        curl -fsSL https://caddyserver.com/api/download?os=linux&arch=amd64 -o /tmp/caddy.tar.gz
        tar -xzf /tmp/caddy.tar.gz -C /tmp
        mv /tmp/caddy /usr/bin/
        chmod +x /usr/bin/caddy
        rm /tmp/caddy.tar.gz
    fi

    # Create caddy user if it doesn't exist
    if ! id caddy &>/dev/null; then
        useradd -r -s /usr/sbin/nologin caddy
    fi

    # Create necessary directories
    mkdir -p /etc/caddy /var/log/caddy /var/lib/caddy
    chown -R caddy:caddy /var/log/caddy /var/lib/caddy

    # Enable and start service
    systemctl daemon-reload
    systemctl enable caddy 2>/dev/null || true
    systemctl restart caddy || true

    # Verify service is running
    if systemctl is-active --quiet caddy; then
        echo "✓ Caddy installed successfully"
        echo "  Version: $(caddy version 2>/dev/null || echo 'unknown')"
    else
        echo "⚠️  Caddy installed but service not started"
        echo "  You may need to start it manually: systemctl start caddy"
    fi
}

step_wireguard_keys_config() {
    echo "→ Generating WireGuard server keys and base config..."

    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

    mkdir -p /etc/wireguard

    cat > "$WG_CONFIG" <<END
[Interface]
Address = 10.66.66.1/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
END

    chmod 600 "$WG_CONFIG"

    # Save keys for API use
    echo "$SERVER_PRIVATE_KEY" > /etc/wireguard/server_private.key
    echo "$SERVER_PUBLIC_KEY" > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
    chmod 644 /etc/wireguard/server_public.key

    echo "→ Server public key: $SERVER_PUBLIC_KEY"
}

step_enable_ip_forward() {
    echo "→ Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1
    sed -i 's/^#\{0,1\}net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
}

step_firewall_rules() {
    echo "→ Setting up basic iptables rules..."
    iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -A FORWARD -i "$WG_INTERFACE" -j ACCEPT
    iptables -A FORWARD -o "$WG_INTERFACE" -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE
    netfilter-persistent save
}

step_start_wireguard() {
    echo "→ Enabling & starting WireGuard interface..."
    systemctl enable --now wg-quick@"$WG_INTERFACE"
}

step_create_api_user() {
    echo "→ Creating non-root user for API (wgapi)..."
    id wgapi 2>/dev/null || useradd -r -s /usr/sbin/nologin wgapi
}

step_install_wg_provision() {
    echo "→ Installing wg-provision..."

    cat > /usr/local/bin/wg-provision << 'EOF'
#!/bin/bash
set -e

WG_IF="wg0"
PUBLIC_KEY="$1"
IP="$2"

if [ -z "$PUBLIC_KEY" ] || [ -z "$IP" ]; then
  echo "Usage: wg-provision <public-key> <ip>"
  exit 1
fi

/usr/bin/wg set "$WG_IF" peer "$PUBLIC_KEY" allowed-ips "$IP/32"
EOF

    chmod +x /usr/local/bin/wg-provision
}

step_install_wg_remove() {
  echo "→ Installing wg-remove..."
  cat > /usr/local/bin/wg-remove << 'EOF'
#!/bin/bash
set -e

WG_IF="wg0"
WG_CONFIG="/etc/wireguard/${WG_IF}.conf"
PUBLIC_KEY="$1"

if [ -z "$PUBLIC_KEY" ]; then
  echo "Usage: wg-remove <public-key>"
  exit 1
fi

# ── Step 1: Remove from live interface ──────────
/usr/bin/wg set "$WG_IF" peer "$PUBLIC_KEY" remove
echo "Removed peer from live interface: $PUBLIC_KEY"

# ── Step 2: Remove [Peer] block from config file ─
# Strategy: read the file, skip the block that contains our key,
# write everything else back. Uses awk for reliable multi-line matching.
TMPFILE=$(mktemp)

awk -v key="$PUBLIC_KEY" '
  /^\[Peer\]/ {
    # Buffer this section until we know if it is ours
    block = $0 "\n"
    in_peer = 1
    next
  }
  in_peer {
    # Another section header means the buffered block is done
    if (/^\[/) {
      if (block !~ key) printf "%s", block
      block = ""
      in_peer = 0
      # Fall through and print this new header normally
    } else {
      block = block $0 "\n"
      next
    }
  }
  # Flush buffered peer block at end of file
  END {
    if (in_peer && block !~ key) printf "%s", block
  }
  { print }
' "$WG_CONFIG" > "$TMPFILE"

mv "$TMPFILE" "$WG_CONFIG"
chmod 600 "$WG_CONFIG"

echo "Removed peer block from $WG_CONFIG"
EOF
  chmod +x /usr/local/bin/wg-remove
}

step_configure_sudoers() {
    echo "→ Configuring sudo permissions for wgapi..."

    cat > /etc/sudoers.d/wgapi << 'EOF'
wgapi ALL=(root) NOPASSWD: /usr/local/bin/wg-provision
wgapi ALL=(root) NOPASSWD: /usr/local/bin/wg-remove
EOF

    chmod 440 /etc/sudoers.d/wgapi
}

step_fix_permissions() {
    echo "→ Fixing WireGuard permissions for API access..."
    
    # Add sudo permissions for file operations
    cat >> /etc/sudoers.d/wgapi << 'EOF'

# Allow wgapi to read/write WireGuard config file
wgapi ALL=(root) NOPASSWD: /usr/bin/cat /etc/wireguard/wg0.conf
wgapi ALL=(root) NOPASSWD: /usr/bin/tee -a /etc/wireguard/wg0.conf
wgapi ALL=(root) NOPASSWD: /usr/bin/chmod 600 /etc/wireguard/wg0.conf
EOF

    # Fix sudoers file permissions
    chmod 440 /etc/sudoers.d/wgapi
    
    # Create a wrapper script for safe config operations
    cat > /usr/local/bin/wg-config-helper << 'EOF'
#!/bin/bash
# Helper script to safely read/write WireGuard config

case "$1" in
    read)
        sudo cat /etc/wireguard/wg0.conf
        ;;
    append)
        shift
        echo "$*" | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
        ;;
    *)
        echo "Usage: wg-config-helper {read|append} [content]"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/wg-config-helper
    
    # Add sudo permission for the helper script
    echo "wgapi ALL=(root) NOPASSWD: /usr/local/bin/wg-config-helper" >> /etc/sudoers.d/wgapi
    
    # Test permissions
    if sudo -u wgapi sudo cat /etc/wireguard/wg0.conf &>/dev/null; then
        echo "✓ wgapi can read WireGuard config"
    else
        echo "⚠️  Warning: wgapi cannot read config directly, will use helper"
    fi
    
    echo "✓ Permissions configured successfully"
}

step_api_npm_setup() {
    echo "→ Preparing API directory and npm dependencies..."
    mkdir -p "$API_DIR"
    chown wgapi:wgapi "$API_DIR"
    cd "$API_DIR" || exit 1

    npm init -y >/dev/null 2>&1
    npm install express express-rate-limit helmet >/dev/null 2>&1
}

step_generate_token() {
    API_TOKEN=$(openssl rand -hex 32)
    echo "→ Generated Bearer token: $API_TOKEN"
}

step_write_server_js() {
    echo "→ Writing Node.js API code..."

    if [ -f "/etc/wireguard/server_public.key" ]; then
        SERVER_PUBLIC_KEY=$(cat /etc/wireguard/server_public.key)
    else
        echo "⚠️  Warning: server_public.key not found."
        SERVER_PUBLIC_KEY="MISSING"
    fi

    cat > "$API_DIR/server.js" <<EOF
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { execSync } = require('child_process');
const fs = require('fs');

const app = express();
app.use(helmet());
app.use(express.json());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 60, message: { error: 'Too many requests' } }));

const API_TOKEN = '${API_TOKEN}';

app.use((req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth || auth !== 'Bearer ' + API_TOKEN) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
});

const WG_CONFIG = '${WG_CONFIG}';
const SERVER_PUB = '${SERVER_PUBLIC_KEY}';
const ENDPOINT = '${DOMAIN}';
const WG_PORT = ${WG_PORT};
const BASE_IP = '10.66.66.';

// Helper function to read config using sudo
function readConfig() {
    try {
        const result = execSync('sudo /usr/local/bin/wg-config-helper read', { encoding: 'utf8' });
        return result;
    } catch (err) {
        console.error('Error reading config:', err.message);
        throw new Error('Cannot read WireGuard configuration');
    }
}

// Helper function to append to config using sudo
function appendToConfig(content) {
    try {
        execSync(\`sudo /usr/local/bin/wg-config-helper append '\${content}'\`, { encoding: 'utf8' });
    } catch (err) {
        console.error('Error writing to config:', err.message);
        throw new Error('Cannot write to WireGuard configuration');
    }
}

function getNextIP() {
    const config = readConfig();
    const matches = config.match(/10\\.66\\.66\\.(\\d+)/g) || [];
    const used = matches.map(ip => parseInt(ip.split('.').pop(), 10));
    for (let i = 2; i <= 254; i++) {
        if (!used.includes(i)) return BASE_IP + i;
    }
    throw new Error('IP pool exhausted');
}

app.post('/create', (req, res) => {
    try {
        const privateKey = execSync('wg genkey', { encoding: 'utf8' }).trim();
        const publicKey = execSync('wg pubkey', { input: privateKey, encoding: 'utf8' }).trim();
        const clientIP = getNextIP();

        const peerConfig = \`\n[Peer]\nPublicKey = \${publicKey}\nAllowedIPs = \${clientIP}/32\n\`;
        appendToConfig(peerConfig);

        execSync(\`sudo /usr/local/bin/wg-provision "\${publicKey}" "\${clientIP}"\`);

        const cfg =
            '[Interface]\n' +
            \`PrivateKey = \${privateKey}\n\` +
            \`Address = \${clientIP}/32\n\` +
            'DNS = 1.1.1.1\n\n' +
            '[Peer]\n' +
            \`PublicKey = \${SERVER_PUB}\n\` +
            \`Endpoint = \${ENDPOINT}:\${WG_PORT}\n\` +
            'AllowedIPs = 0.0.0.0/0\n' +
            'PersistentKeepalive = 25';

        res.json({ success: true, config: cfg });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/remove', (req, res) => {
    const { publicKey } = req.body;
    if (!publicKey) return res.status(400).json({ error: 'publicKey required' });
    try {
        execSync(\`sudo /usr/local/bin/wg-remove "\${publicKey}"\`);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(${API_PORT_INTERNAL}, '127.0.0.1', () => {
    console.log('API listening on localhost:${API_PORT_INTERNAL}');
});
EOF

    chown -R wgapi:wgapi "$API_DIR"
    echo "✓ server.js written"
}

step_configure_caddy() {
    echo "→ Configuring Caddy reverse proxy..."
    
    cat > /etc/caddy/Caddyfile << EOF
${DOMAIN} {
    reverse_proxy localhost:${API_PORT_INTERNAL}
    log {
        output file /var/log/caddy/wg-api.log
    }
}
EOF

    systemctl restart caddy
    echo "✓ Caddy configured"
}

print_success_message() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "                SECURE WIREGUARD API INSTALLED"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "  Domain:          https://$DOMAIN"
    echo "  Bearer Token:    $API_TOKEN"
    echo ""
    echo "  Create client config:"
    echo "  curl -X POST https://$DOMAIN/create \\"
    echo "    -H \"Authorization: Bearer $API_TOKEN\" \\"
    echo "    -H \"Content-Type: application/json\""
    echo ""
    echo "  Remove client (example):"
    echo "  curl -X POST https://$DOMAIN/remove \\"
    echo "    -H \"Authorization: Bearer $API_TOKEN\" \\"
    echo "    -H \"Content-Type: application/json\" \\"
    echo "    -d '{\"publicKey\": \"...\"}'"
    echo ""
    echo "  Logs:"
    echo "    Caddy:     /var/log/caddy/wg-api.log"
    echo "    Service:   journalctl -u $API_SERVICE -f"
    echo ""
    echo "  Security notes:"
    echo "  • Keep the token secret"
    echo "  • HTTPS is automatic via Let's Encrypt"
    echo "  • Node.js runs as non-root user wgapi"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
}

# ────────────────────────────────────────────────
# Main install function (orchestrator)
# ────────────────────────────────────────────────

install() {
    echo "Starting secure WireGuard + HTTPS API installation..."
    echo ""

    detect_outbound_interface
    ask_domain

    step_install_packages
    echo "Instaling Packages Done..."
    step_install_caddy
    echo "Install Caddy Done..."
    step_wireguard_keys_config
    echo "wireguard key config Done..."
    step_enable_ip_forward
    echo "Enable IP forward Done..."
    step_firewall_rules
    echo "forewall rules Done..."
    step_start_wireguard
    step_create_api_user

    step_install_wg_provision
    step_install_wg_remove
    step_configure_sudoers
    step_fix_permissions
    
    step_api_npm_setup
    step_generate_token
    step_write_server_js
    step_create_systemd_service
    step_configure_caddy
    print_success_message

    echo "Done."
}

# ────────────────────────────────────────────────
# Uninstall
# ────────────────────────────────────────────────

uninstall() {
    echo "Uninstalling WireGuard + Secure API setup..."

    systemctl stop wg-quick@"$WG_INTERFACE"     2>/dev/null || true
    systemctl disable wg-quick@"$WG_INTERFACE"  2>/dev/null || true
    systemctl stop "$API_SERVICE"               2>/dev/null || true
    systemctl disable "$API_SERVICE"            2>/dev/null || true
    systemctl stop caddy                        2>/dev/null || true

    rm -f "/etc/systemd/system/$API_SERVICE"
    rm -rf "$API_DIR"
    rm -f "$WG_CONFIG"
    rm -f /etc/caddy/Caddyfile

    iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT                       2>/dev/null || true
    iptables -D FORWARD -i "$WG_INTERFACE" -j ACCEPT                            2>/dev/null || true
    iptables -D FORWARD -o "$WG_INTERFACE" -j ACCEPT                            2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$WG_NETWORK" -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null || true

    netfilter-persistent save 2>/dev/null || true
    systemctl daemon-reload

    echo ""
    echo "Uninstall finished."
    echo "Packages (caddy, wireguard, nodejs, npm, iptables-persistent) still installed."
    echo "Remove them manually if you want: apt remove ..."
}

# ────────────────────────────────────────────────
# CLI argument parsing
# ────────────────────────────────────────────────

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port=*)           WG_PORT="${1#*=}" ; shift ;;
            --api-port=*)       API_PORT_INTERNAL="${1#*=}" ; shift ;;
            --uninstall|-u)     ACTION="uninstall" ; shift ;;
            --help|-h)          show_help ; exit 0 ;;
            *) echo "Unknown argument: $1" ; show_help ; exit 1 ;;
        esac
    done
}

show_help() {
    echo "========================================"
    echo "  WireGuard + Secure API Manager"
    echo "========================================"
    echo ""
    echo "Usage:"
    echo "  sudo ./install-wg.sh                  → interactive menu"
    echo "  sudo ./install-wg.sh --help           → this help"
    echo "  sudo ./install-wg.sh --uninstall      → remove setup"
    echo "  sudo ./install-wg.sh --port=51830     → custom WireGuard port"
    echo "  sudo ./install-wg.sh --api-port=4000  → custom internal API port"
    echo ""
    echo "Note: During interactive install you will be asked for a domain."
    echo "========================================"
}

# ────────────────────────────────────────────────
# Interactive menu
# ────────────────────────────────────────────────

show_menu() {
    clear
    echo "========================================"
    echo "     Secure WireGuard Manager"
    echo "========================================"
    echo ""
    echo "  1) Install WireGuard + HTTPS API"
    echo "  2) Uninstall"
    echo "  3) Usage / Help"
    echo "  0) Exit"
    echo ""
    read -r -p "Choose [0-3]: " choice

    case "$choice" in
        1) install ; read -r -p "Press Enter to continue..." ;;
        2) uninstall ; read -r -p "Press Enter to continue..." ;;
        3) show_help ; read -r -p "Press Enter to continue..." ;;
        0) echo "Goodbye."; exit 0 ;;
        *) echo "Invalid choice."; sleep 1 ;;
    esac
}

# ────────────────────────────────────────────────
# Entry point
# ────────────────────────────────────────────────

check_root
show_menu

#parse_args "$@"

#if [ -n "$ACTION" ]; then
#    if [ "$ACTION" = "uninstall" ]; then
#        uninstall
#    else
#        install
#    fi
#    exit 0
#fi

# Interactive mode
#while true; do
#    show_menu
#done
