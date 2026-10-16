#!/bin/bash
# =============================================================================
# install-wg-full.sh - WireGuard server + HTTPS management API + health tooling
#
# Installs on Debian/Ubuntu:
#   - WireGuard (wg0, 10.66.66.0/24) with NAT/forward rules in PostUp/PostDown
#     (survive reboots) and ip_forward persisted in /etc/sysctl.d
#   - wg-api  (Node.js, localhost only) behind Caddy with automatic HTTPS and a
#     Bearer token: POST /create, POST /remove, GET /health
#   - /usr/local/bin/wg-peer-ctrl.sh   restricted dispatcher (suspend, limits...)
#   - /usr/local/bin/wg-healthcheck.sh health check  (from the repo)
#   - /usr/local/bin/vpn-doctor.sh     diagnose + fix (from the repo)
#   - wg-monitor SSH account (optional, needs the management server's public key)
#   - a daily systemd timer that runs wg-healthcheck.sh
#
# Usage:
#   sudo ./install-wg-full.sh                        interactive menu
#   sudo ./install-wg-full.sh --domain=vpn-api.example.com --port=51820
#   sudo ./install-wg-full.sh --no-api               WireGuard + tools only (no Caddy/Node)
#   sudo ./install-wg-full.sh --add-monitor --monitor-key-file=/root/wg_monitor_key.pub
#   sudo ./install-wg-full.sh --update-tools         re-fetch healthcheck/doctor scripts
#   sudo ./install-wg-full.sh --uninstall
#
# Options:
#   --domain=NAME            domain for the HTTPS API (A record must point here)
#   --port=N                 WireGuard UDP port (default 51820)
#   --api-port=N             internal API port (default 4242)
#   --dns=IP[,IP]            DNS handed to clients (default 1.1.1.1)
#   --monitor-key="ssh-..."  public key of the management server (wg-monitor)
#   --monitor-key-file=FILE  same, read from a file
#   --no-api                 skip Caddy, Node and the API
#   --force                  replace an existing wg0.conf (backs it up first)
#   --yes, -y                do not ask questions
#
# healthcheck/doctor are copied from next to this script when present, otherwise
# downloaded from the GitHub repo (main branch) and syntax-checked first.
#
# Edit this script with: vi install-wg-full.sh
# =============================================================================

set -euo pipefail

# ----------------------------- settings ---------------------------------------
WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.66.0/24"
WG_SERVER_ADDR="10.66.66.1/24"
WG_NET_PREFIX="10.66.66."
WG_CONFIG="/etc/wireguard/${WG_INTERFACE}.conf"
CLIENT_DNS="1.1.1.1"

API_PORT_INTERNAL=4242
API_DIR="/opt/wg-api"
API_SERVICE="wg-api.service"
API_ENV_DIR="/etc/wg-api"
API_USER="wgapi"

MONITOR_USER="wg-monitor"
MONITOR_KEY=""
MONITOR_KEY_FILE=""
MONITOR_MARK="# wg-monitor (install-wg-full.sh)"

BIN_DIR="/usr/local/bin"
REPO_RAW="https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo .)"

DOMAIN=""
OUT_IFACE=""
SERVER_PUBLIC_KEY=""
API_TOKEN=""
PORT_FROM_FLAG=0
INSTALL_API=1
ASSUME_YES=0
FORCE=0
ACTION="install"

# ----------------------------- output helpers ---------------------------------

# Usage: say "message"   -> progress line
say() { printf '→ %s\n' "$*"; }

# Usage: ok "message"    -> success line
ok() { printf '  ✓ %s\n' "$*"; }

# Usage: warn "message"  -> non-fatal problem, printed on stderr
warn() { printf '  ⚠ %s\n' "$*" >&2; }

# Usage: die "message"   -> print an error and exit 1
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Usage: have <command>  -> 0 if the command exists
have() { command -v "$1" >/dev/null 2>&1; }

# Usage: is_tty          -> 0 if stdin is a terminal (safe to ask questions)
is_tty() { [ -t 0 ]; }

# Usage: show_help       -> prints the header comment as help text
show_help() { sed -n '2,41p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ----------------------------- checks and arguments ---------------------------

# Usage: check_root      -> exits unless running as root
check_root() {
    [ "$EUID" -eq 0 ] || die "This script must be run as root (sudo $0)."
}

# Usage: check_os        -> exits unless the OS is Debian or Ubuntu based
check_os() {
    [ -r /etc/os-release ] || die "Cannot detect the OS (/etc/os-release missing)."
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        *debian*|*ubuntu*) ;;
        *) die "Unsupported OS '${PRETTY_NAME:-unknown}'. This installer supports Debian and Ubuntu." ;;
    esac
}

# Usage: parse_args "$@" -> fills the settings above from the command line
parse_args() {
    local a
    for a in "$@"; do
        case "$a" in
            --port=*)             WG_PORT="${a#*=}"; PORT_FROM_FLAG=1 ;;
            --api-port=*)         API_PORT_INTERNAL="${a#*=}" ;;
            --domain=*)           DOMAIN="${a#*=}" ;;
            --dns=*)              CLIENT_DNS="${a#*=}" ;;
            --monitor-key=*)      MONITOR_KEY="${a#*=}" ;;
            --monitor-key-file=*) MONITOR_KEY_FILE="${a#*=}" ;;
            --no-api)             INSTALL_API=0 ;;
            --force)              FORCE=1 ;;
            --yes|-y)             ASSUME_YES=1 ;;
            --uninstall|-u)       ACTION="uninstall" ;;
            --add-monitor)        ACTION="add-monitor" ;;
            --update-tools)       ACTION="update-tools" ;;
            --help|-h)            show_help; exit 0 ;;
            *) echo "Unknown argument: $a" >&2; show_help; exit 1 ;;
        esac
    done
}

# Usage: valid_port <n>  -> 0 if n is an integer from 1 to 65535
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

# Usage: valid_monitor_key <line> -> 0 if the line looks like one SSH public key
valid_monitor_key() {
    [[ "$1" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+)[[:space:]][A-Za-z0-9+/=]+([[:space:]][^[:cntrl:]]*)?$ ]]
}

# Usage: validate_settings -> exits on bad values (they end up in configs, so be strict)
validate_settings() {
    valid_port "$WG_PORT"           || die "Invalid WireGuard port '$WG_PORT'."
    valid_port "$API_PORT_INTERNAL" || die "Invalid API port '$API_PORT_INTERNAL'."
    [[ "$CLIENT_DNS" =~ ^[0-9.]+(,[[:space:]]?[0-9.]+)*$ ]] || die "Invalid --dns value '$CLIENT_DNS' (IPv4 addresses only)."
    if [ -n "$DOMAIN" ]; then
        [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "Invalid domain '$DOMAIN'."
    fi
    if [ -n "$MONITOR_KEY_FILE" ]; then
        [ -r "$MONITOR_KEY_FILE" ] || die "Cannot read $MONITOR_KEY_FILE."
        MONITOR_KEY="$(head -n1 "$MONITOR_KEY_FILE")"
    fi
    if [ -n "$MONITOR_KEY" ]; then
        valid_monitor_key "$MONITOR_KEY" || die "The monitor key is not a valid single-line SSH public key."
    fi
}

# Usage: detect_outbound_interface -> sets OUT_IFACE (used for the ufw route rule and the summary)
detect_outbound_interface() {
    # '|| true': 'ip' may not exist yet on a minimal image, and set -e must not kill the script silently
    OUT_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}' || true)"
    [ -n "$OUT_IFACE" ] || OUT_IFACE="eth0"
    say "Detected outbound interface: $OUT_IFACE"
}

# Usage: ask_port        -> asks for the WireGuard UDP port unless --port or --yes was given
ask_port() {
    [ "$PORT_FROM_FLAG" -eq 1 ] && return 0
    { [ "$ASSUME_YES" -eq 1 ] || ! is_tty; } && return 0
    local p
    read -r -p "WireGuard UDP port [${WG_PORT}]: " p
    if [ -n "$p" ]; then
        valid_port "$p" && WG_PORT="$p" || warn "Invalid port '$p', keeping ${WG_PORT}."
    fi
    say "Using WireGuard UDP port: $WG_PORT"
}

# Usage: ask_domain      -> asks for the API domain (required with the API)
ask_domain() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    if [ -z "$DOMAIN" ]; then
        is_tty || die "A domain is required: pass --domain=NAME (or --no-api)."
        echo
        echo "Automatic HTTPS (Let's Encrypt via Caddy) needs a domain whose A record"
        echo "points to this server's public IP, and ports 80 and 443 open."
        read -r -p "Enter domain (e.g. vpn-api.example.com): " DOMAIN
    fi
    [ -n "$DOMAIN" ] || die "A domain is required (or use --no-api)."
    [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "Invalid domain '$DOMAIN'."
}

# Usage: ask_monitor_key -> asks for the wg-monitor public key (blank = skip)
ask_monitor_key() {
    [ -n "$MONITOR_KEY" ] && return 0
    { [ "$ASSUME_YES" -eq 1 ] || ! is_tty; } && return 0
    echo
    echo "Optional: paste the management server's wg-monitor PUBLIC key"
    echo "(contents of /root/.ssh/wg_monitor_key.pub). Leave blank to skip."
    read -r -p "Public key: " MONITOR_KEY
    if [ -n "$MONITOR_KEY" ] && ! valid_monitor_key "$MONITOR_KEY"; then
        warn "That is not a valid SSH public key; skipping wg-monitor (use --add-monitor later)."
        MONITOR_KEY=""
    fi
}

# ----------------------------- installation steps -----------------------------

# Usage: step_install_packages -> apt packages, Node.js (if missing or older than 18)
step_install_packages() {
    say "Installing required packages..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y wireguard wireguard-tools iptables iptables-persistent \
        iproute2 curl openssl gnupg sudo jq ca-certificates dnsutils tcpdump
    if [ "$INSTALL_API" -eq 1 ]; then
        local major=0
        have node && major="$(node -v | sed 's/^v//; s/\..*//')"
        if [ "$major" -lt 18 ]; then
            say "Installing Node.js 22 from NodeSource..."
            curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
            apt-get install -y nodejs
        fi
        have npm || apt-get install -y npm
        ok "Node $(node -v), npm $(npm -v)"
    fi
}

# Usage: step_install_caddy -> Caddy from the official apt repo (skipped if already installed)
step_install_caddy() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    if have caddy; then ok "Caddy already installed"; return 0; fi
    say "Installing Caddy..."
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt -o /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -y
    apt-get install -y caddy
    mkdir -p /var/log/caddy
    chown caddy:caddy /var/log/caddy
    ok "Caddy $(caddy version 2>/dev/null | head -n1)"
}

# Usage: step_wireguard_keys_config -> server keys and wg0.conf (NAT/forward rules live in PostUp/PostDown)
step_wireguard_keys_config() {
    say "Generating WireGuard server keys and config..."
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard
    if [ -f "$WG_CONFIG" ]; then
        [ "$FORCE" -eq 1 ] || die "$WG_CONFIG already exists. Re-running would replace the server keys and break every client. Use --force (backs it up) or --uninstall first."
        systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
        cp -a "$WG_CONFIG" "${WG_CONFIG}.bak-$(date +%Y%m%d-%H%M%S)"
        ok "Existing config backed up"
    fi
    local priv
    priv="$(wg genkey)"
    SERVER_PUBLIC_KEY="$(printf '%s' "$priv" | wg pubkey)"
    (
        umask 077
        cat > "$WG_CONFIG" <<END
[Interface]
Address = ${WG_SERVER_ADDR}
ListenPort = ${WG_PORT}
PrivateKey = ${priv}
# NAT rule without -o: it keeps working if the uplink is renamed, and
# '! -d' keeps the server's own traffic to ${WG_SERVER_ADDR%/*} out of MASQUERADE.
PostUp = iptables -C INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport ${WG_PORT} -j ACCEPT
PostUp = iptables -C FORWARD -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i ${WG_INTERFACE} -j ACCEPT
PostUp = iptables -C FORWARD -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o ${WG_INTERFACE} -j ACCEPT
PostUp = iptables -t nat -C POSTROUTING -s ${WG_NETWORK} ! -d ${WG_NETWORK} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${WG_NETWORK} ! -d ${WG_NETWORK} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${WG_PORT} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -s ${WG_NETWORK} ! -d ${WG_NETWORK} -j MASQUERADE 2>/dev/null || true
END
    )
    chmod 600 "$WG_CONFIG"
    printf '%s\n' "$priv" > /etc/wireguard/server_private.key
    printf '%s\n' "$SERVER_PUBLIC_KEY" > /etc/wireguard/server_public.key
    chmod 600 /etc/wireguard/server_private.key
    chmod 644 /etc/wireguard/server_public.key
    wg-quick strip "$WG_CONFIG" >/dev/null 2>&1 || die "Generated config does not validate: $WG_CONFIG"
    ok "Server public key: $SERVER_PUBLIC_KEY"
}

# Usage: step_enable_ip_forward -> turns on IPv4 forwarding now and persists it
step_enable_ip_forward() {
    say "Enabling IP forwarding..."
    # a conflicting '=0' in /etc/sysctl.conf would win at boot, so fix it as well
    if grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0' /etc/sysctl.conf 2>/dev/null; then
        sed -i -E 's|^([[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=).*|\11|' /etc/sysctl.conf
    fi
    printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-wireguard.conf
    sysctl --system >/dev/null 2>&1 || sysctl -w net.ipv4.ip_forward=1 >/dev/null
    [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ] || die "Could not enable net.ipv4.ip_forward."
    ok "net.ipv4.ip_forward = 1 (persisted in /etc/sysctl.d/99-wireguard.conf)"
}

# Usage: step_firewall_ufw -> opens the needed ports only if ufw is active
step_firewall_ufw() {
    have ufw || return 0
    ufw status 2>/dev/null | grep -qi 'Status: active' || return 0
    say "ufw is active: adding rules..."
    ufw allow "${WG_PORT}/udp" >/dev/null
    if [ "$INSTALL_API" -eq 1 ]; then
        ufw allow 80/tcp >/dev/null
        ufw allow 443/tcp >/dev/null
    fi
    ufw route allow in on "$WG_INTERFACE" out on "$OUT_IFACE" >/dev/null || true
    ok "ufw: ${WG_PORT}/udp$([ "$INSTALL_API" -eq 1 ] && echo ', 80/tcp, 443/tcp') and routing for ${WG_INTERFACE}"
}

# Usage: step_start_wireguard -> enables and starts wg-quick@wg0 and checks the interface
step_start_wireguard() {
    say "Starting WireGuard..."
    systemctl enable --now "wg-quick@${WG_INTERFACE}"
    wg show "$WG_INTERFACE" >/dev/null 2>&1 || die "Interface ${WG_INTERFACE} did not come up: journalctl -u wg-quick@${WG_INTERFACE}"
    ok "${WG_INTERFACE} is up on udp/${WG_PORT}"
}

# Usage: step_install_peer_ctrl -> installs wg-peer-ctrl.sh (embedded copy of the repo script)
step_install_peer_ctrl() {
    say "Installing wg-peer-ctrl.sh..."
    cat > "${BIN_DIR}/wg-peer-ctrl.sh" <<'WG_PEER_CTRL_EOF'
#!/bin/bash
# wg-peer-ctrl.sh — ForceCommand dispatcher for wg-monitor SSH sessions.
# Also directly callable locally (see CMD line below) — sync-wg-traffic.sh
# uses this for the local (US08) server instead of going over SSH.
#
# INSTALL (once, as root, on each VPN server):
#   install -o root -g root -m 755 wg-peer-ctrl.sh /usr/local/bin/wg-peer-ctrl.sh
#
#   cat > /etc/sudoers.d/wg-monitor <<'EOF'
#   Defaults!/usr/local/bin/wg-peer-ctrl.sh env_keep += "SSH_ORIGINAL_COMMAND"
#   wg-monitor ALL=(root) NOPASSWD: /usr/local/bin/wg-peer-ctrl.sh
#   EOF
#   chmod 440 /etc/sudoers.d/wg-monitor
#
#   In sshd_config's "Match User wg-monitor" block:
#     ForceCommand sudo /usr/local/bin/wg-peer-ctrl.sh
#
# Runs as root via the sudoers entry above, which permits this exact
# binary and nothing else — no internal "sudo" calls needed.
#
# Permitted commands:
#   (empty)                       -> wg show wg0 dump        (traffic sync)
#   peer-disable <pubkey>         -> wg set ... remove       (expire peer)
#   peer-enable  <pubkey> <cidr>  -> wg set ... allowed-ips  (re-enable peer)
#   peer-suspend   <cidr>         -> iptables DROP            (suspend peer)
#   peer-unsuspend <cidr>         -> remove iptables DROP     (unsuspend peer)
#   peer-setlimit  <cidr> <kbps>  -> tc htb cap, both directions
#   peer-clearlimit <cidr>        -> remove tc cap
#
# NOTE on speed limiting: this assumes every peer's address comes from a
# single flat /24 pool (10.66.66.0/24, per install-wg3.sh's getNextIP()),
# and uses the address's last octet as the tc classid. If you ever run
# peers across multiple pools/subnets on one server, this needs a real
# classid allocator instead.

set -euo pipefail

WG_IFACE="wg0"
IFB_IFACE="ifb0"
WG="/usr/bin/wg"
IPT="/sbin/iptables"
TC="/sbin/tc"
SUSPEND_CHAIN="WG-SUSPEND"

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

# Usage: is_valid_pubkey <key>
# Validates a WireGuard public key: base64, exactly 44 chars ending in =
is_valid_pubkey() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }

# Usage: is_valid_cidr <address>
# Validates an IP/CIDR address like 10.66.66.5/32
is_valid_cidr() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; }

# Usage: is_valid_kbps <value>
# Validates a positive integer kbps value.
is_valid_kbps() { [[ "$1" =~ ^[0-9]+$ ]] && [[ "$1" -gt 0 ]]; }

# Usage: audit <r> <message>
# Writes one line per invocation to the system log for later review.
audit() {
    local result="$1"; shift
    logger -t wg-peer-ctrl "result=${result} client=${SSH_CLIENT:-local} cmd=${CMD:-<empty>} $*"
}

# ─────────────────────────────────────────────────────────────────────────────
# IPTABLES CHAIN (suspend/unsuspend)
# ─────────────────────────────────────────────────────────────────────────────

# Usage: ensure_suspend_chain
# Creates the WG-SUSPEND chain and hooks it into FORWARD if not already present.
ensure_suspend_chain() {
    "$IPT" -nL "$SUSPEND_CHAIN" >/dev/null 2>&1 || {
        "$IPT" -N "$SUSPEND_CHAIN"
        "$IPT" -I FORWARD 1 -j "$SUSPEND_CHAIN"
    }
}

# Usage: persist_iptables
# Saves iptables state so suspensions survive a reboot. No-op if unavailable.
persist_iptables() {
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
}

# ─────────────────────────────────────────────────────────────────────────────
# TC SHAPING (speed limit)
#
# Download (server -> client) is shaped directly on wg0's egress.
# Upload (client -> server) arrives as wg0's INGRESS, which Linux cannot
# shape directly — traffic control only shapes what a device sends out.
# The standard workaround: mirror all wg0 ingress onto a virtual "ifb"
# device, which then treats that mirrored traffic as its own egress and
# can shape it normally.
# ─────────────────────────────────────────────────────────────────────────────

# Usage: class_id_for_ip <cidr>
# Derives a stable tc classid from the last octet of the peer's IP.
class_id_for_ip() {
    local ip="${1%%/*}" last_octet="${1%%/*}"
    last_octet="${ip##*.}"
    [[ "$last_octet" =~ ^[0-9]+$ ]] || return 1
    echo "$last_octet"
}

# Usage: ensure_shaping_setup
# One-time (idempotent) setup: ifb device, wg0->ifb0 ingress redirect,
# and a root htb qdisc on both devices with an unlimited default class
# (1:999) so peers with no cap are unaffected.
ensure_shaping_setup() {
    ip link show "$IFB_IFACE" &>/dev/null || {
        modprobe ifb numifbs=1 2>/dev/null || true
        ip link add "$IFB_IFACE" type ifb
    }
    ip link set "$IFB_IFACE" up

    "$TC" qdisc show dev "$WG_IFACE" | grep -q "ingress" || {
        "$TC" qdisc add dev "$WG_IFACE" handle ffff: ingress
        "$TC" filter add dev "$WG_IFACE" parent ffff: protocol ip u32 \
            match u32 0 0 flowid 1:1 action mirred egress redirect dev "$IFB_IFACE"
    }

    "$TC" qdisc show dev "$WG_IFACE" | grep -q "htb 1:" || {
        "$TC" qdisc add dev "$WG_IFACE" root handle 1: htb default 999
        "$TC" class add dev "$WG_IFACE" parent 1: classid 1:999 htb rate 1000mbit
    }
    "$TC" qdisc show dev "$IFB_IFACE" | grep -q "htb 1:" || {
        "$TC" qdisc add dev "$IFB_IFACE" root handle 1: htb default 999
        "$TC" class add dev "$IFB_IFACE" parent 1: classid 1:999 htb rate 1000mbit
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# DISPATCH
# Accepts either SSH_ORIGINAL_COMMAND (via ForceCommand) or plain argv,
# so the same script works over SSH for remote servers and as a direct
# local call for whichever server sync-wg-traffic.sh runs on (US08).
# ─────────────────────────────────────────────────────────────────────────────

CMD="${SSH_ORIGINAL_COMMAND:-$*}"
read -r -a ARGS <<< "$CMD"
NARGS=${#ARGS[@]}

case "${ARGS[0]:-}" in

    "")
        [[ "$NARGS" -eq 0 ]] || { echo "ERROR: unexpected arguments" >&2; audit DENY "reason=args_on_empty"; exit 1; }
        "$WG" show "$WG_IFACE" dump
        audit OK "action=dump"
        ;;

    peer-disable)
        [[ "$NARGS" -eq 2 ]] || { echo "ERROR: usage: peer-disable <pubkey>" >&2; audit DENY "reason=argc"; exit 1; }
        PUBKEY="${ARGS[1]}"
        is_valid_pubkey "$PUBKEY" || { echo "ERROR: invalid pubkey" >&2; audit DENY "reason=bad_pubkey"; exit 1; }
        "$WG" set "$WG_IFACE" peer "$PUBKEY" remove
        echo "OK: peer removed"
        audit OK "action=disable pubkey=${PUBKEY:0:20}…"
        ;;

    peer-enable)
        [[ "$NARGS" -eq 3 ]] || { echo "ERROR: usage: peer-enable <pubkey> <cidr>" >&2; audit DENY "reason=argc"; exit 1; }
        PUBKEY="${ARGS[1]}"; ALLOWED_IPS="${ARGS[2]}"
        is_valid_pubkey "$PUBKEY"     || { echo "ERROR: invalid pubkey" >&2;   audit DENY "reason=bad_pubkey"; exit 1; }
        is_valid_cidr  "$ALLOWED_IPS" || { echo "ERROR: invalid IP/CIDR" >&2; audit DENY "reason=bad_cidr"; exit 1; }
        "$WG" set "$WG_IFACE" peer "$PUBKEY" allowed-ips "$ALLOWED_IPS"
        echo "OK: peer enabled with $ALLOWED_IPS"
        audit OK "action=enable pubkey=${PUBKEY:0:20}… ip=${ALLOWED_IPS}"
        ;;

    peer-suspend)
        [[ "$NARGS" -eq 2 ]] || { echo "ERROR: usage: peer-suspend <cidr>" >&2; audit DENY "reason=argc"; exit 1; }
        IP="${ARGS[1]}"
        is_valid_cidr "$IP" || { echo "ERROR: invalid IP/CIDR" >&2; audit DENY "reason=bad_cidr"; exit 1; }
        ensure_suspend_chain
        "$IPT" -C "$SUSPEND_CHAIN" -s "$IP" -j DROP 2>/dev/null || "$IPT" -A "$SUSPEND_CHAIN" -s "$IP" -j DROP
        "$IPT" -C "$SUSPEND_CHAIN" -d "$IP" -j DROP 2>/dev/null || "$IPT" -A "$SUSPEND_CHAIN" -d "$IP" -j DROP
        persist_iptables
        echo "OK: iptables DROP in place for $IP"
        audit OK "action=suspend ip=${IP}"
        ;;

    peer-unsuspend)
        [[ "$NARGS" -eq 2 ]] || { echo "ERROR: usage: peer-unsuspend <cidr>" >&2; audit DENY "reason=argc"; exit 1; }
        IP="${ARGS[1]}"
        is_valid_cidr "$IP" || { echo "ERROR: invalid IP/CIDR" >&2; audit DENY "reason=bad_cidr"; exit 1; }
        ensure_suspend_chain
        "$IPT" -C "$SUSPEND_CHAIN" -s "$IP" -j DROP 2>/dev/null && "$IPT" -D "$SUSPEND_CHAIN" -s "$IP" -j DROP || true
        "$IPT" -C "$SUSPEND_CHAIN" -d "$IP" -j DROP 2>/dev/null && "$IPT" -D "$SUSPEND_CHAIN" -d "$IP" -j DROP || true
        persist_iptables
        echo "OK: iptables DROP removed for $IP"
        audit OK "action=unsuspend ip=${IP}"
        ;;

    peer-setlimit)
        [[ "$NARGS" -eq 3 ]] || { echo "ERROR: usage: peer-setlimit <cidr> <kbps>" >&2; audit DENY "reason=argc"; exit 1; }
        IP="${ARGS[1]}"; KBPS="${ARGS[2]}"
        is_valid_cidr "$IP"   || { echo "ERROR: invalid IP/CIDR" >&2; audit DENY "reason=bad_cidr"; exit 1; }
        is_valid_kbps "$KBPS" || { echo "ERROR: invalid kbps" >&2;    audit DENY "reason=bad_kbps"; exit 1; }
        CID=$(class_id_for_ip "$IP") || { echo "ERROR: cannot derive class id" >&2; audit DENY "reason=bad_classid"; exit 1; }
        ensure_shaping_setup

        # Download: shape on wg0's own egress, matched by destination (the peer).
        "$TC" class replace dev "$WG_IFACE" parent 1: classid "1:$CID" htb rate "${KBPS}kbit" ceil "${KBPS}kbit"
        "$TC" filter replace dev "$WG_IFACE" parent 1: protocol ip u32 match ip dst "$IP" flowid "1:$CID"

        # Upload: shape on ifb0 (mirrored wg0 ingress), matched by source (the peer).
        "$TC" class replace dev "$IFB_IFACE" parent 1: classid "1:$CID" htb rate "${KBPS}kbit" ceil "${KBPS}kbit"
        "$TC" filter replace dev "$IFB_IFACE" parent 1: protocol ip u32 match ip src "$IP" flowid "1:$CID"

        echo "OK: ${KBPS}kbps limit applied for $IP"
        audit OK "action=setlimit ip=${IP} kbps=${KBPS}"
        ;;

    peer-clearlimit)
        [[ "$NARGS" -eq 2 ]] || { echo "ERROR: usage: peer-clearlimit <cidr>" >&2; audit DENY "reason=argc"; exit 1; }
        IP="${ARGS[1]}"
        is_valid_cidr "$IP" || { echo "ERROR: invalid IP/CIDR" >&2; audit DENY "reason=bad_cidr"; exit 1; }
        CID=$(class_id_for_ip "$IP") || { echo "ERROR: cannot derive class id" >&2; audit DENY "reason=bad_classid"; exit 1; }

        "$TC" filter del dev "$WG_IFACE" parent 1: protocol ip u32 match ip dst "$IP" flowid "1:$CID" 2>/dev/null || true
        "$TC" class  del dev "$WG_IFACE" parent 1: classid "1:$CID" 2>/dev/null || true
        "$TC" filter del dev "$IFB_IFACE" parent 1: protocol ip u32 match ip src "$IP" flowid "1:$CID" 2>/dev/null || true
        "$TC" class  del dev "$IFB_IFACE" parent 1: classid "1:$CID" 2>/dev/null || true

        echo "OK: limit cleared for $IP"
        audit OK "action=clearlimit ip=${IP}"
        ;;

    *)
        echo "ERROR: command not permitted: $CMD" >&2
        audit DENY "reason=unknown_command"
        exit 1
        ;;
esac
WG_PEER_CTRL_EOF
    chown root:root "${BIN_DIR}/wg-peer-ctrl.sh"
    chmod 755 "${BIN_DIR}/wg-peer-ctrl.sh"
    bash -n "${BIN_DIR}/wg-peer-ctrl.sh" || die "wg-peer-ctrl.sh failed its syntax check."
    ok "${BIN_DIR}/wg-peer-ctrl.sh"
}

# Usage: step_install_monitor -> wg-monitor account, sudoers entry and sshd Match block (needs MONITOR_KEY)
step_install_monitor() {
    if [ -z "$MONITOR_KEY" ]; then
        warn "No wg-monitor public key given: skipping the monitor account (add it later with --add-monitor)."
        return 0
    fi
    say "Setting up the ${MONITOR_USER} account..."
    # the shell must be bash: sshd runs ForceCommand through it ('nologin' would break it)
    if ! id "$MONITOR_USER" >/dev/null 2>&1; then
        useradd -r -m -d "/home/${MONITOR_USER}" -s /bin/bash "$MONITOR_USER"
    else
        usermod -s /bin/bash "$MONITOR_USER"
    fi
    install -d -o "$MONITOR_USER" -g "$MONITOR_USER" -m 700 "/home/${MONITOR_USER}/.ssh"
    local ak="/home/${MONITOR_USER}/.ssh/authorized_keys"
    touch "$ak"
    grep -qxF "$MONITOR_KEY" "$ak" || printf '%s\n' "$MONITOR_KEY" >> "$ak"
    chown "${MONITOR_USER}:${MONITOR_USER}" "$ak"
    chmod 600 "$ak"

    # sudoers: validated with visudo before it is installed
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<END
Defaults!${BIN_DIR}/wg-peer-ctrl.sh env_keep += "SSH_ORIGINAL_COMMAND"
${MONITOR_USER} ALL=(root) NOPASSWD: ${BIN_DIR}/wg-peer-ctrl.sh
END
    if visudo -cf "$tmp" >/dev/null 2>&1; then
        install -o root -g root -m 440 "$tmp" "/etc/sudoers.d/${MONITOR_USER}"
    else
        rm -f "$tmp"; die "Generated sudoers entry for ${MONITOR_USER} is invalid."
    fi
    rm -f "$tmp"

    # sshd: Match block appended at the END of sshd_config, tested before reload
    if ! grep -qE "^Match User ${MONITOR_USER}\$" /etc/ssh/sshd_config; then
        local bak="/etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)"
        cp -a /etc/ssh/sshd_config "$bak"
        cat >> /etc/ssh/sshd_config <<END

${MONITOR_MARK}
Match User ${MONITOR_USER}
    PasswordAuthentication no
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    ForceCommand sudo ${BIN_DIR}/wg-peer-ctrl.sh
END
        if sshd -t 2>/dev/null; then
            systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || warn "Could not reload sshd; reload it manually."
        else
            cp -a "$bak" /etc/ssh/sshd_config
            die "sshd -t rejected the new config; /etc/ssh/sshd_config was restored."
        fi
    fi
    if grep -qiE '^[[:space:]]*AllowUsers' /etc/ssh/sshd_config; then
        warn "sshd_config has an AllowUsers line: add '${MONITOR_USER}' to it (vi /etc/ssh/sshd_config) or SSH will refuse the account."
    fi
    ok "${MONITOR_USER} ready (key-only, no TTY, ForceCommand wg-peer-ctrl.sh)"
}

# Usage: step_install_api_helper -> root helper the API calls through sudo (add/remove peers, list used IPs)
step_install_api_helper() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Installing wg-api-helper..."
    cat > "${BIN_DIR}/wg-api-helper" <<'WG_API_HELPER_EOF'
#!/bin/bash
# wg-api-helper - root-owned helper for wg-api. Called through sudo; it is the
# only thing the API user may run as root and it accepts only these commands:
#   wg-api-helper used-ips              last octets already used in 10.66.66.0/24
#   wg-api-helper add <pubkey> <ip>     add a peer to wg0.conf AND the live interface
#   wg-api-helper remove <ip>           remove a peer from wg0.conf AND the live interface
set -euo pipefail

WG_IF="wg0"
WG_CONF="/etc/wireguard/${WG_IF}.conf"

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
WORK="$TMPD/${WG_IF}.conf"   # wg-quick strip needs a <name>.conf file name

# Usage: fail "message"   -> logs a DENY line and exits 1
fail() { echo "ERROR: $*" >&2; logger -t wg-api-helper "result=DENY $*"; exit 1; }

# Usage: is_valid_pubkey <key>  -> base64, 44 chars ending in '='
is_valid_pubkey() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }

# Usage: is_valid_ip <ip>       -> 0 for 10.66.66.2 to 10.66.66.254 (no leading zeros)
is_valid_ip() {
    [[ "$1" =~ ^10\.66\.66\.([1-9][0-9]{0,2})$ ]] || return 1
    local n="${BASH_REMATCH[1]}"
    [ "$n" -ge 2 ] && [ "$n" -le 254 ]
}

# Usage: install_conf <file>    -> validates with wg-quick strip, then atomically replaces wg0.conf
install_conf() {
    wg-quick strip "$1" >/dev/null 2>&1 || fail "modified config does not validate, nothing changed"
    install -o root -g root -m 600 "$1" "${WG_CONF}.new"
    mv -f "${WG_CONF}.new" "$WG_CONF"
}

# Usage: peer_key_for_ip <ip>   -> prints the PublicKey of the [Peer] block that owns <ip>/32
peer_key_for_ip() {
    awk -v ip="$1" '
        /^\[/ { key = "" }
        /^PublicKey[ \t]*=/ { k = $0; sub(/^PublicKey[ \t]*=[ \t]*/, "", k); key = k }
        /^AllowedIPs[ \t]*=/ { l = $0; gsub(/[ \t]/, "", l); if (l == "AllowedIPs=" ip "/32") { print key; exit } }
    ' "$WG_CONF"
}

# Usage: cmd_used_ips           -> prints the last octet of every 10.66.66.x address in the config
cmd_used_ips() {
    grep -oE '10\.66\.66\.[0-9]+' "$WG_CONF" | sed 's/.*\.//' | sort -un || true
}

# Usage: cmd_add <pubkey> <ip>  -> adds the peer to the file first, then to the live interface
cmd_add() {
    local pub="$1" ip="$2"
    is_valid_pubkey "$pub" || fail "invalid public key"
    is_valid_ip "$ip"      || fail "invalid ip"
    if grep -Eq "^AllowedIPs[[:space:]]*=[[:space:]]*${ip//./\\.}/32[[:space:]]*\$" "$WG_CONF"; then fail "ip already allocated: $ip"; fi
    if grep -qxF "PublicKey = $pub" "$WG_CONF"; then fail "public key already present"; fi
    cp -a "$WG_CONF" "$WORK"
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' "$pub" "$ip" >> "$WORK"
    install_conf "$WORK"
    if wg show "$WG_IF" >/dev/null 2>&1; then
        wg set "$WG_IF" peer "$pub" allowed-ips "${ip}/32"
    fi
    logger -t wg-api-helper "result=OK action=add ip=${ip}"
    echo "OK: peer added ($ip)"
}

# Usage: cmd_remove <ip>        -> removes the peer from the live interface and from the file
cmd_remove() {
    local ip="$1" pub
    is_valid_ip "$ip" || fail "invalid ip"
    pub="$(peer_key_for_ip "$ip")"
    [ -n "$pub" ] || fail "no peer found with AllowedIPs ${ip}/32"
    if wg show "$WG_IF" >/dev/null 2>&1; then
        wg set "$WG_IF" peer "$pub" remove || true
    fi
    awk -v ip="$ip" '
        function flush() { if (buf != "" && !drop) printf "%s", buf; buf = ""; drop = 0 }
        /^\[/ { flush() }
        { buf = buf $0 "\n"
          if ($0 ~ /^AllowedIPs[ \t]*=/) { l = $0; gsub(/[ \t]/, "", l); if (l == "AllowedIPs=" ip "/32") drop = 1 } }
        END { flush() }
    ' "$WG_CONF" > "$WORK"
    install_conf "$WORK"
    logger -t wg-api-helper "result=OK action=remove ip=${ip}"
    echo "OK: peer removed ($ip)"
}

exec 9>/run/wg-api-helper.lock
flock 9

case "${1:-}" in
    used-ips) [ "$#" -eq 1 ] || fail "usage: used-ips";           cmd_used_ips ;;
    add)      [ "$#" -eq 3 ] || fail "usage: add <pubkey> <ip>";  cmd_add "$2" "$3" ;;
    remove)   [ "$#" -eq 2 ] || fail "usage: remove <ip>";        cmd_remove "$2" ;;
    *)        fail "command not permitted: ${1:-<empty>}" ;;
esac
WG_API_HELPER_EOF
    chown root:root "${BIN_DIR}/wg-api-helper"
    chmod 755 "${BIN_DIR}/wg-api-helper"
    bash -n "${BIN_DIR}/wg-api-helper" || die "wg-api-helper failed its syntax check."
    ok "${BIN_DIR}/wg-api-helper"
}

# Usage: step_create_api_user -> non-root API user plus its sudoers entry (only wg-api-helper)
step_create_api_user() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Creating the ${API_USER} user..."
    id "$API_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$API_USER"
    local tmp
    tmp="$(mktemp)"
    printf '%s ALL=(root) NOPASSWD: %s/wg-api-helper\n' "$API_USER" "$BIN_DIR" > "$tmp"
    if visudo -cf "$tmp" >/dev/null 2>&1; then
        install -o root -g root -m 440 "$tmp" "/etc/sudoers.d/${API_USER}"
    else
        rm -f "$tmp"; die "Generated sudoers entry for ${API_USER} is invalid."
    fi
    rm -f "$tmp"
    ok "${API_USER} may run only ${BIN_DIR}/wg-api-helper as root"
}

# Usage: step_api_npm_setup -> API directory and npm dependencies
step_api_npm_setup() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Preparing the API directory and npm packages..."
    mkdir -p "$API_DIR"
    cd "$API_DIR"
    [ -f package.json ] || npm init -y >/dev/null 2>&1
    npm install --omit=dev --no-audit --no-fund express express-rate-limit helmet >/dev/null 2>&1 \
        || die "npm install failed in $API_DIR"
    chown -R "${API_USER}:${API_USER}" "$API_DIR"
    ok "express, express-rate-limit, helmet installed"
}

# Usage: step_generate_token -> creates the Bearer token once and keeps it in /etc/wg-api/env (mode 600)
step_generate_token() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    install -d -o root -g root -m 700 "$API_ENV_DIR"
    if [ -f "${API_ENV_DIR}/env" ] && grep -q '^API_TOKEN=' "${API_ENV_DIR}/env"; then
        API_TOKEN="$(sed -n 's/^API_TOKEN=//p' "${API_ENV_DIR}/env" | head -n1)"
        ok "Keeping the existing API token"
    else
        API_TOKEN="$(openssl rand -hex 32)"
        ( umask 077; printf 'API_TOKEN=%s\n' "$API_TOKEN" > "${API_ENV_DIR}/env" )
        ok "Generated a new API token"
    fi
    chmod 600 "${API_ENV_DIR}/env"
}

# Usage: step_write_server_js -> writes the Node.js API (placeholders are filled in with sed)
step_write_server_js() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Writing the Node.js API..."
    cat > "${API_DIR}/server.js" <<'SERVER_JS_EOF'
'use strict';
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const { execFileSync } = require('child_process');

const app = express();

// Caddy runs on this machine and is the only proxy in front of us
app.set('trust proxy', 'loopback');
app.use(helmet());
app.use(express.json());
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
}));

const API_TOKEN = process.env.API_TOKEN || '';
if (API_TOKEN.length < 32) {
    console.error('API_TOKEN is missing or too short (see /etc/wg-api/env)');
    process.exit(1);
}

// NOTE: wg-healthcheck.sh and vpn-doctor.sh read the next line, keep its format
const SERVER_PUB = '__SERVER_PUB__';
const ENDPOINT = '__ENDPOINT__';
const WG_PORT = __WG_PORT__;
const BASE_IP = '__NET_PREFIX__';
const CLIENT_DNS = '__DNS__';
const HELPER = '/usr/local/bin/wg-api-helper';

// Usage: tokenOk(headerValue) -> true if the Authorization header equals "Bearer <token>" (constant time)
function tokenOk(header) {
    const expected = Buffer.from('Bearer ' + API_TOKEN);
    const given = Buffer.from(header || '');
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

// Usage: helper(['add', pubkey, ip]) -> runs wg-api-helper as root through sudo, no shell involved
function helper(args) {
    return execFileSync('sudo', ['-n', HELPER, ...args], { encoding: 'utf8' });
}

// Usage: getNextIP() -> first free 10.66.66.x (2..254), throws when the pool is exhausted
function getNextIP() {
    const used = helper(['used-ips']).split('\n').map(s => parseInt(s, 10)).filter(n => !Number.isNaN(n));
    for (let i = 2; i <= 254; i++) {
        if (!used.includes(i)) return BASE_IP + i;
    }
    throw new Error('IP pool exhausted');
}

// Health endpoint is public (used by wg-healthcheck.sh)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use((req, res, next) => {
    if (!tokenOk(req.headers.authorization)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
});

// POST /create            -> client config as text/plain (backward compatible)
// POST /create?format=json -> { address, publicKey, privateKey, config }
app.post('/create', (req, res) => {
    try {
        const privateKey = execFileSync('wg', ['genkey'], { encoding: 'utf8' }).trim();
        const publicKey = execFileSync('wg', ['pubkey'], { input: privateKey, encoding: 'utf8' }).trim();
        const clientIP = getNextIP();
        helper(['add', publicKey, clientIP]);

        const cfg =
            '[Interface]\n' +
            'PrivateKey = ' + privateKey + '\n' +
            'Address = ' + clientIP + '/32\n' +
            'DNS = ' + CLIENT_DNS + '\n' +
            '\n' +
            '[Peer]\n' +
            'PublicKey = ' + SERVER_PUB + '\n' +
            'Endpoint = ' + ENDPOINT + ':' + WG_PORT + '\n' +
            'AllowedIPs = 0.0.0.0/0\n' +
            'PersistentKeepalive = 25\n';

        if (req.query.format === 'json') {
            return res.json({ address: clientIP + '/32', publicKey, privateKey, config: cfg });
        }
        res.type('text/plain').send(cfg);
    } catch (err) {
        console.error('create failed:', err.message);
        res.status(500).json({ error: 'create failed' });
    }
});

// POST /remove  { "ipAddress": "10.66.66.5" }
app.post('/remove', (req, res) => {
    const ipAddress = req.body && req.body.ipAddress;
    if (typeof ipAddress !== 'string' || !ipAddress) {
        return res.status(400).json({ error: 'ipAddress required' });
    }
    const ipOnly = ipAddress.split('/')[0];
    if (!/^10\.66\.66\.[1-9][0-9]{0,2}$/.test(ipOnly)) {
        return res.status(400).json({ error: 'invalid ipAddress format' });
    }
    try {
        helper(['remove', ipOnly]);
        res.json({ success: true, removed: ipOnly });
    } catch (err) {
        console.error('remove failed:', err.message);
        res.status(500).json({ error: 'remove failed' });
    }
});

app.listen(__API_PORT__, '127.0.0.1', () => {
    console.log('wg-api listening on 127.0.0.1:__API_PORT__');
});
SERVER_JS_EOF
    sed -i \
        -e "s|__SERVER_PUB__|${SERVER_PUBLIC_KEY}|g" \
        -e "s|__ENDPOINT__|${DOMAIN}|g" \
        -e "s|__WG_PORT__|${WG_PORT}|g" \
        -e "s|__NET_PREFIX__|${WG_NET_PREFIX}|g" \
        -e "s|__DNS__|${CLIENT_DNS}|g" \
        -e "s|__API_PORT__|${API_PORT_INTERNAL}|g" \
        "${API_DIR}/server.js"
    chown -R "${API_USER}:${API_USER}" "$API_DIR"
    if have node; then node --check "${API_DIR}/server.js" || die "server.js has a syntax error."; fi
    ok "${API_DIR}/server.js"
}

# Usage: step_create_systemd_service -> wg-api.service (runs as wgapi, token from /etc/wg-api/env)
step_create_systemd_service() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Creating the ${API_SERVICE} systemd unit..."
    cat > "/etc/systemd/system/${API_SERVICE}" <<END
[Unit]
Description=WireGuard API Service
After=network.target

[Service]
Type=simple
User=${API_USER}
Group=${API_USER}
WorkingDirectory=${API_DIR}
EnvironmentFile=${API_ENV_DIR}/env
ExecStart=$(command -v node) ${API_DIR}/server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
END
    systemctl daemon-reload
    systemctl enable "$API_SERVICE" >/dev/null 2>&1
    systemctl restart "$API_SERVICE"
    ok "${API_SERVICE} started"
}

# Usage: step_configure_caddy -> Caddyfile with the reverse proxy; validated before Caddy is restarted
step_configure_caddy() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Configuring Caddy for ${DOMAIN}..."
    mkdir -p /etc/caddy /var/log/caddy
    chown caddy:caddy /var/log/caddy 2>/dev/null || true
    [ -f /etc/caddy/Caddyfile ] && ! grep -q 'install-wg-full.sh' /etc/caddy/Caddyfile \
        && cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)"
    cat > /etc/caddy/Caddyfile <<END
# managed by install-wg-full.sh
${DOMAIN} {
    reverse_proxy 127.0.0.1:${API_PORT_INTERNAL}
    log {
        output file /var/log/caddy/wg-api.log
    }
}
END
    caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || die "Caddyfile does not validate: caddy validate --config /etc/caddy/Caddyfile"
    systemctl enable caddy >/dev/null 2>&1 || true
    systemctl restart caddy
    ok "Caddy proxies https://${DOMAIN} to 127.0.0.1:${API_PORT_INTERNAL}"
}

# Usage: fetch_tool <name> -> installs a repo script into /usr/local/bin (local copy first, else GitHub), syntax-checked
fetch_tool() {
    local name="$1" tmp
    tmp="$(mktemp)"
    if [ -f "${SCRIPT_DIR}/${name}" ]; then
        cp "${SCRIPT_DIR}/${name}" "$tmp"
    elif ! curl -fsSL --retry 3 -m 30 "${REPO_RAW}/${name}" -o "$tmp"; then
        rm -f "$tmp"; warn "Could not download ${name}; run --update-tools later."; return 1
    fi
    if ! head -n1 "$tmp" | grep -q '^#!' || ! bash -n "$tmp" 2>/dev/null; then
        rm -f "$tmp"; warn "${name} failed the syntax check and was not installed."; return 1
    fi
    install -o root -g root -m 755 "$tmp" "${BIN_DIR}/${name}"
    rm -f "$tmp"
    ok "${BIN_DIR}/${name}"
}

# Usage: step_install_tools -> installs wg-healthcheck.sh and vpn-doctor.sh
step_install_tools() {
    say "Installing the health tools..."
    fetch_tool wg-healthcheck.sh || true
    fetch_tool vpn-doctor.sh || true
}

# Usage: step_install_health_timer -> daily systemd timer that runs wg-healthcheck.sh and keeps the report
step_install_health_timer() {
    [ -x "${BIN_DIR}/wg-healthcheck.sh" ] || { warn "wg-healthcheck.sh missing, skipping the daily timer."; return 0; }
    say "Installing the daily health check timer..."
    cat > /etc/systemd/system/wg-healthcheck.service <<END
[Unit]
Description=WireGuard health check

[Service]
Type=oneshot
ExecStart=${BIN_DIR}/wg-healthcheck.sh --no-color --report=/var/log/wg-healthcheck.log
END
    cat > /etc/systemd/system/wg-healthcheck.timer <<END
[Unit]
Description=Daily WireGuard health check

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
END
    systemctl daemon-reload
    systemctl enable --now wg-healthcheck.timer >/dev/null 2>&1
    ok "wg-healthcheck.timer (report: /var/log/wg-healthcheck.log, a FAIL marks the service failed)"
}

# Usage: step_self_test -> quick checks after the install (interface, API health)
step_self_test() {
    say "Self test..."
    wg show "$WG_INTERFACE" >/dev/null 2>&1 && ok "${WG_INTERFACE} is up" || warn "${WG_INTERFACE} is NOT up"
    iptables -t nat -C POSTROUTING -s "$WG_NETWORK" ! -d "$WG_NETWORK" -j MASQUERADE 2>/dev/null \
        && ok "NAT rule is active" || warn "NAT rule is missing: run vpn-doctor.sh"
    if [ "$INSTALL_API" -eq 1 ]; then
        sleep 2
        curl -fsS -m 5 "http://127.0.0.1:${API_PORT_INTERNAL}/health" >/dev/null 2>&1 \
            && ok "wg-api answers on 127.0.0.1:${API_PORT_INTERNAL}" || warn "wg-api does not answer: journalctl -u ${API_SERVICE} -n 30"
    fi
}

# Usage: print_success_message -> final summary with the token and the next steps
print_success_message() {
    echo
    echo "═══════════════════════════════════════════════════════════════"
    echo "              WIREGUARD SERVER INSTALLED"
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Interface:       ${WG_INTERFACE}  (${WG_SERVER_ADDR})"
    echo "  WireGuard port:  ${WG_PORT}/udp"
    echo "  Server pub key:  ${SERVER_PUBLIC_KEY}"
    if [ "$INSTALL_API" -eq 1 ]; then
        echo "  API:             https://${DOMAIN}"
        echo "  Bearer token:    ${API_TOKEN}   (stored in ${API_ENV_DIR}/env)"
        echo
        echo "  Create a client (add ?format=json for JSON):"
        echo "    curl -X POST https://${DOMAIN}/create -H \"Authorization: Bearer ${API_TOKEN}\""
        echo "  Remove a client:"
        echo "    curl -X POST https://${DOMAIN}/remove -H \"Authorization: Bearer ${API_TOKEN}\" \\"
        echo "      -H 'Content-Type: application/json' -d '{\"ipAddress\":\"10.66.66.2\"}'"
    fi
    echo
    echo "  Health tools:"
    echo "    sudo wg-healthcheck.sh [--capture=20]     health check"
    echo "    sudo vpn-doctor.sh [--fix] [--dry-run]    diagnose and fix"
    echo "    journalctl -t wg-peer-ctrl -f             enforcement audit log"
    [ -z "$MONITOR_KEY" ] && echo "    sudo $0 --add-monitor --monitor-key-file=FILE   add wg-monitor later"
    echo
    echo "  Keep the token secret; rotate it (edit ${API_ENV_DIR}/env with vi, then"
    echo "  systemctl restart ${API_SERVICE}) if it was ever pasted anywhere."
    echo "═══════════════════════════════════════════════════════════════"
}

# Usage: install_all -> the full installation, in dependency order
install_all() {
    echo "Starting the WireGuard installation..."
    ask_port
    ask_domain
    ask_monitor_key
    step_install_packages
    detect_outbound_interface
    step_install_caddy
    step_wireguard_keys_config
    step_enable_ip_forward
    step_firewall_ufw
    step_start_wireguard
    step_install_peer_ctrl
    step_install_monitor
    step_install_api_helper
    step_create_api_user
    step_api_npm_setup
    step_generate_token
    step_write_server_js
    step_create_systemd_service
    step_configure_caddy
    step_install_tools
    step_install_health_timer
    step_self_test
    print_success_message
}

# ----------------------------- uninstall --------------------------------------

# Usage: uninstall -> removes everything this installer created; WireGuard files are moved to a backup folder
uninstall() {
    echo
    echo "This removes: the WireGuard interface and config, wg-api, the helper and"
    echo "health scripts, the ${MONITOR_USER}/${API_USER} accounts, sudoers entries, the"
    echo "timer and our Caddyfile. WireGuard keys/config are saved to a backup folder."
    if [ "$ASSUME_YES" -ne 1 ]; then
        local confirm=""
        read -r -p "Type 'yes' to confirm: " confirm
        [ "$confirm" = "yes" ] || { echo "Aborted."; return 0; }
    fi

    say "[1/7] Stopping services..."
    local svc
    for svc in wg-healthcheck.timer wg-healthcheck.service "$API_SERVICE" "wg-quick@${WG_INTERFACE}"; do
        systemctl disable --now "$svc" >/dev/null 2>&1 || true
    done

    say "[2/7] Removing speed limit and suspend state..."
    if ip link show ifb0 >/dev/null 2>&1; then
        tc qdisc del dev ifb0 root 2>/dev/null || true
        ip link del ifb0 2>/dev/null || true
    fi
    if iptables -nL WG-SUSPEND >/dev/null 2>&1; then
        while iptables -D FORWARD -j WG-SUSPEND 2>/dev/null; do :; done
        iptables -F WG-SUSPEND 2>/dev/null || true
        iptables -X WG-SUSPEND 2>/dev/null || true
        have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
    fi

    say "[3/7] Backing up and removing WireGuard files..."
    if [ -d /etc/wireguard ]; then
        local bk="/root/wg-uninstall-backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$bk"
        chmod 700 "$bk"
        cp -a /etc/wireguard/. "$bk"/
        rm -f "$WG_CONFIG" /etc/wireguard/server_private.key /etc/wireguard/server_public.key
        rmdir /etc/wireguard 2>/dev/null || true
        ok "Backup: $bk"
    fi
    rm -f /etc/sysctl.d/99-wireguard.conf

    say "[4/7] Removing API, helpers and units..."
    rm -rf "$API_DIR" "$API_ENV_DIR"
    rm -f "${BIN_DIR}/wg-api-helper" "${BIN_DIR}/wg-peer-ctrl.sh" "${BIN_DIR}/wg-healthcheck.sh" "${BIN_DIR}/vpn-doctor.sh"
    rm -f "/etc/systemd/system/${API_SERVICE}" /etc/systemd/system/wg-healthcheck.service /etc/systemd/system/wg-healthcheck.timer
    systemctl daemon-reload

    say "[5/7] Removing sudoers entries and accounts..."
    rm -f "/etc/sudoers.d/${API_USER}" "/etc/sudoers.d/${MONITOR_USER}"
    id "$API_USER" >/dev/null 2>&1 && userdel "$API_USER" 2>/dev/null || true
    id "$MONITOR_USER" >/dev/null 2>&1 && userdel -r "$MONITOR_USER" 2>/dev/null || true

    say "[6/7] Removing the sshd Match block..."
    if grep -qF "$MONITOR_MARK" /etc/ssh/sshd_config 2>/dev/null; then
        local sbak="/etc/ssh/sshd_config.bak-$(date +%Y%m%d-%H%M%S)"
        cp -a /etc/ssh/sshd_config "$sbak"
        sed -i "/^$(printf '%s' "$MONITOR_MARK" | sed 's/[][\.*^$/]/\\&/g')\$/,/^    ForceCommand sudo .*wg-peer-ctrl\.sh\$/d" /etc/ssh/sshd_config
        if sshd -t 2>/dev/null; then
            systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        else
            cp -a "$sbak" /etc/ssh/sshd_config
            warn "sshd -t failed after cleanup; the original sshd_config was restored (remove the Match block with vi)."
        fi
    fi

    say "[7/7] Caddy and packages..."
    if grep -q 'install-wg-full.sh' /etc/caddy/Caddyfile 2>/dev/null; then
        systemctl disable --now caddy >/dev/null 2>&1 || true
        rm -f /etc/caddy/Caddyfile
    fi
    local rm_pkgs="n"
    if [ "$ASSUME_YES" -ne 1 ]; then
        read -r -p "Also purge the packages (wireguard, wireguard-tools, caddy)? [y/N]: " rm_pkgs
    fi
    if [[ "$rm_pkgs" =~ ^[Yy]$ ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y wireguard wireguard-tools caddy || true
        apt-get autoremove -y || true
        rm -f /etc/apt/sources.list.d/caddy-stable.list /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    fi
    echo
    echo "Uninstall complete. IPv4 forwarding was left as is at runtime; reboot to clear it."
}

# ----------------------------- menu and entry point ---------------------------

# Usage: show_menu -> one-shot interactive menu (used when the script is started without arguments)
show_menu() {
    echo "========================================"
    echo "   WireGuard Server Installer"
    echo "========================================"
    echo "  1) Install WireGuard + HTTPS API + health tools"
    echo "  2) Uninstall"
    echo "  3) Add / repair the wg-monitor account"
    echo "  4) Update health tools (healthcheck, doctor)"
    echo "  0) Exit"
    local choice
    read -r -p "Choose [0-4]: " choice
    case "$choice" in
        1) install_all ;;
        2) uninstall ;;
        3) ask_monitor_key; step_install_peer_ctrl; step_install_monitor ;;
        4) step_install_peer_ctrl; step_install_tools ;;
        0) echo "Goodbye." ;;
        *) echo "Invalid choice." ;;
    esac
}

# Usage: main "$@"  -> entry point
main() {
    local argc=$#
    check_root
    parse_args "$@"
    check_os
    validate_settings
    case "$ACTION" in
        uninstall)    uninstall ;;
        add-monitor)
            [ -n "$MONITOR_KEY" ] || ask_monitor_key
            [ -n "$MONITOR_KEY" ] || die "Give the public key with --monitor-key or --monitor-key-file."
            step_install_peer_ctrl
            step_install_monitor
            ;;
        update-tools) step_install_peer_ctrl; step_install_tools ;;
        install)
            if [ "$argc" -eq 0 ] && is_tty; then show_menu; else install_all; fi
            ;;
    esac
}

main "$@"
