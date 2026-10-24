#!/bin/bash
# =============================================================================
# install-wg-full.sh - WireGuard server + HTTPS management API + health tooling
#
# Installs on Debian/Ubuntu, AlmaLinux/Rocky Linux/CentOS Stream/RHEL 9+/Fedora and Arch Linux:
#   - WireGuard (wg0, 10.66.0.0/16 = about 65,000 keys; --network253 for 10.66.66.0/24 = 253 keys)
#     with NAT/forward rules in PostUp/PostDown
#     (survive reboots) and ip_forward persisted in /etc/sysctl.d
#   - wg-api  (Node.js, localhost only) behind Caddy on an HTTPS port YOU choose
#     (the installer scans for free ports) with a Bearer token:
#     POST /create, POST /remove, GET /keys[/<ip>], GET /usage[/<ip>], GET /health,
#     plus Outline-style routes: GET/POST /access-keys, DELETE /access-keys/<ip>,
#     PUT /access-keys/<ip>/name, GET /server, GET /metrics/transfer,
#     pause/resume a key (POST /keys/<ip>/pause, /resume) and a traffic limit per key
#     (PUT /keys/<ip>/limit {"traffic":"20G"} or "unlimited"; also at create time), and a time limit per key
#     (PUT /keys/<ip>/expiry {"expires":"30d"} from now, {"expiresOn":"2026-12-31 18:00"} on that date and time of the
#     server's clock, or {"expiresAfterFirstConnection":"1m"}).
#     Access config in two formats (Mithra WireGuard Manager takes either):
#       {"apiUrl":"https://host:port","apiToken":"...","certSha256":"..."}
#       {"apiUrl":"https://host:port/<secret>","certSha256":"..."}   (exactly Outline's format:
#        GET <apiUrl>/access-keys returns every key, no header needed)
#     Nothing listens on port 80.
#   - /usr/local/bin/wg-firewall.sh    wg0's filter rules, run by wg-quick: clients cannot reach each other,
#                                      private/metadata networks or the server's own services; paused keys,
#                                      keys over their traffic limit and suspended ones are dropped first
#   - /usr/local/bin/wg-peer-ctrl.sh   restricted dispatcher (suspend, limits...)
#   - /usr/local/bin/wg-healthcheck.sh health check  (from the repo)
#   - /usr/local/bin/vpn-doctor.sh     diagnose + fix (from the repo)
#   - wg-monitor SSH account (optional, needs the management server's public key)
#   - a daily systemd timer that runs wg-healthcheck.sh
#
# Usage:
#   sudo ./install-wg-full.sh                        interactive menu
#   sudo ./install-wg-full.sh --domain=vpn-api.example.com --port=51820 --https-port=8443
#   sudo ./install-wg-full.sh --no-api               WireGuard + tools only (no Caddy/Node)
#   sudo ./install-wg-full.sh --reconfigure-api      change the API HTTPS port/certificate of an
#                                                    existing install (WireGuard keys untouched)
#   sudo ./install-wg-full.sh --add-monitor --monitor-key-file=/root/wg_monitor_key.pub
#   sudo ./install-wg-full.sh --update-tools         re-fetch healthcheck/doctor scripts
#   sudo ./install-wg-full.sh --update-api           rewrite wg-api-helper and server.js to this
#                                                    script's version, and the firewall rules (as
#                                                    --update-firewall); keys/peers untouched
#   sudo ./install-wg-full.sh --update-firewall      install wg-firewall.sh on an older server and
#                                                    switch wg0.conf to it, live (no restart)
#   sudo ./install-wg-full.sh --uninstall
#
# Options:
#   --domain=NAME            domain (or IP) clients use to reach the API
#   --port=N                 WireGuard UDP port (default 51820)
#   --https-port=N           public HTTPS port of the API; without it the installer shows
#                            which of 443 8443 2053 2083 2087 2096 (the HTTPS ports Cloudflare
#                            proxies) are free and asks
#   --tls=selfsigned|letsencrypt
#                            selfsigned (default): certificate made here, pinned by its SHA-256
#                            fingerprint like Outline's certSha256; needs no port 80/443.
#                            letsencrypt: only with --https-port=443 (validation needs the
#                            internet to reach 80 or 443)
#   --tls-cert=FILE --tls-key=FILE
#                            use your own certificate (copied; does not follow renewals)
#   --api-port=N             internal API port (default 4242)
#   --network253            use 10.66.66.0/24 (253 keys, the old install-wg3.sh pool) instead of the
#                            default 10.66.0.0/16 (about 65,000 keys)
#   --dns=IP[,IP]            DNS handed to clients (default 1.1.1.1)
#   --monitor-key="ssh-..."  public key of the management server (wg-monitor)
#   --monitor-key-file=FILE  same, read from a file
#   --no-api                 skip Caddy, Node and the API
#   --no-caddy               install the API but not Caddy; use this when nginx (or another
#                            web server) already owns 80/443. An nginx snippet is printed.
#   --allow-client-to-client let VPN clients reach each other (default: blocked)
#   --allow-private-nets     let VPN clients reach private, link-local (cloud metadata) and CGNAT
#                            addresses through the server (default: blocked)
#   --force                  replace an existing wg0.conf (backs it up first)
#   --yes, -y                do not ask questions
#
# Platforms: systemd-based Linux (WireGuard, iptables, tc and systemd are used directly)
#   debian family   apt-get   Ubuntu, Debian and derivatives
#   rhel family     dnf       AlmaLinux, Rocky, CentOS Stream, RHEL 9+, Fedora. EPEL / Caddy's COPR are enabled
#                             when a package is not in the base repositories. EL8 is refused: its kernel has no
#                             WireGuard module.
#   arch family     pacman    Arch Linux and derivatives. Uses 'pacman -S', never -Syu: upgrading the kernel
#                             without a reboot removes the running kernel's modules.
#   FreeBSD and Windows are detected and refused (exit code 3): they need a different implementation.
#
# healthcheck/doctor are copied from next to this script when present, otherwise
# downloaded from the GitHub repo at a fixed commit and checked against the SHA-256
# below before they are installed (they run as root).
#
# Safer than piping from a branch: download a release, check its SHA-256, then run it:
#   curl -fsSLo install-wg-full.sh https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/<tag>/install-wg-full.sh
#   sha256sum install-wg-full.sh      # compare with the release notes
#   sudo bash install-wg-full.sh
#
# Edit this script with: vi install-wg-full.sh
# =============================================================================

set -euo pipefail

# ----------------------------- settings ---------------------------------------
WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.0.0/16"        # default pool: about 65,000 keys (--network253 selects 10.66.66.0/24)
WG_SERVER_ADDR="10.66.0.1/16"
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
SCRIPT_VERSION="2.4.0"
# the health tools are fetched from this exact commit and must match these hashes (update both together)
REPO_RAW="https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/1764dec2a35b2f054217496e9e3ea929ebb59fe0"
declare -A TOOL_SHA256=(
    [wg-healthcheck.sh]="2568fda3965001df24741d02a87db26acc7e0a97f0a0f6a4112ac8c4acbd1d3f"
    [vpn-doctor.sh]="6e07438934258fcc2256c2f73838d84f6a2694faddbef9d6c9b0becbbd750575"
)
# NodeSource's signing key, only used when the distribution's own nodejs is older than 18
NODESOURCE_FPR="6F71F525282841EEDAF851B42F59B5F99B1BE0B4"
# exact npm versions of the API (installed with --ignore-scripts)
NPM_PACKAGES=(express@4.22.3 express-rate-limit@7.5.1 helmet@8.1.0)
FW_SCRIPT="${BIN_DIR}/wg-firewall.sh"
FW_OPTS="/etc/wireguard/wg-firewall.conf"
FW_ISOLATION=1
FW_BLOCK_PRIVATE=1
FW_HOOK_UP="PostUp = ${BIN_DIR}/wg-firewall.sh up"
FW_HOOK_DOWN="PostDown = ${BIN_DIR}/wg-firewall.sh down"
# BASH_SOURCE is empty when the script is piped (curl ... | sudo bash -s -- ...), and set -u would stop on it
SELF="${BASH_SOURCE[0]:-}"
SCRIPT_DIR="$( [ -n "$SELF" ] && cd "$(dirname "$SELF")" 2>/dev/null && pwd || echo . )"

DOMAIN=""
HTTPS_PORT=""
TLS_MODE=""
TLS_CERT=""
TLS_KEY=""
TLS_DIR="/etc/caddy/wg-api-tls"
TLS_FINGERPRINT=""
TLS_PIN=""
ACCESS_FILE="${API_ENV_DIR}/access.json"
ACCESS_OUTLINE_FILE="${API_ENV_DIR}/access-outline.json"
API_PATH=""
# how to call this script again in printed hints: run through 'bash <(curl ...)' $0 is /dev/fd/NN
case "$0" in
    /dev/fd/*|/proc/*) SELF_CMD="bash install-wg-full.sh" ;;
    *)                 SELF_CMD="$0" ;;
esac
API_URL=""
OUT_IFACE=""
SERVER_PUBLIC_KEY=""
API_TOKEN=""
PORT_FROM_FLAG=0
INSTALL_API=1
INSTALL_CADDY=1
ASSUME_YES=0
FORCE=0
ACTION="install"
# filled in by check_os
OS_ID="unknown"
OS_VER=""
OS_NAME="unknown"
OS_FAMILY="unknown"     # debian | rhel | arch
PKG_MGR=""              # apt-get | dnf | yum | pacman
NOLOGIN="/usr/sbin/nologin"
NGINX_SITE_HINT="/etc/nginx/sites-enabled/<your-site>"

# ----------------------------- output helpers ---------------------------------

# Usage: say "message"   -> progress line
say() { printf '→ %s\n' "$*"; }

# Usage: ok "message"    -> success line
ok() { printf '  ✓ %s\n' "$*"; }

# Usage: warn "message"  -> non-fatal problem, printed on stderr
warn() { printf '  ⚠ %s\n' "$*" >&2; }

# Usage: die "message"   -> print an error and exit 1
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Usage: green "text"    -> the text in bold green on a terminal (unchanged when piped, or with NO_COLOR set)
#        Used for the access config lines, so they are easy to find in the long summary.
green() {
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then printf '\033[1;32m%s\033[0m' "$*"; else printf '%s' "$*"; fi
}

# Usage: access_line <file> [note] -> prints one saved access config (compact JSON, in green), indented, then the note
access_line() {
    [ -f "$1" ] || return 0
    local j
    j="$(jq -c . "$1" 2>/dev/null)" || return 0
    printf '    '
    green "$j"
    printf '%s\n' "${2:+   $2}"
}

# Usage: have <command>  -> 0 if the command exists
have() { command -v "$1" >/dev/null 2>&1; }

# Usage: is_tty          -> 0 if stdin is a terminal (safe to ask questions)
is_tty() { [ -t 0 ]; }

# Usage: show_help       -> prints the header comment as help text
show_help() {
    if [ -n "$SELF" ] && [ -r "$SELF" ]; then
        awk 'NR==2{next} /^# =+$/{exit} {print}' "$SELF" | sed 's/^# \{0,1\}//'
    else
        echo "Download the script first to read its help:  curl -LO $REPO_RAW/install-wg-full.sh && bash install-wg-full.sh --help"
    fi
}

# ----------------------------- checks and arguments ---------------------------

# Usage: check_root      -> exits unless running as root
check_root() {
    [ "$EUID" -eq 0 ] || die "This script must be run as root (sudo ${SELF_CMD})."
}

# Usage: os_release_get <KEY> -> prints one value from /etc/os-release (ID, VERSION_ID, ID_LIKE, PRETTY_NAME) without
#        sourcing the file, so it cannot overwrite this script's own variables. OS_RELEASE_FILE overrides the path (tests).
os_release_get() {
    local f="${OS_RELEASE_FILE:-/etc/os-release}"
    [ -r "$f" ] || return 0
    sed -n "s/^$1=//p" "$f" | head -n1 | tr -d '"' || true
}

# Usage: unsupported_platform <name> <reason> -> explains why this installer cannot run there and exits with code 3
unsupported_platform() {
    printf 'ERROR: unsupported platform: %s\n' "$1" >&2
    printf '       %s\n' "$2" >&2
    exit 3
}

# Usage: require_systemd -> exits unless systemd is the running init system (wg-quick, wg-api and the timers are units)
require_systemd() {
    have systemctl && [ -d /run/systemd/system ] \
        || die "systemd is required (it runs wg-quick, wg-api and the timers) but it is not the init system here."
}

# Usage: check_os        -> detects the platform: sets OS_ID, OS_VER, OS_NAME, OS_FAMILY (debian|rhel|arch), PKG_MGR,
#                           NOLOGIN and NGINX_SITE_HINT. Exits with code 3 on FreeBSD, Windows and other kernels.
check_os() {
    local kernel like major
    kernel="$(uname -s 2>/dev/null || echo unknown)"
    case "$kernel" in
        Linux) ;;
        FreeBSD)
            unsupported_platform "FreeBSD $(uname -r 2>/dev/null)" \
                "FreeBSD has WireGuard, but not systemd, iptables or tc: the service, firewall and speed-limit layers here are Linux-only. A FreeBSD version needs its own script (pf, rc.d)." ;;
        MINGW*|MSYS*|CYGWIN*|Windows*)
            unsupported_platform "Windows ($kernel)" \
                "Windows has WireGuard as a tunnel service, but no wg-quick, iptables, tc or systemd, which this installer and its API helper depend on. Use a Linux server or a Linux VM." ;;
        *)
            unsupported_platform "$kernel" "A systemd-based Linux server is required." ;;
    esac

    [ -r "${OS_RELEASE_FILE:-/etc/os-release}" ] || die "Cannot detect the OS (/etc/os-release missing)."
    OS_ID="$(os_release_get ID)"
    OS_VER="$(os_release_get VERSION_ID)"
    like="$(os_release_get ID_LIKE)"
    OS_NAME="$(os_release_get PRETTY_NAME)"
    OS_NAME="${OS_NAME:-${OS_ID} ${OS_VER}}"

    case " ${OS_ID} ${like} " in
        *" ubuntu "*|*" debian "*)
            OS_FAMILY="debian"; PKG_MGR="apt-get" ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" almalinux "*|*" rocky "*)
            OS_FAMILY="rhel"
            if have dnf; then PKG_MGR="dnf"; else PKG_MGR="yum"; fi
            NGINX_SITE_HINT="/etc/nginx/conf.d/<your-site>.conf" ;;
        *" arch "*|*" archlinux "*)
            OS_FAMILY="arch"; PKG_MGR="pacman"
            NGINX_SITE_HINT="/etc/nginx/nginx.conf (or a file it includes)" ;;
        *)
            die "Unsupported OS '${OS_NAME}'. This installer supports Debian/Ubuntu, AlmaLinux/Rocky/CentOS Stream/RHEL 9+/Fedora and Arch Linux." ;;
    esac

    major="${OS_VER%%.*}"
    if [ "$OS_FAMILY" = "rhel" ] && [ "$OS_ID" != "fedora" ] && [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -lt 9 ]; then
        die "${OS_NAME} is not supported: EL8 kernels have no WireGuard module (it needs ELRepo's kmod-wireguard). Use EL9 or newer."
    fi
    case "$OS_ID" in
        ubuntu) if [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -lt 20 ]; then warn "Ubuntu ${OS_VER} is older than 20.04: WireGuard may need a PPA or a backport."; fi ;;
        debian) if [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -lt 11 ]; then warn "Debian ${OS_VER} is older than 11: WireGuard may need backports."; fi ;;
    esac

    NOLOGIN="$(command -v nologin 2>/dev/null || true)"
    [ -n "$NOLOGIN" ] || NOLOGIN="/usr/sbin/nologin"
    require_systemd
}

# Usage: pkg_update      -> refreshes the package index where the manager needs it (apt); a no-op for dnf and pacman
pkg_update() {
    if [ "$PKG_MGR" = "apt-get" ]; then apt-get update -y >/dev/null 2>&1 || true; fi
}

# Usage: pkg_install <package...> -> installs packages non-interactively with the distribution's package manager
pkg_install() {
    case "$PKG_MGR" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        dnf)     dnf install -y "$@" ;;
        yum)     yum install -y "$@" ;;
        pacman)  pacman -S --noconfirm --needed "$@" ;;
        *)       return 1 ;;
    esac
}

# Usage: pkg_remove <package...> -> removes packages (and unused dependencies / config where the manager can)
pkg_remove() {
    case "$PKG_MGR" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y "$@" && apt-get autoremove -y ;;
        dnf)     dnf remove -y "$@" ;;
        yum)     yum remove -y "$@" ;;
        pacman)  pacman -Rns --noconfirm "$@" ;;
        *)       return 1 ;;
    esac
}

# Usage: ensure_cmd <command> <package...> -> installs the packages only when the command is missing; dies if it still is
ensure_cmd() {
    local c="$1"; shift
    have "$c" && return 0
    say "Installing $* (provides '$c')..."
    pkg_install "$@" || die "Could not install: $*"
    have "$c" || die "'$c' is still missing after installing: $*"
}

# Usage: check_sudoers_include -> exits unless /etc/sudoers reads /etc/sudoers.d (every default install does; the helper
#        and monitor entries live there)
check_sudoers_include() {
    if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers\.d' /etc/sudoers 2>/dev/null; then
        die "/etc/sudoers does not include /etc/sudoers.d. Add the line '#includedir /etc/sudoers.d' with 'visudo' and run again."
    fi
}

# Usage: parse_args "$@" -> fills the settings above from the command line
parse_args() {
    local a
    for a in "$@"; do
        case "$a" in
            --port=*)             WG_PORT="${a#*=}"; PORT_FROM_FLAG=1 ;;
            --api-port=*)         API_PORT_INTERNAL="${a#*=}" ;;
            --domain=*)           DOMAIN="${a#*=}" ;;
            --https-port=*)       HTTPS_PORT="${a#*=}" ;;
            --tls=*)              TLS_MODE="${a#*=}" ;;
            --tls-cert=*)         TLS_CERT="${a#*=}" ;;
            --tls-key=*)          TLS_KEY="${a#*=}" ;;
            --reconfigure-api)    ACTION="reconfigure-api" ;;
            --dns=*)              CLIENT_DNS="${a#*=}" ;;
            --monitor-key=*)      MONITOR_KEY="${a#*=}" ;;
            --monitor-key-file=*) MONITOR_KEY_FILE="${a#*=}" ;;
            --no-api)             INSTALL_API=0 ;;
            --no-caddy)           INSTALL_CADDY=0 ;;
            --force)              FORCE=1 ;;
            --yes|-y)             ASSUME_YES=1 ;;
            --uninstall|-u)       ACTION="uninstall" ;;
            --add-monitor)        ACTION="add-monitor" ;;
            --network253)         WG_NETWORK="10.66.66.0/24"; WG_SERVER_ADDR="10.66.66.1/24" ;;
            --update-tools)       ACTION="update-tools" ;;
            --update-api)         ACTION="update-api" ;;
            --update-firewall)    ACTION="update-firewall" ;;
            --allow-client-to-client) FW_ISOLATION=0 ;;
            --allow-private-nets) FW_BLOCK_PRIVATE=0 ;;
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
    if [ -n "$HTTPS_PORT" ]; then
        valid_port "$HTTPS_PORT" || die "Invalid HTTPS port '$HTTPS_PORT'."
    fi
    case "$TLS_MODE" in
        ""|selfsigned|letsencrypt) ;;
        *) die "--tls must be 'selfsigned' or 'letsencrypt'." ;;
    esac
    if [ -n "${TLS_CERT}${TLS_KEY}" ]; then
        { [ -r "$TLS_CERT" ] && [ -r "$TLS_KEY" ]; } || die "--tls-cert and --tls-key must both be given and readable."
        TLS_MODE="custom"
    fi
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
        echo "Enter the domain (or public IP) clients will use to reach the API."
        echo "A domain's A record should point to this server's public IP."
        read -r -p "Domain or IP (e.g. vpn-api.example.com): " DOMAIN
    fi
    [ -n "$DOMAIN" ] || die "A domain is required (or use --no-api)."
    [[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "Invalid domain '$DOMAIN'."
}

# Usage: port_in_use <port>  -> 0 if something is listening on that TCP port
port_in_use() { [ -n "$(ss -H -ltn "sport = :$1" 2>/dev/null)" ]; }

# Usage: port_owner <port>   -> names of the processes listening on that TCP port ("unknown" if hidden)
port_owner() {
    local o
    o="$(ss -H -ltnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ')"
    o="${o% }"
    printf '%s' "${o:-unknown}"
}

# Usage: port_usable <port>  -> 0 if the port is free, or held only by our own Caddy (a re-run)
port_usable() { ! port_in_use "$1" || [[ "$(port_owner "$1")" == *caddy* ]]; }

# Usage: https_port_problem <port> -> prints why the port cannot be used and returns 0; returns 1 when it is fine
https_port_problem() {
    local p="$1"
    if ! valid_port "$p"; then echo "not a valid port"; return 0; fi
    case "$p" in
        22) echo "that is the SSH port"; return 0 ;;
        80) echo "port 80 is plain HTTP and is not used by this installer"; return 0 ;;
    esac
    if [ "$p" -eq "$API_PORT_INTERNAL" ]; then echo "that is the internal API port"; return 0; fi
    if ! port_usable "$p"; then echo "in use by $(port_owner "$p")"; return 0; fi
    return 1
}

# Usage: cloudflare_port_note <port> -> warns when the port is not one Cloudflare proxies for HTTPS
cloudflare_port_note() {
    case "$1" in
        443|2053|2083|2087|2096|8443) ;;
        *) warn "Port $1 is not a Cloudflare-proxied HTTPS port (443 2053 2083 2087 2096 8443): fine with a DNS-only (grey cloud) record, but it will not work through the Cloudflare proxy." ;;
    esac
}

# Usage: ask_https_port -> scans the Cloudflare HTTPS ports and picks one: --https-port, a menu choice, or the first free one
ask_https_port() {
    [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] || return 0
    if ! have ss; then
        pkg_update
        case "$OS_FAMILY" in
            rhel) pkg_install iproute >/dev/null 2>&1 || true ;;
            *)    pkg_install iproute2 >/dev/null 2>&1 || true ;;
        esac
    fi
    have ss || die "'ss' (iproute2) is needed to check which ports are free."

    if port_in_use "$API_PORT_INTERNAL" && ! systemctl is-active --quiet "$API_SERVICE" 2>/dev/null; then
        die "Internal API port ${API_PORT_INTERNAL} is in use by $(port_owner "$API_PORT_INTERNAL"). Pass --api-port=N."
    fi

    # the HTTPS ports Cloudflare proxies, so the API also works behind an orange-cloud DNS record
    local candidates=(443 8443 2053 2083 2087 2096) p i=0 default="" ans reason=""
    if [ -n "$HTTPS_PORT" ]; then
        if reason="$(https_port_problem "$HTTPS_PORT")"; then die "Cannot use HTTPS port ${HTTPS_PORT}: ${reason}."; fi
        ok "HTTPS port ${HTTPS_PORT} is free"
        cloudflare_port_note "$HTTPS_PORT"
        return 0
    fi

    if [ "$ASSUME_YES" -eq 1 ] || ! is_tty; then
        for p in "${candidates[@]}"; do
            if ! https_port_problem "$p" >/dev/null; then HTTPS_PORT="$p"; break; fi
        done
        [ -n "$HTTPS_PORT" ] || die "None of the usual HTTPS ports (${candidates[*]}) is free. Pass --https-port=N, or use --no-caddy and proxy the API from the web server that owns 443."
        say "Using HTTPS port ${HTTPS_PORT} (first free one)"
        return 0
    fi

    echo
    echo "HTTPS port for the management API (TCP), from Cloudflare's proxied HTTPS ports:"
    for p in "${candidates[@]}"; do
        i=$((i+1))
        if reason="$(https_port_problem "$p")"; then
            printf '  %d) %-5s unavailable: %s\n' "$i" "$p" "$reason"
        else
            printf '  %d) %-5s free\n' "$i" "$p"
            [ -n "$default" ] || default="$p"
        fi
    done
    while :; do
        if [ -n "$default" ]; then
            read -r -p "Choose 1-${#candidates[@]}, type any port, or press Enter for ${default}: " ans
        else
            read -r -p "No usual port is free. Type a free port: " ans
        fi
        [ -n "$ans" ] || ans="$default"
        if [ -z "$ans" ]; then echo "  Please enter a port."; continue; fi
        if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le "${#candidates[@]}" ]; then
            ans="${candidates[$((ans-1))]}"
        fi
        if reason="$(https_port_problem "$ans")"; then echo "  Port ${ans} cannot be used: ${reason}."; continue; fi
        HTTPS_PORT="$ans"
        break
    done
    ok "HTTPS port ${HTTPS_PORT}"
    cloudflare_port_note "$HTTPS_PORT"
}

# Usage: ask_tls_mode -> decides the certificate type: custom (own files), letsencrypt (443 only) or selfsigned (default)
ask_tls_mode() {
    [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] || return 0
    local ans=""
    if [ -z "$TLS_MODE" ]; then
        TLS_MODE="selfsigned"
        if [ "$HTTPS_PORT" = "443" ] && [ "$ASSUME_YES" -ne 1 ] && is_tty; then
            echo
            echo "Port 443 can use a real Let's Encrypt certificate, but the validation needs"
            echo "this server reachable from the internet on port 80 or 443 for the domain."
            read -r -p "Use Let's Encrypt? [y/N]: " ans
            if [[ "$ans" =~ ^[Yy]$ ]]; then TLS_MODE="letsencrypt"; fi
        fi
    fi
    if [ "$TLS_MODE" = "letsencrypt" ] && [ "$HTTPS_PORT" != "443" ]; then
        die "Let's Encrypt needs port 443 (validation cannot use ${HTTPS_PORT}). Use --tls=selfsigned or --https-port=443."
    fi
    if [ "$TLS_MODE" = "letsencrypt" ] && ! port_usable 80; then
        die "Let's Encrypt through Caddy also needs port 80 free, but it is used by $(port_owner 80). Use --tls=selfsigned."
    fi
    ok "TLS mode: ${TLS_MODE}"
}

# Usage: compute_api_url -> sets API_URL (the port is omitted when it is 443 or Caddy is not used)
compute_api_url() {
    if [ -z "$HTTPS_PORT" ] || [ "$HTTPS_PORT" = "443" ]; then
        API_URL="https://${DOMAIN}"
    else
        API_URL="https://${DOMAIN}:${HTTPS_PORT}"
    fi
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

# Usage: install_packages_debian -> WireGuard, iptables and the helper tools through apt
install_packages_debian() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y wireguard wireguard-tools iptables iptables-persistent \
        iproute2 curl openssl gnupg sudo jq ca-certificates dnsutils tcpdump
}

# Usage: enable_epel     -> turns on EPEL (and CRB where it exists) on EL clones and RHEL; Fedora needs neither
enable_epel() {
    [ "$OS_ID" = "fedora" ] && return 0
    say "Enabling EPEL..."
    if [ "$OS_ID" = "rhel" ]; then
        pkg_install "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_VER%%.*}.noarch.rpm" \
            || die "Could not enable EPEL."
    else
        pkg_install epel-release || die "Could not enable EPEL (package epel-release)."
    fi
    # some EPEL packages need CodeReady Builder; best effort, the name differs on RHEL proper
    if pkg_install 'dnf-command(config-manager)' >/dev/null 2>&1; then
        dnf config-manager --set-enabled crb >/dev/null 2>&1 || true
    fi
}

# Usage: install_packages_rhel -> WireGuard, iptables (nft backend), tc and the helper tools through dnf
install_packages_rhel() {
    # wireguard-tools is in AppStream on some releases and in EPEL on others: try the base repositories first
    if ! pkg_install wireguard-tools >/dev/null 2>&1; then
        enable_epel
        pkg_install wireguard-tools || die "Could not install wireguard-tools (EPEL was enabled and tried)."
    fi
    ensure_cmd iptables iptables-nft
    ensure_cmd tc iproute-tc
    pkg_install iproute curl openssl gnupg2 sudo jq ca-certificates bind-utils tcpdump util-linux \
        || die "Could not install the required packages."
    # the ifb / htb / u32 modules used for per-key speed limits live here on some releases; best effort
    pkg_install kernel-modules-extra >/dev/null 2>&1 \
        || warn "kernel-modules-extra could not be installed; per-key speed limits need the ifb and sch_htb modules."
}

# Usage: install_packages_arch -> WireGuard, iptables and the helper tools through pacman (never -Syu)
install_packages_arch() {
    if [ ! -d "/usr/lib/modules/$(uname -r)" ]; then
        warn "The running kernel's modules are missing (the kernel was upgraded without a reboot). Reboot, then run this installer again."
    fi
    pkg_install wireguard-tools openssl gnupg sudo jq ca-certificates bind tcpdump iproute2 curl openssh util-linux \
        || die "pacman could not install the packages. On 404 errors the package database is stale: run 'pacman -Syu', reboot, and run this installer again."
    ensure_cmd iptables iptables
}

# Usage: check_wireguard_module -> reports whether the WireGuard kernel module can be loaded (warns only: DKMS builds and
#        a pending reboot after a kernel update are the usual reasons it cannot yet)
check_wireguard_module() {
    if [ -d /sys/module/wireguard ] || modprobe wireguard 2>/dev/null; then
        ok "WireGuard kernel module is available"
    else
        warn "The WireGuard kernel module cannot be loaded now. After a kernel update a reboot is needed; otherwise the kernel lacks it (wg-quick will say so)."
    fi
}

# Usage: install_node_rhel -> Node.js from the highest AppStream module stream (22, 20, 18) that exists; Fedora has it plain
install_node_rhel() {
    local v
    if [ "$OS_ID" != "fedora" ] && have dnf; then
        for v in 22 20 18; do
            if dnf -q module list nodejs 2>/dev/null | grep -Eq "^nodejs[[:space:]]+${v}[[:space:]]"; then
                dnf -y module reset nodejs >/dev/null 2>&1 || true
                if dnf -y module install "nodejs:${v}" >/dev/null 2>&1; then break; fi
            fi
        done
    fi
    have node || pkg_install nodejs npm >/dev/null 2>&1 || true
}

# Usage: install_node_nodesource_rpm -> Node.js 22 from NodeSource's RPM repository; the signing key must have the
#        fingerprint in NODESOURCE_FPR, and the verified key file is the one the repository is configured with
install_node_nodesource_rpm() {
    say "Installing Node.js 22 from NodeSource (key ${NODESOURCE_FPR})..."
    local keyfile=/etc/pki/rpm-gpg/RPM-GPG-KEY-nodesource tmp got
    tmp="$(mktemp)"
    curl -fsSL https://rpm.nodesource.com/gpgkey/ns-operations-public.key -o "$tmp" \
        || { rm -f "$tmp"; die "Could not download NodeSource's key."; }
    got="$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }' || true)"
    if [ "$got" != "$NODESOURCE_FPR" ]; then
        rm -f "$tmp"
        die "NodeSource's key has fingerprint '${got:-unknown}', expected ${NODESOURCE_FPR}. Install Node.js 18+ yourself (dnf module install nodejs:20) and run again."
    fi
    install -d -m 755 /etc/pki/rpm-gpg
    install -m 644 "$tmp" "$keyfile"
    rm -f "$tmp"
    cat > /etc/yum.repos.d/nodesource-nodejs.repo <<'NODESOURCE_REPO_EOF'
[nodesource-nodejs]
name=Node.js 22 packages for Linux RPM based distros - $basearch
baseurl=https://rpm.nodesource.com/pub_22.x/nodistro/nodejs/$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-nodesource
module_hotfixes=1
NODESOURCE_REPO_EOF
    pkg_install nodejs
}

# Usage: install_nodejs  -> makes sure Node.js 18+ and npm exist: the distribution's package first, NodeSource if too old
install_nodejs() {
    local major=0
    have node && major="$(node_major)"
    if [ "$major" -lt 18 ]; then
        # the distribution's own package first (Debian 12, Ubuntu 24.04: Node 18)
        case "$OS_FAMILY" in
            debian) apt-get install -y nodejs >/dev/null 2>&1 || true ;;
            rhel)   install_node_rhel ;;
            arch)   pkg_install nodejs npm >/dev/null 2>&1 || true ;;
        esac
        have node && major="$(node_major)"
    fi
    if [ "$major" -lt 18 ]; then
        case "$OS_FAMILY" in
            debian) install_node_nodesource ;;
            rhel)   install_node_nodesource_rpm ;;
            arch)   die "Node.js 18+ is required but pacman provides version ${major}. Update the system (pacman -Syu), reboot, and run again." ;;
        esac
    fi
    have npm || pkg_install npm
    ok "Node $(node -v), npm $(npm -v)"
}

# Usage: step_install_packages -> packages for this distribution family, then Node.js (if missing or older than 18)
step_install_packages() {
    say "Installing required packages (${OS_FAMILY} family, ${PKG_MGR})..."
    case "$OS_FAMILY" in
        debian) install_packages_debian ;;
        rhel)   install_packages_rhel ;;
        arch)   install_packages_arch ;;
    esac
    local c
    for c in wg wg-quick iptables iptables-restore ip tc ss curl jq openssl flock logger visudo; do
        have "$c" || die "'$c' is missing after the package installation."
    done
    check_wireguard_module
    if [ "$INSTALL_API" -eq 1 ]; then install_nodejs; fi
}

# Usage: node_major -> major version of the installed node (0 when missing)
node_major() { node -v 2>/dev/null | sed 's/^v//; s/\..*//' | grep -E '^[0-9]+$' || echo 0; }

# Usage: install_node_nodesource -> Node.js 22 from NodeSource's apt repository; the signing key must have the
#        fingerprint in NODESOURCE_FPR (no script is piped into bash)
install_node_nodesource() {
    say "Installing Node.js 22 from NodeSource (key ${NODESOURCE_FPR})..."
    local kr=/usr/share/keyrings/nodesource.gpg tmp got
    tmp="$(mktemp)"
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o "$tmp" || { rm -f "$tmp"; die "Could not download NodeSource's key."; }
    got="$(gpg --show-keys --with-colons "$tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')"
    if [ "$got" != "$NODESOURCE_FPR" ]; then
        rm -f "$tmp"
        die "NodeSource's key has fingerprint '${got:-unknown}', expected ${NODESOURCE_FPR}. Install Node.js 18+ yourself (apt install nodejs) and run again."
    fi
    gpg --dearmor --yes -o "$kr" "$tmp"
    rm -f "$tmp"
    chmod 644 "$kr"
    echo "deb [signed-by=${kr}] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
    apt-get update -y
    apt-get install -y nodejs
}

# Usage: step_install_caddy -> Caddy from the official apt repo (skipped if already installed)
step_install_caddy() {
    [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] || return 0
    if have caddy; then ok "Caddy already installed"; return 0; fi
    say "Installing Caddy..."
    case "$OS_FAMILY" in
        debian)
            apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
            curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt -o /etc/apt/sources.list.d/caddy-stable.list
            apt-get update -y
            apt-get install -y caddy
            ;;
        rhel)
            # Fedora ships Caddy; EL does not, so Caddy's own COPR repository is the fallback
            if ! pkg_install caddy >/dev/null 2>&1; then
                pkg_install 'dnf-command(copr)' || die "Could not install the dnf copr plugin needed for Caddy."
                dnf copr enable -y @caddy/caddy || die "Could not enable the Caddy COPR repository."
                pkg_install caddy || die "Could not install caddy."
            fi
            ;;
        arch)
            pkg_install caddy || die "Could not install caddy."
            ;;
    esac
    # the package starts a default site on port 80; stop it until our own config is in place
    systemctl disable --now caddy >/dev/null 2>&1 || true
    id caddy >/dev/null 2>&1 || useradd -r -s "$NOLOGIN" -d /var/lib/caddy caddy
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
# The filter rules (isolation, suspend, INPUT) are made by wg-firewall.sh, always in the same order.
PostUp = iptables -t nat -C POSTROUTING -s ${WG_NETWORK} ! -d ${WG_NETWORK} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${WG_NETWORK} ! -d ${WG_NETWORK} -j MASQUERADE
${FW_HOOK_UP}
${FW_HOOK_DOWN}
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
    local opened="${WG_PORT}/udp"
    if [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] && [ -n "$HTTPS_PORT" ]; then
        ufw allow "${HTTPS_PORT}/tcp" >/dev/null
        opened="${opened}, ${HTTPS_PORT}/tcp"
    fi
    ufw route allow in on "$WG_INTERFACE" out on "$OUT_IFACE" >/dev/null || true
    ok "ufw: ${opened} and routing for ${WG_INTERFACE} (port 80 is not opened)"
}

# Usage: step_firewall_firewalld -> if firewalld is running, opens the WireGuard UDP port and the HTTPS port (now and
#        permanently). Forwarding wg0 -> uplink works when both are in the same firewalld zone (the default zone).
step_firewall_firewalld() {
    have firewall-cmd || return 0
    firewall-cmd --state >/dev/null 2>&1 || return 0
    say "firewalld is running: adding rules..."
    local opened="${WG_PORT}/udp" spec
    local -a specs=("${WG_PORT}/udp")
    if [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] && [ -n "$HTTPS_PORT" ]; then
        specs+=("${HTTPS_PORT}/tcp")
        opened="${opened}, ${HTTPS_PORT}/tcp"
    fi
    for spec in "${specs[@]}"; do
        firewall-cmd --add-port="$spec" >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port="$spec" >/dev/null 2>&1 || warn "Could not add ${spec} to firewalld permanently."
    done
    ok "firewalld: ${opened} (port 80 is not opened)"
    echo "    note: if clients connect but have no internet, check that ${WG_INTERFACE} and the uplink share a zone: firewall-cmd --get-active-zones"
}

# Usage: step_firewall_host -> opens the ports in whichever host firewall is active (ufw, firewalld) and flags nftables
step_firewall_host() {
    step_firewall_ufw
    step_firewall_firewalld
    if systemctl is-active --quiet nftables 2>/dev/null; then
        warn "nftables.service is active: make sure its ruleset allows udp/${WG_PORT}${HTTPS_PORT:+ and tcp/${HTTPS_PORT}} and forwarding from ${WG_INTERFACE} (vi /etc/nftables.conf)."
    fi
}

# Usage: step_selinux    -> EL with SELinux enforcing: labels a non-standard HTTPS port as http_port_t so Caddy can listen
#        (best effort; needs semanage)
step_selinux() {
    [ "$OS_FAMILY" = "rhel" ] || return 0
    [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] && [ -n "$HTTPS_PORT" ] || return 0
    have getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ] || return 0
    case "$HTTPS_PORT" in 80|81|443|488|8008|8009|8443|9000) return 0 ;; esac   # already web ports in the policy
    have semanage || pkg_install policycoreutils-python-utils >/dev/null 2>&1 || true
    if have semanage \
        && { semanage port -a -t http_port_t -p tcp "$HTTPS_PORT" 2>/dev/null || semanage port -m -t http_port_t -p tcp "$HTTPS_PORT" 2>/dev/null; }; then
        ok "SELinux: tcp/${HTTPS_PORT} labelled http_port_t so Caddy can listen"
    else
        warn "SELinux is enforcing and tcp/${HTTPS_PORT} is not a web port. If Caddy cannot bind: semanage port -a -t http_port_t -p tcp ${HTTPS_PORT}"
    fi
}

# Usage: step_install_firewall -> installs wg-firewall.sh (run by wg-quick PostUp/PostDown) and its options file
step_install_firewall() {
    say "Installing wg-firewall.sh..."
    cat > "${FW_SCRIPT}.new" <<'WG_FIREWALL_EOF'
#!/bin/bash
# wg-firewall.sh - the filter rules of wg0, run by wg-quick (PostUp/PostDown) and by wg-api-helper.
# Installed by install-wg-full.sh; edit the options with: vi /etc/wireguard/wg-firewall.conf
#
#   wg-firewall.sh up             (re)apply every rule in a fixed order (idempotent; removes rules of older versions)
#   wg-firewall.sh down           remove every rule this script made
#   wg-firewall.sh sync-suspend   rebuild the WG-SUSPEND chain from the saved state (paused / over-limit keys)
#   wg-firewall.sh status         print the rules
#
# FORWARD gets one block at the top, always in this order, so a suspension can never be bypassed:
#   1  -j WG-SUSPEND                              paused, over-limit and expired keys, wg-peer-ctrl suspensions
#   2  -i wg0 -j WG-GUARD                         no client-to-client, no private / metadata networks
#   3  -i wg0 -j ACCEPT
#   4  -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
#   5  -o wg0 -j WG-NOINBOUND                     nothing else may enter the tunnel from outside
# INPUT gets: udp/<port> ACCEPT, then -i wg0 -j WG-IN (clients may not reach the server's own services).
# The NAT (MASQUERADE) rule stays in wg0.conf's own PostUp/PostDown lines.
# The suspend state lives in files, so it survives restarts and reboots without netfilter-persistent:
#   /etc/wg-api/policy.db          ip<TAB>pubkey<TAB>paused<TAB>limit bytes<TAB>over limit<TAB>...<TAB>expired (wg-api-helper)
#   /etc/wireguard/suspended.list  one CIDR per line                                         (wg-peer-ctrl.sh)
set -euo pipefail

WG_IF="wg0"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
OPTS="/etc/wireguard/wg-firewall.conf"
POLICY_DB="/etc/wg-api/policy.db"
SUSPEND_LIST="/etc/wireguard/suspended.list"
IPT="$(command -v iptables || echo /usr/sbin/iptables)"

# options (1 = on); /etc/wireguard/wg-firewall.conf may override them
CLIENT_ISOLATION=1        # clients cannot reach each other
BLOCK_PRIVATE_NETS=1      # clients cannot reach private, link-local (cloud metadata) or CGNAT addresses
BLOCK_SERVER_ACCESS=1     # clients cannot open connections to the server itself (ping and DNS still work)
PRIVATE_NETS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 0.0.0.0/8 127.0.0.0/8 224.0.0.0/4 240.0.0.0/4"
# shellcheck disable=SC1090
[ -r "$OPTS" ] && . "$OPTS"

# Usage: wg_port -> prints ListenPort of wg0.conf (empty when missing)
wg_port() { sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$WG_CONF" 2>/dev/null | head -n1; }

# Usage: our_rules -> one rule per line: "<chain> <iptables arguments>", in the order they must appear (top first)
our_rules() {
    local p; p="$(wg_port)"
    [ -n "$p" ] && echo "INPUT -p udp --dport ${p} -j ACCEPT"
    [ "$BLOCK_SERVER_ACCESS" = "1" ] && echo "INPUT -i ${WG_IF} -j WG-IN"
    echo "FORWARD -j WG-SUSPEND"
    echo "FORWARD -i ${WG_IF} -j WG-GUARD"
    echo "FORWARD -i ${WG_IF} -j ACCEPT"
    echo "FORWARD -o ${WG_IF} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    echo "FORWARD -o ${WG_IF} -j WG-NOINBOUND"
}

# Usage: legacy_rules -> rules made by older versions of install-wg-full.sh / wg-peer-ctrl.sh (removed on 'up')
legacy_rules() {
    echo "FORWARD -i ${WG_IF} -j ACCEPT"
    echo "FORWARD -o ${WG_IF} -j ACCEPT"
    echo "FORWARD -j WG-SUSPEND"
    echo "INPUT -i ${WG_IF} -j WG-IN"
}

# Usage: del_all "<chain> <args>" -> deletes every copy of one rule
del_all() {
    local chain="${1%% *}" args="${1#* }"
    # intentional word splitting: the rules above are plain tokens
    # shellcheck disable=SC2086
    while "$IPT" -D "$chain" $args 2>/dev/null; do :; done
}

# Usage: remove_rules -> removes our rules and the legacy ones from INPUT/FORWARD
remove_rules() {
    local r
    while IFS= read -r r; do [ -n "$r" ] && del_all "$r"; done < <(our_rules; legacy_rules)
}

# Usage: valid_cidr <x> -> 0 for a.b.c.d or a.b.c.d/n
valid_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]]; }

# Usage: blocked_cidrs -> every address that must be dropped right now (paused, over limit, suspended)
blocked_cidrs() {
    if [ -r "$POLICY_DB" ]; then
        # paused, over the traffic limit, or past the end of its time limit
        awk -F'\t' '($3 == "1" || $5 == "1" || $9 == "1") { print $1 "/32" }' "$POLICY_DB"
    fi
    if [ -r "$SUSPEND_LIST" ]; then
        grep -vE '^[[:space:]]*(#|$)' "$SUSPEND_LIST" || true
    fi
}

# Usage: sync_suspend -> replaces the content of WG-SUSPEND in one atomic iptables-restore
sync_suspend() {
    local c
    "$IPT" -nL WG-SUSPEND >/dev/null 2>&1 || "$IPT" -N WG-SUSPEND
    {
        echo "*filter"
        echo ":WG-SUSPEND - [0:0]"
        while IFS= read -r c; do
            c="${c%%[[:space:]]*}"
            valid_cidr "$c" || continue
            echo "-A WG-SUSPEND -s ${c} -j DROP"
            echo "-A WG-SUSPEND -d ${c} -j DROP"
        done < <(blocked_cidrs | sort -u)
        echo "COMMIT"
    } | "${IPT}-restore" --noflush
}

# Usage: fill_chain <name> <rule args>... -> creates/flushes a chain and appends the given rules (one per argument)
fill_chain() {
    local name="$1" r; shift
    "$IPT" -nL "$name" >/dev/null 2>&1 || "$IPT" -N "$name"
    "$IPT" -F "$name"
    # shellcheck disable=SC2086
    for r in "$@"; do "$IPT" -A "$name" $r; done
}

# Usage: up -> builds the chains, then puts our block at the top of INPUT and FORWARD
up() {
    local guard=() n r i
    [ "$CLIENT_ISOLATION" = "1" ] && guard+=("-o ${WG_IF} -j DROP")
    if [ "$BLOCK_PRIVATE_NETS" = "1" ]; then
        for n in $PRIVATE_NETS; do guard+=("-d ${n} -j DROP"); done
    fi
    fill_chain WG-GUARD "${guard[@]}"
    fill_chain WG-NOINBOUND "-j DROP"
    fill_chain WG-IN "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" "-p icmp -j ACCEPT" \
        "-p udp --dport 53 -j ACCEPT" "-p tcp --dport 53 -j ACCEPT" "-j DROP"
    sync_suspend
    remove_rules
    # insert bottom-up at position 1 so the final order is exactly our_rules' order
    mapfile -t r < <(our_rules)
    for (( i = ${#r[@]} - 1; i >= 0; i-- )); do
        # shellcheck disable=SC2086
        "$IPT" -I "${r[$i]%% *}" 1 ${r[$i]#* }
    done
}

# Usage: down -> removes everything 'up' made
down() {
    local c
    remove_rules
    for c in WG-SUSPEND WG-GUARD WG-NOINBOUND WG-IN; do
        "$IPT" -F "$c" 2>/dev/null || true
        "$IPT" -X "$c" 2>/dev/null || true
    done
}

case "${1:-}" in
    up)           up ;;
    down)         down ;;
    sync-suspend) sync_suspend ;;
    status)       "$IPT" -S INPUT; "$IPT" -S FORWARD; for c in WG-SUSPEND WG-GUARD WG-NOINBOUND WG-IN; do "$IPT" -S "$c" 2>/dev/null || true; done ;;
    *)            echo "usage: wg-firewall.sh up|down|sync-suspend|status" >&2; exit 1 ;;
esac
WG_FIREWALL_EOF
    bash -n "${FW_SCRIPT}.new" || { rm -f "${FW_SCRIPT}.new"; die "wg-firewall.sh failed its syntax check."; }
    install -o root -g root -m 755 "${FW_SCRIPT}.new" "$FW_SCRIPT"
    rm -f "${FW_SCRIPT}.new"
    mkdir -p /etc/wireguard
    if [ ! -f "$FW_OPTS" ]; then
        ( umask 077; cat > "$FW_OPTS" <<END
# Options of ${FW_SCRIPT} (1 = on). Apply a change with: ${FW_SCRIPT} up
CLIENT_ISOLATION=${FW_ISOLATION}       # VPN clients cannot reach each other
BLOCK_PRIVATE_NETS=${FW_BLOCK_PRIVATE}     # nor private, link-local (cloud metadata) or CGNAT addresses
BLOCK_SERVER_ACCESS=1    # nor the server's own services (ping and DNS still work)
END
        )
    fi
    touch /etc/wireguard/suspended.list
    chmod 600 /etc/wireguard/suspended.list
    ok "${FW_SCRIPT} (options: ${FW_OPTS})"
}

# Usage: migrate_wg_hooks -> switches the PostUp/PostDown lines of an existing wg0.conf to wg-firewall.sh
#        (the old filter lines are dropped, the NAT lines and every peer are kept; validated before it is replaced)
migrate_wg_hooks() {
    [ -f "$WG_CONFIG" ] || die "$WG_CONFIG is missing."
    local tmpd tmp
    tmpd="$(mktemp -d)"; tmp="${tmpd}/${WG_INTERFACE}.conf"
    (
        # the API helper edits wg0.conf under this lock
        exec 9>/run/wg-api-helper.lock
        flock 9
        awk -v up="$FW_HOOK_UP" -v down="$FW_HOOK_DOWN" -v ifc="$WG_INTERFACE" '
            function hooks() { if (!done) { print up; print down; done = 1 } }
            /^\[Peer\]/ { hooks() }
            /^(PostUp|PostDown)[ \t]*=/ {
                if ($0 ~ /wg-firewall\.sh/) next
                if ($0 ~ ("FORWARD -[io] " ifc " -j ACCEPT")) next
                if ($0 ~ /INPUT (1 )?-p udp --dport [0-9]+ -j ACCEPT/) next
            }
            { print }
            END { hooks() }
        ' "$WG_CONFIG" > "$tmp"
        wg-quick strip "$tmp" >/dev/null 2>&1 || { rm -rf "$tmpd"; die "The rewritten ${WG_CONFIG} does not validate; nothing changed."; }
        if ! cmp -s "$tmp" "$WG_CONFIG"; then
            cp -a "$WG_CONFIG" "${WG_CONFIG}.bak-$(date +%Y%m%d-%H%M%S)"
            install -o root -g root -m 600 "$tmp" "${WG_CONFIG}.new"
            mv -f "${WG_CONFIG}.new" "$WG_CONFIG"
        fi
    )
    rm -rf "$tmpd"
}

# Usage: import_live_suspensions -> keeps suspensions that older versions only had in iptables (WG-SUSPEND rules)
import_live_suspensions() {
    local c
    iptables -nL WG-SUSPEND >/dev/null 2>&1 || return 0
    while IFS= read -r c; do
        grep -qxF "$c" /etc/wireguard/suspended.list 2>/dev/null || printf '%s\n' "$c" >> /etc/wireguard/suspended.list
    done < <(iptables -S WG-SUSPEND | sed -n 's/^-A WG-SUSPEND -s \([0-9./]*\) -j DROP$/\1/p')
}

# Usage: update_firewall -> installs wg-firewall.sh on an existing server and applies it live (no restart, peers kept)
update_firewall() {
    [ -f "$WG_CONFIG" ] || die "No ${WG_CONFIG}: run a normal install first."
    step_install_firewall
    import_live_suspensions
    migrate_wg_hooks
    "$FW_SCRIPT" up || die "wg-firewall.sh up failed: ${FW_SCRIPT} status"
    # the rules no longer depend on netfilter-persistent; save once so an old saved set cannot come back at boot
    have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
    ok "Firewall updated: clients isolated, private networks blocked, suspensions always evaluated first"
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
# NOTE on speed limiting: every peer's address must come from ONE flat pool
# (a /24 or the default 10.66.0.0/16). The tc classid is the hex value of
# (third octet * 256 + fourth octet), which is unique inside any pool up to a
# /16 (minor ids 1..fffe). 1:ffff is the unlimited default class. If you ever run
# peers across several pools on one server, this needs a real allocator.

set -euo pipefail

WG_IFACE="wg0"
IFB_IFACE="ifb0"
WG="$(command -v wg || echo /usr/bin/wg)"
IPT="$(command -v iptables || echo /usr/sbin/iptables)"
TC="$(command -v tc || echo /usr/sbin/tc)"
SUSPEND_CHAIN="WG-SUSPEND"
FW="/usr/local/bin/wg-firewall.sh"
SUSPEND_LIST="/etc/wireguard/suspended.list"

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
# Saves iptables state so suspensions survive a reboot. No-op if unavailable (only used without wg-firewall.sh).
persist_iptables() {
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
}

# Usage: suspend_list add|del <cidr>
# With wg-firewall.sh the suspension is kept in /etc/wireguard/suspended.list and WG-SUSPEND is rebuilt from it,
# so it survives wg0 restarts and reboots and always sits above the ACCEPT rules. Returns 1 without wg-firewall.sh.
suspend_list() {
    [ -x "$FW" ] || return 1
    local tmp
    touch "$SUSPEND_LIST"; chmod 600 "$SUSPEND_LIST"
    tmp="$(mktemp)"
    grep -vxF "$2" "$SUSPEND_LIST" > "$tmp" || true
    [ "$1" = "add" ] && printf '%s\n' "$2" >> "$tmp"
    install -o root -g root -m 600 "$tmp" "$SUSPEND_LIST"
    rm -f "$tmp"
    "$FW" sync-suspend
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
# Derives a stable tc classid (hex, as tc expects) from the third and fourth octet of the peer's IP.
class_id_for_ip() {
    local ip="${1%%/*}" a b c d
    IFS=. read -r a b c d <<<"$ip"
    [[ "$c" =~ ^[0-9]{1,3}$ && "$d" =~ ^[0-9]{1,3}$ ]] || return 1
    [ "$((10#$c))" -le 255 ] && [ "$((10#$d))" -le 255 ] || return 1
    printf '%x' $(( 10#$c * 256 + 10#$d ))
}

# Usage: ensure_shaping_setup
# One-time (idempotent) setup: ifb device, wg0->ifb0 ingress redirect,
# and a root htb qdisc on both devices with an unlimited default class
# (1:ffff) so peers with no cap are unaffected.
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
        "$TC" qdisc add dev "$WG_IFACE" root handle 1: htb default ffff
        "$TC" class add dev "$WG_IFACE" parent 1: classid 1:ffff htb rate 1000mbit
    }
    "$TC" qdisc show dev "$IFB_IFACE" | grep -q "htb 1:" || {
        "$TC" qdisc add dev "$IFB_IFACE" root handle 1: htb default ffff
        "$TC" class add dev "$IFB_IFACE" parent 1: classid 1:ffff htb rate 1000mbit
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
        if ! suspend_list add "$IP"; then
            ensure_suspend_chain
            "$IPT" -C "$SUSPEND_CHAIN" -s "$IP" -j DROP 2>/dev/null || "$IPT" -A "$SUSPEND_CHAIN" -s "$IP" -j DROP
            "$IPT" -C "$SUSPEND_CHAIN" -d "$IP" -j DROP 2>/dev/null || "$IPT" -A "$SUSPEND_CHAIN" -d "$IP" -j DROP
            persist_iptables
        fi
        echo "OK: iptables DROP in place for $IP"
        audit OK "action=suspend ip=${IP}"
        ;;

    peer-unsuspend)
        [[ "$NARGS" -eq 2 ]] || { echo "ERROR: usage: peer-unsuspend <cidr>" >&2; audit DENY "reason=argc"; exit 1; }
        IP="${ARGS[1]}"
        is_valid_cidr "$IP" || { echo "ERROR: invalid IP/CIDR" >&2; audit DENY "reason=bad_cidr"; exit 1; }
        if ! suspend_list del "$IP"; then
            ensure_suspend_chain
            "$IPT" -C "$SUSPEND_CHAIN" -s "$IP" -j DROP 2>/dev/null && "$IPT" -D "$SUSPEND_CHAIN" -s "$IP" -j DROP || true
            "$IPT" -C "$SUSPEND_CHAIN" -d "$IP" -j DROP 2>/dev/null && "$IPT" -D "$SUSPEND_CHAIN" -d "$IP" -j DROP || true
            persist_iptables
        fi
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
        say "wg-monitor SSH account not requested (optional; the HTTPS API already provides keys and usage)."
        return 0
    fi
    say "Setting up the ${MONITOR_USER} account..."
    check_sudoers_include
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
    # SELinux (EL): files made here must get the ssh_home_t label or sshd refuses the key
    if have restorecon; then restorecon -R "/home/${MONITOR_USER}/.ssh" >/dev/null 2>&1 || true; fi

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
#   wg-api-helper used-ips              every client address already in wg0.conf
#   wg-api-helper add-auto <pubkey> [<name>] [<ip>] [<limit bytes>] [<expiry>]
#                                       add the peer at <ip> (or the first free address), print the address
#                                       (the client's private key may be given on stdin; it is kept in
#                                        /etc/wg-api/clients.db, root only, so GET /keys can show the config again)
#   wg-api-helper keys [<ip>]           every peer: ip, pubkey, stored private key, created, rx, tx, handshake, name,
#                                       paused (0/1), traffic limit in bytes (0 = unlimited), over the limit (0/1)
#   wg-api-helper pause <ip>            block all traffic of a key (it stays configured; resume undoes it)
#   wg-api-helper resume <ip>           lift a pause
#   wg-api-helper expiry <ip> <spec>    time limit of a key: 0 (none), at:<epoch>, on:<YYYY-MM-DD HH:MM> (server's local
#                                       time), in:<n>h|d|w|m (from now) or
#                                       after:<n>h|d|w|m (from its first connection; m = calendar months). A key past its
#                                       end is blocked like a paused one until it gets a later end (or none).
#   wg-api-helper limit <ip> <bytes>    traffic limit of a key, upload + download since it was created; 0 = unlimited.
#                                       A key over its limit is blocked like a paused one (checked now and every
#                                       minute by traffic-save) and unblocked when the limit is raised or removed.
#   wg-api-helper rename <ip> <name>    give a key a display name (1-64 characters, no control characters)
#   wg-api-helper add <pubkey> <ip>     add a peer to wg0.conf AND the live interface
#   wg-api-helper remove <ip>           remove a peer from wg0.conf AND the live interface
#   wg-api-helper usage [<ip>]          traffic: one line per key 'ip<TAB>rx<TAB>tx<TAB>handshake'
#   wg-api-helper traffic-save          store the counters in /var/lib/wg-api/traffic.db (timer every minute and
#                                       just before wg0 stops), so usage survives wg0 restarts and reboots
# rx/tx everywhere are totals: what was saved before the counters last started from zero, plus the live counters.
set -euo pipefail

WG_IF="wg0"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
CLIENT_DB="/etc/wg-api/clients.db"   # ip<TAB>client pubkey<TAB>client private key or -<TAB>created epoch<TAB>name
TRAFFIC_DB="/var/lib/wg-api/traffic.db"   # pubkey<TAB>saved rx<TAB>saved tx<TAB>last live rx<TAB>last live tx<TAB>generation<TAB>last handshake
                                          # <TAB>first connection (every key; the row goes when the key is removed)
POLICY_DB="/etc/wg-api/policy.db"   # ip<TAB>pubkey<TAB>paused 0/1<TAB>limit bytes (0 = unlimited)<TAB>over the limit 0/1
                                    # <TAB>ends at (epoch, 0 = no end yet)<TAB>duration after first connection (e.g. 30d, 1m)
                                    # <TAB>first connection (epoch, 0 = not yet)<TAB>expired 0/1
FW="/usr/local/bin/wg-firewall.sh"

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
WORK="$TMPD/${WG_IF}.conf"   # wg-quick strip needs a <name>.conf file name

# Usage: fail "message"   -> logs a DENY line and exits 1
fail() { echo "ERROR: $*" >&2; logger -t wg-api-helper "result=DENY $*"; exit 1; }

# Usage: is_valid_pubkey <key>  -> base64, 44 chars ending in '='
is_valid_pubkey() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }

# Usage: ip2int a.b.c.d         -> sets REPLY to the address as an integer (no subshell, fast for big pools)
ip2int() { local IFS=.; local -a o; read -r -a o <<<"$1"; REPLY=$(( (o[0]<<24) + (o[1]<<16) + (o[2]<<8) + o[3] )); }

# Usage: int2ip <int>           -> prints a.b.c.d
int2ip() { echo "$(( ($1>>24)&255 )).$(( ($1>>16)&255 )).$(( ($1>>8)&255 )).$(( $1&255 ))"; }

# Usage: load_network           -> reads the server Address from wg0.conf (any prefix, e.g. /16 or /24) into
#                                  SRV_INT, NET_INT, BCAST_INT
load_network() {
    local addr p mask
    addr="$(sed -n 's/^Address[[:space:]]*=[[:space:]]*\([0-9.]*\/[0-9]*\).*/\1/p' "$WG_CONF" | head -n1)"
    [ -n "$addr" ] || fail "cannot read the Address line from $WG_CONF"
    p="${addr#*/}"
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 8 ] && [ "$p" -le 30 ] || fail "unsupported network prefix in $WG_CONF"
    ip2int "${addr%/*}"; SRV_INT="$REPLY"
    mask=$(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF ))
    NET_INT=$(( SRV_INT & mask ))
    BCAST_INT=$(( NET_INT | (~mask & 0xFFFFFFFF) ))
}

# Usage: is_valid_ip <ip>       -> 0 for a client address inside the server's network
#                                  (not the network address, broadcast or the server itself); no leading zeros
is_valid_ip() {
    [[ "$1" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]] || return 1
    local o
    for o in ${1//./ }; do [ "$o" -le 255 ] || return 1; done
    ip2int "$1"
    [ "$REPLY" -gt "$NET_INT" ] && [ "$REPLY" -lt "$BCAST_INT" ] && [ "$REPLY" -ne "$SRV_INT" ]
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

# Usage: cmd_used_ips           -> prints every client address (AllowedIPs x.x.x.x/32) in the config
cmd_used_ips() {
    grep -E '^AllowedIPs[[:space:]]*=[[:space:]]*[0-9.]+/32' "$WG_CONF" | grep -oE '[0-9.]+/32' | sed 's#/32$##' || true
}

# Usage: next_free_ip           -> prints the first free address of the pool, returns 1 when it is full
next_free_ip() {
    local -A used=()
    local ip i
    while read -r ip; do
        [ -n "$ip" ] || continue
        ip2int "$ip"; used[$REPLY]=1
    done < <(cmd_used_ips)
    for (( i = NET_INT + 1; i < BCAST_INT; i++ )); do
        [ "$i" -eq "$SRV_INT" ] && continue
        if [ -z "${used[$i]:-}" ]; then int2ip "$i"; return 0; fi
    done
    return 1
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
    traffic_drop "$pub"
    awk -v ip="$ip" '
        function flush() { if (buf != "" && !drop) printf "%s", buf; buf = ""; drop = 0 }
        /^\[/ { flush() }
        { buf = buf $0 "\n"
          if ($0 ~ /^AllowedIPs[ \t]*=/) { l = $0; gsub(/[ \t]/, "", l); if (l == "AllowedIPs=" ip "/32") drop = 1 } }
        END { flush() }
    ' "$WG_CONF" > "$WORK"
    install_conf "$WORK"
    db_drop "$ip"
    pol_drop "$ip"
    logger -t wg-api-helper "result=OK action=remove ip=${ip}"
    echo "OK: peer removed ($ip)"
}

# Usage: traffic_gen            -> prints "<boot id>-<wg0 ifindex>"; it changes whenever WireGuard's counters start
#                                  again from zero (reboot, wg-quick down/up), which is how a reset is recognised
traffic_gen() {
    local b i
    b="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo noboot)"
    i="$(cat "/sys/class/net/${WG_IF}/ifindex" 2>/dev/null || echo down)"
    printf '%s-%s' "$b" "$i"
}

# Usage: traffic_merge totals|save  -> reads $TMPD/dump (wg show dump), traffic.db and wg0.conf
#        totals: 'pubkey<TAB>total rx<TAB>total tx<TAB>last handshake<TAB>first connection' for every key in wg0.conf
#                that has traffic or has connected
#        save:   the new traffic.db rows (keys no longer in wg0.conf are dropped)
#        A key's saved part grows by its last live value when the counters were reset since the last save
#        (new generation, or a counter smaller than before).
traffic_merge() {
    if [ -f "$TRAFFIC_DB" ]; then cp "$TRAFFIC_DB" "$TMPD/traffic"; else : > "$TMPD/traffic"; fi
    awk -F'\t' -v mode="$1" -v gen="$(traffic_gen)" '
        FILENAME == ARGV[1] { if (NF >= 6) { brx[$1] = $2; btx[$1] = $3; lrx[$1] = $4; ltx[$1] = $5; g[$1] = $6
                                             shs[$1] = (NF >= 7 ? $7 : 0); sfirst[$1] = (NF >= 8 ? $8 : 0) }; next }
        FILENAME == ARGV[2] { if (FNR > 1) { live[$1] = 1; crx[$1] = $6; ctx[$1] = $7; chs[$1] = $5 }; next }
        /^PublicKey[ \t]*=/ { v = $0; sub(/^PublicKey[ \t]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); conf[v] = 1; next }
        END {
            for (p in conf) {
                # the last handshake is kept too, so "last seen" survives a restart (live value when there is one)
                h = (p in chs && chs[p] + 0 > 0) ? chs[p] : ((p in shs) ? shs[p] + 0 : 0)
                # first connection: kept once seen; otherwise the first handshake noticed (checked every minute)
                f = (p in sfirst && sfirst[p] + 0 > 0) ? sfirst[p] + 0 : h + 0
                if (p in live) {
                    b_rx = (p in brx) ? brx[p] + 0 : 0; b_tx = (p in btx) ? btx[p] + 0 : 0
                    if ((p in g) && (g[p] != gen || crx[p] + 0 < lrx[p] + 0 || ctx[p] + 0 < ltx[p] + 0)) {
                        b_rx += lrx[p]; b_tx += ltx[p]
                    }
                    if (mode == "save") printf "%s\t%.0f\t%.0f\t%.0f\t%.0f\t%s\t%.0f\t%.0f\n", p, b_rx, b_tx, crx[p], ctx[p], gen, h, f
                    else printf "%s\t%.0f\t%.0f\t%.0f\t%.0f\n", p, b_rx + crx[p], b_tx + ctx[p], h, f
                } else if (p in brx) {
                    # wg0 is down (or the peer is not loaded): keep what was saved
                    if (mode == "save") printf "%s\t%s\t%s\t%s\t%s\t%s\t%.0f\t%.0f\n", p, brx[p], btx[p], lrx[p], ltx[p], g[p], h, f
                    else printf "%s\t%.0f\t%.0f\t%.0f\t%.0f\n", p, brx[p] + lrx[p], btx[p] + ltx[p], h, f
                }
            }
        }' "$TMPD/traffic" "$TMPD/dump" "$WG_CONF"
}

# Usage: cmd_traffic_save       -> writes traffic.db atomically (run by wg-traffic.timer and wg-traffic-save.service)
cmd_traffic_save() {
    { wg show "$WG_IF" dump 2>/dev/null || true; } > "$TMPD/dump"
    install -d -o root -g root -m 700 "$(dirname "$TRAFFIC_DB")"
    traffic_merge save > "$TMPD/traffic.new"
    install -o root -g root -m 600 "$TMPD/traffic.new" "${TRAFFIC_DB}.new"
    mv -f "${TRAFFIC_DB}.new" "$TRAFFIC_DB"
    db_prune
    enforce_limits
}

# Usage: db_prune               -> drops clients.db rows (stored private key, name, created) of keys that are no longer in
#                                  wg0.conf, e.g. removed by hand; traffic.db and policy.db prune themselves the same way
db_prune() {
    [ -s "$CLIENT_DB" ] || return 0
    awk -F'\t' '
        FILENAME == ARGV[1] {
            if ($0 ~ /^\[/) pub = ""
            if ($0 ~ /^PublicKey[ \t]*=/) { pub = $0; sub(/^PublicKey[ \t]*=[ \t]*/, "", pub); sub(/[ \t]+$/, "", pub) }
            if ($0 ~ /^AllowedIPs[ \t]*=/ && pub != "") { v = $0; sub(/^AllowedIPs[ \t]*=[ \t]*/, "", v)
                n = split(v, a, /[ \t]*,[ \t]*/); for (i = 1; i <= n; i++) if (a[i] ~ /\/32$/) { sub(/\/32$/, "", a[i]); owner[a[i]] = pub } }
            next
        }
        ($1 in owner) && owner[$1] == $2
        END { for (k in owner) n++; if (!n) exit 3 }
    ' "$WG_CONF" "$CLIENT_DB" > "$TMPD/db.pruned" || return 0      # no peers parsed: never wipe on a bad read
    if ! cmp -s "$TMPD/db.pruned" "$CLIENT_DB"; then
        install -o root -g root -m 600 "$TMPD/db.pruned" "$CLIENT_DB"
        logger -t wg-api-helper "result=OK action=prune-clients-db"
    fi
}

# Usage: load_dump              -> writes the live 'wg show dump' to $TMPD/dump (empty when wg0 is down)
load_dump() { { wg show "$WG_IF" dump 2>/dev/null || true; } > "$TMPD/dump"; }

# Usage: pol_write <file>       -> atomically replaces policy.db with <file> (rows of keys no longer in wg0.conf dropped,
#                                  and rows with nothing set)
pol_write() {
    install -d -o root -g root -m 700 "$(dirname "$POLICY_DB")"
    pol_clean "$1" "$TMPD/policy.clean"
    install -o root -g root -m 600 "$TMPD/policy.clean" "${POLICY_DB}.new"
    mv -f "${POLICY_DB}.new" "$POLICY_DB"
}

# Usage: pol_clean <in> <out>   -> copies the rows of keys still in wg0.conf that have something set
pol_clean() {
    awk -F'\t' '
        FILENAME == ARGV[1] { if ($0 ~ /^PublicKey[ \t]*=/) { v = $0; sub(/^PublicKey[ \t]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); conf[v] = 1 }; next }
        ($2 in conf) && ($3 == "1" || $4 + 0 > 0 || $6 + 0 > 0 || $7 != "")
    ' "$WG_CONF" "$1" > "$2"
}

# Usage: fw_sync                -> applies policy.db to the firewall (WG-SUSPEND), if wg-firewall.sh is installed
fw_sync() {
    if [ -x "$FW" ]; then "$FW" sync-suspend || fail "could not update the firewall (wg-firewall.sh sync-suspend)"; fi
}

# Usage: valid_duration <spec>  -> 0 for <n>h, <n>d, <n>w or <n>m (hours, days, weeks, calendar months), n = 1..9999
valid_duration() { [[ "$1" =~ ^[1-9][0-9]{0,3}[hdwm]$ ]]; }

# Usage: add_duration <epoch> <spec> -> prints <epoch> + <spec>. Months are calendar months in UTC, kept inside the
#        target month: Jan 15 + 1m = Feb 15, Jan 31 + 1m = Feb 28 (or 29).
add_duration() {
    local n="${2%?}" u="${2: -1}" y mo d hms t last
    case "$u" in
        h) echo $(( $1 + n * 3600 )) ;;
        d) echo $(( $1 + n * 86400 )) ;;
        w) echo $(( $1 + n * 604800 )) ;;
        m)
            read -r y mo d hms <<<"$(date -u -d "@$1" '+%Y %m %d %H:%M:%S')"
            t=$(( 10#$mo - 1 + n )); y=$(( 10#$y + t / 12 )); mo=$(( t % 12 + 1 ))
            # last day of the target month: day 1 of the next month minus one day ("UTC" before any '+': GNU date
            # would otherwise read "+ 1" as a time zone)
            last="$(date -u -d "$(printf '%04d-%02d-01' "$y" "$mo") 12:00:00 UTC + 1 month - 1 day" +%d)"
            [ "$(( 10#$d ))" -gt "$(( 10#$last ))" ] && d="$last"
            date -u -d "$(printf '%04d-%02d-%02d' "$y" "$mo" "$(( 10#$d ))") ${hms} UTC" +%s ;;
    esac
}

# Usage: valid_expiry <spec>    -> 0 for: 0 (no time limit) | at:<epoch> | on:<YYYY-MM-DD HH:MM[:SS]> (the SERVER's local
#        time) | in:<duration> | after:<duration>
valid_expiry() {
    case "$1" in
        0) return 0 ;;
        at:*) [[ "${1#at:}" =~ ^[1-9][0-9]{8,10}$ ]] ;;
        on:*) [[ "${1#on:}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[\ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?$ ]] ;;
        in:*) valid_duration "${1#in:}" ;;
        after:*) valid_duration "${1#after:}" ;;
        *) return 1 ;;
    esac
}

# Usage: on_epoch <YYYY-MM-DD HH:MM[:SS]> -> prints the epoch of that wall-clock time in the server's time zone (/etc/localtime);
#        fails for a date that does not exist (2026-02-30, 25:00)
on_epoch() {
    local t="${1/T/ }" e back
    e="$(date -d "$t" +%s 2>/dev/null)" || return 1
    back="$(date -d "@$e" '+%Y-%m-%d %H:%M' 2>/dev/null)" || return 1
    [ "$back" = "${t:0:16}" ] || return 1          # date(1) rolled an impossible time over (e.g. DST gap): refuse it
    printf '%s' "$e"
}

# Usage: check_expiry <spec>    -> fails (exit with a message) unless the spec is valid; an "on:" time must be in the future
check_expiry() {
    local e
    valid_expiry "$1" || fail "invalid expiry"
    case "$1" in
        on:*)
            e="$(on_epoch "${1#on:}")" || fail "invalid expiry"
            [ "$e" -gt "$(date +%s)" ] || fail "end time is in the past" ;;
    esac
}

# Usage: pol_calc <in> <out>    -> recomputes every row of a policy file from the traffic totals ($TMPD/totals) and the clock:
#        over the traffic limit; for "after first connection" keys that connected since the last check, the start (their
#        handshake) and the end; expired. Row: ip pub paused limit over expires duration first_connected expired
pol_calc() {
    local now line ip pub pa li ov ex du first ed
    now="$(date +%s)"
    awk -F'\t' -v OFS='\t' -v now="$now" '
        FILENAME == ARGV[1] { tot[$1] = $2 + $3; first[$1] = $5 + 0; next }
        {
            ex = $6 + 0; du = $7; fi = $8 + 0
            over = ($4 + 0 > 0 && (tot[$2] + 0) >= $4 + 0) ? 1 : 0
            if (du != "" && fi == 0 && first[$2] > 0) { fi = first[$2]; ex = "ADD" }
            expd = (ex != "ADD" && ex > 0 && now + 0 >= ex) ? 1 : 0
            print $1, $2, $3 + 0, $4 + 0, over, ex, du, fi, expd
        }' "$TMPD/totals" "$1" > "$2.tmp"
    if grep -q $'\tADD\t' "$2.tmp"; then
        # a key with a recorded first connection: its end is first connection + duration (months need date(1))
        : > "$2"
        while IFS= read -r line; do
            IFS=$'\t' read -r ip pub pa li ov ex du first ed <<<"$line"
            if [ "$ex" = "ADD" ]; then
                ex="$(add_duration "$first" "$du")"
                ed=0; [ "$now" -ge "$ex" ] && ed=1
                logger -t wg-api-helper "result=OK action=first-connection ip=${ip} ends=${ex}"
                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$ip" "$pub" "$pa" "$li" "$ov" "$ex" "$du" "$first" "$ed" >> "$2"
            else
                printf '%s\n' "$line" >> "$2"
            fi
        done < "$2.tmp"
        rm -f "$2.tmp"
    else
        mv -f "$2.tmp" "$2"
    fi
}

# Usage: pol_set <ip> <pubkey> <paused|-> <limit|-> [<expiry|->]  -> changes one key's policy ('-' keeps the current
#        value), recomputes it (pol_calc) and applies the firewall. <expiry>: see valid_expiry; "in:<d>" is turned into
#        "at:<now + d>", "after:<d>" counts from the key's first connection (waits for it when there is none yet)
pol_set() {
    local ip="$1" pub="$2" paused="$3" limit="$4" exp="${5:--}" ex="-" du="-" first=0 now
    now="$(date +%s)"
    [ -f "$POLICY_DB" ] && cp "$POLICY_DB" "$TMPD/policy" || : > "$TMPD/policy"
    load_dump
    traffic_merge totals > "$TMPD/totals"
    case "$exp" in
        -) ;;
        0) ex=0; du="" ;;
        at:*) ex="${exp#at:}"; du="" ;;
        on:*) ex="$(on_epoch "${exp#on:}")" || fail "invalid expiry"; du="" ;;
        in:*) ex="$(add_duration "$now" "${exp#in:}")"; du="" ;;
        after:*) du="${exp#after:}"; ex=0 ;;      # pol_calc counts from the key's recorded first connection
    esac
    awk -F'\t' -v OFS='\t' -v ip="$ip" -v pub="$pub" -v paused="$paused" -v limit="$limit" -v ex="$ex" -v du="$du" \
        -v first="$first" '
        $1 == ip { op = $3; ol = $4; oe = $6; od = $7; of = $8; next }
        { print }
        END {
            p = (paused == "-") ? op + 0 : paused
            l = (limit == "-") ? ol + 0 : limit
            if (ex == "-") { e = oe + 0; d = od; f = of + 0 } else { e = ex; d = du; f = first + 0 }
            print ip, pub, p, l, 0, e, d, f, 0
        }' "$TMPD/policy" > "$TMPD/policy.set"
    pol_calc "$TMPD/policy.set" "$TMPD/policy.new"
    pol_write "$TMPD/policy.new"
    fw_sync
}

# Usage: enforce_limits         -> every minute (traffic-save): blocks keys that reached their traffic limit or their end,
#                                  starts the clock of "after first connection" keys, unblocks keys whose limit was raised
enforce_limits() {
    [ -s "$POLICY_DB" ] || return 0
    traffic_merge totals > "$TMPD/totals"
    pol_calc "$POLICY_DB" "$TMPD/policy.calc"
    pol_clean "$TMPD/policy.calc" "$TMPD/policy.new"     # also drops keys removed from wg0.conf by hand
    if ! cmp -s "$TMPD/policy.new" "$POLICY_DB"; then
        pol_write "$TMPD/policy.new"
        fw_sync
        logger -t wg-api-helper "result=OK action=enforce-limits"
    fi
}

# Usage: pol_drop <ip>          -> forgets the policy of a removed key
pol_drop() {
    [ -f "$POLICY_DB" ] || return 0
    awk -F'\t' -v ip="$1" '$1 != ip' "$POLICY_DB" > "$TMPD/policy.drop"
    pol_write "$TMPD/policy.drop"
    fw_sync
}

# Usage: valid_bytes <n>        -> 0 for a whole number of bytes, 0 to 10^18
valid_bytes() { [[ "$1" =~ ^(0|[1-9][0-9]{0,17})$ ]]; }

# Usage: key_of <ip>            -> prints the public key of an existing peer, fails when there is none
key_of() {
    local pub
    is_valid_ip "$1" || fail "invalid ip"
    pub="$(peer_key_for_ip "$1")"
    [ -n "$pub" ] || fail "no peer found with AllowedIPs ${1}/32"
    printf '%s' "$pub"
}

# Usage: cmd_pause <ip> / cmd_resume <ip>
cmd_pause()  { local pub; pub="$(key_of "$1")"; pol_set "$1" "$pub" 1 -; logger -t wg-api-helper "result=OK action=pause ip=$1"; echo "OK: paused ($1)"; }
cmd_resume() { local pub; pub="$(key_of "$1")"; pol_set "$1" "$pub" 0 -; logger -t wg-api-helper "result=OK action=resume ip=$1"; echo "OK: resumed ($1)"; }

# Usage: cmd_limit <ip> <bytes> -> 0 removes the limit
cmd_limit() {
    local pub
    valid_bytes "$2" || fail "invalid limit"
    pub="$(key_of "$1")"
    pol_set "$1" "$pub" - "$2"
    logger -t wg-api-helper "result=OK action=limit ip=$1 bytes=$2"
    echo "OK: limit $2 ($1)"
}

# Usage: cmd_expiry <ip> <spec> -> time limit: 0 (none) | at:<epoch> | in:<n>h|d|w|m (from now) | after:<n>h|d|w|m
#                                  (from the key's first connection). A key past its end is blocked until it gets a new one.
cmd_expiry() {
    local pub
    check_expiry "$2"
    pub="$(key_of "$1")"
    pol_set "$1" "$pub" - - "$2"
    logger -t wg-api-helper "result=OK action=expiry ip=$1 spec=$2"
    echo "OK: expiry $2 ($1)"
}

# Usage: traffic_drop <pubkey>  -> forgets the saved traffic of a removed key
traffic_drop() {
    [ -f "$TRAFFIC_DB" ] || return 0
    awk -F'\t' -v p="$1" '$1 != p' "$TRAFFIC_DB" > "$TMPD/traffic.drop"
    install -o root -g root -m 600 "$TMPD/traffic.drop" "${TRAFFIC_DB}.new"
    mv -f "${TRAFFIC_DB}.new" "$TRAFFIC_DB"
}

# Usage: cmd_usage [<ip>]       -> 'ip<TAB>bytes_from_client<TAB>bytes_to_client<TAB>last_handshake_epoch' per peer (read-only)
cmd_usage() {
    cmd_keys "${1:-}" | awk -F'\t' '{ printf "%s\t%s\t%s\t%s\n", $1, $5, $6, $7 }'
}

# Usage: db_drop <ip>           -> removes the stored client record of <ip> (if any)
db_drop() {
    [ -f "$CLIENT_DB" ] || return 0
    awk -F'\t' -v ip="$1" '$1 != ip' "$CLIENT_DB" > "$TMPD/db.new"
    install -o root -g root -m 600 "$TMPD/db.new" "$CLIENT_DB"
}

# Usage: db_put <ip> <pubkey> <privkey|-> [<created epoch>] [<name>]  -> stores the client record of <ip>
#        (created defaults to now)
db_put() {
    db_drop "$1"
    mkdir -p "$(dirname "$CLIENT_DB")"
    ( umask 077; printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-$(date +%s)}" "${5:-}" >> "$CLIENT_DB" )
    chmod 600 "$CLIENT_DB"
}

# Usage: valid_name <name>      -> 0 for 1-64 characters without tabs, newlines or other control characters
valid_name() {
    local n="$1"
    [ -n "$n" ] && [ "${#n}" -le 64 ] && ! [[ "$n" =~ [[:cntrl:]] ]]
}

# Usage: cmd_rename <ip> <name> -> sets the display name of an existing key (keeps its stored private key)
cmd_rename() {
    local ip="$1" name="$2" pub rec
    is_valid_ip "$ip" || fail "invalid ip"
    valid_name "$name" || fail "invalid name"
    pub="$(peer_key_for_ip "$ip")"
    [ -n "$pub" ] || fail "no peer found with AllowedIPs ${ip}/32"
    rec="$(awk -F'\t' -v ip="$ip" -v pub="$pub" '$1 == ip && $2 == pub { print $3 "\t" $4; exit }' "$CLIENT_DB" 2>/dev/null || true)"
    if [ -n "$rec" ]; then
        db_put "$ip" "$pub" "${rec%%$'\t'*}" "${rec#*$'\t'}" "$name"
    else
        db_put "$ip" "$pub" "-" "0" "$name"     # a key made by hand: no private key, creation time unknown
    fi
    logger -t wg-api-helper "result=OK action=rename ip=${ip}"
    echo "OK: renamed ($ip)"
}

# Usage: echo "<privkey>" | cmd_add_auto <pubkey> [<name>] [<ip>] [<limit bytes>]
#                               -> adds the peer at <ip>, or at the first free address, under the same lock; prints the
#                                  address. The optional private key on stdin must belong to <pubkey>; it is stored for
#                                  GET /keys. Empty <name>/<ip>/<limit> mean: none / pick one / unlimited.
cmd_add_auto() {
    local pub="$1" name="${2:-}" want="${3:-}" limit="${4:-}" exp="${5:-}" ip priv=""
    is_valid_pubkey "$pub" || fail "invalid public key"
    if [ -n "$name" ]; then valid_name "$name" || fail "invalid name"; fi
    if [ -n "$want" ]; then
        is_valid_ip "$want" || fail "invalid ip"
        if grep -Eq "^AllowedIPs[[:space:]]*=[[:space:]]*${want//./\\.}/32[[:space:]]*\$" "$WG_CONF"; then fail "ip already allocated: $want"; fi
    fi
    if [ -n "$limit" ]; then valid_bytes "$limit" || fail "invalid limit"; fi
    if [ -n "$exp" ]; then check_expiry "$exp"; fi
    if [ ! -t 0 ]; then IFS= read -r priv || true; fi
    if [ -n "$priv" ]; then
        is_valid_pubkey "$priv" || fail "invalid private key"
        [ "$(printf '%s' "$priv" | wg pubkey 2>/dev/null)" = "$pub" ] || fail "private key does not match the public key"
    fi
    if [ -n "$want" ]; then ip="$want"; else ip="$(next_free_ip)" || fail "IP pool exhausted"; fi
    cmd_add "$pub" "$ip" >/dev/null
    db_put "$ip" "$pub" "${priv:--}" "" "$name"
    if { [ -n "$limit" ] && [ "$limit" != "0" ]; } || { [ -n "$exp" ] && [ "$exp" != "0" ]; }; then
        pol_set "$ip" "$pub" 0 "${limit:-0}" "${exp:-0}"
    fi
    echo "$ip"
}

# Usage: cmd_keys [<ip>]        -> one line per peer in wg0.conf:
#        ip<TAB>client pubkey<TAB>private key or -<TAB>created epoch or 0<TAB>rx<TAB>tx<TAB>last handshake epoch<TAB>name
#        <TAB>paused 0/1<TAB>limit bytes (0 = unlimited)<TAB>over the limit 0/1
#        <TAB>ends at epoch (0 = none yet)<TAB>duration after first connection or -<TAB>first connection epoch (every
#        key; 0 = never connected)<TAB>expired 0/1
#        (keys added by hand or before clients.db existed have no private key: '-')
cmd_keys() {
    local want="${1:-}"
    if [ -n "$want" ]; then is_valid_ip "$want" || fail "invalid ip"; fi
    load_dump
    traffic_merge totals > "$TMPD/totals"
    if [ -f "$CLIENT_DB" ]; then cp "$CLIENT_DB" "$TMPD/db"; else : > "$TMPD/db"; fi
    if [ -f "$POLICY_DB" ]; then cp "$POLICY_DB" "$TMPD/pol"; else : > "$TMPD/pol"; fi
    awk -v want="$want" '
        function flush() {
            if (pub != "" && ip != "" && (want == "" || ip == want)) {
                mine = (ip in dbpriv && dbpub[ip] == pub)
                p = mine ? dbpriv[ip] : "-"
                c = mine ? dbtime[ip] : 0
                nm = mine ? dbname[ip] : ""
                h = (pub in hs && hs[pub] + 0 > 0) ? hs[pub] : (pub in ths ? ths[pub] : 0)
                pol = (ip in ppub && ppub[ip] == pub)
                printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ip, pub, p, c, (pub in trx ? trx[pub] : 0), (pub in ttx ? ttx[pub] : 0), h, nm, (pol ? ppa[ip] + 0 : 0), (pol ? plim[ip] + 0 : 0), (pol ? pov[ip] + 0 : 0), (pol ? pex[ip] + 0 : 0), (pol && pdu[ip] != "" ? pdu[ip] : "-"), (pub in tfi && tfi[pub] + 0 > 0 ? tfi[pub] : (pol ? pfi[ip] + 0 : 0)), (pol ? ped[ip] + 0 : 0)
            }
            pub = ""; ip = ""
        }
        FILENAME == ARGV[1] { split($0, f, "\t"); dbpub[f[1]] = f[2]; dbpriv[f[1]] = f[3]; dbtime[f[1]] = f[4]; dbname[f[1]] = f[5]; next }
        FILENAME == ARGV[2] { split($0, f, "\t"); if (FNR > 1) { hs[f[1]] = f[5] }; next }
        FILENAME == ARGV[3] { split($0, f, "\t"); trx[f[1]] = f[2]; ttx[f[1]] = f[3]; ths[f[1]] = f[4]; tfi[f[1]] = f[5]; next }
        FILENAME == ARGV[4] { split($0, f, "\t"); ppub[f[1]] = f[2]; ppa[f[1]] = f[3]; plim[f[1]] = f[4]; pov[f[1]] = f[5]
                              pex[f[1]] = f[6]; pdu[f[1]] = f[7]; pfi[f[1]] = f[8]; ped[f[1]] = f[9]; next }
        /^\[/ { flush(); next }
        /^PublicKey[ \t]*=/  { v = $0; sub(/^PublicKey[ \t]*=[ \t]*/, "", v); sub(/[ \t]+$/, "", v); pub = v; next }
        /^AllowedIPs[ \t]*=/ { v = $0; sub(/^AllowedIPs[ \t]*=[ \t]*/, "", v); n = split(v, a, /[ \t]*,[ \t]*/)
                               for (i = 1; i <= n; i++) if (a[i] ~ /\/32$/) { sub(/\/32$/, "", a[i]); ip = a[i]; break }
                               next }
        END { flush() }
    ' "$TMPD/db" "$TMPD/dump" "$TMPD/totals" "$TMPD/pol" "$WG_CONF"
}

exec 9>/run/wg-api-helper.lock
flock 9
load_network

case "${1:-}" in
    used-ips) [ "$#" -eq 1 ] || fail "usage: used-ips";           cmd_used_ips ;;
    add)      [ "$#" -eq 3 ] || fail "usage: add <pubkey> <ip>";  cmd_add "$2" "$3" ;;
    add-auto) [ "$#" -ge 2 ] && [ "$#" -le 6 ] || fail "usage: add-auto <pubkey> [<name>] [<ip>] [<limit bytes>] [<expiry>]"; cmd_add_auto "$2" "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
    pause)    [ "$#" -eq 2 ] || fail "usage: pause <ip>";         cmd_pause "$2" ;;
    resume)   [ "$#" -eq 2 ] || fail "usage: resume <ip>";        cmd_resume "$2" ;;
    limit)    [ "$#" -eq 3 ] || fail "usage: limit <ip> <bytes>"; cmd_limit "$2" "$3" ;;
    expiry)   [ "$#" -eq 3 ] || fail "usage: expiry <ip> 0|at:<epoch>|on:<YYYY-MM-DD HH:MM>|in:<n>h|d|w|m|after:<n>h|d|w|m"; cmd_expiry "$2" "$3" ;;
    rename)   [ "$#" -eq 3 ] || fail "usage: rename <ip> <name>"; cmd_rename "$2" "$3" ;;
    keys)     [ "$#" -le 2 ] || fail "usage: keys [<ip>]";        cmd_keys "${2:-}" ;;
    remove)   [ "$#" -eq 2 ] || fail "usage: remove <ip>";        cmd_remove "$2" ;;
    usage)    [ "$#" -le 2 ] || fail "usage: usage [<ip>]";       cmd_usage "${2:-}" ;;
    traffic-save) [ "$#" -eq 1 ] || fail "usage: traffic-save";   cmd_traffic_save ;;
    *)        fail "command not permitted: ${1:-<empty>}" ;;
esac
WG_API_HELPER_EOF
    chown root:root "${BIN_DIR}/wg-api-helper"
    chmod 755 "${BIN_DIR}/wg-api-helper"
    bash -n "${BIN_DIR}/wg-api-helper" || die "wg-api-helper failed its syntax check."
    ok "${BIN_DIR}/wg-api-helper"
}

# Usage: step_install_traffic_saver -> timer that saves the traffic counters every minute, plus a unit that saves them
#        once more right before wg0 stops (shutdown, reboot, systemctl restart wg-quick@wg0), so usage survives restarts
step_install_traffic_saver() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    [ -x "${BIN_DIR}/wg-api-helper" ] || return 0
    say "Installing the traffic saver (usage survives restarts)..."
    cat > /etc/systemd/system/wg-traffic.service <<END
[Unit]
Description=Save WireGuard traffic counters (persistent usage)
After=wg-quick@${WG_INTERFACE}.service

[Service]
Type=oneshot
ExecStart=${BIN_DIR}/wg-api-helper traffic-save
END
    cat > /etc/systemd/system/wg-traffic.timer <<END
[Unit]
Description=Save WireGuard traffic counters every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
END
    # After= makes this unit stop BEFORE wg-quick stops (stop order is the reverse of start order), and PartOf= makes a
    # restart of wg-quick@wg0 restart this unit too: ExecStop saves the counters while wg0 still has them
    cat > /etc/systemd/system/wg-traffic-save.service <<END
[Unit]
Description=Save WireGuard traffic counters before ${WG_INTERFACE} goes down
After=wg-quick@${WG_INTERFACE}.service
PartOf=wg-quick@${WG_INTERFACE}.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${BIN_DIR}/wg-api-helper traffic-save
ExecStop=${BIN_DIR}/wg-api-helper traffic-save

[Install]
WantedBy=multi-user.target wg-quick@${WG_INTERFACE}.service
END
    systemctl daemon-reload
    systemctl enable --now wg-traffic.timer >/dev/null 2>&1 || warn "Could not enable wg-traffic.timer"
    systemctl enable --now wg-traffic-save.service >/dev/null 2>&1 || warn "Could not enable wg-traffic-save.service"
    ok "Usage is saved every minute and before ${WG_INTERFACE} stops (/var/lib/wg-api/traffic.db)"
}

# Usage: step_create_api_user -> non-root API user plus its sudoers entry (only wg-api-helper)
step_create_api_user() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    say "Creating the ${API_USER} user..."
    check_sudoers_include
    id "$API_USER" >/dev/null 2>&1 || useradd -r -s "$NOLOGIN" "$API_USER"
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
    # exact versions, and no install scripts run as root
    npm install --omit=dev --no-audit --no-fund --ignore-scripts --save-exact "${NPM_PACKAGES[@]}" >/dev/null 2>&1 \
        || die "npm install failed in $API_DIR"
    api_dir_perms
    ok "${NPM_PACKAGES[*]} installed"
}

# Usage: api_dir_perms -> the API's code belongs to root and is read-only for the service user, so a compromised
#        wg-api process cannot rewrite its own code
api_dir_perms() {
    chown -R root:root "$API_DIR"
    chmod -R u=rwX,go=rX "$API_DIR"
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
    # the Outline-style secret path (https://host:port/<API_PATH>); added to older installs as well
    API_PATH="$(sed -n 's/^API_PATH=//p' "${API_ENV_DIR}/env" | head -n1)"
    if ! [[ "$API_PATH" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
        API_PATH="$(openssl rand -base64 18 | tr '+/' '-_' | tr -d '=\n')"
        sed -i '/^API_PATH=/d' "${API_ENV_DIR}/env"
        printf 'API_PATH=%s\n' "$API_PATH" >> "${API_ENV_DIR}/env"
        ok "Generated the secret API path"
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
    limit: 600,   // 40/min: room for a manager polling /usage every minute (the token is 256-bit, brute force is not a concern)
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
}));

const API_TOKEN = process.env.API_TOKEN || '';
if (API_TOKEN.length < 32) {
    console.error('API_TOKEN is missing or too short (see /etc/wg-api/env)');
    process.exit(1);
}
// Outline-style secret path: https://host:port/<API_PATH>/... needs no Authorization header (like Outline's apiUrl).
// Empty = only the Bearer token is accepted.
const API_PATH = /^[A-Za-z0-9_-]{16,128}$/.test(process.env.API_PATH || '') ? process.env.API_PATH : '';
if (process.env.API_PATH && !API_PATH) console.error('API_PATH ignored: use 16-128 characters A-Z a-z 0-9 _ -');

// NOTE: wg-healthcheck.sh and vpn-doctor.sh read the next line, keep its format
const SERVER_PUB = '__SERVER_PUB__';
const ENDPOINT = '__ENDPOINT__';
const WG_PORT = __WG_PORT__;
const CLIENT_DNS = '__DNS__';
// WG_API_HELPER: test override only; in production sudoers allows nothing but the real path
const HELPER = process.env.WG_API_HELPER || '/usr/local/bin/wg-api-helper';
// reported by GET /server; Mithra WireGuard Manager uses it to know which routes exist
const API_VERSION = '2.3';
// what this server can do beyond listing/creating/removing keys (the app shows the matching buttons)
const FEATURES = ['names', 'pause', 'limit', 'createAt', 'expiry', 'expiryOn'];
const STARTED_MS = Date.now();

// Usage: sameSecret(a, b) -> true if two strings are equal (constant time)
function sameSecret(a, b) {
    const x = Buffer.from(String(a)), y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Usage: tokenOk(headerValue) -> true if the Authorization header equals "Bearer <token>" (constant time)
function tokenOk(header) {
    const expected = Buffer.from('Bearer ' + API_TOKEN);
    const given = Buffer.from(header || '');
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

// ::/0 as well: IPv6 is sent into the tunnel (and dropped there) instead of leaking around it
const CLIENT_ALLOWED_IPS = '0.0.0.0/0, ::/0';
const CLIENT_KEEPALIVE = 25;

// Usage: helper(['add', pubkey, ip], stdinText?) -> runs wg-api-helper as root through sudo, no shell involved
//        (secrets such as a private key go through stdin, never on the command line)
function helper(args, input) {
    return execFileSync('sudo', ['-n', HELPER, ...args], { encoding: 'utf8', input: input || '' });
}

// Usage: buildConfig(privateKey, ip) -> the client's wg-quick config text
function buildConfig(privateKey, ip) {
    return '[Interface]\n' +
        'PrivateKey = ' + privateKey + '\n' +
        'Address = ' + ip + '/32\n' +
        'DNS = ' + CLIENT_DNS + '\n' +
        '\n' +
        '[Peer]\n' +
        'PublicKey = ' + SERVER_PUB + '\n' +
        'Endpoint = ' + ENDPOINT + ':' + WG_PORT + '\n' +
        'AllowedIPs = ' + CLIENT_ALLOWED_IPS + '\n' +
        'PersistentKeepalive = ' + CLIENT_KEEPALIVE + '\n';
}

// Usage: parseTraffic("20G") -> 20000000000; "unlimited" / "0" / 0 / null -> 0; undefined for anything invalid
//        Units are decimal like the app shows them (K M G T = 10^3 ... 10^12; KiB MiB GiB TiB = 1024^n),
//        a plain number is bytes. Also accepts Outline's {"bytes": N}.
function parseTraffic(v) {
    if (v === null || v === 0 || v === false) return 0;
    if (typeof v === 'object' && v !== null && 'bytes' in v) v = v.bytes;
    if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 && v <= 1e18 ? v : undefined;
    if (typeof v !== 'string') return undefined;
    const t = v.trim();
    if (/^(|0|unlimited|none|off|no)$/i.test(t)) return 0;
    const m = /^(\d+(?:\.\d+)?)\s*([kmgt]?)(i?)b?$/i.exec(t);
    if (!m) return undefined;
    const pow = { '': 0, k: 1, m: 2, g: 3, t: 4 }[m[2].toLowerCase()];
    const bytes = Math.round(parseFloat(m[1]) * Math.pow(m[3] ? 1024 : 1000, pow));
    return Number.isSafeInteger(bytes) && bytes <= 1e18 ? bytes : undefined;
}

// Usage: trafficFrom(req) -> the requested limit in bytes (0 = unlimited), undefined when none was given,
//        or NaN when it was given but is not valid. Body {"traffic":"20G"}, {"limit":{"bytes":N}} (Outline),
//        {"dataLimit":N}, or ?traffic=20G.
function trafficFrom(req) {
    const b = (req.body && typeof req.body === 'object') ? req.body : {};
    let v;
    if ('traffic' in b) v = b.traffic;
    else if ('limit' in b) v = b.limit;
    else if ('dataLimit' in b) v = b.dataLimit;
    else if (req.query.traffic !== undefined) v = String(req.query.traffic);
    else return undefined;
    const n = parseTraffic(v);
    return n === undefined ? NaN : n;
}

// Usage: parseDuration("30d") -> "30d"; "1 month" -> "1m"; "2 weeks" -> "2w"; 12 -> "12d" (a number is days);
//        "never" / "none" / "0" / null -> null (no time limit); undefined for anything invalid.
//        Units: h hours, d days, w weeks, m months (calendar months; "m" is months, not minutes), y years (= 12 calendar
//        months, so "1y" is stored as "12m"). 1..9999 of them (years: 1..833).
function parseDuration(v) {
    if (v === null || v === 0 || v === false) return null;
    if (typeof v === 'number') return Number.isInteger(v) && v > 0 && v < 10000 ? v + 'd' : undefined;
    if (typeof v !== 'string') return undefined;
    const t = v.trim().toLowerCase();
    if (/^(|0|never|none|off|no|unlimited)$/.test(t)) return null;
    const m = /^(\d{1,4})\s*(h|hours?|d|days?|w|weeks?|m|mo|mon|months?|y|yrs?|years?)$/.exec(t);
    if (!m || +m[1] < 1) return undefined;
    if (m[2][0] === 'y') return +m[1] * 12 < 10000 ? (+m[1] * 12) + 'm' : undefined;
    return (+m[1]) + ({ h: 'h', d: 'd', w: 'w', m: 'm' })[m[2][0]];
}

// Usage: endOn(text) -> "on:<YYYY-MM-DD HH:MM:SS>" (a wall-clock time in THIS SERVER's time zone) or "at:<epoch>" (the text
//        carries its own zone: Z or +02:00), NaN when it is not a date. A date alone means the end of that day (23:59:59).
//        "2026-12-31" | "2026-12-31 18:00" | "2026-12-31T18:00[:30]" | "2026-12-31T18:00:00Z" | "2026-12-31T18:00:00+02:00"
function endOn(text) {
    const t = String(text).trim();
    const m = /^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2})(?::(\d{2}))?)?$/.exec(t);
    if (m) return 'on:' + m[1] + ' ' + (m[2] || '23:59') + ':' + (m[3] || (m[2] ? '00' : '59'));
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/.test(t)) {
        const sec = Math.floor(Date.parse(t) / 1000);
        return Number.isFinite(sec) && sec > 1e9 && sec < 1e11 ? 'at:' + sec : NaN;
    }
    return NaN;
}

// Usage: expiryFrom(req) -> the helper's expiry spec ("0", "in:30d", "on:2026-12-31 18:00:00", "at:<epoch>", "after:30d"),
//        undefined when the request sets none, NaN when it is not valid. Body fields:
//          "expires": "30d" | "1m" | "never" (or any date below)
//          "expiresOn": "2026-12-31 18:00" | "2026-12-31" (end of that day) | "never" - the SERVER's clock; a zone in
//                       the text ("...Z", "...+02:00") is honoured
//          "expiresAfterFirstConnection": "30d" | "1m"   (the clock starts at the key's first connection)
function expiryFrom(req) {
    const b = (req.body && typeof req.body === 'object') ? req.body : {};
    if ('expiresAfterFirstConnection' in b) {
        const d = parseDuration(b.expiresAfterFirstConnection);
        return d === undefined ? NaN : (d === null ? '0' : 'after:' + d);
    }
    if ('expiresOn' in b) {
        const v = b.expiresOn;
        if (v === null || (typeof v === 'string' && parseDuration(v) === null)) return '0';
        return typeof v === 'string' ? endOn(v) : NaN;
    }
    if (!('expires' in b)) return undefined;
    const v = b.expires;
    const d = parseDuration(v);
    if (d === null) return '0';
    if (d !== undefined) return 'in:' + d;
    return typeof v === 'string' ? endOn(v) : NaN;
}

// Usage: serverClock(sec) -> "2026-12-31 18:00" for an epoch, in this server's time zone
function serverClock(sec) {
    const d = new Date(sec * 1000), p = n => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

// Usage: serverOffset() -> "+02:00": the server's current offset from UTC
function serverOffset() {
    const o = -new Date().getTimezoneOffset(), a = Math.abs(o), p = n => String(n).padStart(2, '0');
    return (o < 0 ? '-' : '+') + p(Math.floor(a / 60)) + ':' + p(a % 60);
}

// Usage: serverNow() -> "2026-10-19 17:31 (UTC-07:00)"
function serverNow() {
    return serverClock(Date.now() / 1000) + ' (UTC' + serverOffset() + ')';
}

// Usage: keyObject({ip, publicKey, privateKey, created, rx, tx, hs, paused, limit, over}) -> one key as returned by
//        /keys and /create?format=json. privateKey/config are null for keys whose private key the server never saw.
function keyObject(k) {
    const up = k.rx || 0, down = k.tx || 0;
    const limit = k.limit || 0;
    return {
        id: k.ip,
        name: k.name || '',
        ipAddress: k.ip,
        address: k.ip + '/32',
        privateKey: k.privateKey || null,
        publicKey: k.publicKey,
        dns: CLIENT_DNS,
        serverPublicKey: SERVER_PUB,
        endpoint: ENDPOINT + ':' + WG_PORT,
        allowedIPs: CLIENT_ALLOWED_IPS,
        persistentKeepalive: CLIENT_KEEPALIVE,
        createdAt: k.created ? new Date(k.created * 1000).toISOString() : null,
        uploadBytes: up,
        downloadBytes: down,
        totalBytes: up + down,
        lastHandshake: k.hs ? new Date(k.hs * 1000).toISOString() : null,
        paused: !!k.paused,
        dataLimitBytes: limit,                              // 0 = unlimited
        dataLimit: limit ? { bytes: limit } : null,         // Outline's shape
        limitReached: !!(limit && k.over),
        expiresAt: k.exp ? new Date(k.exp * 1000).toISOString() : null,                  // null = no end (yet)
        expiresAtServer: k.exp ? serverClock(k.exp) : null,                             // the same moment on the server's clock
        expiresAfterFirstConnection: k.dur || null,                                      // e.g. "30d", "1m"
        firstConnectedAt: k.first ? new Date(k.first * 1000).toISOString() : null,
        expired: !!k.expd,
        status: k.paused ? 'paused' : (limit && k.over ? 'limit' : (k.expd ? 'expired' : 'active')),
        config: k.privateKey ? buildConfig(k.privateKey, k.ip) : null
    };
}

// Usage: parseKeys(helperOutput) -> [keyObject...] from 'wg-api-helper keys' (15 tab-separated fields per line)
function parseKeys(text) {
    return text.split('\n').filter(Boolean).map(line => {
        const f = line.split('\t');
        return keyObject({
            ip: f[0], publicKey: f[1], privateKey: f[2] === '-' ? null : f[2],
            created: parseInt(f[3], 10) || 0, rx: parseInt(f[4], 10) || 0,
            tx: parseInt(f[5], 10) || 0, hs: parseInt(f[6], 10) || 0, name: f[7] || '',
            paused: f[8] === '1', limit: parseInt(f[9], 10) || 0, over: f[10] === '1',
            exp: parseInt(f[11], 10) || 0, dur: f[12] && f[12] !== '-' ? f[12] : '', first: parseInt(f[13], 10) || 0,
            expd: f[14] === '1'
        });
    });
}

// Usage: helperFailure(err, fallback) -> { status, error } for a failed helper call:
//        400 for an address outside this server's pool, 404 for an unknown key, 503 when the pool is full
function helperFailure(err, fallback) {
    const msg = String((err && err.stderr) || '');
    if (/invalid ip/.test(msg)) return { status: 400, error: 'ip is not a client address of this server' };
    if (/invalid name/.test(msg)) return { status: 400, error: 'name must be 1-64 characters without control characters' };
    if (/no peer found/.test(msg)) return { status: 404, error: 'no such key' };
    if (/IP pool exhausted/.test(msg)) return { status: 503, error: 'IP pool exhausted' };
    if (/ip already allocated/.test(msg)) return { status: 409, error: 'ip already in use' };
    if (/invalid limit/.test(msg)) return { status: 400, error: 'invalid traffic limit' };
    if (/invalid expiry/.test(msg)) return { status: 400, error: 'invalid time limit' };
    if (/end time is in the past/.test(msg)) return { status: 400, error: 'the end time is in the past (server time: ' + serverNow() + ')' };
    return { status: 500, error: fallback };
}

// Usage: cleanName(value) -> a display name (trimmed, at most 64 characters, no control characters) or ''
function cleanName(value) {
    if (typeof value !== 'string') return '';
    // eslint-disable-next-line no-control-regex
    return value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 64);
}

// Usage: IPV4.test(str) -> shape check only; wg-api-helper decides whether the address belongs to the pool
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

// Health endpoint is public (used by wg-healthcheck.sh)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Usage: app.use(auth) -> lets a request through when its first path segment is the secret API_PATH (the segment is
//        then removed, so /<secret>/keys is served as /keys) or when it carries "Authorization: Bearer <token>"
app.use((req, res, next) => {
    if (API_PATH) {
        const m = /^\/([^/?]+)(.*)$/.exec(req.url);
        if (m && sameSecret(m[1], API_PATH)) {
            req.url = m[2] && m[2][0] === '/' ? m[2] : '/' + (m[2] || '');
            return next();
        }
    }
    if (!tokenOk(req.headers.authorization)) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
});

// /health again behind the secret path, so <apiUrl>/health works with an Outline-style apiUrl too
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Usage: createKey(name, ip, limit, expiry) -> keyObject of a new key at <ip> (or the first free address) with a traffic
//        limit in bytes (0 = unlimited) and a time limit (helper spec, '' = none); the private key is kept for GET /keys
function createKey(name, ip, limit, expiry) {
    const privateKey = execFileSync('wg', ['genkey'], { encoding: 'utf8' }).trim();
    const publicKey = execFileSync('wg', ['pubkey'], { input: privateKey, encoding: 'utf8' }).trim();
    const clientIP = helper(['add-auto', publicKey, name || '', ip || '', limit ? String(limit) : '', expiry || ''],
        privateKey + '\n').trim();
    if (!IPV4.test(clientIP)) throw new Error('helper returned an unexpected address');
    const stored = parseKeys(helper(['keys', clientIP]))[0];
    return stored && stored.privateKey ? stored
        : keyObject({ ip: clientIP, publicKey, privateKey, name, created: Math.floor(Date.now() / 1000), limit: limit || 0 });
}

const EXPIRY_HELP = 'invalid time limit: use "expires": "30d", "1m", "1y", "12h" or "never", ' +
    '"expiresOn": "2026-12-31 18:00" (server time), or "expiresAfterFirstConnection": "30d" (units h, d, w, m = months, y = years)';

// Usage: createRequest(req) -> { name, ip, limit, expiry } from the body / query, or { error } (400)
//        {"name": "...", "ipAddress": "10.66.0.2", "traffic": "20G", "expires": "30d"} - every field optional
//        (or "expiresOn": "2026-12-31 18:00" / "expiresAfterFirstConnection": "1m" instead of "expires")
function createRequest(req) {
    const b = (req.body && typeof req.body === 'object') ? req.body : {};
    const name = cleanName(b.name || req.query.name);
    const ipText = b.ipAddress || req.query.ipAddress || '';
    if (ipText && (typeof ipText !== 'string' || !IPV4.test(ipText.split('/')[0]))) return { error: 'invalid ipAddress format' };
    const limit = trafficFrom(req);
    if (Number.isNaN(limit)) return { error: 'invalid traffic: use e.g. "20G", "500M", "1.5T", a number of bytes, or "unlimited"' };
    const expiry = expiryFrom(req);
    if (Number.isNaN(expiry)) return { error: EXPIRY_HELP };
    return { name, ip: ipText ? ipText.split('/')[0] : '', limit: limit || 0, expiry: expiry || '' };
}

// POST /create            -> client config as text/plain (backward compatible)
// POST /create?format=json -> the new key as JSON (same shape as one entry of GET /keys)
//   optional body: {"name": "...", "ipAddress": "10.66.0.2", "traffic": "20G"}
app.post('/create', (req, res) => {
    const r = createRequest(req);
    if (r.error) return res.status(400).json({ error: r.error });
    try {
        const key = createKey(r.name, r.ip, r.limit, r.expiry);
        if (req.query.format === 'json') return res.json(key);
        res.type('text/plain').send(key.config);
    } catch (err) {
        console.error('create failed:', err.message);
        const f = helperFailure(err, 'create failed');
        res.status(f.status).json({ error: f.error });
    }
});

// POST /access-keys  {"name": "...", "ipAddress": "...", "traffic": "20G"}  -> 201 + the new key as JSON
app.post('/access-keys', (req, res) => {
    const r = createRequest(req);
    if (r.error) return res.status(400).json({ error: r.error });
    try {
        res.status(201).json(createKey(r.name, r.ip, r.limit, r.expiry));
    } catch (err) {
        console.error('create failed:', err.message);
        const f = helperFailure(err, 'create failed');
        res.status(f.status).json({ error: f.error });
    }
});

// Usage: removeKey(ipText, res, okStatus) -> validates, removes through the helper and answers the request
function removeKey(ipText, res, okStatus) {
    if (typeof ipText !== 'string' || !ipText) return res.status(400).json({ error: 'ipAddress required' });
    const ipOnly = ipText.split('/')[0];
    if (!IPV4.test(ipOnly)) return res.status(400).json({ error: 'invalid ipAddress format' });
    try {
        helper(['remove', ipOnly]);
        if (okStatus === 204) return res.status(204).end();
        res.json({ success: true, removed: ipOnly });
    } catch (err) {
        console.error('remove failed:', err.message);
        const f = helperFailure(err, 'remove failed');
        res.status(f.status).json({ error: f.error });
    }
}

// POST /remove  { "ipAddress": "10.66.0.5" }
app.post('/remove', (req, res) => removeKey(req.body && req.body.ipAddress, res, 200));

// DELETE /access-keys/10.66.0.5 (Outline Manager's delete call; also /keys/10.66.0.5) -> 204
app.delete(['/access-keys/:ip', '/keys/:ip'], (req, res) => removeKey(req.params.ip, res, 204));

// Usage: parseUsage(text) -> [{ ipAddress, uploadBytes, downloadBytes, lastHandshake }]
// "upload" and "download" are from the client's point of view (server rx = client upload).
function parseUsage(text) {
    return text.split('\n').filter(Boolean).map(line => {
        const f = line.split('\t');
        const up = parseInt(f[1], 10) || 0, down = parseInt(f[2], 10) || 0, hs = parseInt(f[3], 10) || 0;
        return {
            ipAddress: f[0],
            uploadBytes: up,
            downloadBytes: down,
            totalBytes: up + down,
            lastHandshake: hs ? new Date(hs * 1000).toISOString() : null
        };
    });
}

// GET /usage        -> { interface, timestamp, totals, keys: [ per-key usage ] }
// GET /usage/:ip    -> usage of one key, e.g. /usage/10.66.0.5
// Totals: saved every minute and just before wg0 stops, so they survive wg0 restarts and reboots (traffic.db).
app.get('/usage', (req, res) => {
    try {
        const keys = parseUsage(helper(['usage']));
        const totals = keys.reduce((t, k) => ({
            uploadBytes: t.uploadBytes + k.uploadBytes,
            downloadBytes: t.downloadBytes + k.downloadBytes,
            totalBytes: t.totalBytes + k.totalBytes
        }), { uploadBytes: 0, downloadBytes: 0, totalBytes: 0 });
        res.json({ interface: 'wg0', timestamp: new Date().toISOString(), totals, keys });
    } catch (err) {
        console.error('usage failed:', err.message);
        const f = helperFailure(err, 'usage failed');
        res.status(f.status).json({ error: f.error });
    }
});

app.get('/usage/:ip', (req, res) => {
    const ip = req.params.ip.split('/')[0];
    if (!IPV4.test(ip)) {
        return res.status(400).json({ error: 'invalid ip' });
    }
    try {
        const keys = parseUsage(helper(['usage', ip]));
        if (keys.length === 0) return res.status(404).json({ error: 'no such key' });
        res.json(keys[0]);
    } catch (err) {
        console.error('usage failed:', err.message);
        const f = helperFailure(err, 'usage failed');
        res.status(f.status).json({ error: f.error });
    }
});

// Usage: serverInfo() -> the public facts about this server (no secrets)
function serverInfo() {
    return { publicKey: SERVER_PUB, endpoint: ENDPOINT + ':' + WG_PORT, dns: CLIENT_DNS, apiVersion: API_VERSION, features: FEATURES,
        timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone, utcOffset: serverOffset(),
        serverTime: new Date().toISOString(), serverClock: serverClock(Date.now() / 1000) };
}

// Usage: listKeys(field) -> express handler answering { server, timestamp, count, totals, <field>: [ keyObject ] }
function listKeys(field) {
    return (req, res) => {
        try {
            const keys = parseKeys(helper(['keys']));
            const totals = keys.reduce((t, k) => ({
                uploadBytes: t.uploadBytes + k.uploadBytes,
                downloadBytes: t.downloadBytes + k.downloadBytes,
                totalBytes: t.totalBytes + k.totalBytes
            }), { uploadBytes: 0, downloadBytes: 0, totalBytes: 0 });
            res.json({ server: serverInfo(), timestamp: new Date().toISOString(), count: keys.length, totals, [field]: keys });
        } catch (err) {
            console.error('keys failed:', err.message);
            const f = helperFailure(err, 'keys failed');
            res.status(f.status).json({ error: f.error });
        }
    };
}

// GET /keys        -> every key with its full client settings and usage: { server, count, totals, keys: [...] }
//                     also at the apiUrl itself (GET /), so one GET of apiUrl returns every key
// GET /access-keys -> the same list under "accessKeys", the name Outline uses: with the Outline-style
//                     access config, GET <apiUrl>/access-keys needs no header at all
// GET /keys/:ip    -> one key, e.g. /keys/10.66.0.5
app.get(['/', '/keys'], listKeys('keys'));
app.get('/access-keys', listKeys('accessKeys'));

// GET /server -> { name, serverId, publicKey, endpoint, dns, apiVersion, accessKeyCount, ... } (like Outline's /server)
app.get('/server', (req, res) => {
    try {
        const count = helper(['used-ips']).split('\n').filter(Boolean).length;
        res.json(Object.assign({ name: ENDPOINT, serverId: SERVER_PUB, createdTimestampMs: STARTED_MS,
            accessKeyCount: count, portForNewAccessKeys: WG_PORT }, serverInfo()));
    } catch (err) {
        console.error('server failed:', err.message);
        res.status(500).json({ error: 'server info failed' });
    }
});

// GET /metrics/transfer -> { bytesTransferredByUserId: { "10.66.0.2": 12345, ... } } (Outline's usage call)
app.get('/metrics/transfer', (req, res) => {
    try {
        const out = {};
        for (const k of parseUsage(helper(['usage']))) out[k.ipAddress] = k.totalBytes;
        res.json({ bytesTransferredByUserId: out });
    } catch (err) {
        console.error('metrics failed:', err.message);
        const f = helperFailure(err, 'metrics failed');
        res.status(f.status).json({ error: f.error });
    }
});

app.get(['/keys/:ip', '/access-keys/:ip'], (req, res) => {
    const ip = req.params.ip.split('/')[0];
    if (!IPV4.test(ip)) {
        return res.status(400).json({ error: 'invalid ip' });
    }
    try {
        const keys = parseKeys(helper(['keys', ip]));
        if (keys.length === 0) return res.status(404).json({ error: 'no such key' });
        res.json(keys[0]);
    } catch (err) {
        console.error('keys failed:', err.message);
        const f = helperFailure(err, 'keys failed');
        res.status(f.status).json({ error: f.error });
    }
});

// PUT /keys/:ip/name  {"name": "Phone of Ali"}  -> renames a key; returns the key
app.put(['/keys/:ip/name', '/access-keys/:ip/name'], (req, res) => {
    const ip = req.params.ip.split('/')[0];
    const name = cleanName(req.body && req.body.name);
    if (!IPV4.test(ip)) return res.status(400).json({ error: 'invalid ip' });
    if (!name) return res.status(400).json({ error: 'name required' });
    try {
        helper(['rename', ip, name]);
        const keys = parseKeys(helper(['keys', ip]));
        res.json(keys[0] || { ipAddress: ip, name });
    } catch (err) {
        console.error('rename failed:', err.message);
        const f = helperFailure(err, 'rename failed');
        res.status(f.status).json({ error: f.error });
    }
});

// Usage: keyAction(res, ip, args) -> runs one helper command on an existing key and answers with the updated key
function keyAction(res, ipText, args) {
    const ip = String(ipText || '').split('/')[0];
    if (!IPV4.test(ip)) return res.status(400).json({ error: 'invalid ip' });
    try {
        helper([args[0], ip, ...args.slice(1)]);
        const keys = parseKeys(helper(['keys', ip]));
        res.json(keys[0] || { ipAddress: ip });
    } catch (err) {
        console.error(args[0] + ' failed:', err.message);
        const f = helperFailure(err, args[0] + ' failed');
        res.status(f.status).json({ error: f.error });
    }
}

// POST /keys/:ip/pause, /keys/:ip/resume  -> block / unblock all traffic of a key; returns the key
// PUT  /keys/:ip/paused {"paused": true|false}
app.post(['/keys/:ip/pause', '/access-keys/:ip/pause'], (req, res) => keyAction(res, req.params.ip, ['pause']));
app.post(['/keys/:ip/resume', '/access-keys/:ip/resume'], (req, res) => keyAction(res, req.params.ip, ['resume']));
app.put(['/keys/:ip/paused', '/access-keys/:ip/paused'], (req, res) => {
    const p = req.body && req.body.paused;
    if (typeof p !== 'boolean') return res.status(400).json({ error: 'paused must be true or false' });
    keyAction(res, req.params.ip, [p ? 'pause' : 'resume']);
});

// PUT /keys/:ip/limit {"traffic": "20G"}   (or "unlimited"; also {"limit": {"bytes": N}} like Outline's data-limit)
// DELETE /keys/:ip/limit                   -> unlimited
// The limit counts upload + download since the key was created; a key over it is blocked until it is raised.
app.put(['/keys/:ip/limit', '/access-keys/:ip/limit', '/access-keys/:ip/data-limit'], (req, res) => {
    const limit = trafficFrom(req);
    if (limit === undefined || Number.isNaN(limit)) {
        return res.status(400).json({ error: 'traffic required: e.g. "20G", "500M", "1.5T", a number of bytes, or "unlimited"' });
    }
    keyAction(res, req.params.ip, ['limit', String(limit)]);
});
app.delete(['/keys/:ip/limit', '/access-keys/:ip/limit', '/access-keys/:ip/data-limit'], (req, res) => keyAction(res, req.params.ip, ['limit', '0']));

// PUT /keys/:ip/expiry {"expires": "30d"}                       -> ends 30 days from now ("1m" = one calendar month,
//                                                                   "never" = no end)
// PUT /keys/:ip/expiry {"expiresOn": "2026-12-31 18:00"}        -> ends at that time on the SERVER's clock (GET /server shows
//                                                                   it: serverClock, timeZone); a date alone = end of that day
// PUT /keys/:ip/expiry {"expiresAfterFirstConnection": "30d"}   -> ends 30 days after the key's first connection
//                                                                   (now, if it has connected before)
// DELETE /keys/:ip/expiry                                        -> no time limit
// A key past its end is blocked until it gets a later end or none; its config and usage stay.
app.put(['/keys/:ip/expiry', '/access-keys/:ip/expiry'], (req, res) => {
    const spec = expiryFrom(req);
    if (spec === undefined || Number.isNaN(spec)) return res.status(400).json({ error: EXPIRY_HELP });
    keyAction(res, req.params.ip, ['expiry', spec]);
});
app.delete(['/keys/:ip/expiry', '/access-keys/:ip/expiry'], (req, res) => keyAction(res, req.params.ip, ['expiry', '0']));

app.listen(__API_PORT__, '127.0.0.1', () => {
    console.log('wg-api listening on 127.0.0.1:__API_PORT__');
});
SERVER_JS_EOF
    sed -i \
        -e "s|__SERVER_PUB__|${SERVER_PUBLIC_KEY}|g" \
        -e "s|__ENDPOINT__|${DOMAIN}|g" \
        -e "s|__WG_PORT__|${WG_PORT}|g" \
        -e "s|__DNS__|${CLIENT_DNS}|g" \
        -e "s|__API_PORT__|${API_PORT_INTERNAL}|g" \
        "${API_DIR}/server.js"
    api_dir_perms
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
# light hardening: wg-api-helper runs as a child of this service (through sudo) and writes /etc/wireguard and
# /etc/wg-api, so ProtectSystem/NoNewPrivileges cannot be used here
ProtectHome=true
PrivateTmp=true
ProtectControlGroups=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
END
    systemctl daemon-reload
    systemctl enable "$API_SERVICE" >/dev/null 2>&1
    systemctl restart "$API_SERVICE"
    ok "${API_SERVICE} started"
}

# Usage: step_prepare_tls -> selfsigned: creates the certificate; custom: copies yours; sets TLS_FINGERPRINT and TLS_PIN
step_prepare_tls() {
    [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] || return 0
    TLS_FINGERPRINT=""
    TLS_PIN=""
    [ "$TLS_MODE" != "letsencrypt" ] || return 0
    say "Preparing the TLS certificate (${TLS_MODE})..."
    id caddy >/dev/null 2>&1 || useradd -r -s "$NOLOGIN" -d /var/lib/caddy caddy
    install -d -o caddy -g caddy -m 700 "$TLS_DIR"
    local cert="${TLS_DIR}/cert.pem" key="${TLS_DIR}/key.pem" san
    if [ "$TLS_MODE" = "custom" ]; then
        install -o caddy -g caddy -m 644 "$TLS_CERT" "$cert"
        install -o caddy -g caddy -m 600 "$TLS_KEY" "$key"
        warn "Your certificate was COPIED to ${TLS_DIR}; it does not follow renewals. Re-run with --reconfigure-api --tls-cert=... --tls-key=... after each renewal."
    else
        if [[ "$DOMAIN" =~ ^[0-9.]+$ ]]; then san="IP:${DOMAIN}"; else san="DNS:${DOMAIN}"; fi
        if [ ! -f "$cert" ] || ! openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -qF "${san#*:}"; then
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 3650 \
                -keyout "$key" -out "$cert" -subj "/CN=${DOMAIN}" -addext "subjectAltName=${san}" >/dev/null 2>&1 \
                || die "Could not create the self-signed certificate (needs OpenSSL 1.1.1 or newer)."
            chown caddy:caddy "$cert" "$key"
            chmod 644 "$cert"
            chmod 600 "$key"
            ok "Created a self-signed certificate for ${DOMAIN} (valid 10 years)"
        else
            ok "Keeping the existing self-signed certificate for ${DOMAIN}"
        fi
    fi
    TLS_FINGERPRINT="$(openssl x509 -in "$cert" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g')"
    TLS_PIN="sha256//$(openssl x509 -in "$cert" -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl base64)"
    ok "Certificate SHA-256: ${TLS_FINGERPRINT}"
}

# Usage: step_configure_caddy -> Caddyfile for the chosen port and TLS mode; validated before Caddy is restarted
step_configure_caddy() {
    [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ] || return 0
    say "Configuring Caddy for ${DOMAIN} on port ${HTTPS_PORT} (TLS: ${TLS_MODE})..."
    mkdir -p /etc/caddy /var/log/caddy
    id caddy >/dev/null 2>&1 || useradd -r -s "$NOLOGIN" -d /var/lib/caddy caddy
    chown -R caddy:caddy /var/log/caddy
    if [ -f /etc/caddy/Caddyfile ] && ! grep -q 'install-wg-full.sh' /etc/caddy/Caddyfile; then
        cp -a /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)"
    fi
    if [ "$TLS_MODE" = "letsencrypt" ]; then
        cat > /etc/caddy/Caddyfile <<END
# managed by install-wg-full.sh
{
    # do not open a port-80 redirect listener
    auto_https disable_redirects
}

${DOMAIN} {
    reverse_proxy 127.0.0.1:${API_PORT_INTERNAL}
    log {
        output file /var/log/caddy/wg-api.log
        # never write the secret API path or the token to the log
        format filter {
            request>uri delete
            request>headers>Authorization delete
        }
    }
}
END
    else
        cat > /etc/caddy/Caddyfile <<END
# managed by install-wg-full.sh
{
    # the certificate is supplied below: no ACME, no redirects, nothing on port 80
    auto_https off
}

https://${DOMAIN}:${HTTPS_PORT} {
    tls ${TLS_DIR}/cert.pem ${TLS_DIR}/key.pem
    reverse_proxy 127.0.0.1:${API_PORT_INTERNAL}
    log {
        output file /var/log/caddy/wg-api.log
        # never write the secret API path or the token to the log
        format filter {
            request>uri delete
            request>headers>Authorization delete
        }
    }
}
END
    fi
    caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 || die "Caddyfile does not validate: caddy validate --config /etc/caddy/Caddyfile"
    # 'caddy validate' runs as root and creates the log file owned by root; the service runs as
    # user caddy and would then fail with "permission denied", so hand the log files back
    chown -R caddy:caddy /var/log/caddy
    systemctl enable caddy >/dev/null 2>&1 || true
    systemctl reset-failed caddy >/dev/null 2>&1 || true
    systemctl restart caddy || true
    # 'systemctl restart' can report success even when Caddy exits a moment later: check for real
    sleep 2
    if ! systemctl is-active --quiet caddy || { have ss && ! port_in_use "$HTTPS_PORT"; }; then
        journalctl -u caddy -n 15 --no-pager >&2 || true
        die "Caddy is not running on port ${HTTPS_PORT}. Details above; also: systemctl status caddy --no-pager -l"
    fi
    compute_api_url
    ok "Caddy proxies ${API_URL} to 127.0.0.1:${API_PORT_INTERNAL}"
}

# Usage: step_write_access_config -> saves both access configs (mode 600), either one opens the server in
#        Mithra WireGuard Manager:
#          /etc/wg-api/access.json          {apiUrl, apiToken, certSha256}
#          /etc/wg-api/access-outline.json  {apiUrl: <url>/<secret path>, certSha256}   (exactly Outline's format)
step_write_access_config() {
    [ "$INSTALL_API" -eq 1 ] || return 0
    compute_api_url
    have jq || pkg_install jq >/dev/null 2>&1
    install -d -o root -g root -m 700 "$API_ENV_DIR"
    ( umask 077; jq -n --arg u "$API_URL" --arg t "$API_TOKEN" --arg f "$TLS_FINGERPRINT" \
        '{apiUrl: $u, apiToken: $t, certSha256: (if $f == "" then null else $f end)}' > "$ACCESS_FILE" )
    if [ -n "${API_PATH:-}" ]; then
        ( umask 077; jq -n --arg u "${API_URL}/${API_PATH}" --arg f "$TLS_FINGERPRINT" \
            '{apiUrl: $u, certSha256: (if $f == "" then null else $f end)}' > "$ACCESS_OUTLINE_FILE" )
        chmod 600 "$ACCESS_OUTLINE_FILE"
    fi
    chmod 600 "$ACCESS_FILE"
    ok "Access configs saved to ${ACCESS_FILE} and ${ACCESS_OUTLINE_FILE}"
}

# Usage: cidr_network 10.66.0.1/16 -> 10.66.0.0/16
cidr_network() {
    local ip="${1%/*}" p="${1#*/}" o a b c d mask n
    IFS=. read -r a b c d <<<"$ip"
    n=$(( (a<<24) + (b<<16) + (c<<8) + d ))
    mask=$(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF ))
    n=$(( n & mask ))
    echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))/$p"
}

# Usage: sample_ip -> the first client address of the pool (server address + 1), for the example commands
sample_ip() {
    local base="${WG_SERVER_ADDR%/*}"
    echo "${base%.*}.$(( ${base##*.} + 1 ))"
}

# Usage: load_existing_settings -> reads domain, token, keys and ports from an existing install (for --reconfigure-api)
load_existing_settings() {
    [ -f "${API_DIR}/server.js" ] || die "No existing install found (${API_DIR}/server.js is missing). Run a normal install first."
    if [ -z "$DOMAIN" ]; then
        DOMAIN="$(sed -n "s/^const ENDPOINT = '\(.*\)';/\1/p" "${API_DIR}/server.js" | head -n1)"
    fi
    [ -n "$DOMAIN" ] || die "Could not read the domain from ${API_DIR}/server.js; pass --domain=NAME."
    # every read below must survive a missing file: with 'set -e' and 'pipefail' a failing sed would end the script without a word
    API_TOKEN="$(sed -n 's/^API_TOKEN=//p' "${API_ENV_DIR}/env" 2>/dev/null | head -n1 || true)"
    [ -n "$API_TOKEN" ] || die "Could not read the API token from ${API_ENV_DIR}/env (is the file there? ls -l ${API_ENV_DIR})."
    API_PATH="$(sed -n 's/^API_PATH=//p' "${API_ENV_DIR}/env" 2>/dev/null | head -n1 || true)"
    SERVER_PUBLIC_KEY="$(cat /etc/wireguard/server_public.key 2>/dev/null || true)"
    local lp ip addr
    addr="$(sed -n 's/^Address[[:space:]]*=[[:space:]]*\([0-9.]*\/[0-9]*\).*/\1/p' "$WG_CONFIG" 2>/dev/null | head -n1 || true)"
    if [ -n "$addr" ]; then WG_SERVER_ADDR="$addr"; WG_NETWORK="$(cidr_network "$addr")"; fi
    lp="$(sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$WG_CONFIG" 2>/dev/null | head -n1 || true)"
    if [ -n "$lp" ]; then WG_PORT="$lp"; fi
    ip="$(sed -n 's/^app\.listen(\([0-9]*\),.*/\1/p' "${API_DIR}/server.js" | head -n1)"
    if [ -n "$ip" ]; then API_PORT_INTERNAL="$ip"; fi
}

# Usage: update_api -> rewrites wg-api-helper and server.js (new endpoints) and restarts wg-api; keys, peers, token and TLS are kept
update_api() {
    INSTALL_API=1
    load_existing_settings
    local d
    d="$(sed -n "s/^const CLIENT_DNS = '\(.*\)';/\1/p" "${API_DIR}/server.js" | head -n1)"
    if [ -n "$d" ]; then CLIENT_DNS="$d"; fi
    update_firewall
    step_install_peer_ctrl
    step_generate_token
    step_install_api_helper
    step_install_traffic_saver
    step_api_npm_setup
    step_write_server_js
    step_create_systemd_service
    sleep 1
    systemctl is-active --quiet wg-api || die "wg-api is not running: journalctl -u wg-api -n 30"
    caddy_add_log_filter
    # keep the existing URL and certificate fingerprint, add the Outline-style config next to them
    if [ -f "$ACCESS_FILE" ]; then
        API_URL="$(jq -r '.apiUrl // empty' "$ACCESS_FILE")"
        TLS_FINGERPRINT="$(jq -r '.certSha256 // empty' "$ACCESS_FILE")"
        API_URL="${API_URL%/}"
        if [ -n "$API_URL" ]; then
            ( umask 077; jq -n --arg u "${API_URL}/${API_PATH}" --arg f "$TLS_FINGERPRINT" \
                '{apiUrl: $u, certSha256: (if $f == "" then null else $f end)}' > "$ACCESS_OUTLINE_FILE" )
            chmod 600 "$ACCESS_OUTLINE_FILE"
        fi
    fi
    ok "wg-api updated (API 2.3): pause/resume, traffic and time limits (incl. an end date/time in server time), create at a chosen address, IPv6 kept in the tunnel"
    echo "  Client configs now use AllowedIPs = 0.0.0.0/0, ::/0. Devices that imported a key before this update"
    echo "  keep the old config: re-import it (QR / .conf in the app) to stop IPv6 leaking around the tunnel."
    echo
    echo "  Access config, paste either one into Mithra WireGuard Manager:"
    access_line "$ACCESS_FILE"
    access_line "$ACCESS_OUTLINE_FILE" "(Outline format)"
}

# Usage: caddy_add_log_filter -> adds the filter that keeps the secret API path and the token out of Caddy's log to a
#                                Caddyfile written by an older version of this script, then reloads Caddy
caddy_add_log_filter() {
    local cf=/etc/caddy/Caddyfile
    [ -f "$cf" ] && grep -q 'install-wg-full.sh' "$cf" || return 0
    grep -q 'request>uri delete' "$cf" && return 0
    cp -a "$cf" "${cf}.bak-$(date +%Y%m%d-%H%M%S)"
    sed -i '/output file \/var\/log\/caddy\/wg-api.log/a\
        format filter {\
            request>uri delete\
            request>headers>Authorization delete\
        }' "$cf"
    if caddy validate --config "$cf" >/dev/null 2>&1; then
        chown -R caddy:caddy /var/log/caddy 2>/dev/null || true
        systemctl reload caddy 2>/dev/null || systemctl restart caddy || true
        ok "Caddy log no longer records request paths or tokens"
    else
        warn "Could not add the log filter to ${cf} automatically; the original is kept in ${cf}.bak-*"
        cp -a "$(ls -t "${cf}".bak-* | head -n1)" "$cf"
    fi
}

# Usage: reconfigure_api -> new HTTPS port / certificate for an existing install; WireGuard keys and peers are not touched
reconfigure_api() {
    INSTALL_API=1
    INSTALL_CADDY=1
    load_existing_settings
    ask_https_port
    ask_tls_mode
    step_install_caddy
    detect_outbound_interface
    step_prepare_tls
    step_firewall_host
    step_selinux
    step_configure_caddy
    step_write_access_config
    step_self_test
    print_success_message
}

# Usage: fetch_tool <name> -> installs a repo script into /usr/local/bin (local copy first, else GitHub), syntax-checked
fetch_tool() {
    local name="$1" tmp
    tmp="$(mktemp)"
    if [ -f "${SCRIPT_DIR}/${name}" ]; then
        cp "${SCRIPT_DIR}/${name}" "$tmp"
    elif ! curl -fsSL --retry 3 -m 30 "${REPO_RAW}/${name}" -o "$tmp"; then
        rm -f "$tmp"; warn "Could not download ${name}; run --update-tools later."; return 1
    else
        # downloaded: it runs as root (daily timer), so it must be exactly the reviewed version
        local want="${TOOL_SHA256[$name]:-}" got
        got="$(sha256sum "$tmp" | awk '{print $1}')"
        if [ -z "$want" ] || [ "$got" != "$want" ]; then
            rm -f "$tmp"; warn "${name}: SHA-256 ${got} does not match the expected ${want:-<none>}; not installed."; return 1
        fi
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
    if [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 1 ]; then
        local code
        code="$(curl -sk -m 8 --resolve "${DOMAIN}:${HTTPS_PORT}:127.0.0.1" -o /dev/null -w '%{http_code}' \
            "https://${DOMAIN}:${HTTPS_PORT}/health" 2>/dev/null || true)"
        if [ "$code" = "200" ]; then
            ok "HTTPS endpoint answers on ${API_URL}"
        else
            warn "HTTPS check on port ${HTTPS_PORT} returned '${code:-no answer}': systemctl status caddy; journalctl -u caddy -n 30 --no-pager$([ "$TLS_MODE" = "letsencrypt" ] && echo " (Let's Encrypt may still be issuing the certificate)")"
        fi
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
        compute_api_url
        local tlsopts=""
        if [ "$INSTALL_CADDY" -eq 1 ]; then
            echo "  API:             ${API_URL}"
            echo "  HTTPS port:      ${HTTPS_PORT}/tcp   (TLS: ${TLS_MODE})"
            if [ -n "$TLS_FINGERPRINT" ]; then
                echo "  certSha256:      ${TLS_FINGERPRINT}"
                tlsopts="--insecure --pinnedpubkey '${TLS_PIN}' "
            fi
        else
            echo "  API:             http://127.0.0.1:${API_PORT_INTERNAL} (proxy it, see below)"
        fi
        echo "  Bearer token:    ${API_TOKEN}   (stored in ${API_ENV_DIR}/env)"
        echo
        echo "  Access config: paste EITHER line into Mithra WireGuard Manager (Add server)."
        echo "  Both open every key on this server. Treat them like passwords."
        access_line "$ACCESS_FILE"
        access_line "$ACCESS_OUTLINE_FILE" "(Outline format)"
        echo "  (saved in ${ACCESS_FILE} and ${ACCESS_OUTLINE_FILE})"
        echo
        local sep="  ----------------------------------------------------------------------"
        echo "$sep"
        echo "  Create a client (add ?format=json for JSON):"
        echo "    curl ${tlsopts}-X POST ${API_URL}/create -H \"Authorization: Bearer ${API_TOKEN}\""
        echo
        echo "$sep"
        echo "  Remove a client:"
        echo "    curl ${tlsopts}-X POST ${API_URL}/remove -H \"Authorization: Bearer ${API_TOKEN}\" \\"
        echo "      -H 'Content-Type: application/json' -d '{\"ipAddress\":\"$(sample_ip)\"}'"
        echo
        echo "$sep"
        echo "  List ALL keys with their full settings (PrivateKey, DNS, PublicKey, Endpoint, AllowedIPs,"
        echo "  PersistentKeepalive, ready-made config) and usage, like Outline Manager:"
        echo "    curl ${tlsopts}${API_URL}/keys -H \"Authorization: Bearer ${API_TOKEN}\"   (also: ${API_URL}/ and /access-keys)"
        echo
        echo "$sep"
        echo "  Or, from any machine, with ONLY the access config above (like Outline Manager):"
        echo "    ./wg-pull-keys.sh '$(jq -c . "$ACCESS_FILE" 2>/dev/null || echo '<access config>')' --table"
        echo
        echo "$sep"
        echo "  List ALL keys with upload/download (bytes) and last handshake (light, for polling):"
        echo "    curl ${tlsopts}${API_URL}/usage -H \"Authorization: Bearer ${API_TOKEN}\""
        echo
        echo "$sep"
        echo "  Usage of ONE key (by its IP address):"
        echo "    curl ${tlsopts}${API_URL}/usage/$(sample_ip) -H \"Authorization: Bearer ${API_TOKEN}\""
        echo
        echo "$sep"
        echo "  Create a key at a chosen address with a 20 GB traffic limit (or \"unlimited\"):"
        echo "    curl ${tlsopts}-X POST '${API_URL}/create?format=json' -H \"Authorization: Bearer ${API_TOKEN}\" \\"
        echo "      -H 'Content-Type: application/json' -d '{\"ipAddress\":\"$(sample_ip)\",\"traffic\":\"20G\"}'"
        echo "  Change the limit later / remove it:"
        echo "    curl ${tlsopts}-X PUT ${API_URL}/keys/$(sample_ip)/limit -H \"Authorization: Bearer ${API_TOKEN}\" \\"
        echo "      -H 'Content-Type: application/json' -d '{\"traffic\":\"50G\"}'      # or {\"traffic\":\"unlimited\"}"
        echo "  Time limit: 30 days from now, or 1 month from the key's first connection (\"never\" removes it):"
        echo "    curl ${tlsopts}-X PUT ${API_URL}/keys/$(sample_ip)/expiry -H \"Authorization: Bearer ${API_TOKEN}\" \\"
        echo "      -H 'Content-Type: application/json' -d '{\"expires\":\"30d\"}'      # or {\"expiresOn\":\"2026-12-31 18:00\"} (server time) / {\"expiresAfterFirstConnection\":\"1m\"}"
        echo "  Pause / resume a key:"
        echo "    curl ${tlsopts}-X POST ${API_URL}/keys/$(sample_ip)/pause -H \"Authorization: Bearer ${API_TOKEN}\"     # .../resume"
        echo
        echo "  (upload/download are from the client's point of view; totals are kept across restarts and reboots."
        echo "   Polling: one /usage call per minute is fine; prefer it over one call per key.)"
        echo "$sep"
        if [ -n "$tlsopts" ]; then
            echo "  (the certificate is self-made: --pinnedpubkey checks it against the fingerprint above"
            echo "   instead of a public CA; change port or certificate later with --reconfigure-api)"
            echo "  Behind the Cloudflare proxy (orange cloud) clients see Cloudflare's certificate instead:"
            echo "  drop --insecure/--pinnedpubkey and set SSL/TLS mode to 'Full' so Cloudflare accepts this one."
        fi
    fi
    if [ "$INSTALL_API" -eq 1 ] && [ "$INSTALL_CADDY" -eq 0 ]; then
        cat <<END

  Caddy was skipped. Add this inside the nginx server block for ${DOMAIN}
  (vi ${NGINX_SITE_HINT}), then: nginx -t && systemctl reload nginx

    location / {
        proxy_pass http://127.0.0.1:${API_PORT_INTERNAL};
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
END
    fi
    echo
    echo "  Health tools:"
    echo "    sudo wg-healthcheck.sh [--capture=20]     health check"
    echo "    sudo vpn-doctor.sh [--fix] [--dry-run]    diagnose and fix"
    echo "    journalctl -t wg-peer-ctrl -f             enforcement audit log"
    [ -z "$MONITOR_KEY" ] && echo "    ${SELF_CMD} --add-monitor --monitor-key-file=FILE   add wg-monitor later (as root)"
    echo
    echo "  Keep the token secret; rotate it (edit ${API_ENV_DIR}/env with vi, then"
    echo "  systemctl restart ${API_SERVICE}) if it was ever pasted anywhere."
    echo "═══════════════════════════════════════════════════════════════"
}

# Usage: install_all -> the full installation, in dependency order
install_all() {
    echo "Starting the WireGuard installation (install-wg-full.sh ${SCRIPT_VERSION})..."
    say "Platform: ${OS_NAME} (${OS_FAMILY} family, ${PKG_MGR})"
    ask_port
    ask_domain
    ask_https_port
    ask_tls_mode
    # no wg-monitor question here: the HTTPS API (incl. GET /usage) is all a manager needs;
    # the SSH account is opt-in via --monitor-key / --monitor-key-file or --add-monitor
    step_install_packages
    detect_outbound_interface
    step_install_caddy
    step_wireguard_keys_config
    step_enable_ip_forward
    step_firewall_host
    step_selinux
    step_install_firewall
    step_start_wireguard
    step_install_peer_ctrl
    step_create_api_user
    step_install_monitor
    step_install_api_helper
    step_install_traffic_saver
    step_create_api_user
    step_api_npm_setup
    step_generate_token
    step_write_server_js
    step_create_systemd_service
    step_install_tools
    step_install_health_timer
    step_prepare_tls
    step_configure_caddy
    step_write_access_config
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
    for svc in wg-healthcheck.timer wg-healthcheck.service wg-traffic.timer wg-traffic.service wg-traffic-save.service \
               "$API_SERVICE" "wg-quick@${WG_INTERFACE}"; do
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
        rm -f "$WG_CONFIG" /etc/wireguard/server_private.key /etc/wireguard/server_public.key "$FW_OPTS" /etc/wireguard/suspended.list
        rmdir /etc/wireguard 2>/dev/null || true
        ok "Backup: $bk"
    fi
    rm -f /etc/sysctl.d/99-wireguard.conf

    say "[4/7] Removing API, helpers and units..."
    rm -rf "$API_DIR" "$API_ENV_DIR" /var/lib/wg-api
    [ -x "$FW_SCRIPT" ] && "$FW_SCRIPT" down 2>/dev/null || true
    rm -f "${BIN_DIR}/wg-api-helper" "${BIN_DIR}/wg-peer-ctrl.sh" "${BIN_DIR}/wg-healthcheck.sh" "${BIN_DIR}/vpn-doctor.sh" "$FW_SCRIPT"
    rm -f "/etc/systemd/system/${API_SERVICE}" /etc/systemd/system/wg-healthcheck.service /etc/systemd/system/wg-healthcheck.timer \
          /etc/systemd/system/wg-traffic.service /etc/systemd/system/wg-traffic.timer /etc/systemd/system/wg-traffic-save.service
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
        rm -rf "$TLS_DIR"
    fi
    local rm_pkgs="n"
    if [ "$ASSUME_YES" -ne 1 ]; then
        read -r -p "Also purge the packages (wireguard, wireguard-tools, caddy)? [y/N]: " rm_pkgs
    fi
    if [[ "$rm_pkgs" =~ ^[Yy]$ ]]; then
        case "$OS_FAMILY" in
            debian)
                pkg_remove wireguard wireguard-tools caddy || true
                rm -f /etc/apt/sources.list.d/caddy-stable.list /usr/share/keyrings/caddy-stable-archive-keyring.gpg ;;
            rhel)
                pkg_remove wireguard-tools caddy || true
                dnf copr remove -y @caddy/caddy >/dev/null 2>&1 || true ;;
            arch)
                pkg_remove wireguard-tools caddy || true ;;
        esac
    fi
    echo
    echo "Uninstall complete. IPv4 forwarding was left as is at runtime; reboot to clear it."
}

# ----------------------------- menu and entry point ---------------------------

# Usage: show_menu -> one-shot interactive menu (used when the script is started without arguments)
show_menu() {
    echo "========================================"
    echo "   WireGuard Server Installer ${SCRIPT_VERSION}"
    echo "========================================"
    echo "  1) Install WireGuard + HTTPS API + health tools"
    echo "  2) Uninstall"
    echo "  3) Add / repair the wg-monitor account"
    echo "  4) Update health tools (healthcheck, doctor)"
    echo "  5) Change the API HTTPS port / certificate (keeps WireGuard keys and peers)"
    echo "  6) Update the API and firewall to this version (keeps keys and peers)"
    echo "  0) Exit"
    local choice
    read -r -p "Choose [0-6]: " choice
    case "$choice" in
        1) install_all ;;
        2) uninstall ;;
        3) ask_monitor_key; step_install_peer_ctrl; step_install_monitor ;;
        4) step_install_peer_ctrl; step_install_tools ;;
        5) reconfigure_api ;;
        6) update_api ;;
        0) echo "Goodbye." ;;
        *) echo "Invalid choice." ;;
    esac
}

# Usage: main "$@"  -> entry point
main() {
    local argc=$#
    parse_args "$@"      # first, so --help works without root
    check_root
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
        reconfigure-api) reconfigure_api ;;
        update-api)   update_api ;;
        update-firewall) update_firewall ;;
        install)
            if [ "$argc" -eq 0 ] && is_tty; then show_menu; else install_all; fi
            ;;
    esac
}

# Set INSTALL_WG_SOURCE_ONLY=1 to source this file (for tests) without running it.
# main stays the last statement so `curl ... | bash` parses the whole script first.
[ -n "${INSTALL_WG_SOURCE_ONLY:-}" ] || main "$@"
