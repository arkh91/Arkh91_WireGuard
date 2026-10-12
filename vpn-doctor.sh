#!/bin/bash
# =============================================================================
# vpn-doctor.sh - investigate a VPN server, explain what is wrong, and suggest
# (or apply) the fix.
#
# Covers the stack built by install-wg3.sh and friends, auto-detected per server:
#   WireGuard (wg0) + wg-api (Caddy/Node) + Unbound DNS + GameDNS DoH
#   (nginx + certbot) + Outline (Docker)
#
# Modes:
#   sudo ./vpn-doctor.sh                  investigate, diagnose, print a fix plan (read-only)
#   sudo ./vpn-doctor.sh --fix            ...then offer each automatic fix (y/N, backups first)
#   sudo ./vpn-doctor.sh --fix --yes      apply every automatic fix without asking
#   sudo ./vpn-doctor.sh --fix --dry-run  show what --fix would do, change nothing
# Options:
#   --capture=20                sniff the tunnel for 20s while a client browses
#   --report=FILE               also save the report to FILE
#   --if=wg0 --net=10.66.66.0/24  override auto-detection
#   --no-color                  plain output
#
# Straight from GitHub:
#   bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/vpn-doctor.sh) --fix
#
# Safety: investigation is read-only. Fixes back up every file they touch to
# /root/vpn-doctor-backups/<time>/ and validate configs before installing them.
# Secrets (private keys, tokens) are never printed.
# Edit this script with: vi vpn-doctor.sh
# Exit code: 0 = no critical findings, 1 = critical findings remain, 2 = bad usage
# =============================================================================

set -u

# ----------------------------- settings ---------------------------------------
WG_IF=""; WG_NET=""; WG_IP=""; WG_PORT=""; WG_CONF=""; OUT_IFACE=""; PUB_IP=""
DO_FIX=0; ASSUME_YES=0; DRY=0; CAPTURE_SECS=0; REPORT=""; USE_COLOR=1; QUIET=0

# paths (overridable through the environment, mainly for testing)
WG_DIR="${WG_DIR:-/etc/wireguard}"
LE_DIR="${LE_DIR:-/etc/letsencrypt}"
NGINX_DIR="${NGINX_DIR:-/etc/nginx}"
CADDYFILE="${CADDYFILE:-/etc/caddy/Caddyfile}"
UNBOUND_DIR="${UNBOUND_DIR:-/etc/unbound}"
GAMEDNS_DIR="${GAMEDNS_DIR:-/var/lib/gamedns}"
SYSCTL_DIR="${SYSCTL_DIR:-/etc/sysctl.d}"
SYSCTL_CONF="${SYSCTL_CONF:-/etc/sysctl.conf}"
RESOLVED_DIR="${RESOLVED_DIR:-/etc/systemd/resolved.conf.d}"
RESOLV_CONF="${RESOLV_CONF:-/etc/resolv.conf}"
API_DIR="${API_DIR:-/opt/wg-api}"
OUTLINE_DIR="${OUTLINE_DIR:-/opt/outline}"
WEBROOT="${WEBROOT:-/var/www/certbot}"
BACKUP_ROOT="${BACKUP_ROOT:-/root/vpn-doctor-backups}"
BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"

# findings (parallel arrays) and state shared between checks
F_SEV=(); F_ID=(); F_TITLE=(); F_WHY=(); F_FIX=(); F_MANUAL=()
CNT_OK=0; FIX_DONE=" "; BOOT_TIME=""; AUTO_REBOOT=0; NGINX_T=""
ACTIVE_PEERS=0; PEERS_NODATA=0; PEERS_ONEWAY=0; RECHECK=0

# ----------------------------- output helpers ---------------------------------

# Usage: setup_colors   -> defines C_R/C_Y/C_G/C_B/C_0 (empty when colour is off or not a tty)
setup_colors() {
    if [ "$USE_COLOR" -eq 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_B=$'\e[1m'; C_0=$'\e[0m'
    else
        C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""
    fi
}

# Usage: section "Title"   -> prints a section header (hidden during the quiet re-check)
section() { [ "$QUIET" -eq 1 ] && return 0; printf '\n%s== %s ==%s\n' "$C_B" "$*" "$C_0"; }

# Usage: ok "message"      -> a passing check
ok() { CNT_OK=$((CNT_OK+1)); [ "$QUIET" -eq 1 ] && return 0; printf '  %s[ OK ]%s %s\n' "$C_G" "$C_0" "$*"; }

# Usage: info "message"    -> neutral detail line
info() { [ "$QUIET" -eq 1 ] && return 0; printf '         %s\n' "$*"; }

# Usage: have <command>    -> 0 if the command exists
have() { command -v "$1" >/dev/null 2>&1; }

# Usage: active <unit>     -> 0 if the systemd unit is active
active() { systemctl is-active --quiet "$1" 2>/dev/null; }

# Usage: unit_exists <unit> -> 0 if systemd knows the unit
unit_exists() { systemctl cat "$1" >/dev/null 2>&1; }

# Usage: owner_of <port>   -> names of the processes listening on that port (tcp or udp)
owner_of() { ss -H -lntup "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' '; }

# Usage: human <bytes>     -> 1.2MiB style size
human() { if have numfmt; then numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1}B"; else echo "${1}B"; fi; }

# Usage: has_finding <ID>  -> 0 if that finding was already recorded
has_finding() { local i; for i in "${F_ID[@]+"${F_ID[@]}"}"; do [ "$i" = "$1" ] && return 0; done; return 1; }

# Usage: has_any <ID> [ID...] -> 0 if any of the findings was recorded
has_any() { local id; for id in "$@"; do has_finding "$id" && return 0; done; return 1; }

# Usage: finding <crit|warn|info> <ID> <title> <why> <fix-function|-> <manual steps (\n = new line)>
#   Records a problem (printed immediately, summarised later in the fix plan).
finding() {
    local sev="$1" id="$2" tag col
    has_finding "$id" && return 0
    F_SEV+=("$sev"); F_ID+=("$id"); F_TITLE+=("$3"); F_WHY+=("$4"); F_FIX+=("$5"); F_MANUAL+=("$6")
    case "$sev" in crit) tag="FAIL"; col="$C_R" ;; warn) tag="WARN"; col="$C_Y" ;; *) tag="INFO"; col="$C_B" ;; esac
    printf '  %s[%s]%s %s\n' "$col" "$tag" "$C_0" "$3"
}

# Usage: count_sev <crit|warn|info>  -> number of findings of that severity
count_sev() { local n=0 s; for s in "${F_SEV[@]+"${F_SEV[@]}"}"; do [ "$s" = "$1" ] && n=$((n+1)); done; echo "$n"; }

# Usage: count_auto  -> number of findings that have an automatic fix
count_auto() { local n=0 f; for f in "${F_FIX[@]+"${F_FIX[@]}"}"; do [ "$f" != "-" ] && n=$((n+1)); done; echo "$n"; }

# ----------------------------- small utilities --------------------------------

# Usage: ip2int a.b.c.d    -> integer
ip2int() { local IFS=.; set -- $1; echo $(( ($1<<24) + ($2<<16) + ($3<<8) + $4 )); }

# Usage: int2ip <int>      -> a.b.c.d
int2ip() { echo "$(( ($1>>24)&255 )).$(( ($1>>16)&255 )).$(( ($1>>8)&255 )).$(( $1&255 ))"; }

# Usage: cidr_network 10.66.66.1/24 -> 10.66.66.0/24
cidr_network() {
    local ip="${1%/*}" p="${1#*/}" mask
    mask=$(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF ))
    echo "$(int2ip $(( $(ip2int "$ip") & mask )))/$p"
}

# Usage: cidr_overlap <cidr-a> <cidr-b>  -> 0 if the two networks overlap
cidr_overlap() {
    local a="${1%/*}" pa="${1#*/}" b="${2%/*}" pb="${2#*/}" p mask
    p=$pa; [ "$pb" -lt "$pa" ] && p=$pb
    mask=$(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF ))
    [ $(( $(ip2int "$a") & mask )) -eq $(( $(ip2int "$b") & mask )) ]
}

# Usage: persisted_forward_value -> last configured net.ipv4.ip_forward value ("" if none)
persisted_forward_value() {
    local f v="" l
    for f in /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf "$SYSCTL_DIR"/*.conf "$SYSCTL_CONF"; do
        [ -f "$f" ] || continue
        l=$(grep -E '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "$f" 2>/dev/null | tail -n1)
        [ -n "$l" ] && v=$(echo "$l" | sed 's/.*=[[:space:]]*//')
    done
    echo "$v"
}

# Usage: nginx_listen_ports -> unique ports from the loaded nginx config ($NGINX_T), one per line
nginx_listen_ports() {
    echo "$NGINX_T" | grep -E '^[[:space:]]*listen[[:space:]]' \
        | sed -E 's/^[[:space:]]*listen[[:space:]]+(\[::\]:|[0-9.*]+:)?([0-9]+).*/\2/' | grep -E '^[0-9]+$' | sort -un
}

# Usage: parse_args "$@"
parse_args() {
    local a
    for a in "$@"; do
        case "$a" in
            --fix)        DO_FIX=1 ;;
            --yes|-y)     ASSUME_YES=1 ;;
            --dry-run)    DRY=1 ;;
            --capture)    CAPTURE_SECS=15 ;;
            --capture=*)  CAPTURE_SECS="${a#*=}" ;;
            --report=*)   REPORT="${a#*=}"; USE_COLOR=0 ;;
            --if=*)       WG_IF="${a#*=}" ;;
            --net=*)      WG_NET="${a#*=}" ;;
            --no-color)   USE_COLOR=0 ;;
            -h|--help)    usage; exit 0 ;;
            *) echo "Unknown option: $a"; usage; exit 2 ;;
        esac
    done
    [[ "$CAPTURE_SECS" =~ ^[0-9]+$ ]] || { echo "--capture needs a number of seconds"; exit 2; }
    if [ "$DRY" -eq 1 ] && [ "$DO_FIX" -eq 0 ]; then DO_FIX=1; fi
}

# Usage: usage   -> prints the header comment as help
usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; }

# Usage: detect_env   -> fills WG_IF, WG_IP, WG_NET, WG_PORT, WG_CONF, OUT_IFACE, PUB_IP, BOOT_TIME
detect_env() {
    local addr route
    if [ -z "$WG_IF" ]; then WG_IF=$(wg show interfaces 2>/dev/null | awk '{print $1}'); fi
    if [ -z "$WG_IF" ]; then WG_IF=$(ls "$WG_DIR"/*.conf 2>/dev/null | head -n1 | sed 's|.*/||; s|\.conf$||'); fi
    [ -z "$WG_IF" ] && WG_IF="wg0"
    WG_CONF="$WG_DIR/$WG_IF.conf"
    addr=$(ip -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | head -n1)
    [ -z "$addr" ] && addr=$(sed -n 's/^Address[[:space:]]*=[[:space:]]*\([0-9./]*\).*/\1/p' "$WG_CONF" 2>/dev/null | head -n1)
    WG_IP="${addr%/*}"
    if [ -z "$WG_NET" ]; then
        if [ -n "$addr" ] && [[ "$addr" == */* ]]; then WG_NET=$(cidr_network "$addr"); else WG_NET="10.66.66.0/24"; fi
    fi
    WG_PORT=$(wg show "$WG_IF" listen-port 2>/dev/null)
    [ -z "$WG_PORT" ] && WG_PORT=$(sed -n 's/^ListenPort[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$WG_CONF" 2>/dev/null | head -n1)
    route=$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1)
    OUT_IFACE=$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<<"$route")
    PUB_IP=$(sed -n 's/.* src \([^ ]*\).*/\1/p' <<<"$route")
    [ -z "$OUT_IFACE" ] && OUT_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
    BOOT_TIME=$(uptime -s 2>/dev/null)
}

# ----------------------------- investigation ----------------------------------

# Usage: check_system   -> clock, last boot, automatic reboots (explains "it broke at 03:00")
check_system() {
    section "System"
    info "host $(hostname), $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-linux}" ), kernel $(uname -r)"
    [ -n "$BOOT_TIME" ] && info "last boot: $BOOT_TIME ($(uptime -p 2>/dev/null))"
    if have timedatectl; then
        if timedatectl 2>/dev/null | grep -qi 'synchronized: yes'; then ok "clock is NTP-synchronized"
        else finding warn SYS_CLOCK "System clock is not NTP-synchronized" "A drifting clock breaks WireGuard handshakes and TLS certificates." - "timedatectl set-ntp true"; fi
    fi
    if grep -rqsE '^[[:space:]]*Unattended-Upgrade::Automatic-Reboot[[:space:]]+"true"' /etc/apt/apt.conf.d/ 2>/dev/null; then
        AUTO_REBOOT=1
        info "automatic reboots after updates are ON: anything not persisted is wiped at each reboot"
    fi
}

# Usage: check_wireguard   -> tool, interface, service, MTU, config file, key consistency; returns 1 if the interface is down
check_wireguard() {
    section "WireGuard (${WG_IF})"
    if ! have wg; then
        finding crit WG_NOTOOL "wireguard-tools (wg) is not installed" "No WireGuard check can run without it." - "apt install -y wireguard"
        return 1
    fi
    local svc="wg-quick@${WG_IF}"
    if ! ip link show "$WG_IF" >/dev/null 2>&1; then
        local why; why=$(journalctl -u "$svc" -n 3 --no-pager 2>/dev/null | tail -n 3 | cut -c1-150 | tr '\n' ' ')
        finding crit WG_DOWN "WireGuard interface ${WG_IF} does not exist" "The tunnel is down, so no client can connect. Last log: ${why:-none}" fix_wg_up \
            "systemctl restart ${svc}\njournalctl -u ${svc} -n 30 --no-pager   # a broken ${WG_CONF} is the usual reason: wg-quick strip ${WG_CONF}"
        return 1
    fi
    ok "interface ${WG_IF} is up (address ${WG_IP:-?}, udp/${WG_PORT:-?})"
    if active "$svc"; then
        ok "${svc} is active"
        if ! systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            finding warn WG_NOT_ENABLED "${svc} is not enabled at boot" "The tunnel will not come back after a reboot." fix_enable_wg "systemctl enable ${svc}"
        fi
    else
        finding warn WG_SVC "${WG_IF} exists but ${svc} is not active" "The interface was brought up by hand; it will not return after a reboot." - "wg-quick down ${WG_IF} && systemctl enable --now ${svc}"
    fi

    local mtu out_mtu
    mtu=$(cat "/sys/class/net/${WG_IF}/mtu" 2>/dev/null); out_mtu=$(cat "/sys/class/net/${OUT_IFACE}/mtu" 2>/dev/null)
    info "MTU ${WG_IF}=${mtu:-?} ${OUT_IFACE:-?}=${out_mtu:-?}"
    if [ -n "$mtu" ] && [ -n "$out_mtu" ] && [ "$mtu" -gt $((out_mtu - 80)) ]; then
        finding warn WG_MTU "WireGuard MTU ($mtu) is too large for the uplink MTU ($out_mtu)" "Large packets stall: pages half-load while pings work." - "Set MTU = 1380 in the CLIENT [Interface], and in ${WG_CONF} (vi)"
    fi

    if [ ! -f "$WG_CONF" ]; then
        finding crit WG_NOCONF "${WG_CONF} is missing" "The tunnel cannot restart: the interface only exists in memory." - "Restore the file from a backup (the live config can be exported with: wg showconf ${WG_IF} > /root/${WG_IF}.recovered)"
        return 0
    fi
    local perm; perm=$(stat -c '%a' "$WG_CONF")
    [ "$perm" = "600" ] && ok "config permissions 600" || finding warn WG_PERMS "${WG_CONF} permissions are ${perm}" "The config holds the server private key." - "chmod 600 ${WG_CONF}"
    if wg-quick strip "$WG_CONF" >/dev/null 2>&1; then ok "config parses cleanly"
    else
        finding crit WG_CONF_BAD "${WG_CONF} does not parse" "wg-quick will fail at the next restart or reboot and the tunnel stays down. $(wg-quick strip "$WG_CONF" 2>&1 | head -n2 | tr '\n' ' ')" - "vi ${WG_CONF}   # repair, then: wg-quick strip ${WG_CONF} >/dev/null && echo OK"
    fi

    local live_pub api_pub
    live_pub=$(wg show "$WG_IF" public-key 2>/dev/null)
    api_pub=$(sed -n "s/^const SERVER_PUB = '\(.*\)';/\1/p" "$API_DIR/server.js" 2>/dev/null | head -n1)
    if [ -n "$api_pub" ]; then
        if [ "$api_pub" = "$live_pub" ]; then ok "wg-api hands out the correct server public key"
        else finding crit WG_API_KEY "wg-api embeds a different server public key than the live interface" "New client configs get a wrong key: handshake fails or traffic is dropped." - "vi ${API_DIR}/server.js   # set SERVER_PUB to ${live_pub}, then: systemctl restart wg-api"; fi
    fi
    return 0
}

# Usage: check_peers   -> per-peer handshake/traffic classification and file-vs-live drift
check_peers() {
    section "Peers"
    local now pub psk ep aips hs rx tx ka age n=0 active=0 idle=0 never=0 nodata=0 oneway=0
    now=$(date +%s)
    while IFS=$'\t' read -r pub psk ep aips hs rx tx ka; do
        [ -z "$pub" ] && continue
        n=$((n+1))
        if [ "${hs:-0}" -eq 0 ]; then never=$((never+1)); continue; fi
        age=$((now - hs))
        if [ "$age" -le 180 ]; then
            active=$((active+1))
            info "active: ${aips} via ${ep}, handshake ${age}s ago, rx=$(human "$rx") tx=$(human "$tx")"
            if [ $((rx + tx)) -lt 4096 ]; then nodata=$((nodata+1))
            elif [ "$rx" -gt 0 ] && [ "$tx" -eq 0 ]; then oneway=$((oneway+1)); fi
        else idle=$((idle+1)); fi
    done < <(wg show "$WG_IF" dump 2>/dev/null | tail -n +2)
    ACTIVE_PEERS=$active; PEERS_NODATA=$nodata; PEERS_ONEWAY=$oneway
    ok "${n} peers: ${active} active (handshake < 3 min), ${idle} idle, ${never} never connected"
    if [ "$active" -eq 0 ]; then
        info "no client is connected right now: connect one and re-run (add --capture=20) for a live data-path test"
    fi

    [ -f "$WG_CONF" ] || return 0
    local file_keys live_keys k only_file="" only_live="" ips
    file_keys=$(sed -n 's/^PublicKey[[:space:]]*=[[:space:]]*//p' "$WG_CONF" | sort -u)
    live_keys=$(wg show "$WG_IF" peers 2>/dev/null | sort -u)
    for k in $file_keys; do grep -qxF "$k" <<<"$live_keys" || only_file="$only_file $k"; done
    for k in $live_keys; do grep -qxF "$k" <<<"$file_keys" || only_live="$only_live $k"; done
    if [ -n "$only_file" ]; then
        ips=$(awk '/^\[Peer\]/{k="";next} /^PublicKey/{sub(/^PublicKey[ \t]*=[ \t]*/,"");k=$0} /^AllowedIPs/{sub(/^AllowedIPs[ \t]*=[ \t]*/,"");if(k!="")print k"\t"$0}' "$WG_CONF" \
            | while IFS=$'\t' read -r key ip; do case " $only_file " in *" $key "*) printf '%s ' "$ip" ;; esac; done)
        finding warn WG_PEERS_FILE_ONLY "$(wc -w <<<"$only_file") peer(s) are in ${WG_IF}.conf but not on the live interface (${ips% })" \
            "They come back live at the next restart/reboot and their IPs stay reserved in wg-api. Usually leftovers of removed clients." \
            - "cp ${WG_CONF} ${WG_CONF}.bak\nvi ${WG_CONF}   # delete their [Peer] blocks if those clients were removed"
    fi
    if [ -n "$only_live" ]; then
        finding warn WG_PEERS_LIVE_ONLY "$(wc -w <<<"$only_live") live peer(s) are not saved in ${WG_IF}.conf" \
            "They vanish at the next restart/reboot and those clients lose access." \
            - "wg show ${WG_IF} allowed-ips   # then add a [Peer] block (PublicKey, AllowedIPs) for each missing one with vi ${WG_CONF}"
    fi
    [ -z "$only_file$only_live" ] && ok "peers in the file and on the live interface match"
    local dups; dups=$(wg show "$WG_IF" allowed-ips 2>/dev/null | cut -f2 | tr ' ' '\n' | grep -v '^$' | sort | uniq -d | tr '\n' ' ')
    [ -n "$dups" ] && finding crit WG_DUP_IP "Duplicate AllowedIPs on live peers: ${dups}" "Two clients claim one address; traffic goes to the wrong one." - "wg show ${WG_IF} allowed-ips   # remove one: wg set ${WG_IF} peer <pubkey> remove, and fix ${WG_CONF} with vi"
    return 0
}

# Usage: check_forwarding   -> runtime and persistent net.ipv4.ip_forward
check_forwarding() {
    section "IP forwarding"
    local rt pv; rt=$(sysctl -n net.ipv4.ip_forward 2>/dev/null); pv=$(persisted_forward_value)
    if [ "$rt" = "1" ]; then ok "net.ipv4.ip_forward = 1"
    else finding crit FWD_OFF "IP forwarding is off (net.ipv4.ip_forward=${rt:-?})" "The server will not route client traffic: classic 'handshake works, no internet'." fix_ip_forward \
        "sysctl -w net.ipv4.ip_forward=1\necho 'net.ipv4.ip_forward=1' > ${SYSCTL_DIR}/99-wireguard.conf && sysctl --system"; fi
    if [ "$pv" = "1" ]; then ok "ip_forward=1 is persisted"
    else finding warn FWD_NOT_PERSISTED "IP forwarding is not persisted (config says '${pv:-nothing}')" "A reboot can reset it and break the VPN." fix_ip_forward \
        "echo 'net.ipv4.ip_forward=1' > ${SYSCTL_DIR}/99-wireguard.conf && sysctl --system"; fi
}

# Usage: check_nat_firewall   -> NAT rule vs uplink, persistence across reboot, FORWARD chain, ufw/Docker, live egress test
check_nat_firewall() {
    section "NAT, firewall and routing"
    if ! have iptables; then
        if have nft && nft list ruleset 2>/dev/null | grep -q masquerade; then ok "NAT is handled by nftables"
        else finding warn FW_NOIPT "iptables is not installed and no nftables masquerade rule was found" "Clients cannot reach the internet without NAT." - "apt install -y iptables"; fi
        return 0
    fi
    info "backend: $(iptables -V 2>&1)"
    if have iptables-legacy && have iptables-nft; then
        local l n; l=$(iptables-legacy -S 2>/dev/null | grep -c '^-A'); n=$(iptables-nft -S 2>/dev/null | grep -c '^-A')
        if [ "$l" -gt 0 ] && [ "$n" -gt 0 ]; then
            finding warn FW_SPLIT "Firewall rules exist in both iptables-legacy ($l) and iptables-nft ($n)" "Rules may be split between two backends so some are not applied as expected." - "iptables-legacy -S; iptables-nft -S   # keep one backend (update-alternatives --config iptables)"
        fi
    fi

    # --- is the VPN subnet masqueraded, and how
    local nat line good=0 wrong="" broad="" re=' -o ([^ ]+)'
    nat=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep -E -- '-j (MASQUERADE|SNAT)')
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        case "$line" in *" -s ${WG_NET} "*) ;; *" -s "*) continue ;; esac
        if [[ "$line" == *" ! -d "* ]]; then good=1
        elif [[ "$line" =~ $re ]]; then
            if [ "${BASH_REMATCH[1]}" = "$OUT_IFACE" ]; then good=1; else wrong="$line"; fi
        else broad="$line"; fi
    done <<<"$nat"
    if [ "$good" -eq 1 ]; then ok "NAT: ${WG_NET} is masqueraded"
    elif [ -n "$broad" ]; then
        finding warn NAT_BROAD "The NAT rule for ${WG_NET} has no interface and no '! -d ${WG_NET}'" \
            "It also matches the server's own traffic to ${WG_IP:-the VPN address} over loopback, which MASQUERADE drops: the server cannot query its own DNS/services on that address." fix_nat \
            "iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE\niptables -t nat -D POSTROUTING -s ${WG_NET} -j MASQUERADE\nvi ${WG_CONF}   # same change in PostUp/PostDown"
    elif [ -n "$wrong" ]; then
        finding crit NAT_WRONG_IF "The NAT rule for ${WG_NET} is bound to a different interface than the uplink (${OUT_IFACE})" \
            "Traffic leaves via ${OUT_IFACE} without being translated, so replies never come back (rule: ${wrong#-A POSTROUTING })." fix_nat \
            "iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE\nvi ${WG_CONF}   # PostUp/PostDown with the same rule"
    elif have nft && nft list ruleset 2>/dev/null | grep -q masquerade; then
        ok "NAT is handled by a native nftables masquerade rule"
    else
        finding crit NAT_MISSING "No NAT (MASQUERADE) rule exists for ${WG_NET}" \
            "Clients connect (handshake) but their packets leave with a private source address and no reply returns: no internet." fix_nat \
            "iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE\nvi ${WG_CONF}   # add PostUp/PostDown so it survives reboots"
    fi
    local hits; hits=$(iptables -t nat -L POSTROUTING -n -v -x 2>/dev/null | awk -v p="${WG_NET%.*}." '$3=="MASQUERADE" && index($8,p)==1 {s+=$1} END{print s+0}')
    info "NAT rule hit counter: ${hits} packets"

    # --- does the NAT rule survive a reboot?
    local persist=0 hook_broad=0
    if grep -qE '^PostUp[[:space:]]*=.*(MASQUERADE|SNAT)' "$WG_CONF" 2>/dev/null; then
        persist=1
        grep -E '^PostUp[[:space:]]*=.*MASQUERADE' "$WG_CONF" | grep -qvE '! -d | -o ' && hook_broad=1
    elif have netfilter-persistent && systemctl is-enabled --quiet netfilter-persistent 2>/dev/null \
         && grep -qs "MASQUERADE" /etc/iptables/rules.v4 && grep -s MASQUERADE /etc/iptables/rules.v4 | grep -qF -- "${WG_NET%.*}."; then
        persist=1
    fi
    if [ "$persist" -eq 1 ]; then ok "NAT rule is re-applied at boot"
    else
        finding warn NAT_NOT_PERSISTENT "Nothing re-applies the NAT rule at boot (no PostUp, netfilter-persistent missing or disabled)" \
            "The rule lives only in memory: the next reboot${BOOT_TIME:+ (last one: $BOOT_TIME)} wipes it and the VPN loses internet again.$([ "$AUTO_REBOOT" -eq 1 ] && echo ' Automatic reboots are enabled on this server.')" fix_nat \
            "vi ${WG_CONF}   # under [Interface] add:\nPostUp = iptables -t nat -C POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE\nPostDown = iptables -t nat -D POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE 2>/dev/null || true"
    fi
    if [ "$hook_broad" -eq 1 ]; then
        finding warn NAT_HOOK_BROAD "PostUp in ${WG_IF}.conf creates the broad NAT rule (no '! -d ${WG_NET}')" "After the next boot the server's own queries to ${WG_IP:-the VPN address} will time out." fix_nat \
            "vi ${WG_CONF}   # in PostUp/PostDown use: -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE"
    fi

    # --- live egress test through NAT
    if [ -n "$WG_IP" ] && have ping; then
        if ping -c2 -W2 -I "$WG_IP" 1.1.1.1 >/dev/null 2>&1; then ok "ping 1.1.1.1 sourced from ${WG_IP} works (NAT + uplink)"
        elif has_any NAT_MISSING NAT_WRONG_IF; then info "egress test from ${WG_IP} fails, as expected without a working NAT rule"
        elif ping -c2 -W2 1.1.1.1 >/dev/null 2>&1; then
            finding warn NAT_TEST "The server reaches 1.1.1.1 but not when sourced from ${WG_IP}" "NAT may not match, or ICMP from the VPN address is filtered." - "tcpdump -ni ${OUT_IFACE:-eth0} icmp   # run ping -I ${WG_IP} 1.1.1.1 in another shell"
        else
            finding crit EGRESS "The server itself cannot reach the internet" "No client can browse through a server without connectivity. Check the provider network/firewall (ICMP may also be filtered)." - "ip route; ping -c2 1.1.1.1; check the provider's cloud firewall"
        fi
    fi

    # --- FORWARD chain, ufw, Docker
    local policy rules chain="FORWARD" in_ok=0 out_ok=0
    policy=$(iptables -S FORWARD 2>/dev/null | awk '/^-P FORWARD/{print $3}')
    rules=$(iptables -S FORWARD 2>/dev/null; iptables -S DOCKER-USER 2>/dev/null)
    grep -qE -- "-i ${WG_IF} .*-j ACCEPT" <<<"$rules" && in_ok=1
    grep -qE -- "-o ${WG_IF} .*-j ACCEPT" <<<"$rules" && out_ok=1
    if [ "$policy" = "DROP" ] && { [ $in_ok -eq 0 ] || [ $out_ok -eq 0 ]; }; then
        finding crit FWD_DROP "FORWARD policy is DROP and there is no ACCEPT rule for ${WG_IF}" "Docker (or a firewall tool) blocks routed traffic: the VPN carries nothing." fix_forward_rules \
            "iptables -S DOCKER-USER >/dev/null 2>&1 && C=DOCKER-USER || C=FORWARD\niptables -I \$C 1 -i ${WG_IF} -j ACCEPT; iptables -I \$C 2 -o ${WG_IF} -j ACCEPT\nvi ${WG_CONF}   # same rules in PostUp/PostDown to persist"
    else ok "FORWARD policy ${policy:-?}: routed VPN traffic is allowed"; fi
    if grep -E '^-A FORWARD ' <<<"$rules" | grep -qE -- '-j (DROP|REJECT)'; then
        finding warn FWD_BLOCK_RULE "A DROP/REJECT rule exists directly in the FORWARD chain" "It may block VPN traffic depending on its position." - "iptables -S FORWARD   # review it; insert the wg ACCEPT rules above it"
    fi
    if have ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        finding warn FW_UFW "ufw is active" "ufw drops forwarded traffic and unlisted ports by default: WireGuard, DNS and DoH need explicit rules." - \
            "ufw allow ${WG_PORT:-<wg-port>}/udp; ufw allow 53; ufw route allow in on ${WG_IF}\nvi /etc/default/ufw   # DEFAULT_FORWARD_POLICY=\"ACCEPT\""
    fi
    return 0
}

# Usage: check_datapath   -> turns the "handshake but no data" symptom into a finding only when no server-side cause explains it
check_datapath() {
    [ "${ACTIVE_PEERS:-0}" -gt 0 ] || return 0
    section "Data path"
    if [ "$RECHECK" -eq 1 ]; then
        info "byte counters still include the time before the fixes: connect a client now and re-run to confirm the data path (add --capture=20)"
        return 0
    fi
    if [ "$PEERS_NODATA" -eq "$ACTIVE_PEERS" ]; then
        if has_any NAT_MISSING NAT_WRONG_IF FWD_OFF FWD_DROP; then
            info "active clients complete the handshake but almost no data flows: explained by the finding(s) above"
        else
            finding crit WG_NO_DATA "Clients complete the handshake but almost no data flows (${PEERS_NODATA}/${ACTIVE_PEERS} active peers)" \
                "The server side looks fine (NAT and forwarding are in place), so suspect the client: its Address must equal the peer's AllowedIPs/32 on the server, plus DNS and MTU." \
                - "Compare the client's Address with: wg show ${WG_IF} allowed-ips\nTry MTU = 1380 in the client [Interface]\nRe-run with --capture=20 while the client browses to see which side drops traffic"
        fi
    elif [ "$PEERS_ONEWAY" -gt 0 ]; then
        finding warn WG_ONE_WAY "${PEERS_ONEWAY} active peer(s) send data but receive nothing back" "Replies are dropped on the server: NAT, FORWARD policy or egress filtering." - "Check the NAT/firewall findings; test with --capture=20."
    else
        ok "traffic flows for the active peers"
    fi
}

# Usage: check_dns   -> Unbound state, port 53 owner, resolved clash, answers, open-resolver exposure
check_dns() {
    section "DNS (Unbound)"
    local owners; owners=$(owner_of 53)
    if ! unit_exists unbound && [ -z "$owners" ]; then info "no DNS service on this server (skipping)"; return 0; fi

    if unit_exists unbound; then
        if active unbound; then ok "unbound is active"
        else
            local why; why=$(journalctl -u unbound -n 20 --no-pager 2>/dev/null | grep -iE 'address already in use|cannot|error|fatal|failed' | tail -n 2 | cut -c1-150 | tr '\n' ' ')
            if [[ "$owners" == *systemd-resolve* ]]; then
                finding crit DNS_PORT_CLASH "Unbound is down because systemd-resolved holds port 53" "Unbound wants 0.0.0.0:53 but the resolved stub occupies 127.0.0.53:53. ${why}" fix_resolved_stub \
                    "mkdir -p ${RESOLVED_DIR} && printf '[Resolve]\\\\nDNSStubListener=no\\\\n' > ${RESOLVED_DIR}/nostub.conf\nsystemctl restart systemd-resolved && systemctl restart unbound"
            else
                finding crit DNS_DOWN "Unbound is not running" "DNS for clients on this server is down. ${why}" - "unbound-checkconf\njournalctl -u unbound -n 30 --no-pager\nsystemctl restart unbound"
            fi
            return 0
        fi
        if have unbound-checkconf; then
            unbound-checkconf >/dev/null 2>&1 && ok "unbound config is valid" \
                || finding crit DNS_CONF "unbound-checkconf reports errors" "Unbound will not start after its next restart. $(unbound-checkconf 2>&1 | head -n2 | tr '\n' ' ')" - "vi ${UNBOUND_DIR}/unbound.conf   # fix the error, then: unbound-checkconf && systemctl restart unbound"
        fi
    fi

    if have dig; then
        if dig +time=3 +tries=2 +short @127.0.0.1 cloudflare.com A 2>/dev/null | grep -qE '^[0-9]'; then ok "DNS answers on 127.0.0.1"
        else
            local up="upstream resolvers reachable"
            dig +time=3 +tries=1 +short @1.1.1.1 cloudflare.com A 2>/dev/null | grep -qE '^[0-9]' || up="the server cannot reach upstream resolvers (1.1.1.1) either"
            finding crit DNS_NO_ANSWER "Unbound does not answer on 127.0.0.1" "Service is up but resolution fails; ${up}." - "journalctl -u unbound -n 30 --no-pager; unbound-checkconf; systemctl restart unbound"
        fi
        if [ -n "$WG_IP" ]; then
            if dig +time=3 +tries=2 +short @"$WG_IP" cloudflare.com A 2>/dev/null | grep -qE '^[0-9]'; then ok "DNS answers on the VPN address ${WG_IP}"
            else
                local cause="Unbound may not listen on ${WG_IP} (interface: lines) or its access-control excludes ${WG_NET}."
                has_any NAT_BROAD NAT_HOOK_BROAD && cause="This is the broad NAT rule dropping loopback traffic to ${WG_IP} (see the NAT finding)."
                finding warn DNS_WG_NO_ANSWER "No DNS answer from ${WG_IP}:53 (server-side test)" "Clients using ${WG_IP} as DNS would fail. ${cause}" - "dig @${WG_IP} cloudflare.com +time=3   # after the NAT fix; then check interface: / access-control: in ${UNBOUND_DIR}/unbound.conf with vi"
            fi
        fi
        if [ -n "$PUB_IP" ] && dig +time=2 +tries=1 +short @"$PUB_IP" cloudflare.com A 2>/dev/null | grep -qE '^[0-9]' \
           && grep -qsE '^[[:space:]]*access-control:[[:space:]]*0\.0\.0\.0/0[[:space:]]+allow' "$UNBOUND_DIR"/unbound.conf "$UNBOUND_DIR"/unbound.conf.d/*.conf; then
            finding warn DNS_OPEN "Unbound is an open resolver on the public address ${PUB_IP}" \
                "Anyone on the internet can use it (DNS amplification attacks); providers often send abuse notices or block port 53." - \
                "vi ${UNBOUND_DIR}/unbound.conf   # replace 'access-control: 0.0.0.0/0 allow' with:\naccess-control: 127.0.0.0/8 allow\naccess-control: ${WG_NET} allow\n# (plus your own client IPs), then: unbound-checkconf && systemctl restart unbound"
        fi
    else
        info "dig is not installed (apt install -y dnsutils) so DNS answers were not tested"
    fi
}

# Usage: check_web_doh   -> Caddy, nginx, GameDNS DoH service/ports/certs/domain, certbot renewal method
check_web_doh() {
    section "Web stack: Caddy, nginx, GameDNS DoH, certbot"
    local has_caddy=0 has_nginx=0 has_doh=0 caddy_owns80=0
    unit_exists caddy && has_caddy=1
    unit_exists nginx && has_nginx=1
    unit_exists gamedns-doh && has_doh=1
    if [ $has_caddy -eq 0 ] && [ $has_nginx -eq 0 ] && [ $has_doh -eq 0 ]; then info "none installed (skipping)"; return 0; fi
    owner_of 80 | grep -q caddy && caddy_owns80=1

    if [ $has_caddy -eq 1 ]; then
        if active caddy; then ok "caddy is active (443: $(owner_of 443))"
        else finding crit CADDY_DOWN "Caddy is not running" "wg-api HTTPS (client provisioning) and certificate challenges are down." fix_restart_caddy "caddy validate --config ${CADDYFILE}\nsystemctl restart caddy; journalctl -u caddy -n 30 --no-pager"; fi
    fi

    local doh_ports=""
    if [ $has_nginx -eq 1 ] && have nginx; then
        NGINX_T=$(nginx -T 2>/dev/null)
        local nstate conf_ok=1 clash sev
        nstate=$(systemctl is-active nginx 2>/dev/null)
        nginx -t >/dev/null 2>&1 || conf_ok=0
        clash=$(nginx_listen_ports | grep -xE '80|443' | tr '\n' ' ')
        doh_ports=$(nginx_listen_ports | grep -vxE '80|443')
        if [ $conf_ok -eq 0 ]; then
            finding crit NGINX_CONF "nginx configuration test fails" "nginx cannot (re)start with a broken config: $(nginx -t 2>&1 | head -n2 | tr '\n' ' ')" - "nginx -t   # fix the file it names with vi, then: systemctl restart nginx"
        elif [ -n "$clash" ] && [ $caddy_owns80 -eq 1 ]; then
            sev=warn; [ "$nstate" != "active" ] && sev=crit
            finding $sev NGINX_PORT_CLASH "nginx is configured to listen on port(s) ${clash% } which Caddy owns" \
                "nginx cannot start while another server holds its ports, so everything it serves (the DoH and admin ports) is down. Typical source: the default site edited by certbot --nginx." fix_nginx_clash \
                "mv ${NGINX_DIR}/sites-enabled/default /root/nginx-default.disabled   # or edit the file that has 'listen 80/443' with vi\nnginx -t && systemctl restart nginx"
        elif [ "$nstate" != "active" ]; then
            finding crit NGINX_DOWN "nginx is ${nstate}" "The DoH/admin ports it serves are closed. $(journalctl -u nginx -n 4 --no-pager 2>/dev/null | tail -n 2 | cut -c1-140 | tr '\n' ' ')" fix_restart_nginx "journalctl -u nginx -n 30 --no-pager; systemctl restart nginx"
        else
            ok "nginx is active (ports: $(echo $doh_ports))"
        fi
    fi

    if [ $has_doh -eq 1 ]; then
        if active gamedns-doh; then ok "gamedns-doh service is active"
        else finding crit DOH_DOWN "gamedns-doh service is not running" "The DoH backend is down: nginx has nothing to forward to. $(journalctl -u gamedns-doh -n 3 --no-pager 2>/dev/null | tail -n 2 | cut -c1-140 | tr '\n' ' ')" fix_restart_doh "journalctl -u gamedns-doh -n 50 --no-pager; systemctl restart gamedns-doh"; fi
        local d p code
        d=$(echo "$NGINX_T" | sed -n 's/^[[:space:]]*server_name[[:space:]]\+\(.*\);.*/\1/p' | tr -s ' ' '\n' | grep -vE '^(_|localhost|)$' | head -n1)
        for p in $doh_ports; do
            if [ -n "$(owner_of "$p")" ]; then
                ok "port $p is listening ($(owner_of "$p"))"
                if have curl && [ -n "$d" ]; then
                    code=$(curl -sk -m 5 --resolve "${d}:${p}:127.0.0.1" -o /dev/null -w '%{http_code}' "https://${d}:${p}/" 2>/dev/null)
                    [ "${code:-000}" = "000" ] && finding crit DOH_TLS "HTTPS on port $p does not answer locally" "The port is open but the TLS/proxy layer fails: check the certificate paths and the gamedns-doh service." - "curl -skv https://${d}:${p}/ 2>&1 | tail -n 15\nnginx -t"
                fi
            elif [ "$(systemctl is-active nginx 2>/dev/null)" = "active" ]; then
                finding crit DOH_PORT_CLOSED "Nothing listens on port $p although nginx is running" "Connections to $p are refused ('curl: (7) Failed to connect')." - "nginx -T | grep -n 'listen'; systemctl restart nginx"
            fi
        done
        if [ -n "$d" ]; then
            local r; r=$(getent ahostsv4 "$d" 2>/dev/null | awk 'NR==1{print $1}')
            if [ -z "$r" ]; then finding crit DOH_DNS "The DoH domain ${d} does not resolve" "Customers cannot reach the service by name." - "Create an A record for ${d} -> ${PUB_IP:-this server}"
            elif [ "$r" = "$PUB_IP" ] || ip -4 -o addr 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qxF "$r"; then ok "${d} resolves to this server (${r})"
            else finding warn DOH_DNS "${d} resolves to ${r}, which is not this server (${PUB_IP:-?})" "Customers reach a different machine (wrong A record, or a proxy such as Cloudflare in front)." - "Point the A record of ${d} to ${PUB_IP:-this server} (DNS only, no proxy)"; fi
        fi
        if [ -f "$GAMEDNS_DIR/keys.json" ]; then
            info "key store: ${GAMEDNS_DIR}/keys.json$(have jq && echo " ($(jq 'length' "$GAMEDNS_DIR/keys.json" 2>/dev/null) entries)") - never re-run the installer without backing it up"
        fi
        if echo "$doh_ports" | grep -qx 11112; then
            finding info DOH_ADMIN_OPEN "The admin API (11112) is reachable from the whole internet" "Only the bearer token protects /create and /remove; if it leaked (pasted in a chat/log) anyone can mint or delete keys." - \
                "vi ${NGINX_DIR}/conf.d/gamedns-doh.conf   # in the 11112 server block add: allow <your-management-ip>; deny all;\nRotate the token if it was ever shared, then: systemctl restart gamedns-doh"
        fi
    fi

    # certificates used by nginx
    if [ -n "$NGINX_T" ]; then
        local c end days
        for c in $(echo "$NGINX_T" | sed -n 's/^[[:space:]]*ssl_certificate[[:space:]]\+\([^;]*\);.*/\1/p' | sort -u); do
            if [ ! -f "$c" ]; then finding crit CERT_MISSING "nginx references a certificate that does not exist: $c" "nginx cannot start with a missing certificate file." - "certbot certificates   # then re-issue the missing certificate"
            elif have openssl; then
                end=$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)
                days=$(( ( $(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
                if [ "$days" -lt 0 ]; then finding crit CERT_EXPIRED "Certificate expired: $c" "Clients refuse the TLS connection." fix_certbot_webroot "certbot renew --force-renewal   # after fixing the renewal method"
                elif [ "$days" -lt 14 ]; then finding warn CERT_SOON "Certificate expires in ${days} days: $c" "Renewal should have happened already: check the renewal method." fix_certbot_webroot "certbot renew --dry-run"
                else ok "certificate valid for ${days} more days ($(basename "$(dirname "$c")"))"; fi
            fi
        done
    fi

    # certbot renewal method and hooks
    local rf a name nonweb=0
    for rf in "$LE_DIR"/renewal/*.conf; do
        [ -f "$rf" ] || continue
        a=$(sed -n 's/^authenticator[[:space:]]*=[[:space:]]*//p' "$rf" | head -n1)
        name=$(basename "$rf" .conf)
        if [ "$a" = "webroot" ]; then ok "certbot renews ${name} via webroot"
        elif [ $caddy_owns80 -eq 1 ] && { [ "$a" = "nginx" ] || [ "$a" = "standalone" ]; }; then
            nonweb=1
            finding warn CERT_RENEW_BROKEN "certbot renews ${name} via '${a}' but Caddy owns port 80" \
                "The HTTP-01 challenge needs port 80. The next renewal fails and DoH breaks when the certificate expires." fix_certbot_webroot \
                "Add to ${CADDYFILE} (vi):\nhttp://${name} {\n    handle /.well-known/acme-challenge/* {\n        root * ${WEBROOT}\n        file_server\n    }\n    handle {\n        redir https://{host}{uri} permanent\n    }\n}\nmkdir -p ${WEBROOT}; caddy validate --config ${CADDYFILE} && systemctl reload caddy\ncertbot reconfigure --cert-name ${name} --authenticator webroot --webroot-path ${WEBROOT}\ncertbot renew --dry-run"
        fi
    done
    if [ -d "$LE_DIR/renewal" ] && ls "$LE_DIR"/renewal/*.conf >/dev/null 2>&1; then
        if systemctl is-active --quiet certbot.timer 2>/dev/null || systemctl is-active --quiet snap.certbot.renew.timer 2>/dev/null; then ok "certbot renewal timer is active"
        else finding warn CERTBOT_TIMER "No certbot renewal timer is active" "Certificates will not renew automatically." fix_certbot_timer "systemctl enable --now certbot.timer"; fi
        if [ -z "$(ls -A "$LE_DIR/renewal-hooks/deploy" 2>/dev/null)" ] && [ $has_nginx -eq 1 ]; then
            finding warn CERT_NO_HOOK "No certbot deploy hook reloads nginx after renewal" "nginx keeps serving the old certificate until it is reloaded." fix_deploy_hook \
                "printf '#!/bin/sh\\\\nsystemctl reload nginx\\\\n' > ${LE_DIR}/renewal-hooks/deploy/reload-nginx.sh && chmod +x ${LE_DIR}/renewal-hooks/deploy/reload-nginx.sh"
        fi
    fi
    return 0
}

# Usage: check_outline   -> Docker/Outline state, port collisions with WireGuard and DoH, subnet overlap
check_outline() {
    section "Docker / Outline"
    if ! have docker || ! active docker; then info "Docker is not running (skipping)"; return 0; fi
    local ps; ps=$(docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null)
    if grep -qE '^shadowbox\|' <<<"$ps"; then
        if grep -E '^shadowbox\|' <<<"$ps" | grep -q '|Up'; then ok "Outline (shadowbox) is running"
        else finding crit OUTLINE_DOWN "Outline (shadowbox) container is not running" "Outline users cannot connect." fix_start_outline "docker start shadowbox; docker logs shadowbox --tail 30"; fi
    else info "no Outline container found"; fi
    if grep -E '^watchtower\|' <<<"$ps" | grep -q 'Restarting'; then
        finding info OUTLINE_WATCHTOWER "The watchtower container is crash-looping" "It is Outline's auto-updater; it does not affect traffic but Outline never updates. Often an outdated image versus a newer Docker." - "docker logs watchtower --tail 10"
    fi

    local oport oapi
    oport=$(grep -oE '"portForNewAccessKeys"[[:space:]]*:[[:space:]]*[0-9]+' "$OUTLINE_DIR/persisted-state/shadowbox_server_config.json" 2>/dev/null | grep -oE '[0-9]+$')
    oapi=$(grep -oE 'apiUrl:https?://[^:]+:[0-9]+' "$OUTLINE_DIR/access.txt" 2>/dev/null | grep -oE '[0-9]+$')
    if [ -n "$oport" ]; then
        info "Outline access-key port ${oport}${oapi:+, management API ${oapi}}"
        if [ "$oport" = "$WG_PORT" ]; then finding crit OUTLINE_PORT "Outline and WireGuard use the same port ($oport)" "Only one of them can own it." - "Change one of the two ports (WireGuard: ListenPort in ${WG_CONF} with vi)"; fi
    fi
    local s overlap=""
    for s in $(docker network inspect $(docker network ls -q 2>/dev/null) -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null); do
        [[ "$s" == */* ]] && [[ "$s" != *:* ]] && cidr_overlap "$s" "$WG_NET" && overlap="$overlap $s"
    done
    if [ -n "$overlap" ]; then finding crit DOCKER_OVERLAP "A Docker network overlaps the VPN subnet:${overlap}" "Routing between them is ambiguous; VPN traffic can be swallowed by the Docker bridge." - "Change the Docker bridge subnet (/etc/docker/daemon.json with vi, then restart docker) or the VPN subnet"
    else ok "no Docker network overlaps ${WG_NET}"; fi
    return 0
}

# Usage: check_security   -> cheap hygiene hints (SSH password login as root)
check_security() {
    section "Security hints"
    if have sshd; then
        local s; s=$(sshd -T 2>/dev/null)
        if grep -qi '^passwordauthentication yes' <<<"$s" && grep -qi '^permitrootlogin yes' <<<"$s"; then
            finding info SSH_ROOT_PASSWORD "SSH allows root login with a password" "Public servers are brute-forced constantly; one weak password hands over the VPN and the DoH keys." - \
                "Install your SSH key first (ssh-copy-id), keep a second session open, then:\nvi /etc/ssh/sshd_config   # PermitRootLogin prohibit-password / PasswordAuthentication no\n# also check /etc/ssh/sshd_config.d/*.conf (cloud-init often re-enables passwords)\nsshd -t && systemctl reload ssh"
        else ok "SSH root password login is not enabled"; fi
    fi
}

# Usage: run_capture   -> sniff the tunnel for CAPTURE_SECS and say which side drops traffic
run_capture() {
    [ "$CAPTURE_SECS" -le 0 ] && return 0
    section "Live capture (${CAPTURE_SECS}s)"
    if ! have tcpdump; then finding warn CAP_TOOL "tcpdump is not installed" "The live capture needs it." - "apt install -y tcpdump"; return 0; fi
    local fi_ fo_ fl_ cin cout cleak
    fi_=$(mktemp); fo_=$(mktemp); fl_=$(mktemp)
    info ">>> generate traffic on a CLIENT now (ping 1.1.1.1, open a website)..."
    timeout "$CAPTURE_SECS" tcpdump -l -n -q -i "$WG_IF" -Q in  >"$fi_" 2>/dev/null &
    timeout "$CAPTURE_SECS" tcpdump -l -n -q -i "$WG_IF" -Q out >"$fo_" 2>/dev/null &
    timeout "$CAPTURE_SECS" tcpdump -l -n -q -i "${OUT_IFACE:-any}" -Q out "src net ${WG_NET}" >"$fl_" 2>/dev/null &
    wait
    cin=$(grep -cE ' IP6? ' "$fi_"); cout=$(grep -cE ' IP6? ' "$fo_"); cleak=$(grep -cE ' IP6? ' "$fl_")
    info "from clients into ${WG_IF}: ${cin}   back out to clients: ${cout}   un-NATed on ${OUT_IFACE}: ${cleak}"
    if [ "$cin" -eq 0 ]; then finding crit CAP_NO_IN "No client packets arrive inside the tunnel" "Handshake works but no data is sent: the problem is on the CLIENT (Address vs AllowedIPs mismatch, client firewall, MTU, wrong routes)." - "Compare the client's Address with: wg show ${WG_IF} allowed-ips; try MTU = 1380 on the client"
    elif [ "$cleak" -gt 0 ]; then finding crit CAP_LEAK "Private source addresses leave the uplink untranslated" "MASQUERADE is not applied." fix_nat "See the NAT finding."
    elif [ "$cout" -eq 0 ]; then finding crit CAP_NO_OUT "Traffic enters the tunnel but nothing returns" "Forwarding, firewall or upstream DNS/egress on the server drops the replies." - "Check FORWARD/NAT findings; sample: $(head -n2 "$fi_" | tr '\n' ' ')"
    else ok "traffic flows both ways through ${WG_IF}"; fi
    rm -f "$fi_" "$fo_" "$fl_"
}

# Usage: investigate   -> run every check (order matters: later checks reuse earlier findings)
investigate() {
    check_system
    check_wireguard && check_peers
    check_forwarding
    check_nat_firewall
    check_datapath
    check_dns
    check_web_doh
    check_outline
    check_security
    run_capture
}

# ----------------------------- diagnosis and plan -----------------------------

# Usage: say "text"   -> one bullet of the diagnosis
say() { printf '  - %s\n' "$*"; }

# Usage: diagnose   -> plain-language summary of the most likely cause(s), combining the findings
diagnose() {
    section "Diagnosis"
    local crit warn found=0
    crit=$(count_sev crit); warn=$(count_sev warn)
    if has_any NAT_MISSING NAT_WRONG_IF; then
        found=1
        say "WireGuard clients can connect (handshake) but their traffic cannot leave: the NAT rule for ${WG_NET} is $(has_finding NAT_MISSING && echo missing || echo "bound to the wrong interface")."
        has_finding NAT_NOT_PERSISTENT && say "The rule was only in memory, so it disappeared at the last reboot${BOOT_TIME:+ ($BOOT_TIME)}$([ "$AUTO_REBOOT" -eq 1 ] && echo ', and this server reboots automatically after updates')."
    elif has_finding NAT_NOT_PERSISTENT; then
        found=1; say "Everything works now, but the NAT rule is not persisted: the next reboot will silently break the VPN."
    fi
    has_any NAT_BROAD NAT_HOOK_BROAD && { found=1; say "The NAT rule is too broad: internet traffic is fine, but the server cannot talk to its own VPN address (DNS on ${WG_IP:-the VPN address} times out)."; }
    has_finding FWD_OFF && { found=1; say "IP forwarding is disabled, so the server will not route client traffic."; }
    has_finding FWD_DROP && { found=1; say "A firewall/Docker policy drops forwarded packets, so VPN traffic is blocked."; }
    has_finding WG_DOWN && { found=1; say "The WireGuard interface is down."; }
    has_any NGINX_PORT_CLASH && { found=1; say "nginx cannot own ports 80/443 because Caddy has them, so nginx (and with it the DoH and admin ports) is $([ "$(systemctl is-active nginx 2>/dev/null)" = active ] && echo 'fragile after reboots' || echo down)."; }
    has_finding DNS_PORT_CLASH && { found=1; say "Unbound cannot start because systemd-resolved is using port 53."; }
    has_any DNS_DOWN DNS_NO_ANSWER DNS_CONF && { found=1; say "Plain DNS (Unbound) is not answering."; }
    has_finding CERT_RENEW_BROKEN && { found=1; say "The TLS certificate renews through port 80, which Caddy owns: the next renewal will fail and DoH will break when the certificate expires."; }
    has_any DOH_DOWN DOH_PORT_CLOSED DOH_TLS && { found=1; say "The DoH service is not reachable."; }
    has_finding WG_NO_DATA && { found=1; say "Handshakes work but no data flows and the server side looks fine: suspect the client (Address/AllowedIPs mismatch, DNS, MTU). Run with --capture=20 while a client browses."; }
    if [ "$found" -eq 0 ]; then
        if [ "$crit" -eq 0 ] && [ "$warn" -eq 0 ]; then say "No problems found."
        elif [ "$crit" -eq 0 ]; then say "The VPN works; only advisory items remain (see the plan below)."
        else say "See the critical findings above."; fi
    fi
    return 0
}

# Usage: print_plan   -> every finding with cause and fix, most severe first
print_plan() {
    section "Fix plan"
    local n=${#F_ID[@]} i k=0 sev lbl auto
    if [ "$n" -eq 0 ]; then echo "  Nothing to fix."; return 0; fi
    for sev in crit warn info; do
        for ((i=0; i<n; i++)); do
            [ "${F_SEV[$i]}" = "$sev" ] || continue
            k=$((k+1)); case "$sev" in crit) lbl="CRITICAL" ;; warn) lbl="WARNING" ;; *) lbl="INFO" ;; esac
            auto=""; [ "${F_FIX[$i]}" != "-" ] && auto="   (automatic fix available)"
            printf '\n  %d. [%s] %s%s\n' "$k" "$lbl" "${F_TITLE[$i]}" "$auto"
            printf '       Why: %s\n' "${F_WHY[$i]}"
            printf '%b\n' "${F_MANUAL[$i]}" | awk 'NR==1{print "       Fix: " $0; next} {print "            " $0}'
        done
    done
    if [ "$(count_auto)" -gt 0 ] && [ "$DO_FIX" -eq 0 ]; then
        printf '\n  Run again with --fix to apply the %s automatic fix(es): it asks before each one and backs files up first (add --dry-run to preview).\n' "$(count_auto)"
    fi
}

# ----------------------------- fixing -----------------------------------------

# Usage: run <command...>   -> print and execute a command (only print in --dry-run); returns the command's status
run() { printf '         $ %s\n' "$*"; [ "$DRY" -eq 1 ] && return 0; "$@"; }

# Usage: run_sh "<shell string>" -> like run, for strings that need pipes or redirection
run_sh() { printf '         $ %s\n' "$1"; [ "$DRY" -eq 1 ] && return 0; bash -c "$1"; }

# Usage: backup_file <path>  -> copy a file into this run's backup directory before it is changed
backup_file() {
    [ -e "$1" ] || return 0
    if [ "$DRY" -eq 1 ]; then printf '         (dry-run) would back up %s to %s\n' "$1" "$BACKUP_DIR"; return 0; fi
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR" 2>/dev/null
    cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr '/' '_')"
}

# Usage: put_file <path> <mode> <content>  -> write a small file (content uses printf %b escapes)
put_file() {
    local p="$1" m="$2"; shift 2
    printf '         $ write %s\n' "$p"
    [ "$DRY" -eq 1 ] && return 0
    mkdir -p "$(dirname "$p")" && printf '%b' "$*" > "$p" && chmod "$m" "$p"
}

# Usage: confirm "<question>"  -> 0 to proceed (always in --yes / --dry-run, otherwise asks on the terminal)
confirm() {
    [ "$ASSUME_YES" -eq 1 ] || [ "$DRY" -eq 1 ] && return 0
    local ans=""
    printf '         %s [y/N] ' "$1"
    if [ -r /dev/tty ]; then read -r ans </dev/tty 2>/dev/null || ans=""; else echo; fi
    [[ "$ans" =~ ^[Yy]$ ]]
}

# Usage: install_wg_conf <tmpfile>  -> validate a modified wg config, back up the current one and install it
install_wg_conf() {
    local tmp="$1"
    wg-quick strip "$tmp" >/dev/null 2>&1 || { echo "         the modified config does not validate: nothing was changed"; return 1; }
    if [ "$DRY" -eq 1 ]; then
        echo "         (dry-run) changes to ${WG_CONF}:"; diff "$WG_CONF" "$tmp" | grep '^[<>]' | grep -v 'PrivateKey' | sed 's/^/           /'
        return 0
    fi
    backup_file "$WG_CONF"
    cat "$tmp" > "$WG_CONF" && chmod 600 "$WG_CONF" && echo "         updated ${WG_CONF} (backup in ${BACKUP_DIR})"
}

# Usage: add_hook_pair <tag> <PostUp command> <PostDown command>  -> insert a tagged PostUp/PostDown pair into [Interface]
add_hook_pair() {
    local tag="$1" up="$2" down="$3" tmpd tmp
    [ -f "$WG_CONF" ] || { echo "         ${WG_CONF} not found"; return 1; }
    if grep -q "# vpn-doctor:${tag}\$" "$WG_CONF"; then echo "         hook '${tag}' already present"; return 0; fi
    tmpd=$(mktemp -d); tmp="$tmpd/$WG_IF.conf"
    awk -v tag="# vpn-doctor:${tag}" -v up="PostUp = ${up}" -v down="PostDown = ${down}" '
        {print}
        !done && /^PrivateKey[ \t]*=/ {print tag; print up; print down; done=1}' "$WG_CONF" > "$tmp"
    if ! grep -q "# vpn-doctor:${tag}\$" "$tmp"; then
        awk -v tag="# vpn-doctor:${tag}" -v up="PostUp = ${up}" -v down="PostDown = ${down}" '
            {print}
            !done && /^\[Interface\]/ {print tag; print up; print down; done=1}' "$WG_CONF" > "$tmp"
    fi
    install_wg_conf "$tmp"; local rc=$?
    rm -rf "$tmpd"; return $rc
}

# Usage: fix_nat_hooks   -> make the NAT rule persistent: rewrite broad PostUp/PostDown, or add new hooks
fix_nat_hooks() {
    [ -f "$WG_CONF" ] || { echo "         ${WG_CONF} not found"; return 1; }
    local net_re="${WG_NET//./\\.}" up down tmpd tmp rc
    up="iptables -t nat -C POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE"
    down="iptables -t nat -D POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE 2>/dev/null || true"
    if grep -qE '^(PostUp|PostDown)[[:space:]]*=.*(MASQUERADE|SNAT)' "$WG_CONF"; then
        tmpd=$(mktemp -d); tmp="$tmpd/$WG_IF.conf"
        sed -E "/^(PostUp|PostDown)[[:space:]]*=/{/! -d /!{s|-s ${net_re}( -o [^ ]+)? -j MASQUERADE|-s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE|g}}" "$WG_CONF" > "$tmp"
        if cmp -s "$WG_CONF" "$tmp"; then echo "         existing PostUp/PostDown already use the safe rule"; rm -rf "$tmpd"; return 0; fi
        install_wg_conf "$tmp"; rc=$?; rm -rf "$tmpd"; return $rc
    fi
    add_hook_pair nat "$up" "$down"
}

# Usage: fix_nat   -> add the loopback-safe MASQUERADE rule live, remove superseded rules, persist it in the wg config
fix_nat() {
    local new=(-s "$WG_NET" ! -d "$WG_NET" -j MASQUERADE) l old
    if iptables -t nat -C POSTROUTING "${new[@]}" 2>/dev/null; then echo "         live rule already present"
    else run iptables -t nat -A POSTROUTING "${new[@]}" || return 1; fi
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        case "$l" in *" -m "*|*" ! -d "*) continue ;; esac
        old="${l/-A /-D }"
        # intentional word splitting: iptables -S output is plain tokens here
        run iptables -t nat $old
    done < <(iptables -t nat -S POSTROUTING 2>/dev/null | grep -E -- "^-A POSTROUTING -s ${WG_NET//./\\.} .*-j MASQUERADE\$")
    fix_nat_hooks
}

# Usage: fix_forward_rules   -> ACCEPT wg traffic in FORWARD (or DOCKER-USER when Docker is present), live and via PostUp
fix_forward_rules() {
    local c="FORWARD" d
    iptables -S DOCKER-USER >/dev/null 2>&1 && c="DOCKER-USER"
    for d in "-i ${WG_IF}" "-o ${WG_IF}"; do
        # shellcheck disable=SC2086
        iptables -C "$c" $d -j ACCEPT 2>/dev/null || run iptables -I "$c" 1 $d -j ACCEPT
    done
    add_hook_pair fwd \
        "iptables -C ${c} -i ${WG_IF} -j ACCEPT 2>/dev/null || iptables -I ${c} 1 -i ${WG_IF} -j ACCEPT; iptables -C ${c} -o ${WG_IF} -j ACCEPT 2>/dev/null || iptables -I ${c} 1 -o ${WG_IF} -j ACCEPT" \
        "iptables -D ${c} -i ${WG_IF} -j ACCEPT 2>/dev/null || true; iptables -D ${c} -o ${WG_IF} -j ACCEPT 2>/dev/null || true"
}

# Usage: fix_ip_forward   -> enable forwarding now and persist it (also corrects a conflicting /etc/sysctl.conf line)
fix_ip_forward() {
    run sysctl -w net.ipv4.ip_forward=1 || return 1
    if grep -qE '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0' "$SYSCTL_CONF" 2>/dev/null; then
        backup_file "$SYSCTL_CONF"
        run_sh "sed -i -E 's|^([[:space:]]*net\\.ipv4\\.ip_forward[[:space:]]*=).*|\\11|' '${SYSCTL_CONF}'"
    fi
    put_file "$SYSCTL_DIR/99-wireguard.conf" 644 "net.ipv4.ip_forward=1\n"
    [ "$DRY" -eq 1 ] || sysctl --system >/dev/null 2>&1
    return 0
}

# Usage: fix_enable_wg   -> enable the wg-quick unit at boot
fix_enable_wg() { run systemctl enable "wg-quick@${WG_IF}"; }

# Usage: fix_wg_up   -> (re)start the wg-quick unit
fix_wg_up() {
    wg-quick strip "$WG_CONF" >/dev/null 2>&1 || { echo "         ${WG_CONF} does not parse: repair it first (vi ${WG_CONF})"; return 1; }
    run systemctl restart "wg-quick@${WG_IF}"
}

# Usage: fix_resolved_stub   -> stop systemd-resolved from listening on port 53 so Unbound can bind, then restart both
fix_resolved_stub() {
    put_file "$RESOLVED_DIR/nostub.conf" 644 "[Resolve]\nDNSStubListener=no\n"
    if [ "$(readlink -f "$RESOLV_CONF" 2>/dev/null)" = "/run/systemd/resolve/stub-resolv.conf" ]; then
        run ln -sf /run/systemd/resolve/resolv.conf "$RESOLV_CONF"
    fi
    run systemctl restart systemd-resolved && run systemctl restart unbound
}

# Usage: fix_nginx_clash   -> move aside nginx sites that only listen on 80/443 (Caddy owns them), test, restart nginx
fix_nginx_clash() {
    local f ports p other moved=0 manual=""
    [ "$DRY" -eq 1 ] || mkdir -p "$BACKUP_DIR" 2>/dev/null
    for f in "$NGINX_DIR"/sites-enabled/* "$NGINX_DIR"/conf.d/*.conf; do
        [ -e "$f" ] || continue
        ports=$(grep -E '^[[:space:]]*listen[[:space:]]' "$f" | sed -E 's/^[[:space:]]*listen[[:space:]]+(\[::\]:|[0-9.*]+:)?([0-9]+).*/\2/' | sort -u)
        echo "$ports" | grep -qxE '80|443' || continue
        other=0; for p in $ports; do case "$p" in 80|443) ;; *) other=1 ;; esac; done
        if [ "$other" -eq 1 ]; then manual="$manual $f"; continue; fi
        case "$f" in
            */sites-enabled/*)
                if [ "$DRY" -eq 1 ]; then echo "         (dry-run) would move $f to $BACKUP_DIR/"
                else mv "$f" "$BACKUP_DIR/disabled-$(basename "$f")" && echo "         moved $f aside (restore: mv $BACKUP_DIR/disabled-$(basename "$f") $f)"; fi
                moved=$((moved+1)) ;;
            *) manual="$manual $f" ;;
        esac
    done
    [ -n "$manual" ] && echo "         NOT touched (they also serve other ports, edit the 80/443 listen lines with vi):${manual}"
    [ "$DRY" -eq 1 ] && return 0
    if nginx -t >/dev/null 2>&1; then
        run systemctl reset-failed nginx; run systemctl restart nginx
        active nginx && echo "         nginx is active: $(owner_of "$(nginx_listen_ports | grep -vxE '80|443' | head -n1)")" || { echo "         nginx still not active: journalctl -u nginx -n 30"; return 1; }
    else
        echo "         nginx -t still fails, restoring moved sites"
        for f in "$BACKUP_DIR"/disabled-*; do [ -e "$f" ] && mv "$f" "$NGINX_DIR/sites-enabled/$(basename "$f" | sed 's/^disabled-//')"; done
        return 1
    fi
}

# Usage: fix_restart_nginx / fix_restart_doh / fix_restart_caddy / fix_start_outline / fix_certbot_timer -> restart or enable one service
fix_restart_nginx() { nginx -t >/dev/null 2>&1 || { echo "         nginx -t fails: fix the config first"; return 1; }; run systemctl reset-failed nginx; run systemctl restart nginx; }
fix_restart_doh() { run systemctl restart gamedns-doh; }
fix_restart_caddy() { caddy validate --config "$CADDYFILE" >/dev/null 2>&1 || { echo "         Caddyfile does not validate: repair it first (vi ${CADDYFILE})"; return 1; }; run systemctl restart caddy; }
fix_start_outline() { run docker start shadowbox; }
fix_certbot_timer() { run systemctl enable --now certbot.timer; }

# Usage: fix_deploy_hook   -> create the certbot deploy hook that reloads nginx after a renewal
fix_deploy_hook() { put_file "$LE_DIR/renewal-hooks/deploy/reload-nginx.sh" 755 "#!/bin/sh\nsystemctl reload nginx\n"; }

# Usage: ensure_acme_block <domain>  -> make Caddy serve /.well-known/acme-challenge/ for the domain (validated, rolled back on error)
ensure_acme_block() {
    local d="$1" t="$WEBROOT/.well-known/acme-challenge/vpn-doctor-test" got
    [ -f "$CADDYFILE" ] || { echo "         ${CADDYFILE} not found: add the challenge block by hand"; return 1; }
    if grep -qE "^[[:space:]]*http://${d//./\\.}[[:space:]]*\{" "$CADDYFILE"; then
        grep -q 'acme-challenge' "$CADDYFILE" && { echo "         Caddy already has an http://${d} block with acme-challenge"; return 0; }
        echo "         ${CADDYFILE} already has an http://${d} block without acme-challenge: add the handle by hand (vi)"; return 1
    fi
    backup_file "$CADDYFILE"
    run mkdir -p "$WEBROOT/.well-known/acme-challenge" || return 1
    if [ "$DRY" -eq 1 ]; then echo "         (dry-run) would append an http://${d} block (acme-challenge from ${WEBROOT}, everything else redirected to https) to ${CADDYFILE}"; return 0; fi
    printf '\n# vpn-doctor: certbot challenges for %s are served from %s\nhttp://%s {\n    handle /.well-known/acme-challenge/* {\n        root * %s\n        file_server\n    }\n    handle {\n        redir https://{host}{uri} permanent\n    }\n}\n' "$d" "$WEBROOT" "$d" "$WEBROOT" >> "$CADDYFILE"
    if ! caddy validate --config "$CADDYFILE" >/dev/null 2>&1; then
        echo "         Caddy rejected the new block: restoring ${CADDYFILE}"; cp -a "$BACKUP_DIR/$(echo "$CADDYFILE" | tr '/' '_')" "$CADDYFILE"; return 1
    fi
    run systemctl reload caddy || return 1
    echo ok > "$t"; got=$(curl -s -m 5 --resolve "${d}:80:127.0.0.1" "http://${d}/.well-known/acme-challenge/vpn-doctor-test" 2>/dev/null); rm -f "$t"
    [ "$got" = "ok" ] && { echo "         challenge path works through Caddy"; return 0; }
    echo "         the challenge path is not served by Caddy (got '${got}'): restoring ${CADDYFILE}"
    cp -a "$BACKUP_DIR/$(echo "$CADDYFILE" | tr '/' '_')" "$CADDYFILE"; systemctl reload caddy; return 1
}

# Usage: fix_certbot_webroot   -> switch non-webroot certificates to the webroot method served by Caddy, then dry-run a renewal
fix_certbot_webroot() {
    local rf name rc=0
    for rf in "$LE_DIR"/renewal/*.conf; do
        [ -f "$rf" ] || continue
        grep -qE '^authenticator[[:space:]]*=[[:space:]]*webroot' "$rf" && continue
        name=$(basename "$rf" .conf)
        backup_file "$rf"
        ensure_acme_block "$name" || { rc=1; continue; }
        run certbot reconfigure --cert-name "$name" --authenticator webroot --webroot-path "$WEBROOT" || rc=1
    done
    [ "$rc" -eq 0 ] && run certbot renew --dry-run
    return $rc
}

# Usage: apply_fixes   -> run each automatic fix once, most severe first, asking first unless --yes
apply_fixes() {
    section "Applying fixes$([ "$DRY" -eq 1 ] && echo ' (dry-run: nothing is changed)')"
    local sev i fn n=${#F_ID[@]} applied=0 failed=0
    for sev in crit warn; do
        for ((i=0; i<n; i++)); do
            [ "${F_SEV[$i]}" = "$sev" ] || continue
            fn="${F_FIX[$i]}"; [ "$fn" = "-" ] && continue
            case "$FIX_DONE" in *" $fn "*) continue ;; esac
            printf '\n  %s\n' "${F_TITLE[$i]}"
            if ! confirm "Apply '${fn#fix_}'?"; then echo "         skipped"; continue; fi
            FIX_DONE="${FIX_DONE}${fn} "
            if "$fn"; then applied=$((applied+1)); echo "         done"; else failed=$((failed+1)); echo "         FAILED: see the messages above (use the manual steps in the plan)"; fi
        done
    done
    printf '\n  %d fix(es) applied, %d failed.%s\n' "$applied" "$failed" "$([ -d "$BACKUP_DIR" ] && echo " Backups: $BACKUP_DIR")"
}

# Usage: recheck   -> re-run the investigation after fixing and report what was resolved
recheck() {
    local old_id=("${F_ID[@]+"${F_ID[@]}"}") old_title=("${F_TITLE[@]+"${F_TITLE[@]}"}") old_sev=("${F_SEV[@]+"${F_SEV[@]}"}") i cap="$CAPTURE_SECS"
    F_SEV=(); F_ID=(); F_TITLE=(); F_WHY=(); F_FIX=(); F_MANUAL=(); CNT_OK=0
    section "Re-check after fixes"
    CAPTURE_SECS=0; QUIET=1; RECHECK=1; detect_env; investigate; RECHECK=0; QUIET=0; CAPTURE_SECS="$cap"
    for ((i=0; i<${#old_id[@]}; i++)); do
        has_finding "${old_id[$i]}" || { [ "${old_sev[$i]}" != "info" ] && printf '  %s[FIXED]%s %s\n' "$C_G" "$C_0" "${old_title[$i]}"; }
    done
    [ "$(count_sev crit)$(count_sev warn)" = "00" ] && ok "no critical or warning findings remain"
    return 0
}

# Usage: main "$@"
main() {
    parse_args "$@"
    [ "$EUID" -eq 0 ] || { echo "Run as root: sudo $0 $*"; exit 2; }
    setup_colors
    [ -n "$REPORT" ] && exec > >(tee "$REPORT") 2>&1
    printf '%sVPN doctor%s  %s  host=%s%s\n' "$C_B" "$C_0" "$(date '+%F %T %Z')" "$(hostname)" "$([ "$DRY" -eq 1 ] && echo '  [dry-run]')"
    detect_env
    investigate
    diagnose
    print_plan
    if [ "$DO_FIX" -eq 1 ] && [ "$(count_auto)" -gt 0 ]; then
        apply_fixes
        [ "$DRY" -eq 1 ] || recheck
    fi
    printf '\nDOCTOR_SUMMARY host=%s critical=%s warnings=%s info=%s auto_fixable=%s\n' "$(hostname)" "$(count_sev crit)" "$(count_sev warn)" "$(count_sev info)" "$(count_auto)"
    [ "$(count_sev crit)" -eq 0 ]
}

main "$@"
