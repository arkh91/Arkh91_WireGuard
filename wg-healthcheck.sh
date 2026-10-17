#!/bin/bash
# =============================================================================
# wg-healthcheck.sh - WireGuard health check & troubleshooting
#
# Built for the setup created by install-wg3.sh:
#   interface wg0, subnet auto-detected (default pool 10.66.0.0/16), iptables MASQUERADE, wg-api, caddy.
#
# Symptom it targets: "handshake succeeds but no traffic passes".
# A handshake only proves keys + UDP reachability. Everything after that
# (AllowedIPs, ip_forward, FORWARD rules, NAT, MTU, DNS) is checked here.
#
# Usage:
#   sudo ./wg-healthcheck.sh                   # run all checks
#   sudo ./wg-healthcheck.sh --capture=20      # also sniff wg0 for 20s
#   sudo ./wg-healthcheck.sh --if=wg1          # different interface
#   sudo ./wg-healthcheck.sh --net=10.8.0.0/24 # force a VPN subnet (default: read from wg0.conf)
#   sudo ./wg-healthcheck.sh --report=/tmp/wg.txt   # also save output
#   sudo ./wg-healthcheck.sh --no-color
#
# Edit with:  vi wg-healthcheck.sh
# Exit code:  0 = no failures, 1 = at least one FAIL
# =============================================================================

set -u

# ----------------------------- defaults --------------------------------------
WG_IF="wg0"
WG_NET=""            # empty = read it from the Address line of /etc/wireguard/<if>.conf (--net= overrides)
API_PORT=4242
API_DIR="/opt/wg-api"
API_SERVICE="wg-api.service"
CAPTURE_SECS=0
REPORT=""
USE_COLOR=1

PASS=0; WARN=0; FAIL=0
FIXES=()
FRESH_PEERS=0       # peers with a recent handshake
NO_DATA_PEERS=0     # ...of which show (almost) no payload traffic
OUT_IFACE=""
WG_IP=""
WG_PORT=""
WG_CONF=""

# ----------------------------- output helpers --------------------------------

# Usage: setup_colors   (call after parsing args; sets C_G/C_Y/C_R/C_B/C_0)
setup_colors() {
    if [ "$USE_COLOR" -eq 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        C_G=$'\e[32m'; C_Y=$'\e[33m'; C_R=$'\e[31m'; C_B=$'\e[1m'; C_0=$'\e[0m'
    else
        C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""
    fi
}

# Usage: section "Title"   -> prints a section header
section() { printf '\n%s== %s ==%s\n' "$C_B" "$*" "$C_0"; }

# Usage: ok "message"      -> records a passing check
ok()   { PASS=$((PASS+1)); printf '  %s[ OK ]%s %s\n' "$C_G" "$C_0" "$*"; }

# Usage: warn "message"    -> records a warning (not necessarily broken)
warn() { WARN=$((WARN+1)); printf '  %s[WARN]%s %s\n' "$C_Y" "$C_0" "$*"; }

# Usage: fail "message"    -> records a failure (likely cause of the outage)
fail() { FAIL=$((FAIL+1)); printf '  %s[FAIL]%s %s\n' "$C_R" "$C_0" "$*"; }

# Usage: info "message"    -> neutral information line
info() { printf '         %s\n' "$*"; }

# Usage: add_fix "command or instruction"   -> queued for the final summary
add_fix() { FIXES+=("$*"); }

# Usage: have <command>    -> returns 0 if the command exists
have() { command -v "$1" >/dev/null 2>&1; }

# Usage: human <bytes>     -> prints e.g. 1.2KiB (falls back to raw bytes)
human() {
    if have numfmt; then
        numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "${1}B"
    else
        echo "${1}B"
    fi
}

# Usage: usage   -> prints help text
usage() {
    sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
}

# ----------------------------- setup -----------------------------------------

# Usage: parse_args "$@"
parse_args() {
    local a
    for a in "$@"; do
        case "$a" in
            --if=*)       WG_IF="${a#*=}" ;;
            --net=*)      WG_NET="${a#*=}" ;;
            --capture)    CAPTURE_SECS=15 ;;
            --capture=*)  CAPTURE_SECS="${a#*=}" ;;
            --report=*)   REPORT="${a#*=}"; USE_COLOR=0 ;;
            --no-color)   USE_COLOR=0 ;;
            -h|--help)    usage; exit 0 ;;
            *) echo "Unknown argument: $a"; usage; exit 2 ;;
        esac
    done
    if ! [[ "$CAPTURE_SECS" =~ ^[0-9]+$ ]]; then
        echo "--capture needs a number of seconds"; exit 2
    fi
    WG_CONF="/etc/wireguard/${WG_IF}.conf"
    if [ -z "$WG_NET" ]; then WG_NET="$(detect_net)"; fi
}

# Usage: detect_net   -> prints the VPN network (e.g. 10.66.0.0/16 or 10.66.66.0/24) from the interface Address
detect_net() {
    local addr ip p a b c d n mask
    addr=$(sed -n 's/^Address[[:space:]]*=[[:space:]]*\([0-9.]*\/[0-9]*\).*/\1/p' "$WG_CONF" 2>/dev/null | head -n1)
    [ -n "$addr" ] || addr=$(ip -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4; exit}')
    if [ -z "$addr" ]; then echo "10.66.66.0/24"; return; fi
    ip="${addr%/*}"; p="${addr#*/}"
    IFS=. read -r a b c d <<<"$ip"
    n=$(( (a<<24) + (b<<16) + (c<<8) + d ))
    mask=$(( (0xFFFFFFFF << (32-p)) & 0xFFFFFFFF ))
    n=$(( n & mask ))
    echo "$(( (n>>24)&255 )).$(( (n>>16)&255 )).$(( (n>>8)&255 )).$(( n&255 ))/$p"
}

# Usage: require_root   -> exits unless running as root
require_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Run as root: sudo $0 $*"; exit 1
    fi
}

# Usage: detect_env   -> fills OUT_IFACE, WG_IP, WG_PORT
detect_env() {
    OUT_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
    WG_IP=$(ip -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    WG_PORT=$(wg show "$WG_IF" listen-port 2>/dev/null)
    [ -z "$WG_PORT" ] && WG_PORT=$(awk -F= '/^ListenPort/{gsub(/ /,"",$2); print $2}' "$WG_CONF" 2>/dev/null)
}

# ----------------------------- checks ----------------------------------------

# Usage: check_basics   -> tools, kernel module, uptime/time sanity
check_basics() {
    section "Basics"
    if have wg; then ok "wg tool present ($(wg --version 2>/dev/null | head -n1))"
    else fail "wg command not found"; add_fix "apt install -y wireguard"; return 1; fi

    if lsmod 2>/dev/null | grep -q '^wireguard' || [ -d /sys/module/wireguard ]; then
        ok "wireguard kernel module loaded"
    else
        warn "wireguard kernel module not visible (may be built in, or userspace wireguard-go)"
    fi

    info "Kernel: $(uname -r)   Uptime: $(uptime -p 2>/dev/null)"
    info "System time: $(date -u '+%F %T UTC')  (large clock drift breaks handshakes)"
    if have timedatectl; then
        if timedatectl 2>/dev/null | grep -qi 'synchronized: yes'; then ok "clock is NTP-synchronized"
        else warn "clock is not NTP-synchronized"; fi
    fi
}

# Usage: check_services   -> wg-quick, wg-api, caddy state + local API health
check_services() {
    section "Services"
    local s
    for s in "wg-quick@${WG_IF}" "$API_SERVICE" caddy; do
        if systemctl is-active --quiet "$s" 2>/dev/null; then ok "$s is active"
        else
            if [ "$s" = "wg-quick@${WG_IF}" ]; then
                fail "$s is not active"
                add_fix "systemctl restart wg-quick@${WG_IF}; journalctl -u wg-quick@${WG_IF} -n 50"
            else
                warn "$s is not active (affects provisioning API only, not tunnel traffic)"
            fi
        fi
        if ! systemctl is-enabled --quiet "$s" 2>/dev/null && [ "$s" = "wg-quick@${WG_IF}" ]; then
            warn "$s is not enabled -> tunnel will NOT come back after reboot"
            add_fix "systemctl enable wg-quick@${WG_IF}"
        fi
    done
    if have curl; then
        if curl -fsS -m 3 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
            ok "wg-api /health responds on 127.0.0.1:${API_PORT}"
        else
            warn "wg-api /health not responding on 127.0.0.1:${API_PORT}"
        fi
    fi
}

# Usage: check_interface   -> wg0 exists, has address, MTU, listening UDP port
check_interface() {
    section "Interface ${WG_IF}"
    if ! ip link show "$WG_IF" >/dev/null 2>&1; then
        fail "interface $WG_IF does not exist"
        add_fix "wg-quick up ${WG_IF}   (check config: wg-quick strip ${WG_IF})"
        return 1
    fi
    ok "interface exists: $(ip -o link show "$WG_IF" | awk '{print $9, $10, $11}' | head -n1) (state may show UNKNOWN - that is normal for WireGuard)"
    if [ -n "$WG_IP" ]; then ok "address: $WG_IP"; else fail "no IPv4 address on $WG_IF"; fi

    local mtu out_mtu
    mtu=$(cat "/sys/class/net/${WG_IF}/mtu" 2>/dev/null)
    out_mtu=$(cat "/sys/class/net/${OUT_IFACE}/mtu" 2>/dev/null)
    info "MTU ${WG_IF}=${mtu:-?}  ${OUT_IFACE:-?}=${out_mtu:-?}"
    if [ -n "$mtu" ] && [ -n "$out_mtu" ] && [ "$mtu" -gt $((out_mtu - 80)) ]; then
        warn "wg MTU ($mtu) > uplink MTU-80 ($((out_mtu-80))): large packets may stall"
        add_fix "Set a lower MTU in the CLIENT [Interface] (try MTU = 1380), and/or server: vi ${WG_CONF}  (add MTU = 1380)"
    fi

    if [ -n "$WG_PORT" ] && ss -H -lun 2>/dev/null | grep -qE "[:.]${WG_PORT}\b"; then
        ok "UDP port ${WG_PORT} is bound"
    else
        warn "UDP port ${WG_PORT:-?} not seen in 'ss -lun' (kernel sockets sometimes hide; handshake working means it is fine)"
    fi
}

# Usage: check_config   -> config sanity, key consistency, live vs file peers
check_config() {
    section "Configuration (${WG_CONF})"
    if [ ! -f "$WG_CONF" ]; then fail "config file missing"; return 1; fi

    local perm; perm=$(stat -c '%a' "$WG_CONF")
    if [ "$perm" = "600" ]; then ok "permissions 600"; else warn "permissions are $perm (expected 600)"; add_fix "chmod 600 ${WG_CONF}"; fi

    if wg-quick strip "$WG_IF" >/dev/null 2>&1; then ok "config parses cleanly (wg-quick strip)"
    else
        fail "config does NOT parse - a restart of wg-quick will fail (wg-remove awk edits can corrupt it)"
        info "$(wg-quick strip "$WG_IF" 2>&1 | head -n3)"
        add_fix "vi ${WG_CONF}   # repair, then: wg-quick strip ${WG_IF}"
    fi

    # server key consistency
    local live_pub file_pub api_pub
    live_pub=$(wg show "$WG_IF" public-key 2>/dev/null)
    file_pub=$(cat /etc/wireguard/server_public.key 2>/dev/null)
    api_pub=$(sed -n "s/^const SERVER_PUB = '\(.*\)';/\1/p" "$API_DIR/server.js" 2>/dev/null | head -n1)
    if [ -n "$live_pub" ]; then
        info "live server public key: $live_pub"
        [ -n "$file_pub" ] && { [ "$file_pub" = "$live_pub" ] && ok "server_public.key matches live key" || fail "server_public.key differs from live key"; }
        if [ -n "$api_pub" ]; then
            if [ "$api_pub" = "$live_pub" ]; then ok "wg-api hands out the correct server public key"
            else fail "wg-api embeds a STALE server public key -> new client configs cannot pass traffic"
                 add_fix "Re-generate client configs with the key above, or fix SERVER_PUB in ${API_DIR}/server.js (vi) and: systemctl restart ${API_SERVICE}"; fi
        fi
    fi

    # ListenPort live vs file
    local file_port; file_port=$(awk -F= '/^ListenPort/{gsub(/ /,"",$2); print $2}' "$WG_CONF")
    if [ -n "$file_port" ] && [ -n "$WG_PORT" ] && [ "$file_port" != "$WG_PORT" ]; then
        warn "ListenPort differs: file=$file_port live=$WG_PORT (config edited without restart?)"
    fi

    # peers: file vs live
    local file_keys live_keys k missing_live=0 missing_file=0
    # NOTE: base64 keys end in '=', so never split on '=' with awk -F; strip the prefix with sed instead
    file_keys=$(sed -n 's/^PublicKey[[:space:]]*=[[:space:]]*//p' "$WG_CONF" | sort -u)
    live_keys=$(wg show "$WG_IF" peers 2>/dev/null | sort -u)
    for k in $file_keys;  do grep -qxF "$k" <<<"$live_keys" || { missing_live=$((missing_live+1)); }; done
    for k in $live_keys;  do grep -qxF "$k" <<<"$file_keys" || { missing_file=$((missing_file+1)); }; done
    [ "$missing_live" -gt 0 ] && warn "$missing_live peer(s) in the file but not live (restart wg-quick or 'wg syncconf')"
    if [ "$missing_file" -gt 0 ]; then
        warn "$missing_file live peer(s) NOT in ${WG_CONF} -> they vanish on restart/reboot"
        add_fix "cp ${WG_CONF} ${WG_CONF}.bak; then compare with: wg showconf ${WG_IF}  (do NOT restart wg-quick until live-only peers are in the file)"
    fi
    [ "$missing_live" -eq 0 ] && [ "$missing_file" -eq 0 ] && ok "peers in file and live interface match ($(wc -w <<<"$live_keys") peers)"

    # duplicate AllowedIPs (two peers claiming one IP -> traffic goes to the wrong/old peer)
    local dups
    dups=$(wg show "$WG_IF" allowed-ips 2>/dev/null | cut -f2 | tr ' ' '\n' | grep -v '^$' | sort | uniq -d)
    if [ -n "$dups" ]; then fail "duplicate AllowedIPs among peers: $(echo $dups)"
    else ok "no duplicate AllowedIPs among live peers"; fi
    local dups_file
    dups_file=$(grep -E '^AllowedIPs' "$WG_CONF" | sed 's/.*= *//' | sort | uniq -d)
    [ -n "$dups_file" ] && { warn "duplicate AllowedIPs in config file: $(echo $dups_file)"; add_fix "vi ${WG_CONF}   # remove duplicate [Peer] blocks"; }
}

# Usage: check_peers   -> per-peer handshake age and traffic counters
check_peers() {
    section "Peers (handshake + traffic)"
    local now pub psk ep aips hs rx tx ka age short n=0
    now=$(date +%s)
    while IFS=$'\t' read -r pub psk ep aips hs rx tx ka; do
        [ -z "$pub" ] && continue
        n=$((n+1)); short="${pub:0:8}..."
        if [ "${hs:-0}" -eq 0 ]; then
            warn "peer $short ($aips): never completed a handshake (unused or misconfigured client)"
            continue
        fi
        age=$((now - hs))
        if [ "$age" -gt 180 ]; then
            warn "peer $short ($aips): last handshake ${age}s ago (client offline/idle)"
            continue
        fi
        FRESH_PEERS=$((FRESH_PEERS+1))
        local line="peer $short ($aips) endpoint=$ep hs=${age}s ago rx=$(human "$rx") tx=$(human "$tx")"
        if [ $((rx + tx)) -lt 4096 ]; then
            NO_DATA_PEERS=$((NO_DATA_PEERS+1))
            fail "$line  -> handshake OK but ~no payload: tunnel is up, data path is broken"
        elif [ "$rx" -gt 0 ] && [ "$tx" -eq 0 ]; then
            fail "$line  -> server receives, sends NOTHING back (forwarding/NAT/egress)"
        elif [ "$tx" -gt 0 ] && [ "$rx" -eq 0 ]; then
            warn "$line  -> server sends but never receives (client firewall/NAT/AllowedIPs on client)"
        else
            ok "$line"
        fi
    done < <(wg show "$WG_IF" dump 2>/dev/null | tail -n +2)

    [ "$n" -eq 0 ] && warn "no peers configured"
    if [ "$FRESH_PEERS" -gt 0 ] && [ "$NO_DATA_PEERS" -eq "$FRESH_PEERS" ]; then
        info "All connected peers show handshake without data. Server-side suspects are checked below;"
        info "if they all pass, the problem is client-side (AllowedIPs/Address mismatch, MTU, DNS)."
        add_fix "Client side: confirm the client's Address equals the peer's AllowedIPs/32 on the server (wg show ${WG_IF} allowed-ips). A mismatch = handshake OK, packets silently dropped."
    fi
}

# Usage: persisted_forward_value   -> echoes the last configured ip_forward value ("" if none)
persisted_forward_value() {
    local f v=""
    for f in /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf /etc/sysctl.d/*.conf /etc/sysctl.conf; do
        [ -f "$f" ] || continue
        local l; l=$(grep -E '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' "$f" 2>/dev/null | tail -n1)
        [ -n "$l" ] && v=$(echo "$l" | sed 's/.*=[[:space:]]*//')
    done
    echo "$v"
}

# Usage: check_forwarding   -> runtime + persistent net.ipv4.ip_forward
check_forwarding() {
    section "IP forwarding"
    local rt pv
    rt=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    pv=$(persisted_forward_value)
    if [ "$rt" = "1" ]; then ok "net.ipv4.ip_forward = 1 (runtime)"
    else
        fail "net.ipv4.ip_forward = ${rt:-?} (runtime) -> server will NOT route client traffic (classic 'handshake but no internet')"
        add_fix "sysctl -w net.ipv4.ip_forward=1"
    fi
    if [ "$pv" = "1" ]; then ok "ip_forward=1 is persisted"
    else
        warn "ip_forward is not persisted as 1 (found: '${pv:-nothing}'). install-wg3.sh only edits an EXISTING line in /etc/sysctl.conf, so a reboot can reset it."
        add_fix "echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard.conf && sysctl --system"
    fi
}

# Usage: check_firewall   -> FORWARD policy/rules/order/counters, ufw, docker
check_firewall() {
    section "Firewall (FORWARD / INPUT)"
    if ! have iptables; then
        warn "iptables not installed; if using nftables check: nft list ruleset"
        return
    fi
    info "backend: $(iptables -V 2>&1)"

    # mixed backends
    if have iptables-legacy && have iptables-nft; then
        local l n
        l=$(iptables-legacy -S 2>/dev/null | grep -c '^-A')
        n=$(iptables-nft    -S 2>/dev/null | grep -c '^-A')
        if [ "$l" -gt 0 ] && [ "$n" -gt 0 ]; then
            warn "rules exist in BOTH iptables-legacy ($l) and iptables-nft ($n): rules may be split between backends"
        fi
    fi

    local policy rules first_ok in_rule out_rule
    policy=$(iptables -S FORWARD 2>/dev/null | awk '/^-P FORWARD/{print $3}')
    info "FORWARD policy: ${policy:-?}"
    rules=$(iptables -S FORWARD 2>/dev/null | grep '^-A')
    in_rule=$(grep -E -- "^-A FORWARD .*-i ${WG_IF} .*-j ACCEPT" <<<"$rules" | head -n1)
    out_rule=$(grep -E -- "^-A FORWARD .*-o ${WG_IF} .*-j ACCEPT" <<<"$rules" | head -n1)

    if [ -n "$in_rule" ] && [ -n "$out_rule" ]; then ok "FORWARD accepts traffic in/out of ${WG_IF}"
    elif [ "$policy" = "DROP" ]; then
        fail "FORWARD policy is DROP and ${WG_IF} ACCEPT rules are missing (in:${in_rule:+yes}${in_rule:-no} out:${out_rule:+yes}${out_rule:-no})"
        add_fix "iptables -I FORWARD 1 -i ${WG_IF} -j ACCEPT; iptables -I FORWARD 2 -o ${WG_IF} -j ACCEPT; netfilter-persistent save"
    else
        warn "no explicit ${WG_IF} ACCEPT in FORWARD (policy ${policy:-?}) - OK only if another rule allows it"
    fi

    # anything before our ACCEPT that can swallow the traffic?
    if [ -n "$in_rule" ]; then
        local ln=0 idx=0 pre
        while IFS= read -r pre; do
            idx=$((idx+1))
            [ "$pre" = "$in_rule" ] && { ln=$idx; break; }
        done <<<"$rules"
        if [ "$ln" -gt 1 ]; then
            local before; before=$(head -n $((ln-1)) <<<"$rules")
            if grep -qE -- '-j (DROP|REJECT)' <<<"$before"; then
                fail "a DROP/REJECT rule sits BEFORE the ${WG_IF} ACCEPT rule in FORWARD (appended -A rules are evaluated last)"
                info "$(grep -E -- '-j (DROP|REJECT)' <<<"$before" | head -n3)"
                add_fix "iptables -I FORWARD 1 -i ${WG_IF} -j ACCEPT; iptables -I FORWARD 2 -o ${WG_IF} -j ACCEPT; netfilter-persistent save"
            fi
            if grep -qiE -- '-j (DOCKER|ufw|KUBE|CNI|FLANNEL)' <<<"$before"; then
                warn "FORWARD jumps to Docker/ufw/k8s chains before the WireGuard rules; those may drop wg traffic"
                info "Insert WG rules at the top: iptables -I FORWARD 1 -i ${WG_IF} -j ACCEPT ; iptables -I FORWARD 2 -o ${WG_IF} -j ACCEPT"
            fi
        fi
    fi

    # packet counters on the wg rules
    local pin pout
    pin=$(iptables -L FORWARD -n -v -x 2>/dev/null | awk -v i="$WG_IF" '$6==i {p+=$1} END{print p+0}')
    pout=$(iptables -L FORWARD -n -v -x 2>/dev/null | awk -v i="$WG_IF" '$7==i {p+=$1} END{print p+0}')
    info "FORWARD counters: from ${WG_IF}=${pin} pkts, to ${WG_IF}=${pout} pkts (since last reboot/flush)"
    if [ "$pin" -gt 0 ] && [ "$pout" -eq 0 ]; then
        fail "clients send traffic through the server but NO replies come back to ${WG_IF} -> NAT/egress/conntrack problem"
    elif [ "$pin" -eq 0 ] && [ "$pout" -eq 0 ]; then
        warn "zero forwarded packets recorded: either ip_forward was off, rules were reloaded, or no client traffic reaches the server"
    fi

    # INPUT for the UDP port
    local ip_policy; ip_policy=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/{print $3}')
    if iptables -S INPUT 2>/dev/null | grep -qE -- "--dport ${WG_PORT} .*-j ACCEPT"; then ok "INPUT accepts udp/${WG_PORT}"
    elif [ "$ip_policy" = "ACCEPT" ]; then ok "INPUT policy ACCEPT"
    else warn "no INPUT ACCEPT for udp/${WG_PORT} (handshake works now, but check after reboot)"; fi

    # ufw / docker
    if have ufw && ufw status 2>/dev/null | grep -qi 'Status: active'; then
        warn "ufw is ACTIVE: needs 'ufw route allow in on ${WG_IF}' and DEFAULT_FORWARD_POLICY=\"ACCEPT\" in /etc/default/ufw"
        info "$(grep -E '^DEFAULT_FORWARD_POLICY' /etc/default/ufw 2>/dev/null)"
        add_fix "ufw route allow in on ${WG_IF} out on ${OUT_IFACE}; ufw allow ${WG_PORT}/udp   (or edit /etc/default/ufw with vi)"
    fi
    if have docker && systemctl is-active --quiet docker 2>/dev/null; then
        if [ "$policy" = "DROP" ]; then
            warn "Docker is running and FORWARD policy is DROP: WG rules must be in DOCKER-USER or inserted at position 1"
            add_fix "iptables -I DOCKER-USER -i ${WG_IF} -j ACCEPT; iptables -I DOCKER-USER -o ${WG_IF} -j ACCEPT   # or use PostUp in ${WG_CONF}"
        else
            info "Docker is running (FORWARD policy is ${policy:-?}, so it is not blocking WireGuard right now)"
        fi
    fi

    # persistence
    if [ -f /etc/iptables/rules.v4 ]; then
        # must be a MASQUERADE for the WireGuard subnet (Docker's own 172.17.x rule does not count)
        if grep MASQUERADE /etc/iptables/rules.v4 | grep -qF "${WG_NET%.*}."; then
            ok "saved rules (/etc/iptables/rules.v4) contain MASQUERADE for ${WG_NET}"
        else
            warn "/etc/iptables/rules.v4 has NO MASQUERADE for ${WG_NET} -> NAT is lost after every reboot"
            add_fix "After fixing live NAT run: netfilter-persistent save   (then verify: grep MASQUERADE /etc/iptables/rules.v4)"
        fi
    else
        warn "no /etc/iptables/rules.v4: rules are not persisted"
    fi

    # a saved rules file is useless unless something restores it at boot
    local persist_ok=0
    if have netfilter-persistent && systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then persist_ok=1; fi
    if grep -qE '^PostUp.*MASQUERADE' "$WG_CONF" 2>/dev/null; then persist_ok=1; fi
    if [ "$persist_ok" -eq 1 ]; then
        ok "NAT rules are re-applied at boot (netfilter-persistent or PostUp in ${WG_CONF})"
    else
        fail "nothing re-applies the NAT/FORWARD rules at boot (netfilter-persistent missing/disabled, no PostUp): they are lost on every reboot"
        add_fix "vi ${WG_CONF}  -> under [Interface] add: PostUp = iptables -t nat -C POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE"
        add_fix "(alternative) apt install -y iptables-persistent && netfilter-persistent save   # note: also saves Docker's chains"
    fi
}

# Usage: check_nat   -> MASQUERADE rule vs current uplink + egress ping via wg IP
check_nat() {
    section "NAT / egress"
    info "current default-route interface: ${OUT_IFACE:-none}"
    if [ -z "$OUT_IFACE" ]; then fail "server has no default IPv4 route"; return; fi

    local nat; nat=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep MASQUERADE)
    if [ -z "$nat" ]; then
        fail "no MASQUERADE rule in nat/POSTROUTING -> clients leave with private VPN-network source and never get replies"
        add_fix "iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${OUT_IFACE} -j MASQUERADE; netfilter-persistent save"
    else
        info "$(head -n3 <<<"$nat")"
        local wgline; wgline=$(grep -F -- "-s ${WG_NET} " <<<"$nat" | head -n1)
        if [ -n "$wgline" ] && { grep -qF -- "-o ${OUT_IFACE} " <<<"$wgline" || ! grep -qE -- '(^| )-o ' <<<"$wgline"; }; then
            ok "MASQUERADE for ${WG_NET} exists (${wgline#-A POSTROUTING })"
            if ! grep -qE -- '(^| )-o | ! -d ' <<<"$wgline"; then
                warn "MASQUERADE rule has no -o and no '! -d ${WG_NET}': it also matches loopback traffic (MASQUERADE drops it), so the server's own queries to ${WG_IP:-the wg address} time out"
                add_fix "iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE; iptables -t nat -D POSTROUTING -s ${WG_NET} -j MASQUERADE   # then update PostUp/PostDown in ${WG_CONF} with vi"
            fi
        else
            fail "MASQUERADE exists but not for ${WG_NET} on current uplink ${OUT_IFACE} (interface renamed/changed since install?)"
            add_fix "iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${OUT_IFACE} -j MASQUERADE; netfilter-persistent save   # and remove the stale rule"
            add_fix "More robust: in ${WG_CONF} (vi) use PostUp = iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE  (no -o)"
        fi
    fi

    # NAT counters
    local npk
    npk=$(iptables -t nat -L POSTROUTING -n -v -x 2>/dev/null | awk '/MASQUERADE/ && /10\.66\.66\./ {p+=$1} END{print p+0}')
    info "MASQUERADE hit counter: ${npk} pkts"

    if [ -n "$WG_IP" ] && have ping; then
        if ping -c2 -W2 -I "$WG_IP" 1.1.1.1 >/dev/null 2>&1; then
            ok "ping 1.1.1.1 sourced from ${WG_IP} works (NAT + uplink OK)"
        elif ping -c2 -W2 1.1.1.1 >/dev/null 2>&1; then
            fail "server reaches 1.1.1.1, but NOT when sourced from ${WG_IP}: MASQUERADE is not matching"
        else
            fail "server itself cannot ping 1.1.1.1 (uplink/provider problem; ICMP may also be filtered)"
        fi
    fi

    if have dig && [ -n "$WG_IP" ]; then
        if dig +time=2 +tries=1 +short -b "$WG_IP" @1.1.1.1 cloudflare.com 2>/dev/null | grep -q .; then
            ok "DNS query to 1.1.1.1 sourced from ${WG_IP} works (client DNS = 1.1.1.1)"
        else
            warn "DNS to 1.1.1.1 via ${WG_IP} failed (clients would see 'no internet' even if the tunnel works)"
        fi
    elif have getent; then
        getent hosts cloudflare.com >/dev/null 2>&1 && ok "server DNS resolution works" || warn "server DNS resolution failed"
    fi
}

# Usage: check_kernel_misc   -> conntrack table, rp_filter, recent kernel/wg logs
check_kernel_misc() {
    section "Kernel / logs"
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
        local c m
        c=$(cat /proc/sys/net/netfilter/nf_conntrack_count)
        m=$(cat /proc/sys/net/netfilter/nf_conntrack_max)
        if [ "$m" -gt 0 ] && [ $((c * 100 / m)) -gt 85 ]; then
            fail "conntrack table ${c}/${m} nearly full: new connections dropped"
            add_fix "sysctl -w net.netfilter.nf_conntrack_max=262144"
        else
            ok "conntrack ${c}/${m}"
        fi
    fi
    info "rp_filter all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null) ${WG_IF}=$(sysctl -n "net.ipv4.conf.${WG_IF}.rp_filter" 2>/dev/null) ${OUT_IFACE}=$(sysctl -n "net.ipv4.conf.${OUT_IFACE}.rp_filter" 2>/dev/null)"

    if have journalctl; then
        local l
        l=$(journalctl -u "wg-quick@${WG_IF}" -n 8 --no-pager 2>/dev/null | tail -n 8)
        [ -n "$l" ] && { info "--- last wg-quick log lines ---"; echo "$l" | sed 's/^/         /'; }
    fi
    if have dmesg; then
        local d; d=$(dmesg 2>/dev/null | grep -i wireguard | tail -n 5)
        [ -n "$d" ] && { info "--- kernel wireguard messages ---"; echo "$d" | sed 's/^/         /'; }
    fi
}

# Usage: run_capture   -> sniff wg0 (in/out) and uplink leaks for CAPTURE_SECS
run_capture() {
    [ "$CAPTURE_SECS" -le 0 ] && return
    section "Live capture (${CAPTURE_SECS}s)"
    if ! have tcpdump; then warn "tcpdump missing"; add_fix "apt install -y tcpdump"; return; fi
    local fi_ fo_ fl_ cin cout cleak
    fi_=$(mktemp); fo_=$(mktemp); fl_=$(mktemp)
    info ">>> Generate traffic on the CLIENT now (ping 1.1.1.1, open a website)..."
    timeout "$CAPTURE_SECS" tcpdump -l -n -q -i "$WG_IF" -Q in  >"$fi_" 2>/dev/null &
    timeout "$CAPTURE_SECS" tcpdump -l -n -q -i "$WG_IF" -Q out >"$fo_" 2>/dev/null &
    timeout "$CAPTURE_SECS" tcpdump -l -n -q -i "${OUT_IFACE:-any}" -Q out "src net ${WG_NET}" >"$fl_" 2>/dev/null &
    wait
    cin=$(grep -cE ' IP6? ' "$fi_");  cout=$(grep -cE ' IP6? ' "$fo_");  cleak=$(grep -cE ' IP6? ' "$fl_")
    info "packets from clients into ${WG_IF}: ${cin}"
    info "packets from server back out ${WG_IF}: ${cout}"
    info "un-NATed ${WG_NET} packets leaving ${OUT_IFACE}: ${cleak}"
    if [ "$cin" -eq 0 ]; then
        fail "no client packets arrive inside the tunnel: problem is on the CLIENT (routing/AllowedIPs/Address mismatch/MTU/firewall)"
    elif [ "$cleak" -gt 0 ]; then
        fail "private source addresses leave the uplink -> MASQUERADE is not applied"
    elif [ "$cout" -eq 0 ]; then
        fail "traffic enters but nothing returns: forwarding/firewall/egress/DNS reachability on the server"
        info "sample inbound: $(head -n3 "$fi_" | tr '\n' ' ')"
    else
        ok "traffic flows both ways through ${WG_IF}; if the client still has no internet suspect client DNS/MTU"
    fi
    rm -f "$fi_" "$fo_" "$fl_"
}

# Usage: print_summary   -> totals + de-duplicated list of suggested fixes
print_summary() {
    section "Summary"
    printf '  %sOK:%s %d   %sWARN:%s %d   %sFAIL:%s %d\n' "$C_G" "$C_0" "$PASS" "$C_Y" "$C_0" "$WARN" "$C_R" "$C_0" "$FAIL"
    if [ "${#FIXES[@]}" -gt 0 ]; then
        printf '\n  %sSuggested fixes (review before running):%s\n' "$C_B" "$C_0"
        local i=0 f
        while IFS= read -r f; do i=$((i+1)); printf '   %d. %s\n' "$i" "$f"; done < <(printf '%s\n' "${FIXES[@]}" | awk '!s[$0]++')
    fi
    if [ "$CAPTURE_SECS" -eq 0 ] && [ "$FRESH_PEERS" -gt 0 ]; then
        printf '\n  Tip: re-run with --capture=20 while the client is browsing to see which side drops traffic.\n'
    fi
    printf '\n'
}

# Usage: main "$@"
main() {
    parse_args "$@"
    require_root "$@"
    setup_colors
    [ -n "$REPORT" ] && exec > >(tee "$REPORT") 2>&1

    printf '%sWireGuard health check%s  %s  host=%s\n' "$C_B" "$C_0" "$(date '+%F %T %Z')" "$(hostname)"
    check_basics || { print_summary; exit 1; }
    detect_env
    check_services
    check_interface || { print_summary; exit 1; }
    check_config
    check_peers
    check_forwarding
    check_firewall
    check_nat
    check_kernel_misc
    run_capture
    print_summary
    [ "$FAIL" -gt 0 ] && exit 1
    exit 0
}

main "$@"
