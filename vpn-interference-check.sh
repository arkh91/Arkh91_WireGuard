#!/bin/bash
# =============================================================================
# vpn-interference-check.sh - find conflicts between WireGuard (install-wg3.sh),
# the Unbound DNS script (DNS_doHGame_installed.sh) and Outline VPN (Docker).
#
# What it looks for:
#   * port 53 owners: systemd-resolved stub vs Unbound (classic bind conflict)
#   * port 80/443 owners: Caddy (wg-api HTTPS) vs nginx (installed by DNS script)
#   * the WireGuard UDP port vs Outline's ports
#   * GameDNS DoH stack: gamedns-doh, nginx, ports 2083/11112, certs, DNS name
#   * Docker/Outline iptables, FORWARD policy, NAT rules, subnet overlaps
#   * ufw state (installed by the DNS script, must not block wg0 / DNS)
#   * policy routing (ip rule) and failed services
#   * DNS answers from Unbound on localhost, on the wg0 address, and the
#     "open resolver" exposure created by access-control 0.0.0.0/0 allow
#
# Usage:
#   sudo ./vpn-interference-check.sh               # run all checks
#   sudo ./vpn-interference-check.sh --if=wg0 --net=10.66.66.0/24
#   sudo ./vpn-interference-check.sh --report=/tmp/interference.txt
#
# Read-only: it changes nothing. Edit with:  vi vpn-interference-check.sh
# Exit code: 0 = no failures, 1 = at least one FAIL
# =============================================================================

set -u

WG_IF="wg0"
WG_NET="10.66.66.0/24"
REPORT=""
USE_COLOR=1
PASS=0; WARN=0; FAIL=0
FIXES=()
WG_IP=""
WG_PORT=""
OUT_IFACE=""

# ----------------------------- output helpers --------------------------------

# Usage: setup_colors   (call after parse_args; sets C_G/C_Y/C_R/C_B/C_0)
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

# Usage: warn "message"    -> records a warning
warn() { WARN=$((WARN+1)); printf '  %s[WARN]%s %s\n' "$C_Y" "$C_0" "$*"; }

# Usage: fail "message"    -> records a failure
fail() { FAIL=$((FAIL+1)); printf '  %s[FAIL]%s %s\n' "$C_R" "$C_0" "$*"; }

# Usage: info "message"    -> neutral information line
info() { printf '         %s\n' "$*"; }

# Usage: add_fix "text"    -> queued for the final summary
add_fix() { FIXES+=("$*"); }

# Usage: have <command>    -> returns 0 if the command exists
have() { command -v "$1" >/dev/null 2>&1; }

# Usage: usage             -> prints the header comment as help
usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; }

# Usage: parse_args "$@"
parse_args() {
    local a
    for a in "$@"; do
        case "$a" in
            --if=*)     WG_IF="${a#*=}" ;;
            --net=*)    WG_NET="${a#*=}" ;;
            --report=*) REPORT="${a#*=}"; USE_COLOR=0 ;;
            --no-color) USE_COLOR=0 ;;
            -h|--help)  usage; exit 0 ;;
            *) echo "Unknown argument: $a"; usage; exit 2 ;;
        esac
    done
}

# Usage: require_root      -> exits unless running as root
require_root() {
    [ "$EUID" -eq 0 ] || { echo "Run as root: sudo $0"; exit 1; }
}

# Usage: owner_of <port>   -> prints process names listening (tcp/udp) on that port
owner_of() {
    ss -H -lntup "sport = :$1" 2>/dev/null \
        | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' '
}

# Usage: listen_lines <port>  -> prints "proto local-address process" per listener
listen_lines() {
    ss -H -lntup "sport = :$1" 2>/dev/null | awk '{
        p=$NF; if (p !~ /users:/) p="-"; else { sub(/.*users:\(\("/,"",p); sub(/".*/,"",p) }
        print "         " $1, $5, p }'
}

# Usage: detect_env        -> fills WG_IP, WG_PORT, OUT_IFACE
detect_env() {
    OUT_IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
    WG_IP=$(ip -4 -o addr show dev "$WG_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
    WG_PORT=$(wg show "$WG_IF" listen-port 2>/dev/null)
}

# ----------------------------- checks ----------------------------------------

# Usage: check_wireguard_alive   -> one-line sanity so later results make sense
check_wireguard_alive() {
    section "WireGuard baseline"
    if ! have wg; then warn "wg not installed"; return; fi
    if [ -n "$WG_PORT" ]; then ok "${WG_IF} up, listening on udp/${WG_PORT}, address ${WG_IP:-?}"
    else fail "${WG_IF} is not up (wg-quick@${WG_IF} stopped?)"; fi
    if iptables -t nat -S POSTROUTING 2>/dev/null | grep -qF -- "-s ${WG_NET}"; then
        ok "NAT rule for ${WG_NET} present"
        local wl; wl=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep -F -- "-s ${WG_NET} " | head -n1)
        if [ -n "$wl" ] && ! grep -qE -- '(^| )-o | ! -d ' <<<"$wl"; then
            warn "NAT rule is broad (no -o, no '! -d ${WG_NET}'): it also matches loopback traffic and MASQUERADE drops it, so the server's own queries to ${WG_IP:-the wg address} time out"
            add_fix "iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE; iptables -t nat -D POSTROUTING -s ${WG_NET} -j MASQUERADE   # then update PostUp/PostDown in /etc/wireguard/${WG_IF}.conf with vi"
        fi
    else
        fail "NAT rule for ${WG_NET} MISSING (this alone gives 'handshake but no internet')"
        add_fix "iptables -t nat -A POSTROUTING -s ${WG_NET} -o ${OUT_IFACE:-eth0} -j MASQUERADE   (and persist via PostUp in /etc/wireguard/${WG_IF}.conf using vi)"
    fi
}

# Usage: check_port53   -> who owns :53, systemd-resolved stub vs Unbound
check_port53() {
    section "DNS: port 53 / Unbound / systemd-resolved"
    local owners; owners=$(owner_of 53)
    if [ -z "$owners" ]; then
        fail "nothing is listening on port 53: the DNS service is DOWN"
    else
        info "listeners on :53"; listen_lines 53
    fi

    if have unbound || systemctl list-unit-files 2>/dev/null | grep -q '^unbound'; then
        if systemctl is-active --quiet unbound 2>/dev/null; then
            ok "unbound is active"
        else
            fail "unbound is NOT active ($(systemctl is-active unbound 2>&1))"
            local j; j=$(journalctl -u unbound -n 15 --no-pager 2>/dev/null | grep -iE 'bind|address already|error|fatal|failed' | tail -n 4)
            [ -n "$j" ] && echo "$j" | sed 's/^/         /'
        fi
        if have unbound-checkconf; then
            if unbound-checkconf >/dev/null 2>&1; then ok "unbound config is valid"
            else fail "unbound-checkconf reports errors"; unbound-checkconf 2>&1 | head -n3 | sed 's/^/         /'; add_fix "vi /etc/unbound/unbound.conf  (fix the errors above), then: systemctl restart unbound"; fi
        fi
    else
        warn "unbound is not installed"
    fi

    # resolved stub conflict
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        local nostub=0
        grep -rqsE '^[[:space:]]*DNSStubListener[[:space:]]*=[[:space:]]*no' /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/ 2>/dev/null && nostub=1
        if [ "$nostub" -eq 0 ]; then
            if systemctl is-active --quiet unbound 2>/dev/null; then
                warn "systemd-resolved stub (127.0.0.53:53) is still on; works only while Unbound avoids 127.0.0.53"
            else
                fail "systemd-resolved owns 127.0.0.53:53 and Unbound wants 0.0.0.0:53 -> 'Address already in use' (very likely why DNS is not working)"
                add_fix "mkdir -p /etc/systemd/resolved.conf.d && printf '[Resolve]\\nDNSStubListener=no\\n' > /etc/systemd/resolved.conf.d/nostub.conf && ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf && systemctl restart systemd-resolved && systemctl restart unbound"
            fi
        else
            ok "systemd-resolved stub listener is disabled (no :53 clash)"
        fi
    else
        info "systemd-resolved is not running"
    fi
    info "/etc/resolv.conf: $(grep -vE '^\s*#' /etc/resolv.conf 2>/dev/null | grep -E 'nameserver|search' | tr '\n' ';')"
}

# Usage: check_dns_answers   -> query Unbound via localhost and the wg address
check_dns_answers() {
    section "DNS: does it answer?"
    if ! have dig; then warn "dig missing (apt install -y dnsutils)"; return; fi
    local t
    for t in 127.0.0.1 ${WG_IP:-}; do
        [ -z "$t" ] && continue
        if dig +time=3 +tries=2 +short @"$t" cloudflare.com A 2>/dev/null | grep -qE '^[0-9]'; then
            ok "DNS answers on ${t}"
        else
            fail "no DNS answer from ${t}:53"
        fi
    done
    if [ -n "$WG_IP" ] && [ -n "$OUT_IFACE" ]; then
        local pub; pub=$(ip -4 -o addr show dev "$OUT_IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)
        if [ -n "$pub" ] && dig +time=2 +tries=1 +short @"$pub" cloudflare.com A 2>/dev/null | grep -qE '^[0-9]'; then
            warn "Unbound also answers on the public address ${pub}"
        fi
    fi
}

# Usage: check_open_resolver   -> Unbound access-control exposure
check_open_resolver() {
    section "DNS: open resolver exposure"
    local conf; conf=$(cat /etc/unbound/unbound.conf /etc/unbound/unbound.conf.d/*.conf 2>/dev/null)
    if grep -qE '^[[:space:]]*access-control:[[:space:]]*0\.0\.0\.0/0[[:space:]]+allow' <<<"$conf"; then
        local ufw_on=0
        have ufw && ufw status 2>/dev/null | grep -qi 'Status: active' && ufw_on=1
        if [ "$ufw_on" -eq 0 ]; then
            warn "Unbound allows 0.0.0.0/0 and no host firewall is active: anyone on the internet can use (and abuse) this resolver (DNS amplification). Hosting providers often send abuse notices or filter port 53 for this."
            add_fix "vi /etc/unbound/unbound.conf -> replace 'access-control: 0.0.0.0/0 allow' with: access-control: 127.0.0.0/8 allow  and  access-control: ${WG_NET} allow  (plus your own client IPs); then systemctl restart unbound"
        else
            info "Unbound allows 0.0.0.0/0 but ufw is active; confirm ufw restricts port 53"
        fi
    else
        ok "Unbound access-control is not 'allow 0.0.0.0/0'"
    fi
}

# Usage: check_web_ports   -> Caddy (wg-api) vs nginx on 80/443
check_web_ports() {
    section "HTTP(S): Caddy (wg-api) vs nginx"
    local p
    for p in 80 443; do
        local o; o=$(owner_of "$p")
        if [ -z "$o" ]; then warn "nothing listening on :$p"; else info ":$p -> $o"; fi
    done
    local c n
    c=$(systemctl is-active caddy 2>/dev/null); n=$(systemctl is-active nginx 2>/dev/null)
    info "caddy=${c:-n/a} nginx=${n:-n/a}"
    if [ "$n" = "failed" ]; then
        warn "nginx is in FAILED state (it was auto-installed by the DNS script and cannot bind :80 because Caddy owns it)"
        add_fix "systemctl disable --now nginx   # unless you need it; Caddy already serves HTTPS for wg-api"
    elif [ "$n" = "active" ] && [ "$c" != "active" ]; then
        fail "nginx is running but Caddy is not: wg-api HTTPS (Let's Encrypt) will be down or cannot renew"
        add_fix "systemctl disable --now nginx; systemctl restart caddy"
    elif [ "$n" = "active" ] && [ "$c" = "active" ]; then
        if owner_of 80 | grep -q nginx || owner_of 443 | grep -q nginx; then
            warn "nginx and Caddy both active and nginx is on :80/:443: check for a clash"
        else
            ok "nginx and Caddy both active on different ports (nginx: DoH ports only; Caddy: 80/443)"
        fi
    else
        ok "no nginx/Caddy clash"
    fi
}

# Usage: check_port_collisions   -> WG udp port vs everything else bound on that number
check_port_collisions() {
    section "Port collisions with WireGuard (udp/${WG_PORT:-?})"
    [ -z "$WG_PORT" ] && { warn "WireGuard port unknown"; return; }
    local o; o=$(ss -H -lunp "sport = :${WG_PORT}" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | tr '\n' ' ')
    info "udp/${WG_PORT} owners (kernel wireguard shows no process): ${o:-none}"
    if [ -n "$o" ]; then fail "a userspace process shares udp/${WG_PORT} with WireGuard: $o"; else ok "no process competes for udp/${WG_PORT}"; fi

    # Outline persisted state / access info
    local f ports=""
    for f in /opt/outline/persisted-state/shadowbox_server_config.json; do
        [ -f "$f" ] && ports=$(grep -oE '"portForNewAccessKeys"[[:space:]]*:[[:space:]]*[0-9]+' "$f" | grep -oE '[0-9]+$')
    done
    if [ -n "$ports" ]; then
        info "Outline access-key port: $ports"
        if [ "$ports" = "$WG_PORT" ]; then fail "Outline uses the same port ($ports) as WireGuard"; else ok "Outline port ($ports) differs from WireGuard ($WG_PORT)"; fi
    fi
    local oapi=""
    [ -f /opt/outline/access.txt ] && oapi=$(grep -oE 'apiUrl:https?://[^:]+:[0-9]+' /opt/outline/access.txt | grep -oE '[0-9]+$')
    [ -n "$oapi" ] && info "Outline management API port: $oapi"
}

# Usage: check_docker_outline   -> containers, networks, subnet overlap, iptables chains
check_docker_outline() {
    section "Docker / Outline"
    if ! have docker || ! systemctl is-active --quiet docker 2>/dev/null; then
        info "Docker not running"; return
    fi
    info "containers:"
    docker ps --format '         {{.Names}}  {{.Image}}  {{.Status}}  net={{.Networks}}  {{.Ports}}' 2>/dev/null
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'shadowbox|outline'; then
        ok "Outline (shadowbox) container is running"
        local nm; nm=$(docker inspect -f '{{.HostConfig.NetworkMode}}' shadowbox 2>/dev/null)
        [ -n "$nm" ] && info "shadowbox network mode: $nm (host mode = no Docker NAT rules involved)"
    fi

    # subnet overlap
    local ov=0 s
    while read -r s; do
        [ -z "$s" ] && continue
        case "$s" in 10.66.66.*|10.66.*|10.0.0.0/8) ov=1; warn "Docker network subnet $s overlaps ${WG_NET}" ;; esac
    done < <(docker network inspect $(docker network ls -q) -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null)
    [ "$ov" -eq 0 ] && ok "no Docker network overlaps ${WG_NET}"

    local pol; pol=$(iptables -S FORWARD 2>/dev/null | awk '/^-P FORWARD/{print $3}')
    if [ "$pol" = "DROP" ]; then
        fail "Docker set FORWARD policy to DROP: WireGuard clients are blocked unless wg0 ACCEPT rules come first"
        add_fix "iptables -I DOCKER-USER -i ${WG_IF} -j ACCEPT; iptables -I DOCKER-USER -o ${WG_IF} -j ACCEPT   (persist via PostUp)"
    else
        ok "FORWARD policy is ${pol:-?} (Docker is not blocking forwarding)"
    fi
    if iptables -S DOCKER-USER >/dev/null 2>&1; then
        local du; du=$(iptables -S DOCKER-USER | grep -c '^-A')
        info "DOCKER-USER has ${du} rule(s)"
    fi
    info "nat POSTROUTING:"; iptables -t nat -S POSTROUTING 2>/dev/null | sed 's/^/         /'
    info "NOTE: restarting Docker re-creates its chains; it never removes your own POSTROUTING rule, but a reboot loses rules that were not persisted."
}

# Usage: check_firewall_ufw   -> ufw / nftables / persistence that could interfere
check_firewall_ufw() {
    section "Firewall: ufw / nftables"
    if have ufw; then
        if ufw status 2>/dev/null | grep -qi 'Status: active'; then
            warn "ufw is ACTIVE (installed by the DNS script). It must allow udp/${WG_PORT:-WG}, tcp+udp/53 and routed wg0 traffic"
            ufw status verbose 2>/dev/null | sed 's/^/         /' | head -n 20
            add_fix "ufw allow ${WG_PORT:-<wg-port>}/udp; ufw allow 53; ufw route allow in on ${WG_IF}; grep DEFAULT_FORWARD_POLICY /etc/default/ufw  (vi to set ACCEPT)"
        else
            ok "ufw installed but inactive (not interfering). Enabling it later without rules WOULD break WireGuard and DNS"
        fi
    else
        info "ufw not installed"
    fi
    if have nft; then
        local n; n=$(nft list ruleset 2>/dev/null | grep -c 'chain')
        info "nft chains present: ${n} (iptables here is the nf_tables backend, so this is normal)"
    fi
    if have netfilter-persistent && systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then
        ok "netfilter-persistent restores saved rules at boot"
    elif grep -qE '^PostUp.*MASQUERADE' "/etc/wireguard/${WG_IF}.conf" 2>/dev/null; then
        ok "PostUp in ${WG_IF}.conf re-applies NAT at boot"
    else
        fail "nothing re-applies NAT/FORWARD rules after a reboot"
        add_fix "vi /etc/wireguard/${WG_IF}.conf -> add under [Interface]: PostUp = iptables -t nat -C POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${WG_NET} ! -d ${WG_NET} -j MASQUERADE"
    fi
}

# Usage: check_routing   -> policy routing / routes that could hijack wg traffic
check_routing() {
    section "Routing"
    local extra; extra=$(ip rule show 2>/dev/null | grep -vE '^(0|32766|32767):')
    if [ -n "$extra" ]; then warn "custom 'ip rule' entries exist (could redirect VPN traffic):"; echo "$extra" | sed 's/^/         /'
    else ok "no custom ip rules"; fi
    local dup; dup=$(ip route show 2>/dev/null | grep -F "${WG_NET%.*}." | grep -v "dev ${WG_IF}")
    if [ -n "$dup" ]; then fail "a route for ${WG_NET} exists outside ${WG_IF}:"; echo "$dup" | sed 's/^/         /'
    else ok "only ${WG_IF} routes ${WG_NET}"; fi
    info "default route: $(ip -4 route show default | head -n1)"
}

# Usage: check_failed_units   -> systemd failed units that matter here
check_failed_units() {
    section "Failed services"
    local f; f=$(systemctl --failed --no-legend 2>/dev/null | awk '{print $2}' | grep -E 'unbound|nginx|caddy|docker|wg-|netfilter|resolved|outline|certbot' )
    if [ -n "$f" ]; then warn "failed units: $(echo $f)"; add_fix "journalctl -u <unit> -n 50 --no-pager   for each failed unit above"
    else ok "no failed units among unbound/nginx/caddy/docker/wg/resolved"; fi
}

# Usage: check_gamedns   -> GameDNS DoH stack: gamedns-doh service, nginx, DoH/admin ports, certs, DNS name, local TLS tests
check_gamedns() {
    section "GameDNS DoH (gamedns-doh + nginx + certbot)"
    if ! systemctl list-unit-files 2>/dev/null | grep -q '^gamedns-doh'; then
        info "gamedns-doh service not installed on this host (skipping)"; return
    fi

    # 1. the Node service
    local svc; svc=$(systemctl is-active gamedns-doh 2>/dev/null)
    if [ "$svc" = "active" ]; then ok "gamedns-doh is active"
    else
        fail "gamedns-doh is ${svc:-unknown}"
        journalctl -u gamedns-doh -n 8 --no-pager 2>/dev/null | sed 's/^/         /'
        add_fix "journalctl -u gamedns-doh -n 50 --no-pager; systemctl restart gamedns-doh"
    fi

    # 2. nginx: running and config valid
    local ngt ports p domains d
    if have nginx; then
        ngt=$(nginx -T 2>/dev/null)
        if nginx -t >/dev/null 2>&1; then ok "nginx config test passes"
        else
            fail "nginx -t FAILS (nginx cannot (re)start, so the DoH and admin ports stay closed)"
            nginx -t 2>&1 | head -n 4 | sed 's/^/         /'
            add_fix "nginx -t   # fix the reported file with vi (often a missing certificate path), then: systemctl restart nginx"
        fi
    else
        fail "nginx is not installed"; ngt=""
    fi
    local ns; ns=$(systemctl is-active nginx 2>/dev/null)
    if [ "$ns" = "active" ]; then ok "nginx is active"
    else
        fail "nginx is ${ns:-unknown}: DoH (2083) and admin API (11112) cannot listen"
        journalctl -u nginx -n 8 --no-pager 2>/dev/null | sed 's/^/         /'
        add_fix "journalctl -u nginx -n 30 --no-pager; systemctl restart nginx"
    fi

    # 2b. nginx listeners that collide with Caddy (certbot --nginx and the default site add :80/:443)
    local clash
    clash=$(grep -E '^[[:space:]]*listen[[:space:]]' <<<"$ngt" | grep -E '(^|[^0-9])(80|443)([^0-9]|;|$)' | sort -u)
    if [ -n "$clash" ] && { owner_of 80 | grep -q caddy || owner_of 443 | grep -q caddy; }; then
        fail "nginx config has listeners on :80/:443 but Caddy owns them -> nginx can never start, so 2083/11112 stay down"
        echo "$clash" | sed 's/^/         /'
        add_fix "Remove the :80/:443 listeners from nginx (rm /etc/nginx/sites-enabled/default; edit /etc/nginx/conf.d/gamedns-doh.conf with vi), then: nginx -t && systemctl restart nginx"
    fi

    # 2c. certbot renewal method vs Caddy owning :80
    local rf a
    for rf in /etc/letsencrypt/renewal/*.conf; do
        [ -f "$rf" ] || continue
        a=$(sed -n 's/^authenticator *= *//p' "$rf" | head -n1)
        if { [ "$a" = "nginx" ] || [ "$a" = "standalone" ]; } && owner_of 80 | grep -q caddy; then
            fail "certbot renews $(basename "$rf" .conf) via '$a' but Caddy owns :80 -> renewal will fail when the cert comes due"
            add_fix "certbot reconfigure --cert-name $(basename "$rf" .conf) --authenticator webroot --webroot-path /var/www/certbot   (needs the Caddy ACME webroot block)"
        fi
    done

    # 3. which ports should be open (parsed from nginx; fallback to the manual's defaults)
    ports=$(grep -E '^[[:space:]]*listen[[:space:]]' <<<"$ngt" | grep -E 'ssl|http2' | grep -oE '[0-9]{2,5}' | sort -u | grep -vE '^(80|443)$')
    [ -z "$ports" ] && ports="2083 11112"
    for p in $ports; do
        local o; o=$(owner_of "$p")
        if [ -n "$o" ]; then ok "port $p is listening ($o)"
        else fail "nothing listens on port $p (connection refused: matches 'curl: (7) Failed to connect')"; fi
    done

    # 4. certificates referenced by nginx
    local certs c
    certs=$(grep -E '^[[:space:]]*ssl_certificate[[:space:]]' <<<"$ngt" | awk '{print $2}' | tr -d ';' | sort -u)
    for c in $certs; do
        if [ ! -f "$c" ]; then
            fail "nginx references a certificate that does not exist: $c"
            add_fix "certbot certificates   # then re-issue the missing cert (see certbot log lines below)"
        elif have openssl; then
            local end days
            end=$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)
            days=$(( ( $(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
            if [ "$days" -lt 0 ]; then fail "certificate EXPIRED: $c ($end)"
            elif [ "$days" -lt 14 ]; then warn "certificate expires in ${days} days: $c"
            else ok "certificate valid for ${days} more days: $c"; fi
        fi
    done

    # 5. certbot renewal health + the Caddy-owns-port-80 problem
    if systemctl is-active --quiet certbot.timer 2>/dev/null; then ok "certbot.timer is active"
    else warn "certbot.timer is not active: certificates will not auto-renew"; fi
    # renewal method: webroot (challenges served by Caddy) is fine; nginx/standalone cannot work while Caddy owns :80
    local nonweb=0 rf2
    for rf2 in /etc/letsencrypt/renewal/*.conf; do
        [ -f "$rf2" ] || continue
        grep -qE '^authenticator *= *webroot' "$rf2" || nonweb=1
    done
    if owner_of 80 | grep -q caddy; then
        if [ "$nonweb" -eq 0 ]; then
            ok "certbot renews via webroot, challenges served by Caddy on :80 (older log errors are historical)"
        else
            warn "Caddy owns :80 and a certificate does not use the webroot method: HTTP-01 renewal will fail"
            add_fix "certbot reconfigure --cert-name <name> --authenticator webroot --webroot-path /var/www/certbot ; certbot renew --dry-run"
        fi
    fi
    if [ -n "$(ls -A /etc/letsencrypt/renewal-hooks/deploy 2>/dev/null)" ]; then
        ok "certbot deploy hook present (nginx reload after renewal)"
    else
        warn "no certbot deploy hook: nginx will not reload after a real renewal"
        add_fix "printf '#!/bin/sh\\nsystemctl reload nginx\\n' > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh && chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh"
    fi

    # 6. DNS name -> this server?
    domains=$(grep -E '^[[:space:]]*server_name[[:space:]]' <<<"$ngt" | sed 's/server_name//; s/;//' | tr -s ' ' '\n' | grep -vE '^(_|localhost|)$' | sort -u)
    local mine; mine=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    for d in $domains; do
        local r; r=$(getent ahostsv4 "$d" 2>/dev/null | awk 'NR==1{print $1}')
        if [ -z "$r" ]; then fail "domain $d does not resolve"
        elif grep -qxF "$r" <<<"$mine"; then ok "domain $d -> $r (this server)"
        else warn "domain $d -> $r, which is NOT an address of this server (wrong host? e.g. the manual was for ca01, this is ger)"; fi
    done

    # 7. local TLS tests (bypass DNS with --resolve)
    d=$(echo $domains | awk '{print $1}')
    if [ -n "$d" ] && have curl; then
        for p in $ports; do
            local code; code=$(curl -sk -m 5 --resolve "${d}:${p}:127.0.0.1" -o /dev/null -w '%{http_code}' "https://${d}:${p}/" 2>/dev/null)
            if [ "${code:-000}" = "000" ]; then fail "local HTTPS test to ${d}:${p} gets no response"
            else ok "local HTTPS test to ${d}:${p} answered HTTP ${code} (401/403/404 here still means the service is up)"; fi
        done
    fi

    [ -f /var/lib/gamedns/keys.json ] && info "keys file present: /var/lib/gamedns/keys.json$(have jq && echo " ($(jq 'length' /var/lib/gamedns/keys.json 2>/dev/null) entries)")" \
        || warn "/var/lib/gamedns/keys.json not found"
    info "reminder: the admin API (11112) is open to the internet by design; the bearer token is the only gate. Consider restricting it to your management IPs."
}

# Usage: print_summary   -> totals and de-duplicated fix list
print_summary() {
    section "Summary"
    printf '  %sOK:%s %d   %sWARN:%s %d   %sFAIL:%s %d\n' "$C_G" "$C_0" "$PASS" "$C_Y" "$C_0" "$WARN" "$C_R" "$C_0" "$FAIL"
    if [ "${#FIXES[@]}" -gt 0 ]; then
        printf '\n  %sSuggested fixes (review before running):%s\n' "$C_B" "$C_0"
        local i=0 f
        while IFS= read -r f; do i=$((i+1)); printf '   %d. %s\n' "$i" "$f"; done < <(printf '%s\n' "${FIXES[@]}" | awk '!s[$0]++')
    fi
    printf '\n'
}

# Usage: main "$@"
main() {
    parse_args "$@"
    require_root
    setup_colors
    [ -n "$REPORT" ] && exec > >(tee "$REPORT") 2>&1
    printf '%sVPN interference check%s  %s  host=%s\n' "$C_B" "$C_0" "$(date '+%F %T %Z')" "$(hostname)"
    detect_env
    check_wireguard_alive
    check_port53
    check_dns_answers
    check_open_resolver
    check_web_ports
    check_gamedns
    check_port_collisions
    check_docker_outline
    check_firewall_ufw
    check_routing
    check_failed_units
    print_summary
    [ "$FAIL" -gt 0 ] && exit 1
    exit 0
}

main "$@"
