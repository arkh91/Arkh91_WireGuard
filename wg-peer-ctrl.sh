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

# Usage: audit <result> <message>
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
