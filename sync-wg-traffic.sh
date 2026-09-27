#!/bin/bash
# =============================================================================
# sync-wg-traffic.sh
#
# Run every 5 minutes via cron on the management server (US08).
# For each ACTIVE WireGuard server it:
#   1. Pulls peer stats via SSH (or locally for US08 itself)
#   2. Accumulates RX/TX deltas into wg_clients
#   3. Auto-expires peers that cross max_data_limit
#   4. Enforces peer state — expired=removed from wg, suspended=iptables block
#   5. Re-enables peers whose DB flag was cleared by the admin/bot
#   6. Applies/refreshes each active peer's speed_limit_kbps via tc
#
# Peer lifecycle:
#   ACTIVE     is_expired=0  is_suspended=0  → in wg, no iptables block, is_active=1
#   EXPIRED    is_expired=1                  → removed from wg,  is_active=0
#   SUSPENDED  is_suspended=1               → stays in wg, iptables DROP, is_active=0
#
# Re-enable expired peer (e.g. after topping up data):
#   UPDATE wg_clients SET is_expired=0, max_data_limit=<new_bytes> WHERE client_id=X;
#   → next cron run calls enable_peer() automatically
#
# Unsuspend peer:
#   UPDATE wg_clients SET is_suspended=0 WHERE client_id=X;
#   → next cron run calls unsuspend_peer() automatically
#
# Usage:
#   ./sync-wg-traffic.sh           — normal run
#   ./sync-wg-traffic.sh --debug   — verbose, no DB writes, no wg/iptables changes
#   DB_JS=/path/to/db.js ./sync-wg-traffic.sh
# =============================================================================

set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# DEBUG FLAG
# --debug: skips all writes (DB, wg, iptables, tc). Safe to run alongside live cron.
# ─────────────────────────────────────────────────────────────────────────────
DEBUG=0
[[ "${1:-}" == "--debug" ]] && DEBUG=1

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# Writes to stderr so log lines are never captured by $() subshells.
# In normal mode also appends to LOG_FILE.
# ─────────────────────────────────────────────────────────────────────────────
LOG_FILE="${LOG_FILE:-/var/log/sync-wg-traffic.log}"

# Usage: log <LEVEL> <message>
log() {
    local level="$1"; shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo "$msg" >&2
    [[ "$DEBUG" -eq 0 ]] && echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

# Usage: dbg <message>
# Prints only when --debug is active. Used for per-peer field dumps.
dbg() { [[ "$DEBUG" -eq 1 ]] && echo "  [DBG] $*" >&2 || true; }

# ─────────────────────────────────────────────────────────────────────────────
# LOCK FILE
# Prevents two cron runs from overlapping.
# Skipped in debug mode so --debug can run alongside a live sync.
# ─────────────────────────────────────────────────────────────────────────────
LOCK_FILE="/var/run/sync-wg-traffic.lock"

# Usage: acquire_lock
acquire_lock() {
    [[ "$DEBUG" -eq 1 ]] && return
    if [[ -e "$LOCK_FILE" ]]; then
        local old_pid; old_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            log "ERROR" "Already running (PID $old_pid). Exiting."
            exit 1
        fi
        rm -f "$LOCK_FILE"   # stale lock from a crashed run
    fi
    echo $$ > "$LOCK_FILE"
}

# Usage: cleanup
# Called automatically via trap on any exit. Removes temp files.
cleanup() {
    [[ -n "${MYSQL_CNF:-}" && -f "${MYSQL_CNF:-}" ]] && rm -f "$MYSQL_CNF"
    [[ "$DEBUG" -eq 0 ]] && rm -f "$LOCK_FILE" 2>/dev/null || true
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────────────
# DB CREDENTIALS — parsed from your Node.js db.js file
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Global DB vars populated by load_db_credentials()
DB_HOST=""; DB_PORT=""; DB_USER=""; DB_PASS=""; DB_NAME=""

# Usage: find_db_js
# Searches common locations for db.js. Override with: DB_JS=/path/to/db.js
find_db_js() {
    [[ -n "${DB_JS:-}" ]] && { echo "$DB_JS"; return; }
    local candidates=(
        "${SCRIPT_DIR}/db.js"
        "${SCRIPT_DIR}/../db.js"
        "${SCRIPT_DIR}/../config/db.js"
        "/root/RoyalVPN_bot/db.js"
        "/opt/vpnbot/db.js"
    )
    local p
    for p in "${candidates[@]}"; do
        [[ -f "$p" ]] && { echo "$p"; return; }
    done
    echo ""
}

# Usage: parse_db_js <file> <key>
# Extracts a value from db.js. Handles 'single' and "double" quotes,
# with or without a trailing comma.
parse_db_js() {
    grep -oP "${2}:\s*['\"]\\K[^'\"]*(?=['\"])" "$1" 2>/dev/null | head -1
}

# Usage: load_db_credentials
# Locates db.js, parses it, and sets DB_HOST/PORT/USER/PASS/NAME globals.
# Hard-exits if required fields are missing.
load_db_credentials() {
    local js_file; js_file=$(find_db_js)
    [[ -z "$js_file" ]] && {
        log "ERROR" "Cannot find db.js. Set: DB_JS=/path/to/db.js"
        exit 1
    }
    [[ ! -r "$js_file" ]] && {
        log "ERROR" "db.js not readable: $js_file"
        exit 1
    }

    DB_HOST=$(parse_db_js "$js_file" "host");     DB_HOST="${DB_HOST:-127.0.0.1}"
    DB_PORT=$(parse_db_js "$js_file" "port");     DB_PORT="${DB_PORT:-3306}"
    DB_USER=$(parse_db_js "$js_file" "user"    || echo "")
    DB_PASS=$(parse_db_js "$js_file" "password" || echo "")
    DB_NAME=$(parse_db_js "$js_file" "database" || echo "")

    local missing=()
    [[ -z "$DB_USER" ]] && missing+=("user")
    [[ -z "$DB_PASS" ]] && missing+=("password")
    [[ -z "$DB_NAME" ]] && missing+=("database")
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "ERROR" "Missing fields in db.js: ${missing[*]}"
        exit 1
    fi

    log "INFO" "DB loaded from: $js_file (host:${DB_HOST} db:${DB_NAME} user:${DB_USER})"
}

# ─────────────────────────────────────────────────────────────────────────────
# MYSQL TEMP CONFIG
# Credentials written to a chmod-600 temp file so they never appear in
# 'ps aux' and produce no "password on command line" warning.
# ─────────────────────────────────────────────────────────────────────────────
MYSQL_CNF=""

# Usage: setup_mysql_cnf
# Creates the temp credentials file. Must be called after load_db_credentials.
setup_mysql_cnf() {
    MYSQL_CNF=$(mktemp /tmp/.wg-sync-XXXXXX.cnf)
    chmod 600 "$MYSQL_CNF"
    cat > "$MYSQL_CNF" <<EOF
[client]
host     = ${DB_HOST}
port     = ${DB_PORT}
user     = ${DB_USER}
password = ${DB_PASS}
database = ${DB_NAME}
EOF
}

# Usage: db_query <sql>
# Runs a SELECT and returns tab-separated rows on stdout.
db_query() {
    mysql --defaults-extra-file="$MYSQL_CNF" --silent --skip-column-names \
        -e "$1" 2>&1
}

# Usage: db_exec <sql>
# Runs INSERT/UPDATE/DELETE or a transaction block.
# In --debug mode prints the SQL to stderr and does nothing.
db_exec() {
    if [[ "$DEBUG" -eq 1 ]]; then
        echo "$1" | sed 's/^/  [SQL] /' >&2
        return 0
    fi
    mysql --defaults-extra-file="$MYSQL_CNF" --silent --skip-column-names \
        -e "$1" 2>&1
}

# ─────────────────────────────────────────────────────────────────────────────
# SSH CONFIG
# ─────────────────────────────────────────────────────────────────────────────
SSH_USER="${SSH_USER:-wg-monitor}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-/root/.ssh/wg_monitor_key}"
SSH_TIMEOUT="${SSH_TIMEOUT:-10}"

# ─────────────────────────────────────────────────────────────────────────────
# LOCAL IP DETECTION
# ─────────────────────────────────────────────────────────────────────────────
LOCAL_IPS=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -v '^$')

# Usage: is_local_ip <ip>
# Returns 0 (true) if the IP belongs to this machine.
# Used to skip SSH and call wg/iptables/tc directly for the local server.
is_local_ip() { echo "$LOCAL_IPS" | grep -qF "$1"; }

# ─────────────────────────────────────────────────────────────────────────────
# SSH HELPER
# -T : no PTY allocation (suppresses "PTY allocation failed" warning)
# -n : stdin from /dev/null — CRITICAL: prevents SSH from consuming the
#      while-read loop's stdin, which would silently skip remaining servers
# ─────────────────────────────────────────────────────────────────────────────

# Usage: ssh_run <host> [command]
# Runs a command on a remote server via the wg-monitor SSH key.
# With no command, ForceCommand on the remote (wg-peer-ctrl.sh) takes over.
ssh_run() {
    local host="$1"; shift
    ssh -T -n \
        -i "$SSH_KEY" \
        -p "$SSH_PORT" \
        -o ConnectTimeout="$SSH_TIMEOUT" \
        -o StrictHostKeyChecking=no \
        -o BatchMode=yes \
        -o LogLevel=ERROR \
        "${SSH_USER}@${host}" "$@"
}

# Usage: local_ctrl <command...>
# Runs a wg-peer-ctrl.sh verb directly on this machine (US08 itself),
# bypassing SSH entirely. Mirrors ssh_run's calling convention.
local_ctrl() {
    /usr/local/bin/wg-peer-ctrl.sh "$@"
}

# ─────────────────────────────────────────────────────────────────────────────
# WG DUMP
# ─────────────────────────────────────────────────────────────────────────────

# Usage: get_wg_dump <server_ip>
# Returns raw tab-separated "wg show wg0 dump" output.
# Runs wg locally for this machine; goes via SSH for remote servers.
# ForceCommand on remote servers runs wg-peer-ctrl.sh with no SSH_ORIGINAL_COMMAND,
# which defaults to "wg show wg0 dump".
get_wg_dump() {
    local server_ip="$1"
    if is_local_ip "$server_ip"; then
        wg show wg0 dump 2>/dev/null
    else
        ssh_run "$server_ip"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# PEER OPERATIONS
#
# EXPIRED  peers → disable_peer  / enable_peer
#   Removes/restores the peer from WireGuard entirely.
#   An expired peer cannot connect at all.
#
# SUSPENDED peers → suspend_peer / unsuspend_peer
#   Peer STAYS in WireGuard (handshakes succeed) but all forwarded traffic
#   is dropped via iptables FORWARD rules. The client "connects" but gets
#   no data. Used for temporary blocks (overdue payment, manual hold, etc.)
#
# ACTIVE peers with a cap → set_speed_limit / clear_speed_limit
#   Peer stays fully connected; a tc bandwidth cap throttles both
#   directions instead of blocking traffic outright.
#
# Remote servers: commands sent to wg-peer-ctrl.sh via SSH (see README).
# Local server  : wg/iptables/tc called directly (script runs as root).
# ─────────────────────────────────────────────────────────────────────────────

# Usage: disable_peer <server_ip> <pubkey> <client_id>
# Removes the peer from WireGuard. Peer cannot connect until re-enabled.
# Called when is_expired=1 or when max_data_limit is first crossed.
disable_peer() {
    local server_ip="$1" pubkey="$2" client_id="$3"
    log "INFO" "  [DISABLE] client_id=${client_id} pubkey=${pubkey:0:20}…"

    if [[ "$DEBUG" -eq 1 ]]; then
        dbg "would run: wg set wg0 peer ${pubkey:0:20}… remove"
        return 0
    fi

    local result="" exit_code=0
    if is_local_ip "$server_ip"; then
        result=$(wg set wg0 peer "$pubkey" remove 2>&1) || exit_code=$?
    else
        result=$(ssh_run "$server_ip" "peer-disable $pubkey" 2>&1) || exit_code=$?
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        log "INFO"  "  [DISABLE] ✓ peer removed from wg"
    else
        log "ERROR" "  [DISABLE] ✗ failed: ${result}"
    fi
    return "$exit_code"
}

# Usage: enable_peer <server_ip> <pubkey> <allowed_ips> <client_id>
# Re-adds the peer to WireGuard using its IP from the DB.
# Called when a previously expired peer has is_expired reset to 0.
enable_peer() {
    local server_ip="$1" pubkey="$2" allowed_ips="$3" client_id="$4"
    log "INFO" "  [ENABLE] client_id=${client_id} pubkey=${pubkey:0:20}… ip=${allowed_ips}"

    if [[ "$DEBUG" -eq 1 ]]; then
        dbg "would run: wg set wg0 peer ${pubkey:0:20}… allowed-ips ${allowed_ips}"
        return 0
    fi

    if [[ -z "$allowed_ips" ]]; then
        log "ERROR" "  [ENABLE] ✗ no IP address for client_id=${client_id}"
        return 1
    fi

    local result="" exit_code=0
    if is_local_ip "$server_ip"; then
        result=$(wg set wg0 peer "$pubkey" allowed-ips "$allowed_ips" 2>&1) || exit_code=$?
    else
        result=$(ssh_run "$server_ip" "peer-enable $pubkey $allowed_ips" 2>&1) || exit_code=$?
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        db_exec "UPDATE wg_clients
                 SET    is_active    = 1,
                        last_poll_at = '$(date '+%Y-%m-%d %H:%M:%S.000')'
                 WHERE  client_id   = ${client_id};"
        log "INFO"  "  [ENABLE] ✓ peer re-added to wg"
    else
        log "ERROR" "  [ENABLE] ✗ failed: ${result}"
    fi
    return "$exit_code"
}

# Usage: suspend_peer <server_ip> <allowed_ips> <client_id>
# Adds iptables FORWARD DROP rules for this peer's IP.
# Peer stays in WireGuard — handshakes work, data packets are silently dropped.
# Idempotent: checks rule existence with -C before inserting.
suspend_peer() {
    local server_ip="$1" allowed_ips="$2" client_id="$3"
    log "INFO" "  [SUSPEND] client_id=${client_id} ip=${allowed_ips}"

    if [[ -z "$allowed_ips" ]]; then
        log "ERROR" "  [SUSPEND] ✗ no IP for client_id=${client_id} — cannot add iptables rule"
        return 1
    fi

    if [[ "$DEBUG" -eq 1 ]]; then
        dbg "would run: iptables DROP on ${allowed_ips}"
        return 0
    fi

    local result="" exit_code=0
    if is_local_ip "$server_ip"; then
        result=$(local_ctrl peer-suspend "$allowed_ips" 2>&1) || exit_code=$?
    else
        result=$(ssh_run "$server_ip" "peer-suspend $allowed_ips" 2>&1) || exit_code=$?
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        log "INFO"  "  [SUSPEND] ✓ iptables DROP rules in place"
    else
        log "ERROR" "  [SUSPEND] ✗ failed: ${result}"
    fi
    return "$exit_code"
}

# Usage: unsuspend_peer <server_ip> <allowed_ips> <client_id>
# Removes iptables FORWARD DROP rules, restoring normal traffic.
# Called when is_suspended is reset to 0 in DB.
# Idempotent: safe to call even if no rules exist.
unsuspend_peer() {
    local server_ip="$1" allowed_ips="$2" client_id="$3"
    log "INFO" "  [UNSUSPEND] client_id=${client_id} ip=${allowed_ips}"

    if [[ -z "$allowed_ips" ]]; then
        log "ERROR" "  [UNSUSPEND] ✗ no IP for client_id=${client_id}"
        return 1
    fi

    if [[ "$DEBUG" -eq 1 ]]; then
        dbg "would run: iptables unblock ${allowed_ips}"
        return 0
    fi

    local result="" exit_code=0
    if is_local_ip "$server_ip"; then
        result=$(local_ctrl peer-unsuspend "$allowed_ips" 2>&1) || exit_code=$?
    else
        result=$(ssh_run "$server_ip" "peer-unsuspend $allowed_ips" 2>&1) || exit_code=$?
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        log "INFO"  "  [UNSUSPEND] ✓ iptables DROP rules removed"
    else
        log "ERROR" "  [UNSUSPEND] ✗ failed: ${result}"
    fi
    return "$exit_code"
}

# Usage: set_speed_limit <server_ip> <allowed_ips> <kbps> <client_id>
# Applies (or refreshes) a bandwidth cap for this peer via tc, both directions.
# Called every cycle for any active peer with speed_limit_kbps > 0 — cheap
# and idempotent (tc "replace", not "add"), so it also self-heals the cap
# after a server reboot: unlike iptables-persistent, tc rules do not
# survive a restart on their own.
set_speed_limit() {
    local server_ip="$1" allowed_ips="$2" kbps="$3" client_id="$4"
    log "INFO" "  [SETLIMIT] client_id=${client_id} ip=${allowed_ips} kbps=${kbps}"

    if [[ -z "$allowed_ips" || "$kbps" -le 0 ]]; then
        log "ERROR" "  [SETLIMIT] ✗ missing ip or kbps for client_id=${client_id}"
        return 1
    fi

    if [[ "$DEBUG" -eq 1 ]]; then
        dbg "would run: peer-setlimit ${allowed_ips} ${kbps}"
        return 0
    fi

    local result="" exit_code=0
    if is_local_ip "$server_ip"; then
        result=$(local_ctrl peer-setlimit "$allowed_ips" "$kbps" 2>&1) || exit_code=$?
    else
        result=$(ssh_run "$server_ip" "peer-setlimit $allowed_ips $kbps" 2>&1) || exit_code=$?
    fi

    if [[ "$exit_code" -eq 0 ]]; then
        log "INFO"  "  [SETLIMIT] ✓ ${kbps}kbps applied"
    else
        log "ERROR" "  [SETLIMIT] ✗ failed: ${result}"
    fi
    return "$exit_code"
}

# Usage: clear_speed_limit <server_ip> <allowed_ips> <client_id>
# Removes any tc shaping for this peer. Safe to call even if none exists —
# called every cycle for peers with no speed_limit_kbps set, so clearing
# the value in the DB actually removes a previously-applied cap.
clear_speed_limit() {
    local server_ip="$1" allowed_ips="$2" client_id="$3"
    [[ -z "$allowed_ips" ]] && return 0

    log "INFO" "  [CLEARLIMIT] client_id=${client_id} ip=${allowed_ips}"

    if [[ "$DEBUG" -eq 1 ]]; then
        dbg "would run: peer-clearlimit ${allowed_ips}"
        return 0
    fi

    local result="" exit_code=0
    if is_local_ip "$server_ip"; then
        result=$(local_ctrl peer-clearlimit "$allowed_ips" 2>&1) || exit_code=$?
    else
        result=$(ssh_run "$server_ip" "peer-clearlimit $allowed_ips" 2>&1) || exit_code=$?
    fi

    [[ "$exit_code" -ne 0 ]] && log "ERROR" "  [CLEARLIMIT] ✗ failed: ${result}"
    return "$exit_code"
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

# Usage: unix_to_mysql_dt <unix_timestamp>
# Converts a Unix epoch integer to MySQL datetime(3) format.
unix_to_mysql_dt() {
    date -d "@${1}" '+%Y-%m-%d %H:%M:%S.000' 2>/dev/null || echo ""
}

# Usage: normalize_cidr <address>
# Ensures address is in CIDR notation (appends /32 if no prefix is present).
# iptables/tc require CIDR; the DB may store bare IPs.
normalize_cidr() {
    local addr="${1:-}"
    [[ -n "$addr" && "$addr" != */* ]] && addr="${addr}/32"
    echo "$addr"
}

# Usage: build_update_sql <cid> <new_rx> <new_tx> <wg_rx> <wg_tx> \
#                         <hs_sql> <is_active> <total_new> <now_mysql>
# Returns a single UPDATE statement for one peer row.
# is_expired flips to 1 automatically (via CASE) when total >= max_data_limit,
# so expiry is always atomic with the traffic write — no separate UPDATE needed.
# last_rx/tx_snapshot stores the raw wg counter so the next run can compute
# the correct delta even after a wg restart resets the counters to zero.
build_update_sql() {
    local cid="$1"     new_rx="$2"   new_tx="$3"
    local wg_rx="$4"   wg_tx="$5"    hs_sql="$6"
    local is_act="$7"  total="$8"    now="$9"
    cat <<SQL
UPDATE wg_clients SET
    rx_bytes         = ${new_rx},
    tx_bytes         = ${new_tx},
    last_rx_snapshot = ${wg_rx},
    last_tx_snapshot = ${wg_tx},
    last_handshake   = ${hs_sql},
    is_active        = ${is_act},
    is_expired       = CASE
                           WHEN max_data_limit IS NOT NULL
                            AND max_data_limit > 0
                            AND ${total} >= max_data_limit THEN 1
                           ELSE is_expired
                       END,
    last_poll_at     = '${now}'
WHERE client_id = ${cid};
SQL
}

# ─────────────────────────────────────────────────────────────────────────────
# PROCESS ONE SERVER
# ─────────────────────────────────────────────────────────────────────────────

# Usage: process_server <server_name> <server_ip>
# Full sync cycle for one VPN server:
#   1. Pull wg dump (local or SSH)
#   2. Strip sudo noise, validate interface row
#   3. Load all DB clients for this server into CLIENT_MAP (one query)
#   4. Walk wg dump peers → classify, build SQL batch + action queues
#      (including per-cycle speed-limit apply/clear for active peers)
#   5. Walk DB peers not in the dump → queue re-enable or re-suspend
#   6. Commit DB transaction
#   7. Execute wg/iptables/tc actions (after DB is safely written)
process_server() {
    local SERVER_NAME="$1"
    local SERVER_IP="$2"
    # Capture timestamp at the start of THIS server's run so last_poll_at
    # reflects when each server was actually polled, not the cron start time.
    local NOW_MYSQL; NOW_MYSQL=$(date '+%Y-%m-%d %H:%M:%S.000')

    log "INFO" "──── Server: $SERVER_NAME ($SERVER_IP) ────"

    # ── 1. Pull wg dump ───────────────────────────────────────────────────────
    local RAW_DUMP=""
    RAW_DUMP=$(get_wg_dump "$SERVER_IP") || true

    if [[ -z "$RAW_DUMP" ]]; then
        if is_local_ip "$SERVER_IP"; then
            log "WARN" "  No output from local wg. Is wg0 running? Try: wg show wg0 dump"
        else
            log "WARN" "  No output from $SERVER_IP — SSH failed or wg not running."
        fi
        return 0
    fi

    # ── 2. Validate interface row (exactly 4 tab-separated fields) ────────────
    # sudo on some servers prints a warning before the wg output.
    # Detect and strip non-interface lines before processing peers.
    if [[ $(echo "$RAW_DUMP" | head -1 | awk -F'\t' '{print NF}') -ne 4 ]]; then
        log "WARN" "  Sudo noise detected — stripping non-interface lines..."
        RAW_DUMP=$(echo "$RAW_DUMP" | awk -F'\t' 'NF==4{found=1} found{print}')
        if [[ $(echo "$RAW_DUMP" | head -1 | awk -F'\t' '{print NF}') -ne 4 ]]; then
            log "ERROR" "  Cannot find valid interface row. Skipping $SERVER_NAME."
            return 0
        fi
    fi
    dbg "Interface row: $(echo "$RAW_DUMP" | head -1 | cut -c1-80)"

    # Peer lines start at line 2 (line 1 is the interface row)
    local PEER_LINES=""
    PEER_LINES=$(echo "$RAW_DUMP" | tail -n +2)
    if [[ -z "$PEER_LINES" ]]; then
        log "INFO" "  No peers configured on $SERVER_NAME."
        return 0
    fi
    log "INFO" "  Got $(echo "$PEER_LINES" | wc -l) peer(s) from wg."

    # ── 3. Load all DB clients in one query ───────────────────────────────────
    # CLIENT_MAP[pubkey] = "cid|rx|tx|snap_rx|snap_tx|is_act|is_exp|is_susp|is_del|max_limit|speed_kbps|address"
    declare -A CLIENT_MAP=()
    declare -A SEEN_IN_DUMP=()

    local DB_CLIENTS=""
    DB_CLIENTS=$(db_query "
        SELECT public_key,
               client_id,
               COALESCE(rx_bytes,         0),
               COALESCE(tx_bytes,         0),
               COALESCE(last_rx_snapshot, 0),
               COALESCE(last_tx_snapshot, 0),
               is_active,
               is_expired,
               is_suspended,
               is_deleted,
               COALESCE(max_data_limit,   0),
               COALESCE(speed_limit_kbps, 0),
               COALESCE(address,         '')
        FROM   wg_clients
        WHERE  server_name = '${SERVER_NAME}'
          AND  is_deleted  = 0;
    ") || {
        log "ERROR" "  DB query failed for $SERVER_NAME."
        unset CLIENT_MAP SEEN_IN_DUMP
        return 0
    }

    if [[ -z "$DB_CLIENTS" ]]; then
        log "WARN" "  No clients in DB for server_name='${SERVER_NAME}' (case-sensitive)."
        unset CLIENT_MAP SEEN_IN_DUMP
        return 0
    fi

    # Populate CLIENT_MAP — one entry per peer
    local PK="" CID="" RX="" TX="" SRX="" STX="" \
          IACT="" IEXP="" ISUSP="" IDEL="" MLIM="" SPD="" ADDR=""
    while IFS=$'\t' read -r PK CID RX TX SRX STX IACT IEXP ISUSP IDEL MLIM SPD ADDR; do
        [[ -z "${PK:-}" ]] && continue
        # FIX: ensure ADDR is always defined and in CIDR notation
        ADDR=$(normalize_cidr "${ADDR:-}")
        CLIENT_MAP["$PK"]="${CID}|${RX}|${TX}|${SRX}|${STX}|${IACT}|${IEXP}|${ISUSP}|${IDEL}|${MLIM}|${SPD}|${ADDR}"
    done <<< "$DB_CLIENTS"

    log "INFO" "  Loaded ${#CLIENT_MAP[@]} client(s) from DB."

    # ── 4. Process peers in wg dump ───────────────────────────────────────────
    local SQL_BATCH=""
    local -a DISABLE_Q=()     # expired peers  → remove from wg
    local -a SUSPEND_Q=()     # suspended peers → ensure iptables block
    local -a UNSUSPEND_Q=()   # peers whose suspension was lifted → remove block
    local -a SETLIMIT_Q=()    # active peers with a speed cap → (re)apply every cycle
    local -a CLEARLIMIT_Q=()  # active peers with no cap → ensure no stale limit remains
    local UPDATED=0 DISABLED=0 SUSPENDED=0 UNSUSPENDED=0 SKIPPED=0

    local PUBKEY="" _P="" _E="" _A="" LAST_HS="" WG_RX="" WG_TX="" _KA=""
    while IFS=$'\t' read -r PUBKEY _P _E _A LAST_HS WG_RX WG_TX _KA; do
        [[ -z "${PUBKEY:-}" ]] && continue
        SEEN_IN_DUMP["$PUBKEY"]=1

        # ── Peer in wg but missing from DB ────────────────────────────────────
        if [[ -z "${CLIENT_MAP[$PUBKEY]+_}" ]]; then
            log "WARN" "  !! ${PUBKEY:0:20}… is in WireGuard but NOT in wg_clients."
            log "WARN" "     Add it to DB or remove it from wg: wg set wg0 peer ${PUBKEY:0:20}… remove"
            (( SKIPPED++ )) || true
            continue
        fi

        # Unpack DB row — FIX: initialize ALL locals to safe defaults first
        CID="0"; RX="0"; TX="0"; SRX="0"; STX="0"
        IACT="0"; IEXP="0"; ISUSP="0"; IDEL="0"; MLIM="0"; SPD="0"; ADDR=""
        IFS='|' read -r CID RX TX SRX STX IACT IEXP ISUSP IDEL MLIM SPD ADDR \
            <<< "${CLIENT_MAP[$PUBKEY]}"

        # Sanitise numeric fields — replace anything non-numeric with 0
        local var
        for var in WG_RX WG_TX SRX STX RX TX LAST_HS MLIM SPD CID; do
            [[ "${!var}" =~ ^[0-9]+$ ]] || printf -v "$var" '%s' '0'
        done

        # last_handshake: stored for reference — does not affect active status
        local HS_SQL="NULL"
        if [[ "${LAST_HS:-0}" -gt 0 ]]; then
            local HS_DT; HS_DT=$(unix_to_mysql_dt "$LAST_HS")
            [[ -n "$HS_DT" ]] && HS_SQL="'${HS_DT}'"
        fi

        # Delta traffic — wg counters reset to 0 when the interface restarts.
        # If current < snapshot, a restart happened: treat current value as delta.
        local DELTA_RX=0 DELTA_TX=0
        if [[ "$WG_RX" -ge "$SRX" ]]; then
            DELTA_RX=$(( WG_RX - SRX ))
        else
            log "INFO" "  [${PUBKEY:0:20}…] RX counter reset (${SRX} → ${WG_RX})"
            DELTA_RX=$WG_RX
        fi
        if [[ "$WG_TX" -ge "$STX" ]]; then
            DELTA_TX=$(( WG_TX - STX ))
        else
            log "INFO" "  [${PUBKEY:0:20}…] TX counter reset (${STX} → ${WG_TX})"
            DELTA_TX=$WG_TX
        fi

        local NEW_RX=$(( RX + DELTA_RX ))
        local NEW_TX=$(( TX + DELTA_TX ))
        local TOTAL=$(( NEW_RX + NEW_TX ))

        # ════════════════════════════════════════════════════════════════════
        # CASE A — Peer is EXPIRED
        # Should not be in wg. Save traffic then remove it.
        # ════════════════════════════════════════════════════════════════════
        if [[ "$IEXP" -eq 1 ]]; then
            log "WARN" "  [${PUBKEY:0:20}…] expired but still in wg — will disable."
            SQL_BATCH+=$(build_update_sql \
                "$CID" "$NEW_RX" "$NEW_TX" "$WG_RX" "$WG_TX" \
                "$HS_SQL" "0" "$TOTAL" "$NOW_MYSQL")
            DISABLE_Q+=("${PUBKEY}|${CID}")
            (( DISABLED++ )) || true
            continue
        fi

        # ════════════════════════════════════════════════════════════════════
        # CASE B — Peer is SUSPENDED
        # Stays in wg, but traffic is blocked by iptables.
        # Re-apply the iptables block every run (idempotent via -C check).
        # ════════════════════════════════════════════════════════════════════
        if [[ "$ISUSP" -eq 1 ]]; then
            log "INFO" "  [${PUBKEY:0:20}…] suspended — updating traffic, ensuring block."
            SQL_BATCH+=$(build_update_sql \
                "$CID" "$NEW_RX" "$NEW_TX" "$WG_RX" "$WG_TX" \
                "$HS_SQL" "0" "$TOTAL" "$NOW_MYSQL")
            SUSPEND_Q+=("${ADDR}|${CID}")
            (( SUSPENDED++ )) || true
            continue
        fi

        # ════════════════════════════════════════════════════════════════════
        # CASE C — Peer just crossed max_data_limit THIS cycle
        # is_expired flips to 1 in the SQL CASE. Remove from wg after commit.
        # ════════════════════════════════════════════════════════════════════
        if [[ "$MLIM" -gt 0 && "$TOTAL" -ge "$MLIM" ]]; then
            log "WARN" "  [${PUBKEY:0:20}…] limit reached (${TOTAL} >= ${MLIM} bytes) — expiring."
            SQL_BATCH+=$(build_update_sql \
                "$CID" "$NEW_RX" "$NEW_TX" "$WG_RX" "$WG_TX" \
                "$HS_SQL" "0" "$TOTAL" "$NOW_MYSQL")
            DISABLE_Q+=("${PUBKEY}|${CID}")
            (( DISABLED++ )) || true
            continue
        fi

        # ════════════════════════════════════════════════════════════════════
        # CASE D — Normal active peer
        # is_active=1: peer exists in wg and is connectable.
        # If it was previously suspended (is_active was 0, is_susp now 0),
        # queue an unsuspend to remove any lingering iptables rules.
        # Also (re)apply or clear its speed cap every cycle: active peers
        # are the only ones actually passing traffic, so shaping only
        # matters here — an expired or suspended peer is already blocked.
        # ════════════════════════════════════════════════════════════════════
        # Only queue unsuspend if the peer has a valid IP address.
        # Empty ADDR means the DB record has no address — nothing to unblock.
        if [[ "$IACT" -eq 0 && -n "$ADDR" ]]; then
            # Peer was previously inactive — may have a stale iptables block
            # from a prior suspension that was cleared in DB.
            UNSUSPEND_Q+=("${ADDR}|${CID}")
        fi

        if [[ -n "$ADDR" ]]; then
            if [[ "$SPD" -gt 0 ]]; then
                SETLIMIT_Q+=("${ADDR}|${SPD}|${CID}")
            else
                CLEARLIMIT_Q+=("${ADDR}|${CID}")
            fi
        fi

        dbg "[${PUBKEY:0:20}…] +RX:${DELTA_RX}B +TX:${DELTA_TX}B total:${TOTAL}B"
        log "INFO" "  [${PUBKEY:0:20}…] +RX:${DELTA_RX}  +TX:${DELTA_TX}  total:${TOTAL}  active"
        SQL_BATCH+=$(build_update_sql \
            "$CID" "$NEW_RX" "$NEW_TX" "$WG_RX" "$WG_TX" \
            "$HS_SQL" "1" "$TOTAL" "$NOW_MYSQL")
        (( UPDATED++ )) || true

    done <<< "$PEER_LINES"

    # ── 5. Handle DB peers NOT found in the wg dump ───────────────────────────
    local -a ENABLE_Q=()     # peers to re-add to wg (normal peers gone missing)
    local -a RESUSPEND_Q=()  # suspended peers that disappeared — re-add + re-block
    local REENABLED=0

    for PK in "${!CLIENT_MAP[@]}"; do
        [[ -n "${SEEN_IN_DUMP[$PK]+_}" ]] && continue

        # Reset locals for each iteration
        CID="0"; IACT="0"; IEXP="0"; ISUSP="0"; IDEL="0"; MLIM="0"; SPD="0"; ADDR=""
        IFS='|' read -r CID _ _ _ _ IACT IEXP ISUSP IDEL MLIM _ ADDR \
            <<< "${CLIENT_MAP[$PK]}"

        [[ "$IDEL" -eq 1 ]] && continue   # already soft-deleted — ignore

        if [[ "$IEXP" -eq 1 ]]; then
            # Expected absence: expired peer was correctly removed from wg.
            # Ensure is_active=0 in case it was never updated.
            if [[ "$IACT" -eq 1 ]]; then
                SQL_BATCH+="
UPDATE wg_clients
SET    is_active    = 0,
       last_poll_at = '${NOW_MYSQL}'
WHERE  client_id   = ${CID};"
            fi

        elif [[ "$ISUSP" -eq 1 ]]; then
            # Suspended peers should REMAIN in wg (only iptables blocks them).
            # If missing, something removed it externally — re-add and re-block.
            log "WARN" "  [${PK:0:20}…] suspended but missing from wg — will re-add and block."
            RESUSPEND_Q+=("${PK}|${ADDR}|${CID}")
            (( REENABLED++ )) || true

        else
            # Normal peer missing from wg — re-add it.
            # Happens after a wg restart, external removal, or admin re-enabling.
            log "INFO" "  [${PK:0:20}…] should be active but not in wg — queuing re-enable."
            ENABLE_Q+=("${PK}|${ADDR}|${CID}")
            (( REENABLED++ )) || true
        fi
    done

    # ── 6. Commit all DB changes in one transaction ───────────────────────────
    if [[ -n "$SQL_BATCH" ]]; then
        local TX_RESULT=""
        TX_RESULT=$(db_exec "START TRANSACTION; ${SQL_BATCH} COMMIT;") || {
            log "ERROR" "  DB transaction failed: $TX_RESULT"
            db_exec "ROLLBACK;" 2>/dev/null || true
            unset CLIENT_MAP SEEN_IN_DUMP
            return 0
        }
    fi

    # ── 7. Execute wg / iptables / tc actions (always after DB commit) ────────
    local ITEM="" KPUBKEY="" KADDR="" KCID="" KSPD=""

    for ITEM in "${DISABLE_Q[@]+"${DISABLE_Q[@]}"}"; do
        KPUBKEY=""; KCID=""
        IFS='|' read -r KPUBKEY KCID <<< "$ITEM"
        disable_peer "$SERVER_IP" "$KPUBKEY" "$KCID"
    done

    for ITEM in "${SUSPEND_Q[@]+"${SUSPEND_Q[@]}"}"; do
        KADDR=""; KCID=""
        IFS='|' read -r KADDR KCID <<< "$ITEM"
        suspend_peer "$SERVER_IP" "$KADDR" "$KCID"
    done

    for ITEM in "${UNSUSPEND_Q[@]+"${UNSUSPEND_Q[@]}"}"; do
        KADDR=""; KCID=""
        IFS='|' read -r KADDR KCID <<< "$ITEM"
        unsuspend_peer "$SERVER_IP" "$KADDR" "$KCID" && (( UNSUSPENDED++ )) || true
    done

    for ITEM in "${ENABLE_Q[@]+"${ENABLE_Q[@]}"}"; do
        KPUBKEY=""; KADDR=""; KCID=""
        IFS='|' read -r KPUBKEY KADDR KCID <<< "$ITEM"
        enable_peer "$SERVER_IP" "$KPUBKEY" "$KADDR" "$KCID"
    done

    for ITEM in "${RESUSPEND_Q[@]+"${RESUSPEND_Q[@]}"}"; do
        KPUBKEY=""; KADDR=""; KCID=""
        IFS='|' read -r KPUBKEY KADDR KCID <<< "$ITEM"
        enable_peer  "$SERVER_IP" "$KPUBKEY" "$KADDR" "$KCID"
        suspend_peer "$SERVER_IP" "$KADDR" "$KCID"
    done

    for ITEM in "${SETLIMIT_Q[@]+"${SETLIMIT_Q[@]}"}"; do
        KADDR=""; KSPD=""; KCID=""
        IFS='|' read -r KADDR KSPD KCID <<< "$ITEM"
        set_speed_limit "$SERVER_IP" "$KADDR" "$KSPD" "$KCID"
    done

    for ITEM in "${CLEARLIMIT_Q[@]+"${CLEARLIMIT_Q[@]}"}"; do
        KADDR=""; KCID=""
        IFS='|' read -r KADDR KCID <<< "$ITEM"
        clear_speed_limit "$SERVER_IP" "$KADDR" "$KCID"
    done

    log "INFO" "  ✓ updated:${UPDATED}  disabled:${DISABLED}  suspended:${SUSPENDED}  unsuspended:${UNSUSPENDED}  re-enabled:${REENABLED}  skipped:${SKIPPED}"
    unset CLIENT_MAP SEEN_IN_DUMP
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

# Usage: main [--debug]
# Entry point. Loads DB credentials, acquires lock, fetches ACTIVE server list,
# then calls process_server() for each one.
main() {
    load_db_credentials
    setup_mysql_cnf
    acquire_lock

    [[ "$DEBUG" -eq 1 ]] && log "INFO" "========== DEBUG MODE — no writes =========="
    log "INFO" "========== sync-wg-traffic start =========="

    local SERVERS=""
    SERVERS=$(db_query "
        SELECT ServerName, IPAddress
        FROM   vpn_servers
        WHERE  Status    = 'ACTIVE'
          AND  IPAddress IS NOT NULL
          AND  IPAddress != ''
        ORDER  BY ServerID;
    ") || {
        log "ERROR" "Failed to query vpn_servers."
        exit 1
    }

    if [[ -z "$SERVERS" ]]; then
        log "INFO" "No active servers found."
        exit 0
    fi
    log "INFO" "Found $(echo "$SERVERS" | wc -l) active server(s)."

    # -n on ssh_run prevents SSH consuming this loop's stdin
    local SERVER_NAME="" SERVER_IP=""
    while IFS=$'\t' read -r SERVER_NAME SERVER_IP; do
        [[ -z "${SERVER_NAME:-}" || -z "${SERVER_IP:-}" ]] && continue
        process_server "$SERVER_NAME" "$SERVER_IP"
    done <<< "$SERVERS"

    log "INFO" "========== sync-wg-traffic done =========="
}

main "$@"
