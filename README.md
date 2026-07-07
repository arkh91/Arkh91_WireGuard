# Arkh91 WireGuard — VPN Server Setup

## Overview

Two scripts work together:

- **`install-wg.sh`** — installs WireGuard on a new VPN server
- **`sync-wg-traffic.sh`** — runs on US08 every 5 minutes to sync traffic, enforce data limits, and manage peer state

---

## Architecture

```
US08 (management server)
├── sync-wg-traffic.sh       ← cron every 5 min
├── /root/RoyalVPN_bot/db.js ← credentials (auto-read by sync script)
└── /root/.ssh/wg_monitor_key  ← SSH key to all VPN servers

VPN Servers (Ger27, IT, Sweden, Thai02 ...)
├── WireGuard (wg0)
├── wg-monitor user          ← SSH-only, ForceCommand locked
└── /usr/local/bin/wg-peer-ctrl  ← command dispatcher
```

---

## Peer Lifecycle

| State     | DB flags                      | In wg | iptables | is_active |
|-----------|-------------------------------|-------|----------|-----------|
| ACTIVE    | is_expired=0  is_suspended=0  | Yes   | No block | 1         |
| EXPIRED   | is_expired=1                  | No    | —        | 0         |
| SUSPENDED | is_suspended=1                | Yes   | DROP     | 0         |

Re-enable expired peer (e.g. data top-up):
```sql
UPDATE wg_clients SET is_expired=0, max_data_limit=<new_bytes> WHERE client_id=X;
```
Next sync run re-adds the peer to WireGuard automatically.

Unsuspend peer:
```sql
UPDATE wg_clients SET is_suspended=0 WHERE client_id=X;
```
Next sync run removes the iptables block automatically.

---

## Install WireGuard on a New Server

```bash
# Standard port
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg.sh)

# Custom port
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install_wg_custom_port.sh)
```

Then run the wg-monitor setup below before adding the server to `vpn_servers`.

---

## wg-monitor Setup (Every VPN Server)

### Why each step matters

- **bash shell** — `nologin` silently kills the SSH session before `ForceCommand`
  runs. "This account is currently not available." is the symptom.
- **wg-peer-ctrl** — dispatcher that validates and routes SSH commands; rejects
  anything not in the allowlist
- **Expanded sudoers** — old setup only allowed `wg show`; disable/enable/suspend
  also need `wg set` and `iptables`

---

### Step 1 — Create the monitoring user

```bash
# Shell must be bash — ForceCommand requires a real shell to execute
useradd -r -s /bin/bash -M wg-monitor
```

---

### Step 2 — Create the SSH directory

```bash
mkdir -p /home/wg-monitor/.ssh
chown -R wg-monitor:wg-monitor /home/wg-monitor
chmod 700 /home/wg-monitor/.ssh
```

---

### Step 3 — Add the management server public key

On US08, generate the key if not already done:

```bash
ssh-keygen -t ed25519 -f /root/.ssh/wg_monitor_key -N ""
cat /root/.ssh/wg_monitor_key.pub    # copy this line — starts with ssh-ed25519 AAAA...
```

**Never share `wg_monitor_key` (private key). Only copy `wg_monitor_key.pub`.**

On the VPN server:

```bash
echo "ssh-ed25519 AAAA...PASTE_FULL_LINE_HERE" >> /home/wg-monitor/.ssh/authorized_keys
chown wg-monitor:wg-monitor /home/wg-monitor/.ssh/authorized_keys
chmod 600 /home/wg-monitor/.ssh/authorized_keys
```

---

### Step 4 — Install wg-peer-ctrl

This is the `ForceCommand` script. It reads `$SSH_ORIGINAL_COMMAND` and only
allows five specific operations. Everything else is rejected.

```bash
vi /usr/local/bin/wg-peer-ctrl
```

Paste the following:

```bash
#!/bin/bash
# wg-peer-ctrl — ForceCommand dispatcher for wg-monitor SSH sessions.
# Reads SSH_ORIGINAL_COMMAND to determine which wg/iptables operation to run.
#
# Permitted commands (sent by sync-wg-traffic.sh):
#   (empty)                       -> wg show wg0 dump       (traffic sync)
#   peer-disable <pubkey>         -> wg set ... remove      (expire peer)
#   peer-enable  <pubkey> <cidr>  -> wg set ... allowed-ips (re-enable peer)
#   peer-suspend   <cidr>         -> iptables DROP           (suspend peer)
#   peer-unsuspend <cidr>         -> remove iptables DROP    (unsuspend peer)

set -euo pipefail

WG_IFACE="wg0"
WG="/usr/bin/wg"
IPT="/sbin/iptables"

# Usage: is_valid_pubkey <key>
# Validates a WireGuard public key: base64, exactly 44 chars ending in =
is_valid_pubkey() { [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]; }

# Usage: is_valid_cidr <address>
# Validates an IP/CIDR address like 10.66.66.5/32
is_valid_cidr() { [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]]; }

CMD="${SSH_ORIGINAL_COMMAND:-}"

case "$CMD" in

    "")
        sudo "$WG" show "$WG_IFACE" dump
        ;;

    peer-disable\ *)
        PUBKEY="${CMD#peer-disable }"
        is_valid_pubkey "$PUBKEY" || { echo "ERROR: invalid pubkey" >&2; exit 1; }
        sudo "$WG" set "$WG_IFACE" peer "$PUBKEY" remove
        echo "OK: peer removed"
        ;;

    peer-enable\ *\ *)
        PUBKEY=$(echo "$CMD" | awk '{print $2}')
        ALLOWED_IPS=$(echo "$CMD" | awk '{print $3}')
        is_valid_pubkey "$PUBKEY"     || { echo "ERROR: invalid pubkey" >&2;   exit 1; }
        is_valid_cidr  "$ALLOWED_IPS" || { echo "ERROR: invalid IP/CIDR" >&2; exit 1; }
        sudo "$WG" set "$WG_IFACE" peer "$PUBKEY" allowed-ips "$ALLOWED_IPS"
        echo "OK: peer enabled with $ALLOWED_IPS"
        ;;

    peer-suspend\ *)
        IP="${CMD#peer-suspend }"
        is_valid_cidr "$IP" || { echo "ERROR: invalid IP/CIDR" >&2; exit 1; }
        sudo "$IPT" -C FORWARD -s "$IP" -j DROP 2>/dev/null \
            || sudo "$IPT" -I FORWARD -s "$IP" -j DROP
        sudo "$IPT" -C FORWARD -d "$IP" -j DROP 2>/dev/null \
            || sudo "$IPT" -I FORWARD -d "$IP" -j DROP
        echo "OK: iptables DROP in place for $IP"
        ;;

    peer-unsuspend\ *)
        IP="${CMD#peer-unsuspend }"
        is_valid_cidr "$IP" || { echo "ERROR: invalid IP/CIDR" >&2; exit 1; }
        sudo "$IPT" -C FORWARD -s "$IP" -j DROP 2>/dev/null \
            && sudo "$IPT" -D FORWARD -s "$IP" -j DROP || true
        sudo "$IPT" -C FORWARD -d "$IP" -j DROP 2>/dev/null \
            && sudo "$IPT" -D FORWARD -d "$IP" -j DROP || true
        echo "OK: iptables DROP removed for $IP"
        ;;

    *)
        echo "ERROR: command not permitted: $CMD" >&2
        exit 1
        ;;
esac
```

```bash
chmod 755 /usr/local/bin/wg-peer-ctrl
```

---

### Step 5 — Update sudoers

```bash
vi /etc/sudoers.d/wg-monitor
```

Replace the entire file with:

```
Defaults:wg-monitor !lecture
Defaults:wg-monitor !fqdn

wg-monitor ALL=(root) NOPASSWD: /usr/bin/wg show wg0 dump
wg-monitor ALL=(root) NOPASSWD: /usr/bin/wg set wg0 peer * remove
wg-monitor ALL=(root) NOPASSWD: /usr/bin/wg set wg0 peer * allowed-ips *
wg-monitor ALL=(root) NOPASSWD: /sbin/iptables -C FORWARD *
wg-monitor ALL=(root) NOPASSWD: /sbin/iptables -I FORWARD *
wg-monitor ALL=(root) NOPASSWD: /sbin/iptables -D FORWARD *
```

```bash
chmod 440 /etc/sudoers.d/wg-monitor
visudo -c && echo "sudoers OK"
```

---

### Step 6 — Update sshd_config

```bash
# Remove existing wg-monitor Match block
sed -i '/^Match User wg-monitor$/,/^$/d' /etc/ssh/sshd_config

# Append updated block
cat >> /etc/ssh/sshd_config << 'SSHEOF'

Match User wg-monitor
    PasswordAuthentication  no
    PermitTTY               no
    AllowAgentForwarding    no
    AllowTcpForwarding      no
    X11Forwarding           no
    ForceCommand            /usr/local/bin/wg-peer-ctrl
SSHEOF

sshd -t && echo "sshd config OK"
systemctl reload ssh
```

---

### Step 7 — Verify from US08

```bash
SERVER_IP="<VPN_SERVER_IP>"

# Must return wg dump output (tab-separated peer rows)
ssh -T -n -i /root/.ssh/wg_monitor_key wg-monitor@$SERVER_IP

# Must return: OK: iptables DROP in place for 10.66.66.5/32
ssh -T -n -i /root/.ssh/wg_monitor_key wg-monitor@$SERVER_IP 'peer-suspend 10.66.66.5/32'

# Must return: OK: iptables DROP removed for 10.66.66.5/32
ssh -T -n -i /root/.ssh/wg_monitor_key wg-monitor@$SERVER_IP 'peer-unsuspend 10.66.66.5/32'

# Must return non-zero exit and: ERROR: command not permitted
ssh -T -n -i /root/.ssh/wg_monitor_key wg-monitor@$SERVER_IP 'id'; echo "exit: $?"
```

---

### Upgrading an Existing Server

If the server has the old setup (sudoers with only `wg show`, hardcoded ForceCommand):

1. Fix the shell if it is still nologin: `usermod -s /bin/bash wg-monitor`
2. Run Steps 4–6 only (user and key are already in place)

---

## sync-wg-traffic.sh (Management Server — US08 Only)

### Deploy

```bash
cp sync-wg-traffic.sh /root/RoyalVPN_bot/sync-wg-traffic.sh
chmod +x /root/RoyalVPN_bot/sync-wg-traffic.sh
```

Credentials are read automatically from `db.js`. Override the path with:
`DB_JS=/other/path/db.js ./sync-wg-traffic.sh`

### Test (dry run — no writes)

```bash
bash /root/RoyalVPN_bot/sync-wg-traffic.sh --debug 2>&1 | tee /tmp/wg-debug.txt
```

Confirm output per server:
```
[INFO] Got 24 peer(s) from wg.
[INFO] Loaded 21 client(s) from DB.
[INFO] [NfhFNyzKpc4tap37SWJ9...] +RX:0  +TX:0  total:0  active
[INFO] updated:21  disabled:0  suspended:0  unsuspended:0  re-enabled:0  skipped:3
```

### First live run

```bash
bash /root/RoyalVPN_bot/sync-wg-traffic.sh

mysql -u root -p irvpn -e \
  "SELECT client_id, server_name, is_active, last_poll_at
   FROM wg_clients ORDER BY last_poll_at DESC LIMIT 10;"
```

### Cron

```bash
echo "*/5 * * * * root /root/RoyalVPN_bot/sync-wg-traffic.sh" \
    > /etc/cron.d/sync-wg-traffic
chmod 644 /etc/cron.d/sync-wg-traffic
tail -f /var/log/sync-wg-traffic.log
```

### US08 does not need wg-monitor

The sync script detects when the target IP is the local machine and calls `wg`
and `iptables` directly as root, bypassing SSH entirely.

---

## Security Model

| Layer | Mechanism |
|---|---|
| SSH auth | ed25519 key only — password disabled |
| Shell lock | ForceCommand overrides any command the client sends |
| Command allowlist | wg-peer-ctrl rejects everything except 5 known commands |
| Input validation | pubkeys and IPs validated by regex before any sudo call |
| Credential safety | DB password in chmod-600 temp file — never in ps aux |
| Overlap prevention | Lock file prevents cron pile-up |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `This account is currently not available` | Shell is nologin | `usermod -s /bin/bash wg-monitor` |
| `Permission denied (publickey)` | Wrong key | Confirm pub key matches authorized_keys |
| `sudo: unable to resolve host X.vm` | Hostname not in /etc/hosts | `echo "127.0.1.1 $(hostname)" >> /etc/hosts` |
| Servers 3+ silently skipped | SSH consuming loop stdin | Use latest sync script (has -n flag) |
| `ADDR: unbound variable` | Old script version | Replace with latest sync-wg-traffic.sh |
| Peer `!! NOT in wg_clients` every run | Orphan peer from install-wg.sh | `peer-disable <pubkey>` via SSH |
| `ERROR: command not permitted` | wg-peer-ctrl working correctly | Expected for any disallowed command |
