# Arkh91_WireGuard

Custom WireGuard VPS installer with a Node.js/Caddy management API and a
restricted SSH account (`wg-monitor`) that lets a central management server
(e.g. "US08") pull traffic stats and enforce peer limits.

---

## ✅ How you'll run it

```bash
./install-wg3.sh
```

or, run directly from GitHub without downloading first:

```bash
# Standard port
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg.sh)

# Custom port
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install_wg_custom_port.sh)
```

Anything after the closing `)` is passed straight through to the script as
its own arguments, so `--add-monitor` (or `--uninstall`, `--port=...`, etc.)
works the same way here as it does on a local copy:

```bash
# Add/repair wg-monitor on a node installed this way, without a full reinstall
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install_wg_custom_port.sh) --add-monitor
```

Putting `--add-monitor` (or any flag) *before* the closing `)` — e.g.
`curl -Ls <url> --add-monitor` — won't work: `curl` parses it as its own
option, not the script's, and rejects it as unrecognized.

During interactive install you'll be asked for:
1. A domain (for the HTTPS management API via Caddy)
2. A WireGuard UDP port
3. **The management server's `wg-monitor` public key** (paste the contents of
   `/root/.ssh/wg_monitor_key.pub` from US08 — see [below](#1-generate-the-key-once-on-us08)).
   Leave this blank to skip and add it later.

Other entry points:

```bash
sudo ./install-wg3.sh --uninstall      # remove everything this script installed
sudo ./install-wg3.sh --add-monitor    # add/repair wg-monitor on an ALREADY-installed node
sudo ./install-wg3.sh --port=51830     # custom WireGuard port
sudo ./install-wg3.sh --api-port=4000  # custom internal API port
```

`--add-monitor` is the one you want for any node that was set up before this
account existed, or where SSH is currently asking for a password instead of
using the key.

---

# WireGuard Monitoring Account (`wg-monitor`)

This is what lets the management server pull `wg show wg0 dump` output and
send enforcement commands (disable/enable/suspend/unsuspend/speed-limit)
over SSH, without ever giving it a real login on the VPN node.

As of this version, **all of the setup below is automated** by
`install-wg3.sh` (either during install, or via `--add-monitor` on an
existing node). This section documents what it does and why, both so you
can verify it and so you can do it by hand if you're ever working on a node
without the installer.

## 1. Generate the key (once, on US08)

```bash
ssh-keygen -t ed25519 -f /root/.ssh/wg_monitor_key -N ""
```

One keypair is reused across every VPN node — only the **public** half
(`wg_monitor_key.pub`) ever leaves US08.

## 2. What the installer does on each VPN node

```bash
useradd -r -s /bin/bash -M wg-monitor
```

**Important — shell must be `/bin/bash`, not `/usr/sbin/nologin`.**
This is the opposite of what you'd expect for a locked-down account, and it
bit us once already: `sshd`'s `ForceCommand` is executed *through* the
account's login shell, as `<shell> -c "<forced command>"` — not instead of
it. `nologin` ignores whatever it's given and just prints
`This account is currently not available.`, which silently breaks
`ForceCommand` entirely. The account is still fully locked down —
`PermitTTY no` means there's no usable terminal even though the shell
exists, and `ForceCommand` always overrides whatever command the client
sends — so `bash` here costs nothing in security.

```bash
mkdir -p /home/wg-monitor/.ssh
chown -R wg-monitor:wg-monitor /home/wg-monitor
chmod 700 /home/wg-monitor/.ssh
echo "PASTE_US08_PUBLIC_KEY_HERE" > /home/wg-monitor/.ssh/authorized_keys
chown wg-monitor:wg-monitor /home/wg-monitor/.ssh/authorized_keys
chmod 600 /home/wg-monitor/.ssh/authorized_keys
```

```bash
# /etc/sudoers.d/wg-monitor
Defaults!/usr/local/bin/wg-peer-ctrl.sh env_keep += "SSH_ORIGINAL_COMMAND"
wg-monitor ALL=(root) NOPASSWD: /usr/local/bin/wg-peer-ctrl.sh
```

The `env_keep` line matters: `sudo` strips `SSH_ORIGINAL_COMMAND` from the
environment by default, and without this, every call — including
`peer-disable`, `peer-suspend`, etc. — would silently fall through to the
no-argument case and just return the traffic dump instead of doing
anything.

```text
# appended to /etc/ssh/sshd_config

Match User wg-monitor
    PasswordAuthentication no
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    ForceCommand sudo /usr/local/bin/wg-peer-ctrl.sh
```

```bash
sshd -t && systemctl reload ssh
```

The installer never reloads `sshd` on an unchecked config — `sshd -t` must
pass first, since a bad edit here can lock out every SSH session on the
box, not just `wg-monitor`'s.

## 3. `wg-peer-ctrl.sh` — the dispatcher

This is the *only* thing `wg-monitor` can ever execute. It reads
`SSH_ORIGINAL_COMMAND` (or plain `argv`, for local calls on US08 itself)
and validates every argument before touching anything.

| Command | Effect |
|---|---|
| *(empty)* | `wg show wg0 dump` — traffic sync |
| `peer-disable <pubkey>` | Remove peer from WireGuard entirely (expired) |
| `peer-enable <pubkey> <cidr>` | Re-add peer with its allowed-ips |
| `peer-suspend <cidr>` | Block peer's traffic via a dedicated `WG-SUSPEND` iptables chain (peer stays in wg, handshakes still work) |
| `peer-unsuspend <cidr>` | Remove the block |
| `peer-setlimit <cidr> <kbps>` | Cap the peer's bandwidth, both directions, via `tc` (htb + an `ifb0` device for the upload side) |
| `peer-clearlimit <cidr>` | Remove the cap |

Every call is logged via `logger -t wg-peer-ctrl`, viewable with:

```bash
journalctl -t wg-peer-ctrl -f
```

Any command outside this list — including something like `rm -rf /` sent
over the same channel — is rejected with `ERROR: command not permitted`
and logged as a `DENY`.

**Speed-limit note:** `peer-setlimit` derives its `tc` class ID from the
peer's last IP octet, which only works cleanly because every peer comes
from one flat `10.66.66.0/24` pool (per this installer's `getNextIP()`). If
a node ever hands out addresses from more than one subnet, this needs a
proper class-ID allocator instead.

---

## Testing

Work from safest to riskiest.

### 1. Sanity-check the account, on the VPN node

```bash
id wg-monitor                                    # exists, /bin/bash, no error
grep -A6 "Match User wg-monitor" /etc/ssh/sshd_config
cat /etc/sudoers.d/wg-monitor
visudo -c
```

If `sshd -T` is available, ask it what it will *actually* apply — this is
the authoritative answer, more reliable than re-reading the raw file:

```bash
sshd -T -C user=wg-monitor,host=<US08_HOSTNAME>,addr=<US08_IP> \
    | grep -iE "forcecommand|permittty|passwordauthentication"
```

Expect:
```
passwordauthentication no
permittty no
forcecommand sudo /usr/local/bin/wg-peer-ctrl.sh
```

### 2. Read-only test, from US08 (changes nothing)

```bash
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP
```

Expect the `wg show wg0 dump` output (interface line + one line per peer,
tab-separated) and no shell prompt. `PTY allocation request failed on
channel 0` above it is expected noise from `PermitTTY no` — not an error.

If you instead get `This account is currently not available.`, the
account's shell is still `nologin` — run `usermod -s /bin/bash wg-monitor`
on that node and retest.

### 3. Write verbs, against a throwaway peer

```bash
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-suspend 10.66.66.X/32"
# on the VPN node: iptables -L WG-SUSPEND -n
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-unsuspend 10.66.66.X/32"

ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-setlimit 10.66.66.X/32 2000"
# on the VPN node: tc class show dev wg0 ; tc class show dev ifb0
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-clearlimit 10.66.66.X/32"
```

Each should print `OK: ...`, and `journalctl -t wg-peer-ctrl -n 20` should
show a matching `result=OK` line per command.

### 4. Confirm rejection works

```bash
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "rm -rf /"
```

Expect `ERROR: command not permitted` and a `result=DENY` line in the
journal. This is what actually protects you if the key ever leaks — if
this ever returns anything else, stop and fix the sudoers/`ForceCommand`
setup before relying on it.

### 5. Dry-run the sync script, from US08

```bash
LOG_FILE=/tmp/sync-test.log ./sync-wg-traffic.sh --debug
```

`--debug` makes zero writes anywhere (no DB, no `wg`, no `iptables`, no
`tc`) — it only logs what it *would* do. Confirm the server and its peers
show up with sane RX/TX deltas and no `ERROR` lines before running it for
real.

---

## Retrofitting nodes installed before this version

Any node set up from an older copy of this repo has two known issues,
both fixed by re-running the installer with `--add-monitor`:

1. **No `wg-monitor` account at all** — SSH from US08 falls back to asking
   for a password.
2. **`wg-monitor` shell set to `nologin`** — SSH connects and authenticates,
   but every session fails with `This account is currently not available.`
   Fix directly with `usermod -s /bin/bash wg-monitor`, or just re-run
   `--add-monitor`, which repairs this automatically.

---

## Security notes

* Keep `wg_monitor_key` (the private half) on US08 only, mode `600`.
* `wg-monitor` can never obtain an interactive shell — no PTY, no
  forwarding of any kind, and `ForceCommand` always wins over whatever the
  client asks for.
* Every accepted and rejected command is logged (`journalctl -t wg-peer-ctrl`).
* HTTPS management API tokens (from `/create`/`/remove`) are separate from
  this account entirely and should be rotated if ever pasted somewhere
  they could leak.
