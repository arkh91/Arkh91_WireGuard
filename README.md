# Arkh91_WireGuard

Custom WireGuard VPS installer with an HTTPS management API (Node.js behind
Caddy), health tooling, and a restricted SSH account (`wg-monitor`) that lets
a central management server (e.g. "US08") pull traffic stats and enforce peer
limits.

`install-wg-full.sh` is the installer to use. It sets up everything in one
run: WireGuard, the API, the health tools, a daily health-check timer, and
(optionally) the `wg-monitor` account.

---

## Install

Run it directly from GitHub (arguments go **after** the closing `)`):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg-full.sh)
```
```bash
# non-interactive example
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg-full.sh) \
    --domain=vpn.example.com --port=39022 --https-port=2053 --yes
```

or from a local copy: `sudo ./install-wg-full.sh`.

Putting a flag *before* the closing `)` (for example `curl -Ls <url> --add-monitor`)
does not work: `curl` parses it as its own option and rejects it.

During an interactive install you are asked for:
1. A **domain** for the management API.
2. A **WireGuard UDP port**.
3. The **HTTPS port** of the API. The installer scans which of the Cloudflare-proxied
   HTTPS ports (443, 8443, 2053, 2083, 2087, 2096) are free and lets you pick one.
   Nothing ever listens on port 80.
4. The **TLS mode** (see below).

The `wg-monitor` SSH account is **optional and not asked about**: the HTTPS API
(including `GET /usage`) is all a manager such as Outline Manager or a polling script needs, using
`/etc/wg-api/access.json`. Only if you also want SSH-based enforcement (suspend, speed limits)
from a management server, add it with `--monitor-key-file=/root/wg_monitor_key.pub` at install
time or `--add-monitor` later (see [below](#1-generate-the-key-once-on-us08)).

At the end it prints **WIREGUARD SERVER INSTALLED** with the API URL, HTTPS port,
Bearer token, certificate fingerprint and ready-to-copy commands. The same access
details are saved in `/etc/wg-api/access.json`:

```json
{ "apiUrl": "https://vpn.example.com:2053", "apiToken": "...", "certSha256": "..." }
```

### Options

| Flag | Meaning |
|---|---|
| `--domain=NAME` | domain (or IP) clients use to reach the API |
| `--port=N` | WireGuard UDP port (default 51820) |
| `--https-port=N` | public HTTPS port of the API (443, 8443, 2053, 2083, 2087, 2096; asked if omitted) |
| `--tls=selfsigned\|letsencrypt` | `selfsigned` (default, pinned by fingerprint); `letsencrypt` only with `--https-port=443` |
| `--tls-cert=FILE --tls-key=FILE` | use your own certificate (copied, does not follow renewals) |
| `--api-port=N` | internal API port (default 4242, localhost only) |
| `--network253` | use `10.66.66.0/24` (253 keys, the old `install-wg3.sh` pool) instead of the default `10.66.0.0/16` |
| `--dns=IP[,IP]` | DNS handed to clients (default 1.1.1.1) |
| `--monitor-key="ssh-..."` / `--monitor-key-file=FILE` | `wg-monitor` public key of the management server |
| `--no-api` | WireGuard + tools only, no Caddy/Node/API |
| `--no-caddy` | install the API but not Caddy (when nginx or another web server already owns 80/443) |
| `--force` | replace an existing `wg0.conf` (a backup is made first) |
| `--yes`, `-y` | do not ask questions |

### Other actions

```bash
sudo ./install-wg-full.sh --add-monitor --monitor-key-file=/root/wg_monitor_key.pub  # add/repair wg-monitor on an installed node
sudo ./install-wg-full.sh --reconfigure-api   # change the API HTTPS port / certificate (WireGuard keys and peers untouched)
sudo ./install-wg-full.sh --update-api        # rewrite wg-api-helper and server.js to the current version (adds /usage); keys and peers untouched
sudo ./install-wg-full.sh --update-tools      # re-fetch wg-healthcheck.sh and vpn-doctor.sh
sudo ./install-wg-full.sh --uninstall         # remove everything this script installed
```

`--add-monitor` is the one to use for a node set up before the account existed,
or where SSH asks for a password instead of using the key.

---

## Management API

All endpoints except `/health` need the header `Authorization: Bearer <apiToken>`.

| Endpoint | Purpose |
|---|---|
| `POST /create` | create a key; returns the client config as text (`?format=json` for JSON) |
| `POST /remove` | remove a key, body `{"ipAddress":"10.66.0.2"}` |
| `GET /usage` | **all keys**: upload/download bytes, last handshake, plus totals |
| `GET /usage/<ip>` | usage of **one key**, e.g. `/usage/10.66.0.2` |
| `GET /health` | liveness check, no token needed |

Errors: `401` wrong or missing token, `400` malformed address or one that is not a client
address of this server, `404` unknown key, `503` address pool full.

A key is identified by its IP address. The default pool is `10.66.0.0/16`: the server is
`10.66.0.1` and keys are handed out from `10.66.0.2` up to `10.66.255.254`, **65,533 keys** in total.
With `--network253` the pool is `10.66.66.0/24` (`10.66.66.2` to `10.66.66.254`, **253 keys**).
The pool size is fixed when the server is installed; it cannot be changed afterwards without
reinstalling, because every client address and the server's own address would change.

```bash
# self-signed certificate: pin the public key instead of trusting a CA
PIN='sha256//<base64 pin, printed at the end of the install>'
TOKEN='<apiToken from /etc/wg-api/access.json>'
URL='https://vpn.example.com:2053'

curl --insecure --pinnedpubkey "$PIN" -X POST "$URL/create" -H "Authorization: Bearer $TOKEN"
curl --insecure --pinnedpubkey "$PIN" "$URL/usage"          -H "Authorization: Bearer $TOKEN"
curl --insecure --pinnedpubkey "$PIN" "$URL/usage/10.66.0.2" -H "Authorization: Bearer $TOKEN"
```

`GET /usage` response:

```json
{
  "interface": "wg0",
  "timestamp": "2026-10-16T09:13:41.825Z",
  "totals": { "uploadBytes": 1048576, "downloadBytes": 2097152, "totalBytes": 3145728 },
  "keys": [
    { "ipAddress": "10.66.0.2", "uploadBytes": 1048576, "downloadBytes": 2097152,
      "totalBytes": 3145728, "lastHandshake": "2026-10-16T09:10:00.000Z" }
  ]
}
```

* `uploadBytes` / `downloadBytes` are from the **client's** point of view
  (upload = what the client sent to the server).
* `lastHandshake` is `null` for a key that has never connected.
* Usage is **kept across `wg0` restarts and reboots**. WireGuard's own counters start
  from zero every time, so the server saves them to `/var/lib/wg-api/traffic.db`
  every minute (`wg-traffic.timer`) and once more just before `wg0` stops
  (`wg-traffic-save.service`, on shutdown, reboot and `systemctl restart wg-quick@wg0`),
  and reports saved + live. A hard power cut can lose at most the last minute.
  Servers installed before this version get it with `sudo ./install-wg-full.sh --update-api`.
* To collect usage from several servers, keep each server's domain, HTTPS port,
  token and pin (all in its `access.json`) and poll `/usage` on each.

### TLS modes and ports

* **selfsigned** (default): the certificate is made on the server and clients pin
  it, like Outline's `certSha256`. Works on any free HTTPS port.
  The curl pin is computed with:
  ```bash
  openssl x509 -in /etc/caddy/wg-api-tls/cert.pem -pubkey -noout \
    | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
  ```
  (a new certificate, and therefore a new pin, is created on every fresh install).
* **letsencrypt**: only on port 443, because validation needs the internet to reach 80 or 443.
* **Behind the Cloudflare proxy** (orange cloud) clients see Cloudflare's certificate:
  drop `--insecure`/`--pinnedpubkey` and set SSL/TLS mode to **Full**.
  Cloudflare only proxies the HTTPS ports 443, 2053, 2083, 2087, 2096 and 8443.

---

## Health tools

Installed in `/usr/local/bin` and also runnable straight from GitHub:

```bash
sudo wg-healthcheck.sh [--capture=20]      # health check (also runs daily from a systemd timer)
sudo vpn-doctor.sh [--fix] [--dry-run]     # diagnose and fix
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/wg-healthcheck.sh)
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/vpn-interference-check.sh)
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/vpn-doctor.sh)
```

Enforcement actions are logged: `journalctl -t wg-peer-ctrl -f`.

---

## Troubleshooting

* **`curl: (7) Failed to connect`**: wrong port or Caddy is down. Check the port in
  `/etc/wg-api/access.json`, then `systemctl is-active caddy wg-api` and
  `ss -ltnp | grep -E 'caddy|node'`.
* **`curl: (90) SSL: public key does not match pinned public key`**: the pin is from
  an older install, or a placeholder was left in the command. Recompute it (above).
* **`Cannot GET /usage`**: the server still runs an older `server.js`; run `--update-api`.
* **Caddy: `permission denied` on `/var/log/caddy/wg-api.log`**: fixed in the current
  installer; on an old install run `chown -R caddy:caddy /var/log/caddy && systemctl restart caddy`.

---

# WireGuard Monitoring Account (`wg-monitor`)

This is what lets the management server pull `wg show wg0 dump` output and
send enforcement commands (disable/enable/suspend/unsuspend/speed-limit)
over SSH, without ever giving it a real login on the VPN node.

As of this version, **all of the setup below is automated** by
`install-wg-full.sh` (either during install, or via `--add-monitor` on an
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
peer's third and fourth IP octet (`third * 256 + fourth`, in hex, which is what `tc` expects).
That is unique inside any single pool up to a `/16` (the default `10.66.0.0/16` as well as
`--network253`), and `1:ffff` is the unlimited default class. If a node ever hands out
addresses from more than one pool, this needs a proper class-ID allocator instead.
Limits set by an older version of the script used the last octet only; re-apply them
with `peer-setlimit` after upgrading.

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
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-suspend 10.66.0.X/32"
# on the VPN node: iptables -L WG-SUSPEND -n
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-unsuspend 10.66.0.X/32"

ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-setlimit 10.66.0.X/32 2000"
# on the VPN node: tc class show dev wg0 ; tc class show dev ifb0
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "peer-clearlimit 10.66.0.X/32"
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
