# Arkh91_WireGuard

Custom WireGuard VPS installer with an HTTPS management API (Node.js behind
Caddy), health tooling, and a restricted SSH account (`wg-monitor`) that lets
a central management server (e.g. "US08") pull traffic stats and enforce peer
limits.

`install-wg-full.sh` is the installer to use. It sets up everything in one
run: WireGuard, the firewall rules, the API, the health tools, a daily health-check
timer, and (optionally) the `wg-monitor` account.

Current version: **2.3.0** (API 2.3).

New in 2.3.0:
* **End on:** a time limit that ends at a fixed date and time, counted on the **server's clock** (its own
  time zone): `{"expiresOn":"2026-12-31 18:00"}` (a date alone, `"2026-12-31"`, means the end of that day).
  A time that has already passed is refused (HTTP 400, with the server's current time). The key is blocked
  at that moment, like any expired key. `GET /server` now reports `timeZone`, `utcOffset` and `serverClock`; every
  key has `expiresAtServer` (its end on the server's clock). `{"expires":"2026-12-31"}` now also means the
  server's clock, not UTC. Mithra WireGuard Manager 1.3.5 has it as *Ends on a date and time (server time)*.

New in 2.2.2:
* Time limits also take **years** (`"1y"`, `"2 years"`; stored as 12 / 24 calendar months). Hours
  (`"12h"`) already worked; Mithra WireGuard Manager 1.3.4 offers hours, days, weeks, months and years.

New in 2.2.1:
* **First connection and last handshake are stored for every key** (`/var/lib/wg-api/traffic.db`,
  with the usage), so they survive `wg0` restarts and reboots. `firstConnectedAt` and `lastHandshake`
  are in every key of `GET /keys`.
* **Removing a key removes everything stored about it:** usage, handshakes, its stored config and
  its pause / traffic / time limits. A new key that later gets the same address starts clean. Keys
  removed by hand from `wg0.conf` are cleaned up the same way on the next minute's check.
* Time limits "from first connection" now count from the key's real first connection.

New in 2.2:
* **Time limit per key:** ends after N days / weeks / months **from now** (or on a date), or N days /
  weeks / months **from the key's first connection**. An expired key is blocked until it gets a new
  time limit. From the API and from Mithra WireGuard Manager 1.3 (see [Time limits](#time-limits)).

New in 2.1:
* **Pause / resume** a key, and a **traffic limit** per key (or unlimited), from the API and from
  Mithra WireGuard Manager. A key can also be created at a chosen address with a limit.
* **Client isolation:** VPN clients can no longer reach each other, private / cloud-metadata
  networks, or the server's own services.
* **Suspensions can't be bypassed:** paused, over-limit and suspended keys are always checked
  first, and stay blocked across restarts and reboots.
* **No IPv6 leak:** client configs send IPv6 into the tunnel (`AllowedIPs = 0.0.0.0/0, ::/0`).
* **Checked downloads:** the health tools come from a fixed commit and must match a SHA-256;
  no script is piped from NodeSource; npm packages are pinned.
* The access config lines in the installer's summary are printed in **green** (2.1.1).

Already running an older version? See [Updating installed servers](#updating-installed-servers).

---

## Install

Recommended: download the script, check its SHA-256, then run it. The script runs as root, so this
makes sure you run exactly the reviewed 2.3.0 file (if `main` has moved on, the check fails and nothing
runs: use the command from the newer README or the app):

```bash
curl -fsSLo install-wg-full.sh https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg-full.sh
echo "71ecfb389a70b6c98535096c09f0dcf5f920bd054a3ee9f136a88234e1fb7625  install-wg-full.sh" | sha256sum -c -
sudo bash install-wg-full.sh
```
```bash
# non-interactive example (flags go after the script name)
sudo bash install-wg-full.sh --domain=vpn.example.com --port=39022 --https-port=2053 --yes
```

Mithra WireGuard Manager's **Add server** screen shows the same command with a Copy button.

Quick but unchecked (always runs whatever is on `main` at that moment; arguments go **after** the closing `)`):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg-full.sh)
```

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
Bearer token, certificate fingerprint and ready-to-copy commands. The two **access config**
lines (the ones starting with `{"apiUrl"`) are printed in **green** so they are easy to find:
paste either one into Mithra WireGuard Manager (**Add server**). Both open every key on the
server, so treat them like passwords. They are also saved on the server:

```bash
sudo cat /etc/wg-api/access.json           # {"apiUrl":"https://vpn.example.com:2053","apiToken":"...","certSha256":"..."}
sudo cat /etc/wg-api/access-outline.json   # {"apiUrl":"https://vpn.example.com:2053/<secret>","certSha256":"..."}  (Outline format)
```

(The colour is only used on a terminal; piped output and `NO_COLOR=1` stay plain.)

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
| `--allow-client-to-client` | let VPN clients reach each other (default: blocked) |
| `--allow-private-nets` | let VPN clients reach private, link-local (cloud metadata) and CGNAT addresses (default: blocked) |
| `--force` | replace an existing `wg0.conf` (a backup is made first) |
| `--yes`, `-y` | do not ask questions |

### Other actions

```bash
sudo ./install-wg-full.sh --add-monitor --monitor-key-file=/root/wg_monitor_key.pub  # add/repair wg-monitor on an installed node
sudo ./install-wg-full.sh --reconfigure-api   # change the API HTTPS port / certificate (WireGuard keys and peers untouched)
sudo ./install-wg-full.sh --update-api        # bring an installed server to this version: API, helper, firewall; keys and peers untouched
sudo ./install-wg-full.sh --update-firewall   # only the firewall part of --update-api (live, no restart)
sudo ./install-wg-full.sh --update-tools      # re-fetch wg-healthcheck.sh and vpn-doctor.sh (checked against their SHA-256)
sudo ./install-wg-full.sh --uninstall         # remove everything this script installed
```

`--add-monitor` is the one to use for a node set up before the account existed,
or where SSH asks for a password instead of using the key.

Started without arguments, the script shows a menu; option **6** is the same as `--update-api`.

---

## Updating installed servers

Every server installed with an older `install-wg-full.sh` is brought to 2.3.0 with one command
(also servers already on 2.1.x: that adds the time limits).
It keeps every key, peer, token, certificate and the HTTPS port; `wg0` is **not** restarted, so
connected clients stay connected (only `wg-api` restarts, for a second or two).

On each server:

```bash
curl -fsSLo install-wg-full.sh https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg-full.sh
echo "71ecfb389a70b6c98535096c09f0dcf5f920bd054a3ee9f136a88234e1fb7625  install-wg-full.sh" | sha256sum -c -
sudo bash install-wg-full.sh --update-api
```

Mithra WireGuard Manager 1.2 shows this command (with a Copy button) on every server that still
runs an older API, together with the note that pause and traffic limits need the update.

What `--update-api` changes:

1. **Firewall:** installs `/usr/local/bin/wg-firewall.sh`, replaces the old filter lines in
   `wg0.conf`'s PostUp/PostDown with it (the NAT lines and all `[Peer]` blocks stay; a backup
   `wg0.conf.bak-<date>` is made) and applies the new rules live. Suspensions that existed only
   in iptables are carried over to `/etc/wireguard/suspended.list`.
2. **API:** rewrites `wg-api-helper` and `server.js` (API 2.3), reinstalls the pinned npm
   packages, makes `/opt/wg-api` owned by root, rewrites `wg-api.service` and restarts it.
3. **wg-peer-ctrl.sh:** suspensions from the management server now go through the same
   state file, so they survive restarts.
4. Prints both access configs again (in green).

**Afterwards:** client configs now contain `AllowedIPs = 0.0.0.0/0, ::/0`. Devices that imported a
key **before** the update still have the old config; re-import it once (QR code or `.conf` from
the app, or `GET /keys/<ip>`) to stop IPv6 from bypassing the tunnel.

Check a server after the update:

```bash
sudo wg-firewall.sh status | head -12       # FORWARD starts with -j WG-SUSPEND, then WG-GUARD
curl --insecure --pinnedpubkey "$PIN" "$URL/server" -H "Authorization: Bearer $TOKEN"   # "apiVersion":"2.2"
```

Many servers at once, from a machine that can SSH to them as root:

```bash
for h in us08.example.com de01.example.com; do
  ssh root@"$h" 'curl -fsSLo /root/install-wg-full.sh https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg-full.sh &&
    echo "71ecfb389a70b6c98535096c09f0dcf5f920bd054a3ee9f136a88234e1fb7625  /root/install-wg-full.sh" | sha256sum -c - &&
    bash /root/install-wg-full.sh --update-api --yes' || echo "FAILED: $h"
done
```

---

## Management API

All endpoints except `/health` need the header `Authorization: Bearer <apiToken>`
(or, with the Outline-format access config, the secret path: `https://host:port/<secret>/keys`).

| Endpoint | Purpose |
|---|---|
| `POST /create` | create a key; returns the client config as text (`?format=json` for JSON). Optional body `{"name":"Ali phone","ipAddress":"10.66.0.2","traffic":"20G","expires":"30d"}` (or `"expiresAfterFirstConnection":"1m"`) |
| `POST /access-keys` | same as `/create?format=json`, answers `201` (Outline Manager's call) |
| `GET /keys` (also `GET /`, `GET /access-keys`) | **all keys** with their full settings, ready config, usage, pause and limit state |
| `GET /keys/<ip>` | one key |
| `PUT /keys/<ip>/name` | rename, body `{"name":"Office laptop"}` |
| `POST /keys/<ip>/pause` | **pause** a key: it stays configured, but no traffic passes |
| `POST /keys/<ip>/resume` | lift the pause (also `PUT /keys/<ip>/paused {"paused":false}`) |
| `PUT /keys/<ip>/limit` | set or change the **traffic limit**, body `{"traffic":"50G"}`; `{"traffic":"unlimited"}` removes it |
| `DELETE /keys/<ip>/limit` | remove the traffic limit (unlimited) |
| `PUT /keys/<ip>/expiry` | set or change the **time limit**: `{"expires":"30d"}` (from now; also `"12h"`, `"2w"`, `"1m"`, `"1y"`), `{"expiresOn":"2026-12-31 18:00"}` (on that date and time of the **server's clock**), `{"expiresAfterFirstConnection":"1m"}` (from the first connection), `{"expires":"never"}` (none) |
| `DELETE /keys/<ip>/expiry` | remove the time limit |
| `POST /remove` | remove a key, body `{"ipAddress":"10.66.0.2"}` (also `DELETE /keys/<ip>`) |
| `GET /usage` | **all keys**: upload/download bytes, last handshake, plus totals (light, for polling) |
| `GET /usage/<ip>` | usage of **one key**, e.g. `/usage/10.66.0.2` |
| `GET /server` | server facts: public key, endpoint, DNS, `apiVersion`, `features`, key count |
| `GET /metrics/transfer` | `{"bytesTransferredByUserId": {"10.66.0.2": 12345}}` (Outline's usage call) |
| `GET /health` | liveness check, no token needed |

Every `/keys/<ip>/...` route also exists under `/access-keys/<ip>/...`; Outline's
`PUT /access-keys/<ip>/data-limit {"limit":{"bytes":N}}` and `DELETE .../data-limit` work as well.

Errors: `401` wrong or missing token, `400` malformed address, an address that is not a client
address of this server, or a traffic / time value that is not understood, `404` unknown key,
`409` the requested `ipAddress` is already in use, `503` address pool full.

### Traffic limits and pausing

* **Values:** `"20G"`, `"500M"`, `"1.5T"`, `"750 MB"`, a plain number of bytes (`20000000000`), or
  `"unlimited"` / `0`. Units are decimal like the app shows them (1G = 1,000,000,000 bytes);
  `KiB`/`MiB`/`GiB`/`TiB` are binary.
* **What counts:** upload + download since the key was created (the same totals as `/usage`,
  kept across restarts).
* **Enforcement:** checked at once when the limit is set and then every minute. A key that
  reaches its limit is blocked like a paused one (`"status":"limit"`, `"limitReached":true`) until
  the limit is raised or removed; it then works again by itself. Because of the one-minute
  check a busy key can go slightly over before it is stopped.
* **Pause** blocks a key without removing it; its config keeps working after `resume`.
* Both are enforced in the server's firewall (`WG-SUSPEND` chain), are saved in
  `/etc/wg-api/policy.db`, and survive restarts and reboots.
* Each key in `/keys` carries `paused`, `dataLimitBytes` (0 = unlimited), `dataLimit`
  (`{"bytes":N}` or `null`, Outline's shape), `limitReached` and `status`
  (`active` / `paused` / `limit` / `expired`).

### Time limits

Three kinds, set when the key is created (`POST /create`) or later (`PUT /keys/<ip>/expiry`):

| Body | The key stops working |
|---|---|
| `{"expires":"30d"}` | 30 days from now. Units: `h` hours, `d` days, `w` weeks, `m` months, `y` years (`"12 hours"`, `"1 month"`, `"2 weeks"`, `"1 year"` and a plain number of days work too) |
| `{"expiresOn":"2026-12-31 18:00"}` | **End on:** at that date and time on the **server's clock** (its time zone, see `timeZone` / `serverClock` in `GET /server`). `"2026-12-31"` alone = 23:59:59 that day; `"2026-12-31T18:00"` works; a time with a zone (`"...Z"`, `"...+02:00"`) is honoured. A time already past is refused with 400. `"expires"` takes the same dates |
| `{"expiresAfterFirstConnection":"1m"}` | one month after the key's **first connection**. Until it connects, there is no end yet. For a key that has already connected, the end is its first connection + 1 month (so it can already be over) |
| `{"expires":"never"}` or `DELETE /keys/<ip>/expiry` | never (removes the time limit) |

* **`m` is months, not minutes.** Months are calendar months in UTC, kept inside the target month:
  Jan 15 + 1m = Feb 15, Jan 31 + 1m = Feb 28 (29 in a leap year). A year is 12 such months
  (`"1y"` is stored and shown as `"12m"` in `expiresAfterFirstConnection`).
* **Checked every minute**, together with the traffic limits; a new end is applied at once. A key's first
  connection is recorded on the first check after it connects (so up to a minute late). On a server updated
  from an older version, keys that had connected before get the last handshake known at the update as their
  first connection.
* **An expired key is blocked** like a paused one (`"status":"expired"`, `"expired":true`). Its config,
  usage and settings stay; giving it a later end, a new duration or none unblocks it. `resume` does not
  lift an expiry.
* Each key carries `expiresAt` (ISO time, `null` = no end yet), `expiresAtServer` (the same end on the server's clock, e.g. `"2026-12-31 18:00"`), `expiresAfterFirstConnection` (e.g. `"1m"`
  while the key waits for its first connection, and after it), `firstConnectedAt` (every key; `null` = never
  connected) and `expired`.
* Saved in `/etc/wg-api/policy.db`, enforced in the `WG-SUSPEND` firewall chain; survives restarts and reboots.

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

# a key at a chosen address with a 20 GB limit (both optional; the Content-Type header is required for the body)
curl --insecure --pinnedpubkey "$PIN" -X POST "$URL/create?format=json" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"ipAddress":"10.66.0.2","traffic":"20G"}'

# change the limit, or remove it
curl --insecure --pinnedpubkey "$PIN" -X PUT "$URL/keys/10.66.0.2/limit" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"traffic":"50G"}'
curl --insecure --pinnedpubkey "$PIN" -X PUT "$URL/keys/10.66.0.2/limit" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"traffic":"unlimited"}'

# time limit: 30 days from now / on a date and time of the server's clock / 1 month from the first connection / none
curl --insecure --pinnedpubkey "$PIN" -X PUT "$URL/keys/10.66.0.2/expiry" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"expires":"30d"}'
curl --insecure --pinnedpubkey "$PIN" -X PUT "$URL/keys/10.66.0.2/expiry" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"expiresOn":"2026-12-31 18:00"}'
curl --insecure --pinnedpubkey "$PIN" -X PUT "$URL/keys/10.66.0.2/expiry" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"expiresAfterFirstConnection":"1m"}'
curl --insecure --pinnedpubkey "$PIN" -X DELETE "$URL/keys/10.66.0.2/expiry" -H "Authorization: Bearer $TOKEN"

# a new key: 20 GB for one month, counted from its first connection
curl --insecure --pinnedpubkey "$PIN" -X POST "$URL/create?format=json" -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"traffic":"20G","expiresAfterFirstConnection":"1m"}'

# pause and resume
curl --insecure --pinnedpubkey "$PIN" -X POST "$URL/keys/10.66.0.2/pause"  -H "Authorization: Bearer $TOKEN"
curl --insecure --pinnedpubkey "$PIN" -X POST "$URL/keys/10.66.0.2/resume" -H "Authorization: Bearer $TOKEN"
```

Without `-H 'Content-Type: application/json'` the body is ignored: the key is still created,
but at the next free address and without a limit.

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
* "Last seen" (`lastHandshake`) and the first connection (`firstConnectedAt`) are saved with the
  usage for every key, so they no longer show `never` after a restart for a key that has connected before.

### What is stored per key, and when it is deleted

| File (root only) | What | Deleted |
|---|---|---|
| `/var/lib/wg-api/traffic.db` | usage, last handshake, first connection | when the key is removed (API, app, or by hand from `wg0.conf`: on the next minute's check) |
| `/etc/wg-api/clients.db` | the client's private key (for `GET /keys`), name, created | the same |
| `/etc/wg-api/policy.db` | pause, traffic limit, time limit | the same |

A new key that later gets the same address starts with zero usage and no handshakes (everything is
stored per public key, and the old rows are gone).

---

## Firewall

`/usr/local/bin/wg-firewall.sh` makes wg0's filter rules. `wg-quick` runs it on every start
(`PostUp`) and stop (`PostDown`); the NAT (MASQUERADE) rule stays on its own PostUp/PostDown lines.
Because the whole block is rebuilt on every start in a fixed order, a restart can no longer move
an ACCEPT rule above the suspensions.

```text
INPUT    -p udp --dport <wg port> -j ACCEPT
INPUT    -i wg0 -j WG-IN           clients may ping the server and use DNS on it, nothing else
FORWARD  -j WG-SUSPEND             paused, over-limit and expired keys, wg-peer-ctrl suspensions
FORWARD  -i wg0 -j WG-GUARD        no client-to-client; no 10/8, 172.16/12, 192.168/16, 169.254/16 (metadata), 100.64/10 ...
FORWARD  -i wg0 -j ACCEPT
FORWARD  -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
FORWARD  -o wg0 -j WG-NOINBOUND    nothing else may enter the tunnel from outside
```

```bash
sudo wg-firewall.sh status          # show the rules
sudo vi /etc/wireguard/wg-firewall.conf && sudo wg-firewall.sh up    # change an option, apply it
```

Options in `/etc/wireguard/wg-firewall.conf` (1 = on): `CLIENT_ISOLATION`, `BLOCK_PRIVATE_NETS`,
`BLOCK_SERVER_ACCESS`. The block state lives in `/etc/wg-api/policy.db` (API) and
`/etc/wireguard/suspended.list` (`wg-peer-ctrl.sh`), not in iptables, so it does not depend on
`netfilter-persistent`.

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

Installed in `/usr/local/bin` (downloaded from a fixed commit and checked against their SHA-256)
and also runnable straight from GitHub:

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
* **`Cannot GET /usage`**, or `404` on `/keys/<ip>/pause`, `/limit` or `/expiry`: the server still runs an
  older `server.js`; [update it](#updating-installed-servers).
* **A key expired a month early / late**: `"1m"` is one month, not one minute; and a date without a
  time means the *end* of that day in UTC.
* **A key was created without its limit / at another address**: the request had no
  `-H 'Content-Type: application/json'`, so the body was ignored.
* **A paused or over-limit key still works**: check `sudo wg-firewall.sh status` shows
  `-A FORWARD -j WG-SUSPEND` first and the key's address in `WG-SUSPEND`. On a server
  that was never updated, a `wg0` restart moved the old ACCEPT rules above the suspensions;
  run `--update-api`.
* **`sha256sum: WARNING: 1 computed checksum did NOT match`**: the downloaded file is not the
  2.3.0 file (`main` changed since, or the download was altered). Do not run it; use the newer command.
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
| `peer-suspend <cidr>` | Block peer's traffic via the `WG-SUSPEND` iptables chain (peer stays in wg, handshakes still work); saved in `/etc/wireguard/suspended.list`, so it survives restarts |
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
* The access configs (the green lines) open every key on a server, including the
  private keys: share them like passwords.
* VPN clients are isolated from each other and from private / cloud-metadata networks
  by default (see [Firewall](#firewall)).
* Install and update with the script's SHA-256 checked
  (see [Install](#install)); the health tools are pinned the same way inside the script.
