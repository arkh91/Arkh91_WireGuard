# Arkh91_WireGuard
Custom WireGuard

## ✅ How you'll run it

```bash
./install-wg.sh
```

```bash
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg.sh)
```

or with a custom port:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install_wg_custom_port.sh)
```

---

# WireGuard Monitoring Account Setup

Perform the following steps **on every WireGuard VPN server**.

---

## 1. Create the monitoring user

Create a dedicated system account with **no home directory**.

> **Do not set the shell to `/usr/sbin/nologin`.** `ForceCommand` (step 5) is executed
> *through* the user's login shell. `nologin` ignores any command passed to it and
> just prints "This account is currently not available," which breaks the forced
> command entirely. The actual lockdown comes from `ForceCommand` + `PermitTTY no`
> + the other `Match` restrictions below, not from the shell — so a real shell is
> required here and is safe to use.

```bash
useradd -r -s /bin/bash -M wg-monitor
```

---

## 2. Allow only the required command

Grant the user permission to execute **only** `wg show wg0 dump` as root without requiring a password.

```bash
echo 'wg-monitor ALL=(root) NOPASSWD: /usr/bin/wg show wg0 dump' > /etc/sudoers.d/wg-monitor
chmod 440 /etc/sudoers.d/wg-monitor
```

> **If your distro has `Defaults requiretty` set globally** (common on
> RHEL/CentOS-derived systems — check with `grep requiretty /etc/sudoers`), sudo
> will refuse the NOPASSWD rule and demand a password instead, since `PermitTTY no`
> means no TTY is ever available. Fix this by scoping an exception to just this
> user instead of weakening `requiretty` globally:
>
> ```bash
> cat > /etc/sudoers.d/wg-monitor << 'EOF'
> Defaults:wg-monitor !requiretty
> wg-monitor ALL=(root) NOPASSWD: /usr/bin/wg show wg0 dump
> EOF
> chmod 440 /etc/sudoers.d/wg-monitor
> ```
>
> Always validate sudoers syntax after editing, since a mistake here can break
> sudo entirely:
>
> ```bash
> visudo -c
> ```

---

## 3. Create the SSH directory

```bash
mkdir -p /home/wg-monitor/.ssh
chown -R wg-monitor:wg-monitor /home/wg-monitor
chmod 700 /home/wg-monitor/.ssh
```

---

## 4. Configure SSH public key authentication

On the **management server (US08)**, generate a dedicated SSH key if one does not already exist:

```bash
ssh-keygen -t ed25519 -f /root/.ssh/wg_monitor_key -N ""
```

Copy the contents of:

```text
/root/.ssh/wg_monitor_key.pub
```

Then, on **each VPN server**, add the public key:

```bash
echo "PASTE_US08_PUBLIC_KEY_HERE" >> /home/wg-monitor/.ssh/authorized_keys
chown wg-monitor:wg-monitor /home/wg-monitor/.ssh/authorized_keys
chmod 600 /home/wg-monitor/.ssh/authorized_keys
```

---

## 5. Restrict SSH access

Append the following configuration to `/etc/ssh/sshd_config`:

```bash
cat >> /etc/ssh/sshd_config << 'EOF'

Match User wg-monitor
    PasswordAuthentication no
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    ForceCommand sudo /usr/bin/wg show wg0 dump
EOF
```

Validate the config before reloading — a syntax error in a `Match` block can
silently fail to apply or lock out access:

```bash
sshd -t
```

Reload the SSH service:

```bash
systemctl reload sshd
```

(Service name is `sshd` on RHEL/CentOS-derived systems, `ssh` on Debian/Ubuntu —
check with `systemctl status sshd` or `systemctl status ssh` to confirm which
applies to your distro.)

---

## Security Notes

* The `wg-monitor` account cannot obtain an interactive shell (enforced by `ForceCommand`, not by the login shell).
* Password authentication is disabled.
* TTY allocation is disabled.
* SSH agent forwarding is disabled.
* TCP forwarding is disabled.
* X11 forwarding is disabled.
* Every SSH connection is forced to execute only:

```bash
sudo /usr/bin/wg show wg0 dump
```

This provides the management server with read-only access to WireGuard peer information while preventing any other commands from being executed.

---

## Verifying the setup

From the management server (US08):

```bash
# Should print only the wg dump output and close — no shell, no prompt
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP

# Should still be refused/ignored — ForceCommand overrides any command or TTY request
ssh -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP "whoami"
ssh -t -i /root/.ssh/wg_monitor_key wg-monitor@VPN_SERVER_IP

# Should fail immediately with no password prompt — key-only auth
ssh wg-monitor@VPN_SERVER_IP
```

On the VPN server itself:

```bash
# Confirm the sudo grant is scoped to exactly one command
sudo -l -U wg-monitor

# Confirm the account has no usable home dir beyond .ssh
ls -la /home/wg-monitor
getent passwd wg-monitor
```
