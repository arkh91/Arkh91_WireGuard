# Arkh91_WireGuard
Custom WireGuard

✅ How you’ll run it
./install-wg.sh

bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install-wg.sh)


or with a custom port:
bash <(curl -Ls https://raw.githubusercontent.com/arkh91/Arkh91_WireGuard/refs/heads/main/install_wg_custom_port.sh)

Traffic storage
# ── On each VPN server ──────────────────────────────────────────────

# 1. Create a system user — no login shell, no home directory
useradd -r -s /usr/sbin/nologin -M wg-monitor

# 2. Allow it to run ONLY 'wg show wg0 dump' as root, no password
echo 'wg-monitor ALL=(root) NOPASSWD: /usr/bin/wg show wg0 dump' \
    > /etc/sudoers.d/wg-monitor
chmod 440 /etc/sudoers.d/wg-monitor

# 3. Create SSH directory for the user
mkdir -p /home/wg-monitor/.ssh
chown wg-monitor:wg-monitor /home/wg-monitor/.ssh
chmod 700 /home/wg-monitor/.ssh

# 4. Add the management server's public key (US08's key)
#    Run this on US08 first if you don't have one:
#    ssh-keygen -t ed25519 -f /root/.ssh/wg_monitor_key -N ""
echo "PASTE_US08_PUBLIC_KEY_HERE" >> /home/wg-monitor/.ssh/authorized_keys
chown wg-monitor:wg-monitor /home/wg-monitor/.ssh/authorized_keys
chmod 600 /home/wg-monitor/.ssh/authorized_keys

# 5. Lock down sshd for this user — no TTY, no port forwarding, forced command
#    Add to /etc/ssh/sshd_config:
cat >> /etc/ssh/sshd_config << 'EOF'

Match User wg-monitor
    PasswordAuthentication no
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    ForceCommand sudo /usr/bin/wg show wg0 dump
EOF

systemctl reload sshd
