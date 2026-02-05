#!/bin/bash
# WireGuard VPN Auto Installer
# Works on Ubuntu/Debian

set -e

# -------------------------
# Defaults
# -------------------------
WG_INTERFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.66.66.0/24"
OUT_IFACE="eth0"

# -------------------------
# Parse arguments
# -------------------------
for arg in "$@"; do
  case $arg in
    --keys-port=*)
      WG_PORT="${arg#*=}"
      shift
      ;;
    *)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

# -------------------------
# Validate port
# -------------------------
if ! [[ "$WG_PORT" =~ ^[0-9]+$ ]] || [ "$WG_PORT" -lt 1024 ] || [ "$WG_PORT" -gt 65535 ]; then
  echo "Invalid port: $WG_PORT"
  echo "Port must be between 1024 and 65535"
  exit 1
fi

# -------------------------
# Root check
# -------------------------
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root."
  exit 1
fi

echo "Using WireGuard UDP port: $WG_PORT"

# -------------------------
# Install packages
# -------------------------
echo "Updating system..."
apt update && apt upgrade -y

echo "Installing WireGuard..."
apt install -y wireguard qrencode iptables iptables-persistent

# -------------------------
# Generate keys
# -------------------------
SERVER_PRIVATE_KEY=$(wg genkey)
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

# -------------------------
# WireGuard config
# -------------------------
echo "Creating WireGuard config..."
mkdir -p /etc/wireguard

cat > /etc/wireguard/${WG_INTERFACE}.conf <<EOL
[Interface]
Address = 10.66.66.1/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = true
EOL

chmod 600 /etc/wireguard/${WG_INTERFACE}.conf

# -------------------------
# Enable forwarding
# -------------------------
echo "Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf

# -------------------------
# Firewall rules
# -------------------------
echo "Setting up firewall rules..."

iptables -A INPUT  -p udp --dport $WG_PORT -j ACCEPT
iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT
iptables -A FORWARD -o $WG_INTERFACE -j ACCEPT
iptables -t nat -A POSTROUTING -s $WG_NETWORK -o $OUT_IFACE -j MASQUERADE

netfilter-persistent save

# -------------------------
# Start WireGuard
# -------------------------
echo "Starting WireGuard..."
systemctl enable wg-quick@$WG_INTERFACE
systemctl restart wg-quick@$WG_INTERFACE

# -------------------------
# Done
# -------------------------
echo "================================="
echo " WireGuard server setup complete"
echo "================================="
echo " Interface : $WG_INTERFACE"
echo " UDP Port  : $WG_PORT"
echo " PublicKey : $SERVER_PUBLIC_KEY"
echo " Config    : /etc/wireguard/${WG_INTERFACE}.conf"
