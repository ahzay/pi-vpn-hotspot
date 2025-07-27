#!/bin/bash
set -e

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Run with sudo"
   exit 1
fi

# Check WireGuard config exists and is working
if [ ! -f "/etc/wireguard/wg0.conf" ]; then
    echo "ERROR: /etc/wireguard/wg0.conf not found"
    echo "Set up WireGuard first, then run this script"
    exit 1
fi

# Test WireGuard
echo "Testing WireGuard connection..."
wg-quick up wg0 2>/dev/null || true
sleep 3
if ! wg show wg0 &>/dev/null; then
    echo "ERROR: WireGuard not working"
    echo "Fix your WireGuard setup first"
    exit 1
fi
echo "WireGuard OK"

# Check WiFi interfaces
WIFI_COUNT=$(nmcli device status | grep -E "^\s*wlan[0-9]+\s+wifi\s+" | wc -l)
if [ $WIFI_COUNT -lt 2 ]; then
    echo "ERROR: Need 2 WiFi interfaces, found $WIFI_COUNT"
    echo "Connect a USB WiFi adapter"
    exit 1
fi
echo "Found $WIFI_COUNT WiFi interfaces"

# Install packages
echo "Installing packages..."
apt update -q
apt install -y python3 python3-flask iptables network-manager

# Stop conflicting services
systemctl stop hostapd dnsmasq 2>/dev/null || true
systemctl disable hostapd dnsmasq 2>/dev/null || true

# Enable NetworkManager
systemctl enable NetworkManager
systemctl restart NetworkManager
sleep 3

# Install files
echo "Installing gateway..."
mkdir -p /opt/pi-gateway
cp main.py /opt/pi-gateway/
chmod +x /opt/pi-gateway/main.py

cp pi-gateway.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable pi-gateway

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Enable WireGuard
systemctl enable wg-quick@wg0

echo "Setup complete!"
echo "Reboot, then connect to hotspot 'pi' (password: raspberry)"
echo "Web interface: http://192.168.4.1"