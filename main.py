#!/usr/bin/env python3

import os
import subprocess
import logging
import re
from typing import Optional, Tuple, List
from flask import Flask, request, render_template_string

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pi-gateway.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def get_wifi_interfaces() -> List[str]:
    """Get all WiFi interfaces"""
    try:
        result = subprocess.run([
            "nmcli", "device", "status"
        ], capture_output=True, text=True, check=True)
        
        interfaces = []
        lines = result.stdout.strip().split('\n')
        
        # Skip header line
        for line in lines[1:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'wifi':
                    interfaces.append(parts[0])
        
        logger.info(f"Found WiFi interfaces: {interfaces}")
        return interfaces
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get WiFi interfaces: {e}")
        return []

def get_interface_assignment() -> Tuple[Optional[str], Optional[str]]:
    """Determine which interface is for internet (client) and which for hotspot"""
    interfaces = get_wifi_interfaces()
    
    if len(interfaces) < 2:
        logger.warning(f"Need 2 WiFi interfaces, found {len(interfaces)}")
        return None, None
    
    client_iface = None
    hotspot_iface = None
    
    # Check which interface already has a client connection
    for iface in interfaces:
        try:
            result = subprocess.run([
                "nmcli", "device", "show", iface
            ], capture_output=True, text=True, check=True)
            
            # Look for active client connection (has IP and not AP mode)
            has_ip = False
            is_ap = False
            
            for line in result.stdout.split('\n'):
                if 'IP4.ADDRESS[1]' in line and line.split(':')[1].strip():
                    has_ip = True
                if 'WIFI.MODE' in line and 'ap' in line.lower():
                    is_ap = True
            
            if has_ip and not is_ap:
                client_iface = iface
                logger.info(f"Found client interface with connection: {iface}")
                break
                
        except subprocess.CalledProcessError:
            continue
    
    # Assign hotspot to the other interface
    if client_iface:
        hotspot_iface = next((iface for iface in interfaces if iface != client_iface), None)
    else:
        # Neither connected, pick any assignment
        client_iface = interfaces[0]
        hotspot_iface = interfaces[1]
        logger.info(f"No existing connections, assigned client: {client_iface}, hotspot: {hotspot_iface}")
    
    logger.info(f"Interface assignment - Client: {client_iface}, Hotspot: {hotspot_iface}")
    return client_iface, hotspot_iface

def setup_hotspot() -> Optional[str]:
    """Configure hotspot on available WiFi interface"""
    client_iface, hotspot_iface = get_interface_assignment()
    
    if not hotspot_iface:
        logger.error("No interface available for hotspot")
        return None
    
    try:
        # Check if hotspot connection already exists
        result = subprocess.run([
            "nmcli", "connection", "show", "hotspot"
        ], capture_output=True, check=False)
        
        if result.returncode != 0:
            # Create hotspot connection
            subprocess.run([
                "nmcli", "connection", "add",
                "type", "wifi",
                "ifname", hotspot_iface,
                "con-name", "hotspot",
                "wifi.mode", "ap",
                "wifi.ssid", "pi",
                "wifi-sec.key-mgmt", "wpa-psk",
                "wifi-sec.psk", "raspberry",
                #"ip4", "192.168.4.1/24",
                "ipv4.method", "shared",
                "ipv4.addresses", "192.168.4.1/24",
                "connection.autoconnect", "yes"
            ], check=True)
            logger.info(f"Created hotspot connection on {hotspot_iface}")
        
        # Bring up the hotspot
        subprocess.run(["nmcli", "connection", "up", "hotspot"], check=True)
        logger.info(f"Hotspot 'pi' started on {hotspot_iface}")
        return hotspot_iface
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to setup hotspot: {e}")
        return None

def enable_forwarding() -> None:
    """Enable IP forwarding"""
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
        f.write('1')
    logger.info("IP forwarding enabled")

def setup_vpn_routing() -> None:
    """Configure routing for VPN gateway - route hotspot traffic through Pi (WireGuard handles VPN routing)"""
    client_iface, hotspot_iface = get_interface_assignment()
    
    if not hotspot_iface:
        logger.error("Cannot setup routing - missing hotspot interface")
        return
    
    commands = [
        # Clear existing rules
        ["iptables", "-t", "nat", "-F", "POSTROUTING"],
        ["iptables", "-F", "FORWARD"],
        
        # Allow local hotspot network traffic (web interface access)
        ["iptables", "-A", "FORWARD", "-s", "192.168.4.0/24", "-d", "192.168.4.0/24", "-j", "ACCEPT"],
        
        # NAT hotspot internet traffic to appear as coming from Pi
        # (Pi's WireGuard routing will then send it through VPN)
        ["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "192.168.4.0/24", "!", "-d", "192.168.4.0/24", "-j", "MASQUERADE"],
        
        # Forward hotspot traffic through Pi
        ["iptables", "-A", "FORWARD", "-i", hotspot_iface, "-j", "ACCEPT"],
        ["iptables", "-A", "FORWARD", "-o", hotspot_iface, "-j", "ACCEPT"]
    ]
    
    for cmd in commands:
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to setup routing rule {' '.join(cmd)}: {e}")
    
    logger.info(f"VPN routing configured: {hotspot_iface} → Pi → WireGuard VPN")

def connect_wifi(ssid: str, password: str) -> bool:
    """Connect to WiFi network using NetworkManager"""
    client_iface, _ = get_interface_assignment()
    
    if not client_iface:
        logger.error("No client interface available")
        return False
    
    try:
        # Rescan for available networks
        logger.info("Scanning for WiFi networks...")
        subprocess.run([
            "nmcli", "device", "wifi", "rescan"
        ], check=True)
        
        # Wait a moment for scan to complete
        import time
        time.sleep(2)
        
        # Check if connection already exists
        result = subprocess.run([
            "nmcli", "connection", "show", ssid
        ], capture_output=True, check=False)
        
        if result.returncode == 0:
            # Connection exists, just bring it up
            subprocess.run(["nmcli", "connection", "up", ssid], check=True)
        else:
            # Create new WiFi connection on client interface
            subprocess.run([
                "nmcli", "device", "wifi", "connect", ssid,
                "password", password,
                "ifname", client_iface
            ], check=True)
        
        # Wait a moment for connection to establish
        import time
        time.sleep(3)
        
        # Setup routing now that WiFi is connected (allows WireGuard to work)
        setup_vpn_routing()
        
        logger.info(f"Connected to WiFi: {ssid} on {client_iface}")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to connect to WiFi {ssid}: {e}")
        return False

def get_wifi_status() -> Tuple[bool, Optional[str]]:
    """Check if client interface is connected and get IP"""
    client_iface, _ = get_interface_assignment()
    
    if not client_iface:
        return False, None
    
    try:
        result = subprocess.run([
            "nmcli", "device", "show", client_iface
        ], capture_output=True, text=True, check=True)
        
        # Parse for IP address
        for line in result.stdout.split('\n'):
            if 'IP4.ADDRESS[1]' in line:
                ip = line.split(':')[1].strip().split('/')[0]
                return True, ip
        
        return False, None
        
    except subprocess.CalledProcessError:
        return False, None

def get_hotspot_status() -> Tuple[bool, Optional[str]]:
    """Check if hotspot is running"""
    _, hotspot_iface = get_interface_assignment()
    
    if not hotspot_iface:
        return False, None
    
    try:
        result = subprocess.run([
            "nmcli", "connection", "show", "--active", "hotspot"
        ], capture_output=True, check=False)
        
        if result.returncode == 0:
            return True, hotspot_iface
        else:
            return False, hotspot_iface
            
    except subprocess.CalledProcessError:
        return False, hotspot_iface

def get_wg_status() -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Check WireGuard status - return (is_active, vpn_ip, endpoint, last_handshake)"""
    try:
        # Get WireGuard interface info
        result = subprocess.run([
            "ip", "addr", "show", "wg0"
        ], capture_output=True, text=True, check=True)
        
        vpn_ip = None
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                vpn_ip = line.strip().split()[1].split('/')[0]
                break
        
        # Get WireGuard peer info
        result = subprocess.run([
            "wg", "show", "wg0"
        ], capture_output=True, text=True, check=True)
        
        endpoint = None
        last_handshake = None
        
        for line in result.stdout.split('\n'):
            if 'endpoint:' in line:
                endpoint = line.split('endpoint:')[1].strip()
            elif 'latest handshake:' in line:
                last_handshake = line.split('latest handshake:')[1].strip()
        
        # Consider active if we have recent handshake
        is_active = False
        if last_handshake:
            if 'seconds ago' in last_handshake or ('minute' in last_handshake and not 'minutes' in last_handshake):
                is_active = True
            elif 'minutes ago' in last_handshake:
                # Extract number of minutes
                minutes = re.search(r'(\d+)', last_handshake)
                if minutes and int(minutes.group(1)) < 5:
                    is_active = True
        
        return is_active, vpn_ip, endpoint, last_handshake
        
    except subprocess.CalledProcessError:
        return False, None, None, None

def get_logs() -> str:
    """Get recent log entries"""
    try:
        result = subprocess.run(
            ["tail", "-50", "/var/log/pi-gateway.log"],
            capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError:
        return "Could not read logs"

# Web interface templates
INDEX_TEMPLATE = '''<!DOCTYPE html>
<html>
<head><title>Pi VPN Gateway</title></head>
<body>
<h1>Pi Zero VPN Gateway</h1>

<h2>Hotspot Status</h2>
{% if hotspot_active %}
<p>✓ Hotspot "pi" running on {{ hotspot_iface }}</p>
<p>Connect devices to: pi (password: raspberry)</p>
<p>Gateway IP: 192.168.4.1</p>
{% else %}
<p>✗ Hotspot not running</p>
{% endif %}

<h2>VPN Status</h2>
{% if vpn_active %}
<p>✓ WireGuard connected - VPN IP: {{ vpn_ip }}</p>
<p>Endpoint: {{ vpn_endpoint }}</p>
<p>Last handshake: {{ vpn_handshake }}</p>
<p><strong>All hotspot traffic is routed through VPN</strong></p>
{% else %}
<p>✗ VPN not connected</p>
<p>Handshake: {{ vpn_handshake or 'Never' }}</p>
<p><strong>No internet access for hotspot clients</strong></p>
{% endif %}

<h2>Internet Connection (for VPN)</h2>
{% if wifi_connected %}
<p>✓ WiFi Connected - IP: {{ wifi_ip }}</p>
<p>VPN can reach server</p>
{% else %}
<p>✗ WiFi not connected</p>
<p>VPN cannot reach server</p>
{% endif %}

<h2>Connect to WiFi</h2>
<form method="post" action="/connect">
<input type="text" name="ssid" placeholder="Network Name" required><br><br>
<input type="password" name="password" placeholder="Password" required><br><br>
<input type="submit" value="Connect">
</form>

<h2>Logs</h2>
<a href="/logs">View Logs</a>
</body>
</html>'''

LOGS_TEMPLATE = '''<!DOCTYPE html>
<html>
<head><title>Logs</title></head>
<body>
<h1>Gateway Logs</h1>
<a href="/">← Back</a>
<pre>{{ logs }}</pre>
</body>
</html>'''

@app.route('/')
def index():
    wifi_connected, wifi_ip = get_wifi_status()
    hotspot_active, hotspot_iface = get_hotspot_status()
    vpn_active, vpn_ip, vpn_endpoint, vpn_handshake = get_wg_status()
    
    return render_template_string(
        INDEX_TEMPLATE, 
        wifi_connected=wifi_connected, 
        wifi_ip=wifi_ip,
        hotspot_active=hotspot_active,
        hotspot_iface=hotspot_iface,
        vpn_active=vpn_active,
        vpn_ip=vpn_ip,
        vpn_endpoint=vpn_endpoint,
        vpn_handshake=vpn_handshake
    )

@app.route('/connect', methods=['POST'])
def connect():
    ssid = request.form['ssid']
    password = request.form['password']
    
    if connect_wifi(ssid, password):
        return f'<h1>Success!</h1><p>Connected to {ssid}</p><p>WireGuard should now be able to connect to VPN server</p><a href="/">← Back</a>'
    else:
        return f'<h1>Failed</h1><p>Could not connect to {ssid}</p><a href="/">← Back</a>'

@app.route('/logs')
def logs():
    log_content = get_logs()
    return render_template_string(LOGS_TEMPLATE, logs=log_content)

def main() -> None:
    """Main service entry point"""
    logger.info("Starting Pi VPN Gateway service")
    
    # Setup hotspot
    hotspot_iface = setup_hotspot()
    if not hotspot_iface:
        logger.error("Failed to setup hotspot - exiting")
        return
    
    # Enable forwarding
    enable_forwarding()
    
    # Setup initial VPN routing rules
    setup_vpn_routing()
    
    # Start web server on all interfaces
    logger.info("Starting web interface on port 80 (all interfaces)")
    logger.info("WireGuard should be running via systemd service")
    logger.info("Connect to WiFi via web interface to enable VPN connectivity")
    app.run(host='0.0.0.0', port=80, debug=False)

if __name__ == '__main__':
    main()