# Pi VPN Hotspot

Turn a Pi into a portable VPN router. Creates a WiFi hotspot that routes all traffic through WireGuard (for now).

## Requirements

**Hardware:**

- Need 2 WiFi interfaces (built-in + USB adapter)

**Software:**

- WireGuard config must already be at `/etc/wireguard/wg0.conf` and working
- Uses NetworkManager (nmcli) for WiFi management
- Python 3 + Flask for web interface
- iptables for routing/NAT

## Setup

1. **Clone and install:**

    ```bash
    git clone https://github.com/yourusername/pi-zero-vpn-gateway.git
    cd pi-zero-vpn-gateway
    sudo ./setup.sh
    ```

2. **Reboot:**

    ```bash
    sudo reboot
    ```

3. **Connect to hotspot `pi` (password: `raspberry`) and go to `http://192.168.4.1`**

## Usage

- Connect devices to the `pi` hotspot
- Use web interface at `192.168.4.1` to configure WiFi
- All traffic automatically goes through your VPN

## How it works

- Uses NetworkManager to manage both WiFi interfaces (client + hotspot)
- Python script configures hotspot via nmcli commands
- iptables NAT routes hotspot traffic through Pi
- WireGuard tunnels all internet traffic through VPN
- Flask web interface for WiFi configuration

## TODO

- [x] Working basic functionality
- [ ] `setup.sh` not wireguard specific  
- [ ] Better error handling and user feedback
- [ ] Better cleanup on start/exit
- [ ] Test on devices
  - [x] Raspberry Pi Zero 2 W
- [ ] Configuration instead of hardcoded values (SSID, password, IP ranges, Interface Assignment)
- [ ] Use NetworkManager Python API instead of subprocess calls to nmcli
- [ ] Use python-netfilter/iptc instead of subprocess iptables calls
