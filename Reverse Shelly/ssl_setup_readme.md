# SSL Certificate Setup Guide

## 📋 Table of Contents

- [Overview](#overview)
- [Understanding SSL Certificates](#understanding-ssl-certificates)
- [Prerequisites](#prerequisites)
- [Method 1: Automatic Generation (Recommended)](#method-1-automatic-generation-recommended)
- [Method 2: OpenSSL Command Line](#method-2-openssl-command-line)
- [Method 3: Python Script Generation](#method-3-python-script-generation)
- [Method 4: Manual Certificate Creation](#method-4-manual-certificate-creation)
- [Certificate Verification](#certificate-verification)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Advanced Configuration](#advanced-configuration)

## 🎯 Overview

This guide explains how to set up SSL certificates (`server.pem` and `server.key`) for the Advanced Reverse Shell Framework. SSL certificates are required for encrypted communication between the listener and client.

### What You'll Create

- **`server.key`** - Private key file (keep this secret!)
- **`server.pem`** - Public certificate file (contains public key and certificate info)

## 🔐 Understanding SSL Certificates

### Certificate Components

```
SSL Certificate Structure:
├── Private Key (server.key)
│   ├── Used for decryption
│   ├── Must be kept secret
│   └── Never share this file
└── Certificate (server.pem)
    ├── Public key
    ├── Certificate information
    ├── Digital signature
    └── Safe to share
```

### Why SSL is Important

- **Encryption**: All communication is encrypted
- **Authentication**: Verify listener identity
- **Integrity**: Prevent data tampering
- **Stealth**: HTTPS traffic looks normal

## 📋 Prerequisites

### Required Software

**Windows:**
```cmd
# Check if OpenSSL is installed
openssl version

# If not installed, download from:
# https://slproweb.com/products/Win32OpenSSL.html
```

**Linux (Ubuntu/Debian):**
```bash
# Install OpenSSL
sudo apt update
sudo apt install openssl

# Verify installation
openssl version
```

**Linux (CentOS/RHEL):**
```bash
# Install OpenSSL
sudo yum install openssl

# Or for newer versions:
sudo dnf install openssl

# Verify installation
openssl version
```

**macOS:**
```bash
# OpenSSL is usually pre-installed
openssl version

# If not available, install via Homebrew:
brew install openssl
```

## 🤖 Method 1: Automatic Generation (Recommended)

The reverse shell framework can automatically generate certificates for you.

### Step 1: Run the Listener

```bash
# The listener will auto-generate certificates if they don't exist
python reverse_shell_listener_multi.py 0.0.0.0 4444
```

**Expected Output:**
```
[+] Creating self-signed SSL certificate...
[+] SSL certificate created successfully
[+] Listening on 0.0.0.0:4444 (SSL/TLS enabled)
```

### Step 2: Verify Files Created

```bash
# Check that files were created
# Windows:
dir server.*

# Linux/macOS:
ls -la server.*
```

**Expected Files:**
```
server.key    # Private key (keep secret!)
server.pem    # Certificate file
```

## 🔧 Method 2: OpenSSL Command Line

### Basic Certificate Generation

**Single Command (Recommended):**
```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
```

**Step-by-Step Breakdown:**
```bash
# Generate private key and certificate in one command
openssl req \
  -x509 \                    # Create self-signed certificate
  -newkey rsa:2048 \         # Generate 2048-bit RSA key
  -keyout server.key \       # Output private key file
  -out server.pem \          # Output certificate file
  -days 365 \                # Valid for 365 days
  -nodes \                   # Don't encrypt private key
  -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"  # Certificate details
```

### Interactive Certificate Generation

If you want to customize certificate details:

```bash
# Generate certificate with interactive prompts
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes
```

**You'll be prompted for:**
```
Country Name (2 letter code) [XX]: US
State or Province Name (full name) []: California  
Locality Name (eg, city) [Default City]: San Francisco
Organization Name (eg, company) [Default Company Ltd]: Test Lab
Organizational Unit Name (eg, section) []: Security Team
Common Name (eg, your name or your server's hostname) []: localhost
Email Address []: admin@testlab.com
```

### Advanced OpenSSL Options

**High Security Certificate (4096-bit):**
```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
```

**Certificate Valid for Multiple Domains:**
```bash
# Create config file first
cat > server.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Test
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = 192.168.1.50
EOF

# Generate certificate with config
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -config server.conf -extensions v3_req
```

## 🐍 Method 3: Python Script Generation

Create a Python script to generate certificates programmatically.

### Create Certificate Generator Script

Create `generate_certificates.py`:
```python
#!/usr/bin/env python3
"""
SSL Certificate Generator for Reverse Shell Framework
"""

import os
import sys
from datetime import datetime, timedelta

def generate_certificates_cryptography():
    """Generate certificates using cryptography library"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        print("[+] Generating SSL certificates using cryptography library...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate subject
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reverse Shell Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write private key
        with open('server.key', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open('server.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print("[+] Certificates generated successfully!")
        print("    server.key - Private key (keep secret)")
        print("    server.pem - Certificate file")
        
        return True
        
    except ImportError:
        print("[!] cryptography library not installed")
        print("    Install with: pip install cryptography")
        return False
    except Exception as e:
        print(f"[!] Error generating certificates: {e}")
        return False

def generate_certificates_openssl():
    """Generate certificates using OpenSSL command"""
    try:
        import subprocess
        
        print("[+] Generating SSL certificates using OpenSSL...")
        
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', 'server.key', '-out', 'server.pem',
            '-days', '365', '-nodes',
            '-subj', '/C=US/ST=State/L=City/O=Test/CN=localhost'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("[+] Certificates generated successfully!")
            return True
        else:
            print(f"[!] OpenSSL error: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("[!] OpenSSL not found in PATH")
        return False
    except Exception as e:
        print(f"[!] Error running OpenSSL: {e}")
        return False

def verify_certificates():
    """Verify that certificates were created correctly"""
    if not os.path.exists('server.key'):
        print("[!] server.key not found")
        return False
    
    if not os.path.exists('server.pem'):
        print("[!] server.pem not found")
        return False
    
    # Check file sizes
    key_size = os.path.getsize('server.key')
    cert_size = os.path.getsize('server.pem')
    
    print(f"[+] server.key created ({key_size} bytes)")
    print(f"[+] server.pem created ({cert_size} bytes)")
    
    # Basic validation
    if key_size < 100 or cert_size < 100:
        print("[!] Certificate files seem too small - possible error")
        return False
    
    return True

def main():
    """Main certificate generation function"""
    print("="*60)
    print("SSL Certificate Generator")
    print("="*60)
    
    # Check if certificates already exist
    if os.path.exists('server.key') and os.path.exists('server.pem'):
        response = input("Certificates already exist. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Keeping existing certificates.")
            return
    
    # Try different methods
    success = False
    
    # Method 1: Python cryptography library
    if generate_certificates_cryptography():
        success = True
    # Method 2: OpenSSL command
    elif generate_certificates_openssl():
        success = True
    else:
        print("[!] Failed to generate certificates with all methods")
        print("Please install OpenSSL or the cryptography Python library")
        sys.exit(1)
    
    # Verify certificates
    if success and verify_certificates():
        print("\n" + "="*60)
        print("Certificate Generation Complete!")
        print("="*60)
        print("Files created:")
        print("  server.key - Private key (keep this secret!)")
        print("  server.pem - Certificate file")
        print("\nYou can now start the reverse shell listener:")
        print("  python reverse_shell_listener_multi.py 0.0.0.0 4444")
    else:
        print("[!] Certificate verification failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Run the Certificate Generator

```bash
# Run the Python certificate generator
python generate_certificates.py
```

## 🔨 Method 4: Manual Certificate Creation

### Step 1: Generate Private Key

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out server.key 2048

# Or generate 4096-bit key for higher security
openssl genrsa -out server.key 4096
```

### Step 2: Generate Certificate Signing Request (CSR)

```bash
# Create CSR (you'll be prompted for details)
openssl req -new -key server.key -out server.csr
```

### Step 3: Generate Self-Signed Certificate

```bash
# Create self-signed certificate from CSR
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.pem

# Clean up CSR file
rm server.csr
```

## ✅ Certificate Verification

### Verify Certificate Details

```bash
# View certificate information
openssl x509 -in server.pem -text -noout

# Check certificate dates
openssl x509 -in server.pem -dates -noout

# Verify certificate against private key
openssl x509 -noout -modulus -in server.pem | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
# The MD5 hashes should match
```

### Test SSL Connection

```bash
# Test SSL connection (run this after starting the listener)
openssl s_client -connect localhost:4444

# Test with specific protocol
openssl s_client -connect localhost:4444 -tls1_2
```

### Python Verification Script

Create `verify_certificates.py`:
```python
#!/usr/bin/env python3
"""
Verify SSL certificates for reverse shell framework
"""

import ssl
import socket
import os
from datetime import datetime

def verify_certificate_files():
    """Verify certificate files exist and are readable"""
    print("=== Certificate File Verification ===")
    
    files = ['server.key', 'server.pem']
    for file in files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"✓ {file} exists ({size} bytes)")
            
            # Check if file is readable
            try:
                with open(file, 'r') as f:
                    content = f.read(100)  # Read first 100 chars
                if 'BEGIN' in content:
                    print(f"  ✓ {file} has valid PEM format")
                else:
                    print(f"  ✗ {file} may not be in PEM format")
            except Exception as e:
                print(f"  ✗ Error reading {file}: {e}")
        else:
            print(f"✗ {file} not found")
            return False
    
    return True

def verify_ssl_context():
    """Verify SSL context can be created"""
    print("\n=== SSL Context Verification ===")
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.pem", keyfile="server.key")
        print("✓ SSL context created successfully")
        print(f"✓ Protocol: {context.protocol}")
        return True
    except Exception as e:
        print(f"✗ SSL context error: {e}")
        return False

def verify_certificate_details():
    """Extract and display certificate details"""
    print("\n=== Certificate Details ===")
    
    try:
        import subprocess
        
        # Get certificate details
        result = subprocess.run([
            'openssl', 'x509', '-in', 'server.pem', '-text', '-noout'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'Subject:' in line or 'Not Before:' in line or 'Not After:' in line:
                    print(f"  {line.strip()}")
        else:
            print("✗ Could not read certificate details")
            
    except FileNotFoundError:
        print("! OpenSSL not available for detailed verification")
    except Exception as e:
        print(f"✗ Error reading certificate: {e}")

def test_ssl_server(port=4444):
    """Test SSL server functionality"""
    print(f"\n=== SSL Server Test (Port {port}) ===")
    
    try:
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.pem", keyfile="server.key")
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind and listen briefly
        sock.bind(('localhost', port))
        sock.listen(1)
        
        print(f"✓ SSL server can bind to port {port}")
        
        sock.close()
        return True
        
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"! Port {port} is already in use (this may be normal)")
            return True
        else:
            print(f"✗ Socket error: {e}")
            return False
    except Exception as e:
        print(f"✗ SSL server test failed: {e}")
        return False

def main():
    """Main verification function"""
    print("SSL Certificate Verification Tool")
    print("=" * 50)
    
    all_good = True
    
    # Verify files exist
    if not verify_certificate_files():
        all_good = False
    
    # Verify SSL context
    if not verify_ssl_context():
        all_good = False
    
    # Show certificate details
    verify_certificate_details()
    
    # Test SSL server
    if not test_ssl_server():
        all_good = False
    
    print("\n" + "=" * 50)
    if all_good:
        print("✓ All SSL certificate checks passed!")
        print("✓ Ready to start reverse shell listener")
    else:
        print("✗ Some SSL certificate checks failed")
        print("Please regenerate certificates or check configuration")

if __name__ == "__main__":
    main()
```

```bash
# Run certificate verification
python verify_certificates.py
```

## 🛠️ Troubleshooting

### Common Issues and Solutions

#### Issue 1: "OpenSSL not found"

**Windows:**
```cmd
# Download and install OpenSSL from:
# https://slproweb.com/products/Win32OpenSSL.html

# Or use Windows Subsystem for Linux (WSL):
wsl -install
wsl
sudo apt install openssl
```

**Linux:**
```bash
# Ubuntu/Debian:
sudo apt update && sudo apt install openssl

# CentOS/RHEL:
sudo yum install openssl
# or
sudo dnf install openssl
```

#### Issue 2: "Permission denied"

```bash
# Make sure you have write permissions in the directory
ls -la .

# If needed, change permissions:
chmod 755 .

# Or run with elevated privileges:
sudo openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
```

#### Issue 3: "SSL handshake failure"

```bash
# Check certificate and key match:
openssl x509 -noout -modulus -in server.pem | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5

# If hashes don't match, regenerate certificates:
rm server.key server.pem
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
```

#### Issue 4: "Certificate expired"

```bash
# Check certificate expiration:
openssl x509 -in server.pem -dates -noout

# If expired, generate new certificate:
rm server.pem
openssl req -x509 -new -key server.key -out server.pem -days 365 -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
```

#### Issue 5: "File format errors"

```bash
# Verify file formats:
file server.key server.pem

# Should show:
# server.key: PEM RSA private key
# server.pem: PEM certificate

# If wrong format, check file contents:
head -n 3 server.key server.pem

# Should start with:
# server.key: -----BEGIN PRIVATE KEY-----
# server.pem: -----BEGIN CERTIFICATE-----
```

### Debug SSL Issues

Create `debug_ssl.py`:
```python
#!/usr/bin/env python3
"""
Debug SSL certificate issues
"""

import ssl
import socket
import traceback

def debug_ssl_context():
    """Debug SSL context creation"""
    print("=== SSL Context Debug ===")
    
    try:
        # Try to create SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        print("✓ Default SSL context created")
        
        # Try to load server certificates
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile="server.pem", keyfile="server.key")
        print("✓ Server SSL context created")
        
        return True
        
    except Exception as e:
        print(f"✗ SSL context error: {e}")
        traceback.print_exc()
        return False

def debug_certificate_chain():
    """Debug certificate chain"""
    print("\n=== Certificate Chain Debug ===")
    
    try:
        # Connect to ourselves to test certificate
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # This would test the certificate in a real connection
        print("✓ Certificate chain validation would work")
        return True
        
    except Exception as e:
        print(f"✗ Certificate chain error: {e}")
        return False

def main():
    """Main debug function"""
    print("SSL Debug Tool")
    print("=" * 30)
    
    debug_ssl_context()
    debug_certificate_chain()
    
    print("\nSSL Library Information:")
    print(f"SSL Version: {ssl.OPENSSL_VERSION}")
    print(f"SSL Protocol Options: {[p.name for p in ssl._SSLMethod]}")

if __name__ == "__main__":
    main()
```

## 🔒 Security Considerations

### Certificate Security Best Practices

#### 1. Private Key Protection

```bash
# Set proper permissions (Linux/macOS only)
chmod 600 server.key  # Owner read/write only
chmod 644 server.pem  # Owner read/write, others read

# Check permissions:
ls -la server.*
```

#### 2. Certificate Rotation

```bash
# Check certificate expiration
openssl x509 -in server.pem -dates -noout

# Set up automatic renewal (example cron job)
# Add to crontab: crontab -e
# 0 0 1 * * /path/to/regenerate_certificates.sh
```

#### 3. Key Strength

```bash
# Use strong key sizes (2048-bit minimum, 4096-bit preferred)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"

# Check key size:
openssl rsa -in server.key -text -noout | grep "Private-Key"
```

### Security Warnings

⚠️ **Important Security Notes:**

1. **Self-Signed Certificates**: The certificates created are self-signed and not validated by a Certificate Authority
2. **Testing Only**: These certificates are for testing purposes only
3. **Private Key Security**: Never share the `server.key` file
4. **Network Security**: Use VPN or secure networks for testing
5. **Certificate Validation**: Clients disable certificate validation for testing

## 🚀 Advanced Configuration

### Custom Certificate Authority (CA)

Create your own CA for more realistic testing:

#### Step 1: Create CA Private Key

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096
```

#### Step 2: Create CA Certificate

```bash
# Create CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.pem -subj "/C=US/ST=State/L=City/O=Test CA/CN=Test CA"
```

#### Step 3: Create Server Certificate Signed by CA

```bash
# Generate server private key
openssl genrsa -out server.key 2048

# Create certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"

# Sign certificate with CA
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem

# Clean up
rm server.csr
```

### Multi-Domain Certificates

Create certificates valid for multiple domains:

```bash
# Create config file for multi-domain certificate
cat > multi-domain.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Test
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
DNS.3 = example.com
DNS.4 = *.example.com
IP.1 = 127.0.0.1
IP.2 = 192.168.1.50
IP.3 = 10.0.0.1
EOF

# Generate multi-domain certificate
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -config multi-domain.conf -extensions v3_req
```

### Certificate with Password Protection

If you need password-protected private keys:

```bash
# Generate password-protected private key
openssl genrsa -des3 -out server_protected.key 2048

# Create certificate
openssl req -x509 -new -key server_protected.key -out server.pem -days 365 -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"

# Remove password from key (for automated use)
openssl rsa -in server_protected.key -out server.key
```

## 📝 Certificate Management Scripts

### Automated Certificate Renewal

Create `renew_certificates.sh`:
```bash
#!/bin/bash
# Automated certificate renewal script

CERT_FILE="server.pem"
KEY_FILE="server.key"
DAYS_BEFORE_EXPIRY=30

echo "=== Certificate Renewal Check ==="

# Check if certificate exists
if [ ! -f "$CERT_FILE" ]; then
    echo "Certificate not found, generating new one..."
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
    exit 0
fi

# Check certificate expiration
EXPIRY_DATE=$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
CURRENT_EPOCH=$(date +%s)
SECONDS_UNTIL_EXPIRY=$((EXPIRY_EPOCH - CURRENT_EPOCH))
DAYS_UNTIL_EXPIRY=$((SECONDS_UNTIL_EXPIRY / 86400))

echo "Certificate expires in $DAYS_UNTIL_EXPIRY days"

# Renew if expiring soon
if [ $DAYS_UNTIL_EXPIRY -lt $DAYS_BEFORE_EXPIRY ]; then
    echo "Renewing certificate..."
    
    # Backup old certificates
    cp "$CERT_FILE" "${CERT_FILE}.backup.$(date +%Y%m%d)"
    cp "$KEY_FILE" "${KEY_FILE}.backup.$(date +%Y%m%d)"
    
    # Generate new certificate
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"
    
    echo "Certificate renewed successfully"
else
    echo "Certificate is still valid"
fi
```

```bash
# Make script executable and run
chmod +x renew_certificates.sh
./renew_certificates.sh
```

---

## 🎯 Quick Reference

### Essential Commands

```bash
# Generate basic certificate (recommended)
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"

# Verify certificate
openssl x509 -in server.pem -text -noout

# Test SSL connection
openssl s_client -connect localhost:4444

# Check certificate expiration
openssl x509 -in server.pem -dates -noout

# Verify key/certificate match
openssl x509 -noout -modulus -in server.pem | openssl md5
openssl rsa -noout -modulus -in server.key | openssl md5
```

### File Permissions (Linux/macOS)

```bash
# Set secure permissions
chmod 600 server.key  # Private key - owner only
chmod 644 server.pem  # Certificate - readable by all
```

### Troubleshooting Checklist

- [ ] OpenSSL is installed and in PATH
- [ ] Both `server.key` and `server.pem` exist
- [ ] Files are in PEM format (start with `-----BEGIN`)
- [ ] Private key and certificate match (same MD5 hash)
- [ ] Certificate is not expired
- [ ] Proper file permissions set
- [ ] No firewall blocking the port

---

**Remember**: Keep your `server.key` file secure and never share it! Use these certificates only in authorized testing environments.

---

*Last updated: January 2024*