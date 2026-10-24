import socket
import sys
from datetime import datetime

# Define the ports we want to check (e.g., FTP, SSH, HTTP, HTTPS)
PORTS_TO_CHECK = [21, 22, 80, 443, 8080]

def scan_port(ip, port):
    """Attempts to connect to a specific port on the target IP."""
    try:
        # Create a new socket using IPv4 (AF_INET) and TCP (SOCK_STREAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout so the script doesn't hang on filtered ports
        s.settimeout(1.0)
        
        # connect_ex returns 0 if the connection was successful
        result = s.connect_ex((ip, port))
        
        if result == 0:
            print(f"[+] Port {port} is OPEN")
            
        s.close()
    except socket.error as e:
        print(f"[-] Error connecting to port {port}")

if __name__ == "__main__":
    # Ensure the user provides an IP address
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <Target_IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    print("-" * 50)
    print(f"Starting scan on target: {target_ip}")
    print(f"Time started: {str(datetime.now())}")
    print("-" * 50)
    
    # Loop through our list and scan each port
    for port in PORTS_TO_CHECK:
        scan_port(target_ip, port)
