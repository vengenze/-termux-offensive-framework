import socket
import sys
from datetime import datetime

# Common ports: FTP(21), SSH(22), SMTP(25), HTTP(80)
PORTS_TO_CHECK = [21, 22, 25, 80]

def grab_banner(ip, port):
    try:
        # Create socket and set a slightly longer timeout to wait for data
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0) 
        
        # Connect to the target
        result = s.connect_ex((ip, port))
        
        if result == 0:
            banner = ""
            try:
                # Step 1: Passive Grabbing (for SSH, FTP, SMTP)
                # Wait to see if the server sends data immediately
                raw_data = s.recv(1024)
                # Decode bytes to a string, ignoring weird characters
                banner = raw_data.decode('utf-8', errors='ignore').strip()
                
            except socket.timeout:
                # Step 2: Active Grabbing (for HTTP)
                # If it timed out, the server is waiting for us. Let's send an HTTP request.
                try:
                    s.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
                    raw_data = s.recv(1024)
                    banner = raw_data.decode('utf-8', errors='ignore').split('\n')[0].strip()
                except Exception:
                    pass # If it fails again, we just move on
            
            # Print the results cleanly
            if banner:
                print(f"[+] Port {port:<5} | OPEN | {banner}")
            else:
                print(f"[+] Port {port:<5} | OPEN | (No banner)")
                
        s.close()
        
    except socket.error as e:
        pass # Ignore general socket errors to keep output clean

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python grabber.py <Target_IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    print("-" * 50)
    print(f"Banner Grabbing: {target_ip}")
    print("-" * 50)
    
    for port in PORTS_TO_CHECK:
        grab_banner(target_ip, port)
