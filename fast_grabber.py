import socket
import sys
from datetime import datetime
import concurrent.futures

# Let's scan a much larger range now: Ports 1 through 1024
PORTS_TO_CHECK = range(1, 1025)

def grab_banner(ip, port):
    """Scans a single port and returns the result string if open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5) # Slightly lower timeout for faster scanning
        
        result = s.connect_ex((ip, port))
        
        if result == 0:
            banner = ""
            try:
                raw_data = s.recv(1024)
                banner = raw_data.decode('utf-8', errors='ignore').strip()
            except socket.timeout:
                try:
                    s.sendall(b"HEAD / HTTP/1.1\r\n\r\n")
                    raw_data = s.recv(1024)
                    banner = raw_data.decode('utf-8', errors='ignore').split('\n')[0].strip()
                except Exception:
                    pass
            
            s.close()
            
            # Return the string instead of printing directly to avoid messy terminal output
            if banner:
                return f"[+] Port {port:<5} | OPEN | {banner}"
            else:
                return f"[+] Port {port:<5} | OPEN | (No banner)"
                
        s.close()
        return None # Port is closed or filtered
        
    except socket.error:
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fast_grabber.py <Target_IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    
    print("-" * 50)
    print(f"Fast Banner Grabbing: {target_ip}")
    start_time = datetime.now()
    print("-" * 50)
    
    # Create a pool of 50 concurrent worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        # Submit all 1,024 ports to the thread pool
        futures = [executor.submit(grab_banner, target_ip, port) for port in PORTS_TO_CHECK]
        
        # as_completed yields tasks exactly as they finish, in real-time
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)

    end_time = datetime.now()
    print("-" * 50)
    print(f"Scan completed in: {end_time - start_time}")
