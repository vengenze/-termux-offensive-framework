import socket
import argparse
import sys
from datetime import datetime
import concurrent.futures

def parse_ports(port_str):
    """Converts a string like '22,80,100-110' into a unique, sorted list of integers."""
    ports = set() # Using a set prevents duplicate ports if the user types '80,80-90'
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-')
            # range is exclusive at the end, so we add 1 to include the final port
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def grab_banner(ip, port):
    """Scans a single port and returns the result string if open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        
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
            
            if banner:
                return f"[+] Port {port:<5} | OPEN | {banner}"
            else:
                return f"[+] Port {port:<5} | OPEN | (No banner)"
                
        s.close()
        return None
    except socket.error:
        return None

if __name__ == "__main__":
    # 1. Initialize the Argument Parser
    parser = argparse.ArgumentParser(
        description="Fast Threaded Banner Grabber",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # 2. Define the expected arguments
    parser.add_argument("target", help="Target IP address or domain (e.g., scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="Ports to scan (default: 1-1024)\nExample: -p 22,80,443,1000-2000")
    parser.add_argument("-t", "--threads", type=int, default=50, 
                        help="Number of concurrent threads (default: 50)")
    
    # 3. Parse the arguments provided by the user
    args = parser.parse_args()
    
    try:
        target_ports = parse_ports(args.ports)
    except ValueError:
        print("[-] Error: Invalid port format. Please use integers, commas, and dashes only.")
        sys.exit(1)
        
    print("-" * 50)
    print(f"Target: {args.target}")
    print(f"Scanning {len(target_ports)} ports with {args.threads} threads")
    start_time = datetime.now()
    print("-" * 50)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(grab_banner, args.target, port) for port in target_ports]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)

    print("-" * 50)
    print(f"Scan completed in: {datetime.now() - start_time}")
