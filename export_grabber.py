import socket
import argparse
import sys
import csv
from datetime import datetime
import concurrent.futures

def parse_ports(port_str):
    """Converts a string like '22,80,100-110' into a unique, sorted list of integers."""
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-')
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

def grab_banner(ip, port):
    """Scans a port and returns a tuple (port, banner) if open."""
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
            
            # Return raw data instead of a formatted string
            if banner:
                return (port, banner)
            else:
                return (port, "(No banner)")
                
        s.close()
        return None
    except socket.error:
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fast Threaded Banner Grabber with Export",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("target", help="Target IP address or domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", help="Save results to file (e.g., results.txt or results.csv)")
    
    args = parser.parse_args()
    
    try:
        target_ports = parse_ports(args.ports)
    except ValueError:
        print("[-] Error: Invalid port format.")
        sys.exit(1)
        
    print("-" * 50)
    print(f"Target: {args.target}")
    print(f"Scanning {len(target_ports)} ports with {args.threads} threads")
    start_time = datetime.now()
    print("-" * 50)
    
    # We need a list to store our results before we write them to a file
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(grab_banner, args.target, port) for port in target_ports]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                # 1. Print to the terminal in real-time
                print(f"[+] Port {port:<5} | OPEN | {banner}")
                # 2. Save the raw tuple to our list for later
                open_ports.append((port, banner))

    print("-" * 50)
    print(f"Scan completed in: {datetime.now() - start_time}")
    
    # Handle the file export if the user provided an -o argument
    if args.output:
        # Sort the ports so the file is organized sequentially
        open_ports.sort(key=lambda x: x[0])
        
        if args.output.lower().endswith('.csv'):
            # Save as CSV
            with open(args.output, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Port', 'Status', 'Banner']) # Header row
                for port, banner in open_ports:
                    writer.writerow([port, 'OPEN', banner])
        else:
            # Save as standard text
            with open(args.output, 'w') as txtfile:
                txtfile.write(f"Scan results for {args.target}\n")
                txtfile.write("-" * 50 + "\n")
                for port, banner in open_ports:
                    txtfile.write(f"Port {port:<5} | OPEN | {banner}\n")
                    
        print(f"[i] Results successfully saved to {args.output}")
