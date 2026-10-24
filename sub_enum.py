import socket
import argparse
import sys
import concurrent.futures
from datetime import datetime

def resolve_subdomain(domain, subdomain):
    """Attempts to resolve a subdomain to an IP address."""
    target = f"{subdomain}.{domain}"
    try:
        # gethostbyname asks the DNS server for the A record (IPv4 address)
        ip = socket.gethostbyname(target)
        return f"[+] Found: {target:<30} | IP: {ip}"
    except socket.gaierror:
        # socket.gaierror is thrown when the DNS record does not exist
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multithreaded Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the subdomain wordlist")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    parser.add_argument("-o", "--output", help="Save results to a text file")
    
    args = parser.parse_args()
    
    try:
        with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: Wordlist file '{args.wordlist}' not found.")
        sys.exit(1)
        
    print("-" * 60)
    print(f"Target Domain  : {args.domain}")
    print(f"Wordlist Size  : {len(subdomains)} words")
    print(f"Threads        : {args.threads}")
    start_time = datetime.now()
    print("-" * 60)
    
    found_subdomains = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(resolve_subdomain, args.domain, sub) for sub in subdomains]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)
                found_subdomains.append(result)

    print("-" * 60)
    print(f"Enumeration completed in: {datetime.now() - start_time}")
    
    if args.output and found_subdomains:
        with open(args.output, 'w') as f:
            f.write(f"Subdomains for {args.domain}\n")
            f.write("-" * 60 + "\n")
            for entry in found_subdomains:
                f.write(entry + "\n")
        print(f"[i] Results saved to {args.output}")
