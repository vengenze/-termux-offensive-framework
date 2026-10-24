import requests
import argparse
import sys
import concurrent.futures
from datetime import datetime

# Suppress insecure request warnings if testing self-signed SSL targets
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_directory(base_url, directory):
    """Sends a GET request to the target URL + directory."""
    # Ensure URL formatting is clean
    if not base_url.endswith('/'):
        base_url += '/'
        
    target_url = f"{base_url}{directory}"
    
    try:
        # allow_redirects=False lets us see 301/302 redirects instead of blindly following them
        # verify=False ignores SSL certificate errors
        response = requests.get(target_url, timeout=3, allow_redirects=False, verify=False)
        
        # 404 means 'Not Found'. Anything else (200 OK, 301 Redirect, 403 Forbidden) is interesting.
        if response.status_code != 404:
            return f"[+] Found: {target_url:<30} | Status: {response.status_code}"
            
        return None
    except requests.exceptions.RequestException:
        # Silently drop connection errors to keep the terminal output clean
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multithreaded Web Directory Fuzzer")
    parser.add_argument("url", help="Target base URL (e.g., http://192.168.1.1)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the dictionary/wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Number of concurrent threads (default: 30)")
    
    args = parser.parse_args()
    
    # 1. Load the wordlist into a Python list
    try:
        with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            # Read lines and strip out newline characters
            directories = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: Wordlist file '{args.wordlist}' not found.")
        sys.exit(1)
        
    print("-" * 60)
    print(f"Fuzzing Target : {args.url}")
    print(f"Wordlist Size  : {len(directories)} words")
    print(f"Threads        : {args.threads}")
    start_time = datetime.now()
    print("-" * 60)
    
    # 2. Execute the threaded attack
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit tasks
        futures = [executor.submit(check_directory, args.url, dir_name) for dir_name in directories]
        
        # Print results as they are found
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)

    print("-" * 60)
    print(f"Fuzzing completed in: {datetime.now() - start_time}")
