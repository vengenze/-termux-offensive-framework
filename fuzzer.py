import os
import json
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-yield default wordlist for API and directory fuzzing
DEFAULT_WORDLIST = [
    "api", "api/v1", "api/v2", "graphql", "graphiql", "swagger", "swagger.json",
    "openapi.json", "openapi.yaml", "docs", "help", "admin", "dashboard",
    "login", "auth", "token", "config", ".env", "backup.zip", "backup.bak",
    "users", "accounts", "debug", "metrics", "health", "status", "test",
    "v1", "v2", "internal", "secret", "private", "console", "server-status"
]

def fuzz_endpoint(base_url, word, session, discovered_set, lock):
    url = urljoin(base_url.rstrip("/") + "/", word.lstrip("/"))
    try:
        # Using HEAD first for speed, fallback to GET if needed
        res = session.get(url, timeout=3)
        # Filter out standard 404s and soft 404s based on length
        if res.status_code in [200, 403, 401, 500]:
            with lock:
                print(f"    [+] Found: {url} [Status: {res.status_code} | Len: {len(res.text)}]-")
                discovered_set.add((url, res.status_code))
    except Exception:
        pass

def run_fuzzer(target_url, output_file="scan_results.json", reset_state=False):
    target_url = target_url.strip()
    if target_url and not target_url.startswith("http"):
        target_url = "http://" + target_url
        
    print(f"\n[+] [Fuzzer Module] Initializing Multi-Threaded Native Fuzzer on {target_url}...")
    
    if not target_url:
        print("[!] Error: Empty target URL supplied.")
        return False

    session = requests.Session()
    session.verify = False
    
    discovered_set = set()
    import threading
    lock = threading.Lock()
    
    # Fast multi-threaded execution (15 concurrent workers)
    print(f"    [->] Fuzzing {len(DEFAULT_WORDLIST)} high-value paths...")
    with ThreadPoolExecutor(max_workers=15) as executor:
        for word in DEFAULT_WORDLIST:
            executor.submit(fuzz_endpoint, target_url, word, session, discovered_set, lock)
            
    print(f"    [+] Fuzzer discovered {len(discovered_set)} valid endpoints/directories.")

    # Load existing state
    existing_targets = []
    if not reset_state and os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                existing_targets = json.load(f)
        except Exception:
            pass
            
    existing_urls = {t.get("target") for t in existing_targets if t.get("target")}
    new_count = 0
    
    for url, status in discovered_set:
        if url and url not in existing_urls:
            existing_targets.append({
                "target": url,
                "method": "GET",
                "vulnerability": f"Discovered Endpoint (Fuzzer - Status {status})"
            })
            new_count += 1
            
    with open(output_file, "w") as f:
        json.dump(existing_targets, f, indent=4)
        
    print(f"    [+] Successfully added {new_count} new fuzzing targets to '{output_file}'.")
    return True

if __name__ == "__main__":
    target = input("Enter target URL to fuzz: ").strip()
    if target:
        run_fuzzer(target)
