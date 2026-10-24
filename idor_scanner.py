import sys
import urllib.request
import urllib.error
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def banner():
    print("=============================================================")
    print(" [*] ULTRA-FAST OPTIMIZED IDOR / BOLA SCANNER")
    print("=============================================================")

def test_single_id(mutated_url, base_len):
    try:
        # Tight 1-second timeout to fail fast on slow/dead nodes
        req = urllib.request.Request(mutated_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=1.0) as resp:
            code = resp.getcode()
            content = resp.read().decode('utf-8', errors='ignore')
            content_len = len(content)
            
            if code == 200 and abs(content_len - base_len) > 2:
                return {"url": mutated_url, "status": code, "length": content_len, "vulnerable": True}
            return {"url": mutated_url, "status": code, "length": content_len, "vulnerable": False}
    except Exception:
        return None

def test_idor(target_url):
    banner()
    print(f"[*] Target URL: {target_url}")
    
    matches = list(re.finditer(r'([/=])(\d+)', target_url))
    if not matches:
        print("[-] No numeric ID found in URL pattern.")
        return []
    
    last_match = matches[-1]
    base_id = int(last_match.group(2))
    
    id_str = str(base_id)
    idx = target_url.rfind(id_str)
    url_prefix = target_url[:idx]
    tail = target_url[idx + len(id_str):]
    
    # Pre-flight check: Establish baseline and ensure 200 OK before wasting time
    base_len = 0
    try:
        req_base = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_base, timeout=1.5) as resp:
            if resp.getcode() != 200:
                print(f"[-] Base endpoint returned HTTP {resp.getcode()}. Skipping IDOR to save time.")
                return []
            base_len = len(resp.read().decode('utf-8', errors='ignore'))
    except Exception:
        print("[-] Base endpoint unreachable. Skipping IDOR scan.")
        return []

    # Optimized high-yield mutation set (only check +1, -1, +10 to maximize speed)
    test_ids = list(set([max(1, base_id - 1), base_id + 1, base_id + 10]))
    print(f"[*] Base ID {base_id} validated. Fuzzing high-yield offsets {test_ids} concurrently...\n")
    
    vulnerable_endpoints = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(test_single_id, f"{url_prefix}{tid}{tail}", base_len): tid 
            for tid in test_ids
        }
        
        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                if result["vulnerable"]:
                    print(f"    [!] POTENTIAL IDOR FOUND: {result['url']} (HTTP {result['status']}, Length: {result['length']})")
                    vulnerable_endpoints.append(result)
                else:
                    print(f"    [-] Tested {result['url']} -> HTTP {result['status']} (Length: {result['length']})")

    print("\n=============================================================")
    print(f"[*] IDOR scan complete. Found {len(vulnerable_endpoints)} potential finding(s).")
    print("=============================================================")
    return vulnerable_endpoints

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python idor_scanner.py <url_with_id>")
        sys.exit(1)
        
    results = test_idor(sys.argv[1])
    if results:
        with open("idor_findings.json", "w") as f:
            json.dump(results, f, indent=4)
        print("[+] Saved IDOR findings to 'idor_findings.json'")
