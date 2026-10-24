import requests
import argparse
import sys
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_open_redirect(target_url):
    print("-" * 60)
    print(f"[*] Scanning parameters for Open Redirect: {target_url}")
    print("-" * 60)
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print("[-] No query parameters found in URL. Skipping Open Redirect scan.")
        print("-" * 60)
        return

    # Canary redirect payloads
    canary_domains = [
        "https://evil-canary-domain.com",
        "//evil-canary-domain.com",
        "https%3A%2F%2Fevil-canary-domain.com"
    ]
    
    # Common parameter names heavily associated with redirection
    redirect_param_hints = ["url", "redirect", "next", "return", "to", "dest", "destination", "goto", "out"]
    
    vulnerable = False
    
    for param in query_params:
        # Prioritize parameters whose names suggest redirection, but test all if needed
        is_hint = any(hint in param.lower() for hint in redirect_param_hints)
        
        print(f"[*] Testing parameter: '{param}' (Redirect hint match: {is_hint})")
        
        for payload in canary_domains:
            test_params = query_params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            redir_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            
            try:
                # Do not follow redirects automatically so we can inspect the Location header
                resp = requests.get(redir_url, timeout=5, verify=False, allow_redirects=False, headers={"User-Agent": "Mozilla/5.0"})
                
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location_header = resp.headers.get("Location", "")
                    if "evil-canary-domain.com" in location_header:
                        print(f"  [!] CRITICAL: OPEN REDIRECT VULNERABILITY FOUND in parameter '{param}'!")
                        print(f"      Injected Payload: {payload}")
                        print(f"      Redirects to Location: {location_header}")
                        print(f"      Exploit URL: {redir_url}")
                        vulnerable = True
                        break
            except Exception:
                continue
        if vulnerable:
            break

    if not vulnerable:
        print("[-] No obvious open redirect vulnerabilities detected.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Open Redirect Vulnerability Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/login.php?next=/dashboard)")
    
    args = parser.parse_args()
    scan_open_redirect(args.url)
