import requests
import argparse
import sys
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common database error signatures
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "sqlite3.operationalerror",
    "syntax error in sql statement"
]

def scan_parameters(target_url):
    print("-" * 60)
    print(f"[*] Scanning parameters for SQLi & XSS: {target_url}")
    print("-" * 60)
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print("[-] No query parameters found in URL (e.g., ?id=1). Skipping parameter scan.")
        print("-" * 60)
        return

    # Payloads to test
    sqli_payload = "'"
    xss_payload = "<script>alert(1)</script>"
    
    vulnerable = False
    
    for param in query_params:
        print(f"[*] Testing parameter: '{param}'")
        
        # Test SQLi
        test_params = query_params.copy()
        test_params[param] = [sqli_payload]
        new_query = urlencode(test_params, doseq=True)
        sqli_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
        
        try:
            resp = requests.get(sqli_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            body_lower = resp.text.lower()
            
            for err in SQL_ERRORS:
                if err in body_lower:
                    print(f"  [!] POTENTIAL SQL INJECTION FOUND in parameter '{param}'!")
                    print(f"      Matched error signature: '{err}'")
                    print(f"      Payload URL: {sqli_url}")
                    vulnerable = True
                    break
        except Exception:
            pass

        # Test XSS
        test_params[param] = [xss_payload]
        new_query = urlencode(test_params, doseq=True)
        xss_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
        
        try:
            resp = requests.get(xss_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            if xss_payload in resp.text:
                print(f"  [!] POTENTIAL REFLECTED XSS FOUND in parameter '{param}'!")
                print(f"      Payload reflected at: {xss_url}")
                vulnerable = True
        except Exception:
            pass

    if not vulnerable:
        print("[-] No obvious parameter injection vulnerabilities detected.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight SQLi & XSS Parameter Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/page.php?id=1)")
    
    args = parser.parse_args()
    scan_parameters(args.url)
