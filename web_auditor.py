import requests
import argparse
import sys
import urllib3

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def audit_headers(url):
    # Ensure URL has a scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
        
    print("-" * 60)
    print(f"[*] Analyzing security posture for: {url}")
    print("-" * 60)
    
    try:
        response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
        headers = response.headers
        
        print(f"Status Code : {response.status_code}")
        print(f"Final URL   : {response.url}\n")
        
        # 1. Information Disclosure Check
        print("[INFO DISCLOSURE CHECKS]")
        server = headers.get("Server", "Not disclosed / Hidden")
        powered_by = headers.get("X-Powered-By", "Not disclosed / Hidden")
        print(f"  > Server       : {server}")
        print(f"  > X-Powered-By : {powered_by}\n")
        
        # 2. Security Headers Audit
        print("[SECURITY HEADERS AUDIT]")
        security_headers = {
            "Strict-Transport-Security": "HSTS (Enforces secure HTTPS connections)",
            "Content-Security-Policy": "CSP (Mitigates Cross-Site Scripting / XSS)",
            "X-Frame-Options": "Clickjacking Defense (Controls iframe embedding)",
            "X-Content-Type-Options": "Prevents MIME-type sniffing",
            "Referrer-Policy": "Controls how referrer info is sent"
        }
        
        missing_count = 0
        for header, description in security_headers.items():
            if header in headers:
                print(f"  [+] PRESENT : {header}")
            else:
                print(f"  [-] MISSING : {header} -> {description}")
                missing_count += 1
                
        print("-" * 60)
        print(f"Audit complete. Found {missing_count} missing security header(s).")
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTP Security Header & Tech Auditor")
    parser.add_argument("url", help="Target URL or domain (e.g., example.com)")
    
    args = parser.parse_args()
    audit_headers(args.url)
