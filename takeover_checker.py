import requests
import argparse
import sys
import socket
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known vulnerable service signatures in HTTP response bodies
TAKEOVER_SIGNATURES = {
    "GitHub Pages": "There isn't a GitHub Pages site here.",
    "AWS S3 / Bucket": "NoSuchBucket",
    "Heroku": "No such app",
    "Azure": "The specified resource does not exist",
    "Shopify": "Sorry, this shop is currently unavailable",
    "WordPress": "Do you want to register"
}

def check_takeover(domain):
    print("-" * 60)
    print(f"[*] Checking subdomain takeover indicators for: {domain}")
    print("-" * 60)
    
    try:
        # Resolve IP or CNAME check using socket
        ip = socket.gethostbyname(domain)
        print(f"  > Resolved IP: {ip}")
    except socket.gaierror:
        print("  [-] Resolution failed (Potentially a dangling CNAME record!).")
        return

    # Check via HTTPS / HTTP
    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, timeout=4, verify=False, headers={"User-Agent": "Mozilla/5.0"})
            body = response.text
            
            for service, signature in TAKEOVER_SIGNATURES.items():
                if signature.lower() in body.lower():
                    print(f"  [!] VULNERABLE TO TAKEOVER ({service})!")
                    print(f"      Signature matched: '{signature}' at {url}")
                    return
        except requests.exceptions.RequestException:
            continue
            
    print("  [-] No obvious takeover signatures matched.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdomain Takeover & Dangling DNS Checker")
    parser.add_argument("domain", help="Target subdomain (e.g., dev.example.com)")
    
    args = parser.parse_args()
    check_takeover(args.domain)
