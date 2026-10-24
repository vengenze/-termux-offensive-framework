import requests
import argparse
import re
import sys
from urllib.parse import urljoin, urlparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_js_links(html_content, base_url):
    """Finds all <script src='...'> links in the HTML."""
    # Regex to find src attributes in script tags
    script_pattern = re.rfind if hasattr(re, 'rfind') else re.compile(r'<script[^>]+src=["\'](.*?)["\']', re.IGNORECASE)
    matches = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html_content, re.IGNORECASE)
    
    js_urls = set()
    for match in matches:
        full_url = urljoin(base_url, match)
        js_urls.add(full_url)
    return list(js_urls)

def scan_js_files(target_url):
    print("-" * 60)
    print(f"[*] Scraping JS endpoints and secrets for: {target_url}")
    print("-" * 60)
    
    try:
        response = requests.get(target_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code != 200:
            print(f"[-] Failed to load page. Status code: {response.status_code}")
            return
            
        js_links = extract_js_links(response.text, target_url)
        print(f"[+] Found {len(js_links)} external JavaScript file(s).\n")
        
        # Regex patterns for finding endpoints and sensitive keys
        endpoint_regex = re.compile(r'["\'](/api/[a-zA-Z0-9_/?&=.-]+|[a-zA-Z0-9_-]+\.php|[a-zA-Z0-9_-]+\.json)["\']')
        secret_regex = re.compile(r'(api[_-]?key|secret|token|auth|password|bearer)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{8,})["\']', re.IGNORECASE)
        
        found_endpoints = set()
        found_secrets = set()
        
        for js_url in js_links:
            try:
                js_resp = requests.get(js_url, timeout=4, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                if js_resp.status_code == 200:
                    js_content = js_resp.text
                    
                    # Find endpoints
                    endpoints = endpoint_regex.findall(js_content)
                    for ep in endpoints:
                        found_endpoints.add(ep)
                        
                    # Find secrets/tokens
                    secrets = secret_regex.findall(js_content)
                    for sec in secrets:
                        found_secrets.add((sec[0], sec[1]))
            except Exception:
                continue
                
        # Print Results
        print("[DISCOVERED ENDPOINTS / PATHS]")
        if found_endpoints:
            for ep in sorted(found_endpoints):
                print(f"  > {ep}")
        else:
            print("  (No clear API endpoints matched)")
            
        print("\n[POTENTIAL SECRETS / TOKENS MATCHED]")
        if found_secrets:
            for key_type, val in sorted(found_secrets):
                print(f"  [!] {key_type} found: {val}")
        else:
            print("  (No hardcoded tokens or secrets matched)")
            
        print("-" * 60)
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JavaScript Endpoint & Secret Scraper")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    
    args = parser.parse_args()
    scan_js_files(args.url)
