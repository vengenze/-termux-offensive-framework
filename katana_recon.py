import os
import json
import requests
import urllib3
import re
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_katana(target_url, output_file="scan_results.json", reset_state=True):
    target_url = target_url.strip()
    if target_url and not target_url.startswith("http"):
        target_url = "http://" + target_url
        
    print(f"\n[+] [Recon Module] Initializing Native High-Performance Crawler on {target_url}...")
    
    if not target_url:
        print("[!] Error: Empty target URL supplied.")
        return False

    session = requests.Session()
    session.verify = False  # Bypasses self-signed lab certificate blocks
    
    visited = set()
    to_visit = {target_url}
    discovered_endpoints = set()
    
    parsed_base = urlparse(target_url)
    base_netloc = parsed_base.netloc
    
    max_pages = 40  # Expanded crawl depth for deep discovery
    count = 0
    
    print("    [->] Crawling target endpoints & parsing document structure...")
    while to_visit and count < max_pages:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)
        count += 1
        
        try:
            res = session.get(current_url, timeout=5)
            discovered_endpoints.add(current_url)
            
            content_type = res.headers.get("Content-Type", "")
            # Parse HTML, JS, and JSON documents for hidden routes
            if any(t in content_type for t in ["html", "json", "javascript", "text"]):
                # Extract href attributes, action endpoints, and API paths
                links = re.findall(r'(?:href|src|action)=["\'](.*?)["\']', res.text)
                # Also look for explicit path strings in script bodies
                api_paths = re.findall(r'["\'](/api/v[0-9]+/[^"\']+|/[a-zA-Z0-9_-]+)[\'"]', res.text)
                
                for link in links:
                    full_url = urljoin(current_url, link)
                    parsed_link = urlparse(full_url)
                    if parsed_link.netloc == base_netloc and full_url not in visited:
                        to_visit.add(full_url)
                        
                for path in api_paths:
                    full_url = urljoin(target_url, path)
                    discovered_endpoints.add(full_url)
                    
        except Exception:
            continue
            
    # Ensure standard discovery paths are always checked
    common_paths = ["/openapi.json", "/openapi.yaml", "/swagger.json", "/docs", "/help", "/api", "/graphql"]
    for path in common_paths:
        test_url = urljoin(target_url, path)
        try:
            chk = session.head(test_url, timeout=3)
            if chk.status_code < 400:
                discovered_endpoints.add(test_url)
        except Exception:
            pass

    print(f"    [+] Crawler successfully mapped {len(discovered_endpoints)} unique endpoints.")

    existing_targets = []
    if not reset_state and os.path.exists(output_file):
        try:
            with open(output_file, "r") as f:
                existing_targets = json.load(f)
        except Exception:
            pass
            
    existing_urls = {t.get("target") for t in existing_targets if t.get("target")}
    new_count = 0
    
    for ep in discovered_endpoints:
        if ep and ep not in existing_urls:
            existing_targets.append({
                "target": ep,
                "method": "GET",
                "vulnerability": "Discovered Endpoint (Native Crawler)"
            })
            new_count += 1
            
    with open(output_file, "w") as f:
        json.dump(existing_targets, f, indent=4)
        
    print(f"    [+] Successfully updated '{output_file}' with {new_count} new endpoints.")
    return True

if __name__ == "__main__":
    target = input("Enter target URL to crawl: ").strip()
    if target:
        run_katana(target)
