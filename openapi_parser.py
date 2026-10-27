import os
import json
import requests
import urllib3
import re
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_openapi_specs(scan_state_file="scan_results.json"):
    print(f"\n[+] [OpenAPI Module] Scanning state for Swagger/OpenAPI documentation specs...")
    if not os.path.exists(scan_state_file):
        print("    [-] Scan state file not found.")
        return False
        
    try:
        with open(scan_state_file, "r") as f:
            targets = json.load(f)
    except Exception:
        return False
        
    session = requests.Session()
    session.verify = False
    
    new_endpoints = []
    # Identify any discovered specs in our state
    spec_urls = [t.get("target") for t in targets if t.get("target") and any(x in t.get("target").lower() for x in ["openapi", "swagger"])]
    
    if not spec_urls:
        print("    [-] No OpenAPI/Swagger specification URLs found in current state.")
        return False
        
    for spec_url in spec_urls:
        print(f"    [->] Parsing spec document: {spec_url}")
        try:
            res = session.get(spec_url, timeout=5)
            if res.status_code != 200:
                continue
                
            spec_data = None
            # Attempt JSON parsing first
            try:
                spec_data = res.json()
            except Exception:
                # Fallback regex extraction for YAML-based specs
                paths = re.findall(r'^\s{2}/[a-zA-Z0-9_\-/{}]+:', res.text, re.MULTILINE)
                base_parsed = urlparse(spec_url)
                base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
                for p in paths:
                    clean_path = p.strip().rstrip(":")
                    full_ep = urljoin(base_origin, clean_path)
                    new_endpoints.append({
                        "target": full_ep,
                        "method": "GET",
                        "vulnerability": "Extracted via OpenAPI Spec (Regex Fallback)"
                    })
                continue

            if spec_data and isinstance(spec_data, dict):
                paths = spec_data.get("paths", {})
                base_parsed = urlparse(spec_url)
                base_origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
                
                # Check for OpenAPI 3.x server configuration
                servers = spec_data.get("servers", [])
                if servers and isinstance(servers, list):
                    server_url = servers[0].get("url")
                    if server_url:
                        if server_url.startswith("http"):
                            base_origin = server_url.rstrip("/")
                        else:
                            base_origin = urljoin(base_origin, server_url)

                for path, methods in paths.items():
                    if isinstance(methods, dict):
                        for method in methods.keys():
                            if method.lower() in ["get", "post", "put", "delete", "patch"]:
                                full_ep = urljoin(base_origin + "/", path.lstrip("/"))
                                new_endpoints.append({
                                    "target": full_ep,
                                    "method": method.upper(),
                                    "vulnerability": f"Extracted Endpoint (OpenAPI Spec - {method.upper()})"
                                })
        except Exception as e:
            print(f"        [!] Failed to parse {spec_url}: {e}")
            
    if new_endpoints:
        existing_urls = {t.get("target") for t in targets}
        added_count = 0
        for ep in new_endpoints:
            if ep["target"] not in existing_urls:
                targets.append(ep)
                existing_urls.add(ep["target"])
                added_count += 1
                
        with open(scan_state_file, "w") as f:
            json.dump(targets, f, indent=4)
        print(f"    [+] Successfully extracted and added {added_count} new API endpoints from OpenAPI specs!")
        return True
        
    print("    [-] No new endpoints extracted from specs.")
    return False

if __name__ == "__main__":
    parse_openapi_specs()
