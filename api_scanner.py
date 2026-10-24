import requests
import argparse
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-value API documentation, debug routes, and GraphQL endpoints
API_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/api-docs",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/graphiql",
    "/api/swagger.json",
    "/api/docs"
]

def scan_apis(target_url):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
        
    target_url = target_url.rstrip("/")
    
    print("-" * 60)
    print(f"[*] Scanning for exposed API documentation & endpoints: {target_url}")
    print("-" * 60)
    
    # Establish baseline to catch soft 404s
    fake_path = "/nonexistent-api-xyz-98765"
    try:
        base_resp = requests.get(target_url + fake_path, timeout=4, verify=False, allow_redirects=False)
        baseline_len = len(base_resp.text)
        baseline_status = base_resp.status_code
    except Exception:
        baseline_len = -1
        baseline_status = 404

    found_apis = 0

    for path in API_PATHS:
        url = f"{target_url}{path}"
        try:
            resp = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            content_len = len(resp.text)
            
            # Check for valid exposure (Status 200/401/403 with real content)
            if resp.status_code in [200, 401, 403] and baseline_status != resp.status_code:
                if abs(content_len - baseline_len) > 30 and content_len > 0:
                    print(f"  [!] EXPOSED API ENDPOINT / DOCS FOUND: {url}")
                    print(f"      Status: {resp.status_code} | Length: {content_len} bytes")
                    found_apis += 1
        except Exception:
            continue

    if found_apis == 0:
        print("[-] No exposed API documentation or endpoints discovered.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Route & Swagger Discovery Scanner")
    parser.add_argument("url", help="Target base URL (e.g., http://example.com)")
    
    args = parser.parse_args()
    scan_apis(args.url)
