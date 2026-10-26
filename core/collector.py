import os
import json
import requests
import yaml
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ingest_openapi_spec(base_url, output_file="scan_results.json"):
    """Fetches and parses the OpenAPI spec from the target, saving all endpoints to a shared file."""
    spec_url = f"{base_url.rstrip('/')}/openapi.yaml"
    print(f"[*] Ingesting OpenAPI spec from: {spec_url}")
    
    try:
        response = requests.get(spec_url, verify=False, timeout=5)
        if response.status_code != 200:
            print(f"[-] Failed to fetch OpenAPI spec (HTTP {response.status_code})")
            return False

        # Parse YAML spec
        spec_data = yaml.safe_load(response.text)
        paths = spec_data.get("paths", {})
        
        discovered_endpoints = []
        for path, methods in paths.items():
            for method, details in methods.items():
                summary = details.get("summary", "API Endpoint")
                discovered_endpoints.append({
                    "target": f"{base_url.rstrip('/')}{path}",
                    "vulnerability": summary,
                    "method": method.upper(),
                    "parameter": "query" # Default placeholder
                })

        # Save to shared file
        with open(output_file, "w") as f:
            json.dump(discovered_endpoints, f, indent=4)
            
        print(f"[+] Successfully mapped and linked {len(discovered_endpoints)} endpoints to {output_file}")
        return True

    except Exception as e:
        print(f"[-] Error ingesting spec: {e}")
        return False

if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    ingest_openapi_spec(target)
