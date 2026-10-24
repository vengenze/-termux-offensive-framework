import requests
import argparse
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_cors(target_url):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
        
    print("-" * 60)
    print(f"[*] Testing CORS misconfigurations for: {target_url}")
    print("-" * 60)
    
    # Test payloads to see how the server handles arbitrary origins
    test_origins = [
        "https://evil.com",
        "null",
        target_url + ".evil.com"
    ]
    
    try:
        # 1. Baseline Request (Normal request)
        base_resp = requests.get(target_url, timeout=5, verify=False)
        print(f"Base Status Code: {base_resp.status_code}\n")
        
        vulnerability_found = False
        
        for origin in test_origins:
            headers = {"Origin": origin}
            try:
                resp = requests.get(target_url, headers=headers, timeout=4, verify=False)
                
                acao = resp.headers.get("Access-Control-Allow-Origin")
                acac = resp.headers.get("Access-Control-Allow-Credentials")
                
                if acao:
                    print(f"[?] Tested Origin: {origin}")
                    print(f"    -> Access-Control-Allow-Origin: {acao}")
                    if acac:
                        print(f"    -> Access-Control-Allow-Credentials: {acac}")
                        
                    # Check for insecure reflection or wildcard with credentials
                    if acao == "*" and acac and acac.lower() == "true":
                        print("    [!] VULNERABLE: Wildcard '*' with credentials enabled!")
                        vulnerability_found = True
                    elif acao == origin:
                        print(f"    [!] VULNERABLE: Arbitrary origin reflected ({acao})!")
                        vulnerability_found = True
                    print()
            except Exception:
                continue
                
        if not vulnerability_found:
            print("[-] No obvious CORS misconfigurations detected.")
            
        print("-" * 60)
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CORS Misconfiguration Scanner")
    parser.add_argument("url", help="Target URL (e.g., http://example.com)")
    
    args = parser.parse_args()
    check_cors(args.url)
