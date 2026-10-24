import os
import glob
import re

def generate_terminal_baseline():
    print("=" * 60)
    print("[*] COMPILED ACTIONABLE BASELINE & TERMINAL SUMMARY")
    print("=" * 60)
    
    # Containers for findings
    critical_findings = []
    live_endpoints = set()
    open_ports = set()
    
    # 1. Gather Open Ports & Web Services
    for f in glob.glob("scan_*.txt") + glob.glob("**/scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "OPEN" in line:
                    open_ports.add(line.strip())
                    
    # 2. Gather API / Sensitive / Param Vulnerabilities
    for f in glob.glob("api_scan_*.txt") + glob.glob("param_scan_*.txt") + glob.glob("sensitive_scan_*.txt") + glob.glob("jwt_scan_*.txt") + glob.glob("**/api_scan_*.txt", recursive=True) + glob.glob("**/param_scan_*.txt", recursive=True) + glob.glob("**/sensitive_scan_*.txt", recursive=True) + glob.glob("**/jwt_scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "CRITICAL" in line or "EXPOSED" in line or "VULNERABLE" in line:
                    critical_findings.append(line.strip())

    # 3. Gather URLs / Endpoints for further probing
    for f in glob.glob("fuzz_*.txt") + glob.glob("js_scan_*.txt") + glob.glob("api_scan_*.txt") + glob.glob("**/fuzz_*.txt", recursive=True) + glob.glob("**/js_scan_*.txt", recursive=True) + glob.glob("**/api_scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                urls = re.findall(r'https?://[^\s]+', line)
                for u in urls:
                    live_endpoints.add(u.strip())
    # Gather Cloud Bucket Findings
    for f in glob.glob("bucket_scan_*.txt") + glob.glob("**/bucket_scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "CRITICAL" in line or "EXISTS" in line:
                    critical_findings.append(line.strip())

    # --- PRINT TERMINAL SUMMARY ---
    print(f"\n[!] CRITICAL & HIGH-VALUE FINDS ({len(critical_findings)}):")
    if critical_findings:
        for find in critical_findings[:15]: # Show top 15
            print(f"    \033[91m-> {find}\033[0m")
    else:
        print("    \033[92m[-] No high-risk vulnerabilities matched current signatures.\033[0m")

    print(f"\n[+] OPEN PORTS & SERVICES ({len(open_ports)}):")
    if open_ports:
        for port in sorted(list(open_ports))[:10]:
            print(f"    -> {port}")
    
    print(f"\n[+] DISCOVERED PROBING ENDPOINTS ({len(live_endpoints)} URLs):")
    
    # --- WRITE ACTIONABLE BASELINE FILE ---
    baseline_filename = "probe_baseline.txt"
    with open(baseline_filename, "w", encoding="utf-8") as out:
        out.write("# === OFFENSIVE FRAMEWORK PROBING BASELINE ===\n")
        out.write("# Use this file as input for further manual/automated probing (e.g., curl, ffuf, sqlmap)\n\n")
        
        out.write("## CRITICAL FINDINGS\n")
        for cf in critical_findings:
            out.write(f"{cf}\n")
            
        out.write("\n## OPEN PORTS\n")
        for op in sorted(list(open_ports)):
            out.write(f"{op}\n")
            
        out.write("\n## TARGET URLS & ENDPOINTS\n")
        for url in sorted(list(live_endpoints)):
            out.write(f"{url}\n")
            
    print(f"\n[+] Baseline successfully saved to: '{baseline_filename}'")
    print("=" * 60)

if __name__ == "__main__":
    generate_terminal_baseline()
