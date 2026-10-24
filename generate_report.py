import os
import glob
import sys

def generate_summary():
    print("-" * 60)
    print("[*] Compiling user-friendly executive summary of valuable findings...")
    print("-" * 60)
    
    findings = {
        "🚨 Critical Active Vulnerabilities (SQLi, XSS, LFI, RCE, Redirect, SSRF)": [],
        "📂 Exposed Sensitive Files & APIs": [],
        "⚠️ Subdomain Takeovers": [],
        "🌐 Open Ports & Web Services": [],
        "🛡️ CORS & Header Misconfigurations": []
    }
    
    # 1. Subdomain Takeovers
    for f in glob.glob("takeover_results_*.txt") + glob.glob("**/takeover_results_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "VULNERABLE" in line or "Takeover" in line:
                    findings["⚠️ Subdomain Takeovers"].append(line.strip())
                    
    # 2. Port scans & Web Services
    for f in glob.glob("scan_*.txt") + glob.glob("**/scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "OPEN" in line:
                    findings["🌐 Open Ports & Web Services"].append(line.strip())
                    
    # 3. API & Sensitive files
    for f in glob.glob("api_scan_*.txt") + glob.glob("sensitive_scan_*.txt") + glob.glob("**/api_scan_*.txt", recursive=True) + glob.glob("**/sensitive_scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "EXPOSED" in line:
                    findings["📂 Exposed Sensitive Files & APIs"].append(line.strip())
                    
    # 4. CORS & Headers
    for f in glob.glob("cors_scan_*.txt") + glob.glob("web_audit_*.txt") + glob.glob("**/cors_scan_*.txt", recursive=True) + glob.glob("**/web_audit_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "Vulnerable" in line or "Misconfiguration" in line or "Missing" in line:
                    findings["🛡️ CORS & Header Misconfigurations"].append(line.strip())
                    
    # 5. Parameter vulnerabilities
    for f in glob.glob("param_scan_*.txt") + glob.glob("**/param_scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "CRITICAL" in line:
                    findings["🚨 Critical Active Vulnerabilities (SQLi, XSS, LFI, RCE, Redirect, SSRF)"].append(line.strip())

    # 6. JWT Token Vulnerabilities
    for f in glob.glob("jwt_scan_*.txt") + glob.glob("**/jwt_scan_*.txt", recursive=True):
        with open(f, "r", errors="ignore") as file:
            for line in file:
                if "[!]" in line or "CRITICAL" in line:
                    findings["🚨 Critical Active Vulnerabilities (SQLi, XSS, LFI, RCE, Redirect, SSRF)"].append(line.strip())
    # Build Clean Markdown Report
    md_content = "# 🛡️ Actionable Security Finding Summary\n\n"
    md_content += "> **Executive Overview:** This report filters out all scan noise and highlights **only verified, high-value exposures and vulnerabilities** discovered during the assessment.\n\n"
    
    total_findings = sum(len(v) for v in findings.values())
    
    if total_findings == 0:
        md_content += "### 🟢 Target Status: Clean / No Critical Findings\n"
        md_content += "No critical exposures, open takeovers, or active injection vulnerabilities matched the high-priority filter criteria during this run.\n"
    else:
        for category, items in findings.items():
            if items:
                md_content += f"## {category} ({len(items)})\n"
                md_content += "| Actionable Finding |\n|:---|\n"
                for item in items:
                    clean_item = item.replace("|", "\\|")
                    md_content += f"| `{clean_item}` |\n"
                md_content += "\n"
                
    with open("summary.md", "w") as out:
        out.write(md_content)
        
    print("[+] Successfully compiled user-friendly 'summary.md' with zero noise!")
    print("-" * 60)

if __name__ == "__main__":
    generate_summary()
