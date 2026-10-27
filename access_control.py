import os
import json

def run_access_control():
    while True:
        print("\n=================================================================")
        print(" ACCESS GAINED CONTROL CENTER & VULNERABILITY DASHBOARD")
        print("=================================================================")
        
        vulnerabilities = []
        endpoints = []

        # Load Nuclei results safely supporting both JSON array and NDJSON
        if os.path.exists("nuclei_results.json"):
            try:
                with open("nuclei_results.json", "r") as f:
                    content = f.read().strip()
                if content:
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            for item in data:
                                vulnerabilities.append({
                                    "template": item.get("template-id", "unknown"),
                                    "severity": item.get("info", {}).get("severity", "info"),
                                    "target": item.get("matched-at", "")
                                })
                        elif isinstance(data, dict):
                            vulnerabilities.append({
                                "template": data.get("template-id", "unknown"),
                                "severity": data.get("info", {}).get("severity", "info"),
                                "target": data.get("matched-at", "")
                            })
                    except json.JSONDecodeError:
                        # Fallback for line-delimited JSON
                        for line in content.splitlines():
                            if line.strip():
                                try:
                                    item = json.loads(line)
                                    vulnerabilities.append({
                                        "template": item.get("template-id", "unknown"),
                                        "severity": item.get("info", {}).get("severity", "info"),
                                        "target": item.get("matched-at", "")
                                    })
                                except Exception:
                                    pass
            except Exception as e:
                print(f"[!] Error reading nuclei_results.json: {e}")

        # Load Discovered Endpoints
        if os.path.exists("scan_results.json"):
            try:
                with open("scan_results.json", "r") as f:
                    endpoints = json.load(f)
            except Exception:
                pass

        print(f"\n [+] VULNERABILITY FINDINGS (Found: {len(vulnerabilities)}):")
        if vulnerabilities:
            for idx, v in enumerate(vulnerabilities, 1):
                sev = v['severity'].upper()
                print(f"   {idx}. [{sev}] {v['template']} -> {v['target']}")
        else:
            print("   [-] No active vulnerabilities loaded from 'nuclei_results.json'.")

        print("\n [+] DISCOVERED ENDPOINTS / TARGET ASSETS:")
        if endpoints:
            offset = len(vulnerabilities)
            for idx, e in enumerate(endpoints, 1):
                target = e.get("target", "N/A")
                source = e.get("source", "Crawler")
                print(f"   {idx + offset}. [{source}] {target}")
        else:
            print("   [-] No endpoints found in scan state.")
            
        print("=================================================================")
        choice = input("Select item number to inspect, or type '0' to return to main menu: ").strip()
        
        if choice == '0' or not choice:
            break
        
        try:
            sel_idx = int(choice)
            if sel_idx <= len(vulnerabilities):
                selected = vulnerabilities[sel_idx - 1]
                print(f"\n[*] Inspecting Vulnerability:")
                print(f"    - Template ID: {selected['template']}")
                print(f"    - Severity:    {selected['severity'].upper()}")
                print(f"    - Target URL:  {selected['target']}")
            else:
                ep_idx = sel_idx - len(vulnerabilities) - 1
                if 0 <= ep_idx < len(endpoints):
                    selected = endpoints[ep_idx]
                    print(f"\n[*] Inspecting Endpoint Asset:")
                    print(f"    - Target URL:  {selected.get('target')}")
                    print(f"    - Source:      {selected.get('source')}")
                else:
                    print("[!] Invalid selection index.")
        except ValueError:
            print("[!] Please enter a valid number.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    run_access_control()
