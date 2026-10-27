import os
import json
import subprocess
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def inspect_and_action_item(item, item_type):
    """Sub-menu workbench for an individual selected vulnerability or endpoint."""
    session = requests.Session()
    session.verify = False

    while True:
        print("\n=================================================================")
        if item_type == "vulnerability":
            print(f" VULNERABILITY INSPECTION: [{item.get('severity', 'info').upper()}] {item.get('template')}")
            print("=================================================================")
            print(f" Target URL : {item.get('target')}")
            print(f" Template ID: {item.get('template')}")
        else:
            print(f" ENDPOINT ASSET INSPECTION: {item.get('target')}")
            print("=================================================================")
            print(f" Source     : {item.get('source', 'Unknown')}")
            print(f" Target URL : {item.get('target')}")

        print("-----------------------------------------------------------------")
        print(" [1] Send standard HTTP probe / connectivity check")
        print(" [2] Run custom diagnostic command or payload validation")
        print(" [0] Back to Dashboard")
        print("=================================================================")

        choice = input("Select action [0-2]: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            target_url = item.get("target")
            print(f"\n[->] Probing target: {target_url}")
            try:
                res = session.get(target_url, timeout=10)
                print(f"[+] Response Status: {res.status_code} | Length: {len(res.text)}")
                print(f"[+] Snippet:\n{res.text[:400]}...")
            except Exception as e:
                print(f"[!] Probe failed: {e}")
            input("\nPress Enter to continue...")
        elif choice == '2':
            target_url = item.get("target")
            print(f"\n[Diagnostic Workbench] Target: {target_url}")
            custom_cmd = input("Enter custom diagnostic command or modifier (or press Enter to skip): ").strip()
            
            if custom_cmd:
                print(f"[+] Executing diagnostic routine with input: {custom_cmd}")
                # Safe execution wrapper or custom validation logic here
                try:
                    # Example: Test parameter injection or path validation safely
                    test_url = f"{target_url.rstrip('/')}/{custom_cmd}"
                    res = session.get(test_url, timeout=10)
                    print(f"    [Status]: {res.status_code} | Length: {len(res.text)}")
                except Exception as ex:
                    print(f"    [!] Error: {ex}")
            else:
                print("[-] No command entered.")
            input("\nPress Enter to continue...")
        else:
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")

def run_access_control():
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        print("=================================================================")
        print(" ACCESS GAINED CONTROL CENTER & VULNERABILITY DASHBOARD")
        print("=================================================================")
        
        vulnerabilities = []
        endpoints = []

        # 1. Load Nuclei results safely (supports arrays and NDJSON)
        if os.path.exists("nuclei_results.json"):
            try:
                with open("nuclei_results.json", "r") as f:
                    content = f.read().strip()
                if content:
                    try:
                        data = json.loads(content)
                        items = data if isinstance(data, list) else [data]
                        for item in items:
                            vulnerabilities.append({
                                "template": item.get("template-id", "unknown"),
                                "severity": item.get("info", {}).get("severity", "info"),
                                "target": item.get("matched-at", "")
                            })
                    except json.JSONDecodeError:
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

        # 2. Load Discovered Endpoints from pipeline state
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
            print("   [-] No active vulnerabilities loaded from 'nuclei_results.json'. Run a pipeline scan first.")

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
                inspect_and_action_item(selected, "vulnerability")
            else:
                ep_idx = sel_idx - len(vulnerabilities) - 1
                if 0 <= ep_idx < len(endpoints):
                    selected = endpoints[ep_idx]
                    inspect_and_action_item(selected, "endpoint")
                else:
                    print("[!] Invalid selection index.")
                    input("\nPress Enter to continue...")
        except ValueError:
            print("[!] Please enter a valid number.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    run_access_control()
