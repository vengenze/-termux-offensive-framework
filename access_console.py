import os
import json
import subprocess
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OLLAMA_API_URL = "http://127.0.0.1:11434/v1/chat/completions"

def query_ollama(messages, max_tokens=200):
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
            return f"[!] Ollama error {res.status_code}: {res.text}"
    except Exception as e:
        return f"[!] Connection error: Ensure 'ollama serve' is running on port 11434. ({e})"

def run_autonomous_agent_loop(item):
    """Executes a 5-step ReAct chain using robust Python socket automation."""
    print("\n=================================================================")
    print(" [Autonomous Agent] Initializing Python-Socket ReAct Chain...")
    print("=================================================================")
    
    target = item.get('target', '')
    template = item.get('template', item.get('source', 'Unknown'))
    severity = item.get('severity', 'N/A').upper()

    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    if ":" in clean_target:
        target_host, target_port = clean_target.split(":", 1)
    else:
        target_host, target_port = clean_target, "80"

    system_prompt = """You are an autonomous offensive security agent executing an adaptive kill-chain.
AVAILABLE MACROS:
- $HOST = Hostname or IP ({target_host})
- $PORT = Port number ({target_port})

CRITICAL RULES:
1. Avoid native netcat hanging issues by using Python socket one-liners to query raw TCP services.
2. Example Python TCP query: `python3 -c "import socket; s = socket.socket(); s.settimeout(3); s.connect(('$HOST', int($PORT))); s.send(b'INFO\\r\\n'); print(s.recv(1024)); s.close()"`
3. If a command times out or returns no output, try a different command or payload in the next step.
4. Output your single shell command inside ```bash ... ``` code blocks.""".format(
        target_host=target_host, target_port=target_port
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Target Asset: {target}\nVulnerability / Vector: {template}\nSeverity: {severity}\nStep 1: Provide python socket query command to test service."}
    ]

    max_steps = 5
    
    for step in range(1, max_steps + 1):
        print(f"\n--- [Kill-Chain Step {step}/{max_steps}] ---")
        print(f"[+] Agent reasoning...")
        ai_response = query_ollama(messages, max_tokens=200)
        print(f"\n[Agent Thought]:\n{ai_response}")

        cmd_match = re.search(r"```(?:bash|sh)?\s*(.*?)\s*```", ai_response, re.DOTALL)
        raw_cmd = ""
        
        if cmd_match:
            raw_cmd = cmd_match.group(1).strip()
        else:
            for line in ai_response.splitlines():
                line_clean = line.strip()
                if any(tool in line_clean for tool in ["python3 ", "nc ", "curl ", "redis-cli "]):
                    raw_cmd = line_clean
                    break
        
        if not raw_cmd:
            raw_cmd = f"python3 -c \"import socket; s = socket.socket(); s.settimeout(3); s.connect(('$HOST', int($PORT))); s.send(b'INFO\\r\\n'); print(s.recv(1024)); s.close()\""

        final_cmd = raw_cmd.replace("$TARGET", target).replace("$HOST", target_host).replace("$PORT", target_port)

        print(f"\n[Action] Executing command:\n    {final_cmd}\n")
        
        exec_output = ""
        try:
            result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, timeout=8)
            if result.stdout:
                exec_output += f"STDOUT:\n{result.stdout}\n"
            if result.stderr:
                exec_output += f"STDERR / ERROR:\n{result.stderr}\n"
            if not result.stdout and not result.stderr:
                exec_output += "NO_OUTPUT_WARNING: Command executed but returned no data.\n"
        except subprocess.TimeoutExpired:
            exec_output = "ERROR: Command timed out after 8 seconds."
        except Exception as ex:
            exec_output = f"ERROR during execution: {ex}"

        print(f"[Observation Result]:\n{exec_output.strip()}")

        messages.append({"role": "assistant", "content": ai_response})
        messages.append({"role": "user", "content": f"Observation result from step {step}:\n{exec_output}\nAnalyze this output. If it timed out or returned no data, modify your python payload or try a different command string in the next step."})

    print("\n=================================================================")
    print(" [Autonomous Agent] Finalizing Adaptive Exploitation Verdict...")
    print("=================================================================")
    final_summary = query_ollama(messages, max_tokens=250)
    print(f"\n{final_summary}")
    
    input("\nPress Enter to continue...")

def inspect_and_action_item(item, item_type):
    """Sub-menu workbench for an individual selected vulnerability or endpoint asset."""
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
        print(" [2] Run manual shell command (supports $TARGET, $HOST, $PORT)")
        print(" [3] Run Autonomous AI Agent Loop (Python-Socket ReAct)")
        print(" [0] Back to Dashboard")
        print("=================================================================")

        choice = input("Select action [0-3]: ").strip()

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
            run_autonomous_agent_loop(item)
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
