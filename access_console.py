import os
import json
import subprocess
import requests
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OLLAMA_API_URL = "http://127.0.0.1:11434/v1/chat/completions"

def query_ollama(messages, max_tokens=250):
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
    """Executes a multi-step progressive ReAct kill-chain loop: Propose -> Execute -> Adapt -> Progress."""
    print("\n=================================================================")
    print(" [Autonomous Agent] Initializing Multi-Step ReAct Kill-Chain...")
    print("=================================================================")
    
    target = item.get('target', '')
    template = item.get('template', item.get('source', 'Unknown'))
    severity = item.get('severity', 'N/A').upper()

    system_prompt = """You are an autonomous offensive security agent executing a multi-step exploitation and verification loop.
Analyze the target finding and progress through the kill chain.
For each step, provide ONE precise bash/curl/nc/redis-cli command wrapped in ```bash ... ``` using '$TARGET' as the host/URL placeholder.
CRITICAL RULE: If a previous command failed due to timeout or protocol mismatch (e.g. trying HTTP on a non-HTTP port like 6379), you MUST adapt immediately in the next step: switch from HTTP/curl to raw TCP sockets, `nc`, or protocol-specific commands.
Keep your reasoning extremely brief."""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Target Asset: {target}\nVulnerability / Vector: {template}\nSeverity: {severity}\nInitiate step 1: Provide the initial verification command."}
    ]

    max_steps = 2  # Allows the agent to attempt a correction/progression step
    
    for step in range(1, max_steps + 1):
        print(f"\n--- [Kill-Chain Step {step}/{max_steps}] ---")
        print(f"[+] Agent reasoning...")
        ai_response = query_ollama(messages, max_tokens=250)
        print(f"\n[Agent Thought]:\n{ai_response}")

        cmd_match = re.search(r"```(?:bash|sh)?\s*(.*?)\s*```", ai_response, re.DOTALL)
        if not cmd_match:
            print("[-] Agent did not output a command block. Stopping loop.")
            break

        raw_cmd = cmd_match.group(1).strip()
        # Ensure $TARGET replacement works cleanly with ports if needed
        final_cmd = raw_cmd.replace("$TARGET", target)

        print(f"\n[Action] Executing command:\n    {final_cmd}\n")
        
        exec_output = ""
        try:
            result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, timeout=12)
            if result.stdout:
                exec_output += f"STDOUT:\n{result.stdout}\n"
            if result.stderr:
                exec_output += f"STDERR / ERROR:\n{result.stderr}\n"
            if not result.stdout and not result.stderr:
                exec_output += "Command executed successfully with no output returned.\n"
        except subprocess.TimeoutExpired:
            exec_output = "ERROR: Command timed out after 12 seconds (Possible protocol mismatch or blocked port)."
        except Exception as ex:
            exec_output = f"ERROR during execution: {ex}"

        print(f"[Observation Result]:\n{exec_output.strip()}")

        # Feed observation back into conversation history for the next progression step
        messages.append({"role": "assistant", "content": ai_response})
        messages.append({"role": "user", "content": f"Observation result from step {step}:\n{exec_output}\nBased on this output, provide the next corrective command or exploitation progression step."})

    print("\n=================================================================")
    print(" [Autonomous Agent] Finalizing Adaptive Exploitation Verdict...")
    print("=================================================================")
    final_summary = query_ollama(messages, max_tokens=300)
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
        print(" [2] Run manual shell command (supports $TARGET)")
        print(" [3] Run Autonomous AI Agent Loop (Multi-Step ReAct & Adaptive Progression)")
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
                final_cmd = shell_cmd.replace("$TARGET", target_url)
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
