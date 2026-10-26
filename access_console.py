import os
import json
import requests
import urllib3
from core.agent import TerminalAgent

# Suppress SSL warnings for self-signed lab certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def interactive_session(item):
    agent = TerminalAgent()
    target_url = item.get("target")
    method = item.get("method", "GET").upper()
    vuln = item.get("vulnerability", "Unknown")
    param = item.get("parameter", "s")

    print("=" * 65)
    print(f" [*] INTERACTIVE SESSION [{vuln.upper()}]")
    print(f" [*] Target: {target_url}         [*] Method: {method}")
    print(f" [*] Copilot Status: Active ({agent.name})")
    print("=" * 65)
    print(" Type 'help' for available commands, or enter your payload/expression.\n")

    while True:
        try:
            user_input = input("(target session)> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_input:
            continue
        if user_input.lower() == "exit":
            break
        if user_input.lower() == "help":
            print("Commands: 'exit' to quit, or enter payloads prefixed with 'exec'.")
            continue

        # Architectural design: Strip the framework's 'exec ' prefix globally
        command_to_run = user_input
        if user_input.lower().startswith("exec "):
            command_to_run = user_input[5:].strip()

        headers = {"User-Agent": "OffensiveFramework/1.0"}
        status_code = 0
        response_body = ""

        try:
            if method == "POST":
                headers["Content-Type"] = "application/json"
                
                payload_data = command_to_run
                # If interacting with tokens/SQLi and input isn't raw JSON, auto-wrap it into the expected JSON structure
                if "tokens" in target_url and not command_to_run.startswith("{"):
                    payload_data = json.dumps({
                        "username": command_to_run,
                        "password": "password123"
                    })

                print(f"[*] Dispatching POST JSON payload to: {target_url}")
                response = requests.post(target_url, data=payload_data, headers=headers, verify=False, timeout=10)
            else:
                print(f"[*] Dispatching GET payload to: {target_url}")
                params = {param: command_to_run}
                response = requests.get(target_url, params=params, headers=headers, verify=False, timeout=10)

            status_code = response.status_code
            try:
                response_body = response.json()
            except Exception:
                response_body = response.text

            formatted_output = json.dumps(response_body, indent=2) if isinstance(response_body, dict) else response_body
            print(f"    [+] Response (HTTP {status_code}):\n{formatted_output}\n")

        except Exception as e:
            status_code = 500
            response_body = {"error": str(e)}
            print(f"    [-] Request failed: {e}\n")

        analysis = agent.analyze_response(item, command_to_run, status_code, response_body)
        if analysis:
            print(f"    [🤖 Agent Insight]: {analysis.get('suggestion')}")
            if analysis.get("corrected_payload"):
                print(f"    [🤖 Auto-Corrected Payload]: {analysis.get('corrected_payload')}")
            for step in analysis.get("next_steps", []):
                print(f"    [💡 Suggested Next Step]: {step}")
            print("-" * 50)

def main():
    if not os.path.exists("scan_results.json"):
        print("[-] No scan_results.json found. Run the automated pipeline first.")
        return

    with open("scan_results.json", "r") as f:
        results = json.load(f)

    if not results:
        print("[-] No vectors found in scan_results.json.")
        return

    while True:
        print("=" * 65)
        print(" [*] ACCESS GAINED CONTROL CENTER (INTERACTIVE DASHBOARD)")
        print("=" * 65)
        for idx, item in enumerate(results, 1):
            print(f" {idx}. [{item.get('vulnerability')}] {item.get('target')} ({item.get('method', 'GET')})")
        print(" 0. Return to Main Menu")
        print("=" * 65)

        choice = input(f"Select target session [0-{len(results)}]: ").strip()
        if choice == "0" or not choice:
            break
        try:
            selected_idx = int(choice) - 1
            if 0 <= selected_idx < len(results):
                interactive_session(results[selected_idx])
            else:
                print("[-] Invalid selection.")
        except ValueError:
            print("[-] Please enter a valid number.")

if __name__ == "__main__":
    main()
