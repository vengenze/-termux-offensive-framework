from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class MockVulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        decoded_path = urllib.parse.unquote_plus(self.path)
        
        self.send_response(200)
        self.end_headers()
        
        # Check for web shell command execution
        if "cmd=" in decoded_path:
            cmd = decoded_path.split("cmd=")[1].split("&")[0]
            if cmd == "id":
                self.wfile.write(b"uid=0(root) gid=0(root) groups=0(root)")
            elif cmd == "whoami":
                self.wfile.write(b"root")
            else:
                self.wfile.write(f"Command executed: {cmd}\nOutput: Mock system operational.".encode())
            return

        # Check for error-based injection quote
        if "'" in decoded_path and "ORDER BY" not in decoded_path.upper():
            self.wfile.write(b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
            return
            
        # Check for ORDER BY column enumeration
        if "ORDER BY" in decoded_path.upper():
            if any(f"ORDER BY {i}" in decoded_path.upper() for i in range(4, 15)):
                self.wfile.write(b"Unknown column in 'order clause'")
            else:
                self.wfile.write(b"Ordered successfully")
            return

        # Check for UNION SELECT extraction
        if "UNION SELECT" in decoded_path.upper():
            self.wfile.write(b"Data Dump -> version() = 8.0.32, database() = testdb")
            return

        self.wfile.write(b"Welcome to mock vulnerable app! version() = 8.0.32 database() = testdb")

print("[*] Starting full-feature local mock server on port 8080...")
HTTPServer(('127.0.0.1', 8080), MockVulnHandler).serve_forever()
