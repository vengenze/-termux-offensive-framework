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

        # Check for LFI (Local File Inclusion) simulation
        if "file=" in decoded_path:
            if "passwd" in decoded_path or "../" in decoded_path:
                self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/bin/sh")
            else:
                self.wfile.write(b"<html><body>Mock file content loaded successfully.</body></html>")
            return

        # Check for SSRF (Server-Side Request Forgery) simulation
        if "url=" in decoded_path:
            target_url = decoded_path.split("url=")[1].split("&")[0]
            if "localhost" in target_url or "127.0.0.1" in target_url:
                self.wfile.write(b"INTERNAL METADATA SERVICE: instance-id=i-1234567890abcdef0, role=admin-backend")
            else:
                self.wfile.write(f"Fetched external resource from: {target_url}".encode())
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

print("[*] Starting multi-vector mock server on port 8080...")
HTTPServer(('127.0.0.1', 8080), MockVulnHandler).serve_forever()
