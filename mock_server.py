import http.server
import socketserver
import urllib.parse

PORT = 8080

class MockOffensiveHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query_params = urllib.parse.parse_qs(parsed_path.query)

        # 1. Root Page
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = """
            <html>
                <head><title>Mock Vulnerable Application</title></head>
                <body>
                    <h1>Welcome to the Mock Target Suite</h1>
                    <a href="/page.php?file=home">View Home Page</a>
                    <a href="/listproducts.php?cat=1">View Products</a>
                    <script src="/static/app.js"></script>
                </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))

        # 2. LFI / Path Traversal Vulnerability
        elif path == "/page.php":
            file_param = query_params.get("file", [""])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            if "passwd" in file_param or ".." in file_param:
                response = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            else:
                response = f"<html><body><h1>Home Page</h1><p>Loaded file: {file_param}</p></body></html>"
            self.wfile.write(response.encode('utf-8'))

        # 3. SQL Injection Vulnerability
        elif path == "/listproducts.php":
            cat_param = query_params.get("cat", [""])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            if "'" in cat_param or "UNION" in cat_param.upper():
                response = "<html><body>Database Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '' at line 1</body></html>"
            elif "version" in cat_param.lower() or "database" in cat_param.lower():
                response = "<html><body>Product List: [MockDB-v10.4.2-MariaDB, altoro_db, admin_user]</body></html>"
            else:
                response = "<html><body><h1>Products</h1><ul><li>Laptop</li><li>Phone</li></ul></body></html>"
            self.wfile.write(response.encode('utf-8'))

        # 4. IDOR / BOLA Vulnerability (Simulated User API)
        elif path.startswith("/api/v1/user/"):
            try:
                user_id = int(path.split("/")[-1])
            except ValueError:
                user_id = 0

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            if user_id == 101:
                response = '{"id": 101, "username": "alice", "role": "customer", "email": "alice@test.com"}'
            elif user_id == 102:
                response = '{"id": 102, "username": "bob", "role": "customer", "email": "bob@test.com"}'
            elif user_id == 99 or user_id == 100:
                response = '{"id": ' + str(user_id) + ', "username": "system_account", "role": "internal"}'
            else:
                response = '{"id": ' + str(user_id) + ', "username": "administrator", "role": "superadmin", "secret_token": "FLAG{idor_bola_privilege_escalation_success}"}'
            self.wfile.write(response.encode('utf-8'))

        # 5. SSRF Vulnerability
        elif path == "/ssrf.php":
            target_url = query_params.get("url", [""])[0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            response = f"<html><body><h1>SSRF Fetch Result</h1><p>Successfully fetched internal resource: {target_url}</p></body></html>"
            self.wfile.write(response.encode('utf-8'))

        # 6. Specific Valid Endpoints / Admin Paths
        elif path in ["/admin", "/admin.php", "/dashboard", "/api", "/api/v1", "/api/v1/users", "/api/v1/status", "/config.json", "/robots.txt", "/test.php", "/upload", "/uploads", "/register", "/signup", "/server-status", "/phpinfo.php", "/db.sql", "/settings.py", ".env", "/swagger", "/api-docs"]:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Resource: {path}</h1><p>Active endpoint discovered.</p></body></html>".encode('utf-8'))

        # 7. Strict 404 for Everything Else
        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body></html>")

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    print(f"[*] Starting Strict-404 Mock Vulnerable Server on port {PORT}...")
    with socketserver.TCPServer(("", PORT), MockOffensiveHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Mock server stopped.")
