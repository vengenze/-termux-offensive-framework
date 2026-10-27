from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class ComprehensiveMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Serve static assets
        if self.path.startswith("/static/"):
            self.send_response(200)
            if self.path.endswith(".js"):
                self.send_header("Content-type", "application/javascript")
                self.wfile.write(b"console.log('Mock JS Loaded');")
            elif self.path.endswith(".css"):
                self.send_header("Content-type", "text/css")
                self.wfile.write(b"body { background-color: #f8f9fa; }")
            else:
                self.send_header("Content-type", "image/png")
                self.wfile.write(b"\x89PNG\r\n\x1a\n")
            self.end_headers()
            return

        # Expose a mock .env file so Nuclei's exposure templates trigger findings
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=super_secret_db_pass_123\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nAPI_SECRET=mock_token_abcdef")
            return

        # Main Application Routes
        if self.path == "/" or self.path == "":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = """
            <html>
                <head><title>Pentest Ground Mock</title></head>
                <body>
                    <h1>Welcome to Pentest Ground Mock Server</h1>
                    <p>Explore the test environment:</p>
                    <ul>
                        <li><a href="/solutions">Solutions</a></li>
                        <li><a href="/about">About & Secrets</a></li>
                        <li><a href="/upload_paste">Upload Paste</a></li>
                        <li><a href="/audit">Audit Logs</a></li>
                        <li><a href="/.env">Exposed .env File</a></li>
                        <li><a href="/openapi.json">OpenAPI Spec</a></li>
                        <li><a href="/graphql">GraphQL Endpoint</a></li>
                    </ul>
                </body>
            </html>
            """
            self.wfile.write(html.encode())

        elif self.path == "/solutions":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Solutions Training Page</h1></body></html>")

        elif self.path == "/about":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>About Us</h1><p>Internal Admin Password: secret_admin_token_998877</p></body></html>")

        elif self.path == "/upload_paste":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><form><input type='text' name='paste'></form></body></html>")

        elif self.path == "/audit":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Audit Logs</h1><p>Status: Clean</p></body></html>")

        elif self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Mock API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/status": {
                        "get": {"summary": "System Status", "responses": {"200": {"description": "OK"}}}
                    },
                    "/api/v1/users": {
                        "get": {"summary": "Get Users", "responses": {"200": {"description": "Success"}}}
                    }
                }
            }
            self.wfile.write(json.dumps(spec).encode())

        elif self.path == "/graphql" or self.path == "/graphiql":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>GraphiQL Interface Active. Send POST introspection queries.</body></html>")

        else:
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        # Robust GraphQL Introspection Handler for InQL
        if self.path == "/graphql":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            introspection_response = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "subscriptionType": None,
                        "directives": [],
                        "types": [
                            {
                                "kind": "OBJECT",
                                "name": "Query",
                                "description": "Root Query Type",
                                "fields": [
                                    {
                                        "name": "users",
                                        "description": "Fetch all users",
                                        "args": [],
                                        "type": {"kind": "OBJECT", "name": "User", "ofType": None},
                                        "isDeprecated": False,
                                        "deprecationReason": None,
                                        "enumValues": None
                                    }
                                ],
                                "inputFields": None,
                                "interfaces": [],
                                "enumValues": None,
                                "possibleTypes": None
                            },
                            {
                                "kind": "OBJECT",
                                "name": "User",
                                "description": "User account object",
                                "fields": [
                                    {
                                        "name": "id",
                                        "description": "User ID",
                                        "args": [],
                                        "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                                        "isDeprecated": False,
                                        "deprecationReason": None,
                                        "enumValues": None
                                    }
                                ],
                                "inputFields": None,
                                "interfaces": [],
                                "enumValues": None,
                                "possibleTypes": None
                            }
                        ]
                    }
                }
            }
            self.wfile.write(json.dumps(introspection_response).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=ComprehensiveMockHandler, port=5013):
    server_address = ('127.0.0.1', port)
    httpd = server_class(server_address, handler_class)
    print(f"[+] Comprehensive Mock Server running on http://127.0.0.1:{port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
