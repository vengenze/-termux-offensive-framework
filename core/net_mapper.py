import os
import socket
import urllib.parse
import re
import requests
import yaml
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NetworkMapper:
    def __init__(self, target_url, max_threads=15, max_depth=2):
        self.target_url = target_url.rstrip("/")
        parsed = urllib.parse.urlparse(target_url)
        self.hostname = parsed.hostname or target_url
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.discovered_routes = {}
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "AdvancedRecon/6.0 (OffensiveFramework)"})

    def port_scan(self):
        common_ports = [80, 443, 8080, 8443, 5000, 9000, 3000, 8000]
        open_ports = []
        print(f"\n[Recon] Scanning network ports on {self.hostname}...")
        
        def check_port(p):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                result = s.connect_ex((self.hostname, p))
                s.close()
                if result == 0:
                    return p
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=len(common_ports)) as executor:
            futures = [executor.submit(check_port, p) for p in common_ports]
            for f in as_completed(futures):
                p = f.result()
                if p:
                    print(f"    [+] Open Port Discovered: {p}")
                    open_ports.append(p)
        return open_ports

    def extract_openapi_specs(self):
        """Automatically checks for and ingests OpenAPI/Swagger documentation."""
        spec_paths = ["/openapi.yaml", "/openapi.json", "/swagger.json", "/docs/swagger.json"]
        print(f"\n[Recon] Querying target for exposed API documentation specs...")
        
        for path in spec_paths:
            url = f"{self.target_url}{path}"
            try:
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200 and ("paths:" in resp.text or "swagger:" in resp.text or "openapi:" in resp.text):
                    print(f"    [+] Found API Spec Document: {url}")
                    try:
                        spec_data = yaml.safe_load(resp.text)
                        paths = spec_data.get("paths", {})
                        for route, methods in paths.items():
                            for method in methods.keys():
                                full_target = f"{self.target_url}{route}"
                                self.discovered_routes[full_target] = {
                                    "target": full_target,
                                    "method": method.upper(),
                                    "status_code": 200,
                                    "tech_stack": "OpenAPI Spec Mapped",
                                    "vulnerability": "API Endpoint (Spec-Extracted)"
                                }
                        return True
                    except Exception:
                        pass
            except Exception:
                pass
        return False

    def recursive_html_spider(self, url, depth=0):
        """Recursively crawls HTML pages up to max_depth to extract hidden links and forms."""
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        try:
            resp = self.session.get(url, timeout=3)
            if resp.status_code == 200:
                # Fingerprint technology from headers
                server_header = resp.headers.get("Server", "Unknown")
                powered_by = resp.headers.get("X-Powered-By", "None")
                tech_profile = f"Server: {server_header} | Powered-By: {powered_by}"

                if url not in self.discovered_routes:
                    self.discovered_routes[url] = {
                        "target": url,
                        "method": "GET",
                        "status_code": resp.status_code,
                        "tech_stack": tech_profile,
                        "vulnerability": "Discovered Endpoint (Recursive Spider)"
                    }

                # Extract links
                hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', resp.text)
                actions = re.findall(r'action=[\'"]([^\'"]+)[\'"]', resp.text)
                
                for link in hrefs + actions:
                    if link.startswith("/") and not link.startswith("//"):
                        absolute_url = f"{self.target_url}{link}"
                        if absolute_url not in self.visited_urls:
                            self.recursive_html_spider(absolute_url, depth + 1)
                    elif link.startswith(self.target_url):
                        if link not in self.visited_urls:
                            self.recursive_html_spider(link, depth + 1)
        except Exception:
            pass

    def dictionary_bruteforce(self):
        """Fallback high-speed wordlist brute-force for unlinked directories."""
        wordlist = [
            "/api", "/api/v1", "/auth", "/login", "/tokens", "/search", 
            "/user", "/admin", "/dashboard", "/debug", "/config", "/backup", 
            "/status", "/health", "/xml", "/upload", "/eval", "/uptime/id", "/widget"
        ]

        def test_path(path):
            url = f"{self.target_url}{path}"
            if url in self.discovered_routes:
                return None
            try:
                for method in ["GET", "POST"]:
                    resp = self.session.request(method, url, timeout=2)
                    if resp.status_code != 404:
                        server_header = resp.headers.get("Server", "Unknown")
                        return {
                            "target": url,
                            "method": method,
                            "status_code": resp.status_code,
                            "tech_stack": f"Server: {server_header}",
                            "vulnerability": f"Discovered Endpoint (HTTP {resp.status_code})"
                        }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(test_path, path): path for path in wordlist}
            for future in as_completed(futures):
                res = future.result()
                if res and res["target"] not in self.discovered_routes:
                    print(f"    [+] [Brute-force] {res['method']} {res['target']} -> HTTP {res['status_code']}")
                    self.discovered_routes[res["target"]] = res

    def run_full_mapping(self):
        print(f"\n[Recon] Initializing Advanced Multi-Layered Recon Engine...")
        self.port_scan()
        self.extract_openapi_specs()
        
        print(f"\n[Recon] Launching Recursive Web Spider (Depth: {self.max_depth})...")
        self.recursive_html_spider(self.target_url, depth=0)
        
        print(f"\n[Recon] Executing Dictionary Brute-Force Fallback...")
        self.dictionary_bruteforce()
        
        routes = list(self.discovered_routes.values())
        print(f"\n[Recon] Total unique assets mapped & profiled: {len(routes)}")
        return routes

def run_mapping(target_url):
    mapper = NetworkMapper(target_url)
    return mapper.run_full_mapping()

if __name__ == "__main__":
    target = input("Enter target URL to map: ").strip()
    run_mapping(target)
