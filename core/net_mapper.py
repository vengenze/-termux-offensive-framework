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
    def __init__(self, target_url, max_threads=15):
        self.target_url = target_url.rstrip("/")
        parsed = urllib.parse.urlparse(target_url)
        self.hostname = parsed.hostname or target_url
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.max_threads = max_threads
        self.discovered_routes = {}
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "HybridMapper/5.0 (OffensiveFramework)"})

    def port_scan(self):
        common_ports = [80, 443, 8080, 8443, 5000, 9000, 3000, 8000]
        open_ports = []
        print(f"\n[NetMapper] Scanning network ports on {self.hostname}...")
        
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
        print(f"\n[NetMapper] Querying target for exposed API documentation specs...")
        
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
                                    "vulnerability": "API Endpoint (Spec-Extracted)"
                                }
                        return True
                    except Exception:
                        pass
            except Exception:
                pass
        return False

    def html_link_spider(self):
        """Crawls HTML pages to extract embedded links and form endpoints."""
        print(f"\n[NetMapper] Spidering HTML content for hidden links & forms...")
        seed_pages = ["/", "/help", "/api"]
        found_links = set()

        for page in seed_pages:
            url = f"{self.target_url}{page}"
            try:
                resp = self.session.get(url, timeout=3)
                if resp.status_code == 200:
                    # Extract hrefs and action attributes using regex
                    hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', resp.text)
                    actions = re.findall(r'action=[\'"]([^\'"]+)[\'"]', resp.text)
                    for link in hrefs + actions:
                        if link.startswith("/") and not link.startswith("//"):
                            found_links.add(link)
            except Exception:
                pass

        for link in found_links:
            full_target = f"{self.target_url}{link}"
            if full_target not in self.discovered_routes:
                self.discovered_routes[full_target] = {
                    "target": full_target,
                    "method": "GET",
                    "status_code": 200,
                    "vulnerability": "Discovered Endpoint (HTML Spider)"
                }

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
                # Test both GET and POST availability
                for method in ["GET", "POST"]:
                    resp = self.session.request(method, url, timeout=2)
                    if resp.status_code != 404:
                        return {
                            "target": url,
                            "method": method,
                            "status_code": resp.status_code,
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
        self.port_scan()
        spec_found = self.extract_openapi_specs()
        self.html_link_spider()
        self.dictionary_bruteforce()
        
        routes = list(self.discovered_routes.values())
        print(f"\n[NetMapper] Total unique assets mapped: {len(routes)}")
        return routes

def run_mapping(target_url):
    mapper = NetworkMapper(target_url)
    return mapper.run_full_mapping()

if __name__ == "__main__":
    target = input("Enter target URL to map: ").strip()
    run_mapping(target)
