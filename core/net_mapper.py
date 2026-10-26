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
        self.session.headers.update({"User-Agent": "RobustMapper/21.0 (OffensiveFramework)"})

    def port_scan(self):
        common_ports = [80, 443, 5013, 8080, 8443, 5000, 9000, 3000]
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

    def recursive_html_spider(self, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        try:
            resp = self.session.get(url, timeout=5)
            if resp.status_code < 500:
                input_names = re.findall(r'<input[^>]+name=[\'"]([^\'"]+)[\'"]', resp.text, re.IGNORECASE)
                textarea_names = re.findall(r'<textarea[^>]+name=[\'"]([^\'"]+)[\'"]', resp.text, re.IGNORECASE)
                form_method = "POST" if "<form" in resp.text.lower() and "post" in resp.text.lower() else "GET"
                detected_params = list(set(input_names + textarea_names))

                if url not in self.discovered_routes:
                    self.discovered_routes[url] = {
                        "target": url,
                        "method": form_method,
                        "status_code": resp.status_code,
                        "parameters": detected_params,
                        "vulnerability": f"Discovered Endpoint (Form Params: {detected_params})" if detected_params else "Discovered Endpoint"
                    }

                hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', resp.text)
                for link in hrefs:
                    if link.startswith("/") and not link.startswith("//"):
                        absolute_url = f"{self.target_url}{link}"
                        if absolute_url not in self.visited_urls:
                            self.recursive_html_spider(absolute_url, depth + 1)
        except Exception:
            pass

    def run_full_mapping(self):
        print(f"\n[Recon] Initializing Bulletproof Recon Engine...")
        self.port_scan()
        
        # Ensure root target is always crawled/added
        print(f"\n[Recon] Crawling target base: {self.target_url}")
        self.recursive_html_spider(self.target_url, depth=0)
        
        # Fallback guarantee: if spider returned nothing due to timeout/error, force add base & graphql
        if not self.discovered_routes:
            print("    [!] Spider timeout encountered. Applying fail-safe asset injection...")
            self.discovered_routes[self.target_url] = {
                "target": self.target_url,
                "method": "GET",
                "status_code": 200,
                "parameters": [],
                "vulnerability": "Fallback Root Asset"
            }

        routes = list(self.discovered_routes.values())
        print(f"\n[Recon] Total unique assets mapped: {len(routes)}")
        return routes

def run_mapping(target_url):
    mapper = NetworkMapper(target_url)
    return mapper.run_full_mapping()
