import sys
import urllib.request
import urllib.parse
import html.parser
import re
import json

class ScriptTagExtractor(html.parser.HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.script_urls = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            for attr, value in attrs:
                if attr == 'src' and value:
                    full_url = urllib.parse.urljoin(self.base_url, value)
                    if urllib.parse.urlparse(full_url).netloc == urllib.parse.urlparse(self.base_url).netloc:
                        self.script_urls.add(full_url)

def extract_endpoints_from_js(target_url):
    print("=============================================================")
    print(" [*] JAVASCRIPT ENDPOINT & API EXTRACTOR (JS_EXTRACTOR)")
    print("=============================================================")
    print(f"[*] Analyzing target: {target_url}")

    discovered_endpoints = set()
    parsed_base = urllib.parse.urlparse(target_url)
    base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"

    try:
        req = urllib.request.Request(target_url, headers={'User-Agent': 'Mozilla/5.0 (Termux Offensive Framework)'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            html_content = resp.read().decode('utf-8', errors='ignore')
            
            parser = ScriptTagExtractor(target_url)
            parser.feed(html_content)
            print(f"[*] Found {len(parser.script_urls)} JavaScript bundle(s). Scanning code for internal routes...")

            # Regex to find quoted path patterns inside JS (e.g., "/api/v1/...", "/auth/...")
            path_pattern = re.compile(r'["\'](/[a-zA-Z0-9_\-/]+)["\']')

            for script_url in parser.script_urls:
                try:
                    s_req = urllib.request.Request(script_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(s_req, timeout=3) as s_resp:
                        js_code = s_resp.read().decode('utf-8', errors='ignore')
                        matches = path_pattern.findall(js_code)
                        for match in matches:
                            # Filter out common static media/style extensions
                            if not any(match.endswith(ext) for ext in ['.png', '.jpg', '.svg', '.css', '.ico', '.woff', '.json', '.html']):
                                full_endpoint = urllib.parse.urljoin(base_domain, match)
                                discovered_endpoints.add(full_endpoint)
                except Exception:
                    pass
    except Exception as e:
        print(f"[-] Error fetching target: {e}")

    results = list(discovered_endpoints)
    print("\n=============================================================")
    print(f"[*] JS Extraction complete. Uncovered {len(results)} potential endpoint(s).")
    print("=============================================================")
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python js_extractor.py <url>")
        sys.exit(1)
    
    endpoints = extract_endpoints_from_js(sys.argv[1])
    if endpoints:
        with open("js_endpoints.json", "w") as f:
            json.dump(endpoints, f, indent=4)
        print("[+] Saved extracted endpoints to 'js_endpoints.json'")
