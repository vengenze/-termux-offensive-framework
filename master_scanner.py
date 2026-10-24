import requests
import argparse
import sys
import json
import base64
import hmac
import hashlib
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURATIONS & SIGNATURES ---
API_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/api-docs", "/api/v1/", "/api/v2/", "/graphql", "/graphiql"
]

SENSITIVE_FILES = [
    "/.env", "/config.json", "/database.sql", "/backup.zip", "/phpinfo.php",
    "/.git/HEAD", "/server-status", "/debug", "/credentials.txt"
]

COMMON_SECRETS = ["secret", "secret123", "password", "jwt_secret", "key", "123456", "admin", "changeme"]

LFI_SIGNATURES = ["root:x:0:0:", "[extensions]", "[fonts]", "sbin/nologin", "bin/bash"]
SSRF_SIGNATURES = ["ami-id", "instance-id", "iam/security-credentials", "computeMetadata", "root:x:0:0:"]

def base64url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)

def run_master_scan(target_url):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
    target_url = target_url.rstrip("/")
    
    print("=" * 60)
    print(f"[*] MASTER WEB SCANNER INITIATED: {target_url}")
    print("=" * 60)
    
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

    # 1. HEADER AUDIT & SECURITY HEADERS
    print("\n[+] Phase 1: Auditing Security Headers...")
    try:
        resp = requests.get(target_url, timeout=5, verify=False, headers=headers)
        h = resp.headers
        sec_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]
        for sh in sec_headers:
            if sh not in h:
                print(f"    [!] Missing Security Header: {sh}")
            else:
                print(f"    [+] Found {sh}: {h.get(sh)}")
    except Exception as e:
        print(f"    [-] Error checking headers: {e}")

    # 2. CORS MISCONFIGURATION
    print("\n[+] Phase 2: Checking CORS Misconfigurations...")
    try:
        cors_headers = headers.copy()
        cors_headers["Origin"] = "https://evil-canary-domain.com"
        resp = requests.get(target_url, timeout=5, verify=False, headers=cors_headers)
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "https://evil-canary-domain.com" or acao == "*":
            print(f"    [!] CRITICAL: Insecure CORS ACAO found: '{acao}' (Credentials: {acac})")
        else:
            print("    [-] CORS policy securely restricted.")
    except Exception as e:
        print(f"    [-] CORS check failed: {e}")

    # 3. API & SWAGGER DISCOVERY
    print("\n[+] Phase 3: Scanning for Exposed API Docs & Endpoints...")
    for path in API_PATHS:
        try:
            url = f"{target_url}{path}"
            r = requests.get(url, timeout=3, verify=False, allow_redirects=False, headers=headers)
            if r.status_code in [200, 401, 403] and len(r.text) > 20:
                print(f"    [!] EXPOSED API / DOCS: {url} (Status: {r.status_code})")
        except Exception:
            continue

    # 4. SENSITIVE FILES & BACKUPS
    print("\n[+] Phase 4: Probing for Sensitive Files & Backups...")
    for path in SENSITIVE_FILES:
        try:
            url = f"{target_url}{path}"
            r = requests.get(url, timeout=3, verify=False, allow_redirects=False, headers=headers)
            if r.status_code == 200 and len(r.text) > 10:
                print(f"    [!] EXPOSED SENSITIVE FILE: {url} (Length: {len(r.text)})")
        except Exception:
            continue

    # 5. JWT TOKEN & WEAK SECRET SCANNER
    print("\n[+] Phase 5: Checking JWT Authentication & Secrets...")
    try:
        resp = requests.get(target_url, timeout=5, verify=False, headers=headers)
        for cname, cval in resp.cookies.items():
            if cval.startswith("eyJ") and len(cval.split('.')) == 3:
                print(f"    [+] Found JWT in Cookie [{cname}]")
                parts = cval.split('.')
                header_json = json.loads(base64url_decode(parts[0]).decode('utf-8'))
                alg = header_json.get("alg", "").upper()
                print(f"        Algorithm: {alg}")
                if alg == "NONE":
                    print("        [!] CRITICAL: JWT accepts 'alg: none'!")
                elif alg == "HS256":
                    msg = f"{parts[0]}.{parts[1]}".encode('utf-8')
                    target_sig = base64url_decode(parts[2])
                    for sec in COMMON_SECRETS:
                        if hmac.compare_digest(hmac.new(sec.encode('utf-8'), msg, hashlib.sha256).digest(), target_sig):
                            print(f"        [!] CRITICAL: Weak JWT secret cracked: '{sec}'")
                            break
    except Exception:
        pass

    # 6. PARAMETER VULNERABILITY SCANNER (LFI, Open Redirect, SSRF)
    print("\n[+] Phase 6: Scanning Query Parameters (LFI, Open Redirect, SSRF)...")
    parsed = urlparse(target_url)
    q_params = parse_qs(parsed.query)
    if q_params:
        for param in q_params:
            # LFI Test
            for lfi_payload in ["../../../../etc/passwd", "/etc/passwd"]:
                test_p = q_params.copy()
                test_p[param] = [lfi_payload]
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_p, doseq=True), parsed.fragment))
                try:
                    r = requests.get(test_url, timeout=3, verify=False, headers=headers)
                    if any(sig in r.text for sig in LFI_SIGNATURES):
                        print(f"    [!] CRITICAL: LFI Found in parameter '{param}' -> {test_url}")
                except Exception:
                    pass
            # Open Redirect Test
            for redir_payload in ["https://evil-canary-domain.com", "//evil-canary-domain.com"]:
                test_p = q_params.copy()
                test_p[param] = [redir_payload]
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(test_p, doseq=True), parsed.fragment))
                try:
                    r = requests.get(test_url, timeout=3, verify=False, allow_redirects=False, headers=headers)
                    if r.status_code in [301, 302, 307, 308] and "evil-canary-domain.com" in r.headers.get("Location", ""):
                        print(f"    [!] CRITICAL: Open Redirect Found in parameter '{param}'")
                except Exception:
                    pass
    else:
        print("    [-] No query parameters found in target URL for parameter injection tests.")

    print("=" * 60)
    print("[*] Master Scan Complete!")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Master All-in-One Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g., http://example.com/app?id=1)")
    args = parser.parse_args()
    run_master_scan(args.url)
