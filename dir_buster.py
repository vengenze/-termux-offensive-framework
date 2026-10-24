import sys
import urllib.request
import urllib.error
import json
import os

DEFAULT_WORDLIST = [
    "admin", "admin.php", "login", "dashboard", "api", "api/v1", 
    "api/v1/users", "api/v1/status", "config.json", "backup.zip", 
    "robots.txt", ".git/HEAD", "graphql", "test.php", "upload", 
    "uploads", "register", "signup", "server-status", "phpinfo.php",
    "db.sql", "settings.py", ".env", "swagger", "api-docs"
]

def banner():
    print("=============================================================")
    print(" [*] HIGH-SPEED DIRECTORY & API ENDPOINT DISCOVERY (DIR_BUSTER)")
    print("=============================================================")

def brute_force_paths(base_url):
    banner()
    base_url = base_url.rstrip("/")
    print(f"[*] Target Base URL: {base_url}")
    print(f"[*] Loaded {len(DEFAULT_WORDLIST)} wordlist entries for probing...\n")

    discovered = []

    for word in DEFAULT_WORDLIST:
        target_url = f"{base_url}/{word}"
        try:
            req = urllib.request.Request(
                target_url, 
                headers={'User-Agent': 'Mozilla/5.0 (Termux Offensive Framework)'}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                code = resp.getcode()
                if code == 200:
                    print(f"    [+] [200 OK] Found: {target_url}")
                    discovered.append({"target": target_url, "status": 200, "type": "Endpoint"})
                elif code in [301, 302, 403]:
                    print(f"    [!] [{code} Redirect/Forbidden] Found: {target_url}")
                    discovered.append({"target": target_url, "status": code, "type": "Protected"})
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                print(f"    [!] [{e.code} Auth Required] Found: {target_url}")
                discovered.append({"target": target_url, "status": e.code, "type": "Protected"})
        except Exception:
            pass

    print("\n=============================================================")
    print(f"[*] Enumeration complete. Discovered {len(discovered)} active path(s).")
    print("=============================================================")
    return discovered

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dir_buster.py <base_url>")
        print("Example: python dir_buster.py http://127.0.0.1:8080")
        sys.exit(1)

    target_input = sys.argv[1]
    results = brute_force_paths(target_input)

    if results:
        with open("discovered_endpoints.json", "w") as f:
            json.dump(results, f, indent=4)
        print("[+] Saved discovered endpoints to 'discovered_endpoints.json'")
