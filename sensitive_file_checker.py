import requests
import argparse
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-value sensitive files and paths to probe
SENSITIVE_FILES = [
    ".env",
    ".git/HEAD",
    "config.json",
    "config.php",
    "backup.zip",
    "backup.tar.gz",
    "database.sql",
    "phpinfo.php",
    "docker-compose.yml",
    "auth.json",
    "credentials.txt",
    "package-lock.json"
]

def check_sensitive_files(target_url):
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
        
    target_url = target_url.rstrip("/")
    
    print("-" * 60)
    print(f"[*] Checking for sensitive files and backups: {target_url}")
    print("-" * 60)
    
    # Establish a baseline for a clearly non-existent file to catch soft 404s
    fake_path = "/nonexistent-file-xyz-98765.html"
    try:
        base_resp = requests.get(target_url + fake_path, timeout=4, verify=False, allow_redirects=False)
        baseline_len = len(base_resp.text)
        baseline_status = base_resp.status_code
    except Exception:
        baseline_len = -1
        baseline_status = 404

    found_exposures = 0

    for file_path in SENSITIVE_FILES:
        url = f"{target_url}/{file_path}"
        try:
            resp = requests.get(url, timeout=4, verify=False, allow_redirects=False)
            content_len = len(resp.text)
            
            # Check for valid exposure (Status 200, not a soft 404 page, and not a redirect to login/home)
            if resp.status_code == 200 and baseline_status != 200:
                if abs(content_len - baseline_len) > 50 and content_len > 0:
                    print(f"  [!] EXPOSED SENSITIVE FILE FOUND: {url}")
                    print(f"      Status: {resp.status_code} | Length: {content_len} bytes")
                    found_exposures += 1
        except Exception:
            continue

    if found_exposures == 0:
        print("[-] No obvious sensitive files or backups exposed.")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sensitive File & Configuration Exposure Checker")
    parser.add_argument("url", help="Target base URL (e.g., http://example.com)")
    
    args = parser.parse_args()
    check_sensitive_files(args.url)
