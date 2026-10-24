import requests
import argparse
import sys
import json
import base64
import hmac
import hashlib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common weak or default secrets often hardcoded by developers
COMMON_SECRETS = [
    "secret",
    "secret123",
    "password",
    "jwt_secret",
    "key",
    "123456",
    "admin",
    "changeme",
    "api_secret",
    "supersecret"
]

def base64url_decode(input_str):
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)

def analyze_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        header_json = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        payload_json = json.loads(base64url_decode(parts[1]).decode('utf-8'))
        
        return header_json, payload_json, parts[2]
    except Exception:
        return None

def scan_jwt(target_url):
    print("-" * 60)
    print(f"[*] Scanning for JWT authentication and vulnerabilities: {target_url}")
    print("-" * 60)
    
    try:
        resp = requests.get(target_url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        cookies = resp.cookies.get_dict()
        headers = resp.headers
        
        found_tokens = []
        
        # Check authorization header or response text/cookies for JWT patterns (eyJ...)
        for cookie_name, cookie_val in cookies.items():
            if cookie_val.startswith("eyJ") and len(cookie_val.split('.')) == 3:
                found_tokens.append((f"Cookie [{cookie_name}]", cookie_val))
                
        auth_header = headers.get("Authorization", "")
        if "Bearer eyJ" in auth_header:
            token = auth_header.split(" ")[1]
            if len(token.split('.')) == 3:
                found_tokens.append(("Authorization Header", token))
                
        if not found_tokens:
            print("[-] No obvious JWT tokens detected in initial response headers or cookies.")
            print("-" * 60)
            return

        for source, token in found_tokens:
            print(f"[+] Found JWT in {source}")
            header, payload, signature = analyze_jwt(token)
            
            print(f"    > Header: {json.dumps(header)}")
            print(f"    > Payload: {json.dumps(payload)}")
            
            alg = header.get("alg", "").upper()
            print(f"    > Signing Algorithm: {alg}")
            
            # Check for 'alg: none' vulnerability
            if alg == "NONE" or not alg:
                print("    [!] CRITICAL: JWT accepts 'alg: none'! Unsigned payload tampering possible.")
                
            # Check for weak secrets if HS256
            if alg == "HS256":
                print("    [*] Testing common weak secrets against signature...")
                parts = token.split('.')
                message = f"{parts[0]}.{parts[1]}".encode('utf-8')
                target_sig_bytes = base64url_decode(signature)
                
                cracked = False
                for secret in COMMON_SECRETS:
                    computed_sig = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).digest()
                    if hmac.compare_digest(computed_sig, target_sig_bytes):
                        print(f"    [!] CRITICAL: Weak JWT secret cracked! Secret: '{secret}'")
                        cracked = True
                        break
                if not cracked:
                    print("    [-] No weak secrets matched out of standard wordlist.")
                    
    except Exception as e:
        print(f"[-] Error scanning JWT: {e}")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT Vulnerability & Weak Secret Scanner")
    parser.add_argument("url", help="Target URL to check for JWT cookies or headers (e.g., http://example.com/login)")
    
    args = parser.parse_args()
    scan_jwt(args.url)
