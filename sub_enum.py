import sys
import urllib.request
import urllib.error
import json
import socket

COMMON_SUBDOMAINS = [
    "www", "admin", "api", "test", "staging", "dev", "mail",
    "portal", "secure", "vpn", "shop", "blog", "support",
    "jenkins", "git", "status", "dashboard", "auth", "login", "staging-api"
]

def banner():
    print("=============================================================")
    print(" [*] SUBDOMAIN & INFRASTRUCTURE ENUMERATION (SUB_ENUM)")
    print("=============================================================")

def enumerate_subdomains(domain):
    banner()
    # Clean domain input
    domain = domain.replace("http://", "").replace("https://", "").rstrip("/")
    print(f"[*] Target Domain: {domain}")
    print(f"[*] Probing {len(COMMON_SUBDOMAINS)} common subdomain prefixes...\n")

    discovered = []

    for sub in COMMON_SUBDOMAINS:
        sub_domain = f"{sub}.{domain}"
        
        # Test via HTTP/HTTPS request first (web assets)
        active = False
        for scheme in ["http", "https"]:
            target_url = f"{scheme}://{sub_domain}"
            try:
                req = urllib.request.Request(
                    target_url,
                    headers={'User-Agent': 'Mozilla/5.0 (Termux Offensive Framework)'}
                )
                with urllib.request.urlopen(req, timeout=2) as resp:
                    code = resp.getcode()
                    print(f"    [+] [{code} OK] Active Web Asset: {target_url}")
                    discovered.append({"subdomain": sub_domain, "url": target_url, "status": code, "type": "Web"})
                    active = True
                    break
            except urllib.error.HTTPError as e:
                print(f"    [!] [{e.code} HTTP] Active Web Asset: {target_url}")
                discovered.append({"subdomain": sub_domain, "url": target_url, "status": e.code, "type": "Web"})
                active = True
                break
            except Exception:
                pass

        # If HTTP check failed, try raw DNS resolution
        if not active:
            try:
                ip = socket.gethostbyname(sub_domain)
                print(f"    [+] [DNS Resolved] Active Host: {sub_domain} -> {ip}")
                discovered.append({"subdomain": sub_domain, "ip": ip, "status": "DNS_ONLY", "type": "Infrastructure"})
            except Exception:
                pass

    print("\n=============================================================")
    print(f"[*] Enumeration complete. Discovered {len(discovered)} active asset(s).")
    print("=============================================================")
    return discovered

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sub_enum.py <domain>")
        print("Example: python sub_enum.py testfire.net")
        sys.exit(1)

    target_domain = sys.argv[1]
    results = enumerate_subdomains(target_domain)

    if results:
        with open("discovered_subdomains.json", "w") as f:
            json.dump(results, f, indent=4)
        print("[+] Saved discovered subdomains to 'discovered_subdomains.json'")
