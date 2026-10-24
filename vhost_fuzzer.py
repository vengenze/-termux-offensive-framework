import requests
import argparse
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fuzz_vhosts(target_ip, base_domain, wordlist_path):
    print("-" * 60)
    print(f"[*] Fuzzing Virtual Hosts on IP: {target_ip} for domain: {base_domain}")
    print("-" * 60)
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"[-] Error: Wordlist '{wordlist_path}' not found.")
        return

    # Establish a baseline response using a random/invalid host header
    baseline_url = f"http://{target_ip}"
    try:
        base_resp = requests.get(baseline_url, headers={"Host": f"random-nonexistent-subdomain-12345.{base_domain}"}, timeout=4, verify=False)
        baseline_len = len(base_resp.text)
    except Exception:
        baseline_len = 0

    print(f"[*] Baseline response length established: {baseline_len} bytes")
    print(f"[*] Testing {len(words)} potential virtual hosts...\n")

    found_vhosts = 0

    for word in words:
        vhost = f"{word}.{base_domain}"
        headers = {
            "Host": vhost,
            "User-Agent": "Mozilla/5.0"
        }
        
        try:
            resp = requests.get(baseline_url, headers=headers, timeout=3, verify=False, allow_redirects=False)
            content_len = len(resp.text)
            
            # If the response differs significantly from the baseline, it's a potential VHost match
            if resp.status_code != 404 and abs(content_len - baseline_len) > 50:
                print(f"  [+] FOUND VHOST : {vhost}")
                print(f"      Status: {resp.status_code} | Length: {content_len} bytes\n")
                found_vhosts += 1
        except Exception:
            continue

    print(f"[-] VHost scan complete. Discovered {found_vhosts} potential virtual host(s).")
    print("-" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Virtual Host (VHost) Fuzzer")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("domain", help="Base domain name (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    
    args = parser.parse_args()
    fuzz_vhosts(args.ip, args.domain, args.wordlist)
