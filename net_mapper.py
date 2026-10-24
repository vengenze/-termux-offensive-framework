import socket
import subprocess
import concurrent.futures
import argparse
import sys
import urllib3
import ipaddress
import base64

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTERNAL_PORTS = {
    80: "HTTP (Router/Web)",
    443: "HTTPS",
    8080: "HTTP-Proxy/Alt"
}

# Common default router / administrative credentials
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "root"),
    ("root", "password"),
    ("user", "user"),
    ("supervisor", "supervisor")
]

def check_host(ip):
    ip_str = str(ip)
    try:
        param = "-n" if sys.platform.startswith("win") else "-c"
        command = ["ping", param, "1", "-W", "1", ip_str]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return ip_str
    except Exception:
        pass
    return None

def test_router_credentials(url):
    """Test common default credentials against HTTP Basic or login portals"""
    print(f"        [*] Testing default credentials on {url}...")
    for user, pwd in DEFAULT_CREDS:
        try:
            # Test HTTP Basic Authentication
            token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
            headers = {
                "Authorization": f"Basic {token}",
                "User-Agent": "Mozilla/5.0"
            }
            resp = requests.get(url, timeout=2, verify=False, headers=headers, allow_redirects=False)
            
            # If status changes from 401 Unauthorized to 200/302, credentials likely work!
            if resp.status_code in [200, 302, 303]:
                print(f"          [!] SUCCESS: Default credentials found -> Username: '{user}' | Password: '{pwd}'")
                return True
        except Exception:
            continue
    print("          [-] No default credentials matched.")
    return False

def scan_ports(ip):
    open_ports = []
    for port, service in INTERNAL_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append((port, service))
            s.close()
        except Exception:
            pass
    return open_ports

def run_net_map(subnet_str):
    print("=" * 60)
    print(f"[*] Starting Local Network Discovery & Credential Audit: {subnet_str}")
    print("=" * 60)
    
    try:
        net = ipaddress.ip_network(subnet_str, strict=False)
    except ValueError as e:
        print(f"[-] Invalid subnet format: {e}")
        return

    live_hosts = []
    print("[*] Sweeping subnet for active hosts...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in net.hosts()}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                print(f"  [+] Active Host Discovered: {res}")
                live_hosts.append(res)

    if not live_hosts:
        print("[-] No active hosts discovered.")
        return

    print(f"\n[+] Total Live Hosts Found: {len(live_hosts)}")
    print("-" * 60)

    for host in live_hosts:
        print(f"\n[->] Target: {host}")
        open_ports = scan_ports(host)
        
        if open_ports:
            for port, service in open_ports:
                print(f"    [+] Port {port} OPEN ({service})")
                scheme = "https" if port == 443 else "http"
                url = f"{scheme}://{host}:{port}"
                
                try:
                    resp = requests.get(url, timeout=2, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                    print(f"        Web Status: {resp.status_code}")
                    
                    # If it's a web port, check default credentials
                    test_router_credentials(url)
                except Exception:
                    pass
        else:
            print("    [-] No target internal web ports open.")

    print("=" * 60)
    print("[*] Local Network Mapping & Audit Complete!")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local Network & Router Credential Mapper")
    parser.add_argument("subnet", help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)")
    args = parser.parse_args()
    run_net_map(args.subnet)
