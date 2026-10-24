import sys
import argparse
import subprocess
import os

BANNER = r"""
============================================================
   __  __ _________________  __  ___  __   ____  _   __
  / / / /_  __/ ____/ ___/ / / /   |/ /  / __ \/ | / /
 / /_/ / / / / /    \__ \ / / / /| / /  / / / /  |/ / 
/ __  / / / / /___ ___/ / /_/ / |  /  / /_/ / /|  /  
/_/ /_/ /_/  \____/____/\____/_/ |_/   \____/_/ |_/   
       MOBILE OFFENSIVE SECURITY FRAMEWORK (v3.0)
============================================================
"""

def print_help():
    print(BANNER)
    print("Usage: python framework.py <module> [options]")
    print("\nAvailable Modules:")
    print("  [Reconnaissance & Scans]")
    print("    pipeline     - Run full automated domain recon pipeline")
    print("    netmap       - Run local network subnet & router discovery")
    print("    buckets      - Hunt for exposed cloud storage / S3 buckets")
    print("    baseline     - Compile terminal summary & probe_baseline.txt")
    print("\n  [Access Gain & Exploitation]")
    print("    sqldump      - Run automated SQL injection dumper")
    print("    brute        - Run authentication brute-forcer / stuffer")
    print("    exploit      - Deploy RCE exploit & start reverse shell listener")
    print("    upload       - Test arbitrary file upload form & web shell")
    print("\n  [Interactive Menu]")
    print("    menu         - Launch the interactive shell dashboard")
    print("============================================================")

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    module = sys.argv[1].lower()
    args = sys.argv[2:]

    if module == "pipeline":
        domain = args[0] if args else input("Enter target domain: ")
        subprocess.run(["./recon_pipeline.sh", domain])

    elif module == "netmap":
        subnet = args[0] if args else input("Enter target subnet (e.g., 192.168.1.0/24): ")
        subprocess.run(["python", "net_net_mapper.py" if os.path.exists("net_net_mapper.py") else "net_mapper.py", subnet])

    elif module == "buckets":
        target = args[0] if args else input("Enter target company/domain for bucket hunt: ")
        subprocess.run(["python", "bucket_hunter.py", target])

    elif module == "baseline":
        subprocess.run(["python", "build_baseline.py"])

    elif module == "sqldump":
        url = args[0] if args else input("Enter target URL with parameters: ")
        param = args[1] if len(args) > 1 else input("Enter vulnerable parameter name: ")
        subprocess.run(["python", "sql_dumper.py", url, "-p", param])

    elif module == "brute":
        url = args[0] if args else input("Enter login URL: ")
        user = args[1] if len(args) > 1 else input("Enter username or wordlist: ")
        pwd_file = args[2] if len(args) > 2 else input("Enter password wordlist path: ")
        subprocess.run(["python", "auth_bruter.py", url, "-u", user, "-pw", pwd_file])

    elif module == "exploit":
        url = args[0] if args else input("Enter vulnerable URL: ")
        param = args[1] if len(args) > 1 else input("Enter parameter name: ")
        subprocess.run(["python", "exploit_deployer.py", url, param])

    elif module == "upload":
        url = args[0] if args else input("Enter upload endpoint URL: ")
        subprocess.run(["python", "upload_exploiter.py", url])

    elif module == "menu":
        subprocess.run(["./menu.sh"])

    else:
        print(f"[-] Unknown module: '{module}'")
        print_help()

if __name__ == "__main__":
    main()
