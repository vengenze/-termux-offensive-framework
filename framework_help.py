import sys

def show_help():
    print("=" * 65)
    print("     TERMUX OFFENSIVE SECURITY FRAMEWORK - COMMAND REFERENCE")
    print("=" * 65)
    print("\n [Interactive Dashboards & Orchestrators]")
    print("  ./menu.sh                     - Launch main interactive TUI dashboard")
    print("  python auto_exploit.py        - Launch autonomous pipeline orchestrator")
    print("  python access_console.py      - Launch post-exploitation interactive session")
    
    print("\n [Reconnaissance & Enumeration]")
    print("  ./recon_pipeline.sh <domain>  - Run full automated recon suite (subdomains, ports, web)")
    print("  python sub_enum.py <domain>   - Enumerate subdomains")
    print("  python bucket_hunter.py <co>  - Search for exposed cloud S3 buckets")
    print("  ./local_recon.sh              - Audit local network & router configuration")
    
    print("\n [Vulnerability Scanning]")
    print("  python sql_dumper.py <url> -p <param> - Automated SQL injection dumper & extractor")
    print("  python lfi_scanner.py <url>           - Local File Inclusion vulnerability scanner")
    print("  python jwt_scanner.py <url>           - JSON Web Token weakness & misconfiguration checker")
    print("  python auth_bruter.py <url> -u <u> -pw <list> - Authentication brute-forcer")
    
    print("\n [Exploitation & Post-Exploitation]")
    print("  python upload_exploiter.py <url>      - Arbitrary file upload exploiter & web shell deployer")
    print("  python exploit_deployer.py <url> <p>  - Deploy reverse shell listener & payloads")
    
    print("\n [Development & Testing]")
    print("  python mock_server.py &       - Run local mock vulnerable server on port 8080")
    print("=" * 65)

if __name__ == "__main__":
    show_help()
