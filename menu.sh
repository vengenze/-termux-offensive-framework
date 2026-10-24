#!/bin/bash

# Ensure colors are supported
RED='\033[91m'
GREEN='\033[92m'
BLUE='\033[94m'
YELLOW='\033[93m'
RESET='\033[0m'

while true; do
    clear
    echo -e "${BLUE}==================================================${RESET}"
    echo -e "${GREEN}    TERMUX OFFENSIVE SECURITY FRAMEWORK (v3.2)    ${RESET}"
    echo -e "${BLUE}==================================================${RESET}"
    echo " [Reconnaissance & Scans]"
    echo "  1) Run Full Automated Pipeline (Subdomains, Ports, Web)"
    echo "  2) Run Master Web Vulnerability Scan (Single Target URL)"
    echo "  3) Run Local Network Mapper & Router Audit"
    echo "  4) Run Cloud Storage & S3 Bucket Hunter"
    echo ""
    echo " [Access Gain & Exploitation]"
    echo "  5) Run Automated SQL Injection Dumper"
    echo "  6) Run Authentication Brute-Forcer"
    echo "  7) Run Exploit Deployer & Reverse Shell Listener"
    echo "  8) Run Arbitrary File Upload Exploiter"
    echo ""
    echo " [Autonomous Operations]"
    echo "  9) Run Autonomous Exploit & Weakness Deployer"
    echo ""
    echo " [Access Gained / Post-Exploitation]"
    echo " 10) Launch Access Gained Console (Post-Exploitation)"
    echo ""
    echo " [Reporting & Management]"
    echo " 11) Generate Terminal Summary & Baseline (probe_baseline.txt)"
    echo " 12) View Latest probe_baseline.txt"
    echo ""
    echo " [Help & Reference]"
    echo " 13) View Framework Command Reference (Help)"
    echo ""
    echo " [Framework Exit]"
    echo " 14) Exit Framework"
    echo -e "${BLUE}==================================================${RESET}"
    read -p "Select an option [1-14]: " choice

    case $choice in
        1)
            echo -e "\n${YELLOW}[*] Enter target domain (e.g., example.com): ${RESET}"
            read -r target_domain
            if [ -n "$target_domain" ]; then
                ./recon_pipeline.sh "$target_domain"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        2)
            echo -e "\n${YELLOW}[*] Enter target URL (e.g., http://testphp.vulnweb.com): ${RESET}"
            read -r target_url
            if [ -n "$target_url" ]; then
                python master_scanner.py "$target_url"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        3)
            echo -e "\n${YELLOW}[*] Running Local Network Recon...${RESET}"
            ./local_recon.sh
            read -p "Press Enter to return to menu..."
            ;;
        4)
            echo -e "\n${YELLOW}[*] Enter company name or domain for bucket hunt: ${RESET}"
            read -r bucket_target
            if [ -n "$bucket_target" ]; then
                python bucket_hunter.py "$bucket_target"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        5)
            echo -e "\n${YELLOW}[*] SQL Injection Dumper${RESET}"
            read -p "Enter target URL with parameters: " sql_url
            read -p "Enter vulnerable parameter name (default 'cat'): " sql_param
            sql_param=${sql_param:-cat}
            if [ -n "$sql_url" ]; then
                python sql_dumper.py "$sql_url" -p "$sql_param"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        6)
            echo -e "\n${YELLOW}[*] Authentication Brute-Forcer${RESET}"
            read -p "Enter login endpoint URL: " login_url
            read -p "Enter username or wordlist (default 'admin'): " login_user
            login_user=${login_user:-admin}
            read -p "Enter password wordlist path (e.g., passwords.txt): " pass_file
            if [ -n "$login_url" ] && [ -n "$pass_file" ]; then
                python auth_bruter.py "$login_url" -u "$login_user" -pw "$pass_file"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        7)
            echo -e "\n${YELLOW}[*] Exploit Deployer & Reverse Shell${RESET}"
            read -p "Enter vulnerable URL with parameters: " exp_url
            read -p "Enter vulnerable parameter name: " exp_param
            read -p "Enter local listener port (default 4444): " exp_port
            exp_port=${exp_port:-4444}
            if [ -n "$exp_url" ] && [ -n "$exp_param" ]; then
                python exploit_deployer.py "$exp_url" "$exp_param" -p "$exp_port"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        8)
            echo -e "\n${YELLOW}[*] Arbitrary File Upload Exploiter${RESET}"
            read -p "Enter upload endpoint URL: " up_url
            read -p "Enter file form field name (default 'file'): " up_field
            up_field=${up_field:-file}
            read -p "Enter web-accessible storage directory URL (optional): " up_dir
            if [ -n "$up_url" ]; then
                if [ -n "$up_dir" ]; then
                    python upload_exploiter.py "$up_url" -f "$up_field" -d "$up_dir"
                else
                    python upload_exploiter.py "$up_url" -f "$up_field"
                fi
            fi
            read -p "Press Enter to return to menu..."
            ;;
        9)
            echo -e "\n${YELLOW}[*] Launching Autonomous Exploit Orchestrator...${RESET}"
            python auto_exploit.py
            read -p "Press Enter to return to menu..."
            ;;
        10)
            echo -e "\n${YELLOW}[*] Launching Access Gained Console...${RESET}"
            read -p "Enter active target URL or Web Shell URL: " active_url
            read -p "Enter session type (webshell/sql/brute) [default: webshell]: " session_type
            session_type=${session_type:-webshell}
            if [ -n "$active_url" ]; then
                python access_console.py "$active_url" "$session_type"
            fi
            read -p "Press Enter to return to menu..."
            ;;
        11)
            echo -e "\n${YELLOW}[*] Compiling Terminal Summary & Baseline...${RESET}"
            python build_baseline.py
            read -p "Press Enter to return to menu..."
            ;;
        12)
            echo -e "\n${YELLOW}[*] Displaying latest probe_baseline.txt...${RESET}"
            if [ -f "probe_baseline.txt" ]; then
                less probe_baseline.txt
            else
                LATEST_BASE=$(find . -name "probe_baseline.txt" -print0 | xargs -0 ls -t | head -n 1)
                if [ -n "$LATEST_BASE" ]; then
                    less "$LATEST_BASE"
                else
                    echo "[-] No probe_baseline.txt found yet."
                fi
            fi
            ;;
        13)
            echo -e "\n${YELLOW}[*] Displaying Framework Command Reference...${RESET}"
            python framework_help.py
            read -p "Press Enter to return to menu..."
            ;;
        14)
            echo -e "\n${GREEN}[+] Exiting framework. Stay safe!${RESET}"
            exit 0
            ;;
        *)
            echo -e "\n${RED}[-] Invalid option. Please choose between 1 and 14.${RESET}"
            sleep 1
            ;;
    esac
done
