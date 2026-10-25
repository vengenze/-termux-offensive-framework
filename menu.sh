#!/bin/bash

# Termux Offensive Framework Interactive Control Panel (v3.2)

# Colors for UI
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

while true; do
    clear
    echo -e "${CYAN}==================================================${RESET}"
    echo -e "${GREEN}   [!] TERMUX OFFENSIVE SECURITY FRAMEWORK (v3.2) [!]"
    echo -e "${CYAN}==================================================${RESET}"
    echo -e " ${YELLOW}[Reconnaissance & Scans]${RESET}"
    echo "  1) Run Full Autonomous Pipeline (auto_exploit.py)"
    echo "  2) Run Master Web Vulnerability Scan (Single Target)"
    echo "  3) Run Local Network Mapper & Router Audit"
    echo "  4) Run Cloud Storage & S3 Bucket Hunter"
    echo ""
    echo -e " ${YELLOW}[Access Gain & Exploitation]${RESET}"
    echo "  5) Run Automated SQL Injection Dumper"
    echo "  6) Run Authentication Brute-Forcer"
    echo "  7) Run Exploit Deployer & Reverse Shell Listener"
    echo "  8) Run Arbitrary File Upload Exploiter"
    echo ""
    echo -e " ${YELLOW}[Autonomous Operations]${RESET}"
    echo "  9) Run Autonomous Exploit & Weakness Deployer"
    echo ""
    echo -e " ${YELLOW}[Access Gained / Post-Exploitation]${RESET}"
    echo " 10) Launch Access Gained Control Center (Post-Exploitation)"
    echo ""
    echo -e " ${YELLOW}[Reporting & Management]${RESET}"
    echo " 11) Generate Terminal Summary & Baseline"
    echo " 12) View Latest Execution Logs"
    echo ""
    echo -e " ${YELLOW}[Help & Reference]${RESET}"
    echo " 13) View Framework Command Reference (Help)"
    echo ""
    echo -e " ${YELLOW}[Framework Exit]${RESET}"
    echo " 14) Exit Framework"
    echo -e "${CYAN}==================================================${RESET}"
    read -p "Select an option [1-14]: " choice

    case $choice in
        1)
            echo -e "\n${GREEN}[*] Launching Autonomous Multi-Vector Orchestrator...${RESET}"
            python auto_exploit.py
            read -p "Press Enter to return to menu..."
            ;;
        2)
            read -p "Enter target URL for web vuln scan: " target_url
            python master_web_scanner.py "$target_url"
            read -p "Press Enter to return to menu..."
            ;;
        3)
            python network_mapper.py
            read -p "Press Enter to return to menu..."
            ;;
        4)
            python s3_hunter.py
            read -p "Press Enter to return to menu..."
            ;;
        5)
            read -p "Enter target URL with parameter (e.g., http://127.0.0.1:8080/listproducts.php?cat=1): " target_url
            read -p "Enter target parameter name (default 'cat'): " param
            param=${param:-cat}
            python sql_dumper.py "$target_url" -p "$param"
            read -p "Press Enter to return to menu..."
            ;;
        6)
            read -p "Enter target login URL: " target_url
            python auth_brute.py "$target_url"
            read -p "Press Enter to return to menu..."
            ;;
        7)
            python exploit_deployer.py
            read -p "Press Enter to return to menu..."
            ;;
        8)
            read -p "Enter upload endpoint URL: " target_url
            python upload_exploit.py "$target_url"
            read -p "Press Enter to return to menu..."
            ;;
        9)
            python auto_exploit.py
            read -p "Press Enter to return to menu..."
            ;;
        10)
            echo -e "\n${GREEN}[*] Launching Access Gained Control Center...${RESET}"
            python access_console.py
            read -p "Press Enter to return to menu..."
            ;;
        11)
            if [ -f "autonomous_execution.log" ]; then
                echo -e "\n--- Execution Log Summary ---"
                tail -n 25 autonomous_execution.log
            else
                echo "[-] No execution logs found."
            fi
            read -p "Press Enter to return to menu..."
            ;;
        12)
            if [ -f "autonomous_execution.log" ]; then
                cat autonomous_execution.log | less
            else
                echo "[-] No execution logs found."
            fi
            read -p "Press Enter to return to menu..."
            ;;
        13)
            echo -e "\n=== Framework Help & Reference ==="
            echo " This framework coordinates reconnaissance, multi-vector discovery,"
            echo " autonomous exploitation, and post-exploitation asset harvesting."
            echo " Results are automatically piped into scan_results.json."
            read -p "Press Enter to return to menu..."
            ;;
        14)
            echo -e "\n${RED}[*] Exiting framework. Stay safe!${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}[-] Invalid option. Please choose between 1 and 14.${RESET}"
            sleep 2
            ;;
    esac
done
