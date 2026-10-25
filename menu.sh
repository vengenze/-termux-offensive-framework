#!/bin/bash

while true; do
    clear
    echo "================================================================="
    echo " [*] FULLY SCALED INFRASTRUCTURE OFFENSIVE FRAMEWORK"
    echo "================================================================="
    echo " [Autonomous Pipeline]"
    echo "  1) Run Full Autonomous Pipeline (Mock Server)"
    echo "  2) Run Full Autonomous Pipeline (Custom Domain)"
    echo ""
    echo " [Individual Vector Scanners]"
    echo "  3) Run SQL Injection Dumper"
    echo "  4) Run LFI / Path Traversal Scanner"
    echo "  5) Run JWT Priv-Esc Auditor"
    echo "  6) Run Command Injection / RCE Scanner"
    echo "  7) Run GraphQL Introspection & API Auditor"
    echo ""
    echo " [Post-Exploitation & Access Control]"
    echo "  8) Reverse Shell Generator & Listener"
    echo "  9) Access Gained Control Center (Interactive Dashboard)"
    echo ""
    echo " 10) Exit"
    echo "================================================================="
    read -p "Select option [1-10]: " choice

    case $choice in
        1)
            python auto_exploit.py
            read -p "Press Enter to return to menu..."
            ;;
        2)
            read -p "Enter custom domain target (e.g., http://target.internal or https://api.example.com): " custom_domain
            custom_domain=${custom_domain:-http://127.0.0.1:8080}
            python auto_exploit.py "$custom_domain"
            read -p "Press Enter to return to menu..."
            ;;
        3)
            read -p "Enter target URL (e.g., http://127.0.0.1:8080/listproducts.php): " sqli_url
            read -p "Enter vulnerable parameter [cat]: " sqli_param
            sqli_param=${sqli_param:-cat}
            python sql_dumper.py "$sqli_url" -p "$sqli_param"
            read -p "Press Enter to return to menu..."
            ;;
        4)
            read -p "Enter target URL (e.g., http://127.0.0.1:8080/page.php?file=home): " lfi_url
            python lfi_scanner.py "$lfi_url"
            read -p "Press Enter to return to menu..."
            ;;
        5)
            read -p "Enter JWT token: " jwt_token
            read -p "Enter target endpoint [http://127.0.0.1:8080/api/v1/secure-data]: " jwt_url
            jwt_url=${jwt_url:-http://127.0.0.1:8080/api/v1/secure-data}
            python jwt_auditor.py "$jwt_token" "$jwt_url"
            read -p "Press Enter to return to menu..."
            ;;
        6)
            read -p "Enter target URL (e.g., http://127.0.0.1:8080/ping.php?ip=127.0.0.1): " cmd_url
            read -p "Enter vulnerable parameter [ip]: " cmd_param
            cmd_param=${cmd_param:-ip}
            python cmd_inject.py "$cmd_url" -p "$cmd_param"
            read -p "Press Enter to return to menu..."
            ;;
        7)
            read -p "Enter GraphQL endpoint URL [default http://127.0.0.1:8080/graphql]: " gql_url
            gql_url=${gql_url:-http://127.0.0.1:8080/graphql}
            python graphql_audit.py "$gql_url"
            read -p "Press Enter to return to menu..."
            ;;
        8)
            read -p "Enter listener IP [127.0.0.1]: " lhost
            lhost=${lhost:-127.0.0.1}
            read -p "Enter listener port [4444]: " lport
            lport=${lport:-4444}
            python rev_shell.py --ip "$lhost" --port "$lport"
            read -p "Press Enter to return to menu..."
            ;;
        9)
            python access_console.py
            read -p "Press Enter to return to menu..."
            ;;
        10)
            echo "[*] Exiting framework. Stay safe!"
            exit 0
            ;;
        *)
            echo "[-] Invalid option. Please select between 1 and 10."
            sleep 1
            ;;
    esac
done
