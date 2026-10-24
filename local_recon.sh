#!/bin/bash

echo "=================================================="
echo " Detecting Local Network Subnet in Termux..."
echo "=================================================="

# Use Python to reliably grab the local IP without triggering netlink permission errors
SUBNET=$(python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    parts = ip.split('.')
    print(f'{parts[0]}.{parts[1]}.{parts[2]}.0/24')
except Exception:
    print('')
")

if [ -z "$SUBNET" ]; then
    echo "[-] Could not automatically detect local subnet. Please enter manually (e.g., 192.168.1.0/24):"
    read -r SUBNET
fi

echo "[+] Target Subnet Identified: $SUBNET"
echo "=================================================="

# Run the python net mapper
python net_mapper.py "$SUBNET"
