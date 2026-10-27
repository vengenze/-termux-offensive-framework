import nmap
import json
import os

def run_nmap_scan(target_host, output_filepath="scan_results.json"):
    """
    Scans a target host/IP for open ports, detects HTTP/HTTPS services,
    and returns discovered web endpoints.
    """
    nm = nmap.PortScanner()
    
    # Clean up the target host string (remove http:// or trailing slashes if passed)
    clean_host = target_host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    
    print(f"    [->] Running Nmap service scan on: {clean_host} (Top 100 common ports)...")
    
    try:
        # Scan top 100 ports with service version detection (-sV) and script scanning for web
        nm.scan(clean_host, arguments='-sV --top-ports 100 --script http-title')
    except Exception as e:
        print(f"    [!] Nmap scan failed: {e}")
        return []

    discovered_endpoints = []

    for host in nm.all_hosts():
        print(f"    [+] Host: {host} ({nm[host].state()})")
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                if state != 'open':
                    continue
                
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port].get('product', '')
                version = nm[host][proto][port].get('version', '')
                
                # Check if it's a web service based on port or service name
                is_web = False
                scheme = "http"
                
                if port in [443, 8443, 4443] or 'ssl' in service or 'https' in service:
                    is_web = True
                    scheme = "https"
                elif port in [80, 8080, 5000, 3000, 8000] or 'http' in service or 'www' in service:
                    is_web = True
                    scheme = "http"
                
                print(f"        [Port {port}] State: {state} | Service: {service} ({product} {version})")
                
                if is_web:
                    url = f"{scheme}://{clean_host}:{port}"
                    # Avoid default ports cluttering the URL string if standard
                    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                        url = f"{scheme}://{clean_host}"
                        
                    print(f"            [+] Discovered Web Target: {url}")
                    discovered_endpoints.append({
                        "target": url,
                        "method": "GET",  # Added for seamless access_console.py pairing
                        "vulnerability": f"Discovered via Nmap (Service: {service})"
                    })

    # Merge with existing scan state so we don't overwrite previous findings
    existing_data = []
    if os.path.exists(output_filepath):
        try:
            with open(output_filepath, "r") as f:
                existing_data = json.load(f)
        except Exception:
            pass
            
    # Avoid duplicate targets
    existing_urls = {item.get("target") for item in existing_data}
    for item in discovered_endpoints:
        if item["target"] not in existing_urls:
            existing_data.append(item)
            
    with open(output_filepath, "w") as f:
        json.dump(existing_data, f, indent=4)
        
    return discovered_endpoints
