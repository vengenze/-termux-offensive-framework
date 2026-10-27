import subprocess
import json
import os

def run_nuclei_scan(scan_state_filepath="scan_results.json", output_filepath="nuclei_results.json"):
    """
    Feeds discovered endpoints from scan state into ProjectDiscovery's Nuclei scanner.
    """
    print(f"    [+] Initializing Nuclei Vulnerability Scanner...")
    
    if not os.path.exists(scan_state_filepath):
        print(f"        [-] No scan state found to feed into Nuclei.")
        return False

    # Extract unique target URLs from scan_results.json
    targets = set()
    try:
        with open(scan_state_filepath, "r") as f:
            data = json.load(f)
            for item in data:
                url = item.get("target")
                if url and url.startswith("http"):
                    # Strip fragment tags just in case
                    targets.add(url.split("#")[0])
    except Exception as e:
        print(f"        [!] Error reading state for Nuclei: {e}")
        return False

    if not targets:
        print(f"        [-] No valid target URLs found for Nuclei scan.")
        return False

    # Write targets to a temporary file for Nuclei
    target_file = "nuclei_targets.txt"
    with open(target_file, "w") as tf:
        tf.write("\n".join(targets))

    # Nuclei command: nuclei -l targets.txt -json-export results.json -silent
    cmd = ["nuclei", "-l", target_file, "-json-export", output_filepath, "-silent"]

    try:
        print(f"    [->] Running Nuclei across {len(targets)} discovered endpoints...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if os.path.exists(output_filepath) and os.path.getsize(output_filepath) > 0:
            print(f"        [+] Nuclei scan complete! Findings exported to '{output_filepath}'")
            return True
        else:
            print(f"        [-] Nuclei scan completed, no vulnerabilities exported.")
            return False
            
    except FileNotFoundError:
        print(f"        [!] Error: 'nuclei' command not found. Ensure it is installed and in your PATH.")
        return False
    except subprocess.TimeoutExpired:
        print(f"        [!] Nuclei scan timed out.")
        return False
    except Exception as e:
        print(f"        [!] Nuclei subprocess error: {e}")
        return False
