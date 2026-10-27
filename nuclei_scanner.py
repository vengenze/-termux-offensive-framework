import subprocess
import json
import os

def run_nuclei_scan(scan_state_filepath="scan_results.json", output_filepath="nuclei_results.json"):
    print(f"    [+] Initializing Full-Thoroughness Nuclei Scanner (No Hard Timeout)...")
    
    if not os.path.exists(scan_state_filepath):
        print(f"        [-] No scan state found to feed into Nuclei.")
        return False

    targets = set()
    ignored_extensions = (".js", ".css", ".ico", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".gif")
    
    try:
        with open(scan_state_filepath, "r") as f:
            data = json.load(f)
            for item in data:
                url = item.get("target")
                if url and url.startswith("http"):
                    clean_url = url.split("#")[0]
                    if not clean_url.lower().endswith(ignored_extensions):
                        targets.add(clean_url)
    except Exception as e:
        print(f"        [!] Error reading state for Nuclei: {e}")
        return False

    if not targets:
        print(f"        [-] No valid dynamic target URLs found for Nuclei scan.")
        return False

    target_file = "nuclei_targets.txt"
    with open(target_file, "w") as tf:
        tf.write("\n".join(targets))

    # Comprehensive command covering exposures, misconfigs, vulnerabilities, and tokens
    cmd = [
        "nuclei", 
        "-l", target_file, 
        "-json-export", output_filepath, 
        "-silent",
        "-tags", "exposure,misconfig,token,secret,panel,api,cve",
        "-c", "25",                      # Balanced concurrency for Termux
        "-timeout", "8"                  # Individual request timeout
    ]

    try:
        print(f"    [->] Running full Nuclei scan across {len(targets)} endpoints. Please wait...")
        # No timeout parameter—letting Nuclei run to its natural completion
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if os.path.exists(output_filepath) and os.path.getsize(output_filepath) > 0:
            print(f"        [+] Nuclei scan complete! Findings successfully exported to '{output_filepath}'")
            return True
        else:
            print(f"        [-] Nuclei scan finished, no vulnerabilities found matching criteria.")
            return False
            
    except FileNotFoundError:
        print(f"        [!] Error: 'nuclei' command not found. Ensure it is installed and in your PATH.")
        return False
    except Exception as e:
        print(f"        [!] Nuclei execution error: {e}")
        return False
