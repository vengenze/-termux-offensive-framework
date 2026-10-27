import subprocess
import json
import os

def run_inql(target_url, output_dir="inql_output", output_filepath="scan_results.json"):
    """
    Executes Doyensec's InQL CLI tool to extract GraphQL schemas and generate templates.
    """
    print(f"    [+] Initializing InQL GraphQL Recon on {target_url}...")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # InQL CLI command: inql -t <url> -o <output_directory>
    cmd = ["inql", "-t", target_url, "-o", output_dir]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            print(f"        [+] InQL execution successful! Artifacts saved to '{output_dir}/'")
            
            # Update pipeline state
            existing_data = []
            if os.path.exists(output_filepath):
                try:
                    with open(output_filepath, "r") as f:
                        existing_data = json.load(f)
                except Exception:
                    pass
            
            existing_urls = {item.get("target") for item in existing_data}
            if target_url not in existing_urls:
                existing_data.append({
                    "target": target_url,
                    "method": "POST",
                    "vulnerability": "GraphQL Endpoint (Audited via InQL)"
                })
                with open(output_filepath, "w") as f:
                    json.dump(existing_data, f, indent=4)
                    
            return True
        else:
            print(f"        [-] InQL returned an error or endpoint restricted: {result.stderr.strip()}")
            return False
            
    except FileNotFoundError:
        print(f"        [!] Error: 'inql' command not found. Run 'pip install inql'.")
        return False
    except Exception as e:
        print(f"        [!] Subprocess error: {e}")
        return False
