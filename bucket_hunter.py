import requests
import argparse
import sys
import urllib3
import concurrent.futures

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common keywords and suffixes appended to company names to find buckets
BUCKET_SUFFIXES = [
    "",
    "-dev",
    "-stage",
    "-staging",
    "-prod",
    "-production",
    "-backup",
    "-backups",
    "-db",
    "-database",
    "-logs",
    "-assets",
    "-media",
    "-files",
    "-test",
    "-api",
    "-internal",
    "-private",
    "-data"
]

# Cloud storage URL patterns
CLOUD_PATTERNS = [
    "https://{name}.s3.amazonaws.com",
    "https://s3.amazonaws.com/{name}",
    "https://{name}.storage.googleapis.com",
    "https://{name}.blob.core.windows.net"
]

def check_bucket(url):
    try:
        resp = requests.head(url, timeout=3, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        # 200 OK means publicly readable/listable; 403 Forbidden means bucket exists but permissions are restricted (still valuable)
        if resp.status_code == 200:
            return (url, "OPEN / PUBLICLY READABLE", True)
        elif resp.status_code == 403:
            return (url, "EXISTS (Access Denied)", False)
    except Exception:
        pass
    return None

def run_bucket_hunt(target_name):
    print("=" * 60)
    print(f"[*] Cloud Storage & S3 Bucket Hunter: {target_name}")
    print("=" * 60)
    
    # Strip protocol or TLD if user passed a full domain (e.g., example.com -> example)
    clean_name = target_name.split("//")[-1].split("/")[0].split(".")[0]
    
    candidates = []
    for suffix in BUCKET_SUFFIXES:
        name_variant = f"{clean_name}{suffix}"
        for pattern in CLOUD_PATTERNS:
            candidates.append(pattern.format(name=name_variant))
            
    print(f"[*] Generated {len(candidates)} cloud bucket permutations. Sweeping...")
    
    found_buckets = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_bucket, url): url for url in candidates}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                url, status, is_public = res
                found_buckets.append((url, status, is_public))
                if is_public:
                    print(f"    \033[91m[!] CRITICAL PUBLIC BUCKET: {url} ({status})\033[0m")
                else:
                    print(f"    \033[93m[+] Found Bucket: {url} ({status})\033[0m")

    if not found_buckets:
        print("[-] No active cloud storage buckets identified with standard naming patterns.")
    else:
        print(f"\n[+] Total Cloud Storage Endpoints Found: {len(found_buckets)}")

    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud Storage & S3 Bucket Enumerator")
    parser.add_argument("target", help="Target company name or domain (e.g., target or target.com)")
    args = parser.parse_args()
    run_bucket_hunt(args.target)
