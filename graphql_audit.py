import sys
import urllib.request
import urllib.error
import json
import os

RESULTS_FILE = "scan_results.json"

INTROSPECTION_QUERY = {
    "query": """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              fields {
                name
              }
            }
          }
        }
    """
}

def audit_graphql(target_url):
    print("=" * 60)
    print(f" [*] GRAPHQL INTROSPECTION & SCHEMA AUDITOR: {target_url}")
    print("=" * 60)

    data = json.dumps(INTROSPECTION_QUERY).encode('utf-8')
    req = urllib.request.Request(
        target_url,
        data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        },
        method='POST'
    )

    try:
        print("[*] Sending GraphQL introspection query...")
        with urllib.request.urlopen(req, timeout=4) as resp:
            body = resp.read().decode('utf-8', errors='ignore')
            result = json.loads(body)

            if "data" in result and "__schema" in result["data"]:
                print("    [!] VULNERABLE: GraphQL Introspection is ENABLED!")
                schema = result["data"]["__schema"]
                print(f"        Query Type : {schema.get('queryType', {}).get('name')}")
                print(f"        Mutation Type : {schema.get('mutationType', {}).get('name')}")
                
                types = schema.get("types", [])
                print(f"        Discovered Types & Fields ({len(types)} types total):")
                for t in types:
                    if not t["name"].startswith("__"):
                        fields = [f["name"] for f in t.get("fields", []) if f.get("fields") is not None] or [f["name"] for f in t.get("fields", [])]
                        print(f"          - Type: {t['name']} | Fields: {fields}")

                # Save finding
                findings = []
                if os.path.exists(RESULTS_FILE):
                    try:
                        with open(RESULTS_FILE, "r") as f:
                            findings = json.load(f)
                    except Exception:
                        pass
                
                findings.append({
                    "target": target_url,
                    "vulnerability": "GraphQL Introspection Enabled"
                })

                with open(RESULTS_FILE, "w") as f:
                    json.dump(findings, f, indent=4)
                print("[+] Finding saved to scan_results.json")
            else:
                print("[-] GraphQL introspection appears disabled or restricted.")
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        print(f"[-] Connection error: {e.reason}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        audit_graphql(sys.argv[1])
    else:
        audit_graphql("http://127.0.0.1:8080/graphql")
