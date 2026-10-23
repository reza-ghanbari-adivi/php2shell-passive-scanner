#!/usr/bin/env python3
"""
VLAN & Local Subnet Passive Inspector for PHP Versions (CVE-2026-109618 / CVE-2026-109619)
Safely inspects HTTP/HTTPS headers across subnets without disruptive exploitation.
"""

import argparse
import csv
import http.client
import ipaddress
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def is_vulnerable(major: int, minor: int, patch: int) -> bool:
    if major < 8:
        return True
    if major == 8:
        if minor == 1:
            return True
        if minor == 2 and patch < 35:
            return True
        if minor == 3 and patch < 36:
            return True
        if minor == 4 and patch < 27:
            return True
        if minor == 5 and patch < 12:
            return True
    return False

def extract_php_version(header_value: str):
    if not header_value:
        return None
    match = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", header_value, re.IGNORECASE)
    if match:
        return tuple(int(x) for x in match.groups())
    return None

def check_host(ip: str, port: int, timeout: float) -> dict:
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    
    result = {
        "ip": ip,
        "port": port,
        "status": "down",
        "php_version": None,
        "vulnerable": None,
        "server": None
    }
    
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VLAN-Security-Auditor/1.0"},
        method="HEAD"
    )
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        kwargs = {"timeout": timeout}
        if scheme == "https":
            kwargs["context"] = ctx
            
        with urllib.request.urlopen(req, **kwargs) as response:
            result["status"] = "open"
            headers = dict(response.headers)
            result["server"] = headers.get("Server", "Unknown")
            
            x_powered = headers.get("X-Powered-By", "")
            ver_tuple = extract_php_version(x_powered) or extract_php_version(result["server"])
            
            if ver_tuple:
                result["php_version"] = f"{ver_tuple[0]}.{ver_tuple[1]}.{ver_tuple[2]}"
                result["vulnerable"] = is_vulnerable(*ver_tuple)
                
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError, http.client.HTTPException):
        pass

    return result

def save_report(results: list, output_path: str):
    if output_path.endswith(".json"):
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({
                "scan_time": datetime.utcnow().isoformat(),
                "total_hosts": len(results),
                "results": results
            }, f, indent=4)
        print(f"[*] Report saved to JSON: {output_path}")
    elif output_path.endswith(".csv"):
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "port", "status", "php_version", "vulnerable", "server"])
            writer.writeheader()
            for r in results:
                writer.writerow(r)
        print(f"[*] Report saved to CSV: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Scan VLAN/Subnet for exposed vulnerable PHP runtimes safely.")
    parser.add_argument("cidr", help="Target VLAN CIDR range (e.g. 87.107.135.0/24)")
    parser.add_argument("-p", "--port", type=int, default=443, help="HTTP/HTTPS port to scan (default: 443)")
    parser.add_argument("-t", "--threads", type=int, default=60, help="Concurrency thread count (default: 60)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection timeout in seconds (default: 2.0)")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv)")

    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network specification: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning VLAN / Subnet : {network}")
    print(f"[*] Target Port           : {args.port}")
    print(f"[*] Total IP Addresses    : {network.num_addresses}")
    print("=" * 70)

    active_count = 0
    vulnerable_count = 0
    scan_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check_host, str(ip), args.port, args.timeout): ip for ip in network.hosts()}
        
        for future in as_completed(futures):
            res = future.result()
            if res["status"] == "open":
                active_count += 1
                scan_results.append(res)
                if res["vulnerable"] is True:
                    vulnerable_count += 1
                    print(f"[!] VULNERABLE : {res['ip']}:{res['port']} | PHP {res['php_version']} | Server: {res['server']}")
                elif res["vulnerable"] is False:
                    print(f"[+] PATCHED    : {res['ip']}:{res['port']} | PHP {res['php_version']} | Server: {res['server']}")
                else:
                    print(f"[*] ACTIVE     : {res['ip']}:{res['port']} | Header Hidden / Non-PHP | Server: {res['server']}")

    print("=" * 70)
    print(f"[*] Scan complete.")
    print(f"[*] Active Web Services Found : {active_count}")
    print(f"[*] Potentially Vulnerable    : {vulnerable_count}")

    if args.output and scan_results:
        save_report(scan_results, args.output)

if __name__ == "__main__":
    main()
