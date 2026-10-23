
# php2shell-scanner

needed a quick way to scan some subnets and custom ports for those php2shell CVEs (CVE-2026-109618 & CVE-2026-109619) without crashing services or sending payloads. wrote a multi-threaded python script for it, cleaned it up, and here it is.

does CIDR parsing, multi-port ranges, checks headers safely, and spits out JSON or CSV if you care about reports.

---

## usage

clone it:
```bash
git clone https://github.com/reza-ghanbari-adivi/php2shell-scanner.git
cd php2shell-scanner
pip install -e .
```

run it:
```bash
python3 vlan_scanner.py <CIDR_RANGE> [options]
```

### options
* `-p, --ports` : ports to check (supports lists like `80,443` or ranges like `80-443`). defaults to common web/admin ports.
* `-t, --threads` : concurrency threads (default: `100`).
* `-o, --output`  : save results to json or csv.

### examples
```bash
# scan a subnet on default web ports and save to json
python3 vlan_scanner.py 87.107.135.0/24 -o audit.json

# scan a specific port range with custom threads
python3 vlan_scanner.py 87.107.84.0/24 -p 80-443 -t 150 -o results.csv
```
## disclaimer
use it on your own infra or with permission. don't do stupid things.
```
