"""CLI for vulnerability checking against port-scan results."""
import argparse
import json
import os
import sys
from datetime import datetime

from . import ServiceVulnChecker


def _cli(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vuln_checker")
    p.add_argument("scan_file",
                   help="Combined port-scan JSON (output of step 2)")
    p.add_argument("-o", "--output", required=True,
                   help="Where to write the vulnerabilities JSON")
    args = p.parse_args(argv)

    if not os.path.isfile(args.scan_file):
        print(f"ERROR: scan file not found: {args.scan_file}", file=sys.stderr)
        return 2

    try:
        with open(args.scan_file) as f:
            scan_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"ERROR: cannot read scan file: {e}", file=sys.stderr)
        return 2

    checker = ServiceVulnChecker()

    try:
        result = checker.check_scan_results(scan_data)
    except Exception as e:
        print(f"ERROR: vuln check failed: {e}", file=sys.stderr)
        return 1

    # Stamp metadata so the report builder knows where this came from
    result.setdefault("check_metadata", {
        "source_scan": args.scan_file,
        "timestamp":   datetime.now().isoformat(),
    })

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, default=str)

    total = (result.get("summary") or {}).get("total_vulnerabilities", 0)
    by_sev = (result.get("summary") or {}).get("by_severity") or {}
    breakdown = ", ".join(f"{k}:{v}" for k, v in by_sev.items() if v) or "none"
    print(f"Vulnerability check complete: {total} found ({breakdown})",
          file=sys.stderr)

    # exit-code semantics match network_discovery / port_scanner
    if total == 0:
        return 3          # ran clean, no findings — not an error
    return 0


if __name__ == "__main__":
    sys.exit(_cli())