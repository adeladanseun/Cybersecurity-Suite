"""CLI for network discovery."""
import argparse
import json
import os
import sys
from datetime import datetime

from . import NetworkDiscovery


def _read_targets(path_or_target: str) -> list[str]:
    if os.path.isfile(path_or_target):
        with open(path_or_target) as f:
            return [ln.strip() for ln in f
                    if ln.strip() and not ln.startswith("#")]
    return [path_or_target]


def _cli(argv=None) -> int:
    p = argparse.ArgumentParser(prog="network_discovery")
    p.add_argument("targets",
                   help="File with one target per line, or a single target")
    p.add_argument("-o", "--output", default="data/intermediate/discovery.json")
    p.add_argument("--method", default="auto",
                   choices=["auto", "arp", "scapy_tcp", "ping", "nmap"])
    args = p.parse_args(argv)

    targets = _read_targets(args.targets)
    if not targets:
        print("ERROR: no targets", file=sys.stderr)
        return 2

    discovery = NetworkDiscovery()
    results = {
        "targets":   targets,
        "hosts":     [],
        "errors":    [],
        "timestamp": datetime.now().isoformat(),
    }

    for target in targets:
        print(f"Discovering {target}...", file=sys.stderr)
        try:
            r = discovery.discover_network(target, method=args.method)
            results["hosts"].extend(r.get("hosts", []))
        except Exception as e:
            print(f"  Warning: {target}: {e}", file=sys.stderr)
            results["errors"].append({"target": target, "error": str(e)})

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2, default=str)

    n_hosts  = len(results["hosts"])
    n_failed = len(results["errors"])
    print(f"Discovery complete: {n_hosts} hosts found "
          f"({n_failed}/{len(targets)} failed)", file=sys.stderr)

    # exit-code semantics (see "Exit codes" below)
    if n_hosts == 0 and n_failed == len(targets):
        return 1
    if n_hosts == 0:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(_cli())