import argparse
import os
import json
import sys
from datetime import datetime

from .scanner import PortScanner

# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _cli(argv=None):
    import argparse
    import json
    from datetime import datetime

    p = argparse.ArgumentParser(prog="port_scanner")
    p.add_argument("targets",
                   help="File with one target per line, or a single target")
    p.add_argument("--mode", default="quick",
                   choices=["quick", "full", "tcp", "udp", "both"],
                   help="quick=top-1000  full=1-65535+sv+sc  or explicit tcp/udp/both")
    p.add_argument("--scan-type", default=None,
                   choices=["quick", "full", "tcp", "udp", "both"],
                   help=argparse.SUPPRESS)                      # legacy alias
    p.add_argument("--ports", default=None)
    p.add_argument("--timing", default="T4",
                   choices=["T0","T1","T2","T3","T4","T5"])
    p.add_argument("--output-dir", "--output", dest="output_dir",
                   default="data/intermediate")
    p.add_argument("--audit-name", default=None,
                   help="Tag for the combined JSON (e.g. 'acs_20261124')")
    p.add_argument("--combined-output", default=None,
                   help="Path to merged JSON for all targets "
                        "(default: <output-dir>/<audit-name>_scan.json)")
    p.add_argument("--sudo", action="store_true")
    p.add_argument("--script-scan", action="store_true")
    p.add_argument("--no-service", action="store_true")
    args = p.parse_args(argv)

    mode = args.scan_type or args.mode                 # honour either flag

    # ── resolve targets ────────────────────────────────────────────────
    if os.path.isfile(args.targets):
        with open(args.targets) as f:
            targets = [ln.strip() for ln in f
                       if ln.strip() and not ln.startswith("#")]
    else:
        targets = [args.targets]
    if not targets:
        print("ERROR: no targets", file=sys.stderr)
        return 2

    # ── map mode to concrete scan parameters ───────────────────────────
    if mode == "quick":
        st, ports, svc, scr = "tcp", args.ports or "top-1000", False, False
    elif mode == "full":
        st, ports, svc, scr = "tcp", args.ports or "1-65535",  True,  True
    else:
        st, ports = mode, args.ports
        svc       = not args.no_service
        scr       = args.script_scan

    # ── run scans ──────────────────────────────────────────────────────
    scanner = PortScanner(output_dir=args.output_dir)
    combined = {
        "scan_metadata": {
            "audit_name":  args.audit_name or datetime.now().strftime("scan_%Y%m%d_%H%M%S"),
            "targets":     targets,
            "mode":        mode,
            "timestamp":   datetime.now().isoformat(),
            "duration": 0.0,
        },
        "ports":   [],
        "hosts":   [],
        "errors":  [],
        "summary": {"total_open_ports": 0},
    }

    wall_start = datetime.now()
    ok = failed = 0
    for i, t in enumerate(targets, 1):
        print(f"[*] ({i}/{len(targets)}) {t}", file=sys.stderr)
        try:
            r = scanner.scan(t, scan_type=st, ports=ports, timing=args.timing,
                             service_detection=svc, script_scan=scr,
                             ping_first=True, sudo=args.sudo)
            meta = r.get("scan_metadata") or {}
            _dur = meta.get("duration") or 0.0
            combined["scan_metadata"]["duration"] += _dur
            combined["scan_metadata"]["duration_sum"] = \
                combined["scan_metadata"].get("duration_sum", 0.0) + _dur

            combined["scan_metadata"]["duration"] += meta.get("duration") or 0.0
            combined["ports"].extend(r.get("ports", []))
            combined["hosts"].extend(r.get("hosts", []))
            combined["summary"]["total_open_ports"] += \
                r.get("summary", {}).get("total_open_ports", 0)
            print(f"    {r['summary']['total_open_ports']} open ports",
                  file=sys.stderr)
            ok += 1
        except Exception as e:
            print(f"  [!] {t}: {e}", file=sys.stderr)
            combined["errors"].append({"target": t, "error": str(e)})
            failed += 1

    # Wall-clock total (includes setup, JSON writes, etc.) is a more
    # honest "how long did this audit take" number than the sum of
    # per-scan nmap times.  Record both: `duration` = wall, and
    # `total_scan_time` = summed nmap time.
    combined["scan_metadata"]["duration"] = \
        (datetime.now() - wall_start).total_seconds()
    combined["scan_metadata"]["total_scan_time"] = \
        round(combined["scan_metadata"].pop("duration_sum", 0.0), 2)

    # ── write combined JSON ───────────────────────────────────────────
    combined_path = args.combined_output
    if not combined_path:
        stem = args.audit_name or "scan"
        combined_path = os.path.join(args.output_dir, f"{stem}_scan.json")
    os.makedirs(os.path.dirname(combined_path) or ".", exist_ok=True)
    with open(combined_path, "w") as f:
        json.dump(combined, f, indent=2, default=str)

    print(f"[+] {ok} ok, {failed} failed — "
          f"{combined['summary']['total_open_ports']} open ports total",
          file=sys.stderr)

    # ── exit codes (see table below) ──────────────────────────────────
    if ok == 0:
        return 1                                     # every target failed
    if combined["summary"]["total_open_ports"] == 0:
        return 3                                     # all clean, zero findings
    return 0

if __name__ == "__main__":
    sys.exit(_cli())