"""CLI for report generation."""
import argparse
import json
import sys
from datetime import datetime

from . import ReportGenerator


def _cli(argv=None) -> int:
    p = argparse.ArgumentParser(prog="report_builder")
    p.add_argument("input",
                   help="Primary JSON (e.g. vulns file from step 3)")
    p.add_argument("-i", "--include", action="append", default=[],
                   metavar="FILE",
                   help="Additional JSON to fill gaps (scan, discovery). "
                        "Repeatable. Primary values are preserved.")
    p.add_argument("-o", "--output-dir", default="reports")
    p.add_argument("--report-type", default="full",
                   choices=["full", "executive", "technical", "findings"])
    p.add_argument("--formats", default="html,csv,txt,json",
                   help="Comma-separated: html,csv,txt,json,pdf")
    p.add_argument("--name", default=None,
                   help="Report basename (default: report_<timestamp>)")
    args = p.parse_args(argv)

    # ── load primary payload ────────────────────────────────────────────
    try:
        with open(args.input) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"ERROR: cannot read {args.input}: {e}", file=sys.stderr)
        return 2

    # ── shallow-merge enrichments; primary always wins on conflicts ─────
    # This is what fills `ports` from the scan file and `hosts` from the
    # discovery file while leaving the vuln file's `summary` / `findings`
    # untouched.
    for inc in args.include:
        try:
            with open(inc) as f:
                extra = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARN: skipping {inc}: {e}", file=sys.stderr)
            continue
        for k, v in extra.items():
            # Only fill keys the primary is missing or has empty
            if k not in data or data[k] in (None, [], {}, ""):
                data[k] = v

    # ── resolve formats & name ─────────────────────────────────────────
    formats = [s.strip().lower() for s in args.formats.split(",") if s.strip()]
    if not formats:
        print("ERROR: --formats produced no formats", file=sys.stderr)
        return 2
    name = args.name or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # ── generate ────────────────────────────────────────────────────────
    gen = ReportGenerator(output_dir=args.output_dir)
    try:
        paths = gen.generate_report(
            data,
            report_type=args.report_type,
            formats=formats,
            report_name=name,
        )
    except Exception as e:
        print(f"ERROR: report generation failed: {e}", file=sys.stderr)
        return 1

    print(f"Generated {len(paths)} format(s) in {args.output_dir}:",
          file=sys.stderr)
    for fmt, path in paths.items():
        print(f"  {fmt:5s}  {path}", file=sys.stderr)

    # ── exit-code semantics (same contract as steps 1–3) ────────────────
    missing = [f for f in formats if f not in paths]
    if missing:
        print(f"WARN: failed to produce: {', '.join(missing)}",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(_cli())