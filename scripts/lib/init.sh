#!/bin/bash
# scripts/lib/init.sh — sourced by every entry-point script.
# Idempotent: safe to source multiple times.

# ─── resolve caller directory (BASH_SOURCE[1] = the script that sourced us)
_caller="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
if [ -z "${SCRIPT_DIR:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$_caller")" && pwd)"
    export SCRIPT_DIR
fi
unset _caller

# ─── locate project root via marker (no-op if already found) ──────────────
if [ -z "${PROJECT_DIR:-}" ]; then
    d="$SCRIPT_DIR"
    while [ "$d" != "/" ]; do
        [ -f "$d/.cybersec-root" ] && { PROJECT_DIR="$d"; break; }
        d="$(dirname "$d")"
    done
    unset d
    if [ -z "${PROJECT_DIR:-}" ]; then
        echo "init.sh: no .cybersec-root above $SCRIPT_DIR" >&2
        return 1 2>/dev/null || exit 1
    fi
    export PROJECT_DIR
fi

# ─── always run from project root ─────────────────────────────────────────
cd "$PROJECT_DIR" || { echo "init.sh: cannot cd $PROJECT_DIR" >&2; return 1 2>/dev/null || exit 1; }

# ─── sanity guard: fail loud if we're not actually at the root ────────────
if [ ! -d "$PROJECT_DIR/core" ] || [ ! -d "$PROJECT_DIR/tools" ]; then
    echo "init.sh: $PROJECT_DIR does not look like the project root" >&2
    return 1 2>/dev/null || exit 1
fi

# ─── shared helpers (was utils.sh) ────────────────────────────────────────
get_timestamp() { date +%Y%m%d_%H%M%S; }

print_info()    { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
print_success() { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
print_warn()    { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
print_error()   { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; }

show_banner() {
    cat <<'EOF'
╔══════════════════════════════════════════════════════════╗
║          CYBERSECURITY SUITE                              ║
║          Network Security Assessment Toolkit              ║
╚══════════════════════════════════════════════════════════╝
EOF
}

beep() {
    # best-effort; never fails the script
    command -v termux-vibrate >/dev/null 2>&1 && termux-vibrate -d 100 >/dev/null 2>&1 || true
    command -v aplay          >/dev/null 2>&1 && aplay -q /dev/null 2>/dev/null        || true
    return 0
}

# anything else you currently duplicate across scripts goes here