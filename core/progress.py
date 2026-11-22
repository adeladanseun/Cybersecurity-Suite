"""
core/progress.py — universal terminal progress indicators.

Zero-dependency by default (built-in ANSI bar).  Upgrades automatically:
    rich  →  multi-line colorful dashboard
    tqdm  →  classic bar

Auto-disables when:
    - stderr is not a TTY (redirected to file / CI)
    - TERM=dumb
    - NO_PROGRESS=1 is set in the environment

All output goes to stderr so stdout/files stay clean for logs and JSON.
"""
import os
import re
import sys
import time
import threading
from typing import Iterable, Optional


_PERCENT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*%")


# --- enable/disable logic --------------------------------------------------
def _enabled() -> bool:
    if os.environ.get("NO_PROGRESS", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        return sys.stderr.isatty()
    except Exception:
        return False


# --- backend detection -----------------------------------------------------
_BACKEND = "ansi"
try:
    import rich  # noqa: F401
    _BACKEND = "rich"
except ImportError:
    try:
        import tqdm  # noqa: F401
        _BACKEND = "tqdm"
    except ImportError:
        _BACKEND = "ansi"


# ===========================================================================
# Bar
# ===========================================================================
class _Bar:
    def __init__(self, total: int = 100, desc: str = "", unit: str = "it"):
        self.total = total
        self.desc = desc
        self.unit = unit
        self._rich_progress = None
        self._rich_task = None
        self._tqdm = None
        self._current = 0.0
        self._t0 = time.time()
        self._on = _enabled()

    # --- context manager ---------------------------------------------------
    def __enter__(self):
        if not self._on:
            return self
        if _BACKEND == "rich":
            from rich.progress import (
                Progress, BarColumn, TextColumn,
                TimeRemainingColumn, SpinnerColumn,
            )
            self._rich_progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=30),
                TextColumn("[progress.percentage]{task.percentage:>5.1f}%"),
                TextColumn("ETA:"),
                TimeRemainingColumn(),
            )
            self._rich_progress.start()
            self._rich_task = self._rich_progress.add_task(
                self.desc or "Working", total=self.total)
        elif _BACKEND == "tqdm":
            from tqdm import tqdm as _tqdm
            self._tqdm = _tqdm(
                total=self.total, desc=self.desc, unit=self.unit,
                leave=True, file=sys.stderr,
            )
        else:
            self._draw_ansi()
        return self

    def __exit__(self, *exc):
        if self._rich_progress:
            self._rich_progress.stop()
        if self._tqdm:
            self._tqdm.close()
        if _BACKEND == "ansi" and self._on:
            sys.stderr.write("\n")
            sys.stderr.flush()

    # --- updates -----------------------------------------------------------
    def update(self, current: float):
        """Set absolute count (0..total).  Use for manual control."""
        if not self._on:
            return
        current = max(0.0, min(float(current), float(self.total)))
        self._current = current
        if self._rich_progress and self._rich_task is not None:
            self._rich_progress.update(self._rich_task, completed=current)
        elif self._tqdm:
            delta = current - self._tqdm.n
            if delta > 0:
                self._tqdm.update(delta)
        else:
            self._draw_ansi()

    def advance(self, delta: float = 1):
        self.update(min(self._current + delta, self.total))

    def set_description(self, desc: str):
        self.desc = desc
        if self._rich_progress and self._rich_task is not None:
            self._rich_progress.update(self._rich_task, description=desc)
        elif self._tqdm:
            self._tqdm.set_description(desc)
        elif self._on:
            self._draw_ansi()

    # --- subprocess helper -------------------------------------------------
    def feed_line(self, line: str) -> bool:
        """
        Look for a percentage in `line` and update.  Returns True if updated.
        Handles both '32.15%' and '32%' (nmap, masscan, ffuf, gobuster, etc.).
        """
        if not self._on:
            return False
        m = _PERCENT_RE.search(line)
        if not m:
            return False
        try:
            self.update(float(m.group(1)))
            return True
        except ValueError:
            return False

    # --- tiny ANSI fallback ------------------------------------------------
    def _draw_ansi(self):
        pct = (self._current / self.total * 100) if self.total else 0.0
        width = 30
        filled = int(width * pct / 100)
        bar = "█" * filled + "░" * (width - filled)
        eta = ""
        if self._current > 0:
            rate = self._current / max(time.time() - self._t0, 1e-9)
            if rate > 0 and self._current < self.total:
                remaining = (self.total - self._current) / rate
                eta = f" ETA {int(remaining)}s"
        desc = (self.desc or "")[:24]
        sys.stderr.write(f"\r{desc:<24} |{bar}| {pct:5.1f}%{eta}")
        sys.stderr.flush()


# ===========================================================================
# Spinner (unknown duration)
# ===========================================================================
class _Spinner:
    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, desc: str = "Working"):
        self.desc = desc
        self._stop = False
        self._thread = None
        self._on = _enabled()

    def __enter__(self):
        if self._on:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        if self._thread:
            self._thread.join()
        if self._on:
            sys.stderr.write("\r" + " " * 60 + "\r")
            sys.stderr.flush()

    def _spin(self):
        i = 0
        while not self._stop:
            f = self._FRAMES[i % len(self._FRAMES)]
            sys.stderr.write(f"\r{f} {self.desc}")
            sys.stderr.flush()
            i += 1
            time.sleep(0.1)


# ===========================================================================
# Public API
# ===========================================================================
def bar(total: int = 100, desc: str = "", unit: str = "it") -> _Bar:
    """Manual bar. Usage: with bar(total=N, desc='x') as b: b.update(i)"""
    return _Bar(total=total, desc=desc, unit=unit)


def spinner(desc: str = "Working") -> _Spinner:
    """Indeterminate spinner. Usage: with spinner('generating'): do_work()"""
    return _Spinner(desc)


def track(iterable: Iterable, desc: str = "", total: Optional[int] = None):
    """Yield items from `iterable` while showing a bar."""
    if not _enabled():
        yield from iterable
        return
    if total is None:
        try:
            total = len(iterable)  # type: ignore[arg-type]
        except TypeError:
            total = None
    if total is None:
        # unknown length: just spin
        with _Spinner(desc or "Working"):
            yield from iterable
        return
    with _Bar(total=total, desc=desc) as b:
        for i, item in enumerate(iterable, 1):
            yield item
            b.update(i)


"""

2. Four usage patterns — pick the one that matches each tool



Pattern A — iterating over a known‑size collection
Use inside any for loop in dns_enum, web_enum, vuln_checker, etc.

python
from core.progress import track

# before:
for host in hosts:
    do_dns_lookup(host)

# after:
for host in track(hosts, desc="DNS lookups"):
    do_dns_lookup(host)



Pattern B — manual update inside a loop
Good when you need more control (skip items, print things mid‑loop).

python
from core.progress import bar

with bar(total=len(urls), desc="Enumerating") as b:
    for i, url in enumerate(urls, 1):
        try:
            fetch(url)
        except Exception:
            pass
        b.update(i)




        
Pattern C — unknown duration (network calls, report generation)
python
from core.progress import spinner

with spinner("Building HTML report..."):
    generator.generate_from_file(scan_file, ...)
Pattern D — subprocess that emits percentages
This is the nmap case, but it works identically for masscan, ffuf, gobuster, feroxbuster, nuclei, hydra, nikto, sqlmap — anything that writes NN% to stdout/stderr.

python
from core.progress import bar

with bar(total=100, desc=f"nmap {target}", unit="%") as pbar:
    for line in process.stdout:
        logf.write(line)
        pbar.feed_line(line)          # ← one line replaces all %-parsing
        if callback:
            callback(line)
feed_line returns True if it found a percentage, so if you need special handling you can branch on it. Otherwise fire‑and‑forget.

"""