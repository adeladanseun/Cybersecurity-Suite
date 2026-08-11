"""
Audio notification system for CyberSecurity Suite.
Provides system beep patterns for different events.
Uses Linux beep command or fallback to terminal bell.
"""

import os
import platform
import subprocess
import time


class Notifier:
    """Cross-platform audio notification system."""

    BEEP_PATTERNS = {
        "standard": [(800, 0.2), (1000, 0.2)],
        "major": [(800, 0.3), (1000, 0.3), (1200, 0.5)],
        "error": [(200, 0.5), (200, 0.5), (200, 0.5)],
        "complete": [(1000, 0.1), (1200, 0.1), (1400, 0.3)],
        "finding": [(1500, 0.1), (1800, 0.1), (2000, 0.2)],
        "progress": [(1000, 0.1)],
    }

    @staticmethod
    def is_beep_available():
        """Check if beep command is available on the system."""
        try:
            result = subprocess.run(["which", "beep"], capture_output=True, text=True)
            if result.returncode == 0:
                return True

            # Try 'play' command (sox)
            result = subprocess.run(["which", "play"], capture_output=True, text=True)
            return result.returncode == 0

        except FileNotFoundError:
            return False

    @staticmethod
    def _play_tone(frequency, duration):
        """
        Play a single tone using available system tools.

        Args:
            frequency: Tone frequency in Hz
            duration: Duration in seconds
        """
        try:
            # Try 'play' command first (part of sox package)
            subprocess.run(
                [
                    "play",
                    "-nq",
                    "-t",
                    "alsa",
                    "synth",
                    str(duration),
                    "sine",
                    str(frequency),
                ],
                capture_output=True,
                timeout=duration + 1,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            try:
                # Fall back to 'beep' command
                subprocess.run(
                    ["beep", "-f", str(frequency), "-l", str(int(duration * 1000))],
                    capture_output=True,
                    timeout=duration + 1,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Final fallback: terminal bell
                print("\a", end="", flush=True)

    @classmethod
    def beep(cls, pattern="standard", times=1, silent=False):
        """
        Play a beep pattern.

        Args:
            pattern: Pattern name ('standard', 'major', 'error', 'complete', 'finding')
            times: Number of times to repeat the pattern
            silent: If True, suppress all beeps
        """
        if silent:
            return

        if not cls.is_beep_available():
            print("\a", end="", flush=True)
            return

        pattern_tones = cls.BEEP_PATTERNS.get(pattern, cls.BEEP_PATTERNS["standard"])

        for _ in range(times):
            for frequency, duration in pattern_tones:
                cls._play_tone(frequency, duration)
                time.sleep(0.05)  # Small gap between tones

            if times > 1:
                time.sleep(0.3)  # Gap between repetitions

    @classmethod
    def beep_major(cls, silent=False):
        """Beep for major milestones."""
        cls.beep("major", times=1, silent=silent)

    @classmethod
    def beep_complete(cls, silent=False):
        """Beep for task completion."""
        cls.beep("complete", times=1, silent=silent)

    @classmethod
    def beep_error(cls, silent=False):
        """Beep for errors."""
        cls.beep("error", times=2, silent=silent)

    @classmethod
    def beep_finding(cls, silent=False):
        """Beep when a vulnerability is found."""
        cls.beep("finding", times=1, silent=silent)

    @classmethod
    def beep_progress(cls, percentage, silent=False):
        """
        Beep for progress updates (at 25%, 50%, 75%, 100%).

        Args:
            percentage: Progress percentage (0-100)
        """
        if percentage in [25, 50, 75, 100]:
            cls.beep("progress", times=1, silent=silent)
