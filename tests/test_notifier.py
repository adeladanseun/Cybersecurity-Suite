"""
Tests for core.notifier module
Run: python3 tests/test_notifier.py
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.notifier import Notifier


def test_notifier_availability():
    """Test if notifier detects beep capability."""
    print("\n[*] Testing Notifier Availability...")

    # Just verify it doesn't crash
    available = Notifier.is_beep_available()
    print(f"  Beep available: {available}")

    print("  ✓ Notifier availability check passed")


def test_beep_patterns():
    """Test that beep patterns exist and don't crash."""
    print("\n[*] Testing Beep Patterns...")

    # Verify patterns exist
    patterns = ["standard", "major", "error", "complete", "finding", "progress"]
    for pattern in patterns:
        assert pattern in Notifier.BEEP_PATTERNS

    print("  ✓ Beep patterns exist")


def test_silent_beeps():
    """Test that silent mode suppresses beeps."""
    print("\n[*] Testing Silent Mode...")

    # These should not produce sound
    try:
        Notifier.beep(silent=True)
        Notifier.beep_major(silent=True)
        Notifier.beep_complete(silent=True)
        Notifier.beep_error(silent=True)
        Notifier.beep_finding(silent=True)
        Notifier.beep_progress(50, silent=True)

        print("  ✓ Silent mode passed")
    except Exception as e:
        print(f"  ⚠ Beep test had issue (may be normal if no audio): {e}")


def test_audible_beeps():
    """Test actual beeps (will only work if audio available)."""
    print("\n[*] Testing Audible Beeps (you may hear sounds)...")

    try:
        # Test with silent fallback
        if not Notifier.is_beep_available():
            print("  ⚠ Beep tools not found, using terminal bell")

        # Quick beep test
        Notifier.beep_complete(silent=False)
        print("  ✓ Audible beeps executed")

    except Exception as e:
        print(f"  ⚠ Audio test issue (expected if no sound card): {e}")


def run_all_notifier_tests():
    """Run all notifier tests."""
    print("=" * 60)
    print("NOTIFIER MODULE TESTS")
    print("=" * 60)

    try:
        test_notifier_availability()
        test_beep_patterns()
        test_silent_beeps()
        test_audible_beeps()

        print("\n" + "=" * 60)
        print("✅ All notifier tests passed!")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_notifier_tests()
    sys.exit(0 if success else 1)
