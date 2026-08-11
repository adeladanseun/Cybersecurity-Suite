"""
Tests for core.logger module
Run: python3 tests/test_logger.py
"""

import sys
import os
import tempfile
import logging

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.logger import CyberLogger, get_logger


def test_logger_creation():
    """Test logger creation."""
    print("\n[*] Testing Logger Creation...")

    # Create logger with file output
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    try:
        logger = CyberLogger.setup_logger(
            name="test_logger", log_file=log_path, level=logging.DEBUG
        )

        # Verify logger was created
        assert logger is not None
        assert logger.name == "test_logger"

        # Test logging at different levels
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")

        # Verify log file was written
        with open(log_path, "r") as f:
            content = f.read()

        assert "Debug message" in content
        assert "Info message" in content
        assert "Warning message" in content
        assert "Error message" in content

        print("  ✓ Logger creation passed")

    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)


def test_get_logger():
    """Test get_logger convenience function."""
    print("\n[*] Testing Get Logger...")

    logger1 = get_logger("test_get_logger")
    logger2 = get_logger("test_get_logger")

    # Should return same logger instance
    assert logger1 is logger2

    print("  ✓ Get logger passed")


def test_logger_singleton():
    """Test that loggers are properly cached."""
    print("\n[*] Testing Logger Caching...")

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    try:
        logger1 = CyberLogger.setup_logger("test_singleton", log_file=log_path)
        logger2 = CyberLogger.get_logger("test_singleton")
        logger3 = CyberLogger.setup_logger("test_singleton", log_file=log_path)

        # All should be same instance
        assert logger1 is logger2
        assert logger2 is logger3

        print("  ✓ Logger caching passed")

    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)


def run_all_logger_tests():
    """Run all logger tests."""
    print("=" * 60)
    print("LOGGER MODULE TESTS")
    print("=" * 60)

    try:
        test_logger_creation()
        test_get_logger()
        test_logger_singleton()

        print("\n" + "=" * 60)
        print("✅ All logger tests passed!")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_logger_tests()
    sys.exit(0 if success else 1)
