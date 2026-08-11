"""
Tests for core.config module
Run: python3 tests/test_config.py
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.config import Config
from core.exceptions import ConfigError


def test_default_config():
    """Test default configuration creation."""
    print("\n[*] Testing Default Configuration...")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config_path = f.name

    try:
        # Create config
        config = Config(config_path)
        # Check defaults
        assert config.get("version") == "1.0.0"
        assert config.get("paths.data_dir") == "./data"
        assert config.get("scan_defaults.timing") == "T4"

        print("  ✓ Default configuration passed")

    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_get_set_config():
    """Test getting and setting configuration values."""
    print("\n[*] Testing Get/Set Configuration...")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config_path = f.name

    try:
        config = Config(config_path)

        # Set a value
        config.set("custom.key", "test_value")
        assert config.get("custom.key") == "test_value"

        # Set nested value
        config.set("scan_defaults.timeout", 600)
        assert config.get("scan_defaults.timeout") == 600

        # Get with default for non-existent key
        assert config.get("non.existent.key", "default") == "default"

        # Save and reload
        config.save()
        config2 = Config(config_path)
        assert config2.get("custom.key") == "test_value"
        assert config2.get("scan_defaults.timeout") == 600

        print("  ✓ Get/Set configuration passed")

    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_scan_profiles():
    """Test scan profile configurations."""
    print("\n[*] Testing Scan Profiles...")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config_path = f.name

    try:
        config = Config(config_path)

        # Quick scan
        quick = config.get_scan_profile("quick")
        assert quick["ports"] == "top-100"
        assert quick["timing"] == "T4"

        # Full scan
        full = config.get_scan_profile("full")
        assert full["ports"] == "1-65535"
        assert full["script_scan"] == True

        # Stealth scan
        stealth = config.get_scan_profile("stealth")
        assert stealth["timing"] == "T2"

        print("  ✓ Scan profiles passed")

    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def test_reset_config():
    """Test resetting configuration to defaults."""
    print("\n[*] Testing Config Reset...")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config_path = f.name

    try:
        config = Config(config_path)

        # Modify and reset
        config.set("version", "2.0.0")
        config.reset_to_default()

        assert config.get("version") == "1.0.0"

        print("  ✓ Config reset passed")

    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)


def run_all_config_tests():
    """Run all config tests."""
    print("=" * 60)
    print("CONFIG MODULE TESTS")
    print("=" * 60)

    try:
        test_default_config()
        test_get_set_config()
        test_scan_profiles()
        test_reset_config()

        print("\n" + "=" * 60)
        print("✅ All config tests passed!")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_config_tests()
    sys.exit(0 if success else 1)
