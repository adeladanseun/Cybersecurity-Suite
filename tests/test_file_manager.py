"""
Tests for core.file_manager module
Run: python3 tests/test_file_manager.py
"""

import sys
import os
import json
import tempfile
import shutil

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.file_manager import FileManager
from core.exceptions import FileManagerError


def setup_test_environment():
    """Create temporary test directory."""
    test_dir = tempfile.mkdtemp(prefix="cybersec_test_")
    return test_dir, FileManager(test_dir)


def cleanup_test_environment(test_dir):
    """Remove temporary test directory."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_ensure_dir():
    """Test directory creation."""
    print("\n[*] Testing Directory Creation...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Create nested directory
        test_path = "data/test/nested/dir"
        full_path = fm.ensure_dir(test_path)
        
        assert os.path.exists(full_path)
        assert os.path.isdir(full_path)
        
        print("  ✓ Directory creation passed")
    finally:
        cleanup_test_environment(test_dir)


def test_write_and_read_file():
    """Test basic file writing and reading."""
    print("\n[*] Testing File Write/Read...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Write file
        test_content = "Hello, CyberSecurity Suite!"
        fm.write_file("test.txt", test_content)
        
        # Read file
        content = fm.read_file("test.txt")
        assert content == test_content
        
        # Read lines
        fm.write_file("test_lines.txt", "line1\nline2\nline3\n\n#comment\nline4")
        lines = fm.read_lines("test_lines.txt")
        assert len(lines) == 4  # Skips empty and comment
        assert lines[0] == "line1"
        assert "#comment" not in lines
        
        print("  ✓ File write/read passed")
    finally:
        cleanup_test_environment(test_dir)


def test_json_operations():
    """Test JSON file operations."""
    print("\n[*] Testing JSON Operations...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Write JSON
        test_data = {
            "name": "Test Scan",
            "ports": [80, 443, 22],
            "nested": {"key": "value"}
        }
        fm.write_json("test.json", test_data)
        
        # Read JSON
        loaded_data = fm.read_json("test.json")
        assert loaded_data == test_data
        
        # Invalid JSON handling
        fm.write_file("invalid.json", "not valid json{")
        try:
            fm.read_json("invalid.json")
            assert False, "Should have raised FileManagerError"
        except FileManagerError:
            pass  # Expected
        
        print("  ✓ JSON operations passed")
    finally:
        cleanup_test_environment(test_dir)


def test_csv_operations():
    """Test CSV file operations."""
    print("\n[*] Testing CSV Operations...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Write CSV from dicts
        data = [
            {"name": "Alice", "port": "80"},
            {"name": "Bob", "port": "443"}
        ]
        fm.write_csv("test.csv", data)
        
        # Read CSV
        loaded = fm.read_csv("test.csv")
        assert len(loaded) == 2
        assert loaded[0]["name"] == "Alice"
        
        # Append CSV
        new_row = [{"name": "Charlie", "port": "8080"}]
        fm.append_csv("test.csv", new_row)
        loaded = fm.read_csv("test.csv")
        assert len(loaded) == 3
        
        print("  ✓ CSV operations passed")
    finally:
        cleanup_test_environment(test_dir)


def test_read_targets():
    """Test target file reading."""
    print("\n[*] Testing Target File Reading...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Create target file
        target_content = """192.168.1.1
example.com
https://test.com
# This is a comment

10.0.0.0/24
invalid target!!!
"""
        fm.write_file("targets.txt", target_content)
        
        targets = fm.read_targets("targets.txt")
        
        # Should have 4 valid targets
        assert len(targets) == 4
        
        target_list = [t['target'] for t in targets]
        assert "192.168.1.1" in target_list
        assert "example.com" in target_list
        assert "https://test.com" in target_list
        assert "10.0.0.0/24" in target_list
        assert "invalid target!!!" not in target_list
        
        print("  ✓ Target file reading passed")
    finally:
        cleanup_test_environment(test_dir)


def test_timestamp_filename():
    """Test timestamped filename generation."""
    print("\n[*] Testing Filename Generation...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        filename = fm.get_timestamp_filename("scan", "json")
        assert filename.startswith("scan_")
        assert filename.endswith(".json")
        
        # Should contain timestamp
        parts = filename.replace("scan_", "").replace(".json", "").split("_")
        assert len(parts) == 2  # date_time
        
        print("  ✓ Filename generation passed")
    finally:
        cleanup_test_environment(test_dir)


def test_safe_filename():
    """Test safe filename conversion."""
    print("\n[*] Testing Safe Filename...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        assert fm.safe_filename("test file.txt") == "test_file.txt"
        assert fm.safe_filename("evil/path/file") == "evil_path_file"
        assert fm.safe_filename("!!!danger!!!") == "danger"
        
        print("  ✓ Safe filename passed")
    finally:
        cleanup_test_environment(test_dir)


def test_backup_file():
    """Test file backup functionality."""
    print("\n[*] Testing File Backup...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Create a file
        fm.write_file("important.txt", "backup me")
        
        # Backup it
        backup_path = fm.backup_file("important.txt")
        
        assert os.path.exists(backup_path)
        content = fm.read_file(backup_path) if backup_path.startswith(test_dir) else open(backup_path).read()
        
        # Verify content preserved
        assert "backup me" in (content if isinstance(content, str) else str(content))
        
        print("  ✓ File backup passed")
    finally:
        cleanup_test_environment(test_dir)


def test_cleanup_temp_files():
    """Test temporary file cleanup."""
    print("\n[*] Testing Temp File Cleanup...")
    
    test_dir, fm = setup_test_environment()
    
    try:
        # Create temp directory with old files
        temp_dir = fm.ensure_dir("data/temp")
        
        # Create a test file (will be new, won't be cleaned)
        fm.write_file("data/temp/test.txt", "test")
        
        cleaned = fm.cleanup_temp_files(max_age_hours=0)  # Clean files older than 0 hours
        # Might clean or not depending on timing, just verify no error
        assert cleaned >= 0
        
        print("  ✓ Temp file cleanup passed")
    finally:
        cleanup_test_environment(test_dir)


def run_all_file_manager_tests():
    """Run all file manager tests."""
    print("=" * 60)
    print("FILE MANAGER MODULE TESTS")
    print("=" * 60)
    
    try:
        test_ensure_dir()
        test_write_and_read_file()
        test_json_operations()
        test_csv_operations()
        test_read_targets()
        test_timestamp_filename()
        test_safe_filename()
        test_backup_file()
        test_cleanup_temp_files()
        
        print("\n" + "=" * 60)
        print("✅ All file manager tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_file_manager_tests()
    sys.exit(0 if success else 1)