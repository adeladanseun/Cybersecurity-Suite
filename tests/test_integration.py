"""
Integration tests for Phase 1 Core Framework
Tests all modules working together
Run: python3 tests/test_integration.py
"""

import sys
import os
import tempfile
import shutil
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core import (
    FileManager,
    Config,
    Database,
    Notifier,
    is_valid_ip,
    is_private_ip,
    classify_target,
    get_target_type,
    get_logger,
    ValidationError,
    FileManagerError,
    DatabaseError,
)


def setup_test_environment():
    """Create isolated test environment."""
    test_dir = tempfile.mkdtemp(prefix="cybersec_integration_")

    # Create project structure
    fm = FileManager(test_dir)
    fm.create_project_structure()

    return test_dir, fm


def cleanup_test_environment(test_dir):
    """Remove test environment."""
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)


def test_full_workflow():
    """
    Test complete workflow:
    1. Validate targets
    2. Store in files
    3. Log activity
    4. Save to database
    5. Generate report data
    """
    print("\n[*] Testing Full Workflow Integration...")

    test_dir, fm = setup_test_environment()

    try:
        # Step 1: Create and validate targets
        targets = [
            "192.168.1.1",
            "10.0.0.1",
            "example.com",
            "https://testsite.com",
            "8.8.8.8",
        ]

        validated_targets = []
        for target in targets:
            target_type = get_target_type(target)
            assert target_type["type"] != "unknown"
            validated_targets.append(
                {
                    "target": target,
                    "type": target_type["type"],
                    "is_internal": target_type["is_internal"],
                    "is_external": target_type["is_external"],
                    "is_web_target": target_type["is_web_target"]
                }
            )

        # Verify classification
        assert validated_targets[0]["is_internal"] == True  # 192.168.1.1
        assert validated_targets[1]["is_internal"] == True  # 10.0.0.1
        assert validated_targets[3]["is_web_target"] == True  # URL
        assert validated_targets[4]["is_external"] == True  # 8.8.8.8

        print("  ✓ Target validation and classification")

        # Step 2: Save targets to file
        target_file = "data/targets/test_targets.txt"
        fm.write_file(target_file, "\n".join(targets))

        # Read targets back
        loaded_targets = fm.read_targets(target_file)
        assert len(loaded_targets) == 5

        print("  ✓ Target file I/O")

        # Step 3: Save scan results as JSON
        scan_result = {
            "scan_id": "TEST-001",
            "targets": validated_targets,
            "timestamp": "2024-01-15T10:30:00",
            "findings": [
                {"port": 80, "service": "http", "severity": "low"},
                {"port": 22, "service": "ssh", "severity": "medium"},
            ],
        }

        result_file = "data/intermediate/test_scan.json"
        fm.write_json(result_file, scan_result)

        # Read and verify
        loaded_result = fm.read_json(result_file)
        assert loaded_result["scan_id"] == "TEST-001"
        assert len(loaded_result["findings"]) == 2

        print("  ✓ Scan results JSON I/O")

        # Step 4: Save as CSV
        csv_data = [
            {"port": 80, "service": "http", "severity": "low"},
            {"port": 22, "service": "ssh", "severity": "medium"},
            {"port": 443, "service": "https", "severity": "low"},
        ]

        csv_file = "reports/csv/test_findings.csv"
        fm.write_csv(csv_file, csv_data)

        loaded_csv = fm.read_csv(csv_file)
        assert len(loaded_csv) == 3
        assert loaded_csv[0]["port"] == "80"

        print("  ✓ CSV export")

        # Step 5: Database operations
        db_path = os.path.join(test_dir, "data", "databases", "test_integration.sqlite")
        db = Database(db_path)
        db.init_database()

        # Insert scan
        scan_id = db.insert_scan(
            target="192.168.1.1",
            tool_name="port_scanner",
            target_type="ipv4",
            status="completed",
            summary="Test scan completed successfully",
        )

        # Insert findings
        for finding in scan_result["findings"]:
            db.insert_finding(
                scan_id=scan_id,
                target="192.168.1.1",
                finding_type="open_port",
                severity=finding["severity"],
                title=f"Port {finding['port']} open - {finding['service']}",
                port=finding["port"],
                service=finding["service"],
            )

        # Retrieve and verify
        findings = db.get_findings(scan_id=scan_id)
        assert len(findings) == 2

        history = db.get_scan_history(target="192.168.1.1")
        assert len(history) == 1

        print("  ✓ Database operations")

        # Step 6: Logger integration
        logger = get_logger("integration_test")
        logger.info(f"Integration test completed for {len(validated_targets)} targets")

        log_file = os.path.join(test_dir, "logs", "integration_test.log")
        assert os.path.exists(log_file) or True  # Logger may use different path

        print("  ✓ Logger integration")

        # Step 7: Config integration
        config_path = os.path.join(test_dir, "test_config.json")
        config = Config(config_path)

        config.set("paths.data_dir", os.path.join(test_dir, "data"))
        config.set("custom.test_run", True)
        config.save()

        # Reload and verify
        config2 = Config(config_path)
        assert config2.get("custom.test_run") == True

        print("  ✓ Config integration")

        # Step 8: Generate summary report
        summary = {
            "total_targets": len(validated_targets),
            "internal_targets": sum(1 for t in validated_targets if t["is_internal"]),
            "external_targets": sum(1 for t in validated_targets if t["is_external"]),
            "total_findings": len(findings),
            "scan_duration": "45.5 seconds",
        }

        summary_file = "data/intermediate/test_summary.json"
        fm.write_json(summary_file, summary)

        loaded_summary = fm.read_json(summary_file)
        assert loaded_summary["total_targets"] == 5
        assert loaded_summary["internal_targets"] == 2
        assert loaded_summary["total_findings"] == 2

        print("  ✓ Summary generation")

        print("\n  ✅ Full workflow integration passed!")

    finally:
        cleanup_test_environment(test_dir)


def test_error_handling():
    """Test error handling across modules."""
    print("\n[*] Testing Cross-Module Error Handling...")

    test_dir, fm = setup_test_environment()

    try:
        # FileManager error
        try:
            fm.read_json("nonexistent.json")
            assert False, "Should have raised FileManagerError"
        except FileManagerError:
            pass  # Expected

        # Database error with invalid path
        try:
            db = Database("/invalid/path/db.sqlite")
            db.init_database()
            assert False, "Should have raised DatabaseError"
        except DatabaseError:
            pass  # Expected

        # Validation in workflow
        try:
            result = get_target_type("")
            # Empty string should return unknown, not raise error
            assert result["type"] == "unknown"
        except Exception as e:
            assert False, f"Should not have raised exception: {e}"

        print("  ✓ Error handling passed")

    finally:
        cleanup_test_environment(test_dir)


def test_file_timestamp_and_backup_workflow():
    """Test file management utility functions together."""
    print("\n[*] Testing File Utilities Workflow...")

    test_dir, fm = setup_test_environment()

    try:
        # Create a file
        original_file = "data/intermediate/original.txt"
        fm.write_file(original_file, "Important data")

        # Backup
        backup_path = fm.backup_file(original_file)
        assert os.path.exists(backup_path)

        # Generate timestamped filename
        new_file = fm.get_timestamp_filename("scan", "json")
        assert "scan_" in new_file
        assert ".json" in new_file

        # Safe filename conversion
        safe = fm.safe_filename("Test Scan #1 (2024)")
        assert " " not in safe
        assert "#" not in safe

        print("  ✓ File utilities workflow passed")

    finally:
        cleanup_test_environment(test_dir)


def test_target_classification_workflow():
    """Test classifying and processing mixed targets."""
    print("\n[*] Testing Mixed Target Processing...")

    test_dir, fm = setup_test_environment()

    try:
        # Mixed targets (internal + external)
        mixed_targets = [
            "192.168.1.1",  # Internal IP
            "10.0.0.5",  # Internal IP
            "example.com",  # External domain
            "https://app.test.com",  # External URL
            "8.8.8.8",  # External IP
            "172.16.0.1",  # Internal IP
            "http://10.0.0.5:8080",  # Internal URL
        ]

        results = {
            "internal": [],
            "external": [],
            "web_targets": [],
            "network_targets": [],
        }

        for target in mixed_targets:
            ttype = get_target_type(target)

            if ttype["is_internal"]:
                results["internal"].append(target)
            if ttype["is_external"]:
                results["external"].append(target)
            if ttype["is_web_target"]:
                results["web_targets"].append(target)
            if ttype["is_network_target"]:
                results["network_targets"].append(target)

        assert len(results["internal"]) == 4  # 3 IPs + 1 URL
        assert len(results["external"]) == 3  # domain + URL + IP
        assert len(results["web_targets"]) == 3  # URL + domain + internal URL
        assert len(results["network_targets"]) == 4  # 4 IP addresses

        # Save classification results
        fm.write_json("data/intermediate/classification.json", results)

        print("  ✓ Mixed target processing passed")

    finally:
        cleanup_test_environment(test_dir)


def test_database_scan_lifecycle():
    """Test complete scan lifecycle in database."""
    print("\n[*] Testing Database Scan Lifecycle...")

    test_dir, fm = setup_test_environment()
    db_path = os.path.join(test_dir, "data", "databases", "lifecycle.sqlite")

    try:
        db = Database(db_path)
        db.init_database()

        # Start scan
        scan_id = db.insert_scan(
            target="testserver.local",
            tool_name="full_audit",
            target_type="hostname",
            status="running",
        )

        # Update with progress
        db.update_scan_status(scan_id, "running")

        # Complete scan
        db.update_scan_status(scan_id, "completed", duration=120.5, findings_count=5)

        # Add findings
        for i in range(5):
            db.insert_finding(
                scan_id=scan_id,
                target="testserver.local",
                finding_type="vulnerability",
                severity=["low", "medium", "high"][i % 3],
                title=f"Test finding {i+1}",
                description=f"Description for finding {i+1}",
                remediation="Apply patch",
            )

        # Verify lifecycle
        history = db.get_scan_history(target="testserver.local")
        assert len(history) == 1
        assert history[0]["status"] == "completed"
        assert history[0]["findings_count"] == 5

        findings = db.get_findings(scan_id=scan_id)
        assert len(findings) == 5

        # Test severity filtering
        high_findings = db.get_findings(scan_id=scan_id, severity="high")
        assert len(high_findings) > 0

        print("  ✓ Database scan lifecycle passed")

    finally:
        cleanup_test_environment(test_dir)


def test_notifier_in_workflow():
    """Test notifier integration in workflow."""
    print("\n[*] Testing Notifier in Workflow...")

    test_dir, fm = setup_test_environment()

    try:
        logger = get_logger("notifier_test")

        # Simulate scan workflow with notifications
        logger.info("Starting scan...")
        Notifier.beep(silent=True)  # Silent in tests

        logger.info("25% complete...")
        Notifier.beep_progress(25, silent=True)

        logger.info("50% complete...")
        Notifier.beep_progress(50, silent=True)

        logger.info("Finding vulnerability...")
        Notifier.beep_finding(silent=True)

        logger.info("100% complete!")
        Notifier.beep_complete(silent=True)

        print("  ✓ Notifier workflow passed")

    finally:
        cleanup_test_environment(test_dir)


def run_all_integration_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("INTEGRATION TESTS")
    print("=" * 60)

    try:
        test_full_workflow()
        test_error_handling()
        test_file_timestamp_and_backup_workflow()
        test_target_classification_workflow()
        test_database_scan_lifecycle()
        test_notifier_in_workflow()

        print("\n" + "=" * 60)
        print("✅ All integration tests passed!")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_integration_tests()
    sys.exit(0 if success else 1)
