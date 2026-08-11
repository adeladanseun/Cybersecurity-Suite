"""
Tests for core.database module
Run: python3 tests/test_database.py
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import Database
from core.exceptions import DatabaseError


def test_database_creation():
    """Test database initialization."""
    print("\n[*] Testing Database Creation...")
    
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        db.init_database()
        
        # Verify file was created
        assert os.path.exists(db_path)
        
        print("  ✓ Database creation passed")
        
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_insert_and_get_scan():
    """Test inserting and retrieving scan records."""
    print("\n[*] Testing Scan History...")
    
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        db.init_database()
        
        # Insert scan
        scan_id = db.insert_scan(
            target="192.168.1.1",
            tool_name="port_scanner",
            target_type="ipv4",
            status="completed"
        )
        
        assert scan_id > 0
        
        # Get scan history
        history = db.get_scan_history(target="192.168.1.1")
        assert len(history) > 0
        assert history[0]['target'] == "192.168.1.1"
        
        # Update scan status
        db.update_scan_status(scan_id, "completed", duration=45.5, findings_count=3)
        history = db.get_scan_history(target="192.168.1.1")
        assert history[0]['duration_seconds'] == 45.5
        assert history[0]['findings_count'] == 3
        
        print("  ✓ Scan history passed")
        
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_insert_and_get_findings():
    """Test findings operations."""
    print("\n[*] Testing Findings...")
    
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        db.init_database()
        
        # Insert scan first
        scan_id = db.insert_scan(
            target="example.com",
            tool_name="vuln_scanner",
            status="completed"
        )
        
        # Insert findings
        finding_id = db.insert_finding(
            scan_id=scan_id,
            target="example.com",
            finding_type="open_port",
            severity="medium",
            title="Port 22 Open",
            port=22,
            service="ssh"
        )
        
        assert finding_id > 0
        
        # Get findings
        findings = db.get_findings(scan_id=scan_id)
        assert len(findings) == 1
        assert findings[0]['severity'] == "medium"
        
        # Filter by severity
        findings = db.get_findings(severity="medium")
        assert len(findings) > 0
        
        print("  ✓ Findings operations passed")
        
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_knowledge_base():
    """Test knowledge base operations."""
    print("\n[*] Testing Knowledge Base...")
    
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        db.init_database()
        
        # Insert knowledge
        db.insert_knowledge(
            service_name="Apache",
            version_pattern="2.4.*",
            cve_id="CVE-2021-41773",
            severity="critical",
            description="Path traversal vulnerability",
            exploit_available=True
        )
        
        # Search knowledge base
        results = db.search_cve("Apache")
        assert len(results) > 0
        assert results[0]['cve_id'] == "CVE-2021-41773"
        
        print("  ✓ Knowledge base passed")
        
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_export():
    """Test database export functionality."""
    print("\n[*] Testing Database Export...")
    
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
        db_path = f.name
    
    try:
        db = Database(db_path)
        db.init_database()
        
        # Insert some data
        db.insert_knowledge(
            service_name="nginx",
            cve_id="CVE-2021-23017",
            severity="high"
        )
        
        # Export as JSON
        json_export = db.export_table("knowledge_base", format="json")
        assert "nginx" in json_export
        assert "CVE-2021-23017" in json_export
        
        print("  ✓ Database export passed")
        
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def run_all_database_tests():
    """Run all database tests."""
    print("=" * 60)
    print("DATABASE MODULE TESTS")
    print("=" * 60)
    
    try:
        test_database_creation()
        test_insert_and_get_scan()
        test_insert_and_get_findings()
        test_knowledge_base()
        test_export()
        
        print("\n" + "=" * 60)
        print("✅ All database tests passed!")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_database_tests()
    sys.exit(0 if success else 1)