"""
Database management for CyberSecurity Suite.
SQLite-based storage for scan history, findings, and knowledge base.
"""

import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from core.exceptions import DatabaseError


class Database:
    """SQLite database manager for the project."""

    def __init__(self, db_path=None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        if db_path is None:
            db_dir = os.path.join(os.getcwd(), "data", "databases")
            os.makedirs(db_dir, exist_ok=True)
            db_path = os.path.join(db_dir, "cybersec_suite.sqlite")

        self.db_path = db_path
        self.connection = None
        self.cursor = None

    def connect(self):
        """Establish database connection."""
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to connect to database: {e}")

    def disconnect(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None

    def init_database(self):
        """Initialize database schema."""
        self.connect()
        self.create_tables()
        self.disconnect()

    def create_tables(self):
        """Create all required database tables."""
        if not self.connection:
            raise DatabaseError("Database not connected")

        # Scan History Table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                target_type TEXT,
                tool_name TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending',
                duration_seconds REAL,
                output_file TEXT,
                findings_count INTEGER DEFAULT 0,
                summary TEXT,
                raw_data TEXT
            )
        """)

        # Findings Table
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                target TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                port INTEGER,
                service TEXT,
                cve_id TEXT,
                cvss_score REAL,
                remediation TEXT,
                found_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scan_history (id)
            )
        """)

        # Vulnerability Knowledge Base
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                version_pattern TEXT,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                exploit_available BOOLEAN DEFAULT 0,
                remediation TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Custom Wordlists
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS custom_wordlists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                word TEXT NOT NULL UNIQUE,
                source TEXT,
                frequency INTEGER DEFAULT 1,
                category TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create indexes
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_target 
            ON scan_history(target)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_date 
            ON scan_history(scan_date)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_severity 
            ON findings(severity)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_cve 
            ON findings(cve_id)
        """)

        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_knowledge_service 
            ON knowledge_base(service_name)
        """)

        self.connection.commit()

    # ========== Scan History Operations ==========

    def insert_scan(
        self,
        target,
        tool_name,
        target_type=None,
        status="pending",
        output_file=None,
        summary=None,
        raw_data=None,
    ):
        """
        Insert a new scan record.

        Args:
            target: Scan target
            tool_name: Name of tool used
            target_type: Type of target
            status: Scan status
            output_file: Path to output file
            summary: Scan summary text
            raw_data: Raw scan data (JSON string)

        Returns:
            int: Scan ID
        """
        try:
            self.connect()

            self.cursor.execute(
                """
                INSERT INTO scan_history 
                (target, target_type, tool_name, status, output_file, summary, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    target,
                    target_type,
                    tool_name,
                    status,
                    output_file,
                    summary,
                    raw_data,
                ),
            )

            self.connection.commit()
            scan_id = self.cursor.lastrowid

            self.disconnect()
            return scan_id

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to insert scan record: {e}")

    def update_scan_status(self, scan_id, status, duration=None, findings_count=None):
        """
        Update scan status.

        Args:
            scan_id: Scan ID to update
            status: New status
            duration: Scan duration in seconds
            findings_count: Number of findings
        """
        try:
            self.connect()

            query = "UPDATE scan_history SET status = ?"
            params = [status]

            if duration is not None:
                query += ", duration_seconds = ?"
                params.append(duration)

            if findings_count is not None:
                query += ", findings_count = ?"
                params.append(findings_count)

            query += " WHERE id = ?"
            params.append(scan_id)

            self.cursor.execute(query, params)
            self.connection.commit()
            self.disconnect()

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to update scan status: {e}")

    def get_scan_history(self, target=None, limit=50):
        """
        Get scan history records.

        Args:
            target: Filter by target (optional)
            limit: Maximum records to return

        Returns:
            list: List of scan history records
        """
        try:
            self.connect()

            if target:
                self.cursor.execute(
                    """
                    SELECT * FROM scan_history 
                    WHERE target = ? 
                    ORDER BY scan_date DESC 
                    LIMIT ?
                """,
                    (target, limit),
                )
            else:
                self.cursor.execute(
                    """
                    SELECT * FROM scan_history 
                    ORDER BY scan_date DESC 
                    LIMIT ?
                """,
                    (limit,),
                )

            results = [dict(row) for row in self.cursor.fetchall()]
            self.disconnect()
            return results

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get scan history: {e}")

    # ========== Findings Operations ==========

    def insert_finding(
        self,
        scan_id,
        target,
        finding_type,
        severity,
        title,
        description=None,
        port=None,
        service=None,
        cve_id=None,
        cvss_score=None,
        remediation=None,
    ):
        """
        Insert a security finding.

        Args:
            scan_id: Related scan ID
            target: Target identifier
            finding_type: Type of finding
            severity: Severity level
            title: Finding title
            description: Detailed description
            port: Port number
            service: Service name
            cve_id: CVE identifier
            cvss_score: CVSS score
            remediation: Remediation advice

        Returns:
            int: Finding ID
        """
        try:
            self.connect()

            self.cursor.execute(
                """
                INSERT INTO findings 
                (scan_id, target, finding_type, severity, title, description, 
                 port, service, cve_id, cvss_score, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    scan_id,
                    target,
                    finding_type,
                    severity,
                    title,
                    description,
                    port,
                    service,
                    cve_id,
                    cvss_score,
                    remediation,
                ),
            )

            self.connection.commit()
            finding_id = self.cursor.lastrowid
            self.disconnect()
            return finding_id

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to insert finding: {e}")

    def get_findings(self, scan_id=None, severity=None, limit=100):
        """
        Get findings with optional filters.

        Args:
            scan_id: Filter by scan ID
            severity: Filter by severity
            limit: Maximum records

        Returns:
            list: List of findings
        """
        try:
            self.connect()

            query = "SELECT * FROM findings WHERE 1=1"
            params = []

            if scan_id:
                query += " AND scan_id = ?"
                params.append(scan_id)

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            query += " ORDER BY found_date DESC LIMIT ?"
            params.append(limit)

            self.cursor.execute(query, params)
            results = [dict(row) for row in self.cursor.fetchall()]
            self.disconnect()
            return results

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to get findings: {e}")

    # ========== Knowledge Base Operations ==========

    def search_cve(self, service, version=None):
        """
        Search knowledge base for CVEs related to a service.

        Args:
            service: Service name
            version: Service version (optional)

        Returns:
            list: Matching CVE records
        """
        try:
            self.connect()

            if version:
                self.cursor.execute(
                    """
                    SELECT * FROM knowledge_base 
                    WHERE service_name = ? AND version_pattern = ?
                """,
                    (service, version),
                )
            else:
                self.cursor.execute(
                    """
                    SELECT * FROM knowledge_base 
                    WHERE service_name = ?
                """,
                    (service,),
                )

            results = [dict(row) for row in self.cursor.fetchall()]
            self.disconnect()
            return results

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to search knowledge base: {e}")

    def insert_knowledge(
        self,
        service_name,
        version_pattern=None,
        cve_id=None,
        severity=None,
        description=None,
        exploit_available=False,
        remediation=None,
    ):
        """
        Insert knowledge base entry.

        Args:
            service_name: Service/software name
            version_pattern: Version pattern
            cve_id: CVE identifier
            severity: Severity level
            description: Description
            exploit_available: Whether exploit is available
            remediation: Remediation advice

        Returns:
            int: Entry ID
        """
        try:
            self.connect()

            self.cursor.execute(
                """
                INSERT OR REPLACE INTO knowledge_base 
                (service_name, version_pattern, cve_id, severity, description, 
                 exploit_available, remediation)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    service_name,
                    version_pattern,
                    cve_id,
                    severity,
                    description,
                    exploit_available,
                    remediation,
                ),
            )

            self.connection.commit()
            entry_id = self.cursor.lastrowid
            self.disconnect()
            return entry_id

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to insert knowledge entry: {e}")

    # ========== Maintenance Operations ==========

    def vacuum(self):
        """Optimize database by vacuuming."""
        try:
            self.connect()
            self.cursor.execute("VACUUM")
            self.disconnect()
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to vacuum database: {e}")

    def export_table(self, table_name, format="json"):
        """
        Export a table to JSON or CSV format.

        Args:
            table_name: Name of table to export
            format: Export format ('json' or 'csv')

        Returns:
            str: Exported data as string
        """
        try:
            self.connect()

            self.cursor.execute(f"SELECT * FROM {table_name}")
            rows = [dict(row) for row in self.cursor.fetchall()]

            self.disconnect()

            if format == "json":
                return json.dumps(rows, indent=2, default=str)
            elif format == "csv":
                if not rows:
                    return ""

                import csv
                from io import StringIO

                output = StringIO()
                writer = csv.DictWriter(output, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
                return output.getvalue()
            else:
                raise DatabaseError(f"Unsupported export format: {format}")

        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to export table: {e}")
