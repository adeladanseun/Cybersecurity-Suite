# Architecture Guide

This document describes the system architecture of CyberSecurity Suite.

---

## System Overview

CyberSecurity Suite is a modular security assessment platform consisting of:

1. **Core Framework** — Foundation library for file I/O, validation, logging, config, database
2. **CLI Tools** — 8 standalone tools for various security tasks
3. **Bash Scripts** — Automation and orchestration scripts
4. **Django Web App** — Web interface for all features
5. **REST API** — Programmatic access to web app

---

## Directory Structure
```
cybersec-suite/
├── core/ # Core framework (no external deps)
│ ├── init.py
│ ├── exceptions.py # Custom exception classes
│ ├── validator.py # Input validation
│ ├── logger.py # Logging system
│ ├── config.py # Configuration management
│ ├── notifier.py # Audio notifications
│ ├── file_manager.py # File I/O operations
│ └── database.py # SQLite database management
│
├── tools/ # Standalone CLI tools
│ ├── port_scanner/ # Nmap wrapper
│ ├── dns_enum/ # DNS enumeration
│ ├── network_discovery/ # Host discovery
│ ├── web_enum/ # Web enumeration
│ ├── vuln_checker/ # Vulnerability checking
│ ├── exploitation/ # Credential testing
│ └── report_builder/ # Report generation
│
├── scripts/ # Bash automation
│ ├── setup.sh # Installation
│ ├── quick_scan.sh # Quick workflow
│ ├── full_audit.sh # Full audit workflow
│ ├── health_check.sh # System verification
│ └── utils.sh # Shared functions
│
├── web_viewer/ # Django application
│ ├── config/ # Django settings
│ ├── accounts/ # User management
│ ├── targets/ # Target CRUD
│ ├── scans/ # Scan orchestration
│ ├── results/ # Results storage
│ ├── reports/ # Report generation
│ ├── vulnerabilities/ # Vuln management
│ ├── notifications/ # User notifications
│ ├── dashboard/ # Dashboard views
│ └── api/ # REST API
│
├── data/ # Runtime data
├── reports/ # Generated reports
├── tests/ # Test suite
└── suite.sh # Main entry point
```
---

## Data Flow
```
User Input (CLI or Web)
↓
Target Selection
↓
Scan Execution
↓
Results (JSON files)
↓
Database Storage (SQLite)
↓
Processing & Analysis
↓
Report Generation
↓
Output (HTML/PDF/CSV/TXT/JSON)
```

---

## Component Interactions

### CLI Tools Flow
```
CLI Script → Tool Class → Core Framework → System Tools (nmap, etc.)
↓
Results (JSON)
```

### Web App Flow
```
Browser → Django View → ScanService (background thread)
↓
Tool Class → Core Framework
↓
Results → File + Database
↓
Web Display → Reports
```

### Database Schema (SQLite)
```text
targets/
- Target
- TargetGroup
- Project

scans/
- Scan
- ScheduledScan

results/
- ScanResult
- PortResult
- VulnerabilityResult

reports/
- Report
- ReportTemplate

vulnerabilities/
- Vulnerability
- RemediationTask
- VulnerabilityNote

notifications/
- Notification
- NotificationPreference

accounts/
- User (Django built-in)
- UserProfile
```

---

## Key Design Decisions

### 1. UUID Primary Keys

All models use UUID fields instead of auto-incrementing integers:

```python
id = models.UUIDField(
    primary_key=True,
    default=uuid.uuid4,
    editable=False
)
```
Benefits:
- No enumeration attacks
- Safe for distributed systems
- Can generate client-side

### 2. File-Based Results
Scan results are saved as JSON files first, then processed into database. This provides:
- Raw data preservation
- Easy debugging
- Manual inspection ability
- Backup capability

### 3. Background Thread Execution
Scans run in background threads (not Celery tasks) for simplicity:
```python
thread = threading.Thread(
    target=cls._run_scan,
    args=(scan.id,),
    daemon=True
)
thread.start()
```
##### Trade-off: No task queue, but simpler setup.

### 4. Progressive Enhancement
The web app uses Django templates with Bootstrap 5, enhanced with:
- HTMX for AJAX
- Alpine.js for interactivity
- Chart.js for visualizations
- Vanilla JS for simple operations

### 5. Offline-First Design
Tools work without internet using:
- Built-in vulnerability patterns
- Local CVE database (searchsploit)
- Fallback wordlists
- Graceful degradation

## Security Architecture
### Authentication
- Django session-based auth
- Password validation
- CSRF protection
- Login required for all views

### Authorization
- User ownership checks
- Role-based access (admin, analyst, viewer)
- Object-level permissions

### Data Protection
- Sensitive files gitignored
- Reports stored locally
- No external API calls
- Local-only by default

## Scalability Considerations
### Current Limitations
- SQLite database (single user focus)
- Background threads (no task queue)
- Local file storage
- Single server deployment

### Future Improvements
- PostgreSQL for production
- Celery for task queue
- Redis for caching
- S3 for file storage
- Docker containerization
- Load balancing

### Extension Points
#### Adding New Tools
- Create directory in tools/
- Follow tool pattern (init, scanner, parser)
- Register in web app scan types
- Add tests

#### Adding New Web Features
- Create Django app or extend existing
- Add models (UUID keys)
- Add views (LoginRequired)
- Add templates (Bootstrap 5)
- Register URLs
- Add tests