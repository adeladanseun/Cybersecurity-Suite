# Core Modules Guide

This document describes the core framework modules that all tools depend on.

---

## Overview

The `core/` directory contains foundation modules with **zero external dependencies**. They provide consistent behavior across all tools.

---

## Module: FileManager

**File:** `core/file_manager.py`

Handles all file read/write operations with proper error handling.

### Key Methods

```python
from core.file_manager import FileManager

fm = FileManager()

# Directory operations
fm.ensure_dir("data/results")
fm.create_project_structure()

# Read operations
content = fm.read_file("file.txt")
lines = fm.read_lines("targets.txt")
data = fm.read_json("results.json")
rows = fm.read_csv("data.csv")
targets = fm.read_targets("targets.txt")

# Write operations
fm.write_file("output.txt", "content")
fm.write_json("results.json", data)
fm.write_csv("data.csv", rows)

# Utilities
exists = fm.file_exists("file.txt")
filename = fm.get_timestamp_filename("scan", "json")
safe = fm.safe_filename("My File.txt")
backup = fm.backup_file("important.txt")
fm.cleanup_temp_files(24)
```

## Error Handling
Raises FileManagerError on failures. Always wrap in try-catch:

```python
from core.exceptions import FileManagerError

try:
    data = fm.read_json("results.json")
except FileManagerError as e:
    print(f"File error: {e}")
```
## Module: Validator
### File: core/validator.py

Validates user input and classifies targets.

Key Functions
```python
from core.validator import (
    is_valid_ip, is_valid_ipv4, is_valid_ipv6,
    is_private_ip, is_public_ip,
    is_valid_cidr, is_valid_ip_range,
    is_valid_domain, is_valid_url, is_valid_hostname,
    is_valid_port, is_valid_port_range,
    classify_target, get_target_type,
    is_valid_file, is_valid_json
)

# IP validation
is_valid_ip("192.168.1.1")       # True
is_private_ip("10.0.0.1")        # True
is_public_ip("8.8.8.8")          # True

# Domain validation
is_valid_domain("example.com")   # True
is_valid_url("https://test.com") # True

# Port validation
is_valid_port(80)                # True
is_valid_port_range("80-443")    # True

# Target classification
target_type = classify_target("example.com")  # 'domain'
target_info = get_target_type("192.168.1.1")  # {'type': 'ipv4', 'is_internal': True}
```

## Module: Logger
### File: core/logger.py

Provides consistent logging across all tools.

#### Usage
```python
from core.logger import get_logger, log_scan_start, log_scan_complete

logger = get_logger("my_tool")

logger.info("Starting operation")
logger.warning("Potential issue")
logger.error("Operation failed")
logger.debug("Debug information")

# Structured logging
log_scan_start(logger, "target.com", "port_scan")
log_scan_complete(logger, "target.com", "port_scan", duration=45.5)
```
## Module: Config
### File: core/config.py

Manages configuration with JSON file storage.

#### Usage
```python
from core.config import Config

config = Config()  # Loads or creates config.json

# Get values (dot notation)
data_dir = config.get("paths.data_dir")
timing = config.get("scan_defaults.timing")

# Set values
config.set("scan_defaults.timeout", 600)
config.save()

# Get scan profiles
quick_profile = config.get_scan_profile("quick")
full_profile = config.get_scan_profile("full")
```
## Module: Notifier
### File: core/notifier.py

Provides audio notifications for events.

#### Usage
```python
from core.notifier import Notifier

notifier = Notifier()

notifier.beep_complete()   # Task finished
notifier.beep_error()      # Error occurred
notifier.beep_finding()    # Vulnerability found
notifier.beep_progress(50) # Progress update
```
Supports patterns: standard, major, error, complete, finding, progress.

## Module: Database
### File: core/database.py

SQLite database for scan history, findings, and knowledge base.

#### Usage
```python
from core.database import Database

db = Database()  # Uses default path
db.init_database()

# Insert scan
scan_id = db.insert_scan(
    target="192.168.1.1",
    tool_name="port_scanner",
    status="completed"
)

# Insert finding
db.insert_finding(
    scan_id=scan_id,
    target="192.168.1.1",
    finding_type="open_port",
    severity="medium",
    title="Port 80 open"
)

# Query
history = db.get_scan_history(target="192.168.1.1")
findings = db.get_findings(scan_id=scan_id)
```

## Module: Exceptions
### File: core/exceptions.py

Custom exception hierarchy for consistent error handling.

Exception Types
```python
from core.exceptions import (
    CyberSuiteError,      # Base
    ValidationError,      # Input validation
    FileManagerError,     # File operations
    ScanError,           # Scan failures
    ConfigError,         # Configuration
    DatabaseError,       # Database operations
    ToolNotFoundError    # Missing tools
)
```
#### Usage
```python
try:
    scan(target)
except ValidationError as e:
    print(f"Invalid input: {e}")
except ScanError as e:
    print(f"Scan failed: {e}")
except CyberSuiteError as e:
    print(f"General error: {e}")
```
## Best Practices
- Always use FileManager — Don't use raw `open()` for project files
- Validate input — Use validator functions before processing
- Log consistently — Use `get_logger()` not `print()`
- Handle exceptions — Catch specific exceptions, not generic ones
- Use Config — Don't hardcode paths or settings
- Notify users — Use Notifier for important events