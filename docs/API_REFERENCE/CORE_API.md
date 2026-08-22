# Core Module API Reference

This document provides detailed API reference for the core framework modules.

---

## FileManager

**Module:** `core.file_manager`

### Class: FileManager

Handles all file input/output operations.

#### Constructor

```python
FileManager(base_dir=None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_dir` | str | None | Base directory for file operations |

#### Methods

##### ensure_dir

```python
ensure_dir(dir_path) -> str
```

Creates directory if it doesn't exist.

| Parameter | Type | Description |
|-----------|------|-------------|
| `dir_path` | str | Directory path to create |

**Returns:** Created directory path

---

##### create_project_structure

```python
create_project_structure() -> None
```

Creates standard project directory structure (data/, reports/, logs/).

---

##### read_file

```python
read_file(filepath) -> str
```

Reads entire file content.

| Parameter | Type | Description |
|-----------|------|-------------|
| `filepath` | str | Path to file |

**Returns:** File contents as string

**Raises:** `FileManagerError`

---

##### read_lines

```python
read_lines(filepath, skip_empty=True, skip_comments=True) -> list
```

Reads file lines with filtering.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `filepath` | str | - | Path to file |
| `skip_empty` | bool | True | Skip empty lines |
| `skip_comments` | bool | True | Skip lines starting with # |

**Returns:** List of lines

---

##### read_targets

```python
read_targets(filepath) -> list
```

Reads target list and classifies each target.

**Returns:** List of dicts with `target` and `type` keys

---

##### read_json

```python
read_json(filepath) -> dict | list
```

Reads and parses JSON file.

**Raises:** `FileManagerError` on invalid JSON

---

##### read_csv

```python
read_csv(filepath, as_dict=True) -> list
```

Reads CSV file.

| Parameter | Type | Description |
|-----------|------|-------------|
| `as_dict` | bool | Return list of dicts (True) or list of lists (False) |

---

##### write_file

```python
write_file(filepath, content) -> None
```

Writes content to file.

---

##### write_json

```python
write_json(filepath, data, pretty=True) -> None
```

Writes data as JSON.

| Parameter | Type | Description |
|-----------|------|-------------|
| `pretty` | bool | Pretty-print with indent |

---

##### write_csv

```python
write_csv(filepath, data, headers=None, mode='w') -> None
```

Writes data as CSV.

---

##### append_csv

```python
append_csv(filepath, data, headers=None) -> None
```

Appends data to existing CSV.

---

##### file_exists

```python
file_exists(filepath) -> bool
```

Checks if file exists.

---

##### get_timestamp_filename

```python
get_timestamp_filename(prefix, extension) -> str
```

Generates timestamped filename.

**Example:** `get_timestamp_filename("scan", "json")` → `scan_20260820_123456.json`

---

##### safe_filename

```python
safe_filename(name) -> str
```

Converts string to safe filename.

---

##### backup_file

```python
backup_file(filepath) -> str
```

Creates backup of file.

**Returns:** Backup file path

---

##### cleanup_temp_files

```python
cleanup_temp_files(max_age_hours=24) -> int
```

Removes temp files older than specified hours.

**Returns:** Number of files cleaned

---

## Validator

**Module:** `core.validator`

### Functions

#### is_valid_ip

```python
is_valid_ip(ip) -> bool
```

Checks if string is valid IPv4 or IPv6.

```python
is_valid_ip("192.168.1.1")  # True
is_valid_ip("::1")          # True
is_valid_ip("invalid")      # False
```

---

#### is_valid_ipv4

```python
is_valid_ipv4(ip) -> bool
```

Checks if string is valid IPv4.

---

#### is_valid_ipv6

```python
is_valid_ipv6(ip) -> bool
```

Checks if string is valid IPv6.

---

#### is_private_ip

```python
is_private_ip(ip) -> bool
```

Checks if IP is private/internal.

```python
is_private_ip("192.168.1.1")  # True
is_private_ip("10.0.0.1")     # True
is_private_ip("8.8.8.8")      # False
```

---

#### is_public_ip

```python
is_public_ip(ip) -> bool
```

Checks if IP is public/external.

---

#### is_valid_cidr

```python
is_valid_cidr(cidr) -> bool
```

Checks if string is valid CIDR notation.

```python
is_valid_cidr("192.168.1.0/24")  # True
is_valid_cidr("invalid")          # False
```

---

#### is_valid_ip_range

```python
is_valid_ip_range(ip_range) -> bool
```

Checks if string is valid IP range.

```python
is_valid_ip_range("192.168.1.1-192.168.1.254")  # True
```

---

#### is_valid_domain

```python
is_valid_domain(domain) -> bool
```

Checks if string is valid domain name.

---

#### is_valid_url

```python
is_valid_url(url) -> bool
```

Checks if string is valid HTTP/HTTPS URL.

---

#### is_valid_hostname

```python
is_valid_hostname(hostname) -> bool
```

Checks if string is valid hostname (single label or FQDN).

---

#### is_valid_port

```python
is_valid_port(port) -> bool
```

Checks if port is valid (1-65535).

---

#### is_valid_port_range

```python
is_valid_port_range(port_range) -> bool
```

Checks if port range is valid.

```python
is_valid_port_range("80-443")     # True
is_valid_port_range("80,443")     # True
is_valid_port_range("443-80")     # False (start > end)
```

---

#### classify_target

```python
classify_target(target) -> str
```

Classifies target string.

**Returns:** 'ipv4', 'ipv6', 'cidr', 'domain', 'url', 'ip_range', 'hostname', or 'unknown'

```python
classify_target("192.168.1.1")       # 'ipv4'
classify_target("example.com")       # 'domain'
classify_target("https://test.com")  # 'url'
```

---

#### get_target_type

```python
get_target_type(target) -> dict
```

Detailed target classification.

**Returns:**
```python
{
    'type': 'ipv4',
    'is_internal': True,
    'is_external': False,
    'is_web_target': False,
    'is_network_target': True,
    'original': '192.168.1.1'
}
```

---

#### is_valid_file

```python
is_valid_file(filepath) -> bool
```

Checks if file exists and is readable.

---

#### is_valid_json

```python
is_valid_json(filepath) -> bool
```

Checks if file contains valid JSON.

---

## Config

**Module:** `core.config`

### Class: Config

Manages configuration with JSON storage.

#### Constructor

```python
Config(config_path=None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `config_path` | str | "config.json" | Path to config file |

#### Methods

##### get

```python
get(key, default=None) -> any
```

Gets value using dot notation.

```python
config.get("paths.data_dir")           # "./data"
config.get("scan_defaults.timing")     # "T4"
config.get("nonexistent", "fallback")  # "fallback"
```

---

##### set

```python
set(key, value) -> None
```

Sets value using dot notation.

```python
config.set("custom.key", "value")
config.set("scan_defaults.timeout", 600)
```

---

##### save

```python
save(config_path=None) -> None
```

Saves configuration to file.

---

##### get_all

```python
get_all() -> dict
```

Returns entire configuration.

---

##### reset_to_default

```python
reset_to_default() -> None
```

Resets to default configuration.

---

##### get_scan_profile

```python
get_scan_profile(profile_name) -> dict
```

Gets scan profile settings.

| Profile | Description |
|---------|-------------|
| 'quick' | Top 100 ports, T4, no service detection |
| 'full' | All ports, T3, service detection |
| 'stealth' | Top 1000, T2, no detection |

---

## Logger

**Module:** `core.logger`

### Functions

#### get_logger

```python
get_logger(name="cybersec") -> logging.Logger
```

Gets or creates logger instance.

```python
logger = get_logger("my_module")
logger.info("Message")
```

---

#### log_scan_start

```python
log_scan_start(logger, target, tool_name) -> None
```

Logs scan start.

---

#### log_scan_complete

```python
log_scan_complete(logger, target, tool_name, duration=None) -> None
```

Logs scan completion with optional duration.

---

#### log_finding

```python
log_finding(logger, target, finding_type, severity, details="") -> None
```

Logs a security finding.

---

#### log_error

```python
log_error(logger, target, error_message, traceback="") -> None
```

Logs an error.

---

## Notifier

**Module:** `core.notifier`

### Class: Notifier

Provides audio notifications.

#### Methods

##### beep

```python
beep(pattern='standard', times=1, silent=False) -> None
```

Plays beep pattern.

| Pattern | Description |
|---------|-------------|
| 'standard' | Two short beeps |
| 'major' | Three beeps ascending |
| 'error' | Three low beeps |
| 'complete' | Three ascending beeps |
| 'finding' | Three high beeps |
| 'progress' | Single short beep |

---

##### beep_major

```python
beep_major(silent=False) -> None
```

Beep for major milestones.

---

##### beep_complete

```python
beep_complete(silent=False) -> None
```

Beep for task completion.

---

##### beep_error

```python
beep_error(silent=False) -> None
```

Beep for errors.

---

##### beep_finding

```python
beep_finding(silent=False) -> None
```

Beep when vulnerability found.

---

##### beep_progress

```python
beep_progress(percentage, silent=False) -> None
```

Beep at 25%, 50%, 75%, 100%.

---

##### is_beep_available

```python
is_beep_available() -> bool
```

Checks if system has beep capability.

---

## Database

**Module:** `core.database`

### Class: Database

SQLite database manager.

#### Constructor

```python
Database(db_path=None)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `db_path` | str | None | Path to SQLite file |

#### Methods

##### init_database

```python
init_database() -> None
```

Initializes database schema.

---

##### insert_scan

```python
insert_scan(target, tool_name, target_type=None, status='pending', 
            output_file=None, summary=None, raw_data=None) -> int
```

Inserts scan record.

**Returns:** Scan ID

---

##### update_scan_status

```python
update_scan_status(scan_id, status, duration=None, findings_count=None) -> None
```

Updates scan status.

---

##### get_scan_history

```python
get_scan_history(target=None, limit=50) -> list
```

Gets scan history.

---

##### insert_finding

```python
insert_finding(scan_id, target, finding_type, severity, title,
               description=None, port=None, service=None, cve_id=None,
               cvss_score=None, remediation=None) -> int
```

Inserts security finding.

**Returns:** Finding ID

---

##### get_findings

```python
get_findings(scan_id=None, severity=None, limit=100) -> list
```

Gets findings with optional filters.

---

##### search_cve

```python
search_cve(service, version=None) -> list
```

Searches knowledge base for CVEs.

---

##### insert_knowledge

```python
insert_knowledge(service_name, version_pattern=None, cve_id=None,
                 severity=None, description=None, exploit_available=False,
                 remediation=None) -> int
```

Inserts knowledge base entry.

---

##### vacuum

```python
vacuum() -> None
```

Optimizes database.

---

##### export_table

```python
export_table(table_name, format='json') -> str
```

Exports table data.

| Format | Description |
|--------|-------------|
| 'json' | JSON string |
| 'csv' | CSV string |

---

## Exceptions

**Module:** `core.exceptions`

### Exception Classes

| Exception | Parent | Description |
|-----------|--------|-------------|
| `CyberSuiteError` | Exception | Base exception |
| `ValidationError` | CyberSuiteError | Input validation failed |
| `FileManagerError` | CyberSuiteError | File operation failed |
| `ScanError` | CyberSuiteError | Scan failed |
| `ConfigError` | CyberSuiteError | Configuration error |
| `DatabaseError` | CyberSuiteError | Database operation failed |
| `ToolNotFoundError` | CyberSuiteError | Required tool missing |

### Usage

```python
from core.exceptions import ScanError, ValidationError

try:
    scan(target)
except ValidationError as e:
    print(f"Invalid input: {e}")
except ScanError as e:
    print(f"Scan failed: {e}")
```

Each exception accepts optional `message`, `field`, `value`, `filepath`, `target`, `tool` parameters for context.