## Overview

The REST API provides programmatic access to all web application features. It's built with Django REST Framework.

**Base URL:** `http://127.0.0.1:8000/api/`

---

## Authentication

### Session Authentication

Works automatically when logged into the web app.

### Token Authentication

```bash
curl -H "Authorization: Token YOUR_TOKEN" http://127.0.0.1:8000/api/targets/
```

### Basic Authentication

```bash
curl -u username:password http://127.0.0.1:8000/api/targets/
```

---

## Common Response Format

### List Response

```json
[
    {
        "id": "uuid-string",
        "name": "Target Name",
        "created_at": "2026-08-20T12:00:00Z"
    }
]
```

### Detail Response

```json
{
    "id": "uuid-string",
    "name": "Target Name",
    "created_at": "2026-08-20T12:00:00Z"
}
```

### Error Response

```json
{
    "detail": "Error message"
}
```

---

## Endpoints

### Users

#### List Users

```
GET /api/users/
```

**Response:**
```json
[
    {
        "id": 1,
        "username": "admin",
        "email": "admin@test.com",
        "first_name": "Admin",
        "last_name": "User"
    }
]
```

#### Get User

```
GET /api/users/{id}/
```

---

### Targets

#### List Targets

```
GET /api/targets/
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `type` | Filter by type (ip, cidr, domain, url, hostname) |
| `priority` | Filter by priority (low, medium, high, critical) |
| `search` | Search by name or address |

**Response:**
```json
[
    {
        "id": "uuid-string",
        "name": "Web Server",
        "address": "192.168.1.10",
        "type": "ip",
        "description": "Main web server",
        "priority": "high",
        "is_active": true,
        "created_by": {
            "id": 1,
            "username": "admin"
        },
        "created_at": "2026-08-20T12:00:00Z",
        "last_scanned": null
    }
]
```

#### Create Target

```
POST /api/targets/
```

**Request Body:**
```json
{
    "name": "Web Server",
    "address": "192.168.1.10",
    "type": "ip",
    "priority": "high",
    "description": "Main web server"
}
```

#### Get Target

```
GET /api/targets/{id}/
```

#### Update Target

```
PUT /api/targets/{id}/
```

**Request Body:** Same as create

#### Delete Target

```
DELETE /api/targets/{id}/
```

---

### Target Groups

#### List Groups

```
GET /api/target-groups/
```

**Response:**
```json
[
    {
        "id": "uuid-string",
        "name": "Web Servers",
        "description": "All web servers",
        "targets": ["uuid-1", "uuid-2"],
        "targets_count": 2,
        "created_at": "2026-08-20T12:00:00Z"
    }
]
```

#### Create Group

```
POST /api/target-groups/
```

```json
{
    "name": "Web Servers",
    "description": "All web servers",
    "targets": ["uuid-1", "uuid-2"]
}
```

---

### Projects

#### List Projects

```
GET /api/projects/
```

**Response:**
```json
[
    {
        "id": "uuid-string",
        "name": "Security Assessment",
        "description": "Q3 Assessment",
        "status": "active",
        "start_date": "2026-08-01",
        "end_date": null,
        "targets_count": 5,
        "members_count": 3,
        "completion": 40,
        "created_at": "2026-08-20T12:00:00Z"
    }
]
```

#### Create Project

```
POST /api/projects/
```

```json
{
    "name": "Security Assessment",
    "description": "Q3 Assessment",
    "status": "active"
}
```

---

### Scans

#### List Scans

```
GET /api/scans/
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `status` | Filter by status (pending, running, completed, failed, cancelled) |
| `scan_type` | Filter by scan type |

**Response:**
```json
[
    {
        "id": "uuid-string",
        "target": "uuid-string",
        "target_name": "Web Server",
        "target_address": "192.168.1.10",
        "scan_type": "port_scan",
        "status": "completed",
        "progress": 100,
        "started_at": "2026-08-20T12:00:00Z",
        "completed_at": "2026-08-20T12:05:00Z",
        "duration": "00:05:00",
        "initiated_by": {
            "id": 1,
            "username": "admin"
        },
        "created_at": "2026-08-20T12:00:00Z"
    }
]
```

#### Create Scan

```
POST /api/scans/
```

**Request Body:**
```json
{
    "target": "uuid-string",
    "scan_type": "port_scan",
    "parameters": {
        "ports": "80,443",
        "timing": "T4"
    }
}
```

#### Get Scan

```
GET /api/scans/{id}/
```

---

### Scheduled Scans

#### List Scheduled Scans

```
GET /api/scheduled-scans/
```

**Response:**
```json
[
    {
        "id": "uuid-string",
        "target": "uuid-string",
        "target_name": "Web Server",
        "scan_type": "port_scan",
        "frequency": "daily",
        "schedule_time": "03:00:00",
        "is_active": true,
        "last_run": "2026-08-20T03:00:00Z",
        "next_run": "2026-08-21T03:00:00Z"
    }
]
```

#### Create Scheduled Scan

```
POST /api/scheduled-scans/
```

```json
{
    "target": "uuid-string",
    "scan_type": "port_scan",
    "frequency": "daily",
    "schedule_time": "03:00:00"
}
```

---

### Port Results

#### List Port Results

```
GET /api/port-results/
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `state` | Filter by state (open, filtered, closed) |
| `port` | Filter by port number |

**Response:**
```json
[
    {
        "id": "uuid-string",
        "scan": "uuid-string",
        "target_name": "Web Server",
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "product": "Apache",
        "version": "2.4.41",
        "created_at": "2026-08-20T12:05:00Z"
    }
]
```

---

### Vulnerabilities

#### List Vulnerabilities

```
GET /api/vulnerabilities/
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `severity` | Filter by severity (critical, high, medium, low, info) |
| `status` | Filter by status (open, in_progress, resolved, etc.) |
| `cve` | Filter by CVE ID |

**Response:**
```json
[
    {
        "id": "uuid-string",
        "cve_id": "CVE-2021-41773",
        "title": "Path Traversal in Apache",
        "description": "Path traversal vulnerability",
        "severity": "critical",
        "cvss_score": 9.8,
        "scan": "uuid-string",
        "target_name": "Web Server",
        "affected_service": "Apache",
        "port": 80,
        "status": "open",
        "priority": "P1",
        "remediation": "Upgrade to latest version",
        "assigned_to": "uuid-string",
        "assigned_to_username": "analyst1",
        "created_at": "2026-08-20T12:05:00Z",
        "updated_at": "2026-08-20T12:05:00Z",
        "resolved_at": null
    }
]
```

#### Create Vulnerability

```
POST /api/vulnerabilities/
```

```json
{
    "cve_id": "CVE-2021-41773",
    "title": "Path Traversal",
    "severity": "critical",
    "cvss_score": 9.8,
    "affected_service": "Apache",
    "port": 80
}
```

#### Update Vulnerability

```
PUT /api/vulnerabilities/{id}/
```

```json
{
    "status": "in_progress",
    "priority": "P1",
    "assigned_to": "user-uuid"
}
```

---

### Vulnerability Results

#### List Vulnerability Results

```
GET /api/vulnerability-results/
```

**Response:**
```json
[
    {
        "id": "uuid-string",
        "scan": "uuid-string",
        "cve_id": "CVE-2021-41773",
        "title": "Path Traversal",
        "severity": "critical",
        "cvss_score": 9.8,
        "affected_service": "Apache",
        "port": 80,
        "status": "open",
        "created_at": "2026-08-20T12:05:00Z"
    }
]
```

---

### Reports

#### List Reports

```
GET /api/reports/
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `report_type` | Filter by type (executive, technical, findings, full) |
| `format` | Filter by format (html, pdf, csv, txt, json) |

**Response:**
```json
[
    {
        "id": "uuid-string",
        "name": "Security Report",
        "description": "Quarterly assessment",
        "report_type": "executive",
        "format": "html",
        "scan": "uuid-string",
        "target_name": "Web Server",
        "status": "completed",
        "generated_by": {
            "id": 1,
            "username": "admin"
        },
        "generated_at": "2026-08-20T12:10:00Z",
        "download_count": 3,
        "file_size": 24576,
        "created_at": "2026-08-20T12:10:00Z"
    }
]
```

#### Create Report

```
POST /api/reports/
```

```json
{
    "name": "Security Report",
    "report_type": "executive",
    "format": "html",
    "scan": "uuid-string"
}
```

---

### Scan Results

#### List Scan Results

```
GET /api/scan-results/
```

**Response:**
```json
[
    {
        "id": "uuid-string",
        "scan": "uuid-string",
        "result_type": "info",
        "severity": "info",
        "data": {
            "summary": {
                "total_open_ports": 10
            }
        },
        "created_at": "2026-08-20T12:05:00Z"
    }
]
```

---

### Statistics

#### Get Statistics

```
GET /api/stats/
```

**Response:**
```json
{
    "targets": {
        "total": 10,
        "by_type": [
            {"type": "ip", "count": 6},
            {"type": "domain", "count": 4}
        ]
    },
    "scans": {
        "total": 25,
        "by_status": [
            {"status": "completed", "count": 20},
            {"status": "running", "count": 3},
            {"status": "failed", "count": 2}
        ],
        "running": 3
    },
    "vulnerabilities": {
        "total": 50,
        "by_severity": [
            {"severity": "critical", "count": 5},
            {"severity": "high", "count": 15},
            {"severity": "medium", "count": 20},
            {"severity": "low", "count": 10}
        ],
        "open": 30
    },
    "reports": {
        "total": 8,
        "by_format": [
            {"format": "html", "count": 4},
            {"format": "pdf", "count": 3},
            {"format": "csv", "count": 1}
        ]
    }
}
```

---

## Example Usage

### Python (requests)

```python
import requests

BASE_URL = "http://127.0.0.1:8000/api"

# Login
session = requests.Session()
session.post(
    f"{BASE_URL}/auth/login/",
    data={"username": "admin", "password": "password"}
)

# List targets
response = session.get(f"{BASE_URL}/targets/")
targets = response.json()

# Create target
response = session.post(
    f"{BASE_URL}/targets/",
    json={
        "name": "Test Server",
        "address": "192.168.1.100",
        "type": "ip"
    }
)

# Create scan
response = session.post(
    f"{BASE_URL}/scans/",
    json={
        "target": target_id,
        "scan_type": "port_scan",
        "parameters": {"ports": "80,443"}
    }
)

# Get statistics
stats = session.get(f"{BASE_URL}/stats/").json()
```

### cURL

```bash
# List targets
curl -H "Authorization: Token YOUR_TOKEN" \
     http://127.0.0.1:8000/api/targets/

# Create target
curl -X POST \
     -H "Authorization: Token YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name":"Test","address":"192.168.1.1","type":"ip"}' \
     http://127.0.0.1:8000/api/targets/

# Get statistics
curl -H "Authorization: Token YOUR_TOKEN" \
     http://127.0.0.1:8000/api/stats/
```

---

## Pagination

List endpoints support pagination using `?page=N`:

```bash
GET /api/targets/?page=2
```

---

## Filtering

Most list endpoints support filtering via query parameters:

```bash
# Filter targets by type
GET /api/targets/?type=ip

# Filter vulnerabilities by severity
GET /api/vulnerabilities/?severity=critical

# Search targets
GET /api/targets/?search=webserver
```

---

## Rate Limiting

No rate limiting is currently implemented. For production, consider adding Django REST Framework throttling.

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 204 | No content (delete) |
| 400 | Bad request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not found |
| 500 | Server error |