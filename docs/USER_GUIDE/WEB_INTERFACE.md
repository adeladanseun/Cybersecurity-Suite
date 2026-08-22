# Web Interface Guide

This guide covers the complete usage of the CyberSecurity Suite Django web application.

---

## Overview

The web application provides a graphical interface for managing targets, executing scans, viewing results, generating reports, and tracking vulnerabilities. It runs on Django and includes a REST API for programmatic access.

**URL:** `http://127.0.0.1:8000`

---

## Getting Started

### Registration

1. Navigate to `http://127.0.0.1:8000`
2. Click "Register" link
3. Fill in username, email, first name, last name, and password
4. Click "Create Account"
5. You will be automatically logged in and redirected to the dashboard

### Login

1. Navigate to `http://127.0.0.1:8000`
2. Enter username and password
3. Click "Login"

### Profile Management

Navigate to Profile from the user dropdown in the top-right corner. Here you can:
- Update your name and email
- Change organization and job title
- Upload an avatar
- Configure email notifications
- Change your password

---

## Dashboard

The dashboard is the main landing page after login. It displays:

### Statistics Cards
- **Targets** — Total active targets
- **Scans** — Total scans run
- **Open Vulnerabilities** — Vulnerabilities needing attention
- **Total Vulnerabilities** — All vulnerabilities found
- **Reports** — Reports generated
- **Running Scans** — Currently active scans

### Recent Activity
Shows the latest scans, vulnerabilities, and reports with timestamps.

### Notifications
Displays unread notifications with links to the relevant pages.

### Weekly Stats
Shows scans and vulnerabilities from the current week.

---

## Target Management

### Creating a Target

1. Navigate to "Targets" in the navbar
2. Click "New Target"
3. Fill in:
   - **Name** — Friendly name (e.g., "Web Server 1")
   - **Address** — IP, domain, URL, or network range
   - **Type** — Auto-detected or select manually
   - **Priority** — Low, Medium, High, Critical
   - **Description** — Optional details
4. Click "Save Target"

### Importing Targets

1. Navigate to "Targets" → "Import"
2. Upload a file with one target per line
3. Optional: Set type, priority, and group name
4. Click "Import Targets"

### Supported formats:
- 192.168.1.1
- example.com
- https://test.com
- server-name.local
- #### CSV Format:
```text
Name,Address
Web Server,192.168.1.10
```

### Target Groups

Group targets for batch operations. Navigate to Targets and use the group functionality to organize targets by type, location, or project.

### Projects

Projects contain multiple targets and members for organized assessments. Track progress through the completion percentage shown on each project card.

---

## Scan Management

### Creating a Scan

1. Navigate to "Scans" in the navbar
2. Click "New Scan"
3. Select target from dropdown
4. Choose scan type
5. Optionally provide JSON parameters
6. Click "Start Scan"

### Scan Types

| Type | Description |
|------|-------------|
| Port Scan | Quick TCP scan of top 1000 ports |
| Full Port Scan | Complete scan of all 65535 ports |
| UDP Scan | UDP port scanning |
| Service Detection | Identifies service versions |
| DNS Enumeration | DNS record lookup |
| Subdomain Discovery | Finds subdomains |
| Reverse DNS Lookup | IP to hostname |
| Zone Transfer Test | Tests DNS zone transfer |
| Directory Brute Force | Web directory enumeration |
| Technology Fingerprint | Identifies web technologies |
| Web Vulnerability Scan | Checks for SQLi, XSS |
| Parameter Discovery | Finds hidden parameters |
| Vulnerability Scan | Matches CVEs against services |
| SSL/TLS Scan | SSL configuration audit |

### Scan Parameters (JSON)

```json
{"ports": "80,443,8080"}
{"ports": "1-1000"}
{"ports": "top-1000"}
{"timing": "T4"}
{"service_detection": true}
{"script_scan": true}
{"sudo": false}
{"wordlist": "/path/to/wordlist.txt"}
{"checks": ["sqli", "xss", "headers"]}
```
## Tracking Progress
On the scan detail page, a progress bar updates in real-time. The scan runs in a background thread, so you can navigate away and return later.

#### Scheduled Scans
- Navigate to "Scans" → "Scheduled"
- Click "Schedule Scan"
- Select target, scan type, frequency, and time
- Save

#### Supported frequencies:
- Once
- Hourly
- Daily
- Weekly
- Monthly

#### Scan Comparison
- Navigate to "Scans" → "Compare"
- Select two completed scans
- Click "Compare"

#### The comparison shows:
- New ports opened
- Ports closed
- Services changed
- Risk level assessment

## Results Viewing
#### Port Results
Navigate to "Results" → "Ports" to view all open ports from scans. Filter by state (open, filtered, closed) or search by service name.

Vulnerability Results
Navigate to "Results" → "Vulnerabilities" to see vulnerability findings. Each entry shows CVE ID, severity, affected service, and status.

#### Exporting Results
CSV Export — Download results as CSV for spreadsheet analysis

JSON Export — Raw data in JSON format

#### Report Generation
- Navigate to "Reports" in the navbar
- Click "Generate Report"

**Fill in**:
- Name — Report title
- Report Type — Executive, Technical, Findings, Full
- Format — HTML, PDF, CSV, TXT, JSON
- Scan — Optional scan to base report on
- Click "Generate Report"

#### Report Types
|Type |	Audience |	Content |
|--------|----------|----------|
|Executive |	Management |	High-level summary, key metrics |
|Technical |	IT Team |	Detailed port and service data |
|Findings |	Security Team |	Vulnerability listing |
|Full |	All |	Complete assessment |

#### Previewing Reports
HTML and PDF reports can be previewed directly in the browser. TXT reports show in an iframe with line breaks preserved.

#### Downloading Reports
Click "Download" on any completed report to save it locally.

#### Report Templates
Custom HTML templates can be uploaded for personalized report formatting. Navigate to "Reports" → "Templates" to manage templates.

## Vulnerability Management
#### Viewing Vulnerabilities
Navigate to "Vulnerabilities" in the navbar. The list shows:
- Severity (Critical, High, Medium, Low)
- CVE ID
- Title
- Target
- Affected service
- Priority (P1-P4)
- Status
- Assigned user

#### Filtering
Filter vulnerabilities by:
- Severity
- Status
- Priority
- Specific scan
- Search term

#### Updating Status
On a vulnerability detail page:

Select new status from dropdown

Options: Open, In Progress, Resolved, False Positive, Accepted Risk

Click "Update"

#### Adding Notes
On the vulnerability detail page, add notes to document investigation findings, communication with team members, or resolution steps.

#### Remediation Tasks
Create tasks to track remediation efforts:
- Enter task title and description
- Assign to a team member
- Set due date
- Track status (Pending, In Progress, Completed, Blocked)

#### Vulnerability Dashboard
Navigate to "Vulnerabilities" → "Dashboard" for:
- Severity distribution charts
- Priority breakdown
- Recent vulnerabilities
- Most affected services
- Monthly trends

#### CVE Search
Navigate to "Vulnerabilities" → "CVE Search" to search the 44,000+ entry CVE database.

Search by Service
Enter a service name like "apache", "vsftpd", or "mysql" to find related CVEs.

Search by CVE ID
Enter a specific CVE ID like "CVE-2021-41773" to get details.

#### Default Credential Check
Navigate to "Vulnerabilities" → "Cred Check" to test devices for known default credentials.

Enter target IP or hostname

Select device type (router, camera, printer, NAS, switch, firewall)

Click "Check"

Results show any default credentials found with username, password, service, and port.

## Notifications
#### Viewing Notifications
Click the bell icon in the navbar to view notifications. Unread notifications are highlighted.

#### Notification Types
- Scan Complete — When a scan finishes
- Scan Failed — When a scan errors
- Vulnerability Found — New critical/high vulnerability
- Report Ready — Report generation complete

#### Notification Settings
Navigate to Notifications → Settings to configure:

Email notifications (scan complete, vulnerability, report)

In-app notifications

Browser notifications

## REST API
The web app includes a full REST API at ```/api/``` endpoints.

#### Available Endpoints
| Endpoint	| Methods	| Description| 
|----------|-----------|-------------|
| /api/targets/	| GET, POST	| List/create targets| 
| /api/targets/{id}/	| GET, PUT, DELETE	| Target operations| 
| /api/scans/	| GET, POST	| List/create scans| 
| /api/vulnerabilities/	| GET, POST	| List/create vulnerabilities| 
| /api/reports/	| GET, POST	| List/create reports| 
| /api/stats/	| GET	| Overall statistics| 
#### API Usage
```bash
# List targets
curl -H "Authorization: Token YOUR_TOKEN" http://127.0.0.1:8000/api/targets/

# Create a target
curl -X POST \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","address":"192.168.1.1"}' \
  http://127.0.0.1:8000/api/targets/

# Get statistics
curl -H "Authorization: Token YOUR_TOKEN" http://127.0.0.1:8000/api/stats/
```

## Best Practices
- Use descriptive target names — Makes reports more readable
- Set priorities — Critical targets first
- Schedule regular scans — Track changes over time
- Document findings — Use notes and remediation tasks
- Review false positives — Automated scanning may flag non-issues
- Export data — Keep CSV backups of important results
- Use scan comparison — Track security posture changes
- Generate executive reports — Communicate findings to stakeholders

## Troubleshooting
#### Scans stuck at 25%
Configure sudo NOPASSWD for nmap:
```bash
sudo visudo
# Add: YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

#### Reports empty
Ensure results are saved to database. Check scan detail page for results file.

#### PDF preview not working
Install weasyprint:

```bash
pip install weasyprint
```

#### iframe preview blocked
```python
X_FRAME_OPTIONS = 'SAMEORIGIN'# in config/settings.py.
```
#### Notification badge shows 0
Refresh the page. The badge updates on page load via JavaScript.

#### Keyboard Shortcuts
| Shortcut	| Action| 
|----|---|
| /	| Focus search| 
| Esc	| Close modals| 

#### Mobile Access
The web app is responsive and works on mobile browsers. Access the same URL from your phone on the same network:

```text
http://[your-computer-ip]:8000
```

#### Logout
Click your username in the top-right corner, then select "Logout" from the dropdown menu.


