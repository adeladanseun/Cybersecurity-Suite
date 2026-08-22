# Quick Start Guide

This guide walks you through your first security assessment using CyberSecurity Suite, covering both the command-line tools and the web application.

## Prerequisites

Before starting, ensure you have completed the [Installation Guide](INSTALLATION.md). You should have the main project set up with Python virtual environment, the web app running with database migrations applied, and sudo configured for nmap. Verify everything is working by running `bash scripts/health_check.sh` from the main project directory and confirming it shows "All systems healthy." For the web app, make sure your Django server is running at `http://127.0.0.1:8000` by navigating to `cd web_viewer` and running `source venv/bin/activate` followed by `python manage.py runserver 127.0.0.1:8000`.

## Method 1: Quick CLI Scan

The fastest way to perform a scan is through the command line. First, create a target file. Navigate to your project directory and create a file called `data/targets/targets.txt` containing one target per line. Targets can be IP addresses like `192.168.1.10`, domain names like `example.com`, URLs like `https://testsite.com`, or network ranges like `192.168.1.0/24`. You can also add comments by starting lines with `#`.

Once your targets are ready, run the quick scan script with `bash scripts/quick_scan.sh -t data/targets/targets.txt`. This will perform a port scan on each target using the top 1000 common ports, save results as JSON in the `data/intermediate/` directory, and generate HTML and text reports in the `reports/` directory. The script will show progress as it runs and beep when complete if your system has audio support.

For a more thorough assessment, use the full audit script with `bash scripts/full_audit.sh -t data/targets/targets.txt`. This runs network discovery, full port scanning with service detection, vulnerability checking against the CVE database, and generates reports in multiple formats including HTML, CSV, TXT, and JSON. The full audit can take several minutes depending on the number of targets and network speed, but it provides comprehensive results suitable for security reporting.

## Method 2: Using the Python API

If you prefer working directly with Python, you can import and use the tools programmatically. Start by activating your virtual environment with `source .venv/bin/activate`. Then open a Python shell and import the port scanner with `from tools.port_scanner import PortScanner`. Create a scanner instance with `scanner = PortScanner()`, then run a quick scan on a target using `results = scanner.quick_scan("192.168.1.1")`. You can access the summary statistics through `results['summary']` which will show total hosts, open ports, and service counts. Each port's details are available in `results['ports']` with information about protocol, state, service name, product, and version.

For vulnerability checking, import the vulnerability checker with `from tools.vuln_checker import ServiceVulnChecker` and create an instance with `checker = ServiceVulnChecker()`. Pass your scan results to `checker.check_scan_results(results)` to identify known vulnerabilities. The CVE lookup works similarly with `from tools.vuln_checker import CVELookup` and `cve = CVELookup()` which loads the searchsploit database of over 44,000 entries.

## Method 3: Web Application

The web application provides a graphical interface for all scanning operations. Start by opening your browser and navigating to `http://127.0.0.1:8000`. If you haven't already, register an account by clicking the "Register" link and filling out the form. After registration or login, you will see the main dashboard displaying statistics about your targets, scans, vulnerabilities, and reports.

Your first step is to add a target. Click on "Targets" in the navigation bar, then click "New Target." Enter a friendly name for the target, the IP address or domain, select the target type (or leave it for auto-detection), set a priority level, and optionally add a description. Click "Save Target" and your target will appear in the list.

To run a scan, navigate to the "Scans" section and click "New Scan." Select your target from the dropdown, choose a scan type such as Port Scan or Vulnerability Scan, and optionally provide JSON parameters to customize the scan. For example, you can use `{"ports": "80,443,8080"}` to scan only those ports, or `{"ports": "1-1000"}` for a range, or `{"timing": "T4"}` to set the scan speed. Click "Start Scan" and you will be taken to the scan detail page showing the progress bar updating in real-time.

When the scan completes, you can view results by clicking "Results" in the navigation bar. Here you can see port results showing open ports with their services, vulnerability results listing identified CVEs with severity ratings, and generic scan results with summary data. You can filter results by severity, type, or search for specific entries. Export functionality is available through the "Export CSV" button for further analysis in spreadsheet applications.

To generate a report, navigate to "Reports" and click "Generate Report." Give your report a name, select the report type (Executive Summary, Technical Report, or Findings Report), choose the format (HTML, PDF, CSV, TXT, or JSON), and optionally link it to a specific scan. Click "Generate Report" and the report will be created in the background. Once completed, you can preview the report directly in the browser, download it for sharing, or export the report data as JSON.

The "Vulnerabilities" section allows you to manage findings from your scans. Each vulnerability shows its CVE ID, severity, affected service, and current status. You can filter vulnerabilities by severity, status, priority, or specific scan. Click on any vulnerability to view details, update its status from Open to In Progress to Resolved, add notes for collaboration, create remediation tasks with due dates, and assign the vulnerability to team members for follow-up.

## Understanding Scan Parameters

The web application accepts JSON parameters for customizing scans. The ports parameter accepts specific ports like `{"ports": "80,443"}` or ranges like `{"ports": "1-1000"}` or top ports like `{"ports": "top-1000"}`. The timing parameter controls scan speed and stealth using values T0 through T5, where T0 is the slowest and most stealthy while T5 is the fastest but more detectable. The service_detection parameter enables version detection when set to `true`, which helps identify exact software versions for vulnerability matching. The script_scan parameter runs Nmap Scripting Engine scripts for additional checks when set to `true`. The sudo parameter can be set to `false` to run scans without sudo, which uses TCP connect scanning instead of SYN scanning and does not require special permissions.

## Common Workflows

A typical quick assessment workflow starts with adding your targets in the web app, running a quick port scan to identify open ports, reviewing the results to determine which services are exposed, then running a vulnerability scan on the interesting targets. After vulnerability scanning completes, review the findings in the Vulnerabilities section, assign priorities and statuses, and generate an executive report for stakeholders.

For scheduled monitoring, use the Scheduled Scans feature to run scans automatically at regular intervals. Navigate to Scans, then Scheduled, and create a new scheduled scan by selecting the target, scan type, frequency (hourly, daily, weekly, monthly), and time. The system will automatically create and run scans according to the schedule, helping you track changes in your security posture over time.

The full audit workflow combines everything for a comprehensive assessment. From the command line, use the full audit script to run network discovery, complete port scanning, vulnerability checking, and report generation in one command. From the web app, run each scan type sequentially and then generate a combined report. This workflow is ideal for initial assessments of new systems or environments.

## Tips and Best Practices

Always verify that your scan targets are systems you are authorized to test. Keep your searchsploit database updated regularly with `searchsploit -u` to ensure your CVE matching has the latest vulnerability information. Use the appropriate scan type for your needs: quick scans for initial reconnaissance, service scans for version detection, and vulnerability scans for CVE matching. Configure sudo NOPASSWD for nmap before using the web app to avoid scans hanging at 25% progress. Use the vulnerability management features to track remediation efforts and demonstrate security improvements over time.

## Next Steps

Once you are comfortable with basic operations, explore the REST API by navigating to `/api/` endpoints for programmatic access to all features. Check the dashboard statistics page for visualizations of your scan data and vulnerability trends. Review the notification settings to configure email and in-app alerts for important events like scan completion and vulnerability detection. And most importantly, practice on deliberately vulnerable systems like Metasploitable to understand how the tools work in realistic scenarios.