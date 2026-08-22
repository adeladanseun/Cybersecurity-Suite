## General

### Q: Is this tool legal to use?

**A:** Yes, for authorized security testing only. Always obtain written permission before testing any system you don't own. The tool is designed for security professionals and students to practice on authorized targets like Metasploitable.

---

### Q: What operating systems are supported?

**A:** Kali Linux is preferred, but any Debian-based system (Ubuntu, Debian) works. The project was tested on Ubuntu 22.04.

---

### Q: Do I need internet access?

**A:** No. The tools work offline using built-in databases and wordlists. Internet is only needed for initial setup and database updates.

---

### Q: Can I use this on Windows?

**A:** No. The project requires Linux-specific tools (nmap, bash, etc.) and is designed for Kali/Ubuntu.

---

## Installation

### Q: Why is searchsploit not in apt?

**A:** Searchsploit is a Kali-specific tool. On Ubuntu/Debian, install from source from GitLab.

---

### Q: Do I need to install all the databases?

**A:** No. The project works with built-in fallbacks. Large databases (SecLists, Wappalyzer) are optional enhancements.

---

### Q: How much disk space do I need?

**A:** Minimum 1GB for the project. Add 2-3GB if you download all optional databases.

---

## Scans

### Q: Why is my scan taking so long?

**A:** Full port scans (1-65535) can take 10+ minutes. Use quick scans (top-1000) for faster results.

---

### Q: Why are scans stuck at 25%?

**A:** This is almost always the sudo password issue. Configure NOPASSWD for nmap using visudo.

---

### Q: Can I scan multiple targets at once?

**A:** Yes, via CLI:
```python
scanner.scan_multiple(['192.168.1.1', '192.168.1.2'])
```
Or create multiple targets in the web app and run scans on each.

---

### Q: What's the difference between quick and full scan?
**A:** Quick scans check top 1000 common ports. Full scans check all 65535 ports with service detection.

---

## Web App
### Q: How do I access the web app from another device?
**A:** Run the server on 0.0.0.0:

```bash
python manage.py runserver 0.0.0.0:8000
```
Then access via http://your-computer-ip:8000

---

### Q: Why can't I preview PDF reports?
**A:** Install weasyprint:

```bash
pip install weasyprint
```

---

### Q: How do I create a new user?
**A:** Via registration page or command line:

```bash
python manage.py createsuperuser
```

---

### Q: Can I change my password?
**A:** Yes, through Profile → Change Password in the web app.

---

## Vulnerabilities
### Q: How are vulnerabilities detected?
**A:** Two methods:
- Built-in vulnerability database (common services)
- CVE lookup against searchsploit database (44,000+ entries)

---

### Q: What does "false positive" mean?
**A:** A vulnerability that doesn't actually exist on the target. Automated scanning can flag issues based on version numbers that may be patched or not exploitable.

---

### Q: How do I mark a vulnerability as false positive?
**A:** In the web app, open the vulnerability and change status to "False Positive."

---

Reports
### Q: What formats are supported?
**A:** HTML, PDF, CSV, TXT, and JSON.

---

### Q: Can I customize reports?
**A:** Yes, upload custom HTML templates in Reports → Templates.

---

### Q: Why is my PDF report showing HTML content?
**A:** weasyprint isn't installed. The system falls back to HTML but keeps the .pdf extension. Install weasyprint for proper PDFs.

---

## Databases
### Q: How often should I update the CVE database?
**A:** Monthly is recommended:

```bash
searchsploit -u
```

---

### Q: Can I add my own CVE data?
**A:** Yes, create data/databases/cve_database.json with your custom entries.

---

## Troubleshooting
### Q: Port scan finds 0 ports. Is it broken?
**A:** Check:
- Target is reachable (ping)
- Firewall isn't blocking
- Correct IP address
- Try scanning localhost to verify

---

### Q: Django tests fail with import errors?
**A:** Ensure you're in the web_viewer directory with venv activated:

```bash
cd web_viewer
source venv/bin/activate
python manage.py test
```

---

### Q: Web app is slow?
**A:** Check:
- Database size (run VACUUM)
- Number of results loading
- Network latency
- Server resources

---

## Development
### Q: How do I add a new tool?
**A:** See the Tool Development Guide in docs/DEVELOPER_GUIDE/TOOL_DEVELOPMENT.md.

---

### Q: Can I contribute to the project?
**A:** Yes! Fork the repository, make changes, run tests, and submit a pull request.

---

### Q: How do I run tests?
**A:**

```bash
# Main project
python3 tests/test_validator.py

# Web app
cd web_viewer
python manage.py test
```
## Support
### Q: Where do I report bugs?
**A:** Create an issue in the GitHub repository with:
- Bug description
- Steps to reproduce
- Expected vs actual result
- Environment details