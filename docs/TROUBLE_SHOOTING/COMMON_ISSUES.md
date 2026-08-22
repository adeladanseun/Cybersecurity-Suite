## Installation Issues

### searchsploit not found

**Error:** `searchsploit: command not found`

**Cause:** Not installed or symlink missing

**Solution:**
```bash
sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
```
### Wappalyzer clone fails
**Error:** remote: Repository not found

**Cause:** Repository moved

**Solution:**

```bash
git clone --depth 1 https://github.com/enthec/webappanalyzer.git data/databases/wappalyzer
```
### "No directory at staticfiles"
**Error:** Warning: No directory at: /path/web_viewer/staticfiles/

Solution:

```bash
cd web_viewer
mkdir -p staticfiles
```

## Scan Issues
### Scans stuck at 25% progress
**Cause:** sudo password prompt hanging in background thread

**Solution:**

```bash
sudo visudo
# Add: YOUR_USERNAME ALL=(ALL) NOPASSWD: /usr/bin/nmap
```
### Scan fails with "Unknown timing mode"
**Error:** Unknown timing mode (-T argument)

**Cause:** nmap receives -T T4 instead of -T4

**Fix:** Use timing without space in parameters: {"timing": "T4"}

### Scan finds 0 ports
**Possible causes:**
- Target is down
- Firewall blocking scans
- Wrong port range specified
- Network connectivity issue

**Debug:**

```bash
# Test ping
ping -c 3 TARGET_IP

# Test nmap directly
nmap -p 80 TARGET_IP

# Check if target is Metasploitable
nmap -p 21,22,80,3306 TARGET_IP
```
### Scan results not saved to database
**Cause:** _process_results_to_db not called or failing

**Check:**

```bash
cd web_viewer
python manage.py shell -c "
from results.models import PortResult
print(PortResult.objects.count())
"
```
**Fix:** Ensure from django.conf import settings is imported in scans/services.py

## Report Issues
## Report is empty
**Cause:** Results not in database

**Check:**

```bash
python manage.py shell -c "
from results.models import PortResult, ScanResult
print(f'PortResults: {PortResult.objects.count()}')
print(f'ScanResults: {ScanResult.objects.count()}')
"
```
**Fix:** Run a new scan after fixing the results processing.

### PDF preview shows HTML content
**Cause:** weasyprint not installed

**Solution:**

```bash
pip install weasyprint
```
### iframe preview blocked
**Error:** Refused to display in a frame because it set 'X-Frame-Options' to 'deny'

**Solution:**
In config/settings.py:

```python
X_FRAME_OPTIONS = 'SAMEORIGIN'
```
### TXT preview shows raw bytes
**Cause:** Reading file as bytes not string

**Fix:** Use iframe for TXT preview instead of direct read.

## Django Issues
### "Module not found: config"
**Cause:** Running tests from wrong directory

**Solution:**

```bash
cd web_viewer
source venv/bin/activate
python manage.py test
```
### Model conflicts (Reverse accessor clashes)
**Error:** Reverse accessor for 'User.assigned_vulnerabilities' clashes

**Solution:** Change related_name in one model:

```python
related_name='assigned_result_vulnerabilities'
```
### Migration errors
**Solution:**

```bash
# Reset migrations
python manage.py migrate --fake app_name zero
python manage.py makemigrations
python manage.py migrate
```
## Database Issues
### SQLite database locked
**Cause:** Multiple processes accessing simultaneously

**Solution:**

```bash
# Kill stale processes
pkill -f "python manage.py"

# Check connections
lsof db.sqlite3
```
### Database file growing too large
**Solution:**

```bash
python manage.py shell -c "
from django.db import connection
connection.cursor().execute('VACUUM')
"
```
## Network Discovery Issues
### ARP scan requires root
**Error:** PermissionError

**Solution:**

```bash
sudo python3 tests/test_network_discovery.py
```
Or run as root:

```bash
sudo su
python3 tests/test_network_discovery.py
```
### No network interfaces found
**Cause:** netifaces not installed

**Solution:**

```bash
pip install netifaces
```
## CVE Database Issues
### Searchsploit loads 0 entries
**Cause:** Wrong CSV filename or column names

**Check:**

```bash
ls /opt/exploitdb/files_exploits.csv
head -1 /opt/exploitdb/files_exploits.csv
```
**Expected columns:** codes, description (lowercase)

**Fix:** Update _load_searchsploit to use lowercase column names.

### CVE search returns 0 results
**Cause:** Search method not matching

**Test:**

```python
from tools.vuln_checker import CVELookup
cve = CVELookup()
print(f"Loaded: {len(cve.cve_database)}")
print(cve.search_by_service('apache')[:3])
```
## Notification Issues
### Badge shows 0 with unread notifications
**Cause:** JavaScript not fetching count

**Check:** Open browser console for errors

**Fix:** Ensure /notifications/unread-count/ URL exists and requires login.

### Email notifications not sending (not yet configured)
**Cause:** SMTP not configured

**Solution:** Configure in settings.py:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your@email.com'
EMAIL_HOST_PASSWORD = 'password'
```
## Performance Issues
### Slow scans
**Causes:**
- Full port scan (1-65535) takes time
- Slow network
- Target has firewall

**Solutions:**
- Use quick scan for initial
- Reduce port range
- Increase timing (T5)
### Slow web pages
**Causes:**
- Too many database queries
- Large result sets

**Solutions:**
- Add pagination
- Use select_related
- Add database indexes