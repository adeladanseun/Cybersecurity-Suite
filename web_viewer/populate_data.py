import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
import django
django.setup()

from django.contrib.auth.models import User
from targets.models import Target, TargetGroup, Project
from scans.models import Scan, ScheduledScan
from results.models import ScanResult, PortResult, VulnerabilityResult
from reports.models import Report, ReportTemplate
from vulnerabilities.models import Vulnerability, RemediationTask, VulnerabilityNote
from notifications.models import Notification, NotificationPreference
from django.utils import timezone
from datetime import timedelta

# Create users
users_data = [
    ('admin', 'admin@test.com', 'AdminPass123!', True),
    ('analyst1', 'analyst1@test.com', 'AnalystPass123!', False),
    ('analyst2', 'analyst2@test.com', 'AnalystPass123!', False),
    ('viewer1', 'viewer1@test.com', 'ViewerPass123!', False),
]

users = {}
for username, email, password, is_staff in users_data:
    user, created = User.objects.get_or_create(username=username)
    if created:
        user.email = email
        user.set_password(password)
        user.is_staff = is_staff
        user.save()
    users[username] = user
    print(f"User created: {username}")

# Create targets
targets_data = [
    ('Web Server 1', '192.168.1.10', 'ip', 'Main web server', 'high'),
    ('Web Server 2', '192.168.1.20', 'ip', 'Backup web server', 'medium'),
    ('Database Server', '192.168.1.30', 'ip', 'MySQL database', 'critical'),
    ('Mail Server', 'mail.example.com', 'domain', 'Email server', 'high'),
    ('Test Website', 'https://test.example.com', 'url', 'Testing site', 'low'),
    ('Internal Network', '10.0.0.0/24', 'cidr', 'Internal network range', 'medium'),
]

targets = {}
for name, address, ttype, desc, priority in targets_data:
    target, created = Target.objects.get_or_create(
        name=name,
        address=address,
        defaults={
            'type': ttype,
            'description': desc,
            'priority': priority,
            'created_by': users['admin'],
            'last_scanned': timezone.now() - timedelta(days=1),
        }
    )
    targets[name] = target
    print(f"Target created: {name}")

# Create target group
group, created = TargetGroup.objects.get_or_create(
    name='Web Servers',
    defaults={'created_by': users['admin'], 'description': 'All web servers'}
)
group.targets.add(targets['Web Server 1'], targets['Web Server 2'])
print(f"Target group created: {group.name}")

# Create project
project, created = Project.objects.get_or_create(
    name='Security Assessment Q1',
    defaults={
        'description': 'First quarter security assessment',
        'status': 'active',
        'created_by': users['admin'],
        'start_date': timezone.now().date(),
    }
)
project.targets.add(targets['Web Server 1'], targets['Web Server 2'], targets['Database Server'])
project.members.add(users['admin'], users['analyst1'])
print(f"Project created: {project.name}")

# Create scans
scan_types = ['port_scan', 'full_port_scan', 'service_scan', 'vuln_scan']
scan_statuses = ['completed', 'completed', 'running', 'completed']

scans = []
for i, (scan_type, status) in enumerate(zip(scan_types, scan_statuses)):
    target = list(targets.values())[i % len(targets)]
    scan = Scan.objects.create(
        target=target,
        scan_type=scan_type,
        status=status,
        progress=100 if status == 'completed' else 45,
        started_at=timezone.now() - timedelta(hours=i+1),
        completed_at=timezone.now() - timedelta(hours=i) if status == 'completed' else None,
        initiated_by=users['analyst1'],
    )
    scans.append(scan)
    print(f"Scan created: {scan_type} on {target.name} ({status})")

# Create port results
for scan in scans[:2]:
    ports_data = [
        (22, 'tcp', 'open', 'ssh', 'OpenSSH', '8.2'),
        (80, 'tcp', 'open', 'http', 'Apache', '2.4.41'),
        (443, 'tcp', 'open', 'https', 'Apache', '2.4.41'),
        (3306, 'tcp', 'open', 'mysql', 'MySQL', '5.7'),
    ]
    for port, proto, state, service, product, version in ports_data:
        PortResult.objects.get_or_create(
            scan=scan,
            port=port,
            protocol=proto,
            defaults={
                'state': state,
                'service': service,
                'product': product,
                'version': version,
            }
        )
    print(f"Port results created for scan {scan.scan_type}")

# Create vulnerabilities
vulns_data = [
    ('CVE-2021-41773', 'Path Traversal in Apache', 'critical', 9.8, 'Apache', 80, 'open', 'P1'),
    ('CVE-2021-23017', 'DNS resolver vulnerability in nginx', 'high', 7.5, 'nginx', 80, 'open', 'P2'),
    ('CVE-2020-15778', 'Command injection in OpenSSH scp', 'high', 7.0, 'OpenSSH', 22, 'in_progress', 'P2'),
    ('CVE-2019-6111', 'SCP client validation issue', 'medium', 5.5, 'OpenSSH', 22, 'resolved', 'P3'),
]

for cve, title, severity, cvss, service, port, status, priority in vulns_data:
    vuln = Vulnerability.objects.create(
        cve_id=cve,
        title=title,
        description=f'Test vulnerability: {title}',
        severity=severity,
        cvss_score=cvss,
        scan=scans[0],
        affected_service=service,
        port=port,
        status=status,
        priority=priority,
        remediation='Update to latest version',
        assigned_to=users['analyst1'] if status != 'resolved' else users['analyst2'],
        discovered_by=users['admin'],
    )
    print(f"Vulnerability created: {cve}")

# Create remediation tasks
for vuln in Vulnerability.objects.filter(status='open'):
    RemediationTask.objects.create(
        vulnerability=vuln,
        title=f'Fix {vuln.cve_id}',
        description='Apply security patch',
        status='pending',
        assigned_to=users['analyst1'],
        due_date=timezone.now().date() + timedelta(days=7),
    )
    print(f"Remediation task created for {vuln.cve_id}")

# Create reports
report_data = [
    ('Executive Summary Report', 'executive', 'html'),
    ('Technical Findings Report', 'technical', 'pdf'),
    ('Vulnerability Report', 'findings', 'csv'),
]

for name, rtype, fmt in report_data:
    report = Report.objects.create(
        name=name,
        report_type=rtype,
        format=fmt,
        scan=scans[0],
        status='completed',
        generated_by=users['admin'],
        generated_at=timezone.now() - timedelta(hours=1),
        file_size=1024 * 100,
    )
    print(f"Report created: {name}")

# Create notifications
notifications_data = [
    ('Scan Complete', 'Port scan completed on Web Server 1', 'scan_complete', 'medium'),
    ('Vulnerability Found', 'Critical vulnerability detected', 'vulnerability_found', 'urgent'),
    ('Report Ready', 'Executive report generated', 'report_ready', 'low'),
]

for title, message, ntype, priority in notifications_data:
    Notification.objects.create(
        user=users['admin'],
        title=title,
        message=message,
        notification_type=ntype,
        priority=priority,
        is_read=False,
    )
    print(f"Notification created: {title}")

# Create notification preferences
for username, user in users.items():
    pref, created = NotificationPreference.objects.get_or_create(user=user)
    print(f"Notification preference created for {username}")

print("\n✅ Database populated successfully!")
print(f"Users: {User.objects.count()}")
print(f"Targets: {Target.objects.count()}")
print(f"Scans: {Scan.objects.count()}")
print(f"Port Results: {PortResult.objects.count()}")
print(f"Vulnerabilities: {Vulnerability.objects.count()}")
print(f"Reports: {Report.objects.count()}")
print(f"Notifications: {Notification.objects.count()}")
