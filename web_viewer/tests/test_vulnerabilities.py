"""
Tests for Vulnerability Management
Run: cd web_viewer && python manage.py test tests.test_vulnerabilities
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from vulnerabilities.models import Vulnerability, RemediationTask, VulnerabilityNote
from scans.models import Scan
from targets.models import Target


class VulnerabilityModelTest(TestCase):
    """Test Vulnerability model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.target = Target.objects.create(
            name='Test Target',
            address='192.168.1.1',
            created_by=self.user
        )
        
        self.scan = Scan.objects.create(
            target=self.target,
            scan_type='port_scan',
            status='completed',
            initiated_by=self.user
        )
    
    def test_vulnerability_creation(self):
        """Test creating a vulnerability"""
        vuln = Vulnerability.objects.create(
            cve_id='CVE-2021-41773',
            title='Path Traversal',
            severity='critical',
            cvss_score=9.8,
            scan=self.scan,
            affected_service='Apache',
            port=80
        )
        
        self.assertEqual(vuln.cve_id, 'CVE-2021-41773')
        self.assertEqual(vuln.severity, 'critical')
        self.assertEqual(vuln.cvss_score, 9.8)
        self.assertEqual(vuln.get_severity_badge_class(), 'bg-danger')
        self.assertEqual(vuln.status, 'open')
    
    def test_mark_resolved(self):
        """Test marking vulnerability as resolved"""
        vuln = Vulnerability.objects.create(
            title='Test Vuln',
            severity='high'
        )
        
        vuln.mark_resolved(self.user)
        vuln.refresh_from_db()
        
        self.assertEqual(vuln.status, 'resolved')
        self.assertIsNotNone(vuln.resolved_at)
        self.assertEqual(vuln.resolved_by, self.user)
    
    def test_remediation_task(self):
        """Test remediation task creation"""
        vuln = Vulnerability.objects.create(
            title='Test Vuln',
            severity='medium'
        )
        
        task = RemediationTask.objects.create(
            vulnerability=vuln,
            title='Fix vulnerability',
            status='pending'
        )
        
        self.assertEqual(task.vulnerability, vuln)
        self.assertEqual(task.status, 'pending')
        self.assertEqual(vuln.get_open_tasks_count(), 1)
    
    def test_vulnerability_note(self):
        """Test adding note to vulnerability"""
        vuln = Vulnerability.objects.create(
            title='Test Vuln',
            severity='low'
        )
        
        note = VulnerabilityNote.objects.create(
            vulnerability=vuln,
            author=self.user,
            content='Test note'
        )
        
        self.assertEqual(note.vulnerability, vuln)
        self.assertEqual(vuln.get_notes_count(), 1)


class VulnerabilityViewsTest(TestCase):
    """Test vulnerability views"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.vuln = Vulnerability.objects.create(
            cve_id='CVE-2021-41773',
            title='Test Vulnerability',
            severity='high',
            discovered_by=self.user
        )
    
    def test_vuln_list_requires_login(self):
        """Test vulnerability list requires authentication"""
        response = self.client.get('/vulnerabilities/')
        self.assertEqual(response.status_code, 302)
    
    def test_vuln_list_logged_in(self):
        """Test vulnerability list for logged in user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/vulnerabilities/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Vulnerability')
    
    def test_vuln_detail(self):
        """Test vulnerability detail view"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(f'/vulnerabilities/{self.vuln.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'CVE-2021-41773')
    
    def test_vuln_dashboard(self):
        """Test vulnerability dashboard"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/vulnerabilities/dashboard/')
        self.assertEqual(response.status_code, 200)
