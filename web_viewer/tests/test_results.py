"""
Tests for Results Viewing
Run: cd web_viewer && python manage.py test tests.test_results
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from results.models import ScanResult, PortResult, VulnerabilityResult
from scans.models import Scan
from targets.models import Target


class ResultModelTest(TestCase):
    """Test result models"""
    
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
    
    def test_scan_result_creation(self):
        """Test creating a scan result"""
        result = ScanResult.objects.create(
            scan=self.scan,
            result_type='info',
            severity='info',
            data={'summary': 'Test summary'}
        )
        
        self.assertEqual(result.result_type, 'info')
        self.assertEqual(result.severity, 'info')
        self.assertEqual(result.data['summary'], 'Test summary')
    
    def test_port_result_creation(self):
        """Test creating a port result"""
        port = PortResult.objects.create(
            scan=self.scan,
            port=80,
            protocol='tcp',
            state='open',
            service='http',
            product='Apache',
            version='2.4.41'
        )
        
        self.assertEqual(port.port, 80)
        self.assertEqual(port.service, 'http')
        self.assertEqual(port.get_service_display(), 'Apache 2.4.41')
    
    def test_vulnerability_result_creation(self):
        """Test creating a vulnerability result"""
        vuln = VulnerabilityResult.objects.create(
            scan=self.scan,
            cve_id='CVE-2021-41773',
            title='Path Traversal',
            severity='critical',
            cvss_score=9.8,
            affected_service='Apache',
            port=80
        )
        
        self.assertEqual(vuln.cve_id, 'CVE-2021-41773')
        self.assertEqual(vuln.severity, 'critical')
        self.assertEqual(vuln.cvss_score, 9.8)
        self.assertEqual(vuln.get_severity_badge_class(), 'bg-danger')


class ResultViewsTest(TestCase):
    """Test result views"""
    
    def setUp(self):
        self.client = Client()
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
        
        self.result = ScanResult.objects.create(
            scan=self.scan,
            result_type='info',
            severity='info',
            data={'test': 'data'}
        )
    
    def test_result_list_requires_login(self):
        """Test result list requires authentication"""
        response = self.client.get('/results/')
        self.assertEqual(response.status_code, 302)
    
    def test_result_list_logged_in(self):
        """Test result list for logged in user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/results/')
        self.assertEqual(response.status_code, 200)
    
    def test_result_detail(self):
        """Test result detail view"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(f'/results/{self.result.id}/')
        self.assertEqual(response.status_code, 200)
