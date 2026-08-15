"""
Tests for Scan Management
Run: cd web_viewer && python manage.py test tests.test_scans
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from scans.models import Scan, ScheduledScan
from targets.models import Target


class ScanModelTest(TestCase):
    """Test Scan model"""
    
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
    
    def test_scan_creation(self):
        """Test creating a scan"""
        scan = Scan.objects.create(
            target=self.target,
            scan_type='port_scan',
            status='pending',
            initiated_by=self.user
        )
        
        self.assertEqual(scan.scan_type, 'port_scan')
        self.assertEqual(scan.status, 'pending')
        self.assertEqual(scan.progress, 0)
        self.assertTrue(scan.is_active())
    
    def test_scan_progress(self):
        """Test scan progress tracking"""
        scan = Scan.objects.create(
            target=self.target,
            scan_type='port_scan',
            status='running',
            progress=50,
            initiated_by=self.user
        )
        
        self.assertEqual(scan.get_progress_percentage(), 50)
        self.assertTrue(scan.is_active())
    
    def test_scan_duration(self):
        """Test scan duration display"""
        from datetime import timedelta
        
        scan = Scan.objects.create(
            target=self.target,
            scan_type='port_scan',
            status='completed',
            duration=timedelta(minutes=2, seconds=30),
            initiated_by=self.user
        )
        
        self.assertEqual(scan.get_duration_display(), "2m 30s")


class ScheduledScanTest(TestCase):
    """Test ScheduledScan model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.target = Target.objects.create(
            name='Test Target',
            address='example.com',
            created_by=self.user
        )
    
    def test_scheduled_scan_creation(self):
        """Test creating scheduled scan"""
        from datetime import time
        
        scheduled = ScheduledScan.objects.create(
            target=self.target,
            scan_type='port_scan',
            frequency='daily',
            schedule_time=time(3, 0),
            created_by=self.user
        )
        
        self.assertEqual(scheduled.frequency, 'daily')
        self.assertTrue(scheduled.is_active)


class ScanViewsTest(TestCase):
    """Test scan views"""
    
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
    
    def test_scan_list_requires_login(self):
        """Test scan list requires authentication"""
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 302)
    
    def test_scan_list_logged_in(self):
        """Test scan list for logged in user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/scans/')
        self.assertEqual(response.status_code, 200)
    
    def test_scan_detail(self):
        """Test scan detail view"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(f'/scans/{self.scan.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Target')
