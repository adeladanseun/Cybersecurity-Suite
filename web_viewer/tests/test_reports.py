"""
Tests for Report Generation
Run: cd web_viewer && python manage.py test tests.test_reports
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from reports.models import Report, ReportTemplate
from scans.models import Scan
from targets.models import Target


class ReportModelTest(TestCase):
    """Test Report model"""
    
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
    
    def test_report_creation(self):
        """Test creating a report"""
        report = Report.objects.create(
            name='Test Report',
            report_type='executive',
            format='html',
            scan=self.scan,
            generated_by=self.user
        )
        
        self.assertEqual(report.name, 'Test Report')
        self.assertEqual(report.report_type, 'executive')
        self.assertEqual(report.format, 'html')
        self.assertEqual(report.status, 'pending')
    
    def test_file_size_display(self):
        """Test file size formatting"""
        report = Report.objects.create(
            name='Test',
            report_type='executive',
            format='html',
            file_size=1024,
            generated_by=self.user
        )
        
        self.assertEqual(report.get_file_size_display(), '1.0 KB')
    
    def test_download_counter(self):
        """Test download count increment"""
        report = Report.objects.create(
            name='Test',
            report_type='executive',
            format='html',
            generated_by=self.user
        )
        
        report.increment_download_count()
        report.refresh_from_db()
        
        self.assertEqual(report.download_count, 1)


class ReportTemplateTest(TestCase):
    """Test ReportTemplate model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_template_creation(self):
        """Test creating a template"""
        template = ReportTemplate.objects.create(
            name='Custom Template',
            template_type='custom',
            created_by=self.user
        )
        
        self.assertEqual(template.name, 'Custom Template')
        self.assertTrue(template.is_active)


class ReportViewsTest(TestCase):
    """Test report views"""
    
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
        
        self.report = Report.objects.create(
            name='Test Report',
            report_type='executive',
            format='html',
            scan=self.scan,
            generated_by=self.user
        )
    
    def test_report_list_requires_login(self):
        """Test report list requires authentication"""
        response = self.client.get('/reports/')
        self.assertEqual(response.status_code, 302)
    
    def test_report_list_logged_in(self):
        """Test report list for logged in user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/reports/')
        self.assertEqual(response.status_code, 200)
    
    def test_report_detail(self):
        """Test report detail view"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get(f'/reports/{self.report.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Report')
