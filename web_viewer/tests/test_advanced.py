"""
Tests for Advanced Features
Run: cd web_viewer && python manage.py test tests.test_advanced
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from notifications.models import Notification, NotificationPreference
from targets.models import Target


class NotificationTest(TestCase):
    """Test notification system"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_notification_creation(self):
        """Test creating a notification"""
        notification = Notification.objects.create(
            user=self.user,
            title='Test Notification',
            message='This is a test',
            notification_type='system',
            priority='medium'
        )
        
        self.assertEqual(notification.user, self.user)
        self.assertFalse(notification.is_read)
        self.assertEqual(notification.get_priority_badge_class(), 'bg-primary')
    
    def test_mark_as_read(self):
        """Test marking notification as read"""
        notification = Notification.objects.create(
            user=self.user,
            title='Test',
            message='Test'
        )
        
        notification.mark_as_read()
        notification.refresh_from_db()
        
        self.assertTrue(notification.is_read)
    
    def test_notification_preferences(self):
        """Test notification preferences"""
        pref = NotificationPreference.objects.create(user=self.user)
        
        self.assertTrue(pref.email_on_scan_complete)
        self.assertTrue(pref.notify_on_vulnerability)
        self.assertFalse(pref.browser_notifications)


class APITest(TestCase):
    """Test REST API"""
    
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        self.client.force_authenticate(user=self.user)
        
        self.target = Target.objects.create(
            name='API Target',
            address='192.168.1.1',
            created_by=self.user
        )
    
    def test_api_target_list(self):
        """Test API target list"""
        response = self.client.get('/api/targets/')
        
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.data), 1)
    
    def test_api_target_detail(self):
        """Test API target detail"""
        response = self.client.get(f'/api/targets/{self.target.id}/')
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['name'], 'API Target')
    
    def test_api_stats(self):
        """Test API stats endpoint"""
        response = self.client.get('/api/stats/')
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('targets', response.data)
        self.assertIn('scans', response.data)
        self.assertIn('vulnerabilities', response.data)


class DashboardTest(TestCase):
    """Test dashboard views"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_dashboard_requires_login(self):
        """Test dashboard requires authentication"""
        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 302)
    
    def test_dashboard_logged_in(self):
        """Test dashboard for logged in user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 200)
    
    def test_stats_page(self):
        """Test stats page"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/dashboard/stats/')
        self.assertEqual(response.status_code, 200)
    
    def test_activity_page(self):
        """Test activity page"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/dashboard/activity/')
        self.assertEqual(response.status_code, 200)
