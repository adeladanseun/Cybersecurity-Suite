"""
Tests for Target Management
Run: cd web_viewer && python manage.py test tests.test_targets
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from targets.models import Target, TargetGroup, Project


class TargetModelTest(TestCase):
    """Test Target model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
    
    def test_target_creation(self):
        """Test creating a target"""
        target = Target.objects.create(
            name='Test Server',
            address='192.168.1.1',
            created_by=self.user
        )
        
        self.assertEqual(target.name, 'Test Server')
        self.assertEqual(target.address, '192.168.1.1')
        self.assertEqual(target.type, 'ip')
        self.assertTrue(target.is_active)
    
    def test_target_type_detection(self):
        """Test auto-detection of target types"""
        tests = [
            ('192.168.1.1', 'ip'),
            ('192.168.1.0/24', 'cidr'),
            ('example.com', 'domain'),
            ('https://test.com', 'url'),
            ('server-name', 'hostname'),
        ]
        
        for address, expected_type in tests:
            target = Target.objects.create(
                name=address,
                address=address,
                created_by=self.user
            )
            self.assertEqual(target.type, expected_type)


class TargetGroupTest(TestCase):
    """Test TargetGroup model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.target1 = Target.objects.create(
            name='Target 1',
            address='192.168.1.1',
            created_by=self.user
        )
        
        self.target2 = Target.objects.create(
            name='Target 2',
            address='192.168.1.2',
            created_by=self.user
        )
    
    def test_group_creation(self):
        """Test creating a group"""
        group = TargetGroup.objects.create(
            name='Web Servers',
            created_by=self.user
        )
        
        group.targets.add(self.target1, self.target2)
        
        self.assertEqual(group.get_target_count(), 2)


class TargetViewsTest(TestCase):
    """Test target views"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123'
        )
        
        self.target = Target.objects.create(
            name='Test Server',
            address='192.168.1.1',
            created_by=self.user
        )
    
    def test_target_list_requires_login(self):
        """Test target list requires authentication"""
        response = self.client.get('/targets/')
        self.assertEqual(response.status_code, 302)
    
    def test_target_list_logged_in(self):
        """Test target list for logged in user"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/targets/')
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Server')
