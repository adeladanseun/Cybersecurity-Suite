"""
Notification models
"""

import uuid
from django.db import models
from django.contrib.auth.models import User


class Notification(models.Model):
    """User notification"""
    
    TYPE_CHOICES = [
        ('scan_complete', 'Scan Complete'),
        ('scan_failed', 'Scan Failed'),
        ('vulnerability_found', 'Vulnerability Found'),
        ('report_ready', 'Report Ready'),
        ('target_added', 'Target Added'),
        ('system', 'System Notification'),
    ]
    
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('urgent', 'Urgent'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    
    title = models.CharField(max_length=255)
    message = models.TextField()
    
    notification_type = models.CharField(max_length=30, choices=TYPE_CHOICES, default='system')
    priority = models.CharField(max_length=10, choices=PRIORITY_CHOICES, default='medium')
    
    is_read = models.BooleanField(default=False)
    link = models.CharField(max_length=500, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.user.username}"
    
    def mark_as_read(self):
        """Mark notification as read"""
        self.is_read = True
        self.save(update_fields=['is_read'])
    
    def get_priority_badge_class(self):
        """Get CSS class for priority"""
        classes = {
            'low': 'bg-secondary',
            'medium': 'bg-primary',
            'high': 'bg-warning',
            'urgent': 'bg-danger',
        }
        return classes.get(self.priority, 'bg-secondary')


class NotificationPreference(models.Model):
    """User notification preferences"""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='notification_preferences'
    )
    
    # Email notifications
    email_on_scan_complete = models.BooleanField(default=True)
    email_on_vulnerability = models.BooleanField(default=True)
    email_on_report = models.BooleanField(default=True)
    
    # In-app notifications
    notify_on_scan_complete = models.BooleanField(default=True)
    notify_on_scan_failed = models.BooleanField(default=True)
    notify_on_vulnerability = models.BooleanField(default=True)
    notify_on_report = models.BooleanField(default=True)
    
    # Browser notifications
    browser_notifications = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"Preferences for {self.user.username}"
