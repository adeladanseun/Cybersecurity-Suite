"""
Vulnerability management models
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from scans.models import Scan


class Vulnerability(models.Model):
    """Vulnerability finding with management capabilities"""
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('accepted', 'Accepted Risk'),
        ('wont_fix', 'Won\'t Fix'),
    ]
    
    PRIORITY_CHOICES = [
        ('P1', 'P1 - Critical Priority'),
        ('P2', 'P2 - High Priority'),
        ('P3', 'P3 - Medium Priority'),
        ('P4', 'P4 - Low Priority'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    cve_id = models.CharField(max_length=50, blank=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='medium')
    cvss_score = models.FloatField(null=True, blank=True)
    
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='vulnerabilities',
        null=True,
        blank=True
    )
    
    affected_service = models.CharField(max_length=200, blank=True)
    port = models.IntegerField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    priority = models.CharField(max_length=2, choices=PRIORITY_CHOICES, default='P3')
    
    remediation = models.TextField(blank=True)
    
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_vulnerabilities'
    )
    
    discovered_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='discovered_vulnerabilities'
    )
    
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_vulnerabilities'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-cvss_score', '-created_at']
        verbose_name_plural = 'Vulnerabilities'
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['cve_id']),
            models.Index(fields=['priority']),
        ]
    
    def __str__(self):
        return f"{self.cve_id or 'No CVE'} - {self.title}"
    
    def get_severity_badge_class(self):
        """Get CSS class for severity badge"""
        classes = {
            'critical': 'bg-danger',
            'high': 'bg-warning',
            'medium': 'bg-primary',
            'low': 'bg-secondary',
            'info': 'bg-info',
        }
        return classes.get(self.severity, 'bg-secondary')
    
    def get_status_badge_class(self):
        """Get CSS class for status badge"""
        classes = {
            'open': 'bg-danger',
            'in_progress': 'bg-warning',
            'resolved': 'bg-success',
            'false_positive': 'bg-secondary',
            'accepted': 'bg-info',
            'wont_fix': 'bg-dark',
        }
        return classes.get(self.status, 'bg-secondary')
    
    def get_priority_badge_class(self):
        """Get CSS class for priority badge"""
        classes = {
            'P1': 'bg-danger',
            'P2': 'bg-warning',
            'P3': 'bg-primary',
            'P4': 'bg-secondary',
        }
        return classes.get(self.priority, 'bg-secondary')
    
    def mark_resolved(self, user):
        """Mark vulnerability as resolved"""
        from django.utils import timezone
        self.status = 'resolved'
        self.resolved_at = timezone.now()
        self.resolved_by = user
        self.save()
    
    def get_open_tasks_count(self):
        """Get count of open remediation tasks"""
        return self.remediation_tasks.filter(status__in=['pending', 'in_progress']).count()
    
    def get_notes_count(self):
        """Get count of notes"""
        return self.notes.count()


class RemediationTask(models.Model):
    """Remediation task for a vulnerability"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('blocked', 'Blocked'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name='remediation_tasks'
    )
    
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='remediation_tasks'
    )
    
    due_date = models.DateField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['due_date', 'created_at']
    
    def __str__(self):
        return self.title
    
    def is_overdue(self):
        """Check if task is overdue"""
        from django.utils import timezone
        if self.due_date and self.status not in ['completed']:
            return self.due_date < timezone.now().date()
        return False


class VulnerabilityNote(models.Model):
    """Notes on vulnerabilities"""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name='notes'
    )
    
    author = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='vulnerability_notes'
    )
    
    content = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Note by {self.author.username} on {self.vulnerability.title}"
