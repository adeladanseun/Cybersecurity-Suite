"""
Scan management models
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from targets.models import Target


class Scan(models.Model):
    """Represents a scan execution"""
    
    SCAN_TYPE_CHOICES = [
        ('port_scan', 'Port Scan'),
        ('full_port_scan', 'Full Port Scan'),
        ('udp_scan', 'UDP Scan'),
        ('dns_enum', 'DNS Enumeration'),
        ('subdomain_scan', 'Subdomain Discovery'),
        ('web_enum', 'Web Enumeration'),
        ('vuln_scan', 'Vulnerability Scan'),
        ('ssl_scan', 'SSL/TLS Scan'),
        ('service_scan', 'Service Detection'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    target = models.ForeignKey(
        Target,
        on_delete=models.CASCADE,
        related_name='scans'
    )
    
    scan_type = models.CharField(
        max_length=50,
        choices=SCAN_TYPE_CHOICES
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )
    
    progress = models.IntegerField(default=0)
    
    parameters = models.JSONField(default=dict, blank=True)
    
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration = models.DurationField(null=True, blank=True)
    
    results_file = models.FileField(
        upload_to='scans/results/',
        null=True,
        blank=True
    )
    
    error_message = models.TextField(blank=True)
    
    initiated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='scans_initiated'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.scan_type} on {self.target.name} ({self.status})"
    
    def get_progress_percentage(self):
        """Get progress as percentage"""
        return self.progress
    
    def is_active(self):
        """Check if scan is currently running"""
        return self.status in ['pending', 'running']
    
    def get_duration_display(self):
        """Get formatted duration"""
        if self.duration:
            seconds = int(self.duration.total_seconds())
            if seconds < 60:
                return f"{seconds}s"
            elif seconds < 3600:
                return f"{seconds // 60}m {seconds % 60}s"
            else:
                return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
        return "-"


class ScheduledScan(models.Model):
    """Represents a scheduled scan"""
    
    FREQUENCY_CHOICES = [
        ('once', 'Once'),
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    target = models.ForeignKey(
        Target,
        on_delete=models.CASCADE,
        related_name='scheduled_scans'
    )
    
    scan_type = models.CharField(
        max_length=50,
        choices=Scan.SCAN_TYPE_CHOICES
    )
    
    frequency = models.CharField(
        max_length=20,
        choices=FREQUENCY_CHOICES,
        default='daily'
    )
    
    schedule_time = models.TimeField()
    
    is_active = models.BooleanField(default=True)
    
    parameters = models.JSONField(default=dict, blank=True)
    
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='scheduled_scans_created'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['next_run']
    
    def __str__(self):
        return f"{self.scan_type} on {self.target.name} ({self.frequency})"
