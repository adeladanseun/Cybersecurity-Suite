"""
Results models for storing scan results
"""

import uuid
from django.db import models
from scans.models import Scan


class ScanResult(models.Model):
    """Generic scan result container"""
    
    RESULT_TYPE_CHOICES = [
        ('port', 'Port Result'),
        ('service', 'Service Detection'),
        ('vulnerability', 'Vulnerability'),
        ('dns', 'DNS Record'),
        ('ssl', 'SSL/TLS Finding'),
        ('web', 'Web Finding'),
        ('info', 'Information'),
    ]
    
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='results'
    )
    
    result_type = models.CharField(max_length=20, choices=RESULT_TYPE_CHOICES)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='info')
    
    data = models.JSONField(default=dict)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan', 'result_type']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.result_type} - {self.scan.target.name}"


class PortResult(models.Model):
    """Port scan result"""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='port_results'
    )
    
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20, default='open')
    service = models.CharField(max_length=100, blank=True)
    product = models.CharField(max_length=200, blank=True)
    version = models.CharField(max_length=100, blank=True)
    extra_info = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['port']
        unique_together = ['scan', 'port', 'protocol']
        indexes = [
            models.Index(fields=['scan', 'state']),
            models.Index(fields=['service']),
        ]
    
    def __str__(self):
        return f"Port {self.port}/{self.protocol} - {self.service} ({self.state})"
    
    def get_service_display(self):
        """Get formatted service name"""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.service


class VulnerabilityResult(models.Model):
    """Vulnerability finding"""
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('accepted', 'Accepted Risk'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='vulnerability_results'
    )
    
    cve_id = models.CharField(max_length=50, blank=True)
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=10, choices=ScanResult.SEVERITY_CHOICES)
    cvss_score = models.FloatField(null=True, blank=True)
    
    affected_service = models.CharField(max_length=200, blank=True)
    port = models.IntegerField(null=True, blank=True)
    
    remediation = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    
    assigned_to = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_vulnerabilities'
    )
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-cvss_score', '-created_at']
        indexes = [
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['cve_id']),
        ]
    
    def __str__(self):
        return f"{self.cve_id or 'No CVE'} - {self.title} ({self.severity})"
    
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
