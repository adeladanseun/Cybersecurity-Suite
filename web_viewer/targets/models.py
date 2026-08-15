"""
Target management models
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinLengthValidator
from core.validator import is_valid_ip, is_valid_domain, is_valid_url, classify_target


class Target(models.Model):
    """Represents a scan target (IP, domain, URL, etc.)"""
    
    TYPE_CHOICES = [
        ('ip', 'IP Address'),
        ('cidr', 'Network Range'),
        ('domain', 'Domain Name'),
        ('url', 'URL'),
        ('hostname', 'Hostname'),
    ]
    
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    name = models.CharField(max_length=255, help_text="Friendly name for this target")
    
    address = models.CharField(
        max_length=500,
        help_text="IP address, domain, URL, or network range"
    )
    
    type = models.CharField(
        max_length=20,
        choices=TYPE_CHOICES,
        blank=True,
        help_text="Target type (auto-detected if blank)"
    )
    
    description = models.TextField(blank=True)
    
    priority = models.CharField(
        max_length=10,
        choices=PRIORITY_CHOICES,
        default='medium'
    )
    
    is_active = models.BooleanField(default=True)
    
    notes = models.TextField(blank=True)
    
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='targets_created'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    last_scanned = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['name']
        unique_together = ['address', 'created_by']
    
    def __str__(self):
        return f"{self.name} ({self.address})"
    
    def save(self, *args, **kwargs):
        """Auto-detect target type if not provided"""
        if not self.type:
            self.type = self.detect_type()
        super().save(*args, **kwargs)
    
    def detect_type(self):
        """Detect target type from address"""
        target_type = classify_target(self.address)
        
        type_map = {
            'ipv4': 'ip',
            'ipv6': 'ip',
            'cidr': 'cidr',
            'domain': 'domain',
            'url': 'url',
            'hostname': 'hostname',
        }
        
        return type_map.get(target_type, 'ip')
    
    def get_scan_count(self):
        """Get number of scans for this target"""
        return self.scans.count()
    
    def get_vulnerability_count(self):
        """Get number of vulnerabilities found"""
        return self.scans.filter(
            results__vulnerabilities__isnull=False
        ).count()


class TargetGroup(models.Model):
    """Group of targets for batch operations"""
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    targets = models.ManyToManyField(
        Target,
        related_name='groups',
        blank=True
    )
    
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='target_groups_created'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def get_target_count(self):
        """Get number of targets in group"""
        return self.targets.count()


class Project(models.Model):
    """Project containing multiple targets for organized assessment"""
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('completed', 'Completed'),
        ('archived', 'Archived'),
        ('paused', 'Paused'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    targets = models.ManyToManyField(
        Target,
        related_name='projects',
        blank=True
    )
    
    members = models.ManyToManyField(
        User,
        related_name='projects',
        blank=True
    )
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='active'
    )
    
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='projects_created'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name
    
    def get_target_count(self):
        """Get number of targets in project"""
        return self.targets.count()
    
    def get_completion_percentage(self):
        """Calculate project completion based on scanned targets"""
        total = self.targets.count()
        if total == 0:
            return 0
        
        scanned = self.targets.filter(last_scanned__isnull=False).count()
        return int((scanned / total) * 100)
