"""
Report models for report generation and management
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from scans.models import Scan


class Report(models.Model):
    """Generated report"""
    
    REPORT_TYPE_CHOICES = [
        ('executive', 'Executive Summary'),
        ('technical', 'Technical Report'),
        ('findings', 'Findings Report'),
        ('full', 'Full Assessment'),
        ('custom', 'Custom Report'),
    ]
    
    FORMAT_CHOICES = [
        ('html', 'HTML'),
        ('pdf', 'PDF'),
        ('csv', 'CSV'),
        ('txt', 'Text'),
        ('json', 'JSON'),
    ]
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES)
    
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='reports',
        null=True,
        blank=True
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    file = models.FileField(
        upload_to='reports/generated/',
        null=True,
        blank=True
    )
    
    generated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reports_generated'
    )
    
    generated_at = models.DateTimeField(null=True, blank=True)
    
    download_count = models.IntegerField(default=0)
    
    file_size = models.IntegerField(default=0, help_text="File size in bytes")
    
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-generated_at', '-created_at']
        indexes = [
            models.Index(fields=['report_type', 'format']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.get_format_display()})"
    
    def get_file_size_display(self):
        """Get human-readable file size"""
        size = self.file_size
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"
    
    def increment_download_count(self):
        """Increment download counter"""
        self.download_count += 1
        self.save(update_fields=['download_count'])


class ReportTemplate(models.Model):
    """Custom report template"""
    
    TEMPLATE_TYPE_CHOICES = [
        ('executive', 'Executive Summary'),
        ('technical', 'Technical Report'),
        ('findings', 'Findings Report'),
        ('custom', 'Custom Template'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    template_type = models.CharField(max_length=20, choices=TEMPLATE_TYPE_CHOICES)
    
    template_file = models.FileField(
        upload_to='reports/templates/',
        help_text="Upload HTML template file"
    )
    
    is_active = models.BooleanField(default=True)
    
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='report_templates_created'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
