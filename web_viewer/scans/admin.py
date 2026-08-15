"""
Admin configuration for scans app
"""

from django.contrib import admin
from .models import Scan, ScheduledScan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'scan_type', 'status', 'started_at', 'completed_at', 'initiated_by']
    list_filter = ['status', 'scan_type', 'started_at']
    search_fields = ['target__name', 'target__address']
    readonly_fields = ['id', 'started_at', 'completed_at']
    
    fieldsets = (
        ('Scan Information', {
            'fields': ('target', 'scan_type', 'status', 'parameters')
        }),
        ('Timing', {
            'fields': ('started_at', 'completed_at', 'duration')
        }),
        ('Results', {
            'fields': ('results_file', 'error_message')
        }),
        ('User', {
            'fields': ('initiated_by',)
        }),
    )


@admin.register(ScheduledScan)
class ScheduledScanAdmin(admin.ModelAdmin):
    list_display = ['id', 'target', 'scan_type', 'schedule_time', 'is_active', 'next_run']
    list_filter = ['is_active', 'scan_type']
    search_fields = ['target__name']
    readonly_fields = ['id', 'last_run', 'next_run']
