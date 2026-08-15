"""
Admin configuration for vulnerabilities app
"""

from django.contrib import admin
from .models import Vulnerability, RemediationTask, VulnerabilityNote


class VulnerabilityNoteInline(admin.TabularInline):
    model = VulnerabilityNote
    extra = 0
    readonly_fields = ['created_at']


class RemediationTaskInline(admin.TabularInline):
    model = RemediationTask
    extra = 0


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ['id', 'cve_id', 'title', 'severity', 'cvss_score', 'status', 'assigned_to', 'created_at']
    list_filter = ['severity', 'status', 'created_at']
    search_fields = ['cve_id', 'title', 'description', 'affected_service']
    readonly_fields = ['id', 'created_at', 'updated_at']
    inlines = [VulnerabilityNoteInline, RemediationTaskInline]
    
    fieldsets = (
        ('Vulnerability Information', {
            'fields': ('cve_id', 'title', 'description', 'severity', 'cvss_score')
        }),
        ('Affected System', {
            'fields': ('scan', 'affected_service', 'port')
        }),
        ('Status', {
            'fields': ('status', 'assigned_to')
        }),
        ('Remediation', {
            'fields': ('remediation',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(RemediationTask)
class RemediationTaskAdmin(admin.ModelAdmin):
    list_display = ['id', 'vulnerability', 'title', 'status', 'assigned_to', 'due_date']
    list_filter = ['status', 'due_date']
    search_fields = ['title', 'description']


@admin.register(VulnerabilityNote)
class VulnerabilityNoteAdmin(admin.ModelAdmin):
    list_display = ['id', 'vulnerability', 'author', 'created_at']
    search_fields = ['content']
