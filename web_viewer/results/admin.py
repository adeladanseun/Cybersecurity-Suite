"""
Admin configuration for results app
"""

from django.contrib import admin
from .models import ScanResult, PortResult, VulnerabilityResult


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'result_type', 'severity', 'created_at']
    list_filter = ['result_type', 'severity', 'created_at']
    search_fields = ['scan__target__name', 'data']
    readonly_fields = ['id', 'created_at']


@admin.register(PortResult)
class PortResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'port', 'protocol', 'state', 'service', 'product', 'version']
    list_filter = ['state', 'protocol', 'service']
    search_fields = ['scan__target__name', 'service', 'product']
    readonly_fields = ['id']


@admin.register(VulnerabilityResult)
class VulnerabilityResultAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan', 'cve_id', 'severity', 'cvss_score', 'status']
    list_filter = ['severity', 'status']
    search_fields = ['cve_id', 'title', 'affected_service']
    readonly_fields = ['id']
