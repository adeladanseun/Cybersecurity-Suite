"""
Admin configuration for reports app
"""

from django.contrib import admin
from .models import Report, ReportTemplate


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'report_type', 'format', 'scan', 'generated_by', 'generated_at']
    list_filter = ['report_type', 'format', 'generated_at']
    search_fields = ['name', 'scan__target__name']
    readonly_fields = ['id', 'generated_at', 'download_count']
    list_filter = ['report_type', 'format']


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'template_type', 'is_active', 'created_by', 'created_at']
    list_filter = ['template_type', 'is_active']
    search_fields = ['name', 'description']
    readonly_fields = ['id', 'created_at']
