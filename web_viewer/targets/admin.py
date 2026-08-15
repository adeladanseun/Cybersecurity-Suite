"""
Admin configuration for targets app
"""

from django.contrib import admin
from .models import Target, TargetGroup, Project


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ['name', 'address', 'type', 'is_active', 'created_by', 'created_at']
    list_filter = ['type', 'is_active', 'created_at']
    search_fields = ['name', 'address', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'address', 'type', 'description')
        }),
        ('Status', {
            'fields': ('is_active', 'created_by')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(TargetGroup)
class TargetGroupAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_by', 'created_at']
    search_fields = ['name', 'description']
    filter_horizontal = ['targets']


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ['name', 'status', 'start_date', 'end_date', 'created_by']
    list_filter = ['status', 'start_date']
    search_fields = ['name', 'description']
    filter_horizontal = ['targets', 'members']
