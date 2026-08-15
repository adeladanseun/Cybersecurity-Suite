"""
REST API serializers
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from targets.models import Target, TargetGroup, Project
from scans.models import Scan, ScheduledScan
from results.models import ScanResult, PortResult, VulnerabilityResult
from reports.models import Report
from vulnerabilities.models import Vulnerability


class UserSerializer(serializers.ModelSerializer):
    """User serializer"""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']


class TargetSerializer(serializers.ModelSerializer):
    """Target serializer"""
    
    created_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Target
        fields = ['id', 'name', 'address', 'type', 'description', 'priority',
                  'is_active', 'created_by', 'created_at', 'last_scanned']
        read_only_fields = ['id', 'created_at', 'last_scanned']


class TargetGroupSerializer(serializers.ModelSerializer):
    """Target group serializer"""
    
    targets_count = serializers.SerializerMethodField()
    
    class Meta:
        model = TargetGroup
        fields = ['id', 'name', 'description', 'targets', 'targets_count', 'created_at']
        read_only_fields = ['id', 'created_at']
    
    def get_targets_count(self, obj):
        return obj.targets.count()


class ProjectSerializer(serializers.ModelSerializer):
    """Project serializer"""
    
    targets_count = serializers.SerializerMethodField()
    members_count = serializers.SerializerMethodField()
    completion = serializers.SerializerMethodField()
    
    class Meta:
        model = Project
        fields = ['id', 'name', 'description', 'status', 'start_date', 'end_date',
                  'targets_count', 'members_count', 'completion', 'created_at']
        read_only_fields = ['id', 'created_at']
    
    def get_targets_count(self, obj):
        return obj.targets.count()
    
    def get_members_count(self, obj):
        return obj.members.count()
    
    def get_completion(self, obj):
        return obj.get_completion_percentage()


class ScanSerializer(serializers.ModelSerializer):
    """Scan serializer"""
    
    target_name = serializers.CharField(source='target.name', read_only=True)
    target_address = serializers.CharField(source='target.address', read_only=True)
    initiated_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Scan
        fields = ['id', 'target', 'target_name', 'target_address', 'scan_type',
                  'status', 'progress', 'started_at', 'completed_at', 'duration',
                  'initiated_by', 'created_at']
        read_only_fields = ['id', 'status', 'progress', 'started_at', 'completed_at',
                           'duration', 'created_at']


class ScheduledScanSerializer(serializers.ModelSerializer):
    """Scheduled scan serializer"""
    
    target_name = serializers.CharField(source='target.name', read_only=True)
    
    class Meta:
        model = ScheduledScan
        fields = ['id', 'target', 'target_name', 'scan_type', 'frequency',
                  'schedule_time', 'is_active', 'last_run', 'next_run']
        read_only_fields = ['id', 'last_run', 'next_run']


class PortResultSerializer(serializers.ModelSerializer):
    """Port result serializer"""
    
    target_name = serializers.CharField(source='scan.target.name', read_only=True)
    
    class Meta:
        model = PortResult
        fields = ['id', 'scan', 'target_name', 'port', 'protocol', 'state',
                  'service', 'product', 'version', 'created_at']
        read_only_fields = ['id', 'created_at']


class VulnerabilitySerializer(serializers.ModelSerializer):
    """Vulnerability serializer"""
    
    target_name = serializers.CharField(source='scan.target.name', read_only=True, default=None)
    assigned_to_username = serializers.CharField(source='assigned_to.username', read_only=True, default=None)
    
    class Meta:
        model = Vulnerability
        fields = ['id', 'cve_id', 'title', 'description', 'severity', 'cvss_score',
                  'scan', 'target_name', 'affected_service', 'port', 'status',
                  'priority', 'remediation', 'assigned_to', 'assigned_to_username',
                  'created_at', 'updated_at', 'resolved_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'resolved_at']


class VulnerabilityResultSerializer(serializers.ModelSerializer):
    """Vulnerability result serializer"""
    
    class Meta:
        model = VulnerabilityResult
        fields = ['id', 'scan', 'cve_id', 'title', 'severity', 'cvss_score',
                  'affected_service', 'port', 'status', 'created_at']
        read_only_fields = ['id', 'created_at']


class ReportSerializer(serializers.ModelSerializer):
    """Report serializer"""
    
    target_name = serializers.CharField(source='scan.target.name', read_only=True, default=None)
    generated_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Report
        fields = ['id', 'name', 'description', 'report_type', 'format', 'scan',
                  'target_name', 'status', 'generated_by', 'generated_at',
                  'download_count', 'file_size', 'created_at']
        read_only_fields = ['id', 'status', 'generated_at', 'download_count',
                           'file_size', 'created_at']


class ScanResultSerializer(serializers.ModelSerializer):
    """Generic scan result serializer"""
    
    class Meta:
        model = ScanResult
        fields = ['id', 'scan', 'result_type', 'severity', 'data', 'created_at']
        read_only_fields = ['id', 'created_at']
