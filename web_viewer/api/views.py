"""
REST API views
"""

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q

from .serializers import (
    UserSerializer, TargetSerializer, TargetGroupSerializer, ProjectSerializer,
    ScanSerializer, ScheduledScanSerializer, PortResultSerializer,
    VulnerabilitySerializer, VulnerabilityResultSerializer, ReportSerializer,
    ScanResultSerializer
)
from .permissions import IsOwnerOrReadOnly, IsAdminOrReadOnly
from targets.models import Target, TargetGroup, Project
from scans.models import Scan, ScheduledScan
from results.models import ScanResult, PortResult, VulnerabilityResult
from reports.models import Report
from vulnerabilities.models import Vulnerability
from django.contrib.auth.models import User


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for users"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class TargetViewSet(viewsets.ModelViewSet):
    """API endpoint for targets"""
    queryset = Target.objects.filter(is_active=True)
    serializer_class = TargetSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        queryset = Target.objects.filter(is_active=True)
        
        # Filter by type
        target_type = self.request.query_params.get('type', None)
        if target_type:
            queryset = queryset.filter(type=target_type)
        
        # Filter by priority
        priority = self.request.query_params.get('priority', None)
        if priority:
            queryset = queryset.filter(priority=priority)
        
        # Search
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) |
                Q(address__icontains=search)
            )
        
        return queryset
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class TargetGroupViewSet(viewsets.ModelViewSet):
    """API endpoint for target groups"""
    queryset = TargetGroup.objects.all()
    serializer_class = TargetGroupSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class ProjectViewSet(viewsets.ModelViewSet):
    """API endpoint for projects"""
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        return Project.objects.filter(
            Q(created_by=self.request.user) |
            Q(members=self.request.user)
        ).distinct()
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class ScanViewSet(viewsets.ModelViewSet):
    """API endpoint for scans"""
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        queryset = Scan.objects.select_related('target', 'initiated_by')
        
        # Filter by status
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by type
        scan_type = self.request.query_params.get('scan_type', None)
        if scan_type:
            queryset = queryset.filter(scan_type=scan_type)
        
        return queryset
    
    def perform_create(self, serializer):
        serializer.save(initiated_by=self.request.user)


class ScheduledScanViewSet(viewsets.ModelViewSet):
    """API endpoint for scheduled scans"""
    queryset = ScheduledScan.objects.all()
    serializer_class = ScheduledScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class PortResultViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for port results"""
    queryset = PortResult.objects.select_related('scan', 'scan__target')
    serializer_class = PortResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = PortResult.objects.select_related('scan', 'scan__target')
        
        # Filter by state
        state = self.request.query_params.get('state', None)
        if state:
            queryset = queryset.filter(state=state)
        
        # Filter by port
        port = self.request.query_params.get('port', None)
        if port:
            queryset = queryset.filter(port=port)
        
        return queryset


class VulnerabilityViewSet(viewsets.ModelViewSet):
    """API endpoint for vulnerabilities"""
    queryset = Vulnerability.objects.select_related('scan', 'assigned_to')
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        queryset = Vulnerability.objects.select_related('scan', 'assigned_to')
        
        # Filter by severity
        severity = self.request.query_params.get('severity', None)
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by status
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        # Filter by CVE
        cve = self.request.query_params.get('cve', None)
        if cve:
            queryset = queryset.filter(cve_id__icontains=cve)
        
        return queryset


class VulnerabilityResultViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for vulnerability results"""
    queryset = VulnerabilityResult.objects.all()
    serializer_class = VulnerabilityResultSerializer
    permission_classes = [permissions.IsAuthenticated]


class ReportViewSet(viewsets.ModelViewSet):
    """API endpoint for reports"""
    queryset = Report.objects.select_related('scan', 'generated_by')
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        queryset = Report.objects.select_related('scan', 'generated_by')
        
        # Filter by type
        report_type = self.request.query_params.get('report_type', None)
        if report_type:
            queryset = queryset.filter(report_type=report_type)
        
        # Filter by format
        format_type = self.request.query_params.get('format', None)
        if format_type:
            queryset = queryset.filter(format=format_type)
        
        return queryset
    
    def perform_create(self, serializer):
        serializer.save(generated_by=self.request.user)


class ScanResultViewSet(viewsets.ReadOnlyModelViewSet):
    """API endpoint for scan results"""
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer
    permission_classes = [permissions.IsAuthenticated]


class StatsView(APIView):
    """API endpoint for statistics"""
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get overall statistics"""
        stats = {
            'targets': {
                'total': Target.objects.filter(is_active=True).count(),
                'by_type': Target.objects.values('type').annotate(count=Count('id')),
            },
            'scans': {
                'total': Scan.objects.count(),
                'by_status': Scan.objects.values('status').annotate(count=Count('id')),
                'running': Scan.objects.filter(status='running').count(),
            },
            'vulnerabilities': {
                'total': Vulnerability.objects.count(),
                'by_severity': Vulnerability.objects.values('severity').annotate(count=Count('id')),
                'open': Vulnerability.objects.filter(status='open').count(),
            },
            'reports': {
                'total': Report.objects.count(),
                'by_format': Report.objects.values('format').annotate(count=Count('id')),
            },
        }
        
        return Response(stats)
