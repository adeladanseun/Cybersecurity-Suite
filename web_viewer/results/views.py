"""
Views for results viewing
"""

import json
import csv
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.db.models import Q, Count
from django.views.generic import ListView, DetailView
from django.contrib.auth.mixins import LoginRequiredMixin

from .models import ScanResult, PortResult, VulnerabilityResult
from scans.models import Scan


class ResultListView(LoginRequiredMixin, ListView):
    """List all results"""
    model = ScanResult
    template_name = 'results/result_list.html'
    context_object_name = 'results'
    paginate_by = 50
    
    def get_queryset(self):
        queryset = ScanResult.objects.select_related('scan', 'scan__target')
        
        # Filter by severity
        severity = self.request.GET.get('severity', '')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by type
        result_type = self.request.GET.get('result_type', '')
        if result_type:
            queryset = queryset.filter(result_type=result_type)
        
        # Filter by scan
        scan_id = self.request.GET.get('scan', '')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        # Search
        search = self.request.GET.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(data__icontains=search) |
                Q(scan__target__name__icontains=search)
            )
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_results'] = ScanResult.objects.count()
        context['critical_count'] = ScanResult.objects.filter(severity='critical').count()
        context['high_count'] = ScanResult.objects.filter(severity='high').count()
        context['severities'] = ScanResult.SEVERITY_CHOICES
        context['result_types'] = ScanResult.RESULT_TYPE_CHOICES
        return context


class PortResultListView(LoginRequiredMixin, ListView):
    """List port results"""
    model = PortResult
    template_name = 'results/port_results.html'
    context_object_name = 'ports'
    paginate_by = 100
    
    def get_queryset(self):
        queryset = PortResult.objects.select_related('scan', 'scan__target')
        
        # Filter by state
        state = self.request.GET.get('state', '')
        if state:
            queryset = queryset.filter(state=state)
        
        # Filter by service
        service = self.request.GET.get('service', '')
        if service:
            queryset = queryset.filter(service__icontains=service)
        
        # Filter by scan
        scan_id = self.request.GET.get('scan', '')
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['open_ports'] = PortResult.objects.filter(state='open').count()
        context['filtered_ports'] = PortResult.objects.filter(state='filtered').count()
        context['closed_ports'] = PortResult.objects.filter(state='closed').count()
        return context


class VulnerabilityResultListView(LoginRequiredMixin, ListView):
    """List vulnerability results"""
    model = VulnerabilityResult
    template_name = 'results/vuln_results.html'
    context_object_name = 'vulnerabilities'
    paginate_by = 50
    
    def get_queryset(self):
        queryset = VulnerabilityResult.objects.select_related('scan', 'scan__target')
        
        # Filter by severity
        severity = self.request.GET.get('severity', '')
        if severity:
            queryset = queryset.filter(severity=severity)
        
        # Filter by status
        status = self.request.GET.get('status', '')
        if status:
            queryset = queryset.filter(status=status)
        
        # Search by CVE or title
        search = self.request.GET.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(cve_id__icontains=search) |
                Q(title__icontains=search)
            )
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['open_count'] = VulnerabilityResult.objects.filter(status='open').count()
        context['resolved_count'] = VulnerabilityResult.objects.filter(status='resolved').count()
        context['statuses'] = VulnerabilityResult.STATUS_CHOICES
        context['severities'] = VulnerabilityResult.SEVERITY_CHOICES if hasattr(VulnerabilityResult, 'SEVERITY_CHOICES') else ScanResult.SEVERITY_CHOICES
        return context


@login_required
def result_detail(request, pk):
    """View single result detail"""
    result = get_object_or_404(ScanResult, pk=pk)
    
    context = {
        'result': result,
        'scan': result.scan,
        'target': result.scan.target,
        'data_pretty': json.dumps(result.data, indent=2, default=str),
    }
    
    return render(request, 'results/result_detail.html', context)


@login_required
def vulnerability_detail(request, pk):
    """View vulnerability detail"""
    vuln = get_object_or_404(VulnerabilityResult, pk=pk)
    
    context = {
        'vuln': vuln,
        'scan': vuln.scan,
        'target': vuln.scan.target,
    }
    
    return render(request, 'results/vulnerability_detail.html', context)


@login_required
def update_vulnerability_status(request, pk):
    """Update vulnerability status (AJAX)"""
    if request.method == 'POST':
        vuln = get_object_or_404(VulnerabilityResult, pk=pk)
        
        status = request.POST.get('status', '')
        if status in dict(VulnerabilityResult.STATUS_CHOICES):
            vuln.status = status
            vuln.save()
            
            messages.success(request, f'Vulnerability status updated to {vuln.get_status_display()}')
            return JsonResponse({'success': True, 'status': status})
        
        return JsonResponse({'success': False, 'error': 'Invalid status'})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})


@login_required
def export_results_csv(request):
    """Export results to CSV"""
    # Get filter parameters
    severity = request.GET.get('severity', '')
    result_type = request.GET.get('result_type', '')
    
    # Query results
    results = ScanResult.objects.select_related('scan', 'scan__target')
    
    if severity:
        results = results.filter(severity=severity)
    if result_type:
        results = results.filter(result_type=result_type)
    
    # Create response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="scan_results.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Target', 'Scan Type', 'Result Type', 'Severity', 'Data', 'Created At'])
    
    for result in results:
        writer.writerow([
            result.scan.target.name,
            result.scan.get_scan_type_display(),
            result.get_result_type_display(),
            result.get_severity_display(),
            json.dumps(result.data),
            result.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    return response


@login_required
def export_ports_csv(request):
    """Export port results to CSV"""
    ports = PortResult.objects.select_related('scan', 'scan__target')
    
    # Filter
    state = request.GET.get('state', '')
    if state:
        ports = ports.filter(state=state)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="port_results.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Target', 'Port', 'Protocol', 'State', 'Service', 'Product', 'Version'])
    
    for port in ports:
        writer.writerow([
            port.scan.target.name,
            port.port,
            port.protocol,
            port.state,
            port.service,
            port.product,
            port.version
        ])
    
    return response


@login_required
def export_vulns_csv(request):
    """Export vulnerabilities to CSV"""
    vulns = VulnerabilityResult.objects.select_related('scan', 'scan__target')
    
    # Filter
    severity = request.GET.get('severity', '')
    if severity:
        vulns = vulns.filter(severity=severity)
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vulnerabilities.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Target', 'CVE ID', 'Title', 'Severity', 'CVSS Score', 'Service', 'Port', 'Status'])
    
    for vuln in vulns:
        writer.writerow([
            vuln.scan.target.name,
            vuln.cve_id,
            vuln.title,
            vuln.severity,
            vuln.cvss_score,
            vuln.affected_service,
            vuln.port,
            vuln.get_status_display()
        ])
    
    return response
