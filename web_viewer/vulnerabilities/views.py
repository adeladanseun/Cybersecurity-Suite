"""
Views for vulnerability management
"""

import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.db.models import Q, Count
from django.views.generic import ListView, DetailView, CreateView, UpdateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.utils import timezone

from .models import Vulnerability, RemediationTask, VulnerabilityNote
from .forms import VulnerabilityForm, VulnerabilityStatusForm, RemediationTaskForm, VulnerabilityNoteForm


class VulnerabilityListView(LoginRequiredMixin, ListView):
    """List all vulnerabilities"""

    model = Vulnerability
    template_name = "vulnerabilities/vuln_list.html"
    context_object_name = "vulnerabilities"
    paginate_by = 50

    def get_queryset(self):
        queryset = Vulnerability.objects.select_related(
            "scan", "scan__target", "assigned_to"
        )

        # Filter by severity
        severity = self.request.GET.get("severity", "")
        if severity:
            queryset = queryset.filter(severity=severity)

        # Filter by status
        status = self.request.GET.get("status", "")
        if status:
            queryset = queryset.filter(status=status)

        # Filter by priority
        priority = self.request.GET.get("priority", "")
        if priority:
            queryset = queryset.filter(priority=priority)

        # Filter by scan
        scan_id = self.request.GET.get("scan", "")
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)

        # Search
        search = self.request.GET.get("search", "")
        if search:
            queryset = queryset.filter(
                Q(cve_id__icontains=search)
                | Q(title__icontains=search)
                | Q(affected_service__icontains=search)
            )

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from scans.models import Scan

        context["total_vulns"] = Vulnerability.objects.count()
        context["open_vulns"] = Vulnerability.objects.filter(status="open").count()
        context["critical_vulns"] = Vulnerability.objects.filter(
            severity="critical"
        ).count()
        context["resolved_vulns"] = Vulnerability.objects.filter(
            status="resolved"
        ).count()
        context["severities"] = Vulnerability.SEVERITY_CHOICES
        context["statuses"] = Vulnerability.STATUS_CHOICES
        context["priorities"] = Vulnerability.PRIORITY_CHOICES
        context["scans"] = Scan.objects.select_related("target").order_by(
            "-created_at"
        )[:50]
        context["current_scan"] = self.request.GET.get("scan", "")
        return context


class VulnerabilityDetailView(LoginRequiredMixin, DetailView):
    """View vulnerability details"""
    model = Vulnerability
    template_name = 'vulnerabilities/vuln_detail.html'
    context_object_name = 'vuln'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vuln = self.get_object()
        context['tasks'] = vuln.remediation_tasks.all()
        context['notes'] = vuln.notes.select_related('author')
        context['status_form'] = VulnerabilityStatusForm(instance=vuln)
        context['task_form'] = RemediationTaskForm(initial={'vulnerability': vuln})
        context['note_form'] = VulnerabilityNoteForm()
        return context


class VulnerabilityCreateView(LoginRequiredMixin, CreateView):
    """Create new vulnerability"""
    model = Vulnerability
    form_class = VulnerabilityForm
    template_name = 'vulnerabilities/vuln_form.html'
    success_url = reverse_lazy('vulnerabilities:list')
    
    def form_valid(self, form):
        form.instance.discovered_by = self.request.user
        messages.success(self.request, 'Vulnerability created successfully.')
        return super().form_valid(form)


class VulnerabilityUpdateView(LoginRequiredMixin, UpdateView):
    """Update vulnerability"""
    model = Vulnerability
    form_class = VulnerabilityForm
    template_name = 'vulnerabilities/vuln_form.html'
    success_url = reverse_lazy('vulnerabilities:list')
    
    def form_valid(self, form):
        messages.success(self.request, 'Vulnerability updated successfully.')
        return super().form_valid(form)


@login_required
def vulnerability_dashboard(request):
    """Vulnerability statistics dashboard"""
    
    # Severity distribution
    severity_counts = Vulnerability.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('severity')
    
    # Status distribution
    status_counts = Vulnerability.objects.values('status').annotate(
        count=Count('id')
    ).order_by('status')
    
    # Priority distribution
    priority_counts = Vulnerability.objects.values('priority').annotate(
        count=Count('id')
    ).order_by('priority')
    
    # Recent vulnerabilities
    recent_vulns = Vulnerability.objects.order_by('-created_at')[:10]
    
    # Most affected services
    affected_services = Vulnerability.objects.values('affected_service').annotate(
        count=Count('id')
    ).exclude(affected_service='').order_by('-count')[:10]
    
    # Monthly trend
    from django.db.models.functions import TruncMonth
    monthly_trend = Vulnerability.objects.annotate(
        month=TruncMonth('created_at')
    ).values('month').annotate(
        count=Count('id')
    ).order_by('month')
    
    context = {
        'severity_counts': list(severity_counts),
        'status_counts': list(status_counts),
        'priority_counts': list(priority_counts),
        'recent_vulns': recent_vulns,
        'affected_services': list(affected_services),
        'monthly_trend': list(monthly_trend),
        'total_vulns': Vulnerability.objects.count(),
        'open_vulns': Vulnerability.objects.filter(status='open').count(),
        'critical_vulns': Vulnerability.objects.filter(severity='critical').count(),
        'high_vulns': Vulnerability.objects.filter(severity='high').count(),
    }
    
    return render(request, 'vulnerabilities/vuln_dashboard.html', context)


@login_required
def update_status(request, pk):
    """Update vulnerability status"""
    vuln = get_object_or_404(Vulnerability, pk=pk)
    
    if request.method == 'POST':
        form = VulnerabilityStatusForm(request.POST, instance=vuln)
        
        if form.is_valid():
            updated_vuln = form.save()
            
            # If status is resolved, set resolved_at
            if updated_vuln.status == 'resolved' and not updated_vuln.resolved_at:
                updated_vuln.resolved_at = timezone.now()
                updated_vuln.resolved_by = request.user
                updated_vuln.save()
            
            messages.success(request, f'Status updated to {updated_vuln.get_status_display()}')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'status': updated_vuln.status,
                    'status_display': updated_vuln.get_status_display(),
                })
        
        return redirect('vulnerabilities:detail', pk=vuln.id)
    
    return redirect('vulnerabilities:detail', pk=vuln.id)


@login_required
def add_note(request, pk):
    """Add note to vulnerability"""
    vuln = get_object_or_404(Vulnerability, pk=pk)
    
    if request.method == 'POST':
        form = VulnerabilityNoteForm(request.POST)
        
        if form.is_valid():
            note = form.save(commit=False)
            note.vulnerability = vuln
            note.author = request.user
            note.save()
            
            messages.success(request, 'Note added.')
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'note_id': str(note.id),
                    'author': note.author.username,
                    'content': note.content,
                    'created_at': note.created_at.strftime('%Y-%m-%d %H:%M'),
                })
    
    return redirect('vulnerabilities:detail', pk=vuln.id)


@login_required
def add_task(request, pk):
    """Add remediation task to vulnerability"""
    vuln = get_object_or_404(Vulnerability, pk=pk)
    
    if request.method == 'POST':
        form = RemediationTaskForm(request.POST)
        
        if form.is_valid():
            task = form.save(commit=False)
            task.vulnerability = vuln
            task.save()
            
            messages.success(request, 'Remediation task created.')
    
    return redirect('vulnerabilities:detail', pk=vuln.id)


@login_required
def export_vulnerabilities(request):
    """Export vulnerabilities to CSV"""
    import csv

    vulns = Vulnerability.objects.select_related('scan', 'scan__target', 'assigned_to')

    # Apply filters
    severity = request.GET.get('severity', '')
    if severity:
        vulns = vulns.filter(severity=severity)

    status = request.GET.get('status', '')
    if status:
        vulns = vulns.filter(status=status)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vulnerabilities.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'CVE ID', 'Title', 'Severity', 'CVSS Score', 'Priority', 'Status',
        'Target', 'Service', 'Port', 'Assigned To', 'Created At', 'Resolved At'
    ])

    for vuln in vulns:
        writer.writerow([
            vuln.cve_id,
            vuln.title,
            vuln.severity,
            vuln.cvss_score,
            vuln.priority,
            vuln.status,
            vuln.scan.target.name if vuln.scan else 'N/A',
            vuln.affected_service,
            vuln.port,
            vuln.assigned_to.username if vuln.assigned_to else 'Unassigned',
            vuln.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            vuln.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if vuln.resolved_at else ''
        ])

    return response


@login_required
def cve_search(request):
    """Search CVE database"""
    results = []
    query = ""
    search_type = "service"

    if request.GET.get("query"):
        query = request.GET.get("query")
        search_type = request.GET.get("search_type", "service")

        # Add parent directory to path for core modules
        import sys
        from pathlib import Path

        parent_dir = Path(__file__).resolve().parent.parent.parent
        if str(parent_dir) not in sys.path:
            sys.path.insert(0, str(parent_dir))

        from tools.vuln_checker import CVELookup

        cve = CVELookup()

        if search_type == "cve":
            result = cve.lookup_cve(query.upper())
            if result:
                results = [result]
        else:
            results = cve.search_by_service(query)

    context = {
        "results": results,
        "query": query,
        "search_type": search_type,
        "result_count": len(results),
    }

    return render(request, "vulnerabilities/cve_search.html", context)


@login_required
def cred_check(request):
    """Check for default credentials on devices"""
    import sys
    from pathlib import Path

    parent_dir = Path(__file__).resolve().parent.parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))

    from tools.exploitation import DefaultCredChecker

    result = None
    target = ""
    device_type = "router"

    if request.GET.get("target"):
        target = request.GET.get("target")
        device_type = request.GET.get("device_type", "router")

        checker = DefaultCredChecker()
        result = checker.check_device(target, device_type)

    context = {
        "result": result,
        "target": target,
        "device_type": device_type,
        "device_types": ["router", "camera", "printer", "nas", "switch", "firewall"],
    }

    return render(request, "vulnerabilities/cred_check.html", context)
