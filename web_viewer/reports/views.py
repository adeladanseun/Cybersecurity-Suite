"""
Views for report generation and management
"""

import os
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from django.db.models import Q
from django.views.generic import ListView, DetailView, CreateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone

from .models import Report, ReportTemplate
from .forms import ReportGenerationForm, ReportTemplateForm
from .services import ReportService
from scans.models import Scan


class ReportListView(LoginRequiredMixin, ListView):
    """List all reports"""
    model = Report
    template_name = 'reports/report_list.html'
    context_object_name = 'reports'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = Report.objects.select_related('scan', 'scan__target', 'generated_by')
        
        # Filter by type
        report_type = self.request.GET.get('report_type', '')
        if report_type:
            queryset = queryset.filter(report_type=report_type)
        
        # Filter by format
        format_type = self.request.GET.get('format', '')
        if format_type:
            queryset = queryset.filter(format=format_type)
        
        # Search
        search = self.request.GET.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) |
                Q(scan__target__name__icontains=search)
            )
        
        return queryset
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_reports'] = Report.objects.count()
        context['completed_reports'] = Report.objects.filter(status='completed').count()
        context['report_types'] = Report.REPORT_TYPE_CHOICES
        context['formats'] = Report.FORMAT_CHOICES
        return context


class ReportGenerateView(LoginRequiredMixin, CreateView):
    """Generate new report"""
    model = Report
    form_class = ReportGenerationForm
    template_name = 'reports/report_generate.html'
    success_url = reverse_lazy('reports:list')
    
    def form_valid(self, form):
        form.instance.generated_by = self.request.user
        form.instance.status = 'pending'
        
        response = super().form_valid(form)
        
        # Generate report in background
        report = self.object
        ReportService.generate_report(report)
        
        messages.success(self.request, f'Report "{report.name}" generation started.')
        return redirect('reports:detail', pk=report.id)


class ReportDetailView(LoginRequiredMixin, DetailView):
    """View report details"""
    model = Report
    template_name = 'reports/report_detail.html'
    context_object_name = 'report'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        report = self.get_object()
        context['is_ready'] = report.status == 'completed' and report.file
        return context


@login_required
def download_report(request, pk):
    """Download report file"""
    report = get_object_or_404(Report, pk=pk)

    if report.file and report.status == 'completed':
        # Increment download count
        report.increment_download_count()

        # Serve file
        return FileResponse(
            report.file.open('rb'),
            as_attachment=True,
            filename=os.path.basename(report.file.name)
        )

    messages.error(request, 'Report file not available.')
    return redirect('reports:detail', pk=report.id)


@login_required
def preview_report(request, pk):
    """Preview report file inline (no download)"""
    report = get_object_or_404(Report, pk=pk)

    if report.file and report.status == "completed":
        content_type = "application/pdf" if report.format == "pdf" else None
        return FileResponse(
            report.file.open("rb"), as_attachment=False, content_type=content_type
        )

    messages.error(request, "Report file not available.")
    return redirect("reports:detail", pk=report.id)


@login_required
def report_progress(request, pk):
    """Get report generation progress (AJAX)"""
    report = get_object_or_404(Report, pk=pk)
    
    data = {
        'status': report.status,
        'is_ready': report.status == 'completed' and bool(report.file),
    }
    
    return JsonResponse(data)


class ReportTemplateListView(LoginRequiredMixin, ListView):
    """List report templates"""
    model = ReportTemplate
    template_name = 'reports/report_template_list.html'
    context_object_name = 'templates'
    
    def get_queryset(self):
        return ReportTemplate.objects.filter(is_active=True)


class ReportTemplateCreateView(LoginRequiredMixin, CreateView):
    """Create report template"""
    model = ReportTemplate
    form_class = ReportTemplateForm
    template_name = 'reports/report_template_form.html'
    success_url = reverse_lazy('reports:template_list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, f'Template "{form.instance.name}" created.')
        return super().form_valid(form)


@login_required
def export_report_data(request, pk):
    """Export report data as JSON"""
    report = get_object_or_404(Report, pk=pk)
    
    data = {
        'id': str(report.id),
        'name': report.name,
        'report_type': report.report_type,
        'format': report.format,
        'status': report.status,
        'generated_at': report.generated_at.isoformat() if report.generated_at else None,
        'download_count': report.download_count,
        'file_size': report.file_size,
    }
    
    if report.scan:
        data['scan'] = {
            'id': str(report.scan.id),
            'scan_type': report.scan.scan_type,
            'target': report.scan.target.name,
            'target_address': report.scan.target.address,
        }
    
    response = HttpResponse(
        json.dumps(data, indent=2),
        content_type='application/json'
    )
    response['Content-Disposition'] = f'attachment; filename="report_{report.id}.json"'
    
    return response
