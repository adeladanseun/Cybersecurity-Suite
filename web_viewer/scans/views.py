"""
Views for scan management
"""

import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q
from django.views.generic import ListView, DetailView, CreateView
from django.urls import reverse_lazy
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone

from .models import Scan, ScheduledScan
from .forms import ScanForm, QuickScanForm, ScheduledScanForm
from .services import ScanService
from targets.models import Target


class ScanListView(LoginRequiredMixin, ListView):
    """List all scans"""
    model = Scan
    template_name = 'scans/scan_list.html'
    context_object_name = 'scans'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = Scan.objects.all()
        
        # Filter by status
        status = self.request.GET.get('status', '')
        if status:
            queryset = queryset.filter(status=status)
        
        # Filter by scan type
        scan_type = self.request.GET.get('scan_type', '')
        if scan_type:
            queryset = queryset.filter(scan_type=scan_type)
        
        # Search by target
        search = self.request.GET.get('search', '')
        if search:
            queryset = queryset.filter(
                Q(target__name__icontains=search) |
                Q(target__address__icontains=search)
            )
        
        return queryset.select_related('target', 'initiated_by')
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['active_scans'] = Scan.objects.filter(status='running').count()
        context['completed_scans'] = Scan.objects.filter(status='completed').count()
        context['failed_scans'] = Scan.objects.filter(status='failed').count()
        context['scan_types'] = Scan.SCAN_TYPE_CHOICES
        context['statuses'] = Scan.STATUS_CHOICES
        return context


class ScanDetailView(LoginRequiredMixin, DetailView):
    """View scan details"""
    model = Scan
    template_name = 'scans/scan_detail.html'
    context_object_name = 'scan'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scan = self.get_object()
        context['is_active'] = scan.is_active()
        context['results'] = self.get_scan_results(scan)

        # Calculate risk score if results exist
        if context["results"]:
            try:
                import sys
                from pathlib import Path

                parent_dir = Path(__file__).resolve().parent.parent.parent
                if str(parent_dir) not in sys.path:
                    sys.path.insert(0, str(parent_dir))

                from tools.report_builder import RiskCalculator

                calculator = RiskCalculator()

                # Check if results have nested port_scan structure
                risk_data = context["results"]
                if "port_scan" in risk_data and "ports" not in risk_data:
                    risk_data = risk_data["port_scan"]

                context["risk"] = calculator.calculate_risk_score(risk_data)
            except Exception as e:
                print(f"Risk calculation error: {e}")
                context["risk"] = None
        else:
            context["risk"] = None

        return context

    def get_scan_results(self, scan):
        """Get scan results if available"""
        if scan.results_file:
            try:
                with scan.results_file.open('r') as f:
                    return json.load(f)
            except Exception:
                return None
        return None


class ScanCreateView(LoginRequiredMixin, CreateView):
    """Create new scan"""
    model = Scan
    form_class = ScanForm
    template_name = 'scans/scan_new.html'
    success_url = reverse_lazy('scans:list')
    
    def form_valid(self, form):
        form.instance.initiated_by = self.request.user
        form.instance.status = 'pending'
        
        response = super().form_valid(form)
        
        # Start scan in background
        scan = self.object
        ScanService.start_scan(scan)
        
        messages.success(self.request, f'Scan started on {scan.target.name}')
        return redirect('scans:detail', pk=scan.id)


@login_required
def quick_scan(request):
    """Quick scan view"""
    if request.method == 'POST':
        form = QuickScanForm(request.POST)
        
        if form.is_valid():
            target = form.cleaned_data['target']
            scan_type = form.cleaned_data['scan_type']
            
            # Create scan
            scan = Scan.objects.create(
                target=target,
                scan_type=scan_type,
                status='pending',
                initiated_by=request.user
            )
            
            # Start scan
            ScanService.start_scan(scan)
            
            messages.success(request, f'Quick scan started on {target.name}')
            return redirect('scans:detail', pk=scan.id)
    else:
        form = QuickScanForm()
    
    return render(request, 'scans/scan_new.html', {'form': form, 'quick': True})


@login_required
def scan_progress(request, pk):
    """Get scan progress (AJAX endpoint)"""
    scan = get_object_or_404(Scan, pk=pk)
    
    data = {
        'status': scan.status,
        'progress': scan.progress,
        'is_active': scan.is_active(),
    }
    
    return JsonResponse(data)


@login_required
def scan_results(request, pk):
    """View scan results"""
    scan = get_object_or_404(Scan, pk=pk)
    
    results = None
    if scan.results_file:
        try:
            with scan.results_file.open('r') as f:
                results = json.load(f)
        except Exception:
            results = None
    
    context = {
        'scan': scan,
        'results': results,
    }
    
    return render(request, 'scans/scan_results.html', context)


@login_required
def cancel_scan(request, pk):
    """Cancel a running scan"""
    scan = get_object_or_404(Scan, pk=pk)
    
    if request.method == 'POST':
        if scan.is_active():
            scan.status = 'cancelled'
            scan.completed_at = timezone.now()
            scan.save()
            messages.warning(request, f'Scan on {scan.target.name} cancelled.')
        else:
            messages.error(request, 'Scan is not active.')
        
        return redirect('scans:detail', pk=scan.id)
    
    return render(request, 'scans/scan_confirm_cancel.html', {'scan': scan})


class ScheduledScanListView(LoginRequiredMixin, ListView):
    """List scheduled scans"""
    model = ScheduledScan
    template_name = 'scans/scan_schedule.html'
    context_object_name = 'scheduled_scans'
    
    def get_queryset(self):
        return ScheduledScan.objects.filter(is_active=True)


class ScheduledScanCreateView(LoginRequiredMixin, CreateView):
    """Create scheduled scan"""
    model = ScheduledScan
    form_class = ScheduledScanForm
    template_name = 'scans/scan_schedule_form.html'
    success_url = reverse_lazy('scans:schedule_list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        messages.success(self.request, 'Scan scheduled successfully.')
        return super().form_valid(form)


@login_required
def toggle_schedule(request, pk):
    """Toggle scheduled scan active status"""
    scheduled = get_object_or_404(ScheduledScan, pk=pk)
    scheduled.is_active = not scheduled.is_active
    scheduled.save()
    
    status = 'activated' if scheduled.is_active else 'deactivated'
    messages.info(request, f'Scheduled scan {status}.')
    
    return redirect('scans:schedule_list')

@login_required
def compare_scans(request):
    """Compare two scans"""
    import sys
    from pathlib import Path
    parent_dir = Path(__file__).resolve().parent.parent.parent
    if str(parent_dir) not in sys.path:
        sys.path.insert(0, str(parent_dir))
    
    from tools.port_scanner import ScanDiffer
    import json as json_module
    
    scan1 = None
    scan2 = None
    diff = None
    
    if request.GET.get('scan1') and request.GET.get('scan2'):
        scan1 = get_object_or_404(Scan, pk=request.GET.get('scan1'))
        scan2 = get_object_or_404(Scan, pk=request.GET.get('scan2'))
        
        # Load results from JSON files
        data1 = None
        data2 = None
        
        if scan1.results_file:
            try:
                with scan1.results_file.open('r') as f:
                    data1 = json_module.load(f)
            except Exception:
                data1 = None
        
        if scan2.results_file:
            try:
                with scan2.results_file.open('r') as f:
                    data2 = json_module.load(f)
            except Exception:
                data2 = None
        
        # Handle nested port_scan structure
        if data1 and 'port_scan' in data1 and 'ports' not in data1:
            data1 = data1['port_scan']
        if data2 and 'port_scan' in data2 and 'ports' not in data2:
            data2 = data2['port_scan']
        
        if data1 and data2:
            differ = ScanDiffer()
            diff = differ.compare_scans(data1, data2)
    
    context = {
        'scans': Scan.objects.select_related('target').filter(status='completed').order_by('-created_at')[:50],
        'scan1': scan1,
        'scan2': scan2,
        'diff': diff,
    }
    
    return render(request, 'scans/scan_compare.html', context)




    