"""
Dashboard views
"""

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Sum
from django.utils import timezone
from datetime import timedelta


@login_required
def dashboard_index(request):
    """Main dashboard view"""
    from targets.models import Target
    from scans.models import Scan
    from vulnerabilities.models import Vulnerability
    from reports.models import Report
    from notifications.models import Notification
    
    # Basic stats
    total_targets = Target.objects.filter(is_active=True).count()
    total_scans = Scan.objects.count()
    running_scans = Scan.objects.filter(status='running').count()
    total_vulns = Vulnerability.objects.count()
    open_vulns = Vulnerability.objects.filter(status='open').count()
    total_reports = Report.objects.count()
    
    # Recent scans
    recent_scans = Scan.objects.select_related('target').order_by('-created_at')[:5]
    
    # Recent vulnerabilities
    recent_vulns = Vulnerability.objects.select_related('scan').order_by('-created_at')[:5]
    
    # Recent notifications
    recent_notifications = Notification.objects.filter(
        user=request.user,
        is_read=False
    ).order_by('-created_at')[:5]
    
    # Scan activity (last 7 days)
    week_ago = timezone.now() - timedelta(days=7)
    scans_this_week = Scan.objects.filter(created_at__gte=week_ago).count()
    vulns_this_week = Vulnerability.objects.filter(created_at__gte=week_ago).count()
    
    # Severity distribution
    severity_dist = Vulnerability.objects.values('severity').annotate(
        count=Count('id')
    ).order_by('severity')
    
    context = {
        'total_targets': total_targets,
        'total_scans': total_scans,
        'running_scans': running_scans,
        'total_vulns': total_vulns,
        'open_vulns': open_vulns,
        'total_reports': total_reports,
        'recent_scans': recent_scans,
        'recent_vulns': recent_vulns,
        'recent_notifications': recent_notifications,
        'scans_this_week': scans_this_week,
        'vulns_this_week': vulns_this_week,
        'severity_dist': severity_dist,
    }
    
    return render(request, 'dashboard/index.html', context)


@login_required
def dashboard_stats(request):
    """Detailed statistics dashboard"""
    from targets.models import Target
    from scans.models import Scan
    from vulnerabilities.models import Vulnerability
    from reports.models import Report
    from django.db.models.functions import TruncDate
    
    # Targets by type
    targets_by_type = Target.objects.values('type').annotate(count=Count('id'))
    
    # Scans by type
    scans_by_type = Scan.objects.values('scan_type').annotate(count=Count('id'))
    
    # Scans by day (last 30 days)
    month_ago = timezone.now() - timedelta(days=30)
    scans_by_day = Scan.objects.filter(created_at__gte=month_ago).annotate(
        day=TruncDate('created_at')
    ).values('day').annotate(count=Count('id')).order_by('day')
    
    # Vulnerabilities by severity
    vulns_by_severity = Vulnerability.objects.values('severity').annotate(count=Count('id'))
    
    # Top affected services
    top_services = Vulnerability.objects.exclude(affected_service='').values(
        'affected_service'
    ).annotate(count=Count('id')).order_by('-count')[:10]
    
    # Report generation stats
    reports_by_format = Report.objects.values('format').annotate(count=Count('id'))
    
    context = {
        'targets_by_type': targets_by_type,
        'scans_by_type': scans_by_type,
        'scans_by_day': scans_by_day,
        'vulns_by_severity': vulns_by_severity,
        'top_services': top_services,
        'reports_by_format': reports_by_format,
    }
    
    return render(request, 'dashboard/stats.html', context)


@login_required
def dashboard_activity(request):
    """Recent activity feed"""
    from scans.models import Scan
    from vulnerabilities.models import Vulnerability
    from reports.models import Report
    
    # Get recent activity
    recent_scans = list(Scan.objects.select_related('target', 'initiated_by').order_by('-created_at')[:20])
    recent_vulns = list(Vulnerability.objects.select_related('scan').order_by('-created_at')[:20])
    recent_reports = list(Report.objects.select_related('scan').order_by('-created_at')[:20])
    
    # Combine and sort
    activity = []
    
    for scan in recent_scans:
        activity.append({
            'type': 'scan',
            'icon': 'radar',
            'title': f'{scan.get_scan_type_display()} on {scan.target.name}',
            'status': scan.status,
            'timestamp': scan.created_at,
        })
    
    for vuln in recent_vulns:
        activity.append({
            'type': 'vulnerability',
            'icon': 'exclamation-triangle',
            'title': f'{vuln.severity.upper()}: {vuln.title}',
            'status': vuln.status,
            'timestamp': vuln.created_at,
        })
    
    for report in recent_reports:
        activity.append({
            'type': 'report',
            'icon': 'file-alt',
            'title': f'Report: {report.name}',
            'status': report.status,
            'timestamp': report.created_at,
        })
    
    # Sort by timestamp
    activity.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render(request, 'dashboard/activity.html', {'activity': activity[:50]})
