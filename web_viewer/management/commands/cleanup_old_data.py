"""
Management command to clean up old data
Usage: python manage.py cleanup_old_data --days 30
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta


class Command(BaseCommand):
    help = 'Clean up old scan data and temporary files'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Delete data older than this many days'
        )
    
    def handle(self, *args, **options):
        days = options['days']
        cutoff = timezone.now() - timedelta(days=days)
        
        self.stdout.write(f'Cleaning up data older than {days} days...')
        
        # Clean up old scans
        from scans.models import Scan
        old_scans = Scan.objects.filter(
            created_at__lt=cutoff,
            status='completed'
        )
        
        scan_count = old_scans.count()
        old_scans.delete()
        self.stdout.write(f'Deleted {scan_count} old scans')
        
        # Clean up old notifications
        from notifications.models import Notification
        old_notifications = Notification.objects.filter(
            created_at__lt=cutoff,
            is_read=True
        )
        
        notification_count = old_notifications.count()
        old_notifications.delete()
        self.stdout.write(f'Deleted {notification_count} old notifications')
        
        # Clean up old reports
        from reports.models import Report
        old_reports = Report.objects.filter(
            created_at__lt=cutoff,
            status='completed'
        )
        
        report_count = old_reports.count()
        for report in old_reports:
            if report.file:
                report.file.delete(save=False)
        old_reports.delete()
        self.stdout.write(f'Deleted {report_count} old reports')
        
        self.stdout.write(self.style.SUCCESS('Cleanup complete!'))
