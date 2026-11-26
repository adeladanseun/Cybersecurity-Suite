"""
Management command to clean up old data
Usage: python manage.py cleanup_old_data --days 30
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta


class Command(BaseCommand):
    help = 'Clean up old scan data and temporary files'
    
    def handle(self, *args, **options):
        
        # Clean up old scans
        from scans.models import Scan
        old_scans = Scan.objects.all()
        
        scan_count = old_scans.count()
        old_scans.delete()
        self.stdout.write(f'Deleted {scan_count} old scans')
        
        # Clean up old notifications
        from notifications.models import Notification
        all_notifications = Notification.objects.all()
        
        notification_count = all_notifications.count()
        all_notifications.delete()
        self.stdout.write(f'Deleted {notification_count} old notifications')
        
        # Clean up old reports
        from reports.models import Report
        old_reports = Report.objects.all()
        
        report_count = old_reports.count()
        for report in old_reports:
            if report.file:
                report.file.delete(save=False)
        old_reports.delete()
        self.stdout.write(f'Deleted {report_count} old reports')
        


        from targets.models import Target 
        targets = Target.objects.all()
        target_count = targets.count()
        targets.delete()
        self.stdout.write(f'Deleted {target_count} targets')


        

        self.stdout.write(self.style.SUCCESS('Cleanup complete!'))