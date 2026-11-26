"""
Management command to run scheduled scans
Usage: python manage.py run_scheduled_scans
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta


class Command(BaseCommand):
    help = 'Run scheduled scans that are due'
    
    def handle(self, *args, **options):
        from scans.models import ScheduledScan, Scan
        from scans.services import ScanService
        
        now = timezone.now()
        
        # Find due scheduled scans
        scheduled_scans = ScheduledScan.objects.filter(
            is_active=True,
            next_run__lte=now
        )
        
        self.stdout.write(f'Found {scheduled_scans.count()} scheduled scans to run')
        
        for scheduled in scheduled_scans:
            self.stdout.write(f'Running scheduled scan: {scheduled}')
            
            try:
                # Create scan
                scan = Scan.objects.create(
                    target=scheduled.target,
                    scan_type=scheduled.scan_type,
                    status='pending',
                    parameters=scheduled.parameters,
                    initiated_by=scheduled.created_by
                )
                
                # Start scan
                ScanService.start_scan(scan)
                
                # Update schedule
                scheduled.last_run = now
                scheduled.next_run = self.calculate_next_run(scheduled)
                scheduled.save()
                
                self.stdout.write(self.style.SUCCESS(f'Scan started: {scan.id}'))
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Failed to run scheduled scan: {e}'))
    
    def calculate_next_run(self, scheduled):
        """Calculate next run time"""
        now = timezone.now()
        
        if scheduled.frequency == 'hourly':
            return now + timedelta(hours=1)
        elif scheduled.frequency == 'daily':
            return now + timedelta(days=1)
        elif scheduled.frequency == 'weekly':
            return now + timedelta(weeks=1)
        elif scheduled.frequency == 'monthly':
            return now + timedelta(days=30)
        else:
            return None
