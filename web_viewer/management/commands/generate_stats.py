"""
Management command to generate statistics report
Usage: python manage.py generate_stats
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
import json
import os


class Command(BaseCommand):
    help = 'Generate statistics report'
    
    def handle(self, *args, **options):
        from targets.models import Target
        from scans.models import Scan
        from vulnerabilities.models import Vulnerability
        from reports.models import Report
        from django.db.models import Count
        
        self.stdout.write('Generating statistics...')
        
        # Collect stats
        stats = {
            'generated_at': timezone.now().isoformat(),
            'targets': {
                'total': Target.objects.count(),
                'active': Target.objects.filter(is_active=True).count(),
                'by_type': list(Target.objects.values('type').annotate(count=Count('id'))),
            },
            'scans': {
                'total': Scan.objects.count(),
                'by_status': list(Scan.objects.values('status').annotate(count=Count('id'))),
                'by_type': list(Scan.objects.values('scan_type').annotate(count=Count('id'))),
            },
            'vulnerabilities': {
                'total': Vulnerability.objects.count(),
                'by_severity': list(Vulnerability.objects.values('severity').annotate(count=Count('id'))),
                'open': Vulnerability.objects.filter(status='open').count(),
            },
            'reports': {
                'total': Report.objects.count(),
                'by_format': list(Report.objects.values('format').annotate(count=Count('id'))),
            },
        }
        
        # Save to file
        stats_dir = os.path.join(os.getcwd(), 'data', 'stats')
        os.makedirs(stats_dir, exist_ok=True)
        
        filename = f"stats_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(stats_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        
        self.stdout.write(self.style.SUCCESS(f'Statistics saved to {filepath}'))
