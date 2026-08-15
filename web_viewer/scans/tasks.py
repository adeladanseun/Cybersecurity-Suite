"""
Background task definitions for scans
Using threading for now, can be migrated to Celery later
"""

import logging
from datetime import datetime, timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)


def check_scheduled_scans():
    """Check and run scheduled scans"""
    from scans.models import ScheduledScan, Scan
    from scans.services import ScanService
    
    now = timezone.now()
    
    # Find scans that need to run
    scheduled_scans = ScheduledScan.objects.filter(
        is_active=True,
        next_run__lte=now
    )
    
    for scheduled in scheduled_scans:
        logger.info(f"Running scheduled scan: {scheduled}")
        
        try:
            # Create scan from schedule
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
            scheduled.next_run = calculate_next_run(scheduled)
            scheduled.save()
            
        except Exception as e:
            logger.error(f"Failed to run scheduled scan: {e}")


def calculate_next_run(scheduled):
    """Calculate next run time based on frequency"""
    now = timezone.now()
    
    if scheduled.frequency == 'once':
        return None
    elif scheduled.frequency == 'hourly':
        return now + timedelta(hours=1)
    elif scheduled.frequency == 'daily':
        next_run = now + timedelta(days=1)
        return next_run.replace(
            hour=scheduled.schedule_time.hour,
            minute=scheduled.schedule_time.minute,
            second=0
        )
    elif scheduled.frequency == 'weekly':
        return now + timedelta(weeks=1)
    elif scheduled.frequency == 'monthly':
        return now + timedelta(days=30)
    else:
        return None
