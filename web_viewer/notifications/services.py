"""
Notification services
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from core.logger import get_logger

logger = get_logger("web_notifications")


class NotificationService:
    """Service for creating and managing notifications"""
    
    @classmethod
    def create_notification(cls, user, title, message, notification_type='system', 
                           priority='medium', link=''):
        """
        Create a notification for a user.
        
        Args:
            user: User instance
            title: Notification title
            message: Notification message
            notification_type: Type of notification
            priority: Priority level
            link: Optional link
        """
        from notifications.models import Notification
        
        notification = Notification.objects.create(
            user=user,
            title=title,
            message=message,
            notification_type=notification_type,
            priority=priority,
            link=link
        )
        
        logger.info(f"Notification created for {user.username}: {title}")
        return notification
    
    @classmethod
    def notify_scan_complete(cls, user, scan):
        """Notify user that scan is complete"""
        cls.create_notification(
            user=user,
            title=f'Scan Complete: {scan.target.name}',
            message=f'{scan.get_scan_type_display()} completed successfully.',
            notification_type='scan_complete',
            priority='medium',
            link=f'/scans/{scan.id}/'
        )
    
    @classmethod
    def notify_scan_failed(cls, user, scan, error=None):
        """Notify user that scan failed"""
        message = f'{scan.get_scan_type_display()} failed.'
        if error:
            message += f' Error: {error}'
        
        cls.create_notification(
            user=user,
            title=f'Scan Failed: {scan.target.name}',
            message=message,
            notification_type='scan_failed',
            priority='high',
            link=f'/scans/{scan.id}/'
        )
    
    @classmethod
    def notify_vulnerability_found(cls, user, vulnerability):
        """Notify user of new vulnerability"""
        severity = vulnerability.severity.upper()
        priority = 'urgent' if severity in ['critical', 'high'] else 'medium'
        
        cls.create_notification(
            user=user,
            title=f'{severity} Vulnerability Found',
            message=f'{vulnerability.title} ({vulnerability.cve_id or "No CVE"})',
            notification_type='vulnerability_found',
            priority=priority,
            link=f'/vulnerabilities/{vulnerability.id}/'
        )
    
    @classmethod
    def notify_report_ready(cls, user, report):
        """Notify user that report is ready"""
        cls.create_notification(
            user=user,
            title=f'Report Ready: {report.name}',
            message=f'{report.get_report_type_display()} report generated in {report.get_format_display()} format.',
            notification_type='report_ready',
            priority='medium',
            link=f'/reports/{report.id}/'
        )
    
    @classmethod
    def notify_all_admins(cls, title, message, notification_type='system', priority='medium', link=''):
        """Notify all admin users"""
        from django.contrib.auth.models import User
        
        admins = User.objects.filter(is_staff=True)
        for admin in admins:
            cls.create_notification(
                user=admin,
                title=title,
                message=message,
                notification_type=notification_type,
                priority=priority,
                link=link
            )
