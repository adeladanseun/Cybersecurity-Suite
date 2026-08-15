"""
Dashboard services
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from core.logger import get_logger

logger = get_logger("web_dashboard")


class DashboardService:
    """Service for dashboard operations"""
    
    @classmethod
    def get_system_health(cls):
        """Get system health status"""
        health = {
            'database': cls._check_database(),
            'filesystem': cls._check_filesystem(),
            'scan_service': cls._check_scan_service(),
            'report_service': cls._check_report_service(),
        }
        
        return health
    
    @classmethod
    def _check_database(cls):
        """Check database health"""
        try:
            from django.db import connection
            connection.ensure_connection()
            return {'status': 'healthy', 'message': 'Database connected'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def _check_filesystem(cls):
        """Check filesystem health"""
        try:
            import shutil
            total, used, free = shutil.disk_usage('/')
            free_gb = free // (2**30)
            
            if free_gb < 1:
                return {'status': 'warning', 'message': f'Low disk space: {free_gb}GB free'}
            
            return {'status': 'healthy', 'message': f'{free_gb}GB free'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def _check_scan_service(cls):
        """Check scan service health"""
        try:
            from scans.models import Scan
            running = Scan.objects.filter(status='running').count()
            return {'status': 'healthy', 'message': f'{running} scans running'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    @classmethod
    def _check_report_service(cls):
        """Check report service health"""
        try:
            from reports.models import Report
            generating = Report.objects.filter(status='generating').count()
            return {'status': 'healthy', 'message': f'{generating} reports generating'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
