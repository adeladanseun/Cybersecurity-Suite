"""
WSGI config for CyberSecurity Suite Web Viewer
"""

import os
import sys
from pathlib import Path

from django.core.wsgi import get_wsgi_application

# Add parent directory to Python path
parent_dir = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(parent_dir))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_wsgi_application()
