"""
Path setup utility for CyberSecurity Suite Web Viewer
Ensures Django can find core modules from parent directory
"""

import os
import sys
from pathlib import Path


def setup_project_path():
    """
    Add parent directory to Python path so Django can import core modules.
    Call this at the start of any module that needs core access.
    """
    # Get the web_viewer directory
    web_viewer_dir = Path(__file__).resolve().parent.parent
    
    # Get the parent directory (main project root)
    project_root = web_viewer_dir.parent
    
    # Add to Python path if not already there
    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)
    
    # Also set environment variable for subprocesses
    pythonpath = os.environ.get('PYTHONPATH', '')
    if project_root_str not in pythonpath:
        os.environ['PYTHONPATH'] = f"{project_root_str}:{pythonpath}" if pythonpath else project_root_str
    
    return project_root


def get_project_root():
    """Get the main project root directory"""
    web_viewer_dir = Path(__file__).resolve().parent.parent
    return web_viewer_dir.parent


def get_reports_dir():
    """Get the reports directory"""
    return get_project_root() / 'reports'


def get_data_dir():
    """Get the data directory"""
    return get_project_root() / 'data'
