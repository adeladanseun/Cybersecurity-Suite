"""
CyberSecurity Suite - Core Framework
Foundation library providing file management, validation, logging,
configuration, notifications, and database operations.

Version: 1.0.0
Phase 1: Core Framework
"""

__version__ = "1.0.0"
__author__ = "Adeladan Oluwaseun Francis"
__license__ = "MIT"

from core.exceptions import (
    CyberSuiteError,
    ValidationError,
    FileManagerError,
    ScanError,
    ConfigError,
    DatabaseError,
    ToolNotFoundError
) 

from core.validator import (
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_private_ip,
    is_public_ip,
    is_valid_cidr,
    is_valid_ip_range,
    is_valid_domain,
    is_valid_url,
    is_valid_hostname,
    is_valid_port,
    is_valid_port_range,
    classify_target,
    get_target_type,
    is_valid_file,
    is_valid_json
)

from core.logger import CyberLogger, get_logger

from core.config import Config

from core.notifier import Notifier

from core.file_manager import FileManager

from core.database import Database

__all__ = [
    # Version
    '__version__',
    
    # Exceptions
    'CyberSuiteError',
    'ValidationError',
    'FileManagerError',
    'ScanError',
    'ConfigError',
    'DatabaseError',
    'ToolNotFoundError',
    
    # Validator
    'is_valid_ip',
    'is_valid_ipv4',
    'is_valid_ipv6',
    'is_private_ip',
    'is_public_ip',
    'is_valid_cidr',
    'is_valid_ip_range',
    'is_valid_domain',
    'is_valid_url',
    'is_valid_hostname',
    'is_valid_port',
    'is_valid_port_range',
    'classify_target',
    'get_target_type',
    'is_valid_file',
    'is_valid_json',
    
    # Logger
    'CyberLogger',
    'get_logger',
    
    # Config
    'Config',
    
    # Notifier
    'Notifier',
    
    # File Manager
    'FileManager',
    
    # Database
    'Database'
]