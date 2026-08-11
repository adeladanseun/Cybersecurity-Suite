"""
Configuration management for CyberSecurity Suite.
Handles loading, saving, and accessing configuration settings.
"""

import json
import os
from pathlib import Path
from core.exceptions import ConfigError


class Config:
    """Configuration manager with JSON file storage."""

    DEFAULT_CONFIG = {
        "version": "1.0.0",
        "project_name": "CyberSecurity Suite",
        "paths": {
            "data_dir": "./data",
            "reports_dir": "./reports",
            "logs_dir": "./logs",
            "wordlists_dir": "./data/wordlists",
            "databases_dir": "./data/databases",
            "temp_dir": "./data/temp",
            "screenshots_dir": "./data/screenshots",
        },
        "scan_defaults": {
            "timing": "T4",
            "timeout": 300,
            "max_threads": 5,
            "default_ports": "top-1000",
            "ping_scan_first": True,
            "service_detection": True,
        },
        "reporting": {
            "default_formats": ["json", "html", "csv"],
            "include_executive_summary": True,
            "include_remediation": True,
            "company_name": "Security Audit",
            "report_logo": "",
        },
        "notifications": {
            "beep_on_complete": True,
            "beep_on_finding": True,
            "beep_on_error": True,
            "beep_patterns": {
                "complete": "complete",
                "major": "major",
                "finding": "standard",
                "error": "error",
            },
        },
        "tools": {
            "nmap": {"path": "/usr/bin/nmap", "sudo": True},
            "masscan": {"path": "/usr/bin/masscan", "sudo": True},
            "gobuster": {"path": "/usr/bin/gobuster"},
            "hydra": {"path": "/usr/bin/hydra"},
            "searchsploit": {"path": "/usr/bin/searchsploit"},
        },
    }

    def __init__(self, config_path=None):
        """
        Initialize configuration.

        Args:
            config_path: Path to config.json file
        """
        self.config_path = config_path or "config.json"
        self._config = {}
        self._load_or_create()

    def _load_or_create(self):
        """Load existing config or create default."""
        if os.path.exists(self.config_path) and os.path.getsize(self.config_path) > 0:
            try:
                with open(self.config_path, "r") as f:
                    self._config = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                pass # ALERT must raise error and not use default config
                #raise ConfigError(f"Failed to load config: {e}")
        else:
            self._config = self.DEFAULT_CONFIG.copy()
            self.save()

    def get(self, key, default=None):
        """
        Get a configuration value using dot notation.

        Args:
            key: Dot-separated key path (e.g., 'paths.data_dir')
            default: Default value if key not found

        Returns:
            The configuration value
        """
        keys = key.split(".")
        value = self._config

        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key, value):
        """
        Set a configuration value using dot notation.

        Args:
            key: Dot-separated key path
            value: Value to set
        """
        keys = key.split(".")
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self, config_path=None):
        """
        Save configuration to file.

        Args:
            config_path: Optional path to save to
        """
        path = config_path or self.config_path

        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w") as f:
                json.dump(self._config, f, indent=2)
        except IOError as e:
            raise ConfigError(f"Failed to save config: {e}")

    def get_all(self):
        """Get entire configuration dictionary."""
        return self._config.copy()

    def reset_to_default(self):
        """Reset configuration to defaults."""
        self._config = self.DEFAULT_CONFIG.copy()
        self.save()

    def get_scan_profile(self, profile_name):
        """
        Get a scan profile configuration.

        Args:
            profile_name: Name of the profile ('quick', 'full', 'stealth')

        Returns:
            dict: Scan profile settings
        """
        profiles = {
            "quick": {
                "ports": "top-100",
                "timing": "T4",
                "service_detection": False,
                "script_scan": False,
                "timeout": 120,
            },
            "full": {
                "ports": "1-65535",
                "timing": "T3",
                "service_detection": True,
                "script_scan": True,
                "timeout": 600,
            },
            "stealth": {
                "ports": "top-1000",
                "timing": "T2",
                "service_detection": False,
                "script_scan": False,
                "timeout": 300,
            },
        }

        return profiles.get(profile_name, profiles["quick"])

    def create_default_config(self):
        """Create a default configuration file."""
        self._config = self.DEFAULT_CONFIG.copy()
        self.save()
        return self.config_path
