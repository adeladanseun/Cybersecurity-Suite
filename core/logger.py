"""
Logging system for CyberSecurity Suite.
Provides structured logging with file and console output.
"""

import logging
import os
from datetime import datetime
from pathlib import Path


class CyberLogger:
    """Centralized logging management."""

    _loggers = {}
    _default_log_dir = "logs"
    _initialized = False

    @classmethod
    def setup_logger(
        cls,
        name="cybersec",
        log_file=None,
        level=logging.INFO,
        console_output=True,
        file_output=True,
    ):
        """
        Set up a logger instance.

        Args:
            name: Logger name
            log_file: Path to log file (optional)
            level: Logging level
            console_output: Enable console output
            file_output: Enable file output

        Returns:
            logging.Logger: Configured logger instance
        """
        if name in cls._loggers:
            return cls._loggers[name]

        logger = logging.getLogger(name)
        logger.setLevel(level)

        # Remove existing handlers
        logger.handlers.clear()

        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Console handler
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

        # File handler
        if file_output:
            if log_file is None:
                os.makedirs(cls._default_log_dir, exist_ok=True)
                log_file = os.path.join(cls._default_log_dir, f"{name}.log")

            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        cls._loggers[name] = logger
        cls._initialized = True

        return logger

    @classmethod
    def get_logger(cls, name="cybersec"):
        """
        Get an existing logger or create a default one.

        Args:
            name: Logger name

        Returns:
            logging.Logger: Logger instance
        """
        if name in cls._loggers:
            return cls._loggers[name]

        # Create default logger
        return cls.setup_logger(name)


def get_logger(name="cybersec"):
    """Convenience function to get a logger instance."""
    return CyberLogger.get_logger(name)


# Convenience functions for common logging patterns
def log_scan_start(logger, target, tool_name):
    """Log the start of a scan operation."""
    logger.info(f"Starting {tool_name} scan on target: {target}")


def log_scan_complete(logger, target, tool_name, duration=None):
    """Log the completion of a scan operation."""
    duration_str = f" in {duration:.2f}s" if duration else ""
    logger.info(f"Completed {tool_name} scan on {target}{duration_str}")


def log_finding(logger, target, finding_type, severity, details=""):
    """Log a security finding."""
    message = f"Finding [{severity.upper()}] {finding_type} on {target}"
    if details:
        message += f" - {details}"

    if severity.lower() == "critical":
        logger.critical(message)
    elif severity.lower() == "high":
        logger.error(message)
    elif severity.lower() == "medium":
        logger.warning(message)
    else:
        logger.info(message)


def log_error(logger, target, error_message, traceback=""):
    """Log an error with optional traceback."""
    logger.error(f"Error on {target}: {error_message}")
    if traceback:
        logger.debug(f"Traceback: {traceback}")
