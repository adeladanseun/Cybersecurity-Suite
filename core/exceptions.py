"""
Custom exceptions for CyberSecurity Suite.
Provides specific error types for different failure modes.
"""


class CyberSuiteError(Exception):
    """Base exception for all CyberSuite errors."""

    def __init__(self, message="An error occurred in CyberSecurity Suite"):
        self.message = message
        super().__init__(self.message)


class ValidationError(CyberSuiteError):
    """Raised when input validation fails."""

    def __init__(self, message="Input validation failed", field=None, value=None):
        self.field = field
        self.value = value
        if field and value:
            message = f"Validation failed for {field}: {value}"
        super().__init__(message)


class FileManagerError(CyberSuiteError):
    """Raised when file operations fail."""

    def __init__(self, message="File operation failed", filepath=None, operation=None):
        self.filepath = filepath
        self.operation = operation
        if filepath and operation:
            message = f"File {operation} failed: {filepath}"
        super().__init__(message)


class ScanError(CyberSuiteError):
    """Raised when scanning operations fail."""

    def __init__(self, message="Scan operation failed", target=None, tool=None):
        self.target = target
        self.tool = tool
        if target and tool:
            message = f"Scan failed for {target} using {tool}"
        super().__init__(message)


class ConfigError(CyberSuiteError):
    """Raised when configuration operations fail."""

    def __init__(self, message="Configuration error", key=None):
        self.key = key
        if key:
            message = f"Configuration error for key: {key}"
        super().__init__(message)


class DatabaseError(CyberSuiteError):
    """Raised when database operations fail."""

    def __init__(self, message="Database operation failed", query=None):
        self.query = query
        if query:
            message = f"Database query failed: {query}"
        super().__init__(message)


class ToolNotFoundError(CyberSuiteError):
    """Raised when a required external tool is not found."""

    def __init__(self, tool_name=None):
        self.tool_name = tool_name
        message = (
            f"Required tool not found: {tool_name}"
            if tool_name
            else "Required tool not found"
        )
        super().__init__(message)
