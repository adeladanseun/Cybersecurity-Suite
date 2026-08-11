"""
File management utilities for CyberSecurity Suite.
Handles reading, writing, and organizing project files.
"""

import os
import json
import csv
import shutil
from datetime import datetime
from pathlib import Path
from core.exceptions import FileManagerError


class FileManager:
    """Universal file I/O handler for the project."""

    def __init__(self, base_dir=None):
        """
        Initialize FileManager.

        Args:
            base_dir: Base directory for the project
        """
        self.base_dir = base_dir or os.getcwd()

    # ========== Directory Operations ==========

    def ensure_dir(self, dir_path):
        """
        Create directory if it doesn't exist.

        Args:
            dir_path: Directory path to create

        Returns:
            str: Created directory path
        """
        try:
            full_path = (
                os.path.join(self.base_dir, dir_path)
                if not os.path.isabs(dir_path)
                else dir_path
            )
            os.makedirs(full_path, exist_ok=True)
            return full_path
        except OSError as e:
            raise FileManagerError(
                f"Failed to create directory: {dir_path}",
                filepath=dir_path,
                operation="create",
            )

    def create_project_structure(self):
        """Create the standard project directory structure."""
        directories = [
            "data/targets",
            "data/intermediate",
            "data/databases",
            "data/wordlists",
            "data/screenshots",
            "data/sessions",
            "data/temp",
            "reports/html",
            "reports/pdf",
            "reports/csv",
            "reports/txt",
            "reports/json",
            "logs",
        ]

        for directory in directories:
            self.ensure_dir(directory)

        # Create .gitkeep files in empty directories
        for directory in directories:
            gitkeep = os.path.join(self.base_dir, directory, ".gitkeep")
            if not os.path.exists(gitkeep):
                Path(gitkeep).touch()

    # ========== Read Operations ==========

    def read_file(self, filepath):
        """
        Read entire file content.

        Args:
            filepath: Path to file

        Returns:
            str: File contents
        """
        try:
            full_path = (
                os.path.join(self.base_dir, filepath)
                if not os.path.isabs(filepath)
                else filepath
            )
            with open(full_path, "r", encoding="utf-8") as f:
                return f.read()
        except (IOError, OSError) as e:
            raise FileManagerError(
                f"Failed to read file: {filepath}", filepath=filepath, operation="read"
            )

    def read_lines(self, filepath, skip_empty=True, skip_comments=True):
        """
        Read file lines, optionally skipping empty lines and comments.

        Args:
            filepath: Path to file
            skip_empty: Skip empty lines
            skip_comments: Skip lines starting with #

        Returns:
            list: List of lines
        """
        content = self.read_file(filepath)
        lines = content.split("\n")

        result = []
        for line in lines:
            stripped = line.strip()

            if skip_empty and not stripped:
                continue

            if skip_comments and stripped.startswith("#"):
                continue

            result.append(stripped)

        return result

    def read_targets(self, filepath):
        """
        Read target list from file. Handles multiple formats.

        Args:
            filepath: Path to target file

        Returns:
            list: List of validated targets
        """
        from core.validator import classify_target

        lines = self.read_lines(filepath)
        targets = []

        for line in lines:
            # Skip section headers
            if line.startswith("[") and line.endswith("]"):
                continue

            target_type = classify_target(line)
            if target_type != "unknown":
                targets.append({"target": line, "type": target_type})

        return targets

    def read_json(self, filepath):
        """
        Read and parse JSON file.

        Args:
            filepath: Path to JSON file

        Returns:
            dict/list: Parsed JSON data
        """
        try:
            full_path = (
                os.path.join(self.base_dir, filepath)
                if not os.path.isabs(filepath)
                else filepath
            )
            with open(full_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise FileManagerError(
                f"Invalid JSON in file: {filepath}",
                filepath=filepath,
                operation="parse",
            )
        except (IOError, OSError) as e:
            raise FileManagerError(
                f"Failed to read JSON file: {filepath}",
                filepath=filepath,
                operation="read",
            )

    def read_csv(self, filepath, as_dict=True):
        """
        Read CSV file.

        Args:
            filepath: Path to CSV file
            as_dict: Return as list of dictionaries (True) or list of lists (False)

        Returns:
            list: CSV data
        """
        try:
            full_path = (
                os.path.join(self.base_dir, filepath)
                if not os.path.isabs(filepath)
                else filepath
            )
            with open(full_path, "r", encoding="utf-8") as f:
                if as_dict:
                    reader = csv.DictReader(f)
                    return list(reader)
                else:
                    reader = csv.reader(f)
                    return list(reader)
        except (IOError, OSError) as e:
            raise FileManagerError(
                f"Failed to read CSV file: {filepath}",
                filepath=filepath,
                operation="read",
            )

    # ========== Write Operations ==========

    def write_file(self, filepath, content):
        """
        Write content to file.

        Args:
            filepath: Path to file
            content: Content to write
        """
        try:
            full_path = (
                os.path.join(self.base_dir, filepath)
                if not os.path.isabs(filepath)
                else filepath
            )
            self.ensure_dir(os.path.dirname(full_path))

            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
        except (IOError, OSError) as e:
            raise FileManagerError(
                f"Failed to write file: {filepath}",
                filepath=filepath,
                operation="write",
            )

    def write_json(self, filepath, data, pretty=True):
        """
        Write data as JSON file.

        Args:
            filepath: Path to JSON file
            data: Data to serialize
            pretty: Pretty-print JSON
        """
        try:
            full_path = (
                os.path.join(self.base_dir, filepath)
                if not os.path.isabs(filepath)
                else filepath
            )
            self.ensure_dir(os.path.dirname(full_path))

            with open(full_path, "w", encoding="utf-8") as f:
                if pretty:
                    json.dump(data, f, indent=2, default=str)
                else:
                    json.dump(data, f, default=str)
        except (IOError, OSError, TypeError) as e:
            raise FileManagerError(
                f"Failed to write JSON file: {filepath}",
                filepath=filepath,
                operation="write",
            )

    def write_csv(self, filepath, data, headers=None, mode="w"):
        """
        Write data as CSV file.

        Args:
            filepath: Path to CSV file
            data: List of dictionaries or list of lists
            headers: Column headers (if data is list of lists)
            mode: Write mode ('w' for overwrite, 'a' for append)
        """
        try:
            full_path = (
                os.path.join(self.base_dir, filepath)
                if not os.path.isabs(filepath)
                else filepath
            )
            self.ensure_dir(os.path.dirname(full_path))

            with open(full_path, mode, encoding="utf-8", newline="") as f:
                if data and isinstance(data[0], dict):
                    # List of dictionaries
                    if not headers:
                        headers = list(data[0].keys())
                    writer = csv.DictWriter(f, fieldnames=headers)
                    if mode == "w":
                        writer.writeheader()
                    writer.writerows(data)
                else:
                    # List of lists
                    writer = csv.writer(f)
                    if headers and mode == "w":
                        writer.writerow(headers)
                    writer.writerows(data)
        except (IOError, OSError) as e:
            raise FileManagerError(
                f"Failed to write CSV file: {filepath}",
                filepath=filepath,
                operation="write",
            )

    def append_csv(self, filepath, data, headers=None):
        """Append data to existing CSV file."""
        self.write_csv(filepath, data, headers, mode="a")

    # ========== Utility Operations ==========

    def file_exists(self, filepath):
        """Check if file exists."""
        full_path = (
            os.path.join(self.base_dir, filepath)
            if not os.path.isabs(filepath)
            else filepath
        )
        return os.path.isfile(full_path)

    def get_timestamp_filename(self, prefix, extension):
        """
        Generate a timestamped filename.

        Args:
            prefix: Filename prefix
            extension: File extension (without dot)

        Returns:
            str: Timestamped filename (e.g., 'scan_20240115_103000.json')
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{prefix}_{timestamp}.{extension}"

    def safe_filename(self, name):
        """
        Convert string to safe filename.

        Args:
            name: Input string

        Returns:
            str: Safe filename
        """
        # Replace problematic characters
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
        return safe.strip("_") or "unnamed"

    def backup_file(self, filepath):
        """
        Create a backup of a file.

        Args:
            filepath: Path to file to backup

        Returns:
            str: Backup file path
        """
        if not self.file_exists(filepath):
            raise FileManagerError(
                f"File not found for backup: {filepath}",
                filepath=filepath,
                operation="backup",
            )

        full_path = (
            os.path.join(self.base_dir, filepath)
            if not os.path.isabs(filepath)
            else filepath
        )
        backup_path = f"{full_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        try:
            shutil.copy2(full_path, backup_path)
            return backup_path
        except (IOError, OSError) as e:
            raise FileManagerError(
                f"Failed to backup file: {filepath}",
                filepath=filepath,
                operation="backup",
            )

    def cleanup_temp_files(self, max_age_hours=24):
        """
        Clean up temporary files older than specified hours.

        Args:
            max_age_hours: Maximum age in hours

        Returns:
            int: Number of files cleaned
        """
        temp_dir = os.path.join(self.base_dir, "data", "temp")
        if not os.path.exists(temp_dir):
            return 0

        now = datetime.now()
        cleaned = 0

        for filename in os.listdir(temp_dir):
            filepath = os.path.join(temp_dir, filename)
            if os.path.isfile(filepath):
                file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                age_hours = (now - file_time).total_seconds() / 3600

                if age_hours > max_age_hours:
                    try:
                        os.remove(filepath)
                        cleaned += 1
                    except OSError:
                        pass

        return cleaned
