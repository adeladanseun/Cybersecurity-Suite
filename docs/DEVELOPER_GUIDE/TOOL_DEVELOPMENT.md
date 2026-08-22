# Tool Development Guide

This guide explains how to create new tools for CyberSecurity Suite.

---

## Tool Structure

Each tool follows this pattern:
```text
tools/
└── my_tool/
   ├── init.py # Exports
   ├── main.py # Main logic
   ├── parser.py # Result parsing (if needed)
   └── README.md # Documentation
```
---

## Step 1: Create Tool Directory

```bash
mkdir -p tools/my_tool
touch tools/my_tool/__init__.py
```
## Step 2: Write Main Class
```python
# tools/my_tool/main.py

import os
import sys
from pathlib import Path

# Add parent directory to path
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from core.file_manager import FileManager
from core.validator import classify_target
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import ScanError


class MyTool:
    """My custom tool"""
    
    def __init__(self, output_dir=None):
        self.logger = get_logger("my_tool")
        self.notifier = Notifier()
        self.fm = FileManager()
        self.output_dir = output_dir or "./data/intermediate"
        self.fm.ensure_dir(self.output_dir)
    
    def run(self, target, **kwargs):
        """Execute the tool"""
        self.logger.info(f"Running on: {target}")
        
        # Validate target
        target_type = classify_target(target)
        if target_type == 'unknown':
            raise ScanError(f"Invalid target: {target}")
        
        # Execute logic
        results = self._execute(target, **kwargs)
        
        # Save results
        self._save_results(results)
        
        # Notify
        self.notifier.beep_complete()
        
        return results
    
    def _execute(self, target, **kwargs):
        """Actual tool logic"""
        # Implement your logic here
        return {}
    
    def _save_results(self, results):
        """Save results to file"""
        import json
        from datetime import datetime
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"mytool_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        self.fm.write_json(filepath, results)
        results['output_file'] = filepath
        
        return filepath
```
## Step 3: Export from __init__.py
```python
# tools/my_tool/__init__.py

from tools.my_tool.main import MyTool

__all__ = ['MyTool']
```
## Step 4: Write Tests
```python
# tests/test_my_tool.py

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tools.my_tool import MyTool


def test_initialization():
    tool = MyTool()
    assert tool is not None


def test_run():
    tool = MyTool()
    results = tool.run("localhost")
    assert results is not None


if __name__ == "__main__":
    test_initialization()
    test_run()
    print("All tests passed")
```
## Step 5: Add to Web App (Optional)
Add scan type to web_viewer/scans/models.py:
```python
SCAN_TYPE_CHOICES = [
    # Existing types...
    ('my_tool', 'My Custom Tool'),
]
```
Add handler to web_viewer/scans/services.py:
```python
@classmethod
def _run_my_tool(cls, scan):
    from tools.my_tool import MyTool
    
    tool = MyTool()
    target = scan.target.address
    
    params = scan.parameters or {}
    
    results = tool.run(target, **params)
    return results
```
Add to _run_scan dispatch:
```python
elif scan.scan_type == 'my_tool':
    results = cls._run_my_tool(scan)
```
## Step 6: Write Documentation
Create tools/my_tool/README.md:

```markdown
# My Tool

Description of what the tool does.

## Usage

```python
from tools.my_tool import MyTool

tool = MyTool()
results = tool.run("target.com")
#```
Output
Results saved to data/intermediate/mytool_*.json

```

---

## Best Practices

1. **Use core modules** — FileManager, Validator, Logger
2. **Handle errors** — Raise ScanError, ValidationError
3. **Save results** — JSON to data/intermediate/
4. **Add tests** — At least initialization and basic run
5. **Document** — README with usage examples
6. **Log progress** — Use logger, not print()
7. **Notify completion** — Use Notifier
8. **Follow naming** — snake_case for files, CamelCase for classes
