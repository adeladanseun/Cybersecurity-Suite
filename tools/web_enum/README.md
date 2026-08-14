# Web Enumeration Tool

Web application reconnaissance and discovery.

## Features
- Directory and file brute forcing
- Technology fingerprinting
- Hidden parameter discovery
- Parameter value fuzzing
- Multiple export formats

## Usage

### Directory Buster
```python
from tools.web_enum import DirBuster

buster = DirBuster()
results = buster.brute_force("https://example.com")