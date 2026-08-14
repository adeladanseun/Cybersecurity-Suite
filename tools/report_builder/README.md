# Report Builder Tool

Multi-format security report generation from scan results.

## Features
- HTML reports with professional styling
- PDF generation (requires weasyprint or reportlab)
- CSV export for spreadsheet analysis
- Plain text reports
- JSON data export
- Executive, Technical, and Findings templates
- Risk scoring and assessment
- Scan comparison reports

## Usage

### Python API
```python
from tools.report_builder import ReportGenerator

generator = ReportGenerator()

# Generate from scan data
files = generator.generate_report(
    scan_data,
    report_type='executive',
    formats=['html', 'pdf', 'csv', 'txt']
)

print(f"Reports generated: {files}")