"""
Report Generator - Main report generation engine
Produces HTML, PDF, CSV, TXT, and JSON reports from scan data
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.file_manager import FileManager
from core.logger import get_logger
from core.notifier import Notifier
from core.exceptions import FileManagerError


class ReportGenerator:
    """Multi-format report generator for security findings."""
    
    def __init__(self, output_dir=None, template_dir=None):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory for generated reports
            template_dir: Directory containing HTML templates
        """
        self.fm = FileManager()
        self.logger = get_logger("report_builder")
        self.notifier = Notifier()
        
        # Set directories
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(os.getcwd(), "reports")
        
        if template_dir:
            self.template_dir = template_dir
        else:
            self.template_dir = os.path.join(
                os.path.dirname(__file__), "templates"
            )
        
        # Ensure output directories exist
        for subdir in ['html', 'pdf', 'csv', 'txt', 'json']:
            self.fm.ensure_dir(os.path.join(self.output_dir, subdir))
    
    def generate_report(self, data, report_type='full', formats=None, 
                       report_name=None):
        """
        Generate reports in specified formats.
        
        Args:
            data: Scan results data (dict)
            report_type: 'full', 'executive', 'technical', 'findings'
            formats: List of formats ['html', 'pdf', 'csv', 'txt', 'json']
            report_name: Custom report name
        
        Returns:
            dict: Paths to generated reports
        """
        if formats is None:
            formats = ['html', 'csv', 'txt', 'json']
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name = report_name or f"report_{timestamp}"
        
        generated_files = {}
        
        self.logger.info(f"Generating {report_type} report: {name}")
        
        try:
            # Generate each format
            if 'html' in formats:
                html_path = self._generate_html(data, report_type, name)
                generated_files['html'] = html_path
            
            if 'csv' in formats:
                csv_path = self._generate_csv(data, name)
                generated_files['csv'] = csv_path
            
            if 'txt' in formats:
                txt_path = self._generate_txt(data, report_type, name)
                generated_files['txt'] = txt_path
            
            if 'json' in formats:
                json_path = self._generate_json(data, name)
                generated_files['json'] = json_path
            
            if 'pdf' in formats:
                pdf_path = self._generate_pdf(data, report_type, name)
                generated_files['pdf'] = pdf_path
            
            self.logger.info(f"Report generation complete: {len(generated_files)} formats")
            self.notifier.beep_complete()
            
            return generated_files
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            self.notifier.beep_error()
            raise
    
    def _generate_html(self, data, report_type, name):
        """Generate HTML report."""
        output_path = os.path.join(self.output_dir, 'html', f"{name}.html")
        
        # Get template
        template_file = os.path.join(self.template_dir, f"{report_type}.html")
        if not os.path.exists(template_file):
            template_file = os.path.join(self.template_dir, "base.html")
        
        if not os.path.exists(template_file):
            # Generate basic HTML without template
            html_content = self._generate_basic_html(data, report_type)
        else:
            # Use template if available
            html_content = self._render_template(template_file, data, report_type)
        
        self.fm.write_file(output_path, html_content)
        return output_path
    
    def _generate_csv(self, data, name):
        """Generate CSV report of findings."""
        output_path = os.path.join(self.output_dir, 'csv', f"{name}.csv")
        
        csv_data = []
        
        # Extract findings
        findings = self._extract_findings(data)
        
        for finding in findings:
            csv_data.append({
                'Target': finding.get('target', 'N/A'),
                'Port': finding.get('port', 'N/A'),
                'Service': finding.get('service', 'N/A'),
                'Type': finding.get('type', 'N/A'),
                'Severity': finding.get('severity', 'N/A'),
                'Title': finding.get('title', 'N/A'),
                'Description': finding.get('description', 'N/A')[:200],
                'CVE': finding.get('cve', 'N/A'),
                'CVSS': finding.get('cvss', 'N/A'),
                'Remediation': finding.get('remediation', 'N/A')[:200]
            })
        
        if csv_data:
            self.fm.write_csv(output_path, csv_data)
        else:
            # Write empty with headers
            headers = ['Target', 'Port', 'Service', 'Type', 'Severity', 
                      'Title', 'Description', 'CVE', 'CVSS', 'Remediation']
            self.fm.write_csv(output_path, [], headers)
        
        return output_path
    
    def _generate_txt(self, data, report_type, name):
        """Generate plain text report."""
        output_path = os.path.join(self.output_dir, 'txt', f"{name}.txt")
        
        lines = []
        lines.append("=" * 70)
        lines.append("SECURITY ASSESSMENT REPORT")
        lines.append("=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Report Type: {report_type.upper()}")
        lines.append("=" * 70)
        lines.append("")
        
        # Scan metadata
        if 'scan_metadata' in data:
            meta = data['scan_metadata']
            lines.append("SCAN INFORMATION")
            lines.append("-" * 40)
            lines.append(f"  Target:      {meta.get('target', 'N/A')}")
            lines.append(f"  Scan Type:   {meta.get('scan_type', 'N/A')}")
            lines.append(f"  Duration:    {meta.get('duration', 'N/A')} seconds")
            lines.append(f"  Timestamp:   {meta.get('timestamp', 'N/A')}")
            lines.append("")
        
        # Summary
        if 'summary' in data:
            summary = data['summary']
            lines.append("SUMMARY")
            lines.append("-" * 40)
            for key, value in summary.items():
                if not isinstance(value, (list, dict)):
                    lines.append(f"  {key.replace('_', ' ').title()}: {value}")
            lines.append("")
        
        # Open ports
        if 'ports' in data:
            lines.append("OPEN PORTS")
            lines.append("-" * 40)
            for port in data['ports']:
                if port.get('state') == 'open':
                    lines.append(
                        f"  {port.get('port', '?')}/{port.get('protocol', '?')} "
                        f"- {port.get('service', 'unknown')} "
                        f"({port.get('product', 'N/A')} {port.get('version', '')})"
                    )
            lines.append("")
        
        # Findings
        findings = self._extract_findings(data)
        if findings:
            lines.append("FINDINGS")
            lines.append("-" * 40)
            for i, finding in enumerate(findings, 1):
                severity = finding.get('severity', 'info').upper()
                lines.append(f"  [{severity}] Finding #{i}: {finding.get('title', 'N/A')}")
                if finding.get('description'):
                    lines.append(f"    Description: {finding['description'][:150]}")
                if finding.get('remediation'):
                    lines.append(f"    Remediation: {finding['remediation'][:150]}")
                lines.append("")
        
        lines.append("=" * 70)
        lines.append("END OF REPORT")
        
        content = "\n".join(lines)
        self.fm.write_file(output_path, content)
        return output_path
    
    def _generate_json(self, data, name):
        """Generate JSON report (raw data export)."""
        output_path = os.path.join(self.output_dir, 'json', f"{name}.json")
        
        # Add metadata
        export_data = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_name': name,
                'generator_version': '1.0.0'
            },
            'data': data
        }
        
        self.fm.write_json(output_path, export_data)
        return output_path
    
    def _generate_pdf(self, data, report_type, name):
        """Generate PDF report from HTML."""
        output_path = os.path.join(self.output_dir, 'pdf', f"{name}.pdf")
        
        try:
            # Try weasyprint first
            import weasyprint
            
            html_path = self._generate_html(data, report_type, f"{name}_temp")
            html_content = self.fm.read_file(html_path)
            
            weasyprint.HTML(string=html_content).write_pdf(output_path)
            
            # Clean temp HTML
            if os.path.exists(html_path):
                os.remove(html_path)
            
            return output_path
            
        except ImportError:
            # Fall back to reportlab
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
                from reportlab.lib.styles import getSampleStyleSheet
                
                doc = SimpleDocTemplate(output_path, pagesize=letter)
                styles = getSampleStyleSheet()
                story = []
                
                # Title
                title = f"Security Assessment Report - {report_type.title()}"
                story.append(Paragraph(title, styles['Title']))
                story.append(Spacer(1, 12))
                
                # Timestamp
                timestamp = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                story.append(Paragraph(timestamp, styles['Normal']))
                story.append(Spacer(1, 24))
                
                # Summary section
                if 'summary' in data:
                    story.append(Paragraph("Summary", styles['Heading2']))
                    for key, value in data['summary'].items():
                        if not isinstance(value, (list, dict)):
                            text = f"<b>{key.replace('_', ' ').title()}:</b> {value}"
                            story.append(Paragraph(text, styles['Normal']))
                
                doc.build(story)
                return output_path
                
            except ImportError:
                self.logger.warning("No PDF library available. Install weasyprint or reportlab.")
                raise
    
    def _generate_basic_html(self, data, report_type):
        """Generate basic HTML without Jinja2 template."""
        findings = self._extract_findings(data)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {report_type.title()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #1a1a2e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .critical {{ background: #ffebee; color: #c62828; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .high {{ background: #fff3e0; color: #e65100; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .medium {{ background: #fffde7; color: #f9a825; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .low {{ background: #e8f5e9; color: #2e7d32; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .info {{ background: #e3f2fd; color: #1565c0; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p><strong>Report Type:</strong> {report_type.title()}</p>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Summary</h2>"""
        
        if 'summary' in data:
            for key, value in data['summary'].items():
                if not isinstance(value, (list, dict)):
                    html += f"<p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>\n"
        
        html += """
    </div>
    
    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Protocol</th>
            <th>Service</th>
            <th>Product</th>
            <th>Version</th>
            <th>State</th>
        </tr>"""
        
        if 'ports' in data:
            for port in data['ports']:
                state_class = 'info'
                if port.get('state') == 'open':
                    state_class = 'low'
                html += f"""
        <tr>
            <td>{port.get('port', 'N/A')}</td>
            <td>{port.get('protocol', 'N/A')}</td>
            <td>{port.get('service', 'N/A')}</td>
            <td>{port.get('product', 'N/A')}</td>
            <td>{port.get('version', 'N/A')}</td>
            <td><span class="{state_class}">{port.get('state', 'N/A')}</span></td>
        </tr>"""
        
        html += """
    </table>"""
        
        if findings:
            html += """
    <h2>Findings</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Target</th>
            <th>Port</th>
            <th>Description</th>
        </tr>"""
            
            for finding in findings:
                severity = finding.get('severity', 'info').lower()
                html += f"""
        <tr>
            <td><span class="{severity}">{severity.upper()}</span></td>
            <td>{finding.get('title', 'N/A')}</td>
            <td>{finding.get('target', 'N/A')}</td>
            <td>{finding.get('port', 'N/A')}</td>
            <td>{finding.get('description', 'N/A')[:200]}</td>
        </tr>"""
            
            html += """
    </table>"""
        
        html += """
    <div class="footer">
        <p>Generated by CyberSecurity Suite - Report Builder</p>
        <p>This report contains confidential security assessment information.</p>
    </div>
</body>
</html>"""
        
        return html
    
    def _render_template(self, template_file, data, report_type):
        """Render HTML using Jinja2 template if available."""
        try:
            from jinja2 import Template
            
            with open(template_file, 'r') as f:
                template_content = f.read()
            
            template = Template(template_content)
            
            # Prepare template data
            template_data = {
                'report_type': report_type,
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'data': data,
                'findings': self._extract_findings(data),
                'summary': data.get('summary', {}),
                'ports': data.get('ports', []),
                'hosts': data.get('hosts', []),
                'scan_metadata': data.get('scan_metadata', {}),
                'risk_score': self._calculate_overall_risk(data)
            }
            
            return template.render(**template_data)
            
        except ImportError:
            self.logger.debug("Jinja2 not available, using basic HTML")
            return self._generate_basic_html(data, report_type)
    
    def _extract_findings(self, data):
        """Extract findings from various data formats."""
        findings = []
        
        # Direct findings list
        if 'findings' in data:
            findings.extend(data['findings'])
        
        # Port-based findings
        if 'ports' in data:
            for port in data['ports']:
                if port.get('state') == 'open':
                    findings.append({
                        'target': port.get('host', data.get('scan_metadata', {}).get('target', 'N/A')),
                        'port': port.get('port'),
                        'service': port.get('service', 'unknown'),
                        'type': 'open_port',
                        'severity': 'info',
                        'title': f"Open Port: {port.get('port')}/{port.get('protocol', 'tcp')}",
                        'description': f"Port {port.get('port')} is open running {port.get('service', 'unknown')} "
                                      f"{port.get('product', '')} {port.get('version', '')}",
                        'remediation': 'Review if this port needs to be publicly accessible'
                    })
        
        return findings
    
    def _calculate_overall_risk(self, data):
        """Calculate overall risk score from data."""
        from tools.report_builder.risk_calculator import RiskCalculator
        
        calculator = RiskCalculator()
        return calculator.calculate_risk_score(data)
    
    def generate_from_file(self, input_file, **kwargs):
        """Generate report from JSON scan file."""
        data = self.fm.read_json(input_file)
        return self.generate_report(data, **kwargs)
    
    def generate_comparison_report(self, current_data, previous_data, name=None):
        """Generate a comparison report between two scans."""
        from tools.report_builder.diff_report import DiffReportGenerator
        
        diff_gen = DiffReportGenerator()
        diff_data = diff_gen.generate_diff(current_data, previous_data)
        
        name = name or f"comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        return self.generate_report(
            diff_data,
            report_type='findings',
            report_name=name
        )