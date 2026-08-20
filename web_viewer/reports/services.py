"""
Report generation service
"""

import os
import sys
import json
import threading
from datetime import datetime
from pathlib import Path

# Add parent directory to path for core modules
parent_dir = Path(__file__).resolve().parent.parent.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from django.utils import timezone
from django.conf import settings
from core.logger import get_logger
from core.notifier import Notifier

logger = get_logger("web_reports")
notifier = Notifier()


class ReportService:
    """Service for generating reports"""
    
    @classmethod
    def generate_report(cls, report):
        """
        Generate report in background thread.
        
        Args:
            report: Report model instance
        """
        report.status = 'generating'
        report.save()
        
        # Start generation in background
        thread = threading.Thread(
            target=cls._generate,
            args=(report.id,),
            daemon=True
        )
        thread.start()
    
    @classmethod
    def _generate(cls, report_id):
        """Generate the actual report"""
        from reports.models import Report
        
        try:
            report = Report.objects.get(id=report_id)
            
            logger.info(f"Generating {report.report_type} report: {report.name}")
            
            # Prepare report data
            data = cls._prepare_report_data(report)
            
            # Generate report based on format
            if report.format == 'html':
                content = cls._generate_html(report, data)
            elif report.format == 'txt':
                content = cls._generate_text(report, data)
            elif report.format == 'json':
                content = cls._generate_json(report, data)
            elif report.format == 'csv':
                content = cls._generate_csv(report, data)
            elif report.format == 'pdf':
                content = cls._generate_pdf(report, data)
            else:
                content = cls._generate_html(report, data)
            
            # Save report file
            if content:
                file_path = cls._save_report_file(report, content)
                
                # Update report
                report.file.name = file_path
                report.status = 'completed'
                report.generated_at = timezone.now()
                report.file_size = len(content.encode('utf-8')) if isinstance(content, str) else len(content)
                report.save()
                
                logger.info(f"Report generated: {report.name}")
                notifier.beep_complete()
            else:
                raise Exception("Report generation returned empty content")
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            
            try:
                report = Report.objects.get(id=report_id)
                report.status = 'failed'
                report.error_message = str(e)
                report.save()
            except Exception:
                pass
            
            notifier.beep_error()
    
    @classmethod
    def _prepare_report_data(cls, report):
        """Prepare data for report generation"""
        data = {
            'report_info': {
                'name': report.name,
                'description': report.description,
                'type': report.report_type,
                'format': report.format,
                'generated_at': datetime.now().isoformat(),
            }
        }
        
        # Include scan data if available
        if report.scan:
            scan = report.scan
            data['scan_info'] = {
                'id': str(scan.id),
                'type': scan.scan_type,
                'status': scan.status,
                'target': scan.target.name,
                'address': scan.target.address,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            }
            
            # Get scan results
            from results.models import ScanResult, PortResult, VulnerabilityResult
            
            # Ports
            ports = PortResult.objects.filter(scan=scan)
            data['ports'] = [
                {
                    'port': p.port,
                    'protocol': p.protocol,
                    'state': p.state,
                    'service': p.service,
                    'product': p.product,
                    'version': p.version,
                }
                for p in ports
            ]
            
            # Vulnerabilities
            vulns = VulnerabilityResult.objects.filter(scan=scan)
            data['vulnerabilities'] = [
                {
                    'cve': v.cve_id,
                    'title': v.title,
                    'severity': v.severity,
                    'cvss': v.cvss_score,
                    'service': v.affected_service,
                    'port': v.port,
                    'status': v.status,
                    'remediation': v.remediation,
                }
                for v in vulns
            ]
            
            # Generic results
            results = ScanResult.objects.filter(scan=scan)
            data['findings'] = [
                {
                    'type': r.result_type,
                    'severity': r.severity,
                    'data': r.data,
                }
                for r in results
            ]
        
        return data
    
    @classmethod
    def _generate_html(cls, report, data):
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th {{ background: #1a1a2e; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        .critical {{ color: #c62828; font-weight: bold; }}
        .high {{ color: #e65100; font-weight: bold; }}
        .medium {{ color: #f9a825; font-weight: bold; }}
        .low {{ color: #2e7d32; font-weight: bold; }}
        .meta {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <h1>{report.name}</h1>
    <div class="meta">
        <p><strong>Report Type:</strong> {report.get_report_type_display()}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Generated By:</strong> {report.generated_by.username if report.generated_by else 'System'}</p>
    </div>
"""
        
        # Scan info
        if 'scan_info' in data:
            scan = data['scan_info']
            html += f"""
    <h2>Scan Information</h2>
    <table>
        <tr><th>Field</th><th>Value</th></tr>
        <tr><td>Target</td><td>{scan['target']}</td></tr>
        <tr><td>Address</td><td>{scan['address']}</td></tr>
        <tr><td>Scan Type</td><td>{scan['type']}</td></tr>
        <tr><td>Status</td><td>{scan['status']}</td></tr>
        <tr><td>Started</td><td>{scan['started_at'] or 'N/A'}</td></tr>
        <tr><td>Completed</td><td>{scan['completed_at'] or 'N/A'}</td></tr>
    </table>
"""
        
        # Ports
        if data.get('ports'):
            html += """
    <h2>Open Ports</h2>
    <table>
        <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
"""
            for port in data['ports']:
                if port['state'] == 'open':
                    html += f"""
        <tr>
            <td>{port['port']}</td>
            <td>{port['protocol']}</td>
            <td>{port['service']}</td>
            <td>{port['product'] or 'N/A'}</td>
            <td>{port['version'] or 'N/A'}</td>
        </tr>"""
            
            html += "\n    </table>\n"
        
        # Vulnerabilities
        if data.get('vulnerabilities'):
            html += """
    <h2>Vulnerabilities</h2>
    <table>
        <tr><th>Severity</th><th>CVE</th><th>Title</th><th>Service</th><th>Status</th></tr>
"""
            for vuln in data['vulnerabilities']:
                html += f"""
        <tr>
            <td class="{vuln['severity']}">{vuln['severity'].upper()}</td>
            <td>{vuln['cve'] or 'N/A'}</td>
            <td>{vuln['title']}</td>
            <td>{vuln['service'] or 'N/A'}</td>
            <td>{vuln['status']}</td>
        </tr>"""
            
            html += "\n    </table>\n"
        
        html += """
    <footer>
        <p>Generated by CyberSecurity Suite - Web Interface</p>
    </footer>
</body>
</html>"""
        
        return html
    
    @classmethod
    def _generate_text(cls, report, data):
        """Generate plain text report"""
        lines = []
        lines.append("=" * 70)
        lines.append(report.name.upper())
        lines.append("=" * 70)
        lines.append(f"Report Type: {report.get_report_type_display()}")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        if 'scan_info' in data:
            scan = data['scan_info']
            lines.append("SCAN INFORMATION")
            lines.append("-" * 40)
            lines.append(f"  Target: {scan['target']}")
            lines.append(f"  Address: {scan['address']}")
            lines.append(f"  Type: {scan['type']}")
            lines.append("")
        
        if data.get('ports'):
            lines.append("OPEN PORTS")
            lines.append("-" * 40)
            for port in data['ports']:
                if port['state'] == 'open':
                    lines.append(f"  {port['port']}/{port['protocol']} - {port['service']} ({port['product']} {port['version']})")
            lines.append("")
        
        if data.get('vulnerabilities'):
            lines.append("VULNERABILITIES")
            lines.append("-" * 40)
            for vuln in data['vulnerabilities']:
                lines.append(f"  [{vuln['severity'].upper()}] {vuln['cve'] or 'No CVE'} - {vuln['title']}")
            lines.append("")
        
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    @classmethod
    def _generate_json(cls, report, data):
        """Generate JSON report"""
        return json.dumps(data, indent=2, default=str)
    
    @classmethod
    def _generate_csv(cls, report, data):
        """Generate CSV report"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write scan info
        if 'scan_info' in data:
            scan = data['scan_info']
            writer.writerow(['Scan Information'])
            writer.writerow(['Field', 'Value'])
            for key, value in scan.items():
                writer.writerow([key, value])
            writer.writerow([])
        
        # Write ports
        if data.get('ports'):
            writer.writerow(['Port Results'])
            writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Product', 'Version'])
            for port in data['ports']:
                writer.writerow([
                    port['port'], port['protocol'], port['state'],
                    port['service'], port['product'], port['version']
                ])
            writer.writerow([])
        
        # Write vulnerabilities
        if data.get('vulnerabilities'):
            writer.writerow(['Vulnerabilities'])
            writer.writerow(['CVE', 'Title', 'Severity', 'Service', 'Port', 'Status'])
            for vuln in data['vulnerabilities']:
                writer.writerow([
                    vuln['cve'], vuln['title'], vuln['severity'],
                    vuln['service'], vuln['port'], vuln['status']
                ])
        
        return output.getvalue()
    
    @classmethod
    def _generate_pdf(cls, report, data):
        """Generate PDF report (using weasyprint if available)"""
        try:
            import weasyprint
            
            html_content = cls._generate_html(report, data)
            return weasyprint.HTML(string=html_content).write_pdf()
            
        except ImportError:
            logger.warning("weasyprint not available, generating HTML instead")
            # Change format to HTML so file extension matches content
            report.format = 'html'
            report.save(update_fields=['format'])
            return cls._generate_html(report, data)
    

    @classmethod
    def _save_report_file(cls, report, content):
        """Save report content to file"""
        try:
            # Create directory
            reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports', 'generated')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Determine file extension
            ext = report.format if report.format != 'pdf' else 'pdf'
            if isinstance(content, bytes):
                ext = 'pdf'
            
            # Save file
            filename = f"report_{report.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
            filepath = os.path.join(reports_dir, filename)
            
            if isinstance(content, bytes):
                with open(filepath, 'wb') as f:
                    f.write(content)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            # Return relative path for FileField
            return f"reports/generated/{filename}"
            
        except Exception as e:
            logger.error(f"Failed to save report file: {e}")
            raise
