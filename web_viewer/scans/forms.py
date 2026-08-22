"""
Forms for scan management
"""

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Layout, Row, Column, Field
from .models import Scan, ScheduledScan


class ScanForm(forms.ModelForm):
    """Form for creating a new scan"""

    class Meta:
        model = Scan
        fields = ["target", "scan_type", "parameters"]
        widgets = {
            "parameters": forms.Textarea(
                attrs={
                    "rows": 3,
                    "placeholder": '{"ports": "80,443", "timing": "T4", "service_detection": true}',
                }
            ),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = "post"
        self.helper.layout = Layout(
            "target",
            "scan_type",
            "parameters",
            Submit("submit", "Start Scan", css_class="btn-primary"),
        )

        self.fields["parameters"].required = False
        self.fields["parameters"].help_text = """
            JSON parameters: {"ports": "80,443"}, {"ports": "1-1000"}, 
            {"timing": "T4"}, {"service_detection": true}, {"script_scan": true}
        """


class QuickScanForm(forms.Form):
    """Form for quick scan"""
    
    target = forms.ModelChoiceField(
        queryset=None,
        empty_label="Select Target"
    )
    
    scan_type = forms.ChoiceField(
        choices=[
            ('port_scan', 'Quick Port Scan (Top 1000)'),
            ('full_port_scan', 'Full Port Scan (1-65535)'),
            ('service_scan', 'Service Detection'),
            ('vuln_scan', 'Vulnerability Scan'),
        ],
        initial='port_scan'
    )
    
    def __init__(self, *args, **kwargs):
        from targets.models import Target
        super().__init__(*args, **kwargs)
        self.fields['target'].queryset = Target.objects.filter(is_active=True)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            'target',
            'scan_type',
            Submit('submit', 'Start Scan', css_class='btn-success'),
        )


class ScheduledScanForm(forms.ModelForm):
    """Form for scheduling scans"""
    
    class Meta:
        model = ScheduledScan
        fields = ['target', 'scan_type', 'frequency', 'schedule_time', 'is_active']
        widgets = {
            'schedule_time': forms.TimeInput(attrs={'type': 'time'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('target', css_class='col-md-6'),
                Column('scan_type', css_class='col-md-6'),
            ),
            Row(
                Column('frequency', css_class='col-md-6'),
                Column('schedule_time', css_class='col-md-6'),
            ),
            'is_active',
            Submit('submit', 'Schedule Scan', css_class='btn-primary'),
        )
