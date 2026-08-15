"""
Forms for report generation
"""

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Layout, Row, Column, Field
from .models import Report, ReportTemplate


class ReportGenerationForm(forms.ModelForm):
    """Form for generating a new report"""
    
    class Meta:
        model = Report
        fields = ['name', 'description', 'report_type', 'format', 'scan']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('name', css_class='col-md-6'),
                Column('scan', css_class='col-md-6'),
            ),
            'description',
            Row(
                Column('report_type', css_class='col-md-6'),
                Column('format', css_class='col-md-6'),
            ),
            Submit('submit', 'Generate Report', css_class='btn-primary'),
        )
        
        # Filter scans to completed only
        from scans.models import Scan
        self.fields['scan'].queryset = Scan.objects.filter(status='completed')
        self.fields['scan'].required = False


class ReportTemplateForm(forms.ModelForm):
    """Form for managing report templates"""
    
    class Meta:
        model = ReportTemplate
        fields = ['name', 'description', 'template_type', 'template_file', 'is_active']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            Row(
                Column('name', css_class='col-md-6'),
                Column('template_type', css_class='col-md-6'),
            ),
            'description',
            'template_file',
            'is_active',
            Submit('submit', 'Save Template', css_class='btn-primary'),
        )
