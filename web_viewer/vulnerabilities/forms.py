"""
Forms for vulnerability management
"""

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Layout, Row, Column, Field
from .models import Vulnerability, RemediationTask, VulnerabilityNote


class VulnerabilityForm(forms.ModelForm):
    """Form for creating and editing vulnerabilities"""
    
    class Meta:
        model = Vulnerability
        fields = ['cve_id', 'title', 'description', 'severity', 'cvss_score',
                  'scan', 'affected_service', 'port', 'status', 'priority',
                  'remediation', 'assigned_to']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'remediation': forms.Textarea(attrs={'rows': 4}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('title', css_class='col-md-8'),
                Column('cve_id', css_class='col-md-4'),
            ),
            'description',
            Row(
                Column('severity', css_class='col-md-3'),
                Column('cvss_score', css_class='col-md-3'),
                Column('priority', css_class='col-md-3'),
                Column('status', css_class='col-md-3'),
            ),
            Row(
                Column('scan', css_class='col-md-6'),
                Column('affected_service', css_class='col-md-3'),
                Column('port', css_class='col-md-3'),
            ),
            'remediation',
            'assigned_to',
            Submit('submit', 'Save Vulnerability', css_class='btn-primary'),
        )


class VulnerabilityStatusForm(forms.ModelForm):
    """Form for updating vulnerability status"""
    
    class Meta:
        model = Vulnerability
        fields = ['status', 'priority', 'assigned_to']
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('status', css_class='col-md-4'),
                Column('priority', css_class='col-md-4'),
                Column('assigned_to', css_class='col-md-4'),
            ),
            Submit('submit', 'Update Status', css_class='btn-primary'),
        )


class RemediationTaskForm(forms.ModelForm):
    """Form for creating remediation tasks"""
    
    class Meta:
        model = RemediationTask
        fields = ['title', 'description', 'status', 'assigned_to', 'due_date']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'due_date': forms.DateInput(attrs={'type': 'date'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            'title',
            'description',
            Row(
                Column('status', css_class='col-md-4'),
                Column('assigned_to', css_class='col-md-4'),
                Column('due_date', css_class='col-md-4'),
            ),
            Submit('submit', 'Create Task', css_class='btn-primary'),
        )


class VulnerabilityNoteForm(forms.ModelForm):
    """Form for adding notes"""
    
    class Meta:
        model = VulnerabilityNote
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Add a note...'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            'content',
            Submit('submit', 'Add Note', css_class='btn-primary'),
        )
