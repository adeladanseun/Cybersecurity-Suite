"""
Forms for target management
"""

from django import forms
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit, Layout, Row, Column, Field
from .models import Target, TargetGroup, Project


class TargetForm(forms.ModelForm):
    """Form for creating and editing targets"""
    
    class Meta:
        model = Target
        fields = ['name', 'address', 'type', 'description', 'priority', 'is_active', 'notes']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('name', css_class='col-md-6'),
                Column('address', css_class='col-md-6'),
            ),
            Row(
                Column('type', css_class='col-md-4'),
                Column('priority', css_class='col-md-4'),
                Column('is_active', css_class='col-md-4'),
            ),
            'description',
            'notes',
            Submit('submit', 'Save Target', css_class='btn-primary'),
        )
    
    def clean_address(self):
        """Validate target address"""
        address = self.cleaned_data.get('address')
        from core.validator import classify_target
        
        if classify_target(address) == 'unknown':
            raise forms.ValidationError(
                'Invalid target address. Please enter a valid IP, domain, URL, or network range.'
            )
        
        return address


class TargetImportForm(forms.Form):
    """Form for bulk importing targets"""
    
    file = forms.FileField(
        help_text="Upload a file with one target per line (TXT or CSV)"
    )
    
    target_type = forms.ChoiceField(
        choices=[('', 'Auto-Detect')] + Target.TYPE_CHOICES,
        required=False,
        help_text="Force all targets to this type"
    )
    
    priority = forms.ChoiceField(
        choices=Target.PRIORITY_CHOICES,
        initial='medium',
        required=False
    )
    
    group_name = forms.CharField(
        max_length=255,
        required=False,
        help_text="Optional: Add imported targets to a group"
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.form_enctype = 'multipart/form-data'
        self.helper.layout = Layout(
            'file',
            Row(
                Column('target_type', css_class='col-md-6'),
                Column('priority', css_class='col-md-6'),
            ),
            'group_name',
            Submit('submit', 'Import Targets', css_class='btn-success'),
        )


class TargetGroupForm(forms.ModelForm):
    """Form for creating and editing target groups"""
    
    class Meta:
        model = TargetGroup
        fields = ['name', 'description', 'targets']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'targets': forms.CheckboxSelectMultiple(),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            'name',
            'description',
            'targets',
            Submit('submit', 'Save Group', css_class='btn-primary'),
        )


class ProjectForm(forms.ModelForm):
    """Form for creating and editing projects"""
    
    class Meta:
        model = Project
        fields = ['name', 'description', 'targets', 'members', 'status', 'start_date', 'end_date']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'targets': forms.CheckboxSelectMultiple(),
            'members': forms.CheckboxSelectMultiple(),
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_method = 'post'
        self.helper.layout = Layout(
            Row(
                Column('name', css_class='col-md-6'),
                Column('status', css_class='col-md-6'),
            ),
            'description',
            Row(
                Column('start_date', css_class='col-md-6'),
                Column('end_date', css_class='col-md-6'),
            ),
            'targets',
            'members',
            Submit('submit', 'Save Project', css_class='btn-primary'),
        )
