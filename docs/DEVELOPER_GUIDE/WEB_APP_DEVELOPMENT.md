# Web App Development Guide

This guide explains how to extend the Django web application.

---

## Django App Structure

Each app follows this pattern:
```text
web_viewer/
└── my_app/
├── init.py
├── admin.py
├── apps.py
├── models.py
├── forms.py
├── views.py
├── urls.py
├── migrations/
├── templates/
│ └── my_app/
└── static/
└── my_app/
```


## Creating a New App

```bash
cd web_viewer
source venv/bin/activate

python manage.py startapp my_app
```
### Model Pattern
All models use UUID primary keys:

```python
import uuid
from django.db import models
from django.contrib.auth.models import User


class MyModel(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    name = models.CharField(max_length=255)
    
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='my_models'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return self.name
```
### View Pattern
Use LoginRequiredMixin for all views:

```python
from django.views.generic import ListView, DetailView, CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy


class MyModelListView(LoginRequiredMixin, ListView):
    model = MyModel
    template_name = 'my_app/list.html'
    context_object_name = 'items'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = MyModel.objects.all()
        
        # Filters
        search = self.request.GET.get('search', '')
        if search:
            queryset = queryset.filter(name__icontains=search)
        
        return queryset


class MyModelCreateView(LoginRequiredMixin, CreateView):
    model = MyModel
    fields = ['name']
    template_name = 'my_app/form.html'
    success_url = reverse_lazy('my_app:list')
    
    def form_valid(self, form):
        form.instance.created_by = self.request.user
        return super().form_valid(form)
```
### URL Pattern
``` python
# my_app/urls.py

from django.urls import path
from . import views

app_name = 'my_app'

urlpatterns = [
    path('', views.MyModelListView.as_view(), name='list'),
    path('create/', views.MyModelCreateView.as_view(), name='create'),
    path('<uuid:pk>/', views.MyModelDetailView.as_view(), name='detail'),
]
```
### Register in config/urls.py:

```python
path('my-app/', include('my_app.urls')),
```
### Template Pattern
```html
{% extends 'base.html' %}

{% block title %}My App - CyberSecurity Suite{% endblock %}

{% block content %}
<div class="container-fluid">
    <div class="row mb-4">
        <div class="col-md-6">
            <h1>My App</h1>
        </div>
        <div class="col-md-6 text-end">
            <a href="{% url 'my_app:create' %}" class="btn btn-primary">
                <i class="fas fa-plus me-1"></i>New
            </a>
        </div>
    </div>
    
    <div class="card shadow-sm">
        <div class="card-body">
            <!-- Content here -->
        </div>
    </div>
</div>
{% endblock %}
```
### Adding to Settings
Add app to INSTALLED_APPS in config/settings.py:

```python
INSTALLED_APPS = [
    # Existing apps...
    'my_app',
]
```
### Running Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```
#### Adding Scan Types
To add a new scan type:

Add to scans/models.py:

```python
SCAN_TYPE_CHOICES = [
    # Existing...
    ('new_scan', 'New Scan Type'),
]
```
### Add handler in scans/services.py:

```python
@classmethod
def _run_new_scan(cls, scan):
    # Implement logic
    return results
```
### Add to dispatch in _run_scan:

```python
elif scan.scan_type == 'new_scan':
    results = cls._run_new_scan(scan)
```
### Adding REST API Endpoints
Add serializer in api/serializers.py:

```python
class MyModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = MyModel
        fields = '__all__'
```
### Add viewset in api/views.py:

```python
class MyModelViewSet(viewsets.ModelViewSet):
    queryset = MyModel.objects.all()
    serializer_class = MyModelSerializer
    permission_classes = [permissions.IsAuthenticated]
```
### Register in api/urls.py:

```python
router.register(r'my-models', views.MyModelViewSet)
```
## Testing
```python
# tests/test_my_app.py

from django.test import TestCase
from django.contrib.auth.models import User
from my_app.models import MyModel


class MyModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('testuser', password='testpass123')
    
    def test_creation(self):
        obj = MyModel.objects.create(name='Test', created_by=self.user)
        self.assertEqual(obj.name, 'Test')
```
### Run:

```bash
python manage.py test tests.test_my_app

#if above does not work
python manage.py test #test all
```
## Best Practices
- UUID keys — Always use UUID primary keys
- LoginRequired — All views require authentication
- Select related — Reduce database queries
- Pagination — Use for list views
- Filtering — Add filter options
- Error handling — Show user-friendly messages
- Responsive design — Use Bootstrap 5 classes
- Test coverage — Write tests for models and views