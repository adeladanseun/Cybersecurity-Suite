"""
URL patterns for vulnerabilities app
"""

from django.urls import path
from . import views

app_name = 'vulnerabilities'

urlpatterns = [
    # Vulnerability URLs
    path('', views.VulnerabilityListView.as_view(), name='list'),
    path('dashboard/', views.vulnerability_dashboard, name='dashboard'),
    path('create/', views.VulnerabilityCreateView.as_view(), name='create'),
    path('<uuid:pk>/', views.VulnerabilityDetailView.as_view(), name='detail'),
    path('<uuid:pk>/edit/', views.VulnerabilityUpdateView.as_view(), name='edit'),
    path('<uuid:pk>/update-status/', views.update_status, name='update_status'),
    path('<uuid:pk>/add-note/', views.add_note, name='add_note'),
    path('<uuid:pk>/add-task/', views.add_task, name='add_task'),
    
    # Export
    path('export/csv/', views.export_vulnerabilities, name='export_csv'),
]
