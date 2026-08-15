"""
URL patterns for results app
"""

from django.urls import path
from . import views

app_name = 'results'

urlpatterns = [
    # Results
    path('', views.ResultListView.as_view(), name='list'),
    path('<uuid:pk>/', views.result_detail, name='detail'),
    
    # Ports
    path('ports/', views.PortResultListView.as_view(), name='ports'),
    
    # Vulnerabilities
    path('vulnerabilities/', views.VulnerabilityResultListView.as_view(), name='vulns'),
    path('vulnerabilities/<uuid:pk>/', views.vulnerability_detail, name='vuln_detail'),
    path('vulnerabilities/<uuid:pk>/update-status/', views.update_vulnerability_status, name='vuln_update_status'),
    
    # Exports
    path('export/csv/', views.export_results_csv, name='export_csv'),
    path('export/ports/csv/', views.export_ports_csv, name='export_ports_csv'),
    path('export/vulns/csv/', views.export_vulns_csv, name='export_vulns_csv'),
]
