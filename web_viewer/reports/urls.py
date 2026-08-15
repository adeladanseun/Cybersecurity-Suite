"""
URL patterns for reports app
"""

from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    # Report URLs
    path('', views.ReportListView.as_view(), name='list'),
    path('generate/', views.ReportGenerateView.as_view(), name='generate'),
    path('<uuid:pk>/', views.ReportDetailView.as_view(), name='detail'),
    path('<uuid:pk>/download/', views.download_report, name='download'),
    path('<uuid:pk>/progress/', views.report_progress, name='progress'),
    path('<uuid:pk>/export/', views.export_report_data, name='export'),
    
    # Template URLs
    path('templates/', views.ReportTemplateListView.as_view(), name='template_list'),
    path('templates/create/', views.ReportTemplateCreateView.as_view(), name='template_create'),
]
