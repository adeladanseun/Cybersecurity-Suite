"""
URL patterns for scans app
"""

from django.urls import path
from . import views

app_name = 'scans'

urlpatterns = [
    # Scan URLs
    path('', views.ScanListView.as_view(), name='list'),
    path('new/', views.ScanCreateView.as_view(), name='create'),
    path('quick/', views.quick_scan, name='quick'),
    path('<uuid:pk>/', views.ScanDetailView.as_view(), name='detail'),
    path('<uuid:pk>/progress/', views.scan_progress, name='progress'),
    path('<uuid:pk>/results/', views.scan_results, name='results'),
    path('<uuid:pk>/cancel/', views.cancel_scan, name='cancel'),
    
    # Scheduled scan URLs
    path('schedule/', views.ScheduledScanListView.as_view(), name='schedule_list'),
    path('schedule/new/', views.ScheduledScanCreateView.as_view(), name='schedule_create'),
    path('schedule/<uuid:pk>/toggle/', views.toggle_schedule, name='schedule_toggle'),
]
