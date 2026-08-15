"""
URL patterns for dashboard
"""

from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard_index, name='index'),
    path('stats/', views.dashboard_stats, name='stats'),
    path('activity/', views.dashboard_activity, name='activity'),
]
