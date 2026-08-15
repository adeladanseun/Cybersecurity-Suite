"""
URL patterns for targets app
"""

from django.urls import path
from . import views

app_name = 'targets'

urlpatterns = [
    # Target URLs
    path('', views.TargetListView.as_view(), name='list'),
    path('create/', views.TargetCreateView.as_view(), name='create'),
    path('import/', views.import_targets, name='import'),
    path('<uuid:pk>/', views.TargetDetailView.as_view(), name='detail'),
    path('<uuid:pk>/edit/', views.TargetUpdateView.as_view(), name='edit'),
    path('<uuid:pk>/delete/', views.TargetDeleteView.as_view(), name='delete'),
    
    # Project URLs
    path('projects/', views.ProjectListView.as_view(), name='project_list'),
    path('projects/create/', views.ProjectCreateView.as_view(), name='project_create'),
    path('projects/<uuid:pk>/', views.ProjectDetailView.as_view(), name='project_detail'),
    
    # API endpoints
    path('api/targets/', views.api_target_list, name='api_list'),
]
