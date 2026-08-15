"""
URL patterns for API
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'targets', views.TargetViewSet)
router.register(r'target-groups', views.TargetGroupViewSet)
router.register(r'projects', views.ProjectViewSet)
router.register(r'scans', views.ScanViewSet)
router.register(r'scheduled-scans', views.ScheduledScanViewSet)
router.register(r'port-results', views.PortResultViewSet)
router.register(r'vulnerabilities', views.VulnerabilityViewSet)
router.register(r'vulnerability-results', views.VulnerabilityResultViewSet)
router.register(r'reports', views.ReportViewSet)
router.register(r'scan-results', views.ScanResultViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('stats/', views.StatsView.as_view(), name='api_stats'),
    path('auth/', include('rest_framework.urls')),
]
