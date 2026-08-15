"""
URL configuration for CyberSecurity Suite Web Viewer
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Authentication
    path('accounts/', include('accounts.urls')),
    
    # Dashboard
    path('', RedirectView.as_view(pattern_name='dashboard', permanent=False)),
    path('dashboard/', lambda request: __import__('django.shortcuts').shortcuts.render(request, 'dashboard.html'), name='dashboard'),
    
    # Future apps (uncomment in later phases)
    # path('targets/', include('targets.urls')),
    # path('scans/', include('scans.urls')),
    # path('results/', include('results.urls')),
    # path('reports/', include('reports.urls')),
    # path('vulnerabilities/', include('vulnerabilities.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)