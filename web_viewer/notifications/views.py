"""
Views for notifications
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.generic import ListView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone

from .models import Notification, NotificationPreference


class NotificationListView(LoginRequiredMixin, ListView):
    """List user notifications"""
    model = Notification
    template_name = 'notifications/list.html'
    context_object_name = 'notifications'
    paginate_by = 30
    
    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['unread_count'] = Notification.objects.filter(
            user=self.request.user, is_read=False
        ).count()
        context['total_count'] = Notification.objects.filter(
            user=self.request.user
        ).count()
        return context


@login_required
def mark_as_read(request, pk):
    """Mark notification as read"""
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.mark_as_read()
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'success': True})
    
    return redirect('notifications:list')


@login_required
def mark_all_read(request):
    """Mark all notifications as read"""
    Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
    
    messages.success(request, 'All notifications marked as read.')
    return redirect('notifications:list')


@login_required
def unread_count(request):
    """Get unread notification count (AJAX)"""
    count = Notification.objects.filter(user=request.user, is_read=False).count()
    return JsonResponse({'count': count})


@login_required
def notification_settings(request):
    """View and update notification preferences"""
    pref, created = NotificationPreference.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        # Update preferences
        for field in ['email_on_scan_complete', 'email_on_vulnerability', 'email_on_report',
                      'notify_on_scan_complete', 'notify_on_scan_failed',
                      'notify_on_vulnerability', 'notify_on_report',
                      'browser_notifications']:
            value = request.POST.get(field) == 'on'
            setattr(pref, field, value)
        
        pref.save()
        messages.success(request, 'Notification preferences updated.')
        return redirect('notifications:settings')
    
    return render(request, 'notifications/settings.html', {'pref': pref})
