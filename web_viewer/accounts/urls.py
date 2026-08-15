"""
URL patterns for accounts app
"""

from django.urls import path
from django.contrib.auth import views as auth_views

from . import views
from .forms import UserLoginForm

app_name = 'accounts'

urlpatterns = [
    # Login/Logout
    path('login/', auth_views.LoginView.as_view(
        template_name='accounts/login.html',
        authentication_form=UserLoginForm,
        redirect_authenticated_user=True
    ), name='login'),
    
    path('logout/', views.logout_view, name='logout'),
    
    # Registration
    path('register/', views.RegisterView.as_view(), name='register'),
    
    # Profile
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.ProfileUpdateView.as_view(), name='profile_edit'),
    
    # Password change
    path('password/change/', auth_views.PasswordChangeView.as_view(
        template_name='accounts/password_change.html',
        success_url='/accounts/password/change/done/'
    ), name='password_change'),
    
    path('password/change/done/', auth_views.PasswordChangeDoneView.as_view(
        template_name='accounts/password_change_done.html'
    ), name='password_change_done'),
]