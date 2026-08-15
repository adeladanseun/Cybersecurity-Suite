"""
Views for user authentication and profile management
"""

from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.generic import CreateView, UpdateView
from django.urls import reverse_lazy

from .forms import UserRegistrationForm, UserLoginForm, UserProfileForm
from .models import UserProfile


class RegisterView(CreateView):
    """User registration view"""
    form_class = UserRegistrationForm
    template_name = 'accounts/register.html'
    success_url = reverse_lazy('dashboard')
    
    def form_valid(self, form):
        """Save user and log them in"""
        response = super().form_valid(form)
        user = form.save()
        login(self.request, user)
        messages.success(self.request, f'Welcome {user.username}! Your account has been created.')
        return redirect(self.success_url)
    
    def form_invalid(self, form):
        """Add error message"""
        messages.error(self.request, 'Please correct the errors below.')
        return super().form_invalid(form)


class ProfileUpdateView(UpdateView):
    """Update user profile"""
    model = UserProfile
    form_class = UserProfileForm
    template_name = 'accounts/profile.html'
    success_url = reverse_lazy('accounts:profile')
    
    def get_object(self, queryset=None):
        """Get current user's profile"""
        return self.request.user.profile
    
    def form_valid(self, form):
        """Save profile and show success message"""
        messages.success(self.request, 'Profile updated successfully.')
        return super().form_valid(form)


@login_required
def profile_view(request):
    """View user profile"""
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=request.user.profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('accounts:profile')
    else:
        form = UserProfileForm(instance=request.user.profile)
    
    context = {
        'form': form,
        'profile': request.user.profile,
    }
    
    return render(request, 'accounts/profile.html', context)


def logout_view(request):
    """Logout user"""
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('accounts:login')