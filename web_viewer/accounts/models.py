"""
Account models for user profiles
"""

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver


class UserProfile(models.Model):
    """Extended user profile with additional information"""
    
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('analyst', 'Security Analyst'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    
    role = models.CharField(
        max_length=20,
        choices=ROLE_CHOICES,
        default='analyst'
    )
    
    organization = models.CharField(max_length=255, blank=True)
    job_title = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=50, blank=True)
    
    avatar = models.ImageField(
        upload_to='avatars/',
        null=True,
        blank=True
    )
    
    email_notifications = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['user__username']
    
    def __str__(self):
        return self.user.username
    
    def get_full_name(self):
        """Get user's full name"""
        if self.user.get_full_name():
            return self.user.get_full_name()
        return self.user.username
    
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin' or self.user.is_staff


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Automatically create profile when user is created"""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save profile when user is saved"""
    instance.profile.save()