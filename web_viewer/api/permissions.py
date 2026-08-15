"""
Custom API permissions
"""

from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """Allow owners to edit, others read-only"""
    
    def has_object_permission(self, request, view, obj):
        # Read permissions for any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for owner
        return obj.created_by == request.user or obj.initiated_by == request.user


class IsAdminOrReadOnly(permissions.BasePermission):
    """Allow admins to edit, others read-only"""
    
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return request.user.is_authenticated
        
        return request.user.is_staff
