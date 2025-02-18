from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin or request.user.is_superuser

class IsPolice(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_police

class IsCitizen(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_citizen

class IsOwnerOrAdminOrPolice(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Citizens can only view or edit their own profiles
        if request.user.is_citizen:
            return obj.user == request.user
        # Admin and Police can view all
        return request.user.is_admin or request.user.is_police