from rest_framework.permissions import BasePermission


class HasRole(BasePermission):
    """
    Custom permission to check if user has required role.
    Usage: permission_classes = [HasRole]
    Set required_roles as a class attribute on your view.
    """

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        user_roles = getattr(request.user, "roles", [])

        # Admins can access everything
        if "admin" in user_roles:
            return True

        # Get required roles from view
        required_roles = getattr(view, "required_roles", [])

        # If no roles are required, block access
        if not required_roles:
            return False

        # Check if user has any of the required roles
        return any(role in user_roles for role in required_roles)
    