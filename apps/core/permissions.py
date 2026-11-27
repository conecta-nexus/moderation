from rest_framework.permissions import BasePermission


class IsPlatformAdmin(BasePermission):
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and getattr(request.user, "role", None) == "ADMIN"
        )


class CanReadAuditLog(BasePermission):
    message = "The audit:read scope is required."

    def has_permission(self, request, view):
        return "audit:read" in getattr(request.user, "scopes", ())
