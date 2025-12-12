from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .custom_permission import HasRole
from .models import CustomUser
from .serializers import CustomUserSerializer
from drf_spectacular.utils import extend_schema


# Create your views here.
@extend_schema(
    tags=["Users"],
    description="API endpoint that allows users to be viewed. Admin users can view all users, while standard users can only view their own information.",
    responses={200: CustomUserSerializer(many=True)}
)
class UserViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated, HasRole]
    serializer_class = CustomUserSerializer
    required_roles = ["admin", "standard_user"]

    def get_queryset(self):
        # If user has admin role, return all users
        if "admin" in getattr(self.request.user, "keycloak_roles", []):
            return CustomUser.objects.all()

        # Otherwise, return only the current user
        return CustomUser.objects.filter(pk=self.request.user.pk)
    