from .models import CustomUser
from rest_framework import serializers

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "keycloak_id",
            "roles",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "keycloak_id", "roles"]
