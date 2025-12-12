from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.
class CustomUser(AbstractUser):
    keycloak_id = models.CharField(max_length=255, unique=True, db_index=True)
    roles = models.JSONField(default=list, blank=True)
    middle_name = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'username' # login using username
    REQUIRED_FIELDS = [] # no additional fields required

    def __str__(self):
        return self.username or self.keycloak_id
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    # Ensure that a password is not required for Keycloak-authenticated users
    def save(self, *args, **kwargs):
        if not self.pk and not self.has_usable_password():
            self.set_unusable_password()
        super().save(*args, **kwargs)