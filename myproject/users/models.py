from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _

# Custom User Manager to handle user creation and superuser creation
class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """Create and return a superuser with the 'admin' role."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        user = self.create_user(username, email, password, **extra_fields)
        user.role = User.Roles.ADMIN  # Ensure role is set to Admin
        user.save(using=self._db)

        # Create StaffProfile for the superuser
        from .models import StaffProfile
        StaffProfile.objects.get_or_create(user=user)

        return user

class User(AbstractUser):
    class Roles(models.TextChoices):
        ADMIN = 'admin', _('Admin')
        POLICE = 'police', _('Police')
        CITIZEN = 'citizen', _('Citizen')

    role = models.CharField(
        max_length=10,
        choices=Roles.choices,
        default=Roles.CITIZEN,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserManager()  # Use custom UserManager

    def __str__(self):
        return self.username

    @property
    def is_admin(self):
        return self.role == self.Roles.ADMIN
    
    @property
    def is_police(self):
        return self.role == self.Roles.POLICE
    
    @property
    def is_citizen(self):
        return self.role == self.Roles.CITIZEN

    def save(self, *args, **kwargs):
        """Ensure only the appropriate profile is created when a user is saved."""
        is_new = self.pk is None  # Check if user is being created

        super().save(*args, **kwargs)  # Save the User first

        if is_new:
            if self.role == self.Roles.CITIZEN and not hasattr(self, 'citizen_profile'):
                # Create CitizenProfile ONLY if it does not exist
                CitizenProfile.objects.create(user=self)

            elif self.role in [self.Roles.ADMIN, self.Roles.POLICE] and not hasattr(self, 'staff_profile'):
                # Create StaffProfile ONLY if it does not exist
                StaffProfile.objects.create(user=self)

# Citizen Profile Model
class CitizenProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='citizen_profile')
    # Add any additional fields for citizens here

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"

# Staff Profile Model
class StaffProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='staff_profile')
    # Add any additional fields for staff here

    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"
