from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, CitizenProfile, StaffProfile

# Inline profiles for better user experience
class CitizenProfileInline(admin.StackedInline):
    model = CitizenProfile
    can_delete = False
    verbose_name_plural = "Citizen Profile"
    fieldsets = (("Personal Details", {"fields": ("user",)}),)

class StaffProfileInline(admin.StackedInline):
    model = StaffProfile
    can_delete = False
    verbose_name_plural = "Staff Profile"
    fieldsets = (("Personal Details", {"fields": ("user",)}),)

# Customizing UserAdmin to display role and profile in Django Admin
class UserAdmin(BaseUserAdmin):
    list_display = ('id', 'username', 'email', 'role', 'is_staff', 'is_active', 'date_joined')
    list_filter = ('role', 'is_staff', 'is_superuser', 'is_active')
    search_fields = ('username', 'email', 'first_name', 'last_name')  # Search by keyword
    ordering = ('id',)  # Default ordering
    fieldsets = (
        (None, {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('role', 'is_staff', 'is_superuser', 'is_active')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    # Allow sorting by fields in ascending and descending order
    sortable_by = ['id', 'username', 'email', 'role', 'date_joined']

    # Display citizen or staff profile inline based on role
    def get_inline_instances(self, request, obj=None):
        if obj:
            if obj.role == User.Roles.CITIZEN:
                return [CitizenProfileInline(self.model, self.admin_site)]
            elif obj.role in [User.Roles.ADMIN, User.Roles.POLICE]:
                return [StaffProfileInline(self.model, self.admin_site)]
        return []

# Customizing CitizenProfile admin panel
@admin.register(CitizenProfile)
class CitizenProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'user_email', 'user_role')
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name')  # Search by keyword
    list_filter = ('user__role',)
    ordering = ('id',)  # Default sorting by ID
    sortable_by = ['id', 'user__username', 'user__email']  # Allow sorting

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = "Email"

    def user_role(self, obj):
        return obj.user.role
    user_role.short_description = "Role"

# Customizing StaffProfile admin panel
@admin.register(StaffProfile)
class StaffProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'user_email', 'user_role')
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name')  # Search by keyword
    list_filter = ('user__role',)
    ordering = ('id',)  # Default sorting by ID
    sortable_by = ['id', 'user__username', 'user__email']  # Allow sorting

    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = "Email"

    def user_role(self, obj):
        return obj.user.role
    user_role.short_description = "Role"

# Registering the custom UserAdmin
admin.site.register(User, UserAdmin)
