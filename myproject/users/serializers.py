from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import CitizenProfile, StaffProfile
import random
import string

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'role', 'created_at']
        read_only_fields = ['created_at', 'role']

class CitizenProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = CitizenProfile
        fields = ['id', 'user']

class StaffProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True) 
    
    class Meta:
        model = StaffProfile
        fields = ['id', 'user']

class CitizenRegistrationSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password', 'password2']
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password2')
        email = validated_data['email']

        # ✅ Check if user already exists
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"error": "User with this email already exists."})

        user = User.objects.create(
            username=email,
            email=email,
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            role=User.Roles.CITIZEN
        )
        user.set_password(validated_data['password'])
        user.save()

        # ✅ Ensure CitizenProfile is created only once
        if not CitizenProfile.objects.filter(user=user).exists():
            CitizenProfile.objects.create(user=user)

        return user


class StaffRegistrationSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    role = serializers.ChoiceField(choices=[User.Roles.ADMIN, User.Roles.POLICE])
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'role','is_admin']
    
    def create(self, validated_data):
        # Generate unique email based on first name, last name and random number
        first_three = validated_data['first_name'][:3].lower()
        last_three = validated_data['last_name'][:3].lower()
        random_digits = ''.join(random.choices(string.digits, k=4))
        email = f"{first_three}{last_three}{random_digits}@example.com"

        # Set is_superuser to True if role is ADMIN
        is_superuser = True if validated_data['role'] == User.Roles.ADMIN else False
        
        # Create user with default password
        user = User.objects.create(
            username=email,
            email=email,
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            role=validated_data['role'],
            is_staff=True,
            is_superuser=is_superuser
        )
        user.set_password('temp@123')
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'role']
        read_only_fields = ['role']
    