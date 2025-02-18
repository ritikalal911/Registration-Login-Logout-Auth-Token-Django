from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import PermissionDenied, NotFound
from django.contrib.auth import authenticate, get_user_model
from .models import CitizenProfile, StaffProfile
from rest_framework.decorators import api_view
from .serializers import (
    UserSerializer,
    CitizenProfileSerializer,
    CitizenRegistrationSerializer,
    StaffRegistrationSerializer,
    LoginSerializer,
    UserUpdateSerializer,
    StaffProfileSerializer,
)
from .permissions import IsAdmin, IsPolice, IsCitizen, IsOwnerOrAdminOrPolice

User = get_user_model()

class CitizenRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = CitizenRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
            'role': user.role
        }, status=status.HTTP_201_CREATED)

class StaffRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = StaffRegistrationSerializer
    permission_classes = [IsAdmin]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            'user_id': user.pk,
            'email': user.email,
            'role': user.role,
            'default_password': 'temp@123'
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Try authenticate with email as username
        user = authenticate(username=email, password=password)
        
        # If that fails, check if a user exists with this email
        if user is None:
            try:
                user_obj = User.objects.get(email=email)
                # Try with actual username
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None
        
        if user is not None:
            # Debug print to check user role
            print(f"User authenticated: {user.email}, Role: {user.role}")
            
            # Create or get token
            token, created = Token.objects.get_or_create(user=user)
            
            # Ensure admin users get admin role
            if user.is_superuser or (hasattr(user, 'is_admin') and user.is_admin):
                role = User.Roles.ADMIN if hasattr(User, 'Roles') and hasattr(User.Roles, 'ADMIN') else 'admin'
            else:
                role = user.role
            
            response_data = {
                'token': token.key,
                'user_id': user.pk,
                'email': user.email,
                'role': role
            }
            
            # Add specific message based on actual role
            if role == User.Roles.CITIZEN:
                response_data['message'] = 'Logged in successfully as citizen'
            elif role == User.Roles.ADMIN:
                response_data['message'] = 'Logged in successfully as administrator'
            elif role == User.Roles.POLICE:
                response_data['message'] = 'Logged in successfully as police officer'
            else:
                response_data['message'] = f'Logged in successfully as {role}'
            
            return Response(response_data)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        
class LogoutView(APIView):
    def post(self, request):
        request.user.auth_token.delete()
        return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdmin | IsPolice]

class CitizenProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = CitizenProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdminOrPolice]
    
    def get_queryset(self):
        return CitizenProfile.objects.all()
    
    def get_object(self):
        if self.request.user.is_citizen:
            # For citizens, always return their own profile
            try:
                return CitizenProfile.objects.get(user=self.request.user)
            except CitizenProfile.DoesNotExist:
                raise NotFound("Citizen profile not found")
        
        # For admin and police, check if a pk is provided
        pk = self.kwargs.get('pk')
        if pk:
            # If pk is provided, use it to find the profile
            return super().get_object()
        else:
            # If no pk, return all profiles (to be handled by get_queryset)
            raise NotFound("Profile ID required for admin/police users")
        x
class StaffProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = StaffProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdminOrPolice]
    
    def get_queryset(self):
        return StaffProfile.objects.all()
    
    def get_object(self):
        if self.request.user.is_staff:
            # For citizens, always return their own profile
            try:
                return StaffProfile.objects.get(user=self.request.user)
            except StaffProfile.DoesNotExist:
                raise NotFound("Staff profile not found")
        

from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework import status
from rest_framework.response import Response
from .serializers import UserUpdateSerializer
from .models import User

from rest_framework.exceptions import NotFound
from rest_framework import status
from rest_framework.response import Response
from .serializers import UserUpdateSerializer
from .models import User

@api_view(['PATCH', 'PUT'])
def updateUser(request):
    try:
        # Fetch the current logged-in user based on the authenticated request
        user = User.objects.get(pk=request.user.pk)
    except User.DoesNotExist:
        raise NotFound(detail="User not found")

    # If the user is updating their email, check if it's already taken by another user
    if 'email' in request.data:
        new_email = request.data['email']
        if User.objects.filter(email=new_email).exclude(pk=user.pk).exists():
            return Response(
                {"error": "Email already exists"},
                status=status.HTTP_400_BAD_REQUEST
            )

    # For PATCH: Allow partial updates (update only fields passed)
    if request.method == 'PATCH':
        serializer = UserUpdateSerializer(instance=user, data=request.data, partial=True)
    # For PUT: Ensure all fields are provided
    elif request.method == 'PUT':
        serializer = UserUpdateSerializer(instance=user, data=request.data, partial=False)

        # Manually check if all required fields are provided in the request
        missing_fields = []
        for field in serializer.fields:
            if serializer.fields[field].required and field not in request.data:
                missing_fields.append(field)

        if missing_fields:
            return Response(
                {"detail": f"Missing required fields: {', '.join(missing_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    # If serializer is valid, save and return the updated user data
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    # If serializer has errors, return the error response
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class TestAuthView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        return Response({
            'message': 'Authentication successful',
            'user': request.user.username,
            'email': request.user.email,
            'role': request.user.role,
            'auth_type': str(type(request.auth))
        })  