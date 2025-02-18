from django.urls import path
from .views import (
    CitizenRegistrationView,
    StaffRegistrationView,
    LoginView,
    LogoutView,
    UserListView,
    CitizenProfileView,
    TestAuthView, 
    StaffProfileView,  
    updateUser,
)
from . import views

urlpatterns = [
    path('register/citizen/', CitizenRegistrationView.as_view(), name='register-citizen'),
    path('register/staff/', StaffRegistrationView.as_view(), name='register-staff'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('profile/', CitizenProfileView.as_view(), name='profile-self'),
    path('profile/staff/', StaffProfileView.as_view(), name='profile-staff'),
    path('profile/update/', updateUser, name='update-user'),

    path('profile/<int:pk>/', CitizenProfileView.as_view(), name='profile-detail'),
    path('test-auth/', TestAuthView.as_view(), name='test-auth'),
]