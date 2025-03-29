from django.urls import path, include

urlpatterns = [
    path('google/', include('allauth.socialaccount.urls')),  # Google OAuth login
    path('', views.home, name='home'),  # Add your app-specific URLs here
    ]
