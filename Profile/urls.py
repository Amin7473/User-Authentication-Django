from django.contrib import admin
from django.urls import path
from Profile import views
from rest_framework_simplejwt.views import TokenObtainPairView
from Profile.serializers import CustomTokenSerializer

urlpatterns = [
    path("AdminRegisterAPI/", views.AdminRegisterAPI.as_view()),
    path(
        "LoginAPI/",
        TokenObtainPairView.as_view(serializer_class=CustomTokenSerializer),
    ),
    path("VerifyOTP/", views.VerifyOTP.as_view()),
    path("ResendOTP/", views.ResendOTP.as_view()),
    path("ForgotPassword/", views.ForgotPassword.as_view()),
    path("ChangePassword/", views.ChangePassword.as_view()),
    path("CountriesAPI/", views.CountriesAPI.as_view()),
]
