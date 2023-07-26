import datetime
from rest_framework_simplejwt.serializers import (
    TokenObtainSerializer,
    TokenObtainPairSerializer,
)
from rest_framework.serializers import ValidationError
from Profile.models import User, BlacklistTokens
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from UserAuthentication.settings import logger
from rest_framework import status


class CustomTokenSerializer(TokenObtainSerializer):
    token_class = RefreshToken
    username_field = "email"

    @classmethod
    def get_token(cls, user):
        token = cls.token_class.for_user(user)
        token["email"] = user.email
        token["is_admin"] = user.is_admin
        token["company_name"] = user.company_name
        return token

    def validate(self, attrs):
        try:
            data = dict(attrs)
            email = data["email"]
            password = data["password"]
            email_validity = User.objects.filter(email=email).exists()
            if not email_validity:
                raise ValidationError("No user found with the provided email")
            user_obj = User.objects.get(email=email)
            password_validity = user_obj.check_password(password)
            if not password_validity:
                raise ValidationError("Incorrect password entered")
            active_user = user_obj.is_active
            if not active_user:
                raise ValidationError("User account is not active")
            credentials = {"username": user_obj.username, "password": password}
            if all(credentials.values()):
                user = authenticate(**credentials)
                if user:
                    logger.info(f"Authenticated user: {user_obj.id}")
                else:
                    raise ValidationError("User authentication failed")
            if not user_obj.last_login:
                first_login = True
            else:
                first_login = False
            user_obj.last_login = datetime.datetime.now()
            user_obj.save()
            refresh = self.get_token(user_obj)
            token = str(refresh.access_token)
            user_session = BlacklistTokens.objects.filter(user=user_obj)
            if user_session.exists():
                user_session.delete()
            BlacklistTokens.objects.create(token=token, user=user_obj)
            response_dict = {
                "token": token,
                "user_id": user_obj.id,
                "full_name": user_obj.full_name,
                "email": data["email"],
                "is_admin": user_obj.is_admin,
                "company_name": user_obj.company_name,
                "first_login": first_login,
            }
            return response_dict
        except Exception as e:
            raise ValidationError(str(e))
