import datetime
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from Profile.mixins import ResponseMixin
from Profile.models import BlacklistTokens, CompanyModel, User
from Profile.static_vals import success_msg, failure_msg, otp_expiry_minutes
from Profile.utils import (
    CustomAuthentication,
    generate_otp,
    get_countries,
    otp_expiry_time,
    send_an_email,
)
from django.contrib.auth.hashers import make_password
from UserAuthentication.settings import (
    logger,
)
from django.template.loader import render_to_string
import threading
from django.db.models import Q
import mysql.connector


class AdminRegisterAPI(APIView, ResponseMixin):

    """
    Register user as Admin
    """

    def post(self, request):
        try:
            data = request.data
            user_exists = User.objects.filter(email=data["email"]).exists()
            if user_exists:
                return self.sendresponse(
                    msg="User with this email already exists",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            company_name_exists = CompanyModel.objects.filter(
                company_name=data["company_name"]
            ).exists()
            if company_name_exists:
                return self.sendresponse(
                    msg="Company with this name already exists",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            otp = generate_otp()
            user_data = {
                "email": data["email"].lower(),
                "username": data["email"].lower(),
                "full_name": data["full_name"],
                "country_code": data["country_code"],
                "mobile_number": data["mobile_number"],
                "is_admin": True,
                "otp": otp,
                "otp_time": otp_expiry_time(otp_expiry_minutes),
                "password": make_password(data["password"]),
                "timezone_info": data["timezone_info"],
            }
            user_obj = User.objects.create(**user_data)
            logger.info("User created")
            company_data = {
                "user": user_obj,
                "country_code": data["country_code"],
                "mobile_number": data["mobile_number"],
                "company_name": data["company_name"],
                "timezone_info": data["timezone_info"],
                "country": data["country"],
            }
            company_obj = CompanyModel.objects.create(**company_data)
            user_obj.company_name = company_obj.company_name
            user_obj.save()
            logger.info("Company has been created")
            context = {
                "otp_list": list(str(otp)),
                "otp_expiry_minutes": str(otp_expiry_minutes) + ":00 min",
            }
            message = render_to_string("user-registration-otp.html", context)
            thread = threading.Thread(
                target=send_an_email,
                kwargs={
                    "receiver_email": [data["email"].lower()],
                    "subject": "Verify your OTP",
                    "body": message,
                },
            )
            logger.info("Started email sending")
            thread.start()
            return self.sendresponse(
                msg="User created successfully",
                requeststatus=1,
                status_code=status.HTTP_201_CREATED,
            )

        except Exception as e:
            return self.sendresponse(
                data=str(e),
                msg=failure_msg,
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )


class VerifyOTP(APIView, ResponseMixin):
    def post(self, request):
        """ "
        Verify the OTP provided by the user
        """
        try:
            data = request.data
            email = data["email"].lower()
            if User.objects.filter(email=email).exists():
                return self.sendresponse(
                    msg="User does not exist",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            user_obj = User.objects.get(Q(otp=int(data["otp"])) & Q(email=email))
            if user_obj.otp_time.replace(tzinfo=None) < datetime.datetime.now():
                logger.info("OTP Expired")
                return self.sendresponse(
                    msg="OTP expired",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            user_obj.is_verified = True
            user_obj.save()
            return self.sendresponse(
                msg="OTP verified successfully",
                requeststatus=1,
                status_code=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return self.sendresponse(
                msg="Incorrect OTP",
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return self.sendresponse(
                data=str(e),
                msg=failure_msg,
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )


class ResendOTP(APIView, ResponseMixin):
    def post(self, request):
        try:
            data = request.data
            email = data["email"].lower()
            user_obj = User.objects.get(email=email)
            generated_otp = generate_otp()
            logger.info("OTP Generated")
            user_obj.otp = generated_otp
            user_obj.otp_time = otp_expiry_time(minutes=otp_expiry_minutes)
            user_obj.save()
            context = {
                "otp_list": list(str(generated_otp)),
                "otp_expiry_minutes": str(otp_expiry_minutes) + ":00",
            }
            message = render_to_string("resend-otp.html", context)
            thread = threading.Thread(
                target=send_an_email,
                kwargs={
                    "receiver_email": [data["email"]],
                    "subject": "Resent OTP",
                    "body": message,
                },
            )
            logger.info("Sending email")
            thread.start()
            return self.sendresponse(
                msg="OTP resend successful",
                requeststatus=1,
                status_code=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return self.error_response(msg=f"User {data['email']} does not exists.")
        except Exception as e:
            return self.sendresponse(
                data=str(e),
                msg=failure_msg,
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )


class ForgotPassword(APIView, ResponseMixin):
    def post(self, request):
        """
        Set new password if user forgot old password
        """
        try:
            data = request.data
            email = data["email"].lower()
            user_obj = User.objects.get(email=email)
            user_obj.set_password(data["password"])
            user_obj.save()
            logger.info(f"Password Updated for user: {user_obj.email}")
            return self.sendresponse(
                msg="successfully updated password",
                requeststatus=1,
                status_code=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return self.sendresponse(
                msg="User does not exist",
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return self.sendresponse(
                data=str(e),
                msg=failure_msg,
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )


class ChangePassword(APIView, ResponseMixin):
    permission_classes = (IsAuthenticated,)
    authentication_classes = [CustomAuthentication]

    def post(self, request):
        try:
            data = request.data
            user_obj = User.objects.get(id=request.user.id)
            old_password = data["old_password"]
            new_password = data["new_password"]
            confirm_new_password = data["confirm_new_password"]
            password_validity = user_obj.check_password(old_password)
            if not password_validity:
                return self.sendresponse(
                    msg="Old password incorrect ",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            if new_password != confirm_new_password:
                return self.sendresponse(
                    msg="Passwords do not match",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
            user_obj.set_password(new_password)
            user_obj.save()
            return self.sendresponse(
                msg="Password changed successfully",
                requeststatus=1,
                status_code=status.HTTP_200_OK,
            )
        except Exception as e:
            return self.sendresponse(
                data=str(e),
                msg=failure_msg,
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )


class CountriesAPI(APIView, ResponseMixin):
    """
    Get all the available countries from restcountries API
    """

    def get(self, request):
        try:
            final_list = get_countries()
            if final_list:
                logger.info(f"Countries List Generated")
                for data in final_list:
                    if not data["phone_code"]:
                        final_list.remove(data)
                return self.sendresponse(
                    data=final_list,
                    msg=success_msg,
                    requeststatus=1,
                    status_code=status.HTTP_200_OK,
                )
            else:
                logger.info(f"Rest Countries API Failed")
                return self.sendresponse(
                    msg="Error From Rest Countries API",
                    requeststatus=0,
                    status_code=status.HTTP_400_BAD_REQUEST,
                )
        except Exception as e:
            return self.sendresponse(
                data=str(e),
                msg=failure_msg,
                requeststatus=0,
                status_code=status.HTTP_400_BAD_REQUEST,
            )
