import random
import secrets
import datetime
import smtplib
import requests
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from UserAuthentication.settings import SECRET_KEY
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from Profile.models import BlacklistTokens
from email.mime.multipart import MIMEMultipart
from UserAuthentication import settings
from UserAuthentication.settings import logger
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


filename_attach = "attachment; filename= %s"


def generate_otp():
    """
    Generate and return a six digit OTP
    """
    otp = [i for i in range(000000, 999999)]
    return secrets.choice(otp)


class CustomAuthentication(BaseAuthentication):
    def authenticate(self, request):
        try:
            jwt_token = request.headers["Authorization"].split()[1]
            user_session = BlacklistTokens.objects.filter(token=jwt_token)
            if not user_session.exists():
                raise AuthenticationFailed("JWT Authentication Failed")
            user_obj = user_session.first().user
            return (user_obj, jwt_token)
        except:
            raise AuthenticationFailed("JWT Authentication Failed")


def otp_expiry_time(minutes, hours=None):
    """
    Return the OTP expiry time period.
    """
    if hours is None:
        hours = 0
    return datetime.datetime.now() + datetime.timedelta(hours=hours, minutes=minutes)


def send_an_email(
    receiver_email,
    subject,
    body,
    file_name=None,
    file_path=None,
    login_user_name=None,
    login_user_pass=None,
):
    """
    This method is used to login to the user account , by default the login credentials will be taken from the settings.
    If credentials are provided by user, then particular account will be logged in, required details are
    (login_user_name,login_user_pass,smtp_server,smtp_port)
    This method can also be used to send the files as an attachment in the mail.To send files (filename,filepath) need
    to be provided.
    """
    try:
        # instance of MIMEMultipart
        msg = MIMEMultipart()
        msg["Subject"] = subject
        smtp_server = settings.SMTP_SERVER
        smtp_port = settings.SMTP_PORT
        msg["From"] = smtp_sender_email = settings.SMTP_SENDER_EMAIL
        smtp_password = settings.SMTP_PASSWORD
        if None not in [login_user_name, login_user_pass]:
            msg["From"] = smtp_sender_email = login_user_name
            smtp_password = login_user_pass
        logger.info(
            "SMTP {} {} {} {} ".format(
                smtp_server, smtp_port, smtp_sender_email, smtp_password
            )
        )
        # attach the body with the msg instance
        msg.attach(MIMEText(body, "html"))
        if file_path is not None:
            attachment = open(file_path, "rb")
            # instance of MIMEBase and named as p
            p = MIMEBase("application", "octet-stream")
            # To change the payload into encoded form
            p.set_payload((attachment).read())
            # encode into base64
            encoders.encode_base64(p)
            p.add_header("Content-Disposition", filename_attach % file_name)
            # attach the instance 'p' to instance 'msg'
            msg.attach(p)
        # creates SMTP session
        s = smtplib.SMTP(smtp_server, smtp_port)
        logger.info("CONNECTION")
        # start TLS for security
        s.starttls()
        logger.info("TLS STARTED")
        # Authentication
        s.login(smtp_sender_email, smtp_password)
        logger.info("LOGIN SUCCESS")
        # sending the mail
        for recepient in receiver_email:
            if recepient != "":
                msg["To"] = recepient
        s.sendmail(from_addr=smtp_sender_email, to_addrs=receiver_email, msg=str(msg))
        logger.info("MAIL SENT :")
        # terminating the session
        s.quit()
        return True, "Success"
    except Exception as E:
        logger.info("EXCEPTION :{} ".format(str(E)))
        return False, str(E)


def get_countries():
    """
    Get all the available countries.
    """
    try:
        response = requests.get("https://restcountries.com/v3.1/all")
        data = response.json()
        final_list = []
        for each in data:
            req_dict = {
                "official_name": each["name"]["official"],
                "common_name": each["name"]["common"],
                "timezones": each["timezones"],
                "iso2": each["cca2"],
            }
            try:
                phone_code = each["idd"]["root"]
                if len(each["idd"]["suffixes"]) == 1:
                    phone_code += each["idd"]["suffixes"][0]
            except Exception as e:
                phone_code = None
            req_dict["phone_code"] = phone_code
            final_list.append(req_dict)
        final_list = sorted(final_list, key=lambda x: x["common_name"])
        return final_list
    except Exception as e:
        logger.info(f"Error while getting list of countries: {e}")
        return None
