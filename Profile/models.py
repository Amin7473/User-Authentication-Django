from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.
class User(AbstractUser):
    email = models.EmailField(unique=True, blank=True, null=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    country_code = models.CharField(max_length=100, blank=True, null=True)
    profile_picture = models.CharField(max_length=100, blank=True, null=True)
    mobile_number = models.CharField(unique=True, max_length=50, blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    company_name = models.CharField(max_length=250, null=True, blank=True)
    otp = models.IntegerField(null=True, blank=True)
    otp_time = models.DateTimeField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    timezone_info = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return self.email


class CompanyModel(models.Model):
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="user_company"
    )
    country_code = models.CharField(max_length=100, blank=True, null=True)
    mobile_number = models.CharField(max_length=50, blank=True, null=True)
    mail_boxes_limit = models.IntegerField(null=True, blank=True)
    mail_boxes_used = models.IntegerField(null=True, blank=True, default=0)
    company_name = models.CharField(unique=True, max_length=250)
    company_address = models.CharField(max_length=1000, null=True, blank=True)
    website = models.CharField(max_length=250, null=True, blank=True)
    country = models.CharField(max_length=250, null=True, blank=True)
    city = models.CharField(max_length=250, null=True, blank=True)
    timezone_info = models.CharField(max_length=50, blank=True, null=True)
    company_logo = models.CharField(max_length=250, null=True, blank=True)

    class Meta:
        verbose_name = "Company"
        verbose_name_plural = "Companies"

    def __str__(self):
        return self.company_name


class BlacklistTokens(models.Model):
    token = models.CharField(max_length=500)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
