from django.contrib import admin
from Profile.models import User, CompanyModel

# Register your models here.


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "email")


@admin.register(CompanyModel)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ("id", "company_name")
