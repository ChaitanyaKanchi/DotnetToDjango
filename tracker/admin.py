from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import UserDetail, UserResetCode, ResetPasswordModel, ChangePasswordModel, UserSettingsModel

admin.site.register(UserDetail)
admin.site.register(UserResetCode)
admin.site.register(ResetPasswordModel)
admin.site.register(ChangePasswordModel)
admin.site.register(UserSettingsModel)
