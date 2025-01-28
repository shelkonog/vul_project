from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
import logging

logger = logging.getLogger(__name__)


class CustomUserAdmin(UserAdmin):
    list_display = ['username', 'department']
    model = CustomUser

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        # Log the action
        self.log_action(request, obj, change)

    def log_action(self, request, obj, change):
        if change:
            logger.info(f'Updated {obj} by {request.user}')
        else:
            logger.info(f'Created {obj} by {request.user}')

admin.site.register(CustomUser, CustomUserAdmin)
