# ------------------------------------------------------------------
# ADMIN.PY
# This file handles the Admin Panel configuration.
# We register our models here so we can view/edit them at /admin/
# ------------------------------------------------------------------
from django.contrib import admin
from .models import SecurityScan, UserProfile

# Register your models here.
# This makes 'SecurityScan' and 'UserProfile' visible in the Admin Dashboard
admin.site.register(SecurityScan)
admin.site.register(UserProfile)
