# ------------------------------------------------------------------
# APPS.PY
# This file configures the 'scanner' application itself.
# ------------------------------------------------------------------
from django.apps import AppConfig


class ScannerConfig(AppConfig):
    """
    Configuration class for the 'scanner' app.
    Registered in INSTALLED_APPS in settings.py.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'
