"""
ASGI config for security_scanner project.

------------------------------------------------------------------
ASGI.PY - Async Server Gateway Interface
This is the entry point for "Async" web servers.
It sits between the Web Server and our Django Code.
------------------------------------------------------------------

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

# 1. Point to settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'security_scanner.settings')

# 2. Get the ASGI application
# ASGI = Asynchronous Server Gateway Interface
# Used for handling things like WebSockets or Async features (if we added them later)
application = get_asgi_application()
