"""
WSGI config for security_scanner project.

------------------------------------------------------------------
WSGI.PY - Web Server Gateway Interface
This is the standard entry point for Python web servers (like Gunicorn).
It sits between the Web Server and our Django Code.
------------------------------------------------------------------

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

# 1. Point to our settings file
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'security_scanner.settings')

# 2. Extract the application object
# This is what the web server (like Gunicorn or Apache) talks to.
# WSGI = Web Server Gateway Interface (Standard Python web protocol)
application = get_wsgi_application()
