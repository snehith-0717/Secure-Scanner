from pathlib import Path
from decouple import config, Csv

# ------------------------------------------------------------------
# SETTINGS.PY
# "The Control Center"
# This file contains ALL configuration for the project.
# Think of this as the "System Preferences" or "Settings" menu for your code.
# ------------------------------------------------------------------

# BASE_DIR: This gives us the absolute path to the folder where this project lives on your computer.
# It helps us find files relative to the project root (like the database file or templates).
BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------------
# SECURITY CONFIGURATION
# ------------------------------------------------------------------

USE_X_FORWARDED_HOST = True

# SECRET_KEY: A long random string used to sign sessions and encrypt data.
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# DEBUG: When True, Django shows detailed error pages with code snippets.
# SECURITY WARNING: don't run with debug turned on in production!
# Hackers can use the debug info to find vulnerabilities.
DEBUG = config('DEBUG', default=False, cast=bool) 

# ALLOWED_HOSTS: A list of domain names that this site can serve.
# '*' means "allow everyone" (okay for development, bad for production).
# ALLOWED_HOSTS: A list of domain names that this site can serve.
# '*' means "allow everyone" (okay for development, bad for production).
# FORCE FIX: Allow all hosts to confirm traffic flow and stop 400 errors
ALLOWED_HOSTS = ["security_scanner.com", "localhost", "127.0.0.1"]

# Static files (CSS, JavaScript, Images)
# STATIC_ROOT is where collectstatic will put files for Nginx to serve
STATIC_ROOT = BASE_DIR / 'staticfiles' 

# ------------------------------------------------------------------
# APPLICATIONS
# ------------------------------------------------------------------
# INSTALLED_APPS: All the "plugins" or "modules" that are active in this project.
INSTALLED_APPS = [
    'django.contrib.admin',       # Built-in admin site (http://.../admin)
    'django.contrib.auth',        # Authentication system (Users, Login, Logout)
    'django.contrib.contenttypes',# Tracks all models installed in the project
    'django.contrib.sessions',    # Manages user sessions (keeping you logged in)
    'django.contrib.messages',    # Show "flash" messages (e.g., "Login Successful")
    'django.contrib.staticfiles', # Manages static files (CSS, Images, JS)
    
    # Third-Party Apps
    'rest_framework',             # Django REST Framework: Toolkit for building Web APIs
    'corsheaders',                # Handles Cross-Origin Resource Sharing (allows other sites to talk to API)
    
    # Custom Apps (Our Code)
    'scanner',                    # The core logic for our Security Scanner lives here
]

# ------------------------------------------------------------------
# MIDDLEWARE
# ------------------------------------------------------------------
# MIDDLEWARE: Layers of code that process every request/response.
# Think of these as "Gatekeepers" or "Inspectors" that check traffic coming in and out.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',            # Enhances security (SSL, headers, etc.)
    'django.contrib.sessions.middleware.SessionMiddleware',     # Manages user sessions across requests
    'corsheaders.middleware.CorsMiddleware',                    # Adds CORS headers to responses
    'django.middleware.common.CommonMiddleware',                # Generic stuff (path normalization, user agent checks)
    'django.middleware.csrf.CsrfViewMiddleware',                # Protects against Cross-Site Request Forgery attacks
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Associates users with requests using sessions
    'django.contrib.messages.middleware.MessageMiddleware',     # Enables message support
    'django.middleware.clickjacking.XFrameOptionsMiddleware',   # Protects against Clickjacking attacks
]

ROOT_URLCONF = 'security_scanner.urls' # Points to the main urls.py file

# ------------------------------------------------------------------
# TEMPLATES
# ------------------------------------------------------------------
# TEMPLATES: How Django finds and renders HTML files.
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'], # Look for HTML files in the 'templates' folder at project root
        'APP_DIRS': True,                 # Also look for 'templates' folders inside each app
        'OPTIONS': {
            'context_processors': [
                # Context processors pass variables to every single template automatically
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'security_scanner.wsgi.application' # Entry point for web servers (like Gunicorn)

# ------------------------------------------------------------------
# DATABASE
# ------------------------------------------------------------------
# DATABASES: Configuration for the data storage.
# We are using SQLite, which stores the whole database in a single file called 'db.sqlite3'.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3', 
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# ------------------------------------------------------------------
# PASSWORD VALIDATION
# ------------------------------------------------------------------
# Check password strength when users sign up.
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'}, # Cannot be too similar to user info
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},       # Block common passwords (e.g., "password123")
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},      # Check for entirely numeric passwords
]

# ------------------------------------------------------------------
# INTERNATIONALIZATION
# ------------------------------------------------------------------
LANGUAGE_CODE = 'en-us' # English
TIME_ZONE = 'UTC'       # Universal Coordinated Time
USE_I18N = True         # Internationalization
USE_TZ = True           # Timezone awareness

# ------------------------------------------------------------------
# STATIC FILES
# ------------------------------------------------------------------
# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / "static" # Where we put our global static files
]
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField' # Default primary key field type

# ------------------------------------------------------------------
# DRF (API) SETTINGS
# ------------------------------------------------------------------
# Configuration for Django REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication', # Use session cookies for API authentication
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated', # By default, you MUST be logged in to use the API
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        # Rate Limiting: Prevent abuse by limiting the number of requests per minute/day
        'rest_framework.throttling.AnonRateThrottle', # For guests (not logged in)
        'rest_framework.throttling.UserRateThrottle'  # For registered users
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '20/minute',  # Guests can make 20 requests per minute
        'user': '100/day',    # Users can make 100 requests per day (global limit)
        'scan': '10/minute',  # Special 'scan' scope: Limit scanning actions to 10 per minute
    }
}

# ------------------------------------------------------------------
# CORS & CSRF (Security Headers)
# ------------------------------------------------------------------
# CORS_ALLOWED_ORIGINS: Which websites are allowed to fetch data from our API?
CORS_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:8080",
    "http://127.0.0.1:8080",
    "http://localhost:8005",
    "http://127.0.0.1:8005",
]

# CSRF_TRUSTED_ORIGINS: Which domains can submit forms (POST requests) to us?
CSRF_TRUSTED_ORIGINS = [
    "http://security_scanner.com",
    "http://localhost",
    "http://127.0.0.1",
]

# Session Security Settings
# NOTE: We set these to False by default because we are running without HTTPS locally.
# If you enable HTTPS with a certificate (e.g. Certbot), change these to True!
SECURE_SSL_REDIRECT = False # Set to True if using HTTPS
SESSION_COOKIE_SECURE = False # Set to True if using HTTPS
CSRF_COOKIE_SECURE = False    # Set to True if using HTTPS

# These settings are always good to have:
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

# We trust Nginx to tell us if the request is secure (HTTPS)
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

SESSION_COOKIE_HTTPONLY = True  # Javascript cannot read the session cookie (good security)
SESSION_COOKIE_SAMESITE = 'Lax' # Cookie is sent on navigation from external sites (normal behavior)