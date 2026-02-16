# ------------------------------------------------------------------
# URLS.PY (App Level)
# These URLS are for the "scanner" API specifically.
# They all start with /scanner/ from the main urls.py
# ------------------------------------------------------------------
from django.urls import path
from . import views

urlpatterns = [
    # API Endpoints (communicate with JSON data)
    path('api/register/', views.register, name='register'),         # User Registration
    path('api/login/', views.login_view, name='login'),             # User Login
    path('api/logout/', views.logout_view, name='logout'),          # Ends session
    path('api/profile/', views.user_profile, name='profile'),       # Get user info
    
    # Scanning Endpoints
    path('api/scan-headers/', views.scan_headers, name='scan_headers'), # Run header scan
    path('api/scan-ports/', views.scan_network, name='scan_network'),   # Run port scan
    
    # History
    path('api/scan-history/', views.scan_history, name='scan_history'), # Get past scans
    path('api/check-auth/', views.check_auth, name='check_auth'),       # Verify login status
]