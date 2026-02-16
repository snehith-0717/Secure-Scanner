# ------------------------------------------------------------------
# URLS.PY (Project Level)
# "The Main Traffic Cop"
# This file routes the very first part of the URL.
# e.g., if you go to /scanner/, it sends you to the scanner app.
# ------------------------------------------------------------------
from django.contrib import admin
from django.urls import path, include
from django.views.generic import TemplateView

urlpatterns = [
    # Admin Interface
    path('admin/', admin.site.urls),
    
    # Frontend Pages (Serve HTML files directly)
    path('', TemplateView.as_view(template_name='frontend/index.html')),           # Home Page
    path('login/', TemplateView.as_view(template_name='frontend/login.html')),     # Login Page
    path('register/', TemplateView.as_view(template_name='frontend/register.html')), # Register Page
    path('dashboard/', TemplateView.as_view(template_name='frontend/dashboard.html')), # User Dashboard
    path('scanner/', TemplateView.as_view(template_name='frontend/scanner.html')),     # Scanning Interface
    
    # Include urls from the 'scanner' app for API handling
    path('scanner/', include('scanner.urls')),
]