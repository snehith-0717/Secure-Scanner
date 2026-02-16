# ------------------------------------------------------------------
# SERIALIZERS.PY
# This file converts Complex Python Objects -> JSON.
# It allows our JavaScript frontend to read data from the Python backend.
# This process is called "Serialization".
# ------------------------------------------------------------------
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import SecurityScan, UserProfile

class UserSerializer(serializers.ModelSerializer):
    """
    Converts User model to JSON format.
    Exposes only safe fields (username, email, name).
    """
    class Meta:
        model = User
        # We manually specify exactly which fields to include for security.
        # We NEVER include the 'password' field here!
        fields = ['id', 'username', 'email', 'first_name', 'last_name']

class UserProfileSerializer(serializers.ModelSerializer):
    """
    Converts UserProfile model to JSON.
    Includes nested User data.
    """
    # Nested Serializer: This will show the full User object inside the Profile object.
    user = UserSerializer()
    
    class Meta:
        model = UserProfile
        fields = ['user', 'created_at']

class SecurityScanSerializer(serializers.ModelSerializer):
    """
    Converts SecurityScan results to JSON.
    'results' field contains the detailed JSON blob with ports/headers info.
    """
    class Meta:
        model = SecurityScan
        fields = ['id', 'target', 'scan_type', 'results', 'created_at']