# ------------------------------------------------------------------
# VIEWS.PY
# "The Traffic Controller"
# This file receives requests from the website (Frontend), 
# decides what to do, calls the logic (Utils), and returns the answer.
# ------------------------------------------------------------------
from rest_framework import viewsets, status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from .models import SecurityScan, UserProfile
from .serializers import UserSerializer, SecurityScanSerializer, UserProfileSerializer
from .utils import scan_security_headers, scan_ports, validate_url, validate_ip_or_domain
import json
import re
from django.utils import timezone
from datetime import timedelta

# ------------------------------------------------------------------
# AUTHENTICATION & USERS
# ------------------------------------------------------------------

@api_view(['POST']) # Only allow POST requests (sending data), not GET (reading data)
@permission_classes([AllowAny]) # Allow anyone (even if not logged in) to register
@throttle_classes([AnonRateThrottle]) # Limit rate of registrations to prevent spam bots
def register(request):
    """
    User registration endpoint.
    Handles creating a new user account with robust password validation.
    """
    try:
        # 1. Get data from the request
        data = request.data
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        # Simple validation: ensure everything is there
        if not username or not email or not password:
            return Response({'error': 'All fields required'}, status=status.HTTP_400_BAD_REQUEST)

        # ---------------------------------------------------------
        # Username Validation
        # Strict alphanumeric check (a-z, A-Z, 0-9)
        # ---------------------------------------------------------
        if not re.match(r'^[a-zA-Z0-9]+$', username):
            return Response({'error': 'Username must contain only alphanumeric characters (letters and numbers). No special characters or spaces allowed.'}, status=status.HTTP_400_BAD_REQUEST)

        # ---------------------------------------------------------
        # Email Validation
        # Check if email is in a valid format (user@domain.com)
        # ---------------------------------------------------------
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if not email_pattern.match(email):
            return Response({'error': 'Invalid email address format'}, status=status.HTTP_400_BAD_REQUEST)
        
        # ---------------------------------------------------------
        # Strong Password Validation
        # At least 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
        # ---------------------------------------------------------
        # Regex explanation:
        # (?=.*[a-z]) : At least one lowercase
        # (?=.*[A-Z]) : At least one uppercase
        # (?=.*\d)    : At least one digit
        # (?=.*[\W_]) : At least one special character
        # .{8,}       : Length at least 8
        password_pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$')
        
        if not password_pattern.match(password):
            return Response({
                'error': 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if user already exists
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        
        # 2. Create the User
        # "User.objects.create_user" handles hashing the password for us (security best practice)
        # We NEVER store passwords in plain text!
        user = User.objects.create_user(username=username, email=email, password=password)
        
        # 3. Create a Profile
        # We also create a separate "Profile" linked to this user for extra data
        UserProfile.objects.create(user=user)
        
        # 4. Success!
        return Response({'message': 'Registration successful'}, status=status.HTTP_201_CREATED)
    
    except Exception as e:
        # Catch any unexpected errors so the server doesn't crash
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([AnonRateThrottle])
def login_view(request):
    """
    User login endpoint.
    Authenticates username and password and returns user details.
    """
    try:
        data = request.data
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return Response({'error': 'Username and password required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # ---------------------------------------------------------
        # ACCOUNT LOCKOUT CHECK
        # ---------------------------------------------------------
        user_obj = None
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            # Don't reveal user doesn't exist yet, we will fail later
            pass
            
        if user_obj:
            # Check if profile exists (create if missing for legacy users)
            if not hasattr(user_obj, 'userprofile'):
                UserProfile.objects.create(user=user_obj)
                
            profile = user_obj.userprofile
            
            # Check if locked out
            if profile.lockout_until and profile.lockout_until > timezone.now():
                return Response({
                    'error': 'Account locked due to too many failed attempts. Please try again in 15 minutes.'
                }, status=status.HTTP_403_FORBIDDEN)

        # ---------------------------------------------------------
        # AUTHENTICATION
        # ---------------------------------------------------------
        # authenticate() checks the credentials against the database for us
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # SUCCESS
            # Reset counters
            if hasattr(user, 'userprofile'):
                user.userprofile.failed_login_attempts = 0
                user.userprofile.lockout_until = None
                user.userprofile.save()
            
            # login() creates the session and sends the cookie to the browser
            login(request, user)
            return Response({
                'message': 'Login successful',
                'user': {'id': user.id, 'username': user.username, 'email': user.email}
            }, status=status.HTTP_200_OK)
        else:
            # FAILURE
            if user_obj:
                profile = user_obj.userprofile
                profile.failed_login_attempts += 1
                
                # Check if we hit the limit
                if profile.failed_login_attempts >= 5:
                    profile.lockout_until = timezone.now() + timedelta(minutes=15)
                    profile.save()
                    return Response({
                        'error': 'Account locked due to too many failed attempts. Please try again in 15 minutes.'
                    }, status=status.HTTP_403_FORBIDDEN)
                
                profile.save()
            
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated]) # Must be logged in
def logout_view(request):
    """User logout endpoint"""
    logout(request) # Clears the session cookie
    return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """
    Get or update user profile.
    GET: Read data
    PUT: Update data
    """
    try:
        user = request.user
        
        if request.method == 'GET':
            # serialization isn't strictly necessary for a manual dict, but good for consistency
            return Response({
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }, status=status.HTTP_200_OK)
        
        elif request.method == 'PUT':
            data = request.data
            # .get('field', default) keeps the old value if the new one isn't provided
            user.first_name = data.get('first_name', user.first_name)
            user.last_name = data.get('last_name', user.last_name)
            user.save() # Commit changes to DB
            
            return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ------------------------------------------------------------------
# SCANNING LOGIC
# ------------------------------------------------------------------

@api_view(['POST'])
@permission_classes([IsAuthenticated]) # Only logged-in users can scan
@throttle_classes([UserRateThrottle]) # Rate limit valid users (e.g. 100/day)
def scan_headers(request):
    """
    Scan security headers of target URL.
    This function:
    1. Validates the URL.
    2. Calls scan_security_headers() utility.
    3. Saves result to database.
    """
    try:
        target = request.data.get('target')
        
        if not target:
            return Response({'error': 'Target URL required'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Ensure URL has http/https
        if not target.startswith('http'):
            target = 'http://' + target
        
        if not validate_url(target):
            return Response({'error': 'Invalid URL format'}, status=status.HTTP_400_BAD_REQUEST)
        
        # --- EXECUTE SCAN ---
        # This calls our custom function in utils.py
        results = scan_security_headers(target)
        
        # --- SAVE RESULTS ---
        scan = SecurityScan.objects.create(
            user=request.user,
            target=target,
            scan_type='header',
            results=results
        )
        
        # Return the saved scan data to the frontend
        return Response(SecurityScanSerializer(scan).data, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])
def scan_network(request):
    """
    Scan ports on target IP or domain.
    1. Validates input (IP or Domain).
    2. Runs the socket-based port scan.
    3. Returns risk analysis and results.
    """
    try:
        target = request.data.get('target')
        
        if not target:
            return Response({'error': 'Target IP or domain required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not validate_ip_or_domain(target):
            return Response({'error': 'Invalid IP address or domain format'}, status=status.HTTP_400_BAD_REQUEST)
        
        # --- EXECUTE SCAN ---
        # This calls our custom function in utils.py
        results = scan_ports(target)
        
        # --- SAVE RESULTS ---
        scan = SecurityScan.objects.create(
            user=request.user,
            target=target,
            scan_type='port',
            results=results
        )
        
        return Response(SecurityScanSerializer(scan).data, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def scan_history(request):
    """Get user's scan history"""
    try:
        # Get all scans belonging to this user
        scans = SecurityScan.objects.filter(user=request.user)
        # Serialize the list of scans (many=True)
        return Response(SecurityScanSerializer(scans, many=True).data, status=status.HTTP_200_OK)
    
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def check_auth(request):
    """Check if user is authenticated"""
    # Simple check used by frontend to see if it should show the "Login" or "Dashboard" button
    return Response({'authenticated': True, 'username': request.user.username})