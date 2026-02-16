# ------------------------------------------------------------------
# TESTS.PY
# This file is for automated testing.
# ------------------------------------------------------------------
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from .models import UserProfile
from django.utils import timezone
from datetime import timedelta

class AccountLockoutTests(APITestCase):
    def setUp(self):
        # Create a test user
        self.username = 'testuser'
        self.password = 'StrongPass123!'
        self.email = 'test@example.com'
        self.user = User.objects.create_user(
            username=self.username, 
            email=self.email, 
            password=self.password
        )
        # Ensure profile exists
        if not hasattr(self.user, 'userprofile'):
            UserProfile.objects.create(user=self.user)
            
        self.login_url = reverse('login') # Assuming the URL name is 'login' or we use the path

    def test_lockout_after_five_failures(self):
        """
        Verify account is locked after 5 failed attempts
        """


        # 1. Fail 5 times
        print(f"Testing Login URL: {self.login_url}")
        
        for i in range(5):
            response = self.client.post(self.login_url, {
                'username': self.username,
                'password': 'WRONG_PASSWORD'
            }, format='json')
            
            resp_json = response.json() if response.content else {}
            
            if i < 4:
                # First 4 failures -> 401 Unauthorized
                self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED, 
                    f"Attempt {i+1} failed. Got {response.status_code}. Data: {resp_json}")
            else:
                # 5th failure -> 403 Forbidden
                self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN, 
                    f"5th attempt should trigger lockout. Got {response.status_code}. Data: {resp_json}")
                self.assertIn('Account locked', str(resp_json))

        # 2. Verify DB state
        self.user.userprofile.refresh_from_db()
        self.assertEqual(self.user.userprofile.failed_login_attempts, 5)
        self.assertIsNotNone(self.user.userprofile.lockout_until)
        self.assertTrue(self.user.userprofile.lockout_until > timezone.now())

        # 3. Try with CORRECT password (Should still be locked)
        response = self.client.post(self.login_url, {
            'username': self.username,
            'password': self.password
        }, format='json')
        resp_json = response.json() if response.content else {}

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN,
            f"Should be locked with correct password. Got {response.status_code}. Data: {resp_json}")
        
        # 4. Fast-forward time (Unlock)
        self.user.userprofile.lockout_until = timezone.now() - timedelta(minutes=1)
        self.user.userprofile.save()
        
        # 5. Try with CORRECT password (Should succeed)
        response = self.client.post(self.login_url, {
            'username': self.username,
            'password': self.password
        }, format='json')
        resp_json = response.json() if response.content else {}

        self.assertEqual(response.status_code, status.HTTP_200_OK, 
            f"Should succeed after unlock. Got {response.status_code}. Data: {resp_json}")
        
        # Verify counters reset
        self.user.userprofile.refresh_from_db()
        self.assertEqual(self.user.userprofile.failed_login_attempts, 0)
        self.assertIsNone(self.user.userprofile.lockout_until)

class InputValidationTests(APITestCase):
    def test_registration_username_validation(self):
        """Test strict username validation (alphanumeric only)"""
        url = reverse('register') # Assuming 'register' is the name in urls.py
        
        # 1. Test Valid Username (Alphanumeric)
        data = {
            'username': 'ValidUser123', 
            'email': 'valid@example.com', 
            'password': 'StrongPass123!'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, f"Valid user failed: {response.data}")

        # 2. Test Invalid Username (Special Chars) - Mentor's Case
        data = {
            'username': 'cdac<>//', 
            'email': 'bad1@example.com', 
            'password': 'StrongPass123!'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('alphanumeric', str(response.data))

        # 3. Test Invalid Username (Underscore currently disallowed by strict rule)
        data = {
            'username': 'user_name', 
            'email': 'bad2@example.com', 
            'password': 'StrongPass123!'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    def test_scan_input_validation(self):
        """Test validation for scan targets"""
        # Create user regarding scan
        self.user = User.objects.create_user(username='scanuser', email='scan@test.com', password='StrongPass123!')
        self.client.force_authenticate(user=self.user)
        
        # 1. Test Header Scan with XSS Injection in URL
        url = reverse('scan_headers')
        data = {'target': 'http://example.com<script>alert(1)</script>'}
        response = self.client.post(url, data)
        # Should be 400 Bad Request
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST, f"XSS URL accepted: {response.data}")

        # 2. Test Network Scan with invalid IP
        url = reverse('scan_network') # Assuming name
        data = {'target': '192.168.1.999'} # Invalid octet
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # 3. Test Network Scan with Dangerous chars
        data = {'target': 'google.com; cat /etc/passwd'}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
