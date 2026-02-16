# ------------------------------------------------------------------
# MODELS.PY
# This file matches Python Classes to Database Tables.
# Every class here becomes a table in 'db.sqlite3'.
# Django handles all the SQL commands for us (via the ORM).
# ------------------------------------------------------------------
from django.db import models
from django.contrib.auth.models import User

class SecurityScan(models.Model):
    """
    Database table to store scan results.
    Each row represents one scan performed by a user.
    """
    # Choices: A list of tuples. The first element is stored in DB, second is displayed to user.
    SCAN_TYPE_CHOICES = [
        ('header', 'Security Header Scan'), # Checks for HTTP headers (X-Frame-Options, etc.)
        ('port', 'Port Scan'),              # Checks for open ports (22, 80, 443, etc.)
    ]
    
    # ------------------------------------------------------------------
    # FIELDS (Columns in the database)
    # ------------------------------------------------------------------
    
    # ForeignKey: Creates a link to another table (the User table).
    # on_delete=models.CASCADE: If the User is deleted, delete all their scans too.
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # CharField: Stores text. max_length provided to limit storage size.
    target = models.CharField(max_length=255) # The URL (e.g., google.com) or IP being scanned
    
    # Choices field limits the values to our predefined list above.
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPE_CHOICES)
    
    # JSONField: A special field to store complex data (lists, dictionaries) directly.
    # We use this because scan results can vary in size and structure.
    # SQLite supports this by storing it as text, but Django lets us use it like a Python dict.
    results = models.JSONField()
    
    # DateTimeField: Stores when the row was created.
    # auto_now_add=True: Automatically set this to "now" when the object is first created.
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        # Default ordering: Newest scans first (descending order of creation time)
        ordering = ['-created_at']
    
    def __str__(self):
        # This determines how the object is displayed in the Admin panel or console.
        return f"{self.user.username} - {self.target} - {self.scan_type}"

class UserProfile(models.Model):
    """
    Extension of the default User model.
    The built-in User model has username/password/email.
    We use this 'Profile' to store extra info if we ever need it (e.g., phone number, bio).
    """
    # OneToOneField: Each User has exactly ONE Profile, and each Profile belongs to ONE User.
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    
    # Lockout Fields
    failed_login_attempts = models.IntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.user.username