"""
Gunicorn Configuration File
--------------------------
This file configures how the Gunicorn application server runs.
"""

# The full path to the Gunicorn executable in your virtual environment
command = '/home/nicky/security_scanner/venv/bin/gunicorn'

# The python path to your project root (where manage.py is)
pythonpath = '/home/nicky/security_scanner'

# Address to bind to. 
# 'unix:...' means it uses a file socket for faster communication with Nginx.
bind = 'unix:/home/nicky/security_scanner/security_scanner.sock'

# Number of worker processes.
# Formula: (2 x Number of CPUs) + 1. For 1 CPU, 3 workers is standard.
workers = 3

# The user Gunicorn runs as.
user = 'nicky'
