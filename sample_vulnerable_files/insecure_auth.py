"""
Insecure Authentication & Session Management Vulnerability Demo
=============================================================

VULNERABILITY TYPE: Insecure Authentication & Session Management
SEVERITY: High to Critical
DESCRIPTION: This file demonstrates authentication vulnerabilities including
weak passwords, insecure session handling, and improper access controls.

ATTACK VECTORS:
- Brute force attacks on weak passwords
- Session hijacking and fixation
- Privilege escalation
- Insecure password storage

IMPACT:
- Account takeover
- Unauthorized access
- Identity theft
- Session hijacking
"""

import hashlib
import time
from datetime import datetime, timedelta

class VulnerableAuthSystem:
    
    def __init__(self):
        # VULNERABILITY: Plain text password storage
        self.users = {
            'admin': {'password': 'admin123', 'role': 'admin'},
            'user': {'password': 'password', 'role': 'user'},
            'guest': {'password': '123456', 'role': 'guest'}
        }
        self.sessions = {}
    
    def vulnerable_login(self, username, password):
        """
        🚨 VULNERABILITY: Multiple Authentication Issues
        - Plain text password storage
        - User enumeration
        - No brute force protection
        """
        
        # VULNERABILITY: User enumeration
        if username not in self.users:
            return {'success': False, 'error': 'Username does not exist'}
        
        user = self.users[username]
        
        # VULNERABILITY: Plain text password comparison
        if user['password'] != password:
            return {'success': False, 'error': 'Invalid password'}
        
        # VULNERABILITY: Predictable session token
        session_token = f"{username}_{int(time.time())}"
        
        # VULNERABILITY: No session expiration
        self.sessions[session_token] = {
            'username': username,
            'role': user['role'],
            'created_at': datetime.now()
        }
        
        return {
            'success': True,
            'session_token': session_token,
            'username': username,
            'role': user['role']
        }

# Example demonstrating vulnerabilities
if __name__ == "__main__":
    print("=== AUTHENTICATION VULNERABILITY DEMO ===")
    
    auth = VulnerableAuthSystem()
    
    # Brute force attack
    common_passwords = ['123456', 'password', 'admin123']
    for pwd in common_passwords:
        result = auth.vulnerable_login("admin", pwd)
        if result['success']:
            print(f"SUCCESS: Password '{pwd}' worked!")
            break 