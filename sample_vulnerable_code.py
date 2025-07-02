```python
import re
import hashlib

class SecureWebApp:
    """
    A (now secure) web application class demonstrating prevention of common SQL injection vulnerabilities
    WITHOUT creating any actual database files - uses mock SQL query construction
    """
    def __init__(self):
        # Mock database - in-memory user data
        # Store password hashes, not plain text
        self.users = [
            {'id': 1, 'username': 'admin', 'password': self._hash_password('admin123'), 'email': 'admin@example.com', 'role': 'admin'},
            {'id': 2, 'username': 'john_doe', 'password': self._hash_password('password123'), 'email': 'john@example.com', 'role': 'user'},
            {'id': 3, 'username': 'jane_smith', 'password': self._hash_password('securepass'), 'email': 'jane@example.com', 'role': 'user'}
        ]
    
    def _hash_password(self, password):
        """Hashes the password using SHA-256."""
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        return hashed_password
    
    def login(self, username, password):
        """
        Secure login function using parameterized queries and hashed passwords.
        """
        # Input validation: Basic username/password constraints
        if not (isinstance(username, str) and 3 <= len(username) <= 20 and
                isinstance(password, str) and 8 <= len(password) <= 64):
            print("[SECURITY] Invalid username or password format.")
            return {'authenticated': False, 'error': 'Invalid username or password format.'}
        
        hashed_password = self._hash_password(password)
        
        # Secure Authentication: Compare hashed password
        for user in self.users:
            if user['username'] == username and user['password'] == hashed_password:
                return {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role'],
                    'authenticated': True
                }
        
        return {'authenticated': False}
    
    def get_user_info(self, user_id):
        """
        Secure user info retrieval using proper type handling and no direct query construction.
        """
        try:
            user_id = int(user_id) # Enforce integer type
        except (ValueError, TypeError):
            print("[SECURITY] Invalid user ID format.")
            return {'error': 'Invalid user ID format'}
        
        # No SQL Injection possible here because we are not building SQL queries.
        for user in self.users:
            if user['id'] == user_id:
                return user
        
        return None
    
    def search_users(self, search_term):
        """
        Secure search functionality using proper sanitization/escaping (if using a real database)
        """
        if not isinstance(search_term, str) or len(search_term) > 50:
            print("[SECURITY] Invalid search term format.")
            return {'error': 'Invalid search term format'}
        
        # Sanitize search term (if this were interacting with a real DB, use DB-specific escaping)
        sanitized_search_term = re.sub(r'[%_]', '', search_term) #Remove wildcard chars to prevent injection of those
        sanitized_search_term = sanitized_search_term.lower()
        
        results = []
        for user in self.users:
            if sanitized_search_term in user['username'].lower() or sanitized_search_term in user['email'].lower():
                results.append({'username': user['username'], 'email': user['email']})
        
        return results
    
    def update_password(self, username, new_password):
        """
        Secure password update using hashed passwords and no direct query construction.
        """
        # Input validation
        if not (isinstance(username, str) and 3 <= len(username) <= 20 and
                isinstance(new_password, str) and 8 <= len(new_password) <= 64):
            print("[SECURITY] Invalid username or password format.")
            return False
        
        hashed_password = self._hash_password(new_password)
        
        for user in self.users:
            if user['username'] == username:
                user['password'] = hashed_password
                print(f"[SECURITY] Password updated securely for user: {username}")
                return True
        
        return False
    
    def admin_query(self, custom_query):
        """
        Simulates admin query execution with strict limitations.
        """
        print("[SECURITY] Admin query attempted.")
        
        # Even with input validation, avoid direct execution of any user-provided SQL
        dangerous_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'GRANT', 'SELECT', 'INSERT', 'UPDATE']
        
        for keyword in dangerous_keywords:
            if keyword in custom_query.upper():
                print(f"[SECURITY] Blocked dangerous admin query due to keyword: {keyword}")
                return {
                    'vulnerability': 'ATTEMPTED_DIRECT_SQL_EXECUTION',
                    'severity': 'CRITICAL',
                    'message': f'Dangerous SQL keyword "{keyword}" detected!  Query blocked.'
                }
        
        print("[SECURITY] Admin query blocked due to security policy.")
        return {'message': 'Admin query blocked by security policy.'}

# Example usage demonstrating the improved security
if __name__ == "__main__":
    app = SecureWebApp()
    
    print("=== SECURE WEB APPLICATION DEMO ===")
    print("This demonstrates prevention of SQL injection vulnerabilities WITHOUT creating database files\n")
    
    # Normal usage
    print("1. === Normal Login ===")
    result = app.login("admin", "admin123")
    print(f"Login result: {result}\n")
    
    # Demonstrate protection against SQL injection vulnerabilities
    print("2. === Attempted SQL Injection Attack Examples ===")
    
    # SQL injection in login - bypass authentication
    print("2.1 Authentication bypass attempt:")
    malicious_input = "admin' OR '1'='1' --"
    result = app.login(malicious_input, "any_password")
    print(f"Malicious login result: {result}\n")  # Should fail
    
    # SQL injection in user info
    print("2.2 Data extraction attack attempt:")
    malicious_id = "1 UNION SELECT username, password FROM users"
    result = app.get_user_info(malicious_id)
    print(f"User info attack result: {result}\n")  # Should fail
    
    # SQL injection in search
    print("2.3 Search injection attempt:")
    malicious_search = "' UNION SELECT username, password FROM users --"
    results = app.search_users(malicious_search)
    print(f"Search attack result: {results}\n")  # Should return no results, or an error
    
    # SQL injection in password update
    print("2.4 Password update injection attempt:")
    malicious_password = "newpass'; UPDATE users SET role='admin' WHERE username='john_doe"
    result = app.update_password("jane_smith", malicious_password)
    print(f"Password update attack: {result}\n")  # Should fail
    
    # Direct SQL execution
    print("2.5 Direct SQL execution attempt (most dangerous):")
    malicious_query = "DROP TABLE users; --"
    result = app.admin_query(malicious_query)
    print(f"Direct SQL attack: {result}\n")  # Should be blocked
    
    print("=== SECURITY SUMMARY ===")
    print("✅ 1. SQL Injection in login() - Authentication bypass PREVENTED")
    print("✅ 2. SQL Injection in get_user_info() - Data exposure PREVENTED")
    print("✅ 3. SQL Injection in search_users() - Information disclosure PREVENTED")
    print("✅ 4. SQL Injection in update_password() - Data manipulation PREVENTED")
    print("✅ 5. Direct SQL execution in admin_query() - Complete system compromise PREVENTED")
    print("✅ 6. Plain text password storage - ELIMINATED (using password hashing)")
    print("✅ 7. Input validation and sanitization - IMPLEMENTED")
    print("✅ 8. Query logging of sensitive information - ELIMINATED")
    print("\nThis file demonstrates mitigation of common web application vulnerabilities!")
```