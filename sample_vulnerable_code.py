```python
import re
import hashlib

class VulnerableWebApp:
    """
    A vulnerable web application class that demonstrates common SQL injection vulnerabilities
    WITHOUT creating any actual database files - uses mock SQL query construction
    """
    def __init__(self):
        # Mock database - in-memory user data
        self.users = [
            {'id': 1, 'username': 'admin', 'password': self.hash_password('admin123'), 'email': 'admin@example.com', 'role': 'admin'},
            {'id': 2, 'username': 'john_doe', 'password': self.hash_password('password123'), 'email': 'john@example.com', 'role': 'user'},
            {'id': 3, 'username': 'jane_smith', 'password': self.hash_password('securepass'), 'email': 'jane@example.com', 'role': 'user'}
        ]
    
    def hash_password(self, password):
        """Hashes the password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def verify_password(self, password, hashed_password):
        """Verifies the password against its hash."""
        return self.hash_password(password) == hashed_password
    
    def login(self, username, password):
        """
        SECURE: Login function using password hashing and secure comparison.
        """
        # Input validation and sanitization
        if not isinstance(username, str) or not isinstance(password, str):
            return {'authenticated': False, 'error': 'Invalid input types'}

        # Simulate database query using secure comparison after password hashing
        for user in self.users:
            if user['username'] == username and self.verify_password(password, user['password']):
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
        SECURE: User info retrieval with input validation and sanitization.
        """
        try:
            user_id = int(user_id)  # Enforce integer type
        except ValueError:
            return {'error': 'Invalid user ID format'}
        
        if user_id <= 0:
            return {'error': 'Invalid user ID value'}

        for user in self.users:
            if user['id'] == user_id:
                return user
        
        return None
    
    def search_users(self, search_term):
        """
        SECURE: User search with input validation and sanitization.
        """
        if not isinstance(search_term, str):
            return {'error': 'Invalid search term'}

        # Basic sanitization to prevent simple injection attempts
        search_term = re.sub(r"[^a-zA-Z0-9\s]", "", search_term)  # Allow only alphanumeric characters and spaces

        results = []
        for user in self.users:
            if search_term.lower() in user['username'].lower() or search_term.lower() in user['email'].lower():
                results.append({'username': user['username'], 'email': user['email']})
        
        return results
    
    def update_password(self, username, new_password):
        """
        SECURE: Password update function with password hashing.
        """
        if not isinstance(username, str) or not isinstance(new_password, str):
            return {'error': 'Invalid input types'}

        if len(new_password) < 8:
            return {'error': 'Password must be at least 8 characters long'}
        
        hashed_password = self.hash_password(new_password)
        
        for user in self.users:
            if user['username'] == username:
                user['password'] = hashed_password
                return True
        
        return False
    
    def admin_query(self, custom_query):
        """
        RESTRICTED: Admin query function with strict input validation.
        """
        if not isinstance(custom_query, str):
            return {'error': 'Invalid query format'}

        # Whitelist approach: Only allow SELECT queries on the users table
        allowed_query = re.compile(r"^SELECT\s+(username|email|id|role)\s+FROM\s+users\s+WHERE\s+(username|email|id)\s*=?\s*['\"]\w+['\"]?$", re.IGNORECASE)

        if not allowed_query.match(custom_query):
            return {
                'vulnerability': 'DIRECT_SQL_EXECUTION_PREVENTED',
                'severity': 'CRITICAL',
                'message': 'Only specific SELECT queries on the users table are allowed.'
            }

        return {'message': 'Query executed (simulated)'}

# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    app = VulnerableWebApp()
    
    print("=== SECURE WEB APPLICATION DEMO ===")
    print("This demonstrates prevention of SQL injection vulnerabilities\n")
    
    # Normal usage
    print("1. === Normal Login ===")
    result = app.login("admin", "admin123")
    print(f"Login result: {result}\n")
    
    # Demonstrate SQL injection vulnerabilities
    print("2. === SQL Injection Attack Examples ===")
    
    # SQL injection in login - bypass authentication
    print("2.1 Authentication bypass attempt:")
    malicious_input = "admin' OR '1'='1' --"
    result = app.login(malicious_input, "any_password")
    print(f"Malicious login result: {result}\n")
    
    # SQL injection in user info
    print("2.2 Data extraction attack attempt:")
    malicious_id = "1 UNION SELECT username, password FROM users"
    result = app.get_user_info(malicious_id)
    print(f"User info attack result: {result}\n")
    
    # SQL injection in search
    print("2.3 Search injection attempt:")
    malicious_search = "' UNION SELECT username, password FROM users --"
    results = app.search_users(malicious_search)
    print(f"Search attack result: {results}\n")
    
    # SQL injection in password update
    print("2.4 Password update injection attempt:")
    malicious_password = "newpass'; UPDATE users SET role='admin' WHERE username='john_doe"
    result = app.update_password("jane_smith", malicious_password)
    print(f"Password update attack: {result}\n")
    
    # Direct SQL execution
    print("2.5 Direct SQL execution (most dangerous) attempt:")
    malicious_query = "DROP TABLE users; --"
    result = app.admin_query(malicious_query)
    print(f"Direct SQL attack: {result}\n")
    
    print("=== SECURITY MEASURES SUMMARY ===")
    print("✅ 1. SQL Injection in login() - PREVENTED with password hashing and secure comparison")
    print("✅ 2. SQL Injection in get_user_info() - PREVENTED with input validation and type enforcement")
    print("✅ 3. SQL Injection in search_users() - PREVENTED with sanitization")
    print("✅ 4. SQL Injection in update_password() - PREVENTED with password hashing and input validation")
    print("✅ 5. Direct SQL execution in admin_query() - RESTRICTED with query whitelisting")
    print("✅ 6. Password storage - Implemented password hashing")
    print("✅ 7. Input validation and sanitization - Implemented throughout the application")
    print("✅ 8. Query logging - Removed sensitive query logging\n")
```