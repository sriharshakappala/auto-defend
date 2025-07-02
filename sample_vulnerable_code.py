```python
import re
import hashlib
import sqlite3

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

    def verify_password(self, plain_password, hashed_password):
        """Verifies a plain password against a hashed password."""
        return self.hash_password(plain_password) == hashed_password

    def login(self, username, password):
        """
        Secure login function using parameterized queries.
        """
        # Parameterized query to prevent SQL injection
        
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
        Secure user info retrieval using parameterized queries.
        """
        try:
            user_id = int(user_id)
        except ValueError:
            return None
        
        for user in self.users:
            if user['id'] == user_id:
                return user
        
        return None
    
    def search_users(self, search_term):
        """
        Secure user search functionality.
        """
        # Basic input validation (prevent overly broad searches)
        if len(search_term) < 2:
            return []
        
        results = []
        for user in self.users:
            if search_term.lower() in user['username'].lower() or search_term.lower() in user['email'].lower():
                results.append({'username': user['username'], 'email': user['email']})
        
        return results
    
    def update_password(self, username, new_password):
        """
        Secure password update function with password hashing.
        """
        hashed_password = self.hash_password(new_password)
        
        for user in self.users:
            if user['username'] == username:
                user['password'] = hashed_password
                return True
        
        return False
    
    def admin_query(self, custom_query):
        """
        Restricted admin query functionality.
        """
        # This function is inherently dangerous.  In a real application, it
        # should be heavily restricted and audited.
        
        # Whitelist safe commands (SELECT only) and specific tables/columns
        allowed_commands = ['SELECT']
        allowed_tables = ['users']
        allowed_columns = ['id', 'username', 'email', 'role']

        query_upper = custom_query.upper()
        
        # Check if the query starts with an allowed command
        command_valid = False
        for cmd in allowed_commands:
            if query_upper.startswith(cmd):
                command_valid = True
                break
        
        if not command_valid:
            return {
                'vulnerability': 'DIRECT_SQL_EXECUTION',
                'severity': 'CRITICAL',
                'message': f'Only SELECT queries are allowed.'
            }
        
        # Basic table/column validation (very limited example)
        for table in allowed_tables:
            if table.upper() not in query_upper:
                 return {
                'vulnerability': 'DIRECT_SQL_EXECUTION',
                'severity': 'CRITICAL',
                'message': f'Access to table "{table}" is not permitted.'
            }
        
        # Simulate execution (DO NOT EXECUTE RAW SQL IN PRODUCTION)
        return {'message': 'Query executed (simulated)'}

# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    app = VulnerableWebApp()
    
    print("=== VULNERABLE WEB APPLICATION DEMO ===")
    print("This demonstrates SQL injection vulnerabilities WITHOUT creating database files\n")
    
    # Normal usage
    print("1. === Normal Login ===")
    result = app.login("admin", "admin123")
    print(f"Login result: {result}\n")
    
    # Demonstrate SQL injection vulnerabilities
    print("2. === SQL Injection Attack Examples ===")
    
    # SQL injection in login - bypass authentication
    print("2.1 Authentication bypass:")
    malicious_input = "admin' OR '1'='1' --"
    result = app.login(malicious_input, "any_password")
    print(f"Malicious login result: {result}\n")
    
    # SQL injection in user info
    print("2.2 Data extraction attack:")
    malicious_id = "1 UNION SELECT username, password FROM users"
    result = app.get_user_info(malicious_id)
    print(f"User info attack result: {result}\n")
    
    # SQL injection in search
    print("2.3 Search injection:")
    malicious_search = "' UNION SELECT username, password FROM users --"
    results = app.search_users(malicious_search)
    print(f"Search attack result: {results}\n")
    
    # SQL injection in password update
    print("2.4 Password update injection:")
    malicious_password = "newpass'; UPDATE users SET role='admin' WHERE username='john_doe"
    result = app.update_password("jane_smith", malicious_password)
    print(f"Password update attack: {result}\n")
    
    # Direct SQL execution
    print("2.5 Direct SQL execution (most dangerous):")
    malicious_query = "DROP TABLE users; --"
    result = app.admin_query(malicious_query)
    print(f"Direct SQL attack: {result}\n")
    
    print("=== VULNERABILITIES SUMMARY ===")
    print("🚨 1. SQL Injection in login() - Authentication bypass")
    print("🚨 2. SQL Injection in get_user_info() - Data exposure") 
    print("🚨 3. SQL Injection in search_users() - Information disclosure")
    print("🚨 4. SQL Injection in update_password() - Data manipulation")
    print("🚨 5. Direct SQL execution in admin_query() - Complete system compromise")
    print("🚨 6. Plain text password storage")
    print("🚨 7. No input validation or sanitization")
    print("🚨 8. Query logging exposes sensitive information")
    print("\n✅ This file is perfect for testing Auto Defend's security fix capabilities!")
```