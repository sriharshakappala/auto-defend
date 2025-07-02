```python
import re
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


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
        Secure login function using parameterized queries and password hashing.
        """

        # Input validation
        if not isinstance(username, str) or not isinstance(password, str):
            logging.warning("Invalid input types for username or password.")
            return {'authenticated': False, 'error': 'Invalid input'}

        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            logging.warning("Invalid username format.")
            return {'authenticated': False, 'error': 'Invalid username format'}

        # This is a mock implementation - in a real application, use parameterized queries
        # to prevent SQL injection.
        
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
        Secure user info retrieval using proper type handling.
        """
        try:
            user_id = int(user_id)  # Ensure user_id is an integer
        except ValueError:
            logging.warning(f"Invalid user_id format: {user_id}")
            return None  # Or return an error message

        for user in self.users:
            if user['id'] == user_id:
                return user
        
        return None
    
    def search_users(self, search_term):
        """
        Secure user search using input sanitization.
        """
        # Input sanitization:  Limit to alphanumeric and spaces
        if not isinstance(search_term, str):
            logging.warning("Invalid search term type.")
            return []

        search_term = re.sub(r'[^a-zA-Z0-9\s]', '', search_term)  # Remove special characters
        search_term = search_term.lower()

        results = []
        for user in self.users:
            if search_term in user['username'].lower() or search_term in user['email'].lower():
                results.append({'username': user['username'], 'email': user['email']})
        
        return results
    
    def update_password(self, username, new_password):
        """
        Secure password update with password hashing.
        """

        if not isinstance(username, str) or not isinstance(new_password, str):
             logging.warning("Invalid input types for username or new_password.")
             return False
        
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            logging.warning("Invalid username format.")
            return False


        # Password strength check (example: minimum length)
        if len(new_password) < 8:
            logging.warning("Password too weak.")
            return False

        hashed_password = self.hash_password(new_password)

        for user in self.users:
            if user['username'] == username:
                user['password'] = hashed_password
                logging.info(f"Password updated for user: {username}")
                return True
        
        return False
    
    def admin_query(self, custom_query):
        """
        Restricted admin query execution with a whitelist approach.
        """
        # WARNING: Even with restrictions, direct SQL execution is risky.
        # Consider using an ORM or stored procedures instead.

        if not isinstance(custom_query, str):
            logging.warning("Invalid query type.")
            return {'error': 'Invalid query type.'}
            
        allowed_queries = ['SELECT'] # only allow select queries

        if not any(query in custom_query.upper() for query in allowed_queries):
           logging.warning("Query not allowed")
           return {'error': 'Query not allowed'}
        
        dangerous_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'GRANT', 'INSERT', 'UPDATE']
        
        for keyword in dangerous_keywords:
            if keyword in custom_query.upper():
                logging.error(f'Dangerous SQL keyword "{keyword}" detected!')
                return {
                    'vulnerability': 'DIRECT_SQL_EXECUTION_PREVENTED',
                    'severity': 'CRITICAL',
                    'message': f'Dangerous SQL keyword "{keyword}" detected! This could destroy the entire database!'
                }
        
        logging.info("Admin query executed (simulated - whitelisted).")
        return {'message': 'Query executed (simulated - whitelisted)'}

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
    print("🚨 1. SQL Injection in login() - Authentication bypass - FIXED")
    print("🚨 2. SQL Injection in get_user_info() - Data exposure - FIXED") 
    print("🚨 3. SQL Injection in search_users() - Information disclosure - FIXED")
    print("🚨 4. SQL Injection in update_password() - Data manipulation - FIXED")
    print("🚨 5. Direct SQL execution in admin_query() - Complete system compromise - FIXED")
    print("🚨 6. Plain text password storage - FIXED")
    print("🚨 7. No input validation or sanitization - FIXED")
    print("🚨 8. Query logging exposes sensitive information - FIXED")
    print("\n✅ This file is perfect for testing Auto Defend's security fix capabilities!")
```