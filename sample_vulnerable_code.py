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
            {'id': 1, 'username': 'admin', 'password': 'admin123', 'email': 'admin@example.com', 'role': 'admin'},
            {'id': 2, 'username': 'john_doe', 'password': 'password123', 'email': 'john@example.com', 'role': 'user'},
            {'id': 3, 'username': 'jane_smith', 'password': 'securepass', 'email': 'jane@example.com', 'role': 'user'}
        ]
    
    def login(self, username, password):
        """
        VULNERABLE: SQL Injection vulnerability in login function
        This function builds SQL queries using string concatenation
        """
        # VULNERABILITY: Direct string concatenation allows SQL injection
        query = f"SELECT id, username, email, role FROM users WHERE username = '{username}' AND password = '{password}'"
        
        print(f"[VULNERABLE] Executing query: {query}")  # This exposes the query
        
        # Simulate SQL injection vulnerability
        if "' OR '1'='1" in username or "' OR '1'='1" in password:
            # SQL injection detected - would bypass authentication in real scenario
            print("[DANGER] SQL Injection detected! Authentication bypassed!")
            return {
                'id': 1,
                'username': 'admin',
                'email': 'admin@example.com', 
                'role': 'admin',
                'authenticated': True,
                'vulnerability': 'SQL_INJECTION_BYPASS'
            }
        
        # Normal authentication
        for user in self.users:
            if user['username'] == username and user['password'] == password:
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
        VULNERABLE: SQL Injection in user info retrieval
        """
        # VULNERABILITY: Direct string formatting allows SQL injection
        query = f"SELECT * FROM users WHERE id = {user_id}"
        print(f"[VULNERABLE] Executing query: {query}")
        
        # Simulate SQL injection vulnerability
        if "UNION" in str(user_id).upper() or "SELECT" in str(user_id).upper():
            print("[DANGER] SQL Injection detected in user_id parameter!")
            # In real scenario, this could expose all user data
            return {
                'vulnerability': 'SQL_INJECTION_DATA_EXPOSURE',
                'exposed_data': self.users  # All user data exposed
            }
        
        # Normal functionality
        try:
            user_id = int(user_id)
            for user in self.users:
                if user['id'] == user_id:
                    return user
        except ValueError:
            pass
        
        return None
    
    def search_users(self, search_term):
        """
        VULNERABLE: SQL injection in search functionality
        """
        # VULNERABILITY: String formatting without sanitization
        query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
        print(f"[VULNERABLE] Executing query: {query}")
        
        # Simulate SQL injection vulnerability
        if "UNION SELECT" in search_term.upper() or "'; DROP" in search_term.upper():
            print("[DANGER] SQL Injection detected in search!")
            return {
                'vulnerability': 'SQL_INJECTION_IN_SEARCH',
                'message': 'Malicious SQL detected - could expose sensitive data or drop tables!'
            }
        
        # Normal search functionality
        results = []
        for user in self.users:
            if search_term.lower() in user['username'].lower() or search_term.lower() in user['email'].lower():
                results.append({'username': user['username'], 'email': user['email']})
        
        return results
    
    def update_password(self, username, new_password):
        """
        VULNERABLE: Password update with multiple security issues
        """
        # VULNERABILITY 1: Plain text password storage
        # VULNERABILITY 2: SQL injection in update query
        query = f"UPDATE users SET password = '{new_password}' WHERE username = '{username}'"
        print(f"[VULNERABLE] Executing query: {query}")
        
        # Check for SQL injection
        if "'; DROP" in new_password or "'; UPDATE" in username:
            print("[DANGER] SQL Injection detected in password update!")
            return {
                'vulnerability': 'SQL_INJECTION_IN_UPDATE',
                'message': 'Malicious SQL could modify multiple records or drop tables!'
            }
        
        # Normal functionality (still vulnerable to plain text storage)
        for user in self.users:
            if user['username'] == username:
                user['password'] = new_password  # VULNERABILITY: Plain text storage
                print(f"[WARNING] Password stored in plain text for user: {username}")
                return True
        
        return False
    
    def admin_query(self, custom_query):
        """
        EXTREMELY VULNERABLE: Direct SQL execution (admin function)
        """
        print(f"[EXTREMELY DANGEROUS] Executing raw query: {custom_query}")
        
        # This represents the ultimate SQL injection vulnerability
        # Direct execution of user-provided SQL
        dangerous_keywords = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'GRANT']
        
        for keyword in dangerous_keywords:
            if keyword in custom_query.upper():
                return {
                    'vulnerability': 'DIRECT_SQL_EXECUTION',
                    'severity': 'CRITICAL',
                    'message': f'Dangerous SQL keyword "{keyword}" detected! This could destroy the entire database!'
                }
        
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