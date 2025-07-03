```python
"""
SQL Injection Vulnerability Demo
================================

VULNERABILITY TYPE: SQL Injection
SEVERITY: Critical
DESCRIPTION: This file demonstrates SQL injection vulnerabilities where user input
is directly concatenated into SQL queries without proper parameterization or validation.

ATTACK VECTORS:
- Authentication bypass using malicious input like "admin' OR '1'='1' --"
- Data extraction using UNION-based attacks
- Database modification/destruction using DROP, UPDATE, DELETE statements
- Information disclosure through error-based injection

IMPACT:
- Complete database compromise
- Unauthorized access to sensitive data
- Data manipulation or destruction
- Privilege escalation
"""

import sqlite3
import os

class SecureDatabase:
    def __init__(self):
        # Create a simple in-memory database for demonstration
        self.conn = sqlite3.connect(':memory:')
        self.setup_database()
    
    def setup_database(self):
        """Setup sample database with user data"""
        cursor = self.conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                email TEXT,
                role TEXT,
                balance DECIMAL
            )
        ''')
        
        # Insert sample data
        users = [
            (1, 'admin', 'admin123', 'admin@company.com', 'admin', 10000.00),
            (2, 'john_doe', 'password123', 'john@email.com', 'user', 1500.50),
            (3, 'jane_smith', 'securepass', 'jane@email.com', 'user', 2750.25),
            (4, 'guest', 'guest123', 'guest@email.com', 'guest', 0.00)
        ]
        
        cursor.executemany('INSERT INTO users VALUES (?,?,?,?,?,?)', users)
        self.conn.commit()
    
    def secure_login(self, username, password):
        """
        ✅ FIXED: SQL Injection by using parameterized queries.
        """
        cursor = self.conn.cursor()
        
        # SECURE CODE: Using parameterized query to prevent SQL injection
        query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
        
        try:
            cursor.execute(query, (username, password))
            result = cursor.fetchone()
            if result:
                return {'id': result[0], 'username': result[1], 'role': result[2], 'authenticated': True}
            else:
                return {'authenticated': False}
        except Exception as e:
            print(f"Database error: {e}")
            return {'error': str(e)}
    
    def secure_get_user_data(self, user_id):
        """
        ✅ FIXED: SQL Injection by using parameterized queries.
        """
        cursor = self.conn.cursor()

        # Validate user_id to ensure it's an integer
        try:
            user_id = int(user_id)
        except ValueError:
            print("Invalid user ID format.")
            return []

        # SECURE CODE: Using parameterized query
        query = "SELECT username, email, balance FROM users WHERE id = ?"

        try:
            cursor.execute(query, (user_id,))
            return cursor.fetchall()
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def secure_search(self, search_term):
        """
        ✅ FIXED: SQL Injection by using parameterized queries and escaping wildcards.
        """
        cursor = self.conn.cursor()

        # Properly escape special characters in the search term
        search_term = search_term.replace('%', r'\%').replace('_', r'\_')

        # SECURE CODE: Using parameterized query with escaped wildcards
        query = "SELECT username, email FROM users WHERE username LIKE ?"
        
        try:
            cursor.execute(query, (f"%{search_term}%",))
            return cursor.fetchall()
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def secure_update_balance(self, user_id, amount):
        """
        ✅ FIXED: SQL Injection by using parameterized queries and validating input.
        """
        cursor = self.conn.cursor()

        # Validate both user_id and amount to ensure they are the correct type
        try:
            user_id = int(user_id)
            amount = float(amount)
        except ValueError:
            print("Invalid user ID or amount format.")
            return False

        # SECURE CODE: Using parameterized query
        query = "UPDATE users SET balance = balance + ? WHERE id = ?"
        
        try:
            cursor.execute(query, (amount, user_id))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False
    
    def secure_admin_query(self, custom_sql):
        """
        🚨 CRITICAL VULNERABILITY: Direct SQL Execution - REMOVED
        This function was extremely dangerous and has been removed.
        Executing arbitrary SQL from user input is a massive security risk.
        """
        print("Admin query functionality has been disabled for security reasons.")
        return []


# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    db = SecureDatabase()
    
    print("=== SQL INJECTION VULNERABILITY DEMONSTRATIONS (NOW FIXED) ===\n")
    
    # 1. Normal login
    print("1. Normal Login:")
    result = db.secure_login("admin", "admin123")
    print(f"Result: {result}\n")
    
    # 2. SQL Injection - Authentication Bypass (Should Fail)
    print("2. SQL Injection Attack - Authentication Bypass (Should Fail):")
    malicious_username = "admin' OR '1'='1' --"
    result = db.secure_login(malicious_username, "wrongpassword")
    print(f"Attack Result: {result}\n")
    
    # 3. SQL Injection - Data Extraction (Should Fail or Return No Data)
    print("3. SQL Injection Attack - Data Extraction (Should Fail or Return No Data):")
    malicious_id = "1 UNION SELECT username, password, email FROM users"
    result = db.secure_get_user_data(malicious_id)
    print(f"Extracted Data: {result}\n")
    
    # 4. SQL Injection - Search Attack (Should Return No Unexpected Data)
    print("4. SQL Injection Attack - Search (Should Return No Unexpected Data):")
    malicious_search = "' UNION SELECT username, password FROM users --"
    result = db.secure_search(malicious_search)
    print(f"Search Attack Result: {result}\n")
    
    # 5. SQL Injection - Balance Manipulation (Should Not Work)
    print("5. SQL Injection Attack - Balance Update (Should Not Work):")
    malicious_amount = "0; UPDATE users SET balance = 999999 WHERE username = 'guest' --"
    db.secure_update_balance(2, malicious_amount)
    
    print("\n=== SECURITY RECOMMENDATIONS ===")
    print("✅ ALWAYS use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))")
    print("✅ Validate and sanitize ALL user inputs, even numeric ones.")
    print("✅ Use ORM frameworks with built-in SQL injection protection for larger projects.")
    print("✅ Implement proper error handling that doesn't expose database structure.")
    print("✅ Apply the principle of least privilege for database connections.")
    print("✅ Regularly review and update your security practices.")
```