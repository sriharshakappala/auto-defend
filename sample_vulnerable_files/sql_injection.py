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

class VulnerableDatabase:
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
    
    def safe_login(self, username, password):
        """
        ✅ FIXED: SQL Injection in Login Function using parameterized queries
        """
        cursor = self.conn.cursor()
        
        # FIXED CODE: Using parameterized query to prevent SQL injection
        query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
        
        print(f"[SAFE QUERY]: {query} with parameters: {(username, password)}")
        
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
    
    def safe_get_user_data(self, user_id):
        """
        ✅ FIXED: SQL Injection in Data Retrieval using parameterized queries
        Also validates user_id to be an integer
        """
        cursor = self.conn.cursor()

        try:
            user_id = int(user_id)  # Convert user_id to integer and validate
        except ValueError:
            print("Invalid user ID. Must be an integer.")
            return []
        
        # FIXED CODE: Using parameterized query to prevent SQL injection
        query = "SELECT username, email, balance FROM users WHERE id = ?"
        
        print(f"[SAFE QUERY]: {query} with parameter: {(user_id,)}")
        
        try:
            cursor.execute(query, (user_id,))
            return cursor.fetchall()
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def safe_search(self, search_term):
        """
        ✅ FIXED: SQL Injection in Search Function using parameterized queries
        Also using the LIKE operator safely.
        """
        cursor = self.conn.cursor()
        
        # FIXED CODE: Using parameterized query with safe LIKE
        query = "SELECT username, email FROM users WHERE username LIKE ?"
        safe_search_term = f"%{search_term}%"  # Properly escape the search term if needed
        
        print(f"[SAFE QUERY]: {query} with parameter: {(safe_search_term,)}")
        
        try:
            cursor.execute(query, (safe_search_term,))
            return cursor.fetchall()
        except Exception as e:
            print(f"Database error: {e}")
            return []
    
    def safe_update_balance(self, user_id, amount):
        """
        ✅ FIXED: SQL Injection in UPDATE Statement
        Ensures user_id is an integer, and amount is a float.
        """
        cursor = self.conn.cursor()

        try:
            user_id = int(user_id)
            amount = float(amount)
        except ValueError:
            print("Invalid user ID or amount. Must be an integer and a number respectively.")
            return False
        
        # FIXED CODE: Using parameterized query
        query = "UPDATE users SET balance = balance + ? WHERE id = ?"
        
        print(f"[SAFE QUERY]: {query} with parameters: {(amount, user_id)}")
        
        try:
            cursor.execute(query, (amount, user_id))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Database error: {e}")
            return False
    
    def safe_admin_query(self, custom_sql):
        """
        🚨 CRITICAL VULNERABILITY: Direct SQL Execution
        This function is removed because it is inherently unsafe.
        Direct SQL execution should be avoided if possible.
        """
        print("[WARNING]: Direct SQL execution is extremely dangerous and should be avoided.")
        return []

# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    db = VulnerableDatabase()
    
    print("=== SQL INJECTION VULNERABILITY DEMONSTRATIONS ===\n")
    
    # 1. Normal login
    print("1. Normal Login:")
    result = db.safe_login("admin", "admin123")
    print(f"Result: {result}\n")
    
    # 2. SQL Injection - Authentication Bypass
    print("2. SQL Injection Attack - Authentication Bypass (Now Safe):")
    malicious_username = "admin' OR '1'='1' --"
    result = db.safe_login(malicious_username, "wrongpassword")
    print(f"Attack Result: {result}\n")
    
    # 3. SQL Injection - Data Extraction
    print("3. SQL Injection Attack - Data Extraction (Now Safe):")
    malicious_id = "1 UNION SELECT username, password, email FROM users"
    result = db.safe_get_user_data(malicious_id)
    print(f"Extracted Data: {result}\n")
    
    # 4. SQL Injection - Search Attack
    print("4. SQL Injection Attack - Search (Now Safe):")
    malicious_search = "' UNION SELECT username, password FROM users --"
    result = db.safe_search(malicious_search)
    print(f"Search Attack Result: {result}\n")
    
    # 5. SQL Injection - Balance Manipulation
    print("5. SQL Injection Attack - Balance Update (Now Safe):")
    malicious_amount = "0; UPDATE users SET balance = 999999 WHERE username = 'guest' --"
    db.safe_update_balance(2, malicious_amount)
    
    print("\n=== SECURITY RECOMMENDATIONS ===")
    print("✅ Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))")
    print("✅ Validate and sanitize all user inputs")
    print("✅ Use ORM frameworks with built-in SQL injection protection")
    print("✅ Implement proper error handling that doesn't expose database structure")
    print("✅ Apply principle of least privilege for database connections")
```