#!/usr/bin/env python3
"""
Sample vulnerable authentication system with SQL injection vulnerabilities
This file is for TESTING PURPOSES ONLY - demonstrates insecure coding practices
"""

import sqlite3
import hashlib
from flask import Flask, request, session, jsonify

app = Flask(__name__)

def connect_db():
    """Connect to the SQLite database"""
    return sqlite3.connect('users.db')

def login_user(username, password):
    """
    VULNERABLE: Direct string concatenation in SQL query
    This allows SQL injection attacks
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    # VULNERABLE CODE - DO NOT USE IN PRODUCTION
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_profile(user_id):
    """
    VULNERABLE: String formatting in SQL query
    Another SQL injection vulnerability
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    # VULNERABLE CODE - DO NOT USE IN PRODUCTION
    query = "SELECT username, email, profile FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    
    profile = cursor.fetchone()
    conn.close()
    return profile

def search_users(search_term):
    """
    VULNERABLE: f-string interpolation in SQL query
    Yet another SQL injection vulnerability
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    # VULNERABLE CODE - DO NOT USE IN PRODUCTION
    query = f"SELECT username, email FROM users WHERE username LIKE '%{search_term}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return results

def update_user_email(user_id, new_email):
    """
    VULNERABLE: Direct concatenation in UPDATE query
    Allows SQL injection in data modification
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    # VULNERABLE CODE - DO NOT USE IN PRODUCTION
    query = "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
    cursor.execute(query)
    
    conn.commit()
    conn.close()

def delete_user_account(username):
    """
    VULNERABLE: Direct concatenation in DELETE query
    Extremely dangerous SQL injection vulnerability
    """
    conn = connect_db()
    cursor = conn.cursor()
    
    # VULNERABLE CODE - DO NOT USE IN PRODUCTION
    query = "DELETE FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint with SQL injection vulnerability"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    user = login_user(username, password)
    
    if user:
        session['user_id'] = user[0]
        return jsonify({"status": "success", "message": "Login successful"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"})

@app.route('/profile/<int:user_id>')
def profile(user_id):
    """User profile endpoint with SQL injection vulnerability"""
    profile_data = get_user_profile(user_id)
    
    if profile_data:
        return jsonify({
            "username": profile_data[0],
            "email": profile_data[1],
            "profile": profile_data[2]
        })
    else:
        return jsonify({"error": "User not found"})

@app.route('/search')
def search():
    """User search endpoint with SQL injection vulnerability"""
    search_term = request.args.get('q', '')
    results = search_users(search_term)
    
    return jsonify({"users": results})

if __name__ == '__main__':
    app.run(debug=True) 