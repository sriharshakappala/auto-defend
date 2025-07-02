# 🚨 Sample Vulnerable Code Files

This directory contains **intentionally vulnerable code** designed for testing the **Auto Defend** application. Each file demonstrates different types of common security vulnerabilities.

> ⚠️ **WARNING**: These files contain intentionally insecure code for educational and testing purposes only. **NEVER use this code in production!**

## 📁 Files Overview

### 1. `sql_injection.py` - SQL Injection Vulnerabilities
**Severity**: 🔴 Critical  
**Description**: Demonstrates SQL injection vulnerabilities in database operations.

**Vulnerabilities Included**:
- Direct string concatenation in SQL queries
- Authentication bypass via SQL injection
- Data extraction through UNION attacks
- Database manipulation via malicious input

**Test with Auto Defend**:
```
SQL injection vulnerability in sql_injection.py file where user input is directly concatenated into SQL queries without parameterization
```

---

### 2. `xss_vulnerability.py` - Cross-Site Scripting (XSS)
**Severity**: 🟠 High  
**Description**: Shows XSS vulnerabilities in web applications.

**Vulnerabilities Included**:
- Reflected XSS in search functionality
- Stored XSS in user comments
- DOM-based XSS in client-side code
- XSS in error messages

**Test with Auto Defend**:
```
Cross-site scripting vulnerability in xss_vulnerability.py file where user input is rendered in HTML without proper encoding or sanitization
```

---

### 3. `path_traversal.py` - Path Traversal / LFI
**Severity**: 🟠 High  
**Description**: Demonstrates path traversal and local file inclusion vulnerabilities.

**Vulnerabilities Included**:
- Directory traversal using `../` sequences
- Unsafe file path construction
- Access to sensitive system files
- Configuration file disclosure

**Test with Auto Defend**:
```
Path traversal vulnerability in path_traversal.py file where user input is used to construct file paths without proper validation
```

---

### 4. `command_injection.py` - Command Injection
**Severity**: 🔴 Critical  
**Description**: Shows command injection vulnerabilities in system operations.

**Vulnerabilities Included**:
- Direct command execution with user input
- Shell metacharacter injection
- Process manipulation vulnerabilities
- System information disclosure

**Test with Auto Defend**:
```
Command injection vulnerability in command_injection.py file where user input is directly used in system commands without validation
```

---

### 5. `insecure_auth.py` - Authentication Vulnerabilities
**Severity**: 🟠 High  
**Description**: Demonstrates authentication and session management issues.

**Vulnerabilities Included**:
- Plain text password storage
- Weak session token generation
- User enumeration attacks
- No brute force protection

**Test with Auto Defend**:
```
Insecure authentication in insecure_auth.py file with plain text password storage and weak session management
```

## 🎯 How to Test with Auto Defend

### Step 1: Choose a Vulnerability
Select one of the vulnerability descriptions above based on which file you want to test.

### Step 2: Run Auto Defend
1. Make sure your Streamlit app is running: `streamlit run app.py`
2. Open http://localhost:8501 in your browser

### Step 3: Fill the Form
- **Vulnerability Description**: Copy one of the descriptions above
- **GitHub Repository URL**: Your repository URL (e.g., `https://github.com/username/auto-defend`)
- **GitHub Token**: Your personal access token
- **Gemini API Key**: Your Google Gemini API key

### Step 4: Test the Fix
Click "🛡️ Defend & Raise PR" and wait for the AI to analyze and fix the vulnerabilities.

## 🔍 Expected Fixes

### SQL Injection → Parameterized Queries
**Before (Vulnerable)**:
```python
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)
```

**After (Secure)**:
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

### XSS → HTML Encoding
**Before (Vulnerable)**:
```python
return f"<p>Welcome {username}</p>"
```

**After (Secure)**:
```python
import html
return f"<p>Welcome {html.escape(username)}</p>"
```

### Path Traversal → Path Validation
**Before (Vulnerable)**:
```python
file_path = os.path.join(base_dir, filename)
```

**After (Secure)**:
```python
file_path = os.path.join(base_dir, filename)
file_path = os.path.normpath(file_path)
if not file_path.startswith(base_dir):
    raise ValueError("Invalid file path")
```

### Command Injection → Safe Execution
**Before (Vulnerable)**:
```python
os.system(f"ping {hostname}")
```

**After (Secure)**:
```python
subprocess.run(['ping', '-c', '4', hostname], capture_output=True)
```

### Authentication → Secure Practices
**Before (Vulnerable)**:
```python
if user['password'] == password:
    # Plain text comparison
```

**After (Secure)**:
```python
import bcrypt
if bcrypt.checkpw(password.encode(), user['password_hash']):
    # Secure hash comparison
```

## 📝 Testing Different Scenarios

### Comprehensive Security Review
```
Multiple security vulnerabilities in sample_vulnerable_files directory including SQL injection, XSS, path traversal, command injection, and authentication issues
```

### Specific File Testing
```
Fix all vulnerabilities in sql_injection.py file
```

### Function-Specific Testing
```
SQL injection in the vulnerable_login function of insecure_auth.py file
```

## 🛠️ Running Individual Files

You can also run each file individually to see the vulnerabilities in action:

```bash
# Run SQL injection demo
python sample_vulnerable_files/sql_injection.py

# Run XSS demo  
python sample_vulnerable_files/xss_vulnerability.py

# Run path traversal demo
python sample_vulnerable_files/path_traversal.py

# Run command injection demo
python sample_vulnerable_files/command_injection.py

# Run authentication demo
python sample_vulnerable_files/insecure_auth.py
```

## 🔒 Security Best Practices

After testing, review the Auto Defend fixes and ensure they implement:

- ✅ **Input Validation**: All user inputs are validated and sanitized
- ✅ **Parameterized Queries**: SQL queries use proper parameterization
- ✅ **Output Encoding**: HTML output is properly encoded
- ✅ **Path Validation**: File paths are validated and restricted
- ✅ **Safe Execution**: Commands use safe execution methods
- ✅ **Secure Authentication**: Passwords are hashed and sessions are secure

---

**Remember**: These files are for testing and educational purposes only. Never deploy vulnerable code to production environments! 🚨 