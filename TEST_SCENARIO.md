# 🧪 Test Scenario for Auto Defend

This document provides step-by-step instructions to test the Auto Defend application using the provided vulnerable code sample.

## 📁 Sample Vulnerable File

**File:** `sample_vulnerable_code.py`

**Vulnerabilities Present:**
- ✅ SQL Injection in `login()` function
- ✅ SQL Injection in `get_user_info()` function  
- ✅ SQL Injection in `search_users()` function
- ✅ Plain text password storage
- ✅ No input validation/sanitization
- ✅ Sensitive information logging

## 🚀 How to Test Auto Defend

### Prerequisites
1. Auto Defend application running at `http://localhost:8501`
2. GitHub repository with the vulnerable file
3. GitHub Personal Access Token
4. Google Gemini API key

### Step 1: Upload to GitHub Repository

First, you need to upload the vulnerable file to a GitHub repository:

```bash
# Option 1: Add to existing repository
git add sample_vulnerable_code.py
git commit -m "Add vulnerable code for testing"
git push origin main

# Option 2: Create new repository on GitHub and push
git init
git add sample_vulnerable_code.py
git commit -m "Initial commit with vulnerable code"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### Step 2: Test Auto Defend Application

1. **Open the App**: Navigate to `http://localhost:8501`

2. **Fill in the Form**:
   - **Vulnerability Description**: Use one of these examples:
     ```
     SQL injection vulnerability in sample_vulnerable_code.py file where user input is directly concatenated into SQL queries without parameterization in the login function
     ```
     
     Or:
     ```
     Multiple SQL injection vulnerabilities in sample_vulnerable_code.py including login bypass, data extraction, and unsafe query construction
     ```

   - **GitHub Repository URL**: 
     ```
     https://github.com/YOUR_USERNAME/YOUR_REPO
     ```

   - **GitHub Token**: Your personal access token

   - **Gemini API Key**: Your Google Gemini API key

3. **Click "🛡️ Defend & Raise PR"**

### Step 3: Expected Results

The application should:

1. ✅ **Clone the repository** successfully
2. ✅ **Analyze the code** using Gemini AI
3. ✅ **Apply security fixes** such as:
   - Replace string concatenation with parameterized queries
   - Add password hashing
   - Implement input validation
   - Remove sensitive logging
   - Add proper error handling

4. ✅ **Create a pull request** with:
   - Descriptive title
   - Detailed explanation of fixes
   - Clean, secure code

### Step 4: Review the Fix

After the PR is created:

1. **Check the Pull Request** on GitHub
2. **Review the changes** made by Gemini AI
3. **Verify security improvements**:
   - SQL queries use parameterization (e.g., `cursor.execute(query, (username, password))`)
   - Password hashing implementation
   - Input validation added
   - Secure logging practices

## 🔍 Example Fixed Code Expectations

The AI should transform code like this:

**Before (Vulnerable):**
```python
query = f"SELECT id, username, email, role FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

**After (Secure):**
```python
query = "SELECT id, username, email, role FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, hashed_password))
```

## 🐛 Common Issues & Solutions

### Issue: "File not found"
**Solution**: Make sure the vulnerability description includes the exact filename: `sample_vulnerable_code.py`

### Issue: "No changes made"
**Solution**: The AI might think the code is already secure. Try being more specific in the vulnerability description.

### Issue: "API key error"
**Solution**: Verify your GitHub token has repo permissions and Gemini API key is valid.

## 🎯 Success Criteria

✅ **Application successfully processes the request**  
✅ **Creates a new branch with security fixes**  
✅ **Opens a pull request with detailed information**  
✅ **Fixed code uses parameterized queries**  
✅ **Implements proper password hashing**  
✅ **Adds input validation**  
✅ **Removes security vulnerabilities**  

## 🔄 Testing Multiple Scenarios

You can test different vulnerability descriptions:

1. **Focus on specific vulnerability:**
   ```
   SQL injection in the login method of sample_vulnerable_code.py
   ```

2. **Broad security review:**
   ```
   Security vulnerabilities including SQL injection, plain text passwords, and unsafe database operations in sample_vulnerable_code.py
   ```

3. **Specific function:**
   ```
   Fix SQL injection vulnerability in the search_users function of sample_vulnerable_code.py file
   ```

This comprehensive test will validate that your Auto Defend application is working correctly with real-world security vulnerabilities! 🛡️ 