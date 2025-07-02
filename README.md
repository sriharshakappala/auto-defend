# 🛡️ Auto Defend

AI-powered vulnerability remediation for your codebase using Google Gemini AI.

## Features

- **Automated Vulnerability Detection & Fixing**: Uses Google Gemini AI to analyze and fix security vulnerabilities
- **GitHub Integration**: Automatically clones repositories, applies fixes, and creates pull requests
- **User-Friendly Interface**: Simple Streamlit web interface for easy interaction
- **Comprehensive Error Handling**: Detailed error messages and validation

## Setup

### 1. Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Get API Keys

You'll need two API keys:

1. **GitHub Personal Access Token**
   - Go to GitHub Settings → Developer settings → Personal access tokens
   - Generate a new token with `repo` permissions
   - [GitHub Token Guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)

2. **Google Gemini API Key**
   - Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
   - Create a new API key
   - Keep it secure and don't share it

### 3. Run the Application

```bash
source venv/bin/activate
streamlit run app.py
```

The application will be available at `http://localhost:8501`

## Usage

1. **Enter Vulnerability Description**: Describe the security issue you want to fix. Include the filename if possible (e.g., "SQL injection in login.py file")

2. **GitHub Repository URL**: Provide the full GitHub repository URL (e.g., `https://github.com/username/repo`)

3. **GitHub Token**: Enter your GitHub Personal Access Token

4. **Gemini API Key**: Enter your Google Gemini API key

5. **Click "🛡️ Defend & Raise PR"**: The application will:
   - Clone the repository
   - Analyze the vulnerability using Gemini AI
   - Apply security fixes
   - Create and push a new branch
   - Open a pull request with the fixes

## Example Usage

**Vulnerability Description:**
```
SQL injection vulnerability in login.py file where user input is directly concatenated to SQL queries without parameterization
```

**Expected Output:**
- Gemini AI will analyze the code
- Apply proper SQL parameterization
- Create a pull request with security improvements

## Technical Details

### Architecture

- **Frontend**: Streamlit web interface
- **AI Model**: Google Gemini Pro for code analysis and vulnerability fixing
- **Version Control**: GitPython for repository operations
- **GitHub API**: PyGithub for pull request creation

### Security Features

- All credentials are handled securely (never stored)
- Temporary directories for repository cloning
- Automatic cleanup after processing
- Input validation and error handling

## Troubleshooting

### Common Issues

1. **File not found error**: Make sure to include the exact filename in your vulnerability description
2. **API key errors**: Verify your GitHub token has correct permissions and Gemini API key is valid
3. **Repository access**: Ensure your GitHub token has access to the target repository

### Error Messages

- `❌ File not found`: The specified file doesn't exist in the repository
- `❌ Invalid input`: Check your vulnerability description includes a filename
- `❌ An error occurred`: General error - check all inputs and API keys

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Security Notice

This tool modifies code automatically. Always review the generated pull requests before merging to ensure the fixes are appropriate for your specific use case.

## License

MIT License - See LICENSE file for details 