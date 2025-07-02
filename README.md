# Auto Defend

Auto Defend is a web-based Python application that takes security or vulnerability information and a GitHub repository as input, automatically fixes the code, and raises a Pull Request (PR) with the changes.

## Features
- Input a vulnerability description and GitHub repo URL
- Automatically analyze and fix code
- Create a PR with the fix

## Setup
1. Clone this repo
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   streamlit run app.py
   ```

## Configuration
- Requires a GitHub Personal Access Token (PAT) for PR creation
- Optionally, set up OpenAI API key for AI-powered code fixes

## Usage
- Enter the vulnerability description and GitHub repo URL in the web UI
- Provide your GitHub token
- Click 'Defend' to auto-fix and raise a PR 