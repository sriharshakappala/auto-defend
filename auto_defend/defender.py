import os
import tempfile
import git
from github import Github
import google.generativeai as genai
import glob
import shutil
from datetime import datetime
import re

class AutoDefend:
    """
    AutoDefend clones a GitHub repo, uses Google Gemini to fix vulnerabilities in a specified file, and raises a PR.
    """
    def __init__(self, repo_url, github_token, gemini_api_key=None):
        self.repo_url = repo_url
        self.github_token = github_token
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        self.local_dir = tempfile.mkdtemp()
        self.repo = None
        self.github = Github(self.github_token)
        genai.configure(api_key=self.gemini_api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash-exp')
        self.branch_name = f"auto-defend-fix-{datetime.now().strftime('%Y%m%d%H%M%S')}"

    def clone_repo(self):
        self.repo = git.Repo.clone_from(self.repo_url, self.local_dir)
        return self.local_dir

    def extract_filename(self, vuln_desc):
        """
        Extract filename from the vulnerability description using regex for common file patterns.
        """
        # Look for patterns like 'File: filename.ext' or just filename.ext
        match = re.search(r'([\w\-/]+\.[\w]+)', vuln_desc)
        if match:
            return match.group(1)
        return None

    def fix_vulnerability_in_file_with_llm(self, vuln_desc):
        """
        Extract filename from vuln_desc, send its contents and vuln_desc to OpenAI GPT-4, replace with fixed code.
        """
        filename = self.extract_filename(vuln_desc)
        if not filename:
            raise ValueError("Could not extract filename from description. Please include the filename in your description.")
        # Find the file in the repo (search recursively)
        file_path = None
        for root, dirs, files in os.walk(self.local_dir):
            for f in files:
                if f == os.path.basename(filename):
                    file_path = os.path.join(root, f)
                    break
            if file_path:
                break
        if not file_path or not os.path.exists(file_path):
            raise FileNotFoundError(f"File '{filename}' not found in the repository.")
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
        prompt = (
            f"""
You are a security expert and developer. The following file has a vulnerability described below. Fix the vulnerability, improve security, and return ONLY the full corrected file content (no explanation).

Vulnerability description:
{vuln_desc}

File content:
{code}
"""
        )
        try:
            response = self.model.generate_content(prompt)
            fixed_code = response.text.strip()
            if fixed_code and fixed_code != code:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(fixed_code)
        except Exception as e:
            if "404" in str(e) and "models/" in str(e):
                print(f"Gemini model error: {e}")
                print("Trying alternative models...")
                
                # Try alternative models in order of preference
                fallback_models = [
                    'gemini-2.5-pro',
                    'gemini-1.5-pro',
                    'gemini-1.5-flash', 
                    'gemini-pro'
                ]
                
                for model_name in fallback_models:
                    try:
                        print(f"Trying {model_name}...")
                        alt_model = genai.GenerativeModel(model_name)
                        response = alt_model.generate_content(prompt)
                        fixed_code = response.text.strip()
                        if fixed_code and fixed_code != code:
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(fixed_code)
                        print(f"Success with {model_name}!")
                        return  # Exit successfully
                    except Exception as model_error:
                        print(f"{model_name} failed: {model_error}")
                        continue
                
                # If all models failed
                raise Exception(f"All Gemini models failed. Original error: {e}")
            else:
                print(f"Gemini error for {file_path}: {e}")
                raise

    def commit_and_push(self, commit_message):
        repo = self.repo
        repo.git.checkout('-b', self.branch_name)
        repo.git.add(A=True)
        if repo.is_dirty():
            repo.index.commit(commit_message)
            origin = repo.remote(name='origin')
            origin.push(self.branch_name)
            return True
        return False

    def create_pull_request(self, pr_title, pr_body):
        # Parse repository name correctly from various GitHub URL formats
        repo_name = self.parse_repo_name(self.repo_url)
        print(f"Parsed repository name: {repo_name}")
        
        try:
            gh_repo = self.github.get_repo(repo_name)
            pr = gh_repo.create_pull(
                title=pr_title,
                body=pr_body,
                head=self.branch_name,
                base="main"
            )
            return pr.html_url
        except Exception as e:
            if "404" in str(e):
                # Try alternative base branches
                for base_branch in ["master", "develop", "dev"]:
                    try:
                        print(f"Trying base branch: {base_branch}")
                        pr = gh_repo.create_pull(
                            title=pr_title,
                            body=pr_body,
                            head=self.branch_name,
                            base=base_branch
                        )
                        return pr.html_url
                    except:
                        continue
            raise e
    
    def parse_repo_name(self, repo_url):
        """
        Parse repository name from various GitHub URL formats
        """
        # Remove common prefixes and suffixes
        repo_url = repo_url.strip()
        
        # Handle HTTPS URLs
        if repo_url.startswith("https://github.com/"):
            repo_name = repo_url.replace("https://github.com/", "")
        # Handle SSH URLs  
        elif repo_url.startswith("git@github.com:"):
            repo_name = repo_url.replace("git@github.com:", "")
        # Handle other formats
        else:
            # Try to extract owner/repo pattern
            import re
            match = re.search(r'github\.com[:/]([^/]+/[^/]+)', repo_url)
            if match:
                repo_name = match.group(1)
            else:
                raise ValueError(f"Could not parse repository name from URL: {repo_url}")
        
        # Remove .git suffix if present
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
            
        # Remove trailing slash
        repo_name = repo_name.rstrip("/")
        
        return repo_name

    def cleanup(self):
        shutil.rmtree(self.local_dir) 