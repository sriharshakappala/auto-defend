"""
Path Traversal / Local File Inclusion Vulnerability Demo
======================================================

VULNERABILITY TYPE: Path Traversal / Directory Traversal / Local File Inclusion (LFI)
SEVERITY: High to Critical
DESCRIPTION: This file demonstrates path traversal vulnerabilities where user input
is used to construct file paths without proper validation, allowing access to files
outside the intended directory.

ATTACK VECTORS:
- ../ sequences to traverse directories
- Absolute paths to access system files
- URL encoding and double encoding bypasses
- Null byte injection (in older systems)

IMPACT:
- Access to sensitive system files (/etc/passwd, /etc/shadow)
- Configuration file disclosure
- Source code exposure
- Potential remote code execution if combined with file upload
"""

import os
import mimetypes
from pathlib import Path

class VulnerableFileServer:
    
    def __init__(self, base_directory="./uploads"):
        self.base_directory = base_directory
        # Create sample files for demonstration
        self.setup_demo_files()
    
    def setup_demo_files(self):
        """Create sample files for testing"""
        os.makedirs(self.base_directory, exist_ok=True)
        os.makedirs("./logs", exist_ok=True)
        
        # Create sample files
        sample_files = {
            f"{self.base_directory}/public_document.txt": "This is a public document.",
            f"{self.base_directory}/user_data.txt": "User private data here.",
            "./logs/application.log": "2024-01-01 12:00:00 - Application started\n2024-01-01 12:01:00 - User login: admin",
            "./config.ini": "[database]\npassword=super_secret_password\nhost=localhost",
            "./secrets.txt": "API_KEY=sk-1234567890abcdef\nDB_PASSWORD=secret123"
        }
        
        for filepath, content in sample_files.items():
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write(content)
    
    def vulnerable_file_read(self, filename):
        """
        🚨 VULNERABILITY: Path Traversal in File Reading
        
        ISSUE: User input directly used in file path without validation
        ATTACK: filename like "../../../etc/passwd" or "../config.ini"
        """
        
        # VULNERABLE CODE: Direct path concatenation
        file_path = os.path.join(self.base_directory, filename)
        
        print(f"[VULNERABLE] Attempting to read: {file_path}")
        
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                return {
                    'success': True,
                    'filename': filename,
                    'path': file_path,
                    'content': content
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'attempted_path': file_path
            }
    
    def vulnerable_log_viewer(self, log_file):
        """
        🚨 VULNERABILITY: Path Traversal in Log Viewing
        
        ISSUE: Log file parameter not validated
        ATTACK: log_file like "../secrets.txt" or "/etc/passwd"
        """
        
        # VULNERABLE CODE: No path validation
        log_path = f"./logs/{log_file}"
        
        print(f"[VULNERABLE] Reading log file: {log_path}")
        
        try:
            with open(log_path, 'r') as file:
                return {
                    'log_file': log_file,
                    'path': log_path,
                    'content': file.read()
                }
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerable_template_include(self, template_name):
        """
        🚨 VULNERABILITY: Local File Inclusion in Template Loading
        
        ISSUE: Template file path constructed from user input
        ATTACK: template_name like "../../../etc/passwd%00.html" or "../config.ini"
        """
        
        # VULNERABLE CODE: Direct template path construction
        template_path = f"./templates/{template_name}.html"
        
        print(f"[VULNERABLE] Loading template: {template_path}")
        
        try:
            with open(template_path, 'r') as file:
                template_content = file.read()
                return {
                    'template': template_name,
                    'path': template_path,
                    'content': template_content
                }
        except Exception as e:
            # Fallback - even more dangerous
            try:
                # EXTREMELY VULNERABLE: Trying without .html extension
                fallback_path = f"./templates/{template_name}"
                with open(fallback_path, 'r') as file:
                    return {
                        'template': template_name,
                        'path': fallback_path,
                        'content': file.read(),
                        'warning': 'Loaded without extension validation!'
                    }
            except:
                return {'error': str(e)}
    
    def vulnerable_file_download(self, file_id):
        """
        🚨 VULNERABILITY: Path Traversal in File Downloads
        
        ISSUE: File ID used to construct download path without validation
        ATTACK: file_id like "../../../etc/passwd" or "../config.ini"
        """
        
        # VULNERABLE CODE: Direct file path construction
        download_path = f"./downloads/{file_id}"
        
        print(f"[VULNERABLE] Preparing download: {download_path}")
        
        if os.path.exists(download_path):
            try:
                with open(download_path, 'rb') as file:
                    content = file.read()
                    mime_type = mimetypes.guess_type(download_path)[0] or 'application/octet-stream'
                    
                    return {
                        'file_id': file_id,
                        'path': download_path,
                        'size': len(content),
                        'mime_type': mime_type,
                        'content': content.decode('utf-8', errors='replace')[:200] + '...' if len(content) > 200 else content.decode('utf-8', errors='replace')
                    }
            except Exception as e:
                return {'error': str(e)}
        else:
            return {'error': 'File not found', 'attempted_path': download_path}
    
    def vulnerable_config_reader(self, config_section):
        """
        🚨 VULNERABILITY: Path Traversal in Configuration Access
        
        ISSUE: Configuration section parameter used to read different config files
        ATTACK: config_section like "../secrets" or "../../../etc/passwd"
        """
        
        # VULNERABLE CODE: Config file path from user input
        config_file = f"./config/{config_section}.conf"
        
        print(f"[VULNERABLE] Reading config: {config_file}")
        
        try:
            with open(config_file, 'r') as file:
                return {
                    'section': config_section,
                    'file': config_file,
                    'config': file.read()
                }
        except Exception as e:
            return {'error': str(e), 'attempted_file': config_file}

# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    print("=== PATH TRAVERSAL VULNERABILITY DEMONSTRATIONS ===\n")
    
    server = VulnerableFileServer()
    
    # 1. Normal file access
    print("1. Normal File Access:")
    result = server.vulnerable_file_read("public_document.txt")
    print(f"Result: {result['content'] if result['success'] else result['error']}\n")
    
    # 2. Path Traversal Attack - Access config file
    print("2. Path Traversal Attack - Configuration File:")
    malicious_filename = "../config.ini"
    result = server.vulnerable_file_read(malicious_filename)
    print(f"Attack Result: {result.get('content', result.get('error'))}\n")
    
    # 3. Path Traversal Attack - Access secrets
    print("3. Path Traversal Attack - Secrets File:")
    malicious_filename = "../secrets.txt"
    result = server.vulnerable_file_read(malicious_filename)
    print(f"Secrets Exposed: {result.get('content', result.get('error'))}\n")
    
    # 4. Log Viewer Attack
    print("4. Log Viewer Path Traversal:")
    malicious_log = "../config.ini"
    result = server.vulnerable_log_viewer(malicious_log)
    print(f"Log Attack Result: {result.get('content', result.get('error'))}\n")
    
    # 5. Template Inclusion Attack
    print("5. Template Inclusion Attack:")
    malicious_template = "../secrets"
    result = server.vulnerable_template_include(malicious_template)
    print(f"Template Attack: {result.get('content', result.get('error'))}\n")
    
    # 6. Try to access system files (will likely fail on this system but shows the attempt)
    print("6. System File Access Attempt:")
    system_file = "../../../etc/passwd"
    result = server.vulnerable_file_read(system_file)
    print(f"System File Attack: {result.get('content', result.get('error'))}\n")
    
    print("=== SECURITY RECOMMENDATIONS ===")
    print("✅ Validate and sanitize all file path inputs")
    print("✅ Use allowlists of permitted files/directories")
    print("✅ Implement proper access controls and user permissions")
    print("✅ Use os.path.normpath() and check if path starts with allowed directory")
    print("✅ Avoid direct file system access based on user input")
    print("✅ Use secure file handling libraries")
    print("✅ Example secure code:")
    print("   import os")
    print("   def secure_file_read(filename):")
    print("       base_dir = '/safe/uploads/'")
    print("       full_path = os.path.join(base_dir, filename)")
    print("       full_path = os.path.normpath(full_path)")
    print("       if not full_path.startswith(base_dir):")
    print("           raise ValueError('Invalid file path')")
    print("       # Then safely read the file") 