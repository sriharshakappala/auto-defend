#!/usr/bin/env python3
"""
Debug script to test Auto Defend vulnerability detection
"""

import os
from auto_defend.defender import AutoDefend

def debug_test():
    """Test the vulnerability detection with debug output"""
    
    # Test with the current repository (should contain the sample files)
    REPO_URL = "https://github.com/SwapnilBirkhede/auto-defend"  # Adjust this to your actual repo
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "your_token_here")
    OPENAI_API_KEY = "your_openai_key_here"  # Replace with your actual key
    
    # Specific vulnerability description
    VULNERABILITY_DESCRIPTION = "SQL injection vulnerabilities where user input is directly concatenated into SQL queries without proper sanitization or parameterized queries"
    
    print("🔍 Debug Test - Auto Defend Vulnerability Detection")
    print("=" * 60)
    
    if GITHUB_TOKEN == "your_token_here":
        print("❌ Please set your GitHub token in the environment variable GITHUB_TOKEN")
        return
    
    if OPENAI_API_KEY == "your_openai_key_here":
        print("❌ Please set your OpenAI API key in the script")
        return
    
    try:
        print(f"📋 Configuration:")
        print(f"   Repository: {REPO_URL}")
        print(f"   GitHub Token: {GITHUB_TOKEN[:20]}...")
        print(f"   OpenAI Key: {OPENAI_API_KEY[:20] if OPENAI_API_KEY != 'your_openai_key_here' else 'NOT_SET'}...")
        print(f"   Vulnerability: {VULNERABILITY_DESCRIPTION[:50]}...")
        print()
        
        # Initialize AutoDefend
        print("🚀 Initializing Auto Defend...")
        defender = AutoDefend(
            repo_url=REPO_URL,
            github_token=GITHUB_TOKEN,
            openai_api_key=OPENAI_API_KEY
        )
        
        # Run vulnerability scan (without fixing)
        print("🔍 Starting vulnerability scan...")
        results = defender.scan_and_fix_vulnerabilities(VULNERABILITY_DESCRIPTION)
        
        print("\n📊 Results Summary:")
        print("-" * 40)
        print(f"Success: {results.get('total_files_scanned', 0) > 0}")
        print(f"Files Scanned: {results.get('total_files_scanned', 0)}")
        print(f"Vulnerabilities Found: {results.get('vulnerable_files_found', 0)}")
        print(f"Files Fixed: {results.get('files_fixed', 0)}")
        
        if results.get('errors'):
            print(f"\n⚠️ Errors ({len(results['errors'])}):")
            for error in results['errors']:
                print(f"  - {error}")
        
        if results.get('vulnerabilities'):
            print(f"\n🔍 Vulnerabilities Found ({len(results['vulnerabilities'])}):")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"  {i}. File: {vuln['file']}")
                print(f"     Severity: {vuln['severity']}")
                print(f"     Details: {vuln['details'][:100]}...")
                print(f"     Fixed: {'✅ Yes' if vuln['fixed'] else '❌ No'}")
                print()
        
        # Cleanup
        defender.cleanup()
        
        print("✅ Debug test completed!")
        
    except Exception as e:
        print(f"❌ Debug test failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_test() 