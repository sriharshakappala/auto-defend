#!/usr/bin/env python3
import os
import openai
import json

# Quick test of AI vulnerability detection
def test_ai_detection():
    OPENAI_API_KEY = "your_openai_key_here"  # Replace with your actual key
    
    if OPENAI_API_KEY == "your_openai_key_here":
        print("❌ Please set your OpenAI API key in the script")
        return
    
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    
    # Read a sample vulnerable file
    with open("sample_vulnerable_files/user_auth.py", "r") as f:
        code = f.read()
    
    prompt = f"""
You are a cybersecurity expert. Analyze this Python code for SQL injection vulnerabilities.

CODE:
{code[:1000]}...

Look for patterns where user input is directly concatenated into SQL queries without parameterization.

Return ONLY a JSON object:
{{
    "has_vulnerability": true/false,
    "details": "description of vulnerabilities found",
    "count": number_of_vulnerabilities
}}
"""
    
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500,
            temperature=0.1
        )
        
        result = response.choices[0].message.content.strip()
        print("🤖 AI Response:")
        print(result)
        
        # Try to parse JSON
        import re
        json_match = re.search(r'\{.*\}', result, re.DOTALL)
        if json_match:
            parsed = json.loads(json_match.group())
            print(f"\n✅ Parsed Result:")
            print(f"   Has Vulnerability: {parsed.get('has_vulnerability')}")
            print(f"   Details: {parsed.get('details', 'N/A')}")
            print(f"   Count: {parsed.get('count', 'N/A')}")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_ai_detection()
