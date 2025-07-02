import streamlit as st
import os
import requests
import json
from configparser import ConfigParser
from auto_defend.defender import AutoDefend

st.set_page_config(page_title="Auto Defend", layout="centered", page_icon="🛡️")

# Load configuration
@st.cache_data
def load_config():
    """Load configuration from config.properties file"""
    config = ConfigParser()
    config_file = 'config.properties'
    
    if os.path.exists(config_file):
        config.read(config_file)
        return {
            'devrev_user_auth': config.get('DEFAULT', 'devrev_user_auth', fallback=''),
            'devrev_base_url': config.get('DEFAULT', 'devrev_base_url', fallback='https://app.devrev.ai/api/gateway/internal'),
            'devrev_org_id': config.get('DEFAULT', 'devrev_org_id', fallback='don:core:dvrv-in-1:devo/2sRI6Hepzz'),
            'devrev_client_id': config.get('DEFAULT', 'devrev_client_id', fallback='ai.devrev.web-product.prod'),
            'devrev_client_platform': config.get('DEFAULT', 'devrev_client_platform', fallback='web-product'),
            'devrev_client_version': config.get('DEFAULT', 'devrev_client_version', fallback='4fb9e10'),
            'devrev_dev_user_don': config.get('DEFAULT', 'devrev_dev_user_don', fallback='don:identity:dvrv-in-1:devo/2sRI6Hepzz:devu/6117'),
            'devrev_session_id': config.get('DEFAULT', 'devrev_session_id', fallback='c71c3e97-01d4-4d4f-b69f-569d052fbff9')
        }
    else:
        st.warning("⚠️ config.properties file not found. Please create it with your DevRev credentials.")
        return {
            'devrev_user_auth': '',
            'devrev_base_url': 'https://app.devrev.ai/api/gateway/internal',
            'devrev_org_id': 'don:core:dvrv-in-1:devo/2sRI6Hepzz',
            'devrev_client_id': 'ai.devrev.web-product.prod',
            'devrev_client_platform': 'web-product',
            'devrev_client_version': '4fb9e10',
            'devrev_dev_user_don': 'don:identity:dvrv-in-1:devo/2sRI6Hepzz:devu/6117',
            'devrev_session_id': 'c71c3e97-01d4-4d4f-b69f-569d052fbff9'
        }

def validate_jwt_token(token):
    """Basic validation of JWT token format"""
    if not token:
        return False, "Token is empty"
    
    # JWT tokens have 3 parts separated by dots
    parts = token.split('.')
    if len(parts) != 3:
        return False, "Invalid JWT format - should have 3 parts separated by dots"
    
    # Each part should be base64 encoded (basic check)
    if not all(len(part) > 0 for part in parts):
        return False, "Invalid JWT format - empty parts detected"
    
    # Basic length check (JWT tokens are typically quite long)
    if len(token) < 100:
        return False, "Token seems too short to be a valid JWT"
    
    return True, "Token format looks valid"

def extract_ticket_number(ticket_input):
    """Extract ticket number from various DevRev ticket input formats"""
    if not ticket_input or not isinstance(ticket_input, str):
        return None
    
    ticket_input = ticket_input.strip()
    
    # Format 1: Just the number (e.g., "415131")
    if ticket_input.isdigit():
        return ticket_input
    
    # Format 2: Display ID format (e.g., "ISS-415131")
    if ticket_input.startswith("ISS-") and ticket_input[4:].isdigit():
        return ticket_input[4:]  # Remove "ISS-" prefix
    
    # Format 3: Full DON ID format (e.g., "don:core:dvrv-in-1:devo/2sRI6Hepzz:issue/415131")
    if ":issue/" in ticket_input:
        try:
            # Extract the number after the last ":issue/"
            issue_part = ticket_input.split(":issue/")[-1]
            if issue_part.isdigit():
                return issue_part
        except:
            pass
    
    # Format 4: URL format (if user copies from browser)
    # e.g., "https://app.devrev.ai/...issue/415131" or similar
    import re
    url_match = re.search(r'issue[/:](\d+)', ticket_input)
    if url_match:
        return url_match.group(1)
    
    # Format 5: Any format with numbers - extract the last sequence of digits
    numbers = re.findall(r'\d+', ticket_input)
    if numbers:
        # Return the last (and typically longest) number sequence
        return max(numbers, key=len) if len(max(numbers, key=len)) >= 3 else None
    
    return None

def fetch_devrev_ticket_details(ticket_input, config):
    """Fetch ticket details from DevRev API"""
    try:
        # Validate JWT token first
        token_valid, token_message = validate_jwt_token(config.get('devrev_user_auth', ''))
        if not token_valid:
            return {
                'error': f'Invalid JWT token: {token_message}',
                'auth_issue': True,
                'suggestion': 'Please update your JWT token in config.properties'
            }
        
        # Extract ticket number from various input formats
        ticket_id = extract_ticket_number(ticket_input)
        if not ticket_id:
            return {
                'error': f'Invalid ticket format: {ticket_input}. Please enter ticket number (e.g., 415131) or display ID (e.g., ISS-415131)',
                'suggestion': 'Enter a valid DevRev ticket number or ID'
            }
        
        # Construct the API URL - using works.get endpoint
        url = f"{config['devrev_base_url']}/works.get"
        
        # Construct the full ticket ID for the API call
        full_ticket_id = f"{config['devrev_org_id']}:issue/{ticket_id}"
        
        # Parameters - only id parameter needed
        params = {
            'id': full_ticket_id
        }
        
        # Headers - based on the working CURL command
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US',
            'authorization': config['devrev_user_auth'],  # No Bearer prefix needed
            'priority': 'u=1, i',
            'referer': 'https://app.devrev.ai/',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'traceparent': '00-00000000000000009089496d2e5497c5-7f9b948c9170445d-01',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'x-datadog-origin': 'rum',
            'x-datadog-parent-id': '9195106395663385693',
            'x-datadog-sampling-priority': '1',
            'x-datadog-trace-id': '10414936346548541381',
            'x-devrev-client-id': config['devrev_client_id'],
            'x-devrev-client-platform': config['devrev_client_platform'],
            'x-devrev-client-version': config['devrev_client_version'],
            'x-devrev-dev-user-don': config['devrev_dev_user_don'],
            'x-devrev-session-id': config['devrev_session_id']
        }
        
        # Debug information
        print(f"Input ticket: {ticket_input}")
        print(f"Extracted ticket ID: {ticket_id}")
        print(f"Full ticket ID: {full_ticket_id}")
        print(f"Making request to: {url}")
        print(f"With params: {params}")
        print(f"Authorization header: {headers.get('authorization', 'Missing')[:50]}...")
        
        # Make the API request
        response = requests.get(url, params=params, headers=headers)
        
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            return {
                'error': f'HTTP {response.status_code}: {response.text}',
                'auth_issue': True,
                'suggestion': 'JWT token may be expired. Please get a fresh token from DevRev.'
            }
        else:
            return {'error': f'HTTP {response.status_code}: {response.text}'}
            
    except Exception as e:
        return {'error': str(e)}

def display_ticket_details(ticket_data):
    """Display ticket details in a formatted way"""
    if 'error' in ticket_data:
        st.error(f"❌ Error fetching ticket: {ticket_data['error']}")
        
        # Special handling for authentication issues
        if ticket_data.get('auth_issue'):
            st.warning("🔑 **Authentication Issue Detected**")
            st.info(ticket_data.get('suggestion', 'Please check your DevRev credentials.'))
            
            with st.expander("📋 How to get a fresh DevRev JWT token", expanded=True):
                st.markdown("""
                **Steps to get a new JWT token:**
                
                1. **Open DevRev in browser**: Go to https://app.devrev.ai/
                2. **Login to your account** if not already logged in
                3. **Open Developer Tools**: Press F12 or right-click → Inspect
                4. **Go to Network tab** in Developer Tools
                5. **Refresh the page** or navigate to any ticket
                6. **Find any API request** to `app.devrev.ai/api/gateway/internal/`
                7. **Copy the Authorization header** value (starts with `eyJ...`)
                8. **Update config.properties** with the new token:
                
                ```
                [DEFAULT]
                devrev_user_auth=paste_your_new_jwt_token_here
                ```
                
                **Note**: JWT tokens typically expire after 1-2 hours, so you may need to refresh them periodically.
                """)
        
        return None
    
    try:
        st.subheader("🎫 Ticket Details")
        
        # First, let's show the raw response structure for debugging
        with st.expander("🔍 Raw API Response (for debugging)", expanded=False):
            st.json(ticket_data)
        
        # Extract ticket information from DevRev API response structure
        ticket_info = None
        
        # DevRev API returns data under 'work' key
        if 'work' in ticket_data:
            ticket_info = ticket_data['work']
        elif 'data' in ticket_data:
            ticket_info = ticket_data['data']
        else:
            # If it's a direct response
            ticket_info = ticket_data
        
        if ticket_info:
            # Display basic ticket information in two columns
            col1, col2 = st.columns(2)
            
            with col1:
                # Basic ticket info
                st.write("**Ticket ID:**", ticket_info.get('display_id', ticket_info.get('id', 'N/A')))
                st.write("**Type:**", ticket_info.get('type', 'N/A').title())
                
                # Priority info
                priority = ticket_info.get('priority', 'N/A')
                if isinstance(ticket_info.get('priority_v2'), dict):
                    priority = ticket_info['priority_v2'].get('label', priority)
                st.write("**Priority:**", priority)
                
                # Stage/Status info
                stage_name = 'N/A'
                if isinstance(ticket_info.get('stage'), dict):
                    stage_name = ticket_info['stage'].get('display_name', ticket_info['stage'].get('name', 'N/A'))
                st.write("**Status:**", stage_name)
                
                # State info
                state = ticket_info.get('state', 'N/A')
                if isinstance(ticket_info.get('stage', {}).get('state'), dict):
                    state = ticket_info['stage']['state'].get('display_name', state)
                st.write("**State:**", state)
            
            with col2:
                st.write("**Created:**", ticket_info.get('created_date', 'N/A'))
                st.write("**Modified:**", ticket_info.get('modified_date', 'N/A'))
                
                # Created by
                created_by = 'N/A'
                if isinstance(ticket_info.get('created_by'), dict):
                    created_by = ticket_info['created_by'].get('display_name', ticket_info['created_by'].get('full_name', 'N/A'))
                st.write("**Created By:**", created_by)
                
                # Modified by
                modified_by = 'N/A'
                if isinstance(ticket_info.get('modified_by'), dict):
                    modified_by = ticket_info['modified_by'].get('display_name', ticket_info['modified_by'].get('full_name', 'N/A'))
                st.write("**Modified By:**", modified_by)
            
            # Title
            title = ticket_info.get('title', '')
            if title:
                st.markdown("---")
                st.write("**📋 Title:**")
                st.info(title)
            
            # Owned By section
            owned_by = ticket_info.get('owned_by', [])
            if owned_by and isinstance(owned_by, list):
                st.markdown("---")
                st.write("**👤 Owned By:**")
                for i, owner in enumerate(owned_by):
                    if isinstance(owner, dict):
                        name = owner.get('display_name', owner.get('full_name', 'Unknown'))
                        email = owner.get('email', 'No email')
                        handle = owner.get('display_handle', '')
                        
                        # Create a nice display for each owner
                        col_owner1, col_owner2 = st.columns([1, 3])
                        with col_owner1:
                            if owner.get('thumbnail'):
                                st.image(owner['thumbnail'], width=40)
                            else:
                                st.write("👤")
                        with col_owner2:
                            st.write(f"**{name}**")
                            st.write(f"📧 {email}")
                            if handle:
                                st.write(f"🏷️ @{handle}")
                        
                        if i < len(owned_by) - 1:  # Add separator except for last item
                            st.write("")
            
            # Reported By section
            reported_by = ticket_info.get('reported_by', [])
            if reported_by and isinstance(reported_by, list):
                st.markdown("---")
                st.write("**📝 Reported By:**")
                for i, reporter in enumerate(reported_by):
                    if isinstance(reporter, dict):
                        name = reporter.get('display_name', reporter.get('full_name', 'Unknown'))
                        email = reporter.get('email', 'No email')
                        handle = reporter.get('display_handle', '')
                        
                        # Create a nice display for each reporter
                        col_reporter1, col_reporter2 = st.columns([1, 3])
                        with col_reporter1:
                            if reporter.get('thumbnail'):
                                st.image(reporter['thumbnail'], width=40)
                            else:
                                st.write("📝")
                        with col_reporter2:
                            st.write(f"**{name}**")
                            st.write(f"📧 {email}")
                            if handle:
                                st.write(f"🏷️ @{handle}")
                        
                        if i < len(reported_by) - 1:  # Add separator except for last item
                            st.write("")
            
            # Body/Description section - this is the main vulnerability details
            body = ticket_info.get('body', '')
            if body:
                st.markdown("---")
                st.write("**📄 Vulnerability Details:**")
                # Display the body in a formatted text area
                st.text_area("Vulnerability Description", value=body, height=300, disabled=True, key="ticket_body_display")
            
            # Tags section
            tags = ticket_info.get('tags', [])
            if tags and isinstance(tags, list):
                st.markdown("---")
                st.write("**🏷️ Tags:**")
                tag_names = []
                for tag in tags:
                    if isinstance(tag, dict) and 'tag' in tag:
                        tag_name = tag['tag'].get('name', 'Unknown')
                        tag_names.append(tag_name)
                if tag_names:
                    st.write(", ".join(tag_names))
            
            # Additional custom fields for security context
            custom_fields = ticket_info.get('custom_fields', {})
            if custom_fields:
                with st.expander("🔧 Additional Security Details", expanded=False):
                    # Extract relevant security fields
                    repo = custom_fields.get('ctype__customfield_10081', custom_fields.get('ctype__customfield_10084'))
                    if repo:
                        st.write(f"**Repository:** {repo}")
                    
                    severity = custom_fields.get('ctype__customfield_10092', custom_fields.get('ctype__customfield_10093'))
                    if severity:
                        st.write(f"**Severity:** {severity}")
                    
                    issue_type = custom_fields.get('ctype__customfield_10079')
                    if issue_type:
                        st.write(f"**Issue Type:** {issue_type}")
                    
                    semgrep_url = custom_fields.get('ctype__customfield_12521')
                    if semgrep_url:
                        st.write(f"**Semgrep URL:** [{semgrep_url}]({semgrep_url})")
            
            return ticket_info
        else:
            st.warning("⚠️ Could not parse ticket information from API response")
            st.json(ticket_data)
            return ticket_data
            
    except Exception as e:
        st.error(f"❌ Error displaying ticket details: {str(e)}")
        st.json(ticket_data)  # Fallback to raw JSON
        return None

# Sidebar
with st.sidebar:
    st.title("🛡️ Auto Defend")
    st.markdown("""
    **Auto Defend** helps you automatically fix security vulnerabilities in your codebase and raise a Pull Request on GitHub.
    
    **Two modes available:**
    1. **Manual**: Enter vulnerability description directly
    2. **DevRev**: Fetch ticket details from DevRev
    
    **Get your API keys:**
    - [GitHub Token Guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
    - [Gemini API Key](https://makersuite.google.com/app/apikey)
    """)
    st.info("Your credentials are never stored.")

# Main UI
st.markdown("""
<div style='text-align: center;'>
    <h1 style='margin-bottom:0;'>🛡️ Auto Defend</h1>
    <p style='color: #666; margin-top:0;'>AI-powered vulnerability remediation for your codebase</p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# Load configuration
config = load_config()

# Create tabs
tab1, tab2 = st.tabs(["📝 Manual Entry", "🎫 DevRev Ticket"])

# Tab 1: Manual Entry (Original functionality)
with tab1:
    st.header("Manual Vulnerability Entry")
    
    col1, col2 = st.columns(2)

    with col1:
        vuln_desc = st.text_area(
            "Vulnerability Description",
            help="Describe the security issue or vulnerability.",
            placeholder="e.g. SQL Injection in user login...",
            key="manual_vuln_desc"
        )

    with col2:
        repo_url = st.text_input(
            "GitHub Repository URL",
            help="e.g. https://github.com/user/repo",
            placeholder="https://github.com/user/repo",
            key="manual_repo_url"
        )
        github_token = st.text_input(
            "GitHub Token",
            type="password",
            help="Personal Access Token with repo permissions.",
            key="manual_github_token"
        )
        
        gemini_api_key = st.text_input(
            "Gemini API Key",
            type="password",
            help="Google Gemini API key for AI-powered vulnerability fixes.",
            key="manual_gemini_key"
        )

    st.markdown("---")

    col3, col4, col5 = st.columns([1,2,1])
    with col4:
        manual_defend_btn = st.button("🛡️ Defend & Raise PR", use_container_width=True, key="manual_defend")

    if manual_defend_btn:
        # Validate inputs
        if not vuln_desc:
            st.error("Please provide a vulnerability description.")
        elif not repo_url:
            st.error("Please provide a GitHub repository URL.")
        elif not github_token:
            st.error("Please provide your GitHub token.")
        elif not gemini_api_key:
            st.error("Please provide your Gemini API key.")
        else:
            try:
                with st.spinner("🔍 Analyzing and defending your repository..."):
                    # Initialize AutoDefend
                    defender = AutoDefend(
                        repo_url=repo_url,
                        github_token=github_token,
                        gemini_api_key=gemini_api_key
                    )
                    
                    # Clone the repository
                    st.info("📥 Cloning repository...")
                    local_dir = defender.clone_repo()
                    
                    # Fix vulnerabilities using Gemini
                    st.info("🤖 Analyzing vulnerabilities with Gemini AI...")
                    defender.fix_vulnerability_in_file_with_llm(vuln_desc)
                    
                    # Commit and push changes
                    st.info("💾 Committing and pushing changes...")
                    commit_message = f"🛡️ Auto Defend: Fix vulnerability - {vuln_desc[:50]}..."
                    if defender.commit_and_push(commit_message):
                        # Create pull request
                        st.info("🔄 Creating pull request...")
                        pr_title = f"🛡️ Auto Defend: Security vulnerability fix"
                        pr_body = f"""This PR was automatically generated by Auto Defend to fix the following security vulnerability:

**Vulnerability Description:**
{vuln_desc}

**Changes Made:**
- Applied AI-powered security fixes using Google Gemini
- Improved code security and best practices

**Generated by:** Auto Defend 🛡️
"""
                        
                        pr_url = defender.create_pull_request(pr_title, pr_body)
                        
                        # Success message
                        st.success("✅ Pull Request created successfully!")
                        st.markdown(f"**PR URL:** [{pr_url}]({pr_url})")
                        
                        # Cleanup
                        defender.cleanup()
                    else:
                        st.warning("⚠️ No changes were made to the repository. The vulnerability might already be fixed or the description needs to be more specific.")
                        defender.cleanup()
                        
            except FileNotFoundError as e:
                st.error(f"❌ File not found: {str(e)}")
            except ValueError as e:
                st.error(f"❌ Invalid input: {str(e)}")
            except Exception as e:
                st.error(f"❌ An error occurred: {str(e)}")
                st.info("💡 Please check your inputs and try again.")

# Tab 2: DevRev Integration
with tab2:
    st.header("DevRev Ticket Integration")
    
    if not config or not config.get('devrev_user_auth'):
        st.error("❌ DevRev configuration not found. Please update config.properties with your DevRev credentials.")
        st.code("""
# Create config.properties file with:
[DEFAULT]
devrev_user_auth=your_jwt_token_here
devrev_base_url=https://app.devrev.ai/api/gateway/internal
devrev_org_id=don:core:dvrv-in-1:devo/2sRI6Hepzz
devrev_dev_user_don=don:identity:dvrv-in-1:devo/2sRI6Hepzz:devu/6117
devrev_session_id=your_session_id_here
        """)
    else:
        # DevRev ticket input
        col1, col2 = st.columns([1, 1])
        
        with col1:
            ticket_number = st.text_input(
                "DevRev Ticket Number",
                help="Enter ticket in any format: 415131, ISS-415131, or full DON ID",
                placeholder="415131 or ISS-415131",
                key="devrev_ticket_number"
            )
            
            fetch_btn = st.button("🔍 Fetch Ticket Details", key="fetch_ticket")
        
        with col2:
            devrev_repo_url = st.text_input(
                "GitHub Repository URL",
                help="e.g. https://github.com/user/repo",
                placeholder="https://github.com/user/repo",
                key="devrev_repo_url"
            )
            devrev_github_token = st.text_input(
                "GitHub Token",
                type="password",
                help="Personal Access Token with repo permissions.",
                key="devrev_github_token"
            )
            
            devrev_gemini_api_key = st.text_input(
                "Gemini API Key",
                type="password",
                help="Google Gemini API key for AI-powered vulnerability fixes.",
                key="devrev_gemini_key"
            )
        
        # Show current token status for debugging
        if config.get('devrev_user_auth'):
            token = config['devrev_user_auth']
            with st.expander("🔍 Current Token Status", expanded=False):
                st.write(f"**Token Length**: {len(token)} characters")
                st.write(f"**Token Preview**: {token[:30]}...{token[-10:]}")
                token_valid, token_message = validate_jwt_token(token)
                if token_valid:
                    st.success(f"✅ {token_message}")
                else:
                    st.error(f"❌ {token_message}")
        
        # Show ticket ID extraction preview
        if ticket_number:
            extracted_id = extract_ticket_number(ticket_number)
            if extracted_id:
                st.info(f"🎯 Extracted Ticket ID: **{extracted_id}** from input: `{ticket_number}`")
            else:
                st.warning(f"⚠️ Could not extract valid ticket ID from: `{ticket_number}`")
        
        # Fetch ticket details
        if fetch_btn and ticket_number:
            with st.spinner("🔍 Fetching ticket details from DevRev..."):
                ticket_data = fetch_devrev_ticket_details(ticket_number, config)
                st.session_state.ticket_data = ticket_data
                st.session_state.ticket_number = ticket_number
        
        # Display ticket details if available
        if 'ticket_data' in st.session_state and st.session_state.ticket_data:
            ticket_details = display_ticket_details(st.session_state.ticket_data)
            
            if ticket_details and 'error' not in st.session_state.ticket_data:
                st.markdown("---")
                
                # Extract vulnerability description from ticket
                vulnerability_desc = ""
                if isinstance(ticket_details, dict):
                    # Try multiple fields for the vulnerability description
                    description = ticket_details.get('description', ticket_details.get('body', ''))
                    title = ticket_details.get('title', ticket_details.get('summary', ''))
                    
                    if description:
                        vulnerability_desc = description
                    elif title:
                        vulnerability_desc = title
                    
                    # If both exist, combine them
                    if description and title and description != title:
                        vulnerability_desc = f"{title}\n\n{description}"
                
                # Show extracted vulnerability description
                st.subheader("🔧 Vulnerability Analysis")
                extracted_vuln = st.text_area(
                    "Extracted Vulnerability Description",
                    value=vulnerability_desc,
                    help="Edit if needed before running Auto Defend",
                    height=100,
                    key="extracted_vuln_desc"
                )
                
                # Defend button for DevRev ticket
                col3, col4, col5 = st.columns([1,2,1])
                with col4:
                    devrev_defend_btn = st.button("🛡️ Defend & Raise PR from Ticket", use_container_width=True, key="devrev_defend")
                
                if devrev_defend_btn:
                    # Validate inputs
                    if not extracted_vuln:
                        st.error("Please provide a vulnerability description.")
                    elif not devrev_repo_url:
                        st.error("Please provide a GitHub repository URL.")
                    elif not devrev_github_token:
                        st.error("Please provide your GitHub token.")
                    elif not devrev_gemini_api_key:
                        st.error("Please provide your Gemini API key.")
                    else:
                        try:
                            with st.spinner("🔍 Analyzing and defending your repository..."):
                                # Initialize AutoDefend
                                defender = AutoDefend(
                                    repo_url=devrev_repo_url,
                                    github_token=devrev_github_token,
                                    gemini_api_key=devrev_gemini_api_key
                                )
                                
                                # Clone the repository
                                st.info("📥 Cloning repository...")
                                local_dir = defender.clone_repo()
                                
                                # Fix vulnerabilities using Gemini
                                st.info("🤖 Analyzing vulnerabilities with Gemini AI...")
                                defender.fix_vulnerability_in_file_with_llm(extracted_vuln)
                                
                                # Commit and push changes
                                st.info("💾 Committing and pushing changes...")
                                commit_message = f"🛡️ Auto Defend: Fix vulnerability from DevRev ticket #{st.session_state.ticket_number}"
                                if defender.commit_and_push(commit_message):
                                    # Create pull request
                                    st.info("🔄 Creating pull request...")
                                    pr_title = f"🛡️ Auto Defend: Fix vulnerability from DevRev ticket #{st.session_state.ticket_number}"
                                    pr_body = f"""This PR was automatically generated by Auto Defend to fix security vulnerability from DevRev ticket.

**DevRev Ticket:** #{st.session_state.ticket_number}
**Vulnerability Description:**
{extracted_vuln}

**Changes Made:**
- Applied AI-powered security fixes using Google Gemini
- Improved code security and best practices

**Generated by:** Auto Defend 🛡️
"""
                                    
                                    pr_url = defender.create_pull_request(pr_title, pr_body)
                                    
                                    # Success message
                                    st.success("✅ Pull Request created successfully!")
                                    st.markdown(f"**PR URL:** [{pr_url}]({pr_url})")
                                    st.markdown(f"**DevRev Ticket:** #{st.session_state.ticket_number}")
                                    
                                    # Cleanup
                                    defender.cleanup()
                                else:
                                    st.warning("⚠️ No changes were made to the repository. The vulnerability might already be fixed or the description needs to be more specific.")
                                    defender.cleanup()
                                    
                        except FileNotFoundError as e:
                            st.error(f"❌ File not found: {str(e)}")
                        except ValueError as e:
                            st.error(f"❌ Invalid input: {str(e)}")
                        except Exception as e:
                            st.error(f"❌ An error occurred: {str(e)}")
                            st.info("💡 Please check your inputs and try again.") 