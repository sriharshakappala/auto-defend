import streamlit as st
import requests
import re
from auto_defend.defender import AutoDefend

st.set_page_config(page_title="DevRev Ticket Auto Defend", layout="centered", page_icon="🛡️")
st.title("🛡️ DevRev Ticket Auto Defend")

st.write("""
Enter a DevRev Ticket ID. This tool will fetch the ticket, extract the vulnerability, repository, and file, and automatically fix and raise a PR.
""")

ticket_id = st.text_input("DevRev Ticket ID", help="Paste the ticket ID here.")
gemini_api_key = st.text_input("Gemini API Key", type="password", help="Your Google Gemini API key.")
github_token = st.text_input("GitHub Token", type="password", help="Personal Access Token with repo permissions.")

def fetch_ticket(ticket_id, auth_token):
    url = f"https://app.devrev.ai/api/gateway/internal/works.get?id=don%3Acore%3Advrv-in-1%3Adevo%2F2sRI6Hepzz%3Aissue%2F{ticket_id}"
    headers = {
        'accept': 'application/json, text/plain, */*',
        'authorization': auth_token,
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def parse_ticket_description(desc):
    """
    Extract repo name, file name, and vulnerability details from the ticket description.
    """
    # Example: 'Repo: user/repo File: app.py Vulnerability: ...'
    repo_match = re.search(r'Repo[:=\s]+([\w\-/]+)', desc, re.IGNORECASE)
    file_match = re.search(r'File[:=\s]+([\w\-/\.]+)', desc, re.IGNORECASE)
    vuln_match = re.search(r'Vulnerability[:=\s]+(.+)', desc, re.IGNORECASE | re.DOTALL)
    repo = repo_match.group(1) if repo_match else None
    file = file_match.group(1) if file_match else None
    vuln = vuln_match.group(1).strip() if vuln_match else desc.strip()
    return repo, file, vuln

if st.button("Defend & Raise PR from Ticket"):
    if not ticket_id or not gemini_api_key or not github_token:
        st.error("Please provide all required fields.")
    else:
        with st.spinner("Fetching ticket and analyzing..."):
            try:
                auth_token = st.secrets["devrev_auth_token"]
                ticket = fetch_ticket(ticket_id, auth_token)
                if 'work' in ticket and 'body' in ticket['work']:
                    desc = ticket['work']['body']
                else:
                    st.error(f"Ticket response missing 'body'. Ticket JSON: {ticket}")
                    st.stop()
                repo, file, vuln = parse_ticket_description(desc)
                if not repo or not file:
                    st.error("Could not extract repository or file name from ticket description.")
                else:
                    repo_url = f"https://github.com/{repo}.git"
                    vuln_desc = f"File: {file}\n{vuln}"
                    defender = AutoDefend(repo_url, github_token, gemini_api_key)
                    defender.clone_repo()
                    defender.fix_vulnerability_in_file_with_llm(vuln_desc)
                    commit_message = f"Auto-defend: Fix vulnerability in {file} from DevRev ticket {ticket_id}"
                    defender.commit_and_push(commit_message)
                    pr_url = defender.create_pull_request(f"Fix vulnerability in {file}", f"Automated fix for vulnerability in {file} from DevRev ticket {ticket_id}.")
                    defender.cleanup()
                    st.success(f"Pull Request created: [View PR]({pr_url})")
            except Exception as e:
                st.error(f"Error: {e}") 