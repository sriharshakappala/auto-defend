import streamlit as st

st.set_page_config(page_title="Auto Defend", layout="centered", page_icon="🛡️")

# Sidebar
with st.sidebar:
    st.title("🛡️ Auto Defend")
    st.markdown("""
    **Auto Defend** helps you automatically fix security vulnerabilities in your codebase and raise a Pull Request on GitHub.
    
    - Enter a vulnerability description
    - Provide a GitHub repo URL
    - Add your GitHub token
    
    [GitHub Token Guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
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

col1, col2 = st.columns(2)

with col1:
    vuln_desc = st.text_area(
        "Vulnerability Description",
        help="Describe the security issue or vulnerability.",
        placeholder="e.g. SQL Injection in user login..."
    )

with col2:
    repo_url = st.text_input(
        "GitHub Repository URL",
        help="e.g. https://github.com/user/repo",
        placeholder="https://github.com/user/repo"
    )
    github_token = st.text_input(
        "GitHub Token",
        type="password",
        help="Personal Access Token with repo permissions."
    )

st.markdown("---")

col3, col4, col5 = st.columns([1,2,1])
with col4:
    defend_btn = st.button("🛡️ Defend & Raise PR", use_container_width=True)

if defend_btn:
    with st.spinner("Analyzing and defending your repository..."):
        st.info("Defend process will be implemented here.")
    # On success:
    # st.success("Pull Request created successfully!")
    # On error:
    # st.error("Failed to create Pull Request. Please check your inputs.") 