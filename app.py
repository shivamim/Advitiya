import streamlit as st
import os
import json
import time
from dotenv import load_dotenv
from typing import Any
from groq import Groq

# Load environment variables
load_dotenv()

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> str:
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are Advitiya, an advanced AI security assistant powered by cutting-edge language models."},
                {"role": "user", "content": prompt}
            ],
            model=model,
            temperature=0.7,
            max_tokens=4096,
            top_p=1,
            stream=False
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"

def save_chat_history():
    with open('chat_history.json', 'w') as f:
        json.dump(st.session_state.chat_history, f)
    st.success("Chat history saved successfully!")
def perform_static_analysis(language_used: str, file_data: str, api_key: str, model: str) -> str:
    instructions = """
    As a code security expert, analyze the given programming file to identify:
    1. Security vulnerabilities
    2. Code quality issues
    3. Potential bugs
    4. Exposed sensitive information (API keys, credentials)
    5. Security best practices violations

    Provide a detailed analysis with:
    - Severity levels for each issue
    - Code snippets highlighting problems
    - Recommended fixes
    - Security best practices

    Format the response in Markdown with clear headers and bullet points.
    """
    analysis_prompt = f"""
    {instructions}
    Language: {language_used}
    Code to analyze:
    ```{language_used}
    {file_data}
    ```
    """
    return fetch_groq_response(analysis_prompt, api_key, model)

def perform_vuln_analysis(scan_type: str, scan_data: str, api_key: str, model: str) -> str:
    instructions = """
    As a security vulnerability analyzer, examine the provided scan data to:
    1. Identify all security vulnerabilities
    2. Assess the risk level of each finding
    3. Detect misconfigurations
    4. Identify exposed sensitive information
    5. Evaluate security controls

    Provide a comprehensive report including:
    - Executive summary
    - Detailed findings with CVSS scores where applicable
    - Risk ratings (Critical, High, Medium, Low)
    - Remediation steps
    - Technical recommendations

    Format the response in Markdown with clear sections and proper formatting.
    """
    analysis_prompt = f"""
    {instructions}
    Scan Type: {scan_type}
    Scan Data:
    ```    
    {scan_data}
    ```
    """
    return fetch_groq_response(analysis_prompt, api_key, model)

def load_custom_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
    .stApp {
        background: url("https://img.freepik.com/premium-vector/tech-grey-futuristic-abstract-background_42705913.jpg") no-repeat center center fixed;
        background-size: cover;
    }
    .block-container::before {
        content: "";
        position: absolute;
        top: 0; left: 0;
        width: 100%; height: 100%;
        background: rgba(255, 255, 255, 0.85);
        z-index: -1;
    }
    .main, .block-container {
        font-family: 'Poppins', sans-serif;
        color: #000000 !important;
    }
    .main-title {
        font-size: 3rem;
        font-weight: 700;
        color: #000 !important;
        animation: pulse 2s infinite;
    }
    .main-subtitle {
        font-size: 1.2rem;
        color: #333 !important;
    }
    .analysis-card {
        background: rgba(255,255,255,0.85);
        border-radius: 20px;
        padding: 2rem;
        margin: 1rem 0;
        border: 1px solid #ddd;
        box-shadow: 0 8px 20px rgba(0,0,0,0.05);
    }
    .stButton > button {
        background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.75rem 2rem;
        font-weight: 600;
        font-size: 1rem;
    }
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    </style>
    """, unsafe_allow_html=True)

def display_hero_section():
    st.markdown("""
    <div class="main-header fade-in">
        <div class="main-title pulse">🔐 Advitiya AI</div>
        <div class="main-subtitle">
            Advanced AI-Powered Security Analysis Assistant<br>
            <strong>Developed by Shivam Shukla</strong><br>
            Leveraging cutting-edge language models for intelligent security assessments
        </div>
    </div>
    """, unsafe_allow_html=True)
def main():
    st.set_page_config(
        page_title="Advitiya AI - Security Assistant", 
        page_icon="🔐", 
        layout="wide", 
        initial_sidebar_state="expanded"
    )

    load_custom_css()
    display_hero_section()

    # Sidebar Config
    st.sidebar.title("⚙️ Configuration")
    api_key = st.sidebar.text_input("🔑 Groq API Key", type="password")
    model = st.sidebar.selectbox("Select Model", [
        "llama3-8b-8192", "llama-3.1-8b-instant", 
        "deepseek-r1-distill-llama-70b", 
        "mixtral-8x7b-32768", 
        "gemma-7b-it"
    ])

    if st.sidebar.button("💾 Save Chat History"):
        save_chat_history()

    st.sidebar.markdown("---")
    st.sidebar.metric("Total Messages", len(st.session_state.chat_history))
    st.sidebar.metric("Selected Model", model)

    # Show last few chat entries in sidebar
    if st.session_state.chat_history:
        st.sidebar.markdown("### 📚 Recent Conversations")
        for idx, chat in enumerate(reversed(st.session_state.chat_history[-5:])):
            with st.sidebar.expander(f"Chat {len(st.session_state.chat_history) - idx}", expanded=False):
                st.markdown(f"**⏰ Time:** {chat.get('timestamp', '')}")
                st.info(chat["query"])
                st.success(chat["response"][:300] + "...")

    # Tabs for UI
    tab1, tab2, tab3, tab4 = st.tabs([
        "💬 Interactive Chat", 
        "🔍 Static Analysis", 
        "🛡️ Vulnerability Analysis",
        "📚 Security Resources"
    ])
    # Chat Tab
    with tab1:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("💬 Chat with Advitiya")
        st.markdown("Ask anything about cybersecurity, vulnerability analysis, secure coding, etc.")

        user_input = st.text_area("Your Security Question:", height=150)

        col1, col2 = st.columns([2, 1])
        with col1:
            if st.button("🚀 Send Message"):
                if not api_key:
                    st.error("⚠️ Please provide your Groq API Key.")
                elif user_input:
                    with st.spinner("🤔 Advitiya is thinking..."):
                        response = fetch_groq_response(user_input, api_key, model)
                        st.session_state.chat_history.append({
                            "query": user_input, 
                            "response": response,
                            "model": model,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        })
                        st.markdown("### 🤖 Advitiya's Response:")
                        st.markdown(response)
        with col2:
            if st.button("🗑️ Clear Chat"):
                st.session_state.chat_history = []
                st.success("Chat cleared!")
        st.markdown('</div>', unsafe_allow_html=True)

    # Static Analysis Tab
    with tab2:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("🔍 Static Code Analysis")
        lang = st.selectbox("Programming Language", ["Python", "JavaScript", "Java", "C++", "Other"])
        code = st.text_area("Paste your code here:", height=300)
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("Please enter your Groq API key.")
            elif code:
                with st.spinner("Analyzing..."):
                    result = perform_static_analysis(lang, code, api_key, model)
                    st.markdown("### 📊 Results")
                    st.markdown(result)
        st.markdown('</div>', unsafe_allow_html=True)

    # Vulnerability Analysis Tab
    with tab3:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("🛡️ Vulnerability Assessment")
        scan = st.selectbox("Scan Type", ["Nmap", "Burp Suite", "OWASP ZAP", "Nessus", "Other"])
        scan_data = st.text_area("Paste your scan data:", height=300)
        if st.button("🛡️ Analyze Vulnerabilities"):
            if not api_key:
                st.error("Enter your API Key.")
            elif scan_data:
                with st.spinner("Analyzing vulnerabilities..."):
                    result = perform_vuln_analysis(scan, scan_data, api_key, model)
                    st.markdown("### 🧪 Report")
                    st.markdown(result)
        st.markdown('</div>', unsafe_allow_html=True)

    # Security Resources Tab
    with tab4:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("📚 Security Resources & Best Practices")

        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown("""
            ### 🔐 Frameworks
            - OWASP Top 10
            - NIST CSF
            - CIS Controls
            - ISO 27001
            - SANS Top 25
            """)
            st.markdown("""
            ### 🛠️ Tools
            - Static: SonarQube, Veracode
            - Dynamic: Burp Suite, ZAP
            - Network: Nmap, Nessus
            """)
        with col2:
            st.markdown("""
            ### 📖 Learning
            - [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
            - [SANS](https://sans.org)
            - [CISA](https://cisa.gov)
            - [NVD](https://nvd.nist.gov)
            """)
            st.markdown("""
            ### 🚨 Intelligence
            - CVE DB
            - MITRE ATT&CK
            - Threat Feeds
            - Vendor Advisories
            """)
        st.markdown('</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()
