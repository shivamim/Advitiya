import streamlit as st
import os
import json
import requests
from rich.markdown import Markdown
from typing import Any
from dotenv import load_dotenv
from groq import Groq

# Load environment variables
load_dotenv()

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

def fetch_groq_response(prompt: str, api_key: str, model: str = "llama2-70b-4096") -> str:
    """Fetch response from Groq API."""
    try:
        client = Groq(api_key=api_key)
        
        # Call the Groq API
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are Advitiya, an advanced AI security assistant powered by Llama 3."},
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
    """Save chat history to JSON file."""
    with open('chat_history.json', 'w') as f:
        json.dump(st.session_state.chat_history, f)
    st.success("Chat history saved successfully!")

def perform_static_analysis(language_used: str, file_data: str, api_key: str, model: str) -> str:
    """Perform static code analysis."""
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
    
    Format the response in Markdown.
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
    """Perform vulnerability analysis."""
    instructions = """
    As a security vulnerability analyzer, examine the provided scan data to:
    1. Identify all security vulnerabilities
    2. Assess the risk level of each finding
    3. Detect misconfigurations
    4. Identify exposed sensitive information
    5. Evaluate security controls
    
    Provide a comprehensive report including:
    - Executive summary
    - Detailed findings
    - Risk ratings
    - Remediation steps
    - Technical recommendations
    
    Format the response in Markdown.
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

def main():
    # Page configuration with custom theme
    st.set_page_config(
        page_title="Advitiya AI", 
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Custom CSS
    st.markdown("""
        <style>
        .main {
            background-color: #f5f5f5;
        }
        .stTitle {
            color: #1E3D59;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 24px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding-top: 10px;
            padding-bottom: 10px;
        }
        .stButton > button {
            background-color: #1E3D59;
            color: white;
        }
        .success {
            background-color: #D4EDDA;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
        }
        </style>
        """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.title("⚙️ Configuration")
    st.sidebar.markdown("---")
    
    # API Configuration
    st.sidebar.header("API Configuration")
    api_key = st.sidebar.text_input("Groq API Key", type="password", placeholder="Enter your Groq API Key here")
    
    # Model Selection
    st.sidebar.header("Model Selection")
    model = st.sidebar.selectbox(
        "Select Model",
        [
            "llama2-70b-4096",
            "mixtral-8x7b-32768",
            "gemma-7b-it"
        ],
        help="Choose the AI model for analysis"
    )
    
    if st.sidebar.button("💾 Save Chat History"):
        save_chat_history()
    
    # Main title and description
    st.title("🔐 Advitiya AI")
    st.markdown("""
    Welcome to Advitiya AI - Your Advanced Security Analysis Assistant powered by Llama 3
    
    Leveraging state-of-the-art language models through Groq's high-performance API for intelligent security analysis.
    Select your analysis type below to begin your security assessment.
    """)
    
    # Create tabs with icons
    tab1, tab2, tab3 = st.tabs([
        "💬 Interactive Chat", 
        "🔍 Static Analysis", 
        "🛡️ Vulnerability Analysis"
    ])
    
    # Chat Tab
    with tab1:
        st.header("💬 Chat with Advitiya")
        user_input = st.text_area(
            "What would you like to know about security?",
            help="Enter your security-related query here"
        )
        
        col1, col2 = st.columns([1, 6])
        with col1:
            if st.button("Send 📤", key="chat_send", use_container_width=True):
                if not api_key:
                    st.error("⚠️ Please provide your Groq API Key in the sidebar.")
                elif user_input:
                    with st.spinner("🤔 Processing your query..."):
                        response = fetch_groq_response(user_input, api_key, model)
                        
                        st.session_state.chat_history.append({
                            "query": user_input,
                            "response": response
                        })
                        
                        st.markdown(response)
    
    # Static Analysis Tab
    with tab2:
        st.header("🔍 Static Code Analysis")
        language = st.selectbox(
            "Select Programming Language", 
            ["Python", "JavaScript", "Java", "C++", "PHP", "Ruby", "Go", "Rust", "Other"]
        )
        code = st.text_area(
            "Code for Analysis:",
            height=200,
            help="Paste your code here for security analysis"
        )
        
        if st.button("🔎 Analyze Code", use_container_width=True):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key in the sidebar.")
            elif code:
                with st.spinner("🔍 Analyzing code for vulnerabilities..."):
                    result = perform_static_analysis(language, code, api_key, model)
                    st.markdown(result)
    
    # Vulnerability Analysis Tab
    with tab3:
        st.header("🛡️ Vulnerability Analysis")
        scan_type = st.selectbox(
            "Select Scan Type", 
            ["Nmap", "Nikto", "OWASP ZAP", "Burp Suite", "Custom Log", "Network Scan", 
             "Web Application Scan", "Container Scan", "Cloud Security Scan"]
        )
        scan_data = st.text_area(
            "Scan Data:",
            height=200,
            help="Paste your scan results or log data here"
        )
        
        if st.button("🔍 Analyze Vulnerabilities", use_container_width=True):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key in the sidebar.")
            elif scan_data:
                with st.spinner("🔍 Analyzing security vulnerabilities..."):
                    result = perform_vuln_analysis(scan_type, scan_data, api_key, model)
                    st.markdown(result)
    
    # Display chat history with improved styling
    if st.session_state.chat_history:
        st.sidebar.markdown("---")
        st.sidebar.header("📚 Chat History")
        for idx, chat in enumerate(reversed(st.session_state.chat_history)):
            with st.sidebar.expander(f"Conversation {len(st.session_state.chat_history) - idx}"):
                st.markdown("**🗣️ Query:**")
                st.info(chat["query"])
                st.markdown("**🤖 Response:**")
                st.success(chat["response"])

if __name__ == "__main__":
    main()
