import streamlit as st
import os
import json
import requests
from rich.markdown import Markdown
from typing import Any
from dotenv import load_dotenv
from groq import Groq
import time

# Load environment variables
load_dotenv()

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> str:
    """Fetch response from Groq API."""
    try:
        client = Groq(api_key=api_key)
        
        # Call the Groq API
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
    """Load custom CSS with white background and black text, keeping design & animations intact."""
    st.markdown("""
    <style>
        /* Import Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');
        /* 🔳 Futuristic Background */
.stApp {
    background: url("https://img.freepik.com/premium-vector/tech-grey-futuristic-abstract-background_42705913.jpg") no-repeat center center fixed;
    background-size: cover;
    background-attachment: fixed;
}

/* Overlay for readability */
.block-container::before {
    content: "";
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: rgba(255, 255, 255, 0.8);  /* slight white layer */
    z-index: -1;
}


        /* Global Overrides */
        .main, .stApp, .block-container {
            background: #ffffff !important;
            font-family: 'Poppins', sans-serif;
            color: #000000 !important;
        }

        /* Header Section */
        .main-header {
            background: rgba(255, 255, 255, 0.6);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid rgba(0, 0, 0, 0.1);
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
        }

        .main-title {
            font-size: 3rem;
            font-weight: 700;
            color: #000000 !important;
            text-shadow: 1px 1px 6px rgba(0,0,0,0.1);
            margin-bottom: 1rem;
        }

        .main-subtitle {
            font-size: 1.2rem;
            color: #333 !important;
            font-weight: 300;
            line-height: 1.6;
        }

        /* Sidebar */
        .css-1d391kg, .css-17lntkn, .css-1cypcdb {
            background: #f9f9f9 !important;
            color: #000000 !important;
            border-right: 1px solid #ddd;
        }

        .sidebar-header {
            color: #000000 !important;
            font-weight: 600;
            font-size: 1.2rem;
            margin-bottom: 1rem;
        }

        /* Text Everywhere */
        h1, h2, h3, h4, h5, h6, p, span, div, label,
        .stMarkdown, .stMarkdown *, .stText, .stHelp,
        .stTabs [data-baseweb="tab-panel"] * {
            color: #000000 !important;
        }

        /* Inputs */
        .stTextInput input, .stTextArea textarea {
            background: #f9f9f9 !important;
            color: #000000 !important;
            border: 1px solid #ccc !important;
            border-radius: 8px !important;
        }

        .stTextInput input::placeholder, .stTextArea textarea::placeholder {
            color: #888 !important;
        }

        /* Selectboxes */
        .stSelectbox > div > div {
            background: #ffffff !important;
            border: 1px solid #ccc !important;
            border-radius: 8px !important;
        }

        .stSelectbox > div > div > div {
            color: #000000 !important;
            background: #ffffff !important;
        }

        .stSelectbox div[data-baseweb="select"] div[role="option"] {
            color: #000000 !important;
            background: #ffffff !important;
        }

        .stSelectbox div[data-baseweb="select"] div[role="option"]:hover {
            background: #eaeaea !important;
            color: #000000 !important;
        }

        /* Buttons */
        .stButton > button {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
            color: white;
            border: none;
            border-radius: 25px;
            padding: 0.75rem 2rem;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }

        .stButton > button:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.15);
        }

        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {
            background: #f0f0f0;
            border-radius: 15px;
            padding: 1rem;
            border: 1px solid #ddd;
        }

        .stTabs [data-baseweb="tab"] {
            background: #ffffff;
            border-radius: 10px;
            color: #000000 !important;
            font-weight: 500;
            padding: 1rem 2rem;
            border: 1px solid #ccc;
            transition: all 0.3s ease;
        }

        .stTabs [data-baseweb="tab"]:hover {
            background: #f5f5f5;
            transform: translateY(-2px);
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4) !important;
            color: #ffffff !important;
            border: none;
        }

        /* Cards */
        .analysis-card {
            background: #fefefe;
            border-radius: 20px;
            padding: 2rem;
            margin: 1rem 0;
            border: 1px solid #eee;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }

        /* Messages */
        .stInfo > div {
            background: #e6f3ff !important;
            color: #000 !important;
            border: 1px solid #91c4e3 !important;
        }

        .stSuccess > div {
            background: #e6ffe6 !important;
            color: #000 !important;
            border: 1px solid #9dd69d !important;
        }

        .stError > div {
            background: #ffe6e6 !important;
            color: #000 !important;
            border: 1px solid #e29999 !important;
        }

        .stWarning > div {
            background: #fff8e6 !important;
            color: #000 !important;
            border: 1px solid #ebcd85 !important;
        }

        /* Animations */
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        /* Nice glow on headers */
        h1, h2, h3 {
            text-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }

        /* Responsive tweak */
        @media (max-width: 768px) {
            .main-title {
                font-size: 2rem;
            }

            .main-subtitle {
                font-size: 1rem;
            }

            .stTabs [data-baseweb="tab-list"] {
                gap: 1rem;
            }
        }
    </style>
    """, unsafe_allow_html=True)


def display_hero_section():
    """Display hero section with animated elements."""
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

def display_model_info(model):
    """Display information about the selected model."""
    model_info = {
        "llama3-8b-8192": {
            "name": "Llama 3 8B",
            "description": "Fast and efficient model for general security analysis",
            "best_for": "Quick analysis, code reviews"
        },
        "llama-3.1-8b-instant": {
            "name": "Llama 3.1 8B Instant",
            "description": "Latest Llama model with enhanced capabilities",
            "best_for": "Real-time analysis, instant responses"
        },
        "deepseek-r1-distill-llama-70b": {
            "name": "DeepSeek R1 Distill 70B",
            "description": "Advanced reasoning model for complex security analysis",
            "best_for": "Deep vulnerability analysis, complex threat modeling"
        },
        "mixtral-8x7b-32768": {
            "name": "Mixtral 8x7B",
            "description": "High-performance mixture of experts model",
            "best_for": "Comprehensive analysis, detailed reports"
        },
        "gemma-7b-it": {
            "name": "Gemma 7B IT",
            "description": "Instruction-tuned model for focused tasks",
            "best_for": "Specific security tasks, targeted analysis"
        }
    }
    
    if model in model_info:
        info = model_info[model]
        st.sidebar.markdown(f"""
        <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 10px; margin: 1rem 0; border: 1px solid rgba(255,255,255,0.2);">
            <h4 style="color: #4ECDC4; margin-bottom: 0.5rem;">🤖 {info['name']}</h4>
            <p style="color: rgba(255,255,255,0.9); font-size: 0.9rem; margin-bottom: 0.5rem;">{info['description']}</p>
            <p style="color: #FF6B6B; font-size: 0.8rem; font-weight: 600;">Best for: {info['best_for']}</p>
        </div>
        """, unsafe_allow_html=True)

def main():
    # Page configuration with custom theme
    st.set_page_config(
        page_title="Advitiya AI - Security Assistant", 
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Load custom CSS
    load_custom_css()
    
    # Display hero section
    display_hero_section()
    
    # Sidebar configuration with enhanced styling
    st.sidebar.markdown('<div class="sidebar-header">⚙️ Configuration Panel</div>', unsafe_allow_html=True)
    st.sidebar.markdown("---")
    
    # API Configuration
    st.sidebar.markdown('<div class="sidebar-header">🔑 API Configuration</div>', unsafe_allow_html=True)
    api_key = st.sidebar.text_input(
        "Groq API Key", 
        type="password", 
        placeholder="Enter your Groq API Key here",
        help="Get your API key from https://console.groq.com/"
    )
    
    # Model Selection with enhanced options
    st.sidebar.markdown('<div class="sidebar-header">🧠 Model Selection</div>', unsafe_allow_html=True)
    model = st.sidebar.selectbox(
        "Select AI Model",
        [
            "deepseek-r1-distill-llama-70b",
            "llama-3.1-8b-instant", 
            "llama3-8b-8192",
            "mixtral-8x7b-32768",
            "gemma-7b-it"
        ],
        help="Choose the AI model for analysis. Different models have different strengths."
    )
    
    # Display model information
    display_model_info(model)
    
    # Save chat history button with enhanced styling
    if st.sidebar.button("💾 Save Chat History", use_container_width=True):
        save_chat_history()
    
    # Statistics section
    st.sidebar.markdown("---")
    st.sidebar.markdown('<div class="sidebar-header">📊 Session Stats</div>', unsafe_allow_html=True)
    st.sidebar.metric("Chat Messages", len(st.session_state.chat_history))
    st.sidebar.metric("Selected Model", model.split('-')[0].title())
    
    # Create tabs with enhanced styling
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
        st.markdown("Ask me anything about cybersecurity, vulnerability analysis, secure coding practices, or threat assessment.")
        
        user_input = st.text_area(
            "Your Security Question:", 
            height=150,
            placeholder="e.g., How can I secure my REST API against common attacks?",
            help="Enter your security-related query here"
        )
        
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            if st.button("🚀 Send Message", key="chat_send", use_container_width=True):
                if not api_key:
                    st.error("⚠️ Please provide your Groq API Key in the sidebar.")
                elif user_input:
                    with st.spinner("🤔 Advitiya is thinking..."):
                        response = fetch_groq_response(user_input, api_key, model)
                        
                        st.session_state.chat_history.append({
                            "query": user_input, 
                            "response": response,
                            "model": model,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        })
                        
                        # Display response with enhanced formatting
                        st.markdown("### 🤖 Advitiya's Response:")
                        st.markdown(response)
        
        with col2:
            if st.button("🗑️ Clear Chat", use_container_width=True):
                st.session_state.chat_history = []
                st.success("Chat history cleared!")
        
        st.markdown('</div>', unsafe_allow_html=True)

    # Static Analysis Tab
    with tab2:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("🔍 Static Code Analysis")
        st.markdown("Upload or paste your code for comprehensive security analysis and vulnerability detection.")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            language = st.selectbox(
                "Programming Language", 
                ["Python", "JavaScript", "Java", "C++", "C#", "PHP", "Ruby", "Go", "Rust", "TypeScript", "Kotlin", "Swift", "Other"]
            )
        
        with col2:
            analysis_type = st.selectbox(
                "Analysis Type",
                ["Security Vulnerabilities", "Code Quality", "Performance Issues", "Best Practices", "Complete Analysis"]
            )
        
        code = st.text_area(
            "Code for Analysis:", 
            height=300, 
            placeholder="Paste your code here for security analysis...",
            help="Paste your code here for comprehensive security analysis"
        )
        
        if st.button("🔎 Analyze Code", use_container_width=True):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key in the sidebar.")
            elif code:
                with st.spinner("🔍 Analyzing code for vulnerabilities..."):
                    result = perform_static_analysis(language, code, api_key, model)
                    st.markdown("### 📊 Analysis Results:")
                    st.markdown(result)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Vulnerability Analysis Tab
    with tab3:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("🛡️ Vulnerability Analysis")
        st.markdown("Analyze scan results, logs, and security reports for comprehensive vulnerability assessment.")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            scan_type = st.selectbox(
                "Scan Type", 
                [
                    "Nmap Network Scan", 
                    "Nikto Web Scan", 
                    "OWASP ZAP Report", 
                    "Burp Suite Results", 
                    "Nessus Scan", 
                    "OpenVAS Report",
                    "Custom Security Log", 
                    "Network Packet Analysis", 
                    "Web Application Scan", 
                    "Container Security Scan", 
                    "Cloud Security Assessment",
                    "Penetration Test Report"
                ]
            )
        
        with col2:
            output_format = st.selectbox(
                "Report Format",
                ["Detailed Report", "Executive Summary", "Technical Details", "Remediation Focus"]
            )
        
        scan_data = st.text_area(
            "Scan Data/Results:", 
            height=300, 
            placeholder="Paste your scan results, logs, or security data here...",
            help="Paste your scan results or log data here for analysis"
        )
        
        if st.button("🔍 Analyze Vulnerabilities", use_container_width=True):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key in the sidebar.")
            elif scan_data:
                with st.spinner("🔍 Analyzing security vulnerabilities..."):
                    result = perform_vuln_analysis(scan_type, scan_data, api_key, model)
                    st.markdown("### 🎯 Vulnerability Assessment Results:")
                    st.markdown(result)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Security Resources Tab
    with tab4:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.header("📚 Security Resources & Best Practices")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("""
            ### 🔐 Security Frameworks
            - **OWASP Top 10** - Web application security risks
            - **NIST Cybersecurity Framework** - Comprehensive security guidance
            - **CIS Controls** - Critical security controls
            - **ISO 27001** - Information security management
            - **SANS Top 25** - Software security errors
            """)
            
            st.markdown("""
            ### 🛠️ Security Tools
            - **Static Analysis**: SonarQube, Checkmarx, Veracode
            - **Dynamic Analysis**: OWASP ZAP, Burp Suite
            - **Network Security**: Nmap, Wireshark, Nessus
            - **Container Security**: Docker Bench, Clair, Twistlock
            """)
        
        with col2:
            st.markdown("""
            ### 📖 Learning Resources
            - [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
            - [SANS Security Training](https://www.sans.org/)
            - [Cybersecurity & Infrastructure Security Agency](https://www.cisa.gov/)
            - [National Vulnerability Database](https://nvd.nist.gov/)
            """)
            
            st.markdown("""
            ### 🚨 Threat Intelligence
            - **CVE Database** - Common Vulnerabilities and Exposures
            - **MITRE ATT&CK** - Adversarial tactics and techniques
            - **Threat Feeds** - Real-time security intelligence
            - **Security Advisories** - Vendor security updates
            """)
        
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Enhanced chat history display
    if st.session_state.chat_history:
        st.sidebar.markdown("---")
        st.sidebar.markdown('<div class="sidebar-header">📚 Recent Conversations</div>', unsafe_allow_html=True)
        
        for idx, chat in enumerate(reversed(st.session_state.chat_history[-5:])):  # Show last 5 conversations
            with st.sidebar.expander(f"💬 Chat {len(st.session_state.chat_history) - idx}", expanded=False):
                st.markdown(f"**🤖 Model:** {chat.get('model', 'Unknown')}")
                st.markdown(f"**⏰ Time:** {chat.get('timestamp', 'Unknown')}")
                st.markdown("**❓ Query:**")
                st.info(chat["query"][:100] + "..." if len(chat["query"]) > 100 else chat["query"])
                st.markdown("**✅ Response:**")
                st.success(chat["response"][:150] + "..." if len(chat["response"]) > 150 else chat["response"])

if __name__ == "__main__":
    main()
