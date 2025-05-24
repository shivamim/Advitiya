import streamlit as st
import os
import json
import requests
from rich.markdown import Markdown
from typing import Any
from dotenv import load_dotenv
from groq import Groq
import time
import re
import tldextract
import joblib
import gdown

# Load environment variables
load_dotenv()

# Download model from Google Drive if not exists
MODEL_URL = "https://drive.google.com/uc?id=143Et7ju96CgnsBj8aOHToqNVAhP4mEfY"  # replace with your file ID
MODEL_FILE = "malicious_url_model.pkl"

if not os.path.exists(MODEL_FILE):
    with st.spinner("⬇️ Downloading model from Google Drive..."):
        gdown.download(MODEL_URL, MODEL_FILE, quiet=False)

# Initialize session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Load malicious URL detection model
try:
    url_model = joblib.load(MODEL_FILE)
except Exception as e:
    url_model = None
    st.warning(f"⚠️ Could not load 'malicious_url_model.pkl': {e}")

# Feature extractor
def extract_url_features(url):
    features = {}
    features["url_length"] = len(url)
    features["https"] = int(url.startswith("https"))
    features["num_dots"] = url.count(".")
    features["has_ip"] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    features["has_suspicious_words"] = int(any(word in url.lower() for word in ["login", "secure", "update", "verify", "account", "bank", "free", "click"]))
    ext = tldextract.extract(url)
    features["domain_length"] = len(ext.domain)
    return list(features.values())

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
    """Load custom CSS with white background and black text, keeping design & animations intact."""
    st.markdown("""
    <style>
        /* Import Fonts */
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap');

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

def display_model_info(model):
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
        <div style="padding: 1rem; border-radius: 10px; margin: 1rem 0; border: 1px solid #ccc;">
            <h4>🤖 {info['name']}</h4>
            <p>{info['description']}</p>
            <p><strong>Best for:</strong> {info['best_for']}</p>
        </div>
        """, unsafe_allow_html=True)

def main():
    st.set_page_config(page_title="Advitiya AI - Security Assistant", page_icon="🔐", layout="wide")
    load_custom_css()
    display_hero_section()

    st.sidebar.markdown('<div class="sidebar-header">⚙️ Configuration Panel</div>', unsafe_allow_html=True)
    st.sidebar.markdown("---")

    api_key = st.sidebar.text_input("Groq API Key", type="password", placeholder="Enter your Groq API Key here")
    model = st.sidebar.selectbox("Select AI Model", [
        "deepseek-r1-distill-llama-70b",
        "llama-3.1-8b-instant",
        "llama3-8b-8192",
        "mixtral-8x7b-32768",
        "gemma-7b-it"
    ])
    display_model_info(model)

    if st.sidebar.button("💾 Save Chat History", use_container_width=True):
        save_chat_history()

    st.sidebar.markdown("---")
    st.sidebar.metric("Chat Messages", len(st.session_state.chat_history))
    st.sidebar.metric("Selected Model", model.split('-')[0].title())

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💬 Interactive Chat",
        "🔍 Static Analysis",
        "🛡️ Vulnerability Analysis",
        "📚 Security Resources",
        "🧪 URL Safety Checker"
    ])

    # --- Tab 1: Chat ---
    with tab1:
        st.header("💬 Chat with Advitiya")
        user_input = st.text_area("Your Security Question:", height=150)
        if st.button("🚀 Send Message", key="chat_send"):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key.")
            elif user_input:
                with st.spinner("🤔 Thinking..."):
                    response = fetch_groq_response(user_input, api_key, model)
                    st.session_state.chat_history.append({
                        "query": user_input,
                        "response": response,
                        "model": model,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    st.markdown("### 🤖 Advitiya's Response:")
                    st.markdown(response)
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.success("Chat history cleared!")

    # --- Tab 2: Static Code Analysis ---
    with tab2:
        st.header("🔍 Static Code Analysis")
        language = st.selectbox("Programming Language", ["Python", "JavaScript", "Java", "C++", "C#", "PHP", "Go", "Other"])
        analysis_type = st.selectbox("Analysis Type", ["Security Vulnerabilities", "Code Quality", "Performance Issues", "Best Practices", "Complete Analysis"])
        code = st.text_area("Code for Analysis:", height=300)
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key.")
            elif code:
                with st.spinner("Analyzing..."):
                    result = perform_static_analysis(language, code, api_key, model)
                    st.markdown("### 📊 Analysis Results:")
                    st.markdown(result)

    # --- Tab 3: Vulnerability Analysis ---
    with tab3:
        st.header("🛡️ Vulnerability Analysis")
        scan_type = st.selectbox("Scan Type", ["Nmap Network Scan", "OWASP ZAP Report", "Nessus Scan", "Custom Log"])
        output_format = st.selectbox("Report Format", ["Detailed Report", "Executive Summary", "Technical Details", "Remediation Focus"])
        scan_data = st.text_area("Scan Data/Results:", height=300)
        if st.button("🔍 Analyze Vulnerabilities"):
            if not api_key:
                st.error("⚠️ Please provide your Groq API Key.")
            elif scan_data:
                with st.spinner("Analyzing..."):
                    result = perform_vuln_analysis(scan_type, scan_data, api_key, model)
                    st.markdown("### 🎯 Vulnerability Assessment Results:")
                    st.markdown(result)

    # --- Tab 4: Security Resources ---
    with tab4:
        st.header("📚 Security Resources & Best Practices")
        st.markdown("### 🔐 Security Frameworks")
        st.markdown("- OWASP Top 10\n- NIST Cybersecurity Framework\n- CIS Controls\n- ISO 27001\n- SANS Top 25")
        st.markdown("### 🛠️ Tools")
        st.markdown("- Static: SonarQube, Checkmarx\n- Dynamic: ZAP, Burp Suite\n- Network: Nmap, Nessus")
        st.markdown("### 📖 Learning")
        st.markdown("[OWASP Guide](https://owasp.org/), [SANS](https://sans.org/), [CISA](https://cisa.gov/)")

    # --- Tab 5: URL Safety Checker ---
    with tab5:
        st.header("🧪 Malicious URL Detector")
        url_input = st.text_input("🔗 Enter a URL", placeholder="e.g., http://example-login.com")
        if st.button("🚦 Check URL"):
            if not url_input:
                st.error("❗ Please enter a valid URL.")
            elif url_model is None:
                st.error("⚠️ Model not loaded. Please ensure 'malicious_url_model.pkl' exists.")
            else:
                try:
                    features = [extract_url_features(url_input)]
                    prediction = url_model.predict(features)[0]
                    label_map = {0: "BENIGN", 1: "DEFACEMENT", 2: "MALWARE", 3: "PHISHING"}
                    verdict = label_map.get(prediction, "UNKNOWN")
                    if verdict == "BENIGN":
                        st.success("✅ Safe: The URL appears to be **benign**.")
                    else:
                        st.error(f"⚠️ Warning: This URL appears to be **{verdict}**.")
                except Exception as ex:
                    st.error(f"❌ Error during prediction: {ex}")

if __name__ == "__main__":
    main()
