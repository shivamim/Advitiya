# ----------------- Imports and Config -----------------
import streamlit as st
st.set_page_config(page_title="Advitiya AI - Security Assistant", page_icon="⚡", layout="wide")

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

# ----------------- Load ENV -----------------
load_dotenv()

# ----------------- Download Model if Needed -----------------
MODEL_URL = "https://drive.google.com/uc?id=1cpKoE1MGVKBtgHWV3KJnwFPK0LgfNKSC"
MODEL_FILE = "random_forest_model.pkl"

if not os.path.exists(MODEL_FILE):
    with st.spinner("⬇️ Downloading model from Google Drive..."):
        gdown.download(MODEL_URL, MODEL_FILE, quiet=False)


# ----------------- Session State -----------------
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
# ----------------- Custom CSS -----------------
def load_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap');

        html, body, .main, .stApp {
            background: #ffffff !important;
            color: #000000 !important;
            font-family: 'Poppins', sans-serif;
        }

        /* Hero Header */
        .main-header {
            background: rgba(255, 255, 255, 0.7);
            backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 2rem;
            margin-bottom: 2rem;
            text-align: center;
            border: 1px solid #e0e0e0;
            box-shadow: 0 8px 24px rgba(0,0,0,0.05);
            animation: fadeIn 1s ease-in-out;
        }

        .main-title {
            font-size: 2.5rem;
            font-weight: 700;
            color: #000000;
        }

        .main-subtitle {
            font-size: 1.2rem;
            font-weight: 300;
            color: #444444;
        }

        /* Glass-style Cards */
        .analysis-card {
            background: rgba(255, 255, 255, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 2rem;
            margin: 1rem 0;
            border: 1px solid #dddddd;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04);
            animation: fadeIn 0.8s ease-in-out;
        }

        /* Stylish Buttons */
        .stButton > button {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
            color: white;
            font-weight: 600;
            border-radius: 25px;
            border: none;
            padding: 10px 25px;
            font-size: 1rem;
            transition: all 0.3s ease;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
        }

        .stButton > button:hover {
            transform: scale(1.03);
            box-shadow: 0 0 15px rgba(0,0,0,0.15);
        }

        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {
            background: #f2f2f2;
            border-radius: 12px;
            padding: 0.5rem;
            border: 1px solid #ddd;
        }

        .stTabs [data-baseweb="tab"] {
            font-weight: 500;
            font-size: 1rem;
            padding: 1rem 1.5rem;
            border-radius: 10px;
            background: #ffffff;
            color: #000000;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(90deg, #FF6B6B, #4ECDC4);
            color: white !important;
        }

        /* Inputs */
        input, textarea, select {
            background: #ffffff !important;
            color: #000000 !important;
            border: 1px solid #ccc !important;
            border-radius: 8px !important;
        }

        input::placeholder, textarea::placeholder {
            color: #888 !important;
        }

        /* Sidebar */
        .css-1d391kg, .css-17lntkn, .css-1cypcdb {
            background: #f9f9f9 !important;
            color: #000000 !important;
            border-right: 1px solid #ddd;
        }

        .sidebar-header {
            font-weight: 600;
            font-size: 1.2rem;
            color: #000000 !important;
        }

        /* Metric text */
        .stMetric label {
            color: #000000 !important;
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .fade-in {
            animation: fadeIn 0.6s ease-in-out;
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.03); }
            100% { transform: scale(1); }
        }
    </style>
    """, unsafe_allow_html=True)


# ----------------- Display Header -----------------
def display_hero_section():
    st.markdown("""
    <div class="main-header">
        <div class="main-title">🔐 Advitiya AI</div>
        <div class="main-subtitle">
            Advanced AI-Powered Security Assistant<br>
            <strong>Developed by Team XAI</strong>
        </div>
    </div>
    """, unsafe_allow_html=True)


# ----------------- Feature Extraction -----------------
def extract_url_features(url):
    features = {}
    features["url_length"] = len(url)
    features["https"] = int(url.startswith("https"))
    features["num_dots"] = url.count(".")
    features["has_ip"] = int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    features["has_suspicious_words"] = int(any(word in url.lower() for word in [
        "login", "secure", "update", "verify", "account", "bank", "free", "click"]))
    ext = tldextract.extract(url)
    features["domain_length"] = len(ext.domain)
    return list(features.values())
# ----------------- Analysis Helpers -----------------
def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> str:
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are Advitiya, an advanced AI security assistant."},
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


def perform_static_analysis(language_used: str, file_data: str, api_key: str, model: str) -> str:
    instructions = "Analyze this code for security vulnerabilities, quality issues, bugs, and bad practices."
    prompt = f"{instructions}\nLanguage: {language_used}\nCode:\n```{language_used}\n{file_data}\n```"
    return fetch_groq_response(prompt, api_key, model)


def perform_vuln_analysis(scan_type: str, scan_data: str, api_key: str, model: str) -> str:
    instructions = "Analyze this vulnerability scan for risks, misconfigurations, and fixes."
    prompt = f"{instructions}\nScan Type: {scan_type}\nScan Data:\n{scan_data}"
    return fetch_groq_response(prompt, api_key, model)


# ----------------- Main App Logic -----------------
def main():
    load_custom_css()
    display_hero_section()

    # ----------------- Sidebar -----------------
    st.sidebar.markdown('<div class="sidebar-header">⚙️ Configuration Panel</div>', unsafe_allow_html=True)
    api_key = st.sidebar.text_input("Groq API Key", type="password", placeholder="Enter your Groq API Key")
    model = st.sidebar.selectbox("AI Model", [
        "deepseek-r1-distill-llama-70b",
        "llama-3.1-8b-instant",
        "llama3-8b-8192",
        "mixtral-8x7b-32768",
        "gemma-7b-it"
    ])
    if st.sidebar.button("💾 Save Chat History"):
        with open('chat_history.json', 'w') as f:
            json.dump(st.session_state.chat_history, f)
        st.sidebar.success("Chat history saved!")

    st.sidebar.markdown("---")
    st.sidebar.metric("Messages", len(st.session_state.chat_history))
    st.sidebar.metric("Model", model.split('-')[0].title())

    # ----------------- Tabs -----------------
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💬 Chat",
        "🔍 Static Analysis",
        "🛡️ Vulnerability Analysis",
        "📚 Resources",
        "🧪 URL Safety Checker"
    ])

    # ----------------- Tab 1: Chat -----------------
    with tab1:
        st.header("💬 Ask Security Questions")
        user_input = st.text_area("Your Question:", height=150)
        if st.button("🚀 Send Message", key="chat_send"):
            if not api_key:
                st.error("Please provide your Groq API key.")
            elif user_input:
                with st.spinner("Thinking..."):
                    response = fetch_groq_response(user_input, api_key, model)
                    st.session_state.chat_history.append({
                        "query": user_input,
                        "response": response,
                        "model": model,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    st.markdown("### 🤖 Advitiya's Response:")
                    st.markdown(response)

    # ----------------- Tab 2: Static Code Analysis -----------------
    with tab2:
        st.header("🔍 Static Code Analysis")
        language = st.selectbox("Select Language", ["Python", "JavaScript", "C++", "Java", "Go", "Other"])
        code = st.text_area("Paste your code here", height=300)
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("Please provide your Groq API key.")
            elif code:
                with st.spinner("Analyzing code..."):
                    result = perform_static_analysis(language, code, api_key, model)
                    st.markdown("### 📊 Analysis Results:")
                    st.markdown(result)

    # ----------------- Tab 3: Vulnerability Analysis -----------------
    with tab3:
        st.header("🛡️ Vulnerability Scan Review")
        scan_type = st.selectbox("Scan Type", ["Nmap", "ZAP", "Nessus", "Custom Log"])
        scan_data = st.text_area("Paste scan output or data", height=300)
        if st.button("🔍 Analyze Vulnerabilities"):
            if not api_key:
                st.error("Please provide your Groq API key.")
            elif scan_data:
                with st.spinner("Analyzing vulnerabilities..."):
                    result = perform_vuln_analysis(scan_type, scan_data, api_key, model)
                    st.markdown("### 🎯 Vulnerability Report:")
                    st.markdown(result)

    # ----------------- Tab 4: Security Resources -----------------
    with tab4:
        st.header("📚 Cybersecurity Resources")
        st.markdown("""
        - 🔐 [OWASP Top 10](https://owasp.org/www-project-top-ten/)
        - 🛡️ [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
        - ✅ [CIS Critical Controls](https://www.cisecurity.org/controls/)
        - 🧠 [ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html)
        - 🐞 [SANS Top 25 Software Errors](https://www.sans.org/top25-software-errors/)
        """)

    # ----------------- Tab 5: URL Safety Checker -----------------
    with tab5:
        st.header("🧪 Malicious URL Detector")
        url_input = st.text_input("🔗 Enter URL to check", placeholder="http://example.com")
        if st.button("🚦 Check URL"):
            if not url_input:
                st.error("Please enter a valid URL.")
            elif url_model is None:
                st.error("⚠️ Model not loaded. Please check the file.")
            else:
                try:
                    features = [extract_url_features(url_input)]
                    prediction = url_model.predict(features)[0]
                    label_map = {0: "BENIGN", 1: "DEFACEMENT", 2: "MALWARE", 3: "PHISHING"}
                    result = label_map.get(prediction, "UNKNOWN")
                    if result == "BENIGN":
                        st.success("✅ Safe: This URL appears to be benign.")
                    else:
                        st.error(f"⚠️ Warning: This URL appears to be {result}.")
                except Exception as e:
                    st.error(f"Error during prediction: {e}")


# ----------------- Launch App -----------------
if __name__ == "__main__":
    main()
