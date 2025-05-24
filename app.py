# ----------------- Imports and Config -----------------
import streamlit as st
st.set_page_config(page_title="Advitiya AI - Security Assistant", page_icon="⚡", layout="wide")

import os
import json
import time
import re
import joblib
import numpy as np
import tldextract
import gdown
from dotenv import load_dotenv
from rich.markdown import Markdown
from typing import Any
from groq import Groq
from streamlit_lottie import st_lottie
import requests

# ----------------- Load ENV -----------------
load_dotenv()

# ----------------- Helper Function -----------------
def convertion(url, prediction):
    if prediction == 1:
        return f"The URL '{url}' appears to be **safe** and legitimate."
    else:
        return f"⚠️ The URL '{url}' looks **suspicious** and might be a phishing attempt."

# ----------------- Download Model from Google Drive -----------------
MODEL_URL = "https://drive.google.com/uc?id=1cpKoE1MGVKBtgHWV3KJnwFPK0LgfNKSC"
MODEL_FILE = "malicious_url_model.pkl"

if not os.path.exists(MODEL_FILE):
    with st.spinner("⬇️ Downloading phishing detection model from Google Drive..."):
        gdown.download(MODEL_URL, MODEL_FILE, quiet=False)

try:
    phishing_model = joblib.load(MODEL_FILE)
except Exception as e:
    phishing_model = None

# ----------------- Session State -----------------
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# ----------------- Load Lottie -----------------
def load_lottie_url(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_shield = load_lottie_url("https://assets10.lottiefiles.com/packages/lf20_tutvdkg0.json")

# ----------------- Custom CSS -----------------
def load_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap');
        html, body, .main, .stApp {
            background: linear-gradient(135deg, #000000, #1a1a1a);
            color: #f8f8f8;
            font-family: 'Orbitron', sans-serif;
        }
        .main-header {
            background: rgba(0, 0, 0, 0.8);
            border: 2px solid #00FFFF;
            border-radius: 15px;
            padding: 2rem;
            text-align: center;
            box-shadow: 0 0 30px #00FFFF;
            animation: pulseHeader 3s infinite;
        }
        @keyframes pulseHeader {
            0% { box-shadow: 0 0 20px #00FFFF; }
            50% { box-shadow: 0 0 40px #FF00FF; }
            100% { box-shadow: 0 0 20px #00FFFF; }
        }
        .main-title {
            font-size: 3rem;
            color: #00FFFF;
        }
        .main-subtitle {
            font-size: 1.2rem;
            color: #ffffff;
        }
        .stButton > button {
            background: linear-gradient(45deg, #00FFFF, #FF00FF);
            color: white;
            font-weight: bold;
            border-radius: 25px;
            border: none;
            padding: 10px 25px;
            font-size: 1rem;
            box-shadow: 0 0 10px #00FFFF;
            transition: transform 0.2s ease-in-out;
        }
        .stButton > button:hover {
            transform: scale(1.08);
            box-shadow: 0 0 25px #FF00FF;
        }
        .stTabs [data-baseweb="tab-list"] {
            background: #101010;
            border-radius: 12px;
            padding: 0.5rem;
            border: 1px solid #00FFFF;
        }
        .stTabs [data-baseweb="tab"] {
            font-weight: bold;
            font-size: 1rem;
            padding: 1rem 1.5rem;
            border-radius: 10px;
            background: #1f1f1f;
            color: #ffffff;
        }
        .stTabs [aria-selected="true"] {
            background: linear-gradient(to right, #00FFFF, #FF00FF);
            color: #ffffff !important;
        }
    </style>
    """, unsafe_allow_html=True)

# ----------------- Display Hero -----------------
def display_hero_section():
    st.markdown("""
    <div class="main-header">
        <div class="main-title">⚡ Advitiya AI</div>
        <div class="main-subtitle">
            Futuristic AI-Powered Cybersecurity Assistant by Team XAI
        </div>
    </div>
    """, unsafe_allow_html=True)
    st_lottie(lottie_shield, height=200, key="shield")

# Keep rest of your app as-is...


# ----------------- Groq Integration -----------------
def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> str:
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are Advitiya, a helpful AI for cybersecurity and security analysis."},
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

# ----------------- Feature Extraction Inline -----------------
class FeatureExtraction:
    def __init__(self, url):
        self.url = url

    def getFeaturesList(self):
        features = []
        features.append(len(self.url))
        features.append(int(self.url.startswith("https")))
        features.append(self.url.count("."))
        features.append(int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', self.url))))
        features.append(int(any(word in self.url.lower() for word in ["login", "secure", "update", "verify", "account", "bank", "free", "click"])))
        ext = tldextract.extract(self.url)
        features.append(len(ext.domain))
        return features

# ----------------- App Main -----------------
def main():
    load_custom_css()
    display_hero_section()

    st.sidebar.header("⚙️ Configuration")
    api_key = st.sidebar.text_input("Groq API Key", type="password")
    model = st.sidebar.selectbox("AI Model", [
        "deepseek-r1-distill-llama-70b", "llama3-8b-8192", "mixtral-8x7b-32768", "gemma-7b-it"])
    st.sidebar.markdown("---")
    st.sidebar.metric("Messages", len(st.session_state.chat_history))
    st.sidebar.metric("Model", model)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💬 Chat", "🔍 Static Code Analysis", "🛡️ Vulnerability Analysis", "📚 Resources", "🧪 Phishing URL Detector"
    ])

    with tab1:
        st.header("💬 Ask Security Questions")
        user_input = st.text_area("Your Question:", height=150)
        if st.button("🚀 Send Message", key="chat_send"):
            if not api_key:
                st.error("Please enter Groq API key.")
            elif user_input:
                with st.spinner("Generating response..."):
                    response = fetch_groq_response(user_input, api_key, model)
                    st.session_state.chat_history.append({
                        "query": user_input, "response": response, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    st.markdown("### 🤖 Response:")
                    st.markdown(response)

    with tab2:
        st.header("🔍 Static Code Analysis")
        language = st.selectbox("Language", ["Python", "JavaScript", "C++", "Java", "Go", "Other"])
        code = st.text_area("Paste your code here:", height=300)
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("Please enter Groq API key.")
            elif code:
                with st.spinner("Analyzing code..."):
                    prompt = f"""
                    Analyze this code written in {language} for any security flaws, vulnerabilities, and improvement suggestions:
                    ```{language.lower()}
                    {code}
                    ```
                    """
                    result = fetch_groq_response(prompt, api_key, model)
                    st.markdown("### 📊 Code Analysis:")
                    st.markdown(result)

    with tab3:
        st.header("🛡️ Vulnerability Scan Analysis")
        scan_type = st.selectbox("Scan Type", ["Nmap", "ZAP", "Nessus", "Custom Log"])
        scan_data = st.text_area("Paste scan output:", height=300)
        if st.button("🔍 Analyze Vulnerabilities"):
            if not api_key:
                st.error("Please enter Groq API key.")
            elif scan_data:
                with st.spinner("Analyzing vulnerabilities..."):
                    prompt = f"Analyze this {scan_type} scan for security issues and provide fixes:\n{scan_data}"
                    result = fetch_groq_response(prompt, api_key, model)
                    st.markdown("### 🎯 Vulnerability Report:")
                    st.markdown(result)

    with tab4:
        st.header("📚 Cybersecurity Resources")
        st.markdown("""
        - 🔐 [OWASP Top 10](https://owasp.org/www-project-top-ten/)
        - 🛡️ [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
        - ✅ [CIS Critical Controls](https://www.cisecurity.org/controls/)
        - 🧠 [ISO/IEC 27001](https://www.iso.org/isoiec-27001-information-security.html)
        - 🐞 [SANS Top 25 Software Errors](https://www.sans.org/top25-software-errors/)
        """)

    with tab5:
        st.header("🧪 Phishing URL Detector")
        url = st.text_input("🔗 Enter URL to analyze", placeholder="https://example.com")
        if st.button("🚦 Check URL"):
            if not url:
                st.warning("Please enter a valid URL.")
            elif phishing_model is None:
                st.error("⚠️ Model not loaded. Please check the file.")
            else:
                try:
                    obj = FeatureExtraction(url)
                    x = np.array(obj.getFeaturesList()).reshape(1, -1)
                    safe_domains = ["google.com", "facebook.com", "netflix.com"]
                    parsed = tldextract.extract(url)
                    domain = f"{parsed.domain}.{parsed.suffix}"

                    if domain in safe_domains:
                        prediction = 1
                        st.info("🔒 Trusted domain detected.")
                    else:
                        prediction = phishing_model.predict(x)[0]

                    label_map = {1: "✅ Safe", -1: "⚠️ Phishing"}
                    result = label_map.get(prediction, "Unknown")

                    st.subheader(result)
                    st.markdown(convertion(url, prediction))

                    with st.expander("🔍 Feature Breakdown"):
                        features = obj.getFeaturesList()
                        for i, val in enumerate(features):
                            st.write(f"Feature {i+1}: {val}")

                except Exception as e:
                    st.error(f"Error during prediction: {str(e)}")

# ----------------- Launch -----------------
if __name__ == "__main__":
    main()
