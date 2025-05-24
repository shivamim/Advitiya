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
import numpy as np
from feature import FeatureExtraction

# ----------------- Human-readable explanation -----------------
def convertion(url, prediction):
    if prediction == 1:
        return f"The URL '{url}' appears to be **safe** and legitimate."
    else:
        return f"⚠️ The URL '{url}' looks **suspicious** and might be a phishing attempt."

# ----------------- Load ENV -----------------
load_dotenv()

# ----------------- Load Phishing Model -----------------
phishing_model = None

try:
    phishing_model = joblib.load("model/phishing.pkl")
except Exception as e:
    print(f"⚠️ Could not load phishing model: {e}")

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

# ----------------- Groq Integration -----------------
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

# ----------------- Main App -----------------
def main():
    load_custom_css()
    display_hero_section()

    # ----------------- Sidebar -----------------
    st.sidebar.markdown('<div class="sidebar-header">⚙️ Configuration Panel</div>', unsafe_allow_html=True)
    api_key = st.sidebar.text_input("Groq API Key", type="password", placeholder="Enter your Groq API Key")
    model = st.sidebar.selectbox("AI Model", [
        "deepseek-r1-distill-llama-70b", "llama-3.1-8b-instant", "llama3-8b-8192",
        "mixtral-8x7b-32768", "gemma-7b-it"])
    if st.sidebar.button("💾 Save Chat History"):
        with open('chat_history.json', 'w') as f:
            json.dump(st.session_state.chat_history, f)
        st.sidebar.success("Chat history saved!")

    st.sidebar.markdown("---")
    st.sidebar.metric("Messages", len(st.session_state.chat_history))
    st.sidebar.metric("Model", model.split('-')[0].title())

    # ----------------- Tabs -----------------
    tab1, tab2, tab3, tab4 = st.tabs([
        "💬 Chat", "🔍 Static Analysis", "🛡️ Vulnerability Analysis", "🧪 Phishing URL Checker"
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
                        "query": user_input, "response": response, "model": model,
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
                    prompt = f"Analyze this code for security vulnerabilities and issues.\nLanguage: {language}\nCode:\n```{language}\n{code}\n```"
                    result = fetch_groq_response(prompt, api_key, model)
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
                    prompt = f"Analyze this {scan_type} scan output for vulnerabilities:\n{scan_data}"
                    result = fetch_groq_response(prompt, api_key, model)
                    st.markdown("### 🎯 Vulnerability Report:")
                    st.markdown(result)

    # ----------------- Tab 4: Phishing URL Detection -----------------
    with tab4:
        st.header("🧪 Phishing URL Detection")
        url_input = st.text_input("🔗 Enter a URL to check")

        if st.button("🚦 Predict"):
            if not url_input:
                st.warning("Please enter a URL.")
            elif phishing_model is None:
                st.error("⚠️ Phishing model not loaded.")
            else:
                try:
                    obj = FeatureExtraction(url_input)
                    x = np.array(obj.getFeaturesList()).reshape(1, 30)
                    y_pred = phishing_model.predict(x)[0]
                    y_proba = phishing_model.predict_proba(x)[0]
                    name = convertion(url_input, int(y_pred))
                    confidence = y_proba[1] if y_pred == 1 else y_proba[0]
                    if y_pred == 1:
                        st.success(f"✅ Legitimate URL (Confidence: {confidence*100:.2f}%)")
                    else:
                        st.error(f"⚠️ Phishing URL Detected (Confidence: {confidence*100:.2f}%)")
                    st.markdown(f"**Explanation:** {name}")
                except Exception as e:
                    st.error(f"Error during prediction: {e}")

# ----------------- Launch App -----------------
if __name__ == "__main__":
    main()
