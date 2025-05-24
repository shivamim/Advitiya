# ----------------- Imports and Config -----------------
import streamlit as st
st.set_page_config(page_title="Advitiya AI - Security Assistant", page_icon="⚡", layout="wide")

import os
import json
import time
import re
import numpy as np
import joblib
from dotenv import load_dotenv
from groq import Groq
from feature import FeatureExtraction

# ----------------- Load ENV -----------------
load_dotenv()

# ----------------- Load Phishing Model -----------------
phishing_model = None
model_path = "newmodel.pkl"
if os.path.exists(model_path):
    try:
        phishing_model = joblib.load(model_path)
        print("✅ Model loaded from:", model_path)
    except Exception as e:
        print("❌ Error loading model:", e)
else:
    print("❌ Model file not found at:", model_path)

# ----------------- Session State -----------------
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# ----------------- Helper -----------------
def convertion(url, prediction):
    return f"✅ '{url}' is SAFE." if prediction == 1 else f"⚠️ '{url}' may be PHISHING."

# ----------------- CSS -----------------
def load_custom_css():
    st.markdown("""
    <style>
        body { font-family: 'Poppins', sans-serif; }
        .main-header { background: #f8f9fa; padding: 2rem; text-align: center; border-radius: 10px; }
        .main-title { font-size: 2.5rem; font-weight: bold; }
        .main-subtitle { font-size: 1.2rem; color: #555; }
        .stButton > button {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
            color: white; font-weight: bold;
            border-radius: 25px; padding: 10px 25px;
        }
        .stButton > button:hover {
            transform: scale(1.03);
        }
    </style>
    """, unsafe_allow_html=True)

# ----------------- Header -----------------
def display_hero_section():
    st.markdown("""
    <div class="main-header">
        <div class="main-title">🔐 Advitiya AI</div>
        <div class="main-subtitle">Advanced AI-Powered Security Assistant</div>
    </div>
    """, unsafe_allow_html=True)

# ----------------- Groq Chat -----------------
def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> str:
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are Advitiya, a helpful AI security assistant."},
                {"role": "user", "content": prompt}
            ],
            model=model
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ----------------- Main -----------------
def main():
    load_custom_css()
    display_hero_section()

    # Sidebar
    st.sidebar.header("⚙️ Configuration")
    api_key = st.sidebar.text_input("🔑 Groq API Key", type="password")
    model = st.sidebar.selectbox("🤖 Model", [
        "deepseek-r1-distill-llama-70b",
        "llama-3.1-8b-instant",
        "llama3-8b-8192",
        "mixtral-8x7b-32768",
        "gemma-7b-it"])
    if phishing_model:
        st.sidebar.success("✅ Model loaded")
    else:
        st.sidebar.error("❌ Model not loaded")

    st.sidebar.markdown("---")
    st.sidebar.metric("Messages", len(st.session_state.chat_history))

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "💬 Chat", "🔍 Code Analysis", "🛡️ Vulnerability Review", "🧪 Phishing URL Detection"])

    # Chat Tab
    with tab1:
        st.header("💬 Ask Security Questions")
        user_input = st.text_area("Your Question:", height=120)
        if st.button("🚀 Send Message", key="chat"):
            if not api_key:
                st.error("API Key missing")
            elif user_input:
                with st.spinner("Thinking..."):
                    reply = fetch_groq_response(user_input, api_key, model)
                    st.session_state.chat_history.append({"query": user_input, "response": reply})
                    st.markdown("### 🤖 Response:")
                    st.markdown(reply)

    # Code Tab
    with tab2:
        st.header("🔍 Static Code Analysis")
        lang = st.selectbox("Language", ["Python", "JavaScript", "Java", "C++", "Other"])
        code = st.text_area("Paste your code here", height=300)
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("API Key missing")
            elif code:
                prompt = f"Analyze this code for security issues:\nLanguage: {lang}\n```{lang}\n{code}\n```"
                result = fetch_groq_response(prompt, api_key, model)
                st.markdown("### 📊 Results:")
                st.markdown(result)

    # Vulnerability Tab
    with tab3:
        st.header("🛡️ Vulnerability Scan Review")
        scan_type = st.selectbox("Scan Tool", ["Nmap", "ZAP", "Nessus", "Custom Log"])
        data = st.text_area("Paste scan data", height=300)
        if st.button("🔍 Analyze Scan"):
            if not api_key:
                st.error("API Key missing")
            elif data:
                prompt = f"Analyze this vulnerability scan ({scan_type}) for issues:\n{data}"
                result = fetch_groq_response(prompt, api_key, model)
                st.markdown("### 🧾 Analysis Report:")
                st.markdown(result)

    # Phishing Tab
    with tab4:
        st.header("🧪 Phishing URL Detection")
        url = st.text_input("Enter URL to analyze")
        if st.button("🚦 Analyze URL"):
            if not url:
                st.warning("Enter a URL first")
            elif phishing_model is None:
                st.error("⚠️ Model not loaded")
            else:
                try:
                    obj = FeatureExtraction(url)
                    x = np.array(obj.getFeaturesList()).reshape(1, 30)
                    y_pred = phishing_model.predict(x)[0]
                    y_proba = phishing_model.predict_proba(x)[0]
                    confidence = y_proba[1] if y_pred == 1 else y_proba[0]

                    if y_pred == 1:
                        st.success(f"✅ Legitimate URL (Confidence: {confidence*100:.2f}%)")
                    else:
                        st.error(f"⚠️ Phishing URL (Confidence: {confidence*100:.2f}%)")
                    st.markdown(f"**Explanation:** {convertion(url, int(y_pred))}")

                    if st.checkbox("Show raw features"):
                        st.write(obj.getFeaturesList())
                except Exception as e:
                    st.error(f"Prediction Error: {str(e)}")

# ----------------- Launch App -----------------
if __name__ == "__main__":
    main()
