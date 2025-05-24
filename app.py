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
from feature import FeatureExtraction

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

# ----------------- Custom CSS -----------------
def load_custom_css():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap');
        html, body, .main, .stApp {
            background: #f5f7fa !important;
            font-family: 'Poppins', sans-serif;
        }
        .main-header {
            background: linear-gradient(90deg, #4ECDC4, #556270);
            color: white;
            border-radius: 15px;
            padding: 2rem;
            text-align: center;
            box-shadow: 0 6px 20px rgba(0,0,0,0.1);
        }
        .main-title {
            font-size: 2.8rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        .main-subtitle {
            font-size: 1.2rem;
            font-weight: 300;
        }
        .stButton > button {
            background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
            color: white;
            font-weight: 600;
            border-radius: 25px;
            border: none;
            padding: 10px 25px;
            font-size: 1rem;
        }
        .stButton > button:hover {
            transform: scale(1.03);
            box-shadow: 0 0 15px rgba(0,0,0,0.1);
        }
        .metric-container {
            padding: 1rem;
            border-radius: 10px;
            background: white;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04);
        }
    </style>
    """, unsafe_allow_html=True)

# ----------------- Display Hero -----------------
def display_hero_section():
    st.markdown("""
    <div class="main-header">
        <div class="main-title">🔐 Advitiya AI</div>
        <div class="main-subtitle">
            Advanced AI-Powered Security Assistant by Team XAI
        </div>
    </div>
    """, unsafe_allow_html=True)

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

    tab1, tab2 = st.tabs(["💬 Chat Assistant", "🧪 Phishing URL Detector"])

    with tab1:
        st.header("💬 Ask Security Questions")
        user_input = st.text_area("Your Question:", height=150)
        if st.button("🚀 Send"):
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
        st.header("🧪 Malicious URL Detection")
        url = st.text_input("🔗 Enter a URL to check", placeholder="https://example.com")
        if st.button("🚦 Check URL"):
            if not url:
                st.warning("Please enter a valid URL.")
            elif phishing_model is None:
                st.error("⚠️ Model not loaded. Please check the file.")
            else:
                try:
                    obj = FeatureExtraction(url)
                    x = np.array(obj.getFeaturesList()).reshape(1, 30)
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
