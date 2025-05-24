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

# ----------------- Load Phishing Model (ENHANCED DEBUG VERSION) -----------------
phishing_model = None

def load_phishing_model():
    """Load the phishing detection model with multiple fallback paths and enhanced debugging"""
    global phishing_model
    
    print("🔍 DEBUG: Starting model loading process...")
    print(f"🔍 DEBUG: Current working directory: {os.getcwd()}")
    print(f"🔍 DEBUG: Files in current directory: {os.listdir('.')}")
    
    # Check if model directory exists
    if os.path.exists("model"):
        print(f"🔍 DEBUG: Model directory exists!")
        print(f"🔍 DEBUG: Files in model directory: {os.listdir('model')}")
    else:
        print("🔍 DEBUG: Model directory does NOT exist!")
    
    # Try multiple possible paths
    possible_paths = [
        "model/newmodel.pkl",  # Original path
        "./model/newmodel.pkl",  # Relative path
        os.path.join(os.getcwd(), "model", "newmodel.pkl"),  # Current working directory
        "newmodel.pkl",  # Direct file in root
        "./newmodel.pkl",  # Direct relative path
    ]
    
    # Add script directory path if __file__ is available
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_model_path = os.path.join(script_dir, "model", "newmodel.pkl")
        possible_paths.append(script_model_path)
        print(f"🔍 DEBUG: Script directory: {script_dir}")
    except:
        print("🔍 DEBUG: __file__ not available (running in Streamlit Cloud)")
    
    print(f"🔍 DEBUG: Trying {len(possible_paths)} possible paths...")
    
    for i, model_path in enumerate(possible_paths):
        print(f"🔍 DEBUG: [{i+1}] Checking path: {model_path}")
        print(f"🔍 DEBUG: [{i+1}] Path exists: {os.path.exists(model_path)}")
        
        if os.path.exists(model_path):
            try:
                print(f"🔍 DEBUG: [{i+1}] Attempting to load model...")
                phishing_model = joblib.load(model_path)
                print(f"✅ SUCCESS: Model loaded from: {model_path}")
                return True, model_path
            except Exception as e:
                print(f"❌ ERROR: Failed to load from {model_path}: {str(e)}")
                print(f"❌ ERROR: Exception type: {type(e).__name__}")
                continue
        else:
            print(f"❌ SKIP: Path does not exist: {model_path}")
    
    print("❌ FINAL: Model file not found in any location!")
    print("📋 SUMMARY: Paths checked:")
    for i, path in enumerate(possible_paths):
        print(f"   [{i+1}] {path} -> {'EXISTS' if os.path.exists(path) else 'NOT FOUND'}")
    
    return False, None

# Call the function to load the model
model_loaded, model_path_used = load_phishing_model()

# Debug function with enhanced information
def debug_file_structure():
    """Debug function to show current file structure with detailed info"""
    debug_info = {
        "current_dir": os.getcwd(),
        "files_in_current": [],
        "model_dir_exists": False,
        "model_files": [],
        "newmodel_pkl_locations": []
    }
    
    try:
        debug_info["script_dir"] = os.path.dirname(os.path.abspath(__file__)) if '__file__' in globals() else "N/A (Streamlit Cloud)"
    except:
        debug_info["script_dir"] = "N/A"
    
    try:
        debug_info["files_in_current"] = os.listdir(".")
    except Exception as e:
        debug_info["files_in_current"] = [f"Error: {str(e)}"]
    
    # Check model directory
    if os.path.exists("model"):
        debug_info["model_dir_exists"] = True
        try:
            debug_info["model_files"] = os.listdir("model")
            # Check specifically for newmodel.pkl
            if "newmodel.pkl" in debug_info["model_files"]:
                model_path = "model/newmodel.pkl"
                debug_info["newmodel_pkl_locations"].append({
                    "path": model_path,
                    "exists": os.path.exists(model_path),
                    "size": os.path.getsize(model_path) if os.path.exists(model_path) else "N/A"
                })
        except Exception as e:
            debug_info["model_files"] = [f"Error: {str(e)}"]
    
    # Search for newmodel.pkl in current directory
    if "newmodel.pkl" in debug_info["files_in_current"]:
        debug_info["newmodel_pkl_locations"].append({
            "path": "newmodel.pkl",
            "exists": True,
            "size": os.path.getsize("newmodel.pkl")
        })
    
    return debug_info
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
        .debug-info {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 10px;
            border-left: 4px solid #007bff;
            margin: 1rem 0;
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
                {"role": "system", "content": "You are Advitiya, an advanced AI security assistant created by Team XAI. You provide expert cybersecurity advice, analyze code for vulnerabilities, and help with security best practices."},
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
        return f"❌ Error: {str(e)}\n\nPlease check your API key and try again."
        # ----------------- Main App Function -----------------
# ----------------- Main App Function -----------------
def main():
    load_custom_css()
    display_hero_section()

    # ----------------- Sidebar Configuration -----------------
    st.sidebar.markdown('<div style="font-size: 1.5rem; font-weight: 600; margin-bottom: 1rem;">⚙️ Configuration Panel</div>', unsafe_allow_html=True)
    
    # Declare global variables at the start of function
    global phishing_model, model_loaded, model_path_used
    
    # Model Status Display
    if phishing_model is not None:
        st.sidebar.success(f"✅ Phishing model loaded successfully!")
        if model_path_used:
            st.sidebar.info(f"📁 Loaded from: {os.path.basename(model_path_used)}")
    else:
        st.sidebar.error("❌ Phishing model not loaded.")
        if st.sidebar.button("🔄 Retry Loading Model"):
            model_loaded, model_path_used = load_phishing_model()
            if model_loaded:
                st.rerun()

    # Debug Information (enhanced)
    with st.sidebar.expander("🔍 Debug Information", expanded=not model_loaded):
        debug_info = debug_file_structure()
        st.write("**Current Directory:**", debug_info["current_dir"])
        st.write("**Script Directory:**", debug_info["script_dir"])
        
        st.write("**Files in Current Dir:**")
        st.json(debug_info["files_in_current"])
        
        st.write("**Model Directory Exists:**", debug_info["model_dir_exists"])
        if debug_info["model_dir_exists"]:
            st.write("**Files in Model Dir:**")
            st.json(debug_info["model_files"])
            
            # Highlight if newmodel.pkl is found
            if "newmodel.pkl" in debug_info["model_files"]:
                st.success("✅ newmodel.pkl found in model directory!")
            else:
                st.error("❌ newmodel.pkl NOT found in model directory!")
        
        # Show newmodel.pkl locations if found
        if debug_info["newmodel_pkl_locations"]:
            st.write("**newmodel.pkl Locations Found:**")
            for location in debug_info["newmodel_pkl_locations"]:
                st.write(f"- **Path:** {location['path']}")
                st.write(f"  - **Exists:** {location['exists']}")
                st.write(f"  - **Size:** {location['size']} bytes")
        else:
            st.error("❌ newmodel.pkl not found anywhere!")
            
        # Manual path test
        st.write("**Manual Path Tests:**")
        test_paths = ["model/newmodel.pkl", "./model/newmodel.pkl", "newmodel.pkl"]
        for path in test_paths:
            exists = os.path.exists(path)
            st.write(f"- `{path}`: {'✅ EXISTS' if exists else '❌ NOT FOUND'}")
            if exists:
                try:
                    size = os.path.getsize(path)
                    st.write(f"  Size: {size} bytes")
                except:
                    st.write("  Size: Error getting size")

    st.sidebar.markdown("---")
    
    # API Configuration
    api_key = st.sidebar.text_input("🔑 Groq API Key", type="password", placeholder="Enter your Groq API Key")
    model = st.sidebar.selectbox("🤖 AI Model", [
        "deepseek-r1-distill-llama-70b", 
        "llama-3.1-8b-instant", 
        "llama3-8b-8192",
        "mixtral-8x7b-32768", 
        "gemma-7b-it"
    ])

    # Chat History Management
    if st.sidebar.button("💾 Save Chat History"):
        try:
            with open('chat_history.json', 'w') as f:
                json.dump(st.session_state.chat_history, f, indent=2)
            st.sidebar.success("💾 Chat history saved!")
        except Exception as e:
            st.sidebar.error(f"❌ Error saving: {str(e)}")
    
    if st.sidebar.button("🗑️ Clear Chat History"):
        st.session_state.chat_history = []
        st.sidebar.success("🗑️ Chat history cleared!")

    st.sidebar.markdown("---")
    
    # Statistics
    st.sidebar.metric("💬 Total Messages", len(st.session_state.chat_history))
    st.sidebar.metric("🤖 Current Model", model.split('-')[0].title())
    st.sidebar.metric("🛡️ Model Status", "✅ Loaded" if phishing_model else "❌ Not Loaded")

    # ----------------- Main Tabs -----------------
    tab1, tab2, tab3, tab4 = st.tabs([
        "💬 Chat Assistant", "🔍 Code Analysis", "🛡️ Vulnerability Scan", "🧪 Phishing Detector"
    ])
    # ----------------- Tab 1: Chat Assistant -----------------
    with tab1:
        st.header("💬 AI Security Assistant")
        st.markdown("Ask me anything about cybersecurity, security best practices, threat analysis, or get help with security-related questions.")
        
        user_input = st.text_area("🗨️ Your Security Question:", height=120, placeholder="e.g., How can I secure my web application against SQL injection attacks?")
        
        col1, col2 = st.columns([1, 4])
        with col1:
            send_button = st.button("🚀 Send Message", key="chat_send")
        with col2:
            if len(st.session_state.chat_history) > 0:
                if st.button("📜 Show Chat History"):
                    st.session_state.show_history = not st.session_state.get('show_history', False)

        if send_button:
            if not api_key:
                st.error("🔑 Please provide your Groq API key in the sidebar.")
            elif not user_input.strip():
                st.warning("💭 Please enter your question.")
            else:
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

        # Display chat history if toggled
        if st.session_state.get('show_history', False) and st.session_state.chat_history:
            st.markdown("### 📜 Chat History")
            for i, chat in enumerate(reversed(st.session_state.chat_history[-5:])):  # Show last 5
                with st.expander(f"💬 {chat['timestamp']} - {chat['query'][:50]}..."):
                    st.markdown(f"**Question:** {chat['query']}")
                    st.markdown(f"**Response:** {chat['response']}")
                    st.markdown(f"*Model: {chat['model']} | Time: {chat['timestamp']}*")

    # ----------------- Tab 2: Static Code Analysis -----------------
    with tab2:
        st.header("🔍 Static Code Security Analysis")
        st.markdown("Upload or paste your code for comprehensive security vulnerability analysis.")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            language = st.selectbox("Programming Language", ["Python", "JavaScript", "C++", "Java", "C#", "PHP", "Go", "Ruby", "Other"])
        with col2:
            analysis_type = st.selectbox("Analysis Focus", ["General Security", "SQL Injection", "XSS Vulnerabilities", "Authentication Issues", "Input Validation"])
        
        code = st.text_area("📝 Paste your code here:", height=300, placeholder="Paste your code here for security analysis...")
        
        if st.button("🔎 Analyze Code Security", key="code_analyze"):
            if not api_key:
                st.error("🔑 Please provide your Groq API key in the sidebar.")
            elif not code.strip():
                st.warning("📝 Please paste some code to analyze.")
            else:
                with st.spinner("🔍 Analyzing code for security vulnerabilities..."):
                    prompt = f"""
                    As a cybersecurity expert, analyze this {language} code for security vulnerabilities and issues.
                    Focus on: {analysis_type}
                    
                    Provide:
                    1. Critical security vulnerabilities
                    2. Potential security risks
                    3. Best practice recommendations
                    4. Code improvement suggestions
                    
                    Language: {language}
                    Code:
                    ```{language.lower()}
                    {code}
                    ```
                    """
                    result = fetch_groq_response(prompt, api_key, model)
                    st.markdown("### 📊 Security Analysis Results:")
                    st.markdown(result)

    # ----------------- Tab 3: Vulnerability Analysis -----------------
    with tab3:
        st.header("🛡️ Vulnerability Scan Analysis")
        st.markdown("Analyze and interpret security scan results from various tools.")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            scan_type = st.selectbox("Scan Tool/Type", ["Nmap", "ZAP (OWASP)", "Nessus", "OpenVAS", "Burp Suite", "Custom Log", "Penetration Test Results"])
        with col2:
            priority_filter = st.selectbox("Priority Focus", ["All Issues", "Critical Only", "High & Critical", "Medium & Above"])
        
        scan_data = st.text_area("🔬 Paste scan output or vulnerability data:", height=300, placeholder="Paste your security scan results here...")
        
        if st.button("🔍 Analyze Vulnerabilities", key="vuln_analyze"):
            if not api_key:
                st.error("🔑 Please provide your Groq API key in the sidebar.")
            elif not scan_data.strip():
                st.warning("📊 Please paste scan data to analyze.")
            else:
                with st.spinner("🛡️ Analyzing vulnerability scan results..."):
                    prompt = f"""
                    As a cybersecurity analyst, analyze this {scan_type} scan output for vulnerabilities and security issues.
                    Focus on: {priority_filter}
                    
                    Provide:
                    1. Executive summary of findings
                    2. Critical vulnerabilities that need immediate attention
                    3. Risk assessment and prioritization
                    4. Remediation recommendations
                    5. False positive identification (if any)
                    
                    Scan Data:
                    {scan_data}
                    """
                    result = fetch_groq_response(prompt, api_key, model)
                    st.markdown("### 🎯 Vulnerability Analysis Report:")
                    st.markdown(result)

    # ----------------- Tab 4: Phishing URL Checker -----------------
    with tab4:
        st.header("🧪 Advanced Phishing URL Detection")
        st.markdown("Detect malicious and phishing URLs using machine learning analysis.")
        
        col1, col2 = st.columns([3, 1])
        with col1:
            url_input = st.text_input("🔗 Enter URL to analyze:", placeholder="https://example.com")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)  # Spacing
            predict_button = st.button("🚦 Analyze URL", key="url_predict")

        if predict_button:
            if not url_input.strip():
                st.warning("🔗 Please enter a URL to analyze.")
            elif phishing_model is None:
                st.error("⚠️ Phishing detection model is not loaded. Please check the debug information in the sidebar.")
                st.info("💡 **Troubleshooting:** Make sure the `newmodel.pkl` file is in the `model/` directory.")
            else:
                try:
                    with st.spinner("🔍 Analyzing URL for phishing indicators..."):
                        # Extract features from URL
                        obj = FeatureExtraction(url_input)
                        x = np.array(obj.getFeaturesList()).reshape(1, 30)
                        
                        # Make prediction
                        y_pred = phishing_model.predict(x)[0]
                        y_proba = phishing_model.predict_proba(x)[0]
                        
                        # Get confidence score
                        confidence = y_proba[1] if y_pred == 1 else y_proba[0]
                        
                        # Display results
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            if y_pred == 1:
                                st.success(f"✅ **LEGITIMATE URL**")
                                st.metric("Safety Score", f"{confidence*100:.1f}%", delta="Safe")
                            else:
                                st.error(f"⚠️ **PHISHING DETECTED**")
                                st.metric("Threat Level", f"{confidence*100:.1f}%", delta="Dangerous")
                        
                        with col2:
                            st.info(f"**URL:** {url_input}")
                            st.info(f"**Analysis Time:** {time.strftime('%H:%M:%S')}")
                        
                        # Detailed explanation
                        explanation = convertion(url_input, int(y_pred))
                        st.markdown("### 📋 Analysis Details:")
                        st.markdown(explanation)
                        
                        # Feature breakdown (optional advanced view)
                        if st.checkbox("🔬 Show Advanced Feature Analysis"):
                            features = obj.getFeaturesList()
                            st.markdown("**URL Features Analyzed:**")
                            feature_names = [f"Feature_{i+1}" for i in range(len(features))]
                            feature_df = {"Feature": feature_names, "Value": features}
                            st.dataframe(feature_df, height=200)
                            
                except Exception as e:
                    st.error(f"❌ Error during URL analysis: {str(e)}")
                    st.info("💡 Make sure the `feature.py` file is available and the URL format is correct.")

# ----------------- Launch Application -----------------
if __name__ == "__main__":
    main()
