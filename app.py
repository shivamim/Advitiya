import streamlit as st
st.set_page_config(page_title="Advitiya AI - Security Assistant", page_icon="🔐", layout="wide")

import os, json, re, time, joblib
import tldextract, gdown
from dotenv import load_dotenv
from groq import Groq

# Load env
load_dotenv()

# Model download
MODEL_URL = "https://drive.google.com/uc?id=14rCp6hZJCdGwwFZUVVBGeSh8DCMFsTMy"
MODEL_FILE = "malicious_url_model.pkl"
if not os.path.exists(MODEL_FILE):
    with st.spinner("⬇️ Downloading model from Google Drive..."):
        gdown.download(MODEL_URL, MODEL_FILE, quiet=False)

try:
    url_model = joblib.load(MODEL_FILE)
except Exception as e:
    url_model = None
    st.warning(f"⚠️ Could not load model: {e}")

if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

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
        .thump-badge {
            display: inline-block;
            background: linear-gradient(90deg, #ff6b6b, #4ecdc4);
            color: #fff;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 1rem;
            border-radius: 50px;
            margin-top: 20px;
            box-shadow: 0 0 20px rgba(255,255,255,0.2);
            animation: thump 1.8s infinite ease-in-out, fadeIn 1s ease-in-out;
        }
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
        input, textarea, select {
            background: #ffffff !important;
            color: #000000 !important;
            border: 1px solid #ccc !important;
            border-radius: 8px !important;
        }
        .sidebar-header { font-weight: 600; font-size: 1.2rem; color: #000 !important; }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes thump {
            0% { transform: scale(1); }
            50% { transform: scale(1.08); }
            100% { transform: scale(1); }
        }
    </style>
    """, unsafe_allow_html=True)

def display_hero_section():
    st.markdown("""
    <div class="main-header">
        <div class="main-title">🔐 Advitiya AI</div>
        <div class="main-subtitle">
            Advanced AI-Powered Security Analysis Assistant<br>
            <strong>Developed by Shivam Shukla</strong>
        </div>
        <div class="thump-badge">🔥 Live AI Protection Enabled</div>
    </div>
    """, unsafe_allow_html=True)

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

def fetch_groq_response(prompt: str, api_key: str, model: str = "llama3-8b-8192") -> str:
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            messages=[{"role": "system", "content": "You are Advitiya, an advanced AI security assistant."},
                      {"role": "user", "content": prompt}],
            model=model, temperature=0.7, max_tokens=4096, top_p=1, stream=False)
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error: {str(e)}"

def perform_static_analysis(language, code, api_key, model):
    prompt = f"""Analyze the following {language} code for security vulnerabilities, bugs, and bad practices:
    ```{language}
    {code}
    ```"""
    return fetch_groq_response(prompt, api_key, model)

def perform_vuln_analysis(scan_type, data, api_key, model):
    prompt = f"""Analyze this {scan_type} scan for vulnerabilities and misconfigurations:
    {data}"""
    return fetch_groq_response(prompt, api_key, model)
def main():
    load_custom_css()
    display_hero_section()

    # Sidebar
    st.sidebar.markdown('<div class="sidebar-header">⚙️ Configuration Panel</div>', unsafe_allow_html=True)
    api_key = st.sidebar.text_input("🔑 Groq API Key", type="password", placeholder="Enter Groq API Key")
    model = st.sidebar.selectbox("🧠 Select AI Model", [
        "deepseek-r1-distill-llama-70b",
        "llama-3.1-8b-instant",
        "llama3-8b-8192",
        "mixtral-8x7b-32768",
        "gemma-7b-it"
    ])

    if st.sidebar.button("💾 Save Chat History"):
        with open("chat_history.json", "w") as f:
            json.dump(st.session_state.chat_history, f)
        st.sidebar.success("✅ Saved!")

    st.sidebar.markdown("---")
    st.sidebar.metric("💬 Messages", len(st.session_state.chat_history))
    st.sidebar.metric("🎯 Model", model.split('-')[0].title())

    # Tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "💬 Chat",
        "🔍 Static Analysis",
        "🛡️ Vulnerability Review",
        "📚 Security Resources",
        "🧪 URL Safety Checker"
    ])

    # --- Tab 1: Chat ---
    with tab1:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.subheader("💬 Chat with Advitiya")
        query = st.text_area("Ask anything related to cybersecurity or secure coding", height=150)
        if st.button("🚀 Send"):
            if not api_key:
                st.error("❗ API Key missing")
            elif query:
                with st.spinner("🤔 Thinking..."):
                    reply = fetch_groq_response(query, api_key, model)
                    st.session_state.chat_history.append({
                        "query": query,
                        "response": reply,
                        "model": model,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    st.markdown("### 🤖 Advitiya’s Reply:")
                    st.markdown(reply)
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.success("Chat cleared!")
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Tab 2: Static Code Analysis ---
    with tab2:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.subheader("🔍 Analyze Your Code")
        language = st.selectbox("Select Language", ["Python", "JavaScript", "Java", "C++", "Go", "Other"])
        code = st.text_area("Paste your code for analysis", height=300)
        if st.button("🔎 Analyze Code"):
            if not api_key:
                st.error("❗ API Key required")
            elif code:
                with st.spinner("🧠 Analyzing..."):
                    result = perform_static_analysis(language, code, api_key, model)
                    st.markdown("### 📊 Analysis Report")
                    st.markdown(result)
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Tab 3: Vulnerability Analysis ---
    with tab3:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.subheader("🛡️ Analyze Vulnerability Data")
        scan_type = st.selectbox("Type of Scan", ["Nmap", "ZAP", "Nessus", "Custom"])
        data = st.text_area("Paste your scan results or logs", height=300)
        if st.button("🧠 Analyze Vulnerabilities"):
            if not api_key:
                st.error("❗ API Key required")
            elif data:
                with st.spinner("🔍 Working on it..."):
                    result = perform_vuln_analysis(scan_type, data, api_key, model)
                    st.markdown("### 🧾 Findings")
                    st.markdown(result)
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Tab 4: Security Resources ---
    with tab4:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.subheader("📚 Security Learning Hub")
        st.markdown("""
        ### 🔐 Frameworks  
        - [OWASP Top 10](https://owasp.org/www-project-top-ten/)  
        - [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)  
        - [CIS Controls](https://www.cisecurity.org/controls/)  

        ### 🛠️ Tools  
        - **Static Analysis**: SonarQube, Checkmarx  
        - **Dynamic Testing**: ZAP, Burp Suite  
        - **Network Security**: Nmap, Nessus  

        ### 📖 Guides & Learning  
        - [SANS Top 25](https://www.sans.org/top25-software-errors/)  
        - [ISO 27001](https://www.iso.org/isoiec-27001-information-security.html)
        """)
        st.markdown('</div>', unsafe_allow_html=True)
    # --- Tab 5: URL Safety Checker ---
    with tab5:
        st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
        st.subheader("🧪 Malicious URL Detector")
        url_input = st.text_input("🔗 Enter a URL to check", placeholder="e.g., http://example-login.com")

        if st.button("🚦 Check URL"):
            if not url_input:
                st.error("❗ Please enter a valid URL.")
            elif url_model is None:
                st.error("⚠️ Model not loaded. Please check the .pkl file.")
            else:
                try:
                    features = [extract_url_features(url_input)]
                    prediction = url_model.predict(features)[0]
                    label_map = {0: "BENIGN", 1: "DEFACEMENT", 2: "MALWARE", 3: "PHISHING"}
                    verdict = label_map.get(prediction, "UNKNOWN")

                    if verdict == "BENIGN":
                        st.success("✅ This URL appears to be SAFE.")
                    else:
                        st.error(f"🚨 This URL appears to be **{verdict}**.")
                except Exception as e:
                    st.error(f"❌ Prediction error: {e}")
        st.markdown('</div>', unsafe_allow_html=True)

# ----------------- Run the App -----------------
if __name__ == "__main__":
    main()
