import whois
from urllib.parse import urlparse
import httpx
import pickle as pk
import pandas as pd
import extractorFunctions as ef

# Optional: List of well-known safe domains (for tuning or whitelisting)
TRUSTED_DOMAINS = ["google.com", "github.com", "openai.com"]

# Set to True for console debug output
DEBUG = False

def featureExtraction(url):
    features = []

    # 🔧 Ensure URL has a scheme for proper parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # 🔧 Robust domain parsing
    parsed = urlparse(url)
    netloc = parsed.netloc.strip().lower() if parsed.netloc else parsed.path.strip().lower()

    # ---- Address Bar Based Features ----
    features.append(ef.getLength(url))              # URL_Length
    features.append(ef.getDepth(url))               # URL_Depth
    features.append(ef.tinyURL(url))                # TinyURL
    features.append(ef.prefixSuffix(url))           # Prefix/Suffix
    features.append(ef.no_of_dots(url))             # No_Of_Dots
    features.append(ef.sensitive_word(url))         # Sensitive_Words

    # ---- Domain-Based Features ----
    dns = 0
    try:
        domain_name = whois.whois(netloc)
    except:
        dns = 1
        domain_name = None

    features.append(1 if dns == 1 else ef.domainAge(domain_name))  # Domain_Age
    features.append(1 if dns == 1 else ef.domainEnd(domain_name))  # Domain_End

    # ---- HTML/JS Based Features ----
    dom = []
    try:
        response = httpx.get(url, timeout=5)
    except:
        response = ""

    dom.append(ef.iframe(response))                 # IFrame
    dom.append(ef.mouseOver(response))              # Mouse_Over
    dom.append(ef.forwarding(response))             # Web_Forwards

    # ---- Combined Features ----
    features.append(
        ef.has_unicode(url) +
        ef.haveAtSign(url) +
        ef.havingIP(url)
    )                                               # Have_Symbol

    # ---- PCA Feature ----
    with open('model/pca_model.pkl', 'rb') as file:
        pca = pk.load(file)

    dom_pd = pd.DataFrame([dom], columns=['iFrame', 'Web_Forwards', 'Mouse_Over'])
    pca_component = pca.transform(dom_pd)[0][0]
    features.append(pca_component)                 # domain_att

    # ---- DataFrame Assembly ----
    feature_names = [
        'URL_Length', 'URL_Depth', 'TinyURL', 'Prefix/Suffix', 'No_Of_Dots', 'Sensitive_Words',
        'Domain_Age', 'Domain_End', 'Have_Symbol', 'domain_att'
    ]
    row = pd.DataFrame([features], columns=feature_names)

    # 🔍 Optional Debugging Output
    if DEBUG:
        print("🔎 Feature Extraction Output:")
        print(row.to_dict())

    return row
