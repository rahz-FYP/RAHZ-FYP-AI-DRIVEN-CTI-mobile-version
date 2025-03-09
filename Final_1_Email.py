import streamlit as st
import imaplib
import email
from email.header import decode_header
import re
import requests
import time
import base64

# VT API Key setup
API_KEY = "e159bd3230294963cb4e9bab76d45bb4abba4b5951b4ff1a6a2ed825d25bb1fb"
SUBMIT_URL = "https://www.virustotal.com/api/v3/urls"
HEADERS = {"x-apikey": API_KEY}

# Filtered Engines
engines_of_interest = [
    "Lionic", "BitDefender", "Cluster25", "CyRadar",
    "Fortinet", "G-Data", "Kaspersky", "Netcraft", "Sophos", "Trustwave",
    "VIPRE", "Webroot"
]


# URL Extraction
def extract_url(body):
    url_pattern = r'(https?://\S+)'
    match = re.search(url_pattern, body)
    return match.group(0) if match else None


# URL Analysis
def analyze_url(url_to_query):
    data = {"url": url_to_query}
    submit_response = requests.post(SUBMIT_URL, data=data, headers=HEADERS)

    if submit_response.status_code == 200:
        url_id = base64.urlsafe_b64encode(url_to_query.encode()).decode().strip("=")
        time.sleep(30)  # Wait for VirusTotal analysis
        fetch_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        fetch_response = requests.get(fetch_url, headers=HEADERS)

        if fetch_response.status_code == 200:
            vt_results = fetch_response.json()
            scan_data = vt_results.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            filtered_results = {
                engine: scan_data[engine]["result"]
                for engine in engines_of_interest if engine in scan_data
            }
            return filtered_results if filtered_results else {"message": "No relevant results"}

    return {"message": "VirusTotal analysis failed"}


# Automatic Email Retrieval
def fetch_emails(username, password, num_to_display):
    imap_server = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
    imap_server.login(username, password)
    imap_server.select("INBOX")
    status, messages = imap_server.search(None, "ALL")
    email_ids = messages[0].split()[-num_to_display:]
    results = []

    for idx, email_id in enumerate(email_ids, start=1):
        status, msg_data = imap_server.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                from_ = msg.get("From")
                body = ""

                if msg.is_multipart():
                    for part in msg.walk():
                        try:
                            body = part.get_payload(decode=True).decode()
                        except:
                            pass
                else:
                    body = msg.get_payload(decode=True).decode()

                check_url = extract_url(body)
                url_analysis = analyze_url(check_url) if check_url else {"message": "No URL detected"}
                results.append(
                    {"Number": idx, "Subject": subject, "From": from_, "URL": check_url, "Analysis": url_analysis,
                     "Headers": msg})

    imap_server.logout()
    return results

def load_image(image_path):
    with open(image_path, "rb") as img_file:
        encoded = base64.b64encode(img_file.read()).decode()
    return encoded

# Set Background Image
def set_background(image_file):
    page_bg_img = f"""
    <style>
    .stApp {{
        background: url(data:image/jpeg;base64,{image_file});
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }}

    .result-box {{
        background-color: rgba(0, 0, 0, 0.7); /* Dark background with transparency */
        color: white; 
        padding: 10px;
        border-radius: 8px;
        font-size: 16px;
        margin-bottom: 10px;
    }}

    .warning-box {{
        background-color: rgba(255, 0, 0, 0.7); /* Red background for warnings */
        color: white;
        padding: 10px;
        border-radius: 8px;
        font-size: 16px;
        margin-bottom: 10px;
    }}

    .success-box {{
        background-color: rgba(0, 128, 0, 0.7); /* Green background for success */
        color: white;
        padding: 10px;
        border-radius: 8px;
        font-size: 16px;
        margin-bottom: 10px;
    }}
    </style>
    """
    st.markdown(page_bg_img, unsafe_allow_html=True)

# Parse Email Headers
def parse_email_header(header_input):
    try:
        headers = email.message_from_string(header_input)
        parsed_headers = {key: value for key, value in headers.items()}
        return parsed_headers
    except Exception as e:
        return {"Error": f"Failed to parse headers: {str(e)}"}


# Analyze Email Headers
def analyze_email_header(headers):
    parsed_headers = parse_email_header(headers)
    results = {}

    if 'From' in parsed_headers and 'Reply-To' in parsed_headers and parsed_headers['From'] != parsed_headers[
        'Reply-To']:
        results['From-Reply-To Mismatch'] = "🚨 **Warning:** 'From' and 'Reply-To' addresses do not match! 🔴"
    else:
        results['From-Reply-To Mismatch'] = "✅ **'From' and 'Reply-To' addresses match.** 🟢"

    spf_result = parsed_headers.get('Received-SPF', 'pass')
    dkim_result = parsed_headers.get('Authentication-Results', 'dkim=pass')
    dmarc_result = parsed_headers.get('Authentication-Results', 'dmarc=pass')

    results['SPF'] = "🚨 **Warning:** SPF check failed! 🔴" if 'fail' in spf_result.lower() else "✅ **SPF check passed.** 🟢"
    results['DKIM'] = "🚨 **Warning:** DKIM check failed! 🔴" if 'fail' in dkim_result.lower() else "✅ **DKIM check passed.** 🟢"
    results['DMARC'] = "🚨 **Warning:** DMARC check failed! 🔴" if 'fail' in dmarc_result.lower() else "✅ **DMARC check passed.** 🟢"

    return results

def analyze_email_header_1(header_input):
    headers = parse_email_header(header_input)
    st.subheader("Parsed Headers:")
    for key, value in headers.items():
        st.write(f"**{key}:** {value}")

    st.subheader("Header Analysis Results:")
    if 'From' in headers and 'Reply-To' in headers and headers['From'] != headers['Reply-To']:
        st.markdown("🚨 **Warning:** 'From' and 'Reply-To' addresses do not match! 🔴", unsafe_allow_html=True)
    else:
        st.markdown("✅ **'From' and 'Reply-To' addresses match.** 🟢", unsafe_allow_html=True)

    spf_result = headers.get('Received-SPF', 'pass')
    dkim_result = headers.get('Authentication-Results', 'dkim=pass')
    dmarc_result = headers.get('Authentication-Results', 'dmarc=pass')

    if 'fail' in spf_result.lower():
        st.markdown("🚨 **Warning:** SPF check failed! 🔴", unsafe_allow_html=True)
    else:
        st.markdown("✅ **SPF check passed.** 🟢", unsafe_allow_html=True)

    if 'fail' in dkim_result.lower():
        st.markdown("🚨 **Warning:** DKIM check failed! 🔴", unsafe_allow_html=True)
    else:
        st.markdown("✅ **DKIM check passed.** 🟢", unsafe_allow_html=True)

    if 'fail' in dmarc_result.lower():
        st.markdown("🚨 **Warning:** DMARC check failed! 🔴", unsafe_allow_html=True)
    else:
        st.markdown("✅ **DMARC check passed.** 🟢", unsafe_allow_html=True)

# UI
def email_phishing_tab():
    #st.set_page_config(layout="wide", page_title="Email Phishing Module", page_icon="📧")
    # Set Background Image
    background_image = load_image("7.jpg")
    set_background(background_image)

    # Main Title
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    st.title("📧 Email Phishing Detection System")
    st.subheader("🔍 Cyber Vigilant Email Security")
    tab1, tab2, tab3 = st.tabs([
        "**📩 Automated Email Analysis**",
        "**📜 Manual Header Analysis**",
        "**🔗 Manual Content-based Detection**"
    ])

    with tab1:
        st.subheader("📩 Automated Email Retrieval & Phishing Analysis")

        # Input Fields
        col1, col2 = st.columns(2)
        with col1:
            username = st.text_input("📧 Yahoo Email:", type="default")
        with col2:
            password = st.text_input("🔒 Yahoo Password:", type="password")

        num_emails = st.slider("📊 Number of Emails to Scan:", min_value=1, max_value=10, value=5)

        if st.button("🚀 Start Email Analysis"):
            results = fetch_emails(username, password, num_emails)
            if results:
                st.markdown('<div class="success-box">✅ Email scan completed!</div>', unsafe_allow_html=True)
                for res in results:
                    with st.expander(f"📨 **Email {res['Number']} - {res['Subject']}**"):
                        st.markdown(f"**📧 From:** `{res['From']}`")
                        st.markdown(f'<div class="result-box"><b>🔗 Extracted URL:</b> {res["URL"] if res["URL"] else "No URL found"}</div>', unsafe_allow_html=True)

                        st.markdown("### 🛡 Content-Based Scan Results")
                        for engine, verdict in res["Analysis"].items():
                            color = "✅" if verdict == "clean" else "🚨" if verdict in ["malicious", "phishing"] else "⚠️"
                            st.markdown(f'<div class="result-box"><b>{engine}:</b> {color} {verdict}</div>', unsafe_allow_html=True)

                        # 🛡 Header-Based Security Analysis
                        st.markdown("### 🛡 Header-Based Scan Results")
                        header_results = analyze_email_header(res["Headers"])
                        for key, value in header_results.items():
                            st.markdown(
                                f"""
                                <div style="
                                    padding: 10px; 
                                    margin: 5px 0; 
                                    background-color: rgba(0, 0, 0, 0.7); 
                                    border-left: 5px solid #FFD700;
                                    color: white;
                                    font-size: 16px;
                                    border-radius: 5px;
                                ">
                                    <b>{key}:</b> {value}
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                        st.markdown("---")

            else:
                st.markdown('<div class="warning-box">⚠️ No emails found or analysis failed.</div>', unsafe_allow_html=True)

    with tab2:
        st.subheader("📩 Manual Header-Based Detection")
        header_input = st.text_area("✉️ Paste Email Headers Here:")

        if st.button("🔍 Analyze Headers"):
            headers = parse_email_header(header_input)

            # Collapsible Section for Parsed Headers
            with st.expander("📜 View Parsed Headers"):
                for key, value in headers.items():
                    st.markdown(f"**{key}:** `{value}`")

            st.markdown("<h3 style='color: #FFD700;'>🛡 Header Analysis Results</h3>", unsafe_allow_html=True)

            # Check From-Reply-To Mismatch
            if 'From' in headers and 'Reply-To' in headers and headers['From'] != headers['Reply-To']:
                from_reply_result = "🚨 **Warning:** 'From' and 'Reply-To' addresses do not match! 🔴"
            else:
                from_reply_result = "✅ **'From' and 'Reply-To' addresses match.** 🟢"

            # SPF, DKIM, and DMARC Checks
            spf_result = headers.get('Received-SPF', 'pass')
            dkim_result = headers.get('Authentication-Results', 'dkim=pass')
            dmarc_result = headers.get('Authentication-Results', 'dmarc=pass')

            spf_status = "🚨 **Warning:** SPF check failed! 🔴" if 'fail' in spf_result.lower() else "✅ **SPF check passed.** 🟢"
            dkim_status = "🚨 **Warning:** DKIM check failed! 🔴" if 'fail' in dkim_result.lower() else "✅ **DKIM check passed.** 🟢"
            dmarc_status = "🚨 **Warning:** DMARC check failed! 🔴" if 'fail' in dmarc_result.lower() else "✅ **DMARC check passed.** 🟢"

            # Stylish Result Boxes
            for check_name, result in {
                "From-Reply-To Check": from_reply_result,
                "SPF Check": spf_status,
                "DKIM Check": dkim_status,
                "DMARC Check": dmarc_status
            }.items():
                st.markdown(f"""
                <div style="
                    padding: 10px; 
                    margin: 5px 0; 
                    background-color: rgba(0, 0, 0, 0.7); 
                    border-left: 5px solid #FFD700;
                    color: white;
                    font-size: 16px;
                    border-radius: 5px;
                ">
                    <b>{check_name}:</b> {result}
                </div>
                """, unsafe_allow_html=True)

            st.markdown("---")

    with tab3:
        st.subheader("🔍 URL Analysis")
        url_input = st.text_input("🔗 Enter URL for Analysis:")

        if st.button("Analyze URL"):
            result = analyze_url(url_input)

            st.markdown("<h3 style='color: #FFD700;'>🛡 URL Analysis Results</h3>", unsafe_allow_html=True)

            if "message" in result:
                st.warning(result["message"])
            else:
                for engine, verdict in result.items():
                    color = "#00C853" if verdict == "clean" else "#FF3D00" if verdict in ["malicious",
                                                                                          "phishing"] else "#FFD600"
                    emoji = "✅" if verdict == "clean" else "🚨" if verdict in ["malicious", "phishing"] else "⚠️"

                    st.markdown(f"""
                    <div style="
                        padding: 10px;
                        margin: 5px 0;
                        background-color: rgba(0, 0, 0, 0.7);
                        border-left: 5px solid {color};
                        color: white;
                        font-size: 16px;
                        border-radius: 5px;
                    ">
                        <b>{engine}:</b> {emoji} {verdict}
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("---")


email_phishing_tab()