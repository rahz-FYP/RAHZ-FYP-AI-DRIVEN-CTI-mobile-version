import streamlit as st
import pandas as pd
import plotly.express as px
import re
import base64


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
    </style>
    """
    st.markdown(page_bg_img, unsafe_allow_html=True)
# Function to Read Attack Statistics
def read_attack_stats(file_path):
    stats = {
        "Total Attacks": 0,
        "SQL Injection": 0,
        "XSS": 0,
        "Command Injection": 0,
        "LFI/RFI": 0,
        "RCE": 0,
        "Buffer Overflow": 0
    }

    with open(file_path, "r") as file:
        for line in file:
            if "Total number of attacks detected" in line:
                stats["Total Attacks"] = int(line.split(":")[-1].strip())
            elif "SQL Injection" in line:
                stats["SQL Injection"] = int(line.split(":")[-1].strip())
            elif "XSS" in line:
                stats["XSS"] = int(line.split(":")[-1].strip())
            elif "Command Injection" in line:
                stats["Command Injection"] = int(line.split(":")[-1].strip())
            elif "Path Traversal and LFI/RFI" in line:
                stats["LFI/RFI"] = int(line.split(":")[-1].strip())
            elif "RCE" in line:
                stats["RCE"] = int(line.split(":")[-1].strip())
            elif "Buffer Overflow" in line:
                stats["Buffer Overflow"] = int(line.split(":")[-1].strip())

    return stats


# Function to Read Protocol Statistics for Graph 1
def read_protocol_stats(file_path):
    protocol_counts = {}

    with open(file_path, "r") as file:
        for line in file:
            # Match lines with "frames: <number>" and extract protocol & frame count
            match = re.match(r"(\S+)\s+frames:(\d+)", line.strip())
            if match:
                protocol, frames = match.groups()
                protocol_counts[protocol] = int(frames)

    return protocol_counts


# Function to Read POST vs GET Requests for Graph 2
def read_request_counts(file_path):
    requests = {"POST": 0, "GET": 0}

    with open(file_path, "r") as file:
        for line in file:
            if "Post_requests" in line:
                requests["POST"] = int(line.split("=")[-1].strip())
            elif "Get_requests" in line:
                requests["GET"] = int(line.split("=")[-1].strip())

    return requests


# Function to Read Signature-Based Analysis Results
def read_signature_based_results(file_path):
    results = []
    with open(file_path, "r") as file:
        lines = file.readlines()

    formatted_results = []
    current_result = ""

    for line in lines:
        if line.startswith('Potential'):
            if current_result:
                formatted_results.append(current_result.strip())
            current_result = line.strip()
        else:
            current_result += " " + line.strip()

    if current_result:
        formatted_results.append(current_result.strip())

    return formatted_results


# Function to Color Code the Results
def color_code_result(result):
    if "XSS" in result:
        return f"<div style='color: pink;'>{result}</div>"
    elif "SQL Injection" in result:
        return f"<div style='color: red;'>{result}</div>"
    elif "Command Injection" in result:
        return f"<div style='color: green;'>{result}</div>"
    elif "LFI" in result or "RFI" in result:
        return f"<div style='color: orange;'>{result}</div>"
    elif "RCE" in result:
        return f"<div style='color: purple;'>{result}</div>"
    elif "Buffer Overflow" in result:
        return f"<div style='color: yellow;'>{result}</div>"
    else:
        return f"<div>{result}</div>"

# Function to Read Detected Protocols for Graph 3
def read_detected_protocols(file_path):
    protocols = {}

    with open(file_path, "r") as file:
        for line in file:
            match = re.match(r"(\S+)\s+packets:\s+(\d+)", line.strip())
            if match:
                protocol, packets = match.groups()
                protocols[protocol] = int(packets)

    return protocols

# Function to Read Protocol Safety for Graph 4
def read_protocol_safety(file_path):
    safety_protocols = {}

    with open(file_path, "r") as file:
        for line in file:
            match = re.match(r"(\S+)\s+packets:\s+(\d+)", line.strip())
            if match:
                protocol, packets = match.groups()
                safety_protocols[protocol] = int(packets)

    return safety_protocols

# File Paths
ATTACK_STATS_FILE = "attack_stats.txt"
PROTOCOL_STATS_FILE = "protocol_stats.log"
REQUESTS_FILE = "post_get_count.txt"
TRAFFIC_IMAGE_FILE = "img1.jpg.jpeg"
SIGNATURE_RESULTS_FILE = "attack_results.txt"
PROTOCOL_DETECTED_FILE = "protocols_detected.txt"
PROTOCOL_SAFETY_FILE = "protocol_safety.txt"

# Load Data
attack_stats = read_attack_stats(ATTACK_STATS_FILE)
protocol_stats = read_protocol_stats(PROTOCOL_STATS_FILE)
request_counts = read_request_counts(REQUESTS_FILE)
signature_results = read_signature_based_results(SIGNATURE_RESULTS_FILE)
detected_protocols = read_detected_protocols(PROTOCOL_DETECTED_FILE)
protocol_safety = read_protocol_safety(PROTOCOL_SAFETY_FILE)

# Streamlit UI
def cyber_dashboard_tab():

    attack_stats = read_attack_stats(ATTACK_STATS_FILE)
    protocol_stats = read_protocol_stats(PROTOCOL_STATS_FILE)
    request_counts = read_request_counts(REQUESTS_FILE)
    signature_results = read_signature_based_results(SIGNATURE_RESULTS_FILE)
    detected_protocols = read_detected_protocols(PROTOCOL_DETECTED_FILE)
    protocol_safety = read_protocol_safety(PROTOCOL_SAFETY_FILE)

    #st.set_page_config(layout="wide", page_title="Cyber Vigilant Dashboard", page_icon="🛡️")
    # Set Background Image
    background_image = load_image("7.jpg")
    set_background(background_image)

    # Main Title
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    st.title("📧 Network Security Analysis results")
    st.subheader("🔍 Cyber Vigilant Network Security")
    tab1, tab2 = st.tabs([
        "**📩 CTI Dashboard**",
        "**📜 Signature-Based Analysis Results**"
    ])

    with tab1:
        st.markdown("<h2 style='color: white;'>Web Detected Attacks</h2>", unsafe_allow_html=True)

        # Display Attack Statistics in Colored Boxes (same as before)
        cols = st.columns(7)
        colors = ["#0040ff", "#b30000", "#e377c2", "#008000", "#e68a00", "#800080", "#cccc00"]
        labels = ["Total Attacks", "SQL Injection", "XSS", "Command Injection", "LFI/RFI", "RCE", "Buffer Overflow"]
        for col, label, color in zip(cols, labels, colors):
            col.markdown(
                f"<div style='background-color:{color}; padding:10px; text-align:center; border-radius:5px; font-size:18px; color:white;'>"
                f"{label}<br><b>{attack_stats[label]}</b></div>", unsafe_allow_html=True)

        st.markdown("---")

        # Graphs Section

        st.markdown("<h2 style='color: white;'>Traffic Analysis</h2>", unsafe_allow_html=True)

        # Graph 1 - Protocol Statistics
        st.markdown("<h3 style='color: yellow;'>Protocol Hierarchy</h3>", unsafe_allow_html=True)
        df_protocol = pd.DataFrame(list(protocol_stats.items()), columns=["Protocol", "Frames"])
        fig_bar = px.bar(df_protocol, x="Protocol", y="Frames", color="Protocol", title="Protocol Statistics")
        st.plotly_chart(fig_bar, use_container_width=True)
        st.markdown("---")

        col2, col3, col4 = st.columns(3)

        # Graph 2 - POST vs GET Requests (Donut Chart)
        with col2:
            st.markdown("<h3 style='color: yellow;'>POST vs GET Requests</h3>", unsafe_allow_html=True)
            df_requests = pd.DataFrame(list(request_counts.items()), columns=["Request Type", "Count"])
            fig_donut = px.pie(df_requests, names="Request Type", values="Count", title="POST vs GET Requests", hole=0.7)
            st.plotly_chart(fig_donut, use_container_width=True)

        # Graph 3 - Detected Protocols (Doughnut Chart)
        with col3:
            st.markdown("<h3 style='color: yellow;'>Detected Protocols</h3>", unsafe_allow_html=True)
            df_detected_protocols = pd.DataFrame(list(detected_protocols.items()), columns=["Protocol", "Packets"])
            fig_donut_detected = px.pie(df_detected_protocols, names="Protocol", values="Packets", title="Detected Protocols", hole=0.7)
            st.plotly_chart(fig_donut_detected, use_container_width=True)

        # Graph 4 - Protocol Safety (Doughnut Chart)
        with col4:
            st.markdown("<h3 style='color: yellow;'>Protocol Safety</h3>", unsafe_allow_html=True)
            df_protocol_safety = pd.DataFrame(list(protocol_safety.items()), columns=["Protocol", "Packets"])
            fig_donut_safety = px.pie(df_protocol_safety, names="Protocol", values="Packets", title="Protocol Safety", hole=0.7)
            st.plotly_chart(fig_donut_safety, use_container_width=True)

        st.markdown("---")

        # Traffic IP Locations
        st.markdown("<h2 style='color: white;'>Traffic IP Locations</h2>", unsafe_allow_html=True)
        st.image(TRAFFIC_IMAGE_FILE, use_container_width=True)

        st.markdown("---")

    with tab2:
        # Signature Based Analysis Results Section
        st.markdown("""
        <div style="background-color: rgba(0, 0, 0, 0.7); padding: 20px; border-radius: 10px;">
            <h2 style="text-align: center; color: white;">Signature-Based Analysis Results</h2>
        </div>
        """, unsafe_allow_html=True)

        # Display Results with Color Coding inside a styled div
        for result in signature_results:
            colored_result = color_code_result(result)
            st.markdown(f"""
            <div style="background-color: rgba(0, 0, 0, 0.7); padding: 10px; border-radius: 5px; margin-bottom: 5px;">
                {colored_result}
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")


    # Refresh Button (same as before)
    if st.button("🔄 Refresh Data"):
        attack_stats = read_attack_stats(ATTACK_STATS_FILE)
        protocol_stats = read_protocol_stats(PROTOCOL_STATS_FILE)
        request_counts = read_request_counts(REQUESTS_FILE)
        signature_results = read_signature_based_results(SIGNATURE_RESULTS_FILE)
        detected_protocols = read_detected_protocols("protocols_detected.txt")
        protocol_safety = read_protocol_safety("protocol_safety.txt")
        st.rerun()

