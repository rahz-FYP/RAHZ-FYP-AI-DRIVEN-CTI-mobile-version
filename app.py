import streamlit as st
import asyncio

# Set Page Configurations
st.set_page_config(layout="wide", page_title="Cyber Vigilant Suite", page_icon="🛡️")

# Custom CSS to adjust sidebar width, color, and title styling
st.markdown("""
    <style>
        [data-testid="stSidebar"] {
            width: 200px !important;
            background-color: #003366 !important;
        }
        [data-testid="stSidebarNav"] > ul {
            font-size: 14px !important;
        }

        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500&display=swap');

        .sidebar-title {
            text-align: center;
            font-size: 22px;
            font-family: 'Audiowide', sans-serif;
            color: #FF3131;
            text-shadow: 0px 0px 10px #FF3131, 0px 0px 20px #FF0000;
            letter-spacing: 1.5px;
        }
    </style>
""", unsafe_allow_html=True)

# Sidebar Navigation with Futuristic Title
st.sidebar.markdown("""
    <h2 class='sidebar-title'>🔍 Cyber Vigilant Suite</h2>
""", unsafe_allow_html=True)

selected_module = st.sidebar.radio("Select Module:", [
    "Analysis Dashboard", "Email Security", "AI Anomaly Detection", "Real-Time Monitoring & DPI"
])

# Module Selection
if selected_module == "Analysis Dashboard":
    from Final_2_Dashboard import cyber_dashboard_tab

    cyber_dashboard_tab()

elif selected_module == "Email Security":
    from Final_1_Email import email_phishing_tab

    email_phishing_tab()

elif selected_module == "AI Anomaly Detection":
    from Final_3_AI import ai_anomaly_detection_tab

    ai_anomaly_detection_tab()

elif selected_module == "Real-Time Monitoring & DPI":
    from Project4 import run_proxy

    st.warning("🚀 Real-Time Monitoring & DPI is running...")
    asyncio.run(run_proxy())

# This script acts as the main launcher integrating all four modules
