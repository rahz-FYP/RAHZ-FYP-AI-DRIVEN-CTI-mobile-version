import streamlit as st
import subprocess
import time
import numpy as np
import plotly.graph_objects as go
import base64
import plotly.express as px
import pandas as pd


# Function to run Start_Project.py
def start_capture():
    subprocess.Popen(['python', 'Start_Project.py'])


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
        background-color: rgba(0, 0, 0, 0.7);
        color: white;
        padding: 10px;
        border-radius: 8px;
        font-size: 16px;
        margin-bottom: 10px;
    }}

    .warning-box {{
        background-color: rgba(255, 0, 0, 0.7);
        color: white;
        padding: 10px;
        border-radius: 8px;
        font-size: 16px;
        margin-bottom: 10px;
    }}

    .success-box {{
        background-color: rgba(0, 128, 0, 0.7);
        color: white;
        padding: 10px;
        border-radius: 8px;
        font-size: 16px;
        margin-bottom: 10px;
    }}
    </style>
    """
    st.markdown(page_bg_img, unsafe_allow_html=True)

# Function to animate graph
def animate_graph(status, duration, placeholder):
    x_vals = np.linspace(0, 10, 100)
    fig = go.Figure()
    for i in range(duration * 10):
        y_vals = np.sin(x_vals + i / 5.0) * 30 + 100
        y_vals += np.sin(x_vals * 2 + i / 10.0) * 10
        y_vals += np.random.normal(0, 5, size=len(x_vals))
        y_vals = np.clip(y_vals, 70, 130)

        fig.data = []
        fig.add_trace(go.Scatter(
            x=x_vals, y=y_vals, mode='lines',
            line=dict(width=3, color='deepskyblue', shape='spline', dash='solid'),
            fill='tozeroy', fillcolor='rgba(0,191,255,0.2)'
        ))

        fig.add_trace(go.Scatter(
            x=[5], y=[40],
            text=[f" {status.replace('_', ' ').capitalize()}..."],
            mode="text",
            textfont=dict(size=20, color="white"),
            showlegend=False
        ))

        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Traffic Volume",
            template="plotly_dark",
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor="black",
            font=dict(color="white"),
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showline=True, linecolor='gray'),
            yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)', zeroline=False, showline=True,
                       linecolor='gray'),
        )

        placeholder.plotly_chart(fig, use_container_width=True)
        time.sleep(0.1)

def parse_results(file_path="Model_Results.txt"):
    try:
        with open(file_path, "r") as file:
            content = file.read()

        # Extract predictions
        match = content.split("Predictions: [")
        if len(match) < 2:
            st.error("Predictions not found in file.")
            return None

        # Convert extracted text into a list of predictions
        predictions = match[1].split("]")[0].replace("'", "").split()

        # Count occurrences of each label
        total_count = len(predictions)
        label_counts = pd.Series(predictions).value_counts().to_dict()

        # Separate benign and anomaly counts
        benign_count = label_counts.get("BENIGN", 0)
        anomaly_count = total_count - benign_count

        # Compute percentages
        benign_percentage = (benign_count / total_count) * 100 if total_count > 0 else 0
        anomaly_percentage = (anomaly_count / total_count) * 100 if total_count > 0 else 0

        # Get anomaly breakdown (excluding BENIGN)
        anomaly_breakdown = {k: (v / total_count) * 100 for k, v in label_counts.items() if k != "BENIGN"}

        return {
            "benign_count": benign_count,
            "anomaly_count": anomaly_count,
            "total_count": total_count,
            "benign_percentage": benign_percentage,
            "anomaly_percentage": anomaly_percentage,
            "anomaly_breakdown": anomaly_breakdown,
        }

    except Exception as e:
        st.error(f"Error reading file: {e}")
        return None

def parse_risk_stats(file_path="risk_stats.txt"):
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()

        if not lines:
            return None

        # Extract header
        header = lines[0].strip()

        # Extract the main risk summary
        risk_summary = lines[1].strip()

        # Extract individual risk details
        risk_details = []
        for line in lines[2:]:
            if line.strip() and ":" not in line and "NOTE" not in line:
                risk_details.append(line.strip())

        return {
            "header": header,
            "summary": risk_summary,
            "details": risk_details,
        }

    except FileNotFoundError:
        return None
# AI Anomaly Detection Tab
def ai_anomaly_detection_tab():
    background_image = load_image("7.jpg")
    set_background(background_image)
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    st.title("📊 Network Traffic Anomaly Detection")

    placeholder = st.empty()  # Define placeholder before calling animate_graph

    if st.button("Start Capture"):
        st.session_state.status = "capturing"
        start_capture()
        st.rerun()

    if 'status' not in st.session_state:
        st.session_state.status = "idle"

    if st.session_state.status == "capturing":
        animate_graph("🚀 Capturing Traffic", 10, placeholder)
        st.session_state.status = "converting"
        st.rerun()

    elif st.session_state.status == "converting":
        animate_graph("📄 Converting to CSV", 10, placeholder)
        st.session_state.status = "analyzing"
        st.rerun()

    elif st.session_state.status == "analyzing":
        animate_graph("📊 Analyzing Traffic", 5, placeholder)
        st.session_state.status = "detecting"
        st.rerun()

    elif st.session_state.status == "detecting":
        animate_graph("🔍 Detecting Anomalies", 10, placeholder)
        st.session_state.status = "idle"
        st.rerun()

    if st.session_state.status == "idle":
        if st.button("Show Traffic Report"):
            try:
                with open("Traffic Report.txt", "r") as file:
                    report_lines = file.readlines()

                if report_lines:
                    # Styled heading box for Traffic Report
                    heading_box = f"""
                    <div class='result-box' style='text-align:center; padding:10px; border-radius:8px;'>
                        <h2 style='color: yellow; margin: 0;'>🚦 {report_lines[0].strip()}</h2>
                    </div>
                    """

                    formatted_report = "<div class='result-box'><ul>"

                    for line in report_lines[1:]:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            formatted_report += f"<li><b>{key.strip()}:</b> <span style='color: yellow;'>{value.strip()}</span></li>"
                        else:
                            formatted_report += f"<li>{line.strip()}</li>"

                    formatted_report += "</ul></div>"

                    # Display the heading box first, then the report
                    st.markdown(heading_box, unsafe_allow_html=True)
                    st.markdown(formatted_report, unsafe_allow_html=True)
                else:
                    st.markdown("<div class='warning-box'>⚠️ Traffic Report is empty.</div>", unsafe_allow_html=True)

            except FileNotFoundError:
                st.markdown("<div class='warning-box'>⚠️ Traffic Report not found.</div>", unsafe_allow_html=True)

    if st.button("Show Anomaly Detection Report"):
        results = parse_results()

        if results:
            # Create DataFrame for Plotly
            df_results = pd.DataFrame(
                {
                    "Type": ["Benign", "Anomaly"],
                    "Count": [results["benign_count"], results["anomaly_count"]],
                }
            )

            # Plotly Doughnut Chart
            fig_donut = px.pie(
                df_results,
                names="Type",
                values="Count",
                title="Benign vs Anomaly",
                hole=0.7,  # Makes it a doughnut
                color="Type",
                color_discrete_map={"Benign": "#FFD700", "Anomaly": "#FFFFFF"},
            )

            # Wrap anomaly report inside a styled box
            anomaly_report = f"""
            <div class='result-box'>
                <h2 style='color:yellow; text-align:center;'>📊 Anomaly Detection Report</h2>
                <ul>
                    <li><b>Benign Traffic:</b> <span style='color:yellow;'>{results["benign_percentage"]:.2f}%</span> ({results["benign_count"]} instances)</li>
                    <li><b>Anomalous Traffic:</b> <span style='color:yellow;'>{results["anomaly_percentage"]:.2f}%</span> ({results["anomaly_count"]} instances)</li>
                </ul>
            </div>
            """

            # Display report inside a box
            st.markdown(anomaly_report, unsafe_allow_html=True)

            # Display the Doughnut Chart
            st.plotly_chart(fig_donut, use_container_width=True)

            # Show anomaly breakdown
            if results["anomaly_breakdown"]:
                breakdown_report = "<div class='result-box'><h3 style='color:white;'>🚨 Attack Breakdown:</h3><ul>"
                for attack, percentage in results["anomaly_breakdown"].items():
                    breakdown_report += f"<li><b>{attack}:</b> <span style='color:yellow;'>{percentage:.2f}%</span></li>"
                breakdown_report += "</ul></div>"
                st.markdown(breakdown_report, unsafe_allow_html=True)
        else:
            st.markdown("<div class='warning-box'>No anomalies detected or failed to fetch results.</div>",
                        unsafe_allow_html=True)

    if st.button("Show Network Risk Statistics Report"):
        risk_stats = parse_risk_stats()

        if risk_stats:
            # Format the risk report
            risk_report = f"""
            <div class='result-box'>
                <h2 style='color:yellow; text-align:center;'>📊 Network Risk Statistics Report</h2>
                <p><b style='color:white;'>{risk_stats["header"]}</b></p>
                <p style='color:yellow;'>{risk_stats["summary"]}</p>
                <ul>
            """

            for detail in risk_stats["details"]:
                risk_report += f"<li style='color:white;'>{detail}</li>"

            risk_report += "</ul></div>"

            # Display the report inside a styled box
            st.markdown(risk_report, unsafe_allow_html=True)

        else:
            st.markdown("<div class='warning-box'>⚠️ Risk Statistics Report not found or empty.</div>",
                        unsafe_allow_html=True)


# Run module only if executed directly
if __name__ == "__main__":
    ai_anomaly_detection_tab()
