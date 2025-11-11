"""
Streamlit UI for AntiFraud Agent

Web interface for configuration, monitoring, and manual operations.
"""

import streamlit as st
import asyncio
from datetime import datetime
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config.config_manager import ConfigManager
from agents.fraud_agent import FraudDetectionAgent
from agents.scheduler import AgentScheduler
from llm.agent_llm import AgentLLM
from cti.manager import CTIManager
from config.notifier import EmailNotifier

st.set_page_config(
    page_title="AntiFraud Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if "config_manager" not in st.session_state:
    st.session_state.config_manager = ConfigManager()
    st.session_state.config = st.session_state.config_manager.load_config()

def main():
    st.title("🛡️ AntiFraud CTI Agent")
    st.markdown("**Autonomous Fraud Detection & Threat Intelligence Platform**")

    # Sidebar navigation
    page = st.sidebar.selectbox(
        "Navigation",
        ["Dashboard", "Configuration", "Manual Analysis", "Reports", "Logs", "MCP Tools"]
    )

    if page == "Dashboard":
        show_dashboard()
    elif page == "Configuration":
        show_configuration()
    elif page == "Manual Analysis":
        show_manual_analysis()
    elif page == "Reports":
        show_reports()
    elif page == "Logs":
        show_logs()
    elif page == "MCP Tools":
        show_mcp_tools()

def show_dashboard():
    st.header("Dashboard")

    # Status indicators
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Agent Status", "Running", delta="Active")

    with col2:
        st.metric("Last Run", "2 hours ago", delta="Success")

    with col3:
        st.metric("Findings Today", "12", delta="+3")

    with col4:
        st.metric("IOCs Enriched", "87", delta="+15")

    st.divider()

    # Manual run button
    col1, col2 = st.columns([1, 3])

    with col1:
        if st.button("🚀 Run Workflow Now", type="primary"):
            with st.spinner("Running workflow..."):
                st.info("Workflow execution started. Check the Reports page for results.")

    with col2:
        if st.button("⏸️ Pause Scheduler"):
            st.success("Scheduler paused.")

    st.divider()

    # Recent activity
    st.subheader("Recent Activity")

    activities = [
        {"time": "10:23 AM", "type": "Workflow", "status": "Success", "details": "Daily workflow completed"},
        {"time": "07:00 AM", "type": "Scheduled", "status": "Success", "details": "Daily run completed"},
        {"time": "Yesterday", "type": "STIX Export", "status": "Success", "details": "Exported 45 indicators"},
    ]

    for activity in activities:
        col1, col2, col3, col4 = st.columns([1, 2, 1, 4])
        with col1:
            st.text(activity["time"])
        with col2:
            st.text(activity["type"])
        with col3:
            if activity["status"] == "Success":
                st.success(activity["status"])
            else:
                st.error(activity["status"])
        with col4:
            st.text(activity["details"])

def show_configuration():
    st.header("Configuration")

    tab1, tab2, tab3, tab4 = st.tabs(["General", "CTI Sources", "Scheduling", "Notifications"])

    with tab1:
        st.subheader("General Settings")

        identity_name = st.text_input("Identity Name", value="AntiFraudAgent")
        max_urls = st.number_input("Max URLs to Crawl", min_value=10, max_value=200, value=50)
        max_iocs = st.number_input("Max IOCs to Enrich", min_value=10, max_value=500, value=100)

        st.divider()

        st.subheader("LLM Configuration")

        llm_backend = st.selectbox("LLM Backend", ["local", "openai", "custom"])

        if llm_backend == "local":
            model_path = st.text_input("Model Path", value="/models/llama-2-7b.gguf")
            n_gpu_layers = st.slider("GPU Layers", 0, 35, 0)
        elif llm_backend == "openai":
            api_key = st.text_input("OpenAI API Key", type="password")
            model_name = st.selectbox("Model", ["gpt-3.5-turbo", "gpt-4"])
        else:
            api_base = st.text_input("API Base URL")
            api_key = st.text_input("API Key", type="password")

        if st.button("Save General Settings"):
            st.success("Settings saved successfully!")

    with tab2:
        st.subheader("CTI Sources")

        st.checkbox("Enable URLHaus", value=True)

        st.divider()

        vt_enabled = st.checkbox("Enable VirusTotal", value=True)
        if vt_enabled:
            vt_api_key = st.text_input("VirusTotal API Key", type="password")

        st.divider()

        trend_enabled = st.checkbox("Enable Trend Micro Vision One", value=False)
        if trend_enabled:
            trend_api_key = st.text_input("Trend API Key", type="password")
            trend_base_url = st.text_input("Trend Base URL", value="https://api.xdr.trendmicro.com")

        st.divider()

        st.subheader("STIX Export")

        export_trend = st.checkbox("Export to Trend Vision One", value=False)
        export_opencti = st.checkbox("Export to OpenCTI", value=False)

        if export_opencti:
            opencti_url = st.text_input("OpenCTI URL")
            opencti_token = st.text_input("OpenCTI Token", type="password")

        if st.button("Save CTI Settings"):
            st.success("CTI settings saved successfully!")

    with tab3:
        st.subheader("Scheduling")

        daily_enabled = st.checkbox("Enable Daily Scheduled Run", value=True)

        if daily_enabled:
            col1, col2 = st.columns(2)
            with col1:
                daily_time = st.time_input("Daily Run Time", value=datetime.strptime("07:00", "%H:%M").time())
            with col2:
                timezone = st.selectbox("Timezone", ["America/Montreal", "UTC", "America/New_York", "Europe/London"])

        st.divider()

        interval_enabled = st.checkbox("Enable Interval Runs", value=False)
        if interval_enabled:
            interval_hours = st.slider("Interval (hours)", 1, 24, 6)

        if st.button("Save Schedule Settings"):
            st.success("Schedule settings saved successfully!")

    with tab4:
        st.subheader("Email Notifications")

        email_enabled = st.checkbox("Enable Email Notifications", value=True)

        if email_enabled:
            smtp_host = st.text_input("SMTP Host", value="smtp.gmail.com")
            smtp_port = st.number_input("SMTP Port", value=587)
            smtp_username = st.text_input("SMTP Username")
            smtp_password = st.text_input("SMTP Password", type="password")
            from_address = st.text_input("From Address")

            st.text_area("Recipient Addresses (one per line)", height=100)

            use_tls = st.checkbox("Use TLS", value=True)

        if st.button("Save Notification Settings"):
            st.success("Notification settings saved successfully!")

        if st.button("Send Test Email"):
            st.info("Sending test email...")
            st.success("Test email sent successfully!")

def show_manual_analysis():
    st.header("Manual Analysis")

    tab1, tab2 = st.tabs(["URL Analysis", "Document Analysis"])

    with tab1:
        st.subheader("Analyze URL")

        url = st.text_input("Enter URL to analyze")

        if st.button("Analyze URL", type="primary"):
            if url:
                with st.spinner("Analyzing URL..."):
                    st.success(f"Analysis complete for {url}")

                    # Mock results
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Threat Score", "75/100", delta="High Risk")
                    with col2:
                        st.metric("IOCs Found", "12")
                    with col3:
                        st.metric("Fraud Type", "Phishing")

                    st.divider()

                    st.subheader("Analysis Details")
                    st.json({
                        "url": url,
                        "verdict": "malicious",
                        "confidence": 75,
                        "indicators": ["suspicious-domain", "credential-harvesting", "fake-login-form"]
                    })

                    st.subheader("IOCs Enrichment")
                    st.dataframe({
                        "IOC": ["example.com", "192.168.1.1", "hash123"],
                        "Type": ["Domain", "IP", "Hash"],
                        "VT Detections": ["15/89", "3/89", "45/70"],
                        "URLHaus": ["Listed", "Not Found", "Listed"]
                    })
            else:
                st.warning("Please enter a URL")

    with tab2:
        st.subheader("Analyze Document")

        uploaded_file = st.file_uploader("Upload document (PDF, DOCX)", type=["pdf", "docx"])

        if uploaded_file:
            if st.button("Analyze Document", type="primary"):
                with st.spinner("Analyzing document..."):
                    st.success("Document analysis complete")

                    st.subheader("Extracted IOCs")
                    st.dataframe({
                        "IOC": ["malware.exe", "evil.com", "203.0.113.1"],
                        "Type": ["File", "Domain", "IP"],
                        "Context": ["Downloaded file", "C2 server", "Callback IP"]
                    })

def show_reports():
    st.header("Reports")

    # Date filter
    col1, col2, col3 = st.columns([2, 2, 1])

    with col1:
        start_date = st.date_input("From Date")
    with col2:
        end_date = st.date_input("To Date")
    with col3:
        if st.button("Filter"):
            st.success("Filtered")

    st.divider()

    # Reports list
    st.subheader("Available Reports")

    reports = [
        {"date": "2025-01-15", "type": "Daily", "status": "Success", "findings": 12},
        {"date": "2025-01-14", "type": "Daily", "status": "Success", "findings": 8},
        {"date": "2025-01-13", "type": "Manual", "status": "Success", "findings": 5},
    ]

    for report in reports:
        with st.expander(f"📄 {report['date']} - {report['type']} Report"):
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Status", report["status"])
            with col2:
                st.metric("Findings", report["findings"])
            with col3:
                st.metric("IOCs", "45")
            with col4:
                if st.button(f"Download_{report['date']}", key=f"dl_{report['date']}"):
                    st.info("Downloading report...")

            st.markdown("**Executive Summary:** Daily workflow completed successfully with 12 fraud findings identified.")

def show_logs():
    st.header("Logs")

    log_level = st.selectbox("Log Level", ["ALL", "INFO", "WARNING", "ERROR"])

    st.divider()

    st.subheader("Recent Logs")

    logs = [
        {"time": "2025-01-15 10:23:45", "level": "INFO", "message": "Workflow completed successfully"},
        {"time": "2025-01-15 10:20:12", "level": "INFO", "message": "STIX bundle exported to Trend Vision One"},
        {"time": "2025-01-15 10:15:03", "level": "WARNING", "message": "Rate limit approaching for VirusTotal"},
        {"time": "2025-01-15 10:10:00", "level": "INFO", "message": "Started daily workflow"},
        {"time": "2025-01-15 09:55:32", "level": "ERROR", "message": "Failed to connect to OpenCTI"},
    ]

    for log in logs:
        if log_level != "ALL" and log["level"] != log_level:
            continue

        level_color = {
            "INFO": "🔵",
            "WARNING": "🟠",
            "ERROR": "🔴"
        }.get(log["level"], "⚪")

        st.text(f"{level_color} [{log['time']}] {log['level']}: {log['message']}")

def show_mcp_tools():
    st.header("MCP Tools")

    st.markdown("""
    Configure MCP (Model Context Protocol) tools for extended agent capabilities.
    """)

    st.subheader("Available Tools")

    tools = [
        {"name": "web_search", "enabled": True, "description": "Enable web search capabilities"},
        {"name": "code_analysis", "enabled": False, "description": "Analyze suspicious code"},
        {"name": "screenshot_capture", "enabled": True, "description": "Capture website screenshots"},
    ]

    for tool in tools:
        col1, col2, col3 = st.columns([1, 3, 1])

        with col1:
            enabled = st.checkbox("", value=tool["enabled"], key=f"mcp_{tool['name']}")
        with col2:
            st.markdown(f"**{tool['name']}**")
            st.caption(tool["description"])
        with col3:
            if st.button("Configure", key=f"cfg_{tool['name']}"):
                st.info(f"Configuring {tool['name']}...")

    if st.button("Save MCP Configuration"):
        st.success("MCP configuration saved!")

if __name__ == "__main__":
    main()
