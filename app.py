"""
app.py
------
Professional Streamlit dashboard for the Packet Sniffer project.

How to run:
    Terminal 1 (Admin): python main.py
    Terminal 2:         python -m streamlit run app.py
"""

import html
import os
import time

import pandas as pd
import streamlit as st

from config import ALERTS_LOG_FILE, PACKETS_LOG_FILE
from demo_data import get_demo_alerts, get_demo_packets

# ==========================================
# Page Config (must be the FIRST Streamlit call)
# ==========================================
st.set_page_config(
    page_title="NetSentry | Packet Sniffer Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==========================================
# Custom CSS
# ==========================================
st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #e6edf3; }

    .main-header {
        background: linear-gradient(90deg, #00b4d8, #0077b6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    .sub-header { color: #8b949e; font-size: 1rem; margin-top: -10px; }

    [data-testid="stMetric"] {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 16px 20px;
    }
    [data-testid="stMetricLabel"] { color: #8b949e !important; font-size: 0.85rem; }
    [data-testid="stMetricValue"] { color: #e6edf3 !important; font-size: 1.8rem; font-weight: 700; }

    .section-label {
        color: #58a6ff;
        font-size: 1.05rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        border-bottom: 1px solid #21262d;
        padding-bottom: 6px;
        margin-bottom: 12px;
    }

    /* BUG FIX: escape alert text server-side (see log_alert usage below) */
    .alert-card {
        background: #1c0a0a;
        border-left: 4px solid #f85149;
        border-radius: 8px;
        padding: 10px 16px;
        margin-bottom: 8px;
        font-family: 'Courier New', monospace;
        font-size: 0.82rem;
        color: #f85149;
        word-break: break-all;
    }

    [data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #30363d; }
    [data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; }
</style>
""", unsafe_allow_html=True)


# ==========================================
# Data Loaders  (cached to avoid re-reading disk every render)
# ==========================================
@st.cache_data(ttl=5)
def load_packets() -> pd.DataFrame:
    """Safely read packets.csv. Returns empty DataFrame on any error."""
    if not os.path.exists(PACKETS_LOG_FILE):
        return pd.DataFrame()
    try:
        df = pd.read_csv(PACKETS_LOG_FILE)
        # Guard: make sure the expected columns exist before returning
        required = {"Protocol", "Src_IP", "Dst_IP"}
        if not required.issubset(df.columns):
            return pd.DataFrame()
        return df
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=5)
def load_alerts() -> list:
    """Safely read alerts.txt. Returns empty list on any error."""
    if not os.path.exists(ALERTS_LOG_FILE):
        return []
    try:
        with open(ALERTS_LOG_FILE, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        return lines[::-1]   # newest first
    except Exception:
        return []


# ==========================================
# Sidebar  (rendered FIRST so demo_mode is available before data loading)
# ==========================================
with st.sidebar:
    st.markdown("### 🛡️ NetSentry")
    st.caption("Network Packet Sniffer Dashboard")
    st.markdown("---")

    mode = st.radio("📡 Data Source", ["🟢 Live Mode", "🟡 Demo Mode"], index=0)
    demo_mode = (mode == "🟡 Demo Mode")
    if demo_mode:
        st.info("Showing sample data for presentation purposes.")
    st.markdown("---")

    auto_refresh = st.toggle("Auto Refresh", value=not demo_mode)
    refresh_rate = st.select_slider("Interval (seconds)", [5, 10, 15, 30], value=10)
    st.markdown("---")
    st.markdown("**▶ How to Run**")
    st.code("python main.py", language="bash")
    st.code("python -m streamlit run app.py", language="bash")
    st.markdown("---")

    # Live status indicator (FIX: show live packet count)
    _check_df = load_packets()
    if demo_mode:
        st.warning("📽️ Demo Mode active")
    elif _check_df.empty:
        st.warning("⚠️ No live data yet")
    else:
        st.success(f"✅ {len(_check_df):,} packets logged")


# ==========================================
# Load data
# ==========================================
if demo_mode:
    df      = get_demo_packets()
    alerts  = get_demo_alerts()
else:
    df      = load_packets()
    alerts  = load_alerts()


# ==========================================
# Header
# ==========================================
st.markdown('<p class="main-header">🛡️ NetSentry Dashboard</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="sub-header">Local Network Traffic Monitoring & Suspicious Activity Detection</p>',
    unsafe_allow_html=True,
)

if demo_mode:
    st.warning("📽️ **Demo Mode Active** — Displaying sample data. Switch to 🟢 Live Mode once the sniffer is running.")

st.markdown("<br>", unsafe_allow_html=True)

if df.empty:
    st.warning("No packet data found. Start `python main.py` in an Admin terminal, or switch to **Demo Mode** in the sidebar.")
    st.stop()


# ==========================================
# Metric Cards
# ==========================================
st.markdown('<p class="section-label">📊 Live Traffic Overview</p>', unsafe_allow_html=True)
c1, c2, c3, c4, c5 = st.columns(5)

total_pkts  = len(df)
total_alerts = len(alerts)

# FIX: guard against missing Protocol column before filtering
proto_col = df["Protocol"] if "Protocol" in df.columns else pd.Series(dtype=str)
tcp_count  = int((proto_col == "TCP").sum())
udp_count  = int((proto_col == "UDP").sum())
icmp_count = int((proto_col == "ICMP").sum())

c1.metric("📦 Total Packets",  f"{total_pkts:,}")
c2.metric("🚨 Alerts Raised",  f"{total_alerts:,}")
c3.metric("🔵 TCP",            f"{tcp_count:,}")
c4.metric("🟠 UDP",            f"{udp_count:,}")
c5.metric("🟡 ICMP",           f"{icmp_count:,}")
st.markdown("<br>", unsafe_allow_html=True)


# ==========================================
# Protocol Distribution + Top Source IPs
# ==========================================
st.markdown('<p class="section-label">📡 Protocol Distribution & Top Talkers</p>', unsafe_allow_html=True)
col1, col2 = st.columns(2)

with col1:
    # FIX: use explicit column name to be pandas-version-safe
    proto_counts = proto_col.value_counts().reset_index()
    proto_counts.columns = ["Protocol", "Count"]
    st.bar_chart(proto_counts.set_index("Protocol"), color="#00b4d8", use_container_width=True)

with col2:
    top_src = df["Src_IP"].dropna().value_counts().head(8).reset_index()
    top_src.columns = ["Source IP", "Packets"]
    st.dataframe(top_src, use_container_width=True, hide_index=True, height=280)

st.markdown("<br>", unsafe_allow_html=True)


# ==========================================
# Top Destination IPs + Top Ports
# ==========================================
st.markdown('<p class="section-label">🎯 Network Endpoints & Services</p>', unsafe_allow_html=True)
col3, col4 = st.columns(2)

with col3:
    top_dst = df["Dst_IP"].dropna().value_counts().head(8).reset_index()
    top_dst.columns = ["Destination IP", "Packets"]
    st.dataframe(top_dst, use_container_width=True, hide_index=True)

with col4:
    if "Dst_Port" in df.columns:
        ports_df = df.dropna(subset=["Dst_Port"]).copy()
        ports_df["Dst_Port"] = ports_df["Dst_Port"].astype(int)
        top_ports = ports_df["Dst_Port"].value_counts().head(8).reset_index()
        top_ports.columns = ["Port", "Hits"]
        st.dataframe(top_ports, use_container_width=True, hide_index=True)
    else:
        st.info("No port data available.")

st.markdown("<br>", unsafe_allow_html=True)


# ==========================================
# Recent Captured Packets Table
# ==========================================
st.markdown('<p class="section-label">📋 Recent Captured Packets</p>', unsafe_allow_html=True)
n = st.slider("Rows to display", 10, 200, 50, step=10, label_visibility="collapsed")
recent_df = df.tail(n).iloc[::-1].reset_index(drop=True)
st.dataframe(recent_df, use_container_width=True, height=350)
st.markdown("<br>", unsafe_allow_html=True)


# ==========================================
# Security Alerts Feed
# ==========================================
st.markdown('<p class="section-label">🚨 Security Alerts Feed</p>', unsafe_allow_html=True)

if not alerts:
    st.success("✅ No suspicious alerts detected. Network traffic looks normal.")
else:
    for alert in alerts[:12]:
        # FIX: escape HTML special chars to prevent rendering issues
        safe_alert = html.escape(alert)
        st.markdown(f'<div class="alert-card">⚠️ {safe_alert}</div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ==========================================
# Detection Type Breakdown
# ==========================================
st.markdown('<p class="section-label">🔍 Detection Type Breakdown</p>', unsafe_allow_html=True)

if alerts:
    alert_types = []
    for line in alerts:
        try:
            alert_types.append(line.split("ALERT: ")[1].split(" from ")[0])
        except (IndexError, AttributeError):
            pass  # skip malformed lines silently

    if alert_types:
        det_df = pd.Series(alert_types).value_counts().reset_index()
        det_df.columns = ["Alert Type", "Count"]
        ca, cb = st.columns([1, 1.5])
        with ca:
            st.dataframe(det_df, use_container_width=True, hide_index=True)
        with cb:
            st.bar_chart(det_df.set_index("Alert Type"), color="#f85149")
    else:
        # FIX: show a useful message when parsing succeeded but no types extracted
        st.info("Could not parse alert types from the alerts file.")
else:
    st.info("No alerts generated yet.")


# ==========================================
# Footer
# ==========================================
st.markdown("---")
st.caption(
    f"📁 Packets: `{PACKETS_LOG_FILE}`  |  "
    f"🚨 Alerts: `{ALERTS_LOG_FILE}`  |  "
    f"Auto-refresh: {'ON (' + str(refresh_rate) + 's)' if auto_refresh else 'OFF'}"
)

# FIX: auto-refresh runs LAST so full page renders before sleeping
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
