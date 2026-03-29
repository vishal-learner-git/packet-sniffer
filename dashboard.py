"""
dashboard.py
------------
A simple Streamlit web dashboard to visualize the packet sniffer logs.
Reads from logs/packets.csv and logs/alerts.txt.

To run this dashboard:
    streamlit run dashboard.py
"""

import streamlit as st
import pandas as pd
import os
from collections import Counter
from netsentry.utils.config import PACKETS_LOG_FILE, ALERTS_LOG_FILE

# Set basic page configuration
st.set_page_config(page_title="Packet Sniffer Dashboard", layout="wide")

st.title("🛡️ Network Packet Sniffer Dashboard")
st.markdown("Live monitoring metrics and cybersecurity alerts parsed from your network traffic logs.")

# ==========================================
# Data Loading Functions
# ==========================================

@st.cache_data(ttl=5) # Cache data for 5 seconds to prevent constant disk reads
def load_packet_data():
    if not os.path.exists(PACKETS_LOG_FILE):
        return pd.DataFrame() # Return empty if no logs exist yet
    
    try:
        df = pd.read_csv(PACKETS_LOG_FILE)
        return df
    except Exception as e:
        st.error(f"Error reading packets.csv: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=5)
def load_alerts():
    if not os.path.exists(ALERTS_LOG_FILE):
        return []
        
    try:
        with open(ALERTS_LOG_FILE, "r") as f:
            lines = f.readlines()
        # Reverse to show newest alerts first
        return lines[::-1] 
    except Exception as e:
        st.error(f"Error reading alerts.txt: {e}")
        return []

# ==========================================
# Dashboard Layout & Visualization
# ==========================================

df_packets = load_packet_data()
alerts = load_alerts()

if df_packets.empty:
    st.warning("No packet data found. Is the sniffer running and logging to packets.csv?")
else:
    # 1. Top Level Metrics (Row 1)
    col1, col2, col3 = st.columns(3)
    
    total_packets = len(df_packets)
    total_alerts = len(alerts)
    
    # TCP Count
    tcp_count = len(df_packets[df_packets['Protocol'] == 'TCP'])
    udp_count = len(df_packets[df_packets['Protocol'] == 'UDP'])
    
    col1.metric("Total Packets Captured", f"{total_packets:,}")
    col2.metric("Suspicious Alerts", f"{total_alerts:,}", delta_color="inverse")
    col3.metric("TCP / UDP Packets", f"{tcp_count:,} / {udp_count:,}")
    
    st.markdown("---")
    
    # 2. Protocol Distribution & Top Talkers (Row 2)
    row2_col1, row2_col2 = st.columns(2)
    
    with row2_col1:
        st.subheader("Protocol Distribution")
        # Simple bar chart of protocols
        protocol_counts = df_packets['Protocol'].value_counts()
        st.bar_chart(protocol_counts)
        
    with row2_col2:
        st.subheader("Top Source IPs (Top Talkers)")
        top_srcs = df_packets['Src_IP'].value_counts().head(5)
        st.table(top_srcs.reset_index(name='Packet Count').rename(columns={'Src_IP': 'IP Address'}))

    st.markdown("---")
    
    # 3. More granular details (Row 3)
    row3_col1, row3_col2 = st.columns(2)
    
    with row3_col1:
        st.subheader("Top Destination IPs")
        top_dsts = df_packets['Dst_IP'].value_counts().head(5)
        st.table(top_dsts.reset_index(name='Packet Count').rename(columns={'Dst_IP': 'IP Address'}))
        
    with row3_col2:
        st.subheader("Top Destination Ports")
        ports_df = df_packets.dropna(subset=['Dst_Port']).copy()  # .copy() prevents pandas warning
        ports_df['Dst_Port'] = ports_df['Dst_Port'].astype(int)
        top_ports = ports_df['Dst_Port'].value_counts().head(5)
        st.table(top_ports.reset_index(name='Hit Count').rename(columns={'Dst_Port': 'Port'}))

# ==========================================
# Recent Alerts Feed
# ==========================================
st.markdown("---")
st.subheader("🚨 Recent Security Alerts")

if not alerts:
    st.success("No suspicious activity detected yet. Your network looks clean!")
else:
    # Display the 10 most recent alerts in a clean code block
    recent_alerts = "\n".join(alerts[:10])
    st.code(recent_alerts, language="log")
