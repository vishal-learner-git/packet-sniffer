import os
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from demo_data import get_demo_alerts, get_demo_packets
from netsentry.utils.config import ALERTS_LOG_FILE, PACKETS_LOG_FILE


st.set_page_config(
    page_title="NetSentry | Sentinel-01",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


st.markdown(
    """
    <style>
    .stApp {
        background:
            radial-gradient(circle at top left, rgba(10, 133, 255, 0.10), transparent 24%),
            radial-gradient(circle at top right, rgba(255, 83, 112, 0.08), transparent 20%),
            linear-gradient(180deg, #07111b 0%, #0b1622 45%, #0f1822 100%);
        color: #e8eef5;
    }

    [data-testid="stHeader"] {
        background: rgba(7, 17, 27, 0.72);
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #08111a 0%, #0d1824 100%);
        border-right: 1px solid rgba(130, 155, 180, 0.12);
    }

    .block-container {
        max-width: 1380px;
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    .hero-card {
        background: linear-gradient(135deg, rgba(11, 27, 39, 0.96), rgba(14, 34, 48, 0.88));
        border: 1px solid rgba(95, 140, 179, 0.16);
        border-radius: 22px;
        padding: 1.4rem 1.5rem;
        box-shadow: 0 18px 50px rgba(0, 0, 0, 0.18);
        margin-bottom: 1.1rem;
    }

    .hero-title {
        font-size: 2.3rem;
        font-weight: 800;
        letter-spacing: -0.03em;
        color: #f4f8fb;
        margin-bottom: 0.25rem;
    }

    .hero-subtitle {
        color: #97a9bc;
        font-size: 0.98rem;
        margin-bottom: 0;
    }

    .status-pill {
        display: inline-block;
        padding: 0.4rem 0.8rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        border: 1px solid rgba(255, 255, 255, 0.09);
    }

    .status-safe {
        background: rgba(25, 135, 84, 0.16);
        color: #8ef0b7;
    }

    .status-moderate {
        background: rgba(255, 193, 7, 0.16);
        color: #ffd970;
    }

    .status-critical {
        background: rgba(220, 53, 69, 0.16);
        color: #ff9aa8;
    }

    .section-heading {
        font-size: 0.82rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        color: #8fa5bb;
        margin: 0.2rem 0 0.8rem 0;
    }

    .panel-caption {
        color: #89a0b5;
        font-size: 0.9rem;
        margin-bottom: 0.2rem;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(180deg, rgba(10, 24, 35, 0.95), rgba(13, 29, 41, 0.88));
        border: 1px solid rgba(104, 140, 170, 0.14);
        border-radius: 18px;
        padding: 1rem 1.05rem;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02);
    }

    [data-testid="stMetricLabel"] {
        color: #95a9bd !important;
        font-size: 0.84rem !important;
        font-weight: 600 !important;
    }

    [data-testid="stMetricValue"] {
        color: #f3f7fb !important;
        font-size: 1.8rem !important;
        font-weight: 800 !important;
    }

    [data-testid="stMetricDelta"] {
        font-weight: 600 !important;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(104, 140, 170, 0.12);
        border-radius: 16px;
        overflow: hidden;
    }

    .alert-card {
        border-radius: 16px;
        padding: 0.95rem 1rem;
        margin-bottom: 0.75rem;
        border: 1px solid rgba(255, 255, 255, 0.06);
        background: linear-gradient(180deg, rgba(12, 22, 32, 0.96), rgba(9, 18, 27, 0.92));
    }

    .alert-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
        margin-bottom: 0.45rem;
    }

    .alert-type {
        color: #f3f7fb;
        font-weight: 700;
        letter-spacing: 0.04em;
    }

    .alert-meta {
        color: #8ea4b9;
        font-size: 0.83rem;
    }

    .sev-badge {
        display: inline-block;
        padding: 0.28rem 0.58rem;
        border-radius: 999px;
        font-size: 0.7rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    .sev-critical {
        background: rgba(239, 68, 68, 0.18);
        color: #ff9a9a;
    }

    .sev-high {
        background: rgba(249, 115, 22, 0.18);
        color: #ffc285;
    }

    .sev-medium {
        background: rgba(59, 130, 246, 0.18);
        color: #9fcbff;
    }

    .sev-low {
        background: rgba(34, 197, 94, 0.18);
        color: #9ff0b8;
    }

    .footer-note {
        color: #7f95aa;
        font-size: 0.86rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


SEVERITY_COLOR_MAP = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#38bdf8",
    "Low": "#22c55e",
}


def normalize_packet_columns(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    rename_map = {
        "Timestamp": "timestamp",
        "Protocol": "protocol",
        "Src_IP": "src_ip",
        "Dst_IP": "dst_ip",
        "Src_Port": "src_port",
        "Dst_Port": "dst_port",
        "Size": "size",
        "TCP_Flags": "tcp_flags",
        "MAC_Src": "mac_src",
        "MAC_Dst": "mac_dst",
        "ICMP_Type": "icmp_type",
        "ICMP_Code": "icmp_code",
    }
    return df.rename(columns=rename_map)


@st.cache_data(ttl=5)
def load_live_packets() -> pd.DataFrame:
    if not os.path.exists(PACKETS_LOG_FILE):
        return pd.DataFrame()

    try:
        df = pd.read_csv(PACKETS_LOG_FILE)
        return normalize_packet_columns(df)
    except Exception:
        return pd.DataFrame()


def parse_alert_line(line: str):
    if "ALERT:" not in line:
        return None

    try:
        ts_part, rest = line.split("] ALERT: ", 1)
        timestamp = ts_part.strip()[1:]
        head, reason_part = rest.split(" | Reason: ", 1)
        reason = reason_part.strip()

        severity = "Medium"
        category = "General"
        source_ip = "Unknown"

        if "] [" in head:
            alert_type, metadata = head.split(" [", 1)
            severity, tail = metadata.split("] [", 1)
            category, source_ip = tail.split("] from ", 1)
        elif " [" in head and "] from " in head:
            alert_type, metadata = head.split(" [", 1)
            severity, source_ip = metadata.split("] from ", 1)
        else:
            alert_type, source_ip = head.split(" from ", 1)

        return {
            "timestamp": timestamp,
            "type": alert_type.strip(),
            "severity": severity.strip(),
            "category": category.strip(),
            "source_ip": source_ip.strip(),
            "message": reason,
        }
    except Exception:
        return None


@st.cache_data(ttl=5)
def load_live_alerts() -> pd.DataFrame:
    if not os.path.exists(ALERTS_LOG_FILE):
        return pd.DataFrame()

    rows = []
    try:
        with open(ALERTS_LOG_FILE, "r", encoding="utf-8") as alert_file:
            for line in alert_file:
                parsed = parse_alert_line(line.strip())
                if parsed:
                    rows.append(parsed)
    except Exception:
        return pd.DataFrame()

    return pd.DataFrame(rows)


@st.cache_data(ttl=10)
def load_demo_alerts() -> pd.DataFrame:
    rows = []
    for line in get_demo_alerts():
        parsed = parse_alert_line(line)
        if parsed:
            rows.append(parsed)
    return pd.DataFrame(rows)


def get_dashboard_data(demo_mode: bool):
    if demo_mode:
        packets = normalize_packet_columns(get_demo_packets())
        alerts = load_demo_alerts()
    else:
        packets = load_live_packets()
        alerts = load_live_alerts()
    return packets, alerts


def compute_posture(alerts_df: pd.DataFrame):
    if alerts_df.empty:
        return "SAFE", 0, "status-safe", "No suspicious activity detected in the current window."

    critical = int((alerts_df["severity"] == "Critical").sum())
    high = int((alerts_df["severity"] == "High").sum())
    total = len(alerts_df)
    score = (critical * 30) + (high * 15) + (total * 4)

    if score >= 90:
        return "CRITICAL", score, "status-critical", "Multiple high-impact events require immediate review."
    if score >= 35:
        return "MODERATE", score, "status-moderate", "Suspicious activity detected and worth analyst attention."
    return "SAFE", score, "status-safe", "Observed traffic appears stable with limited security concerns."


def style_packets_table(df: pd.DataFrame):
    style_df = df.copy()
    if "size" in style_df.columns:
        style_df["size"] = style_df["size"].map(lambda value: f"{int(value):,}" if pd.notna(value) else "")

    styled = style_df.style
    if "protocol" in style_df.columns:
        styled = styled.map(
            lambda value: (
                "color: #7dd3fc; font-weight: 700;" if value == "TCP"
                else "color: #86efac; font-weight: 700;" if value == "UDP"
                else "color: #f9a8d4; font-weight: 700;" if value == "ICMP"
                else "color: #cbd5e1;"
            ),
            subset=["protocol"],
        )

    if "tcp_flags" in style_df.columns:
        styled = styled.map(
            lambda value: "color: #fda4af; font-weight: 700;" if str(value).strip() not in {"", "nan", "None", "-"} else "color: #94a3b8;",
            subset=["tcp_flags"],
        )

    return styled


def style_alerts_table(df: pd.DataFrame):
    styled = df.style
    if "severity" in df.columns:
        styled = styled.map(
            lambda value: (
                "background-color: rgba(239, 68, 68, 0.22); color: #ffe2e2; font-weight: 800;" if value == "Critical"
                else "background-color: rgba(249, 115, 22, 0.20); color: #ffe1c2; font-weight: 800;" if value == "High"
                else "background-color: rgba(56, 189, 248, 0.18); color: #d8f4ff; font-weight: 800;" if value == "Medium"
                else "background-color: rgba(34, 197, 94, 0.16); color: #d9ffe7; font-weight: 800;"
            ),
            subset=["severity"],
        )
    return styled


def render_alert_card(alert_row):
    severity = alert_row.get("severity", "Medium")
    severity_class = f"sev-{severity.lower()}" if severity.lower() in {"critical", "high", "medium", "low"} else "sev-medium"
    st.markdown(
        f"""
        <div class="alert-card">
            <div class="alert-header">
                <div class="alert-type">{alert_row.get("type", "Unknown Threat")}</div>
                <div class="sev-badge {severity_class}">{severity}</div>
            </div>
            <div class="alert-meta">{alert_row.get("timestamp", "")} | {alert_row.get("category", "General")} | Source: {alert_row.get("source_ip", "Unknown")}</div>
            <div class="panel-caption" style="margin-top:0.55rem;">{alert_row.get("message", "")}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_plotly_layout(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#dbe7f3"),
        margin=dict(l=20, r=20, t=40, b=20),
        legend_title_text="",
    )
    return fig


with st.sidebar:
    st.markdown("## 🛡️ NetSentry")
    st.caption("Recruiter-friendly network monitoring demo")
    st.markdown("---")

    mode_label = st.radio("Data Source", ["Live Mode", "Demo Mode"], index=0)
    demo_mode = mode_label == "Demo Mode"

    auto_refresh = st.toggle("Auto Refresh", value=not demo_mode)
    refresh_rate = st.select_slider("Refresh Every", options=[5, 10, 15, 30, 60], value=10)
    st.markdown("---")

    st.markdown("#### Controls")
    st.caption("Use Demo Mode for polished screenshots and walkthroughs.")
    st.code("python main.py", language="bash")
    st.code("python -m streamlit run streamlit_app.py", language="bash")


packets_df, alerts_df = get_dashboard_data(demo_mode)

if not packets_df.empty:
    protocol_options = sorted(packets_df["protocol"].dropna().astype(str).unique().tolist()) if "protocol" in packets_df.columns else []
else:
    protocol_options = []

if not alerts_df.empty:
    severity_options = ["Critical", "High", "Medium", "Low"]
    available_severities = [sev for sev in severity_options if sev in alerts_df["severity"].astype(str).unique().tolist()]
else:
    available_severities = []

with st.sidebar:
    st.markdown("---")
    st.markdown("#### Filters")
    selected_protocols = st.multiselect("Protocol", protocol_options, default=protocol_options)
    selected_severities = st.multiselect("Alert Severity", available_severities, default=available_severities)
    st.markdown("---")

    if demo_mode:
        st.info("Demo Mode is active. Data is loaded from realistic sample traffic.")
    elif packets_df.empty:
        st.warning("No live packet data found yet.")
    else:
        st.success(f"Monitoring dataset loaded: {len(packets_df):,} packets")

    st.caption(f"Last refresh snapshot: {datetime.now().strftime('%H:%M:%S')}")


if selected_protocols and not packets_df.empty and "protocol" in packets_df.columns:
    packets_df = packets_df[packets_df["protocol"].isin(selected_protocols)]

if selected_severities and not alerts_df.empty:
    alerts_df = alerts_df[alerts_df["severity"].isin(selected_severities)]


total_packets = len(packets_df)
total_alerts = len(alerts_df)
critical_alerts = int((alerts_df["severity"] == "Critical").sum()) if not alerts_df.empty else 0
high_alerts = int((alerts_df["severity"] == "High").sum()) if not alerts_df.empty else 0
tcp_count = int((packets_df["protocol"] == "TCP").sum()) if "protocol" in packets_df.columns else 0
udp_count = int((packets_df["protocol"] == "UDP").sum()) if "protocol" in packets_df.columns else 0
icmp_count = int((packets_df["protocol"] == "ICMP").sum()) if "protocol" in packets_df.columns else 0
risky_hosts = alerts_df["source_ip"].nunique() if not alerts_df.empty and "source_ip" in alerts_df.columns else 0

posture_label, posture_score, posture_class, posture_caption = compute_posture(alerts_df)


st.markdown(
    f"""
    <div class="hero-card">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:1rem; flex-wrap:wrap;">
            <div>
                <div class="hero-title">Sentinel-01 Streamlit Console</div>
                <p class="hero-subtitle">Local Network Threat Monitor & Packet Intelligence Dashboard built for demos, GitHub, and recruiter walkthroughs.</p>
            </div>
            <div>
                <span class="status-pill {posture_class}">{posture_label}</span>
            </div>
        </div>
        <div class="panel-caption" style="margin-top:0.85rem;">{posture_caption}</div>
    </div>
    """,
    unsafe_allow_html=True,
)


metric_cols = st.columns(5)
metric_cols[0].metric("Packets Analyzed", f"{total_packets:,}", delta="Current view")
metric_cols[1].metric("Alerts Raised", f"{total_alerts:,}", delta=f"{critical_alerts} critical")
metric_cols[2].metric("Risky Hosts", f"{risky_hosts:,}", delta=f"{high_alerts} high severity")
metric_cols[3].metric("TCP / UDP", f"{tcp_count:,} / {udp_count:,}", delta=f"ICMP {icmp_count:,}")
metric_cols[4].metric("Threat Score", posture_label, delta=f"Score {posture_score}")


if packets_df.empty and not demo_mode:
    st.warning("No packet data found. Start `python main.py` for live capture, or switch to Demo Mode for a presentation-ready view.")
    st.stop()


st.markdown('<div class="section-heading">Traffic Overview</div>', unsafe_allow_html=True)
chart_col_1, chart_col_2 = st.columns([1.15, 1])

with chart_col_1:
    with st.container(border=True):
        st.markdown("##### Protocol Distribution")
        st.caption("Quick breakdown of the dominant traffic mix.")
        if not packets_df.empty and "protocol" in packets_df.columns:
            proto_counts = packets_df["protocol"].value_counts().reset_index()
            proto_counts.columns = ["protocol", "count"]
            fig_proto = px.bar(
                proto_counts,
                x="protocol",
                y="count",
                color="protocol",
                color_discrete_map={
                    "TCP": "#38bdf8",
                    "UDP": "#22c55e",
                    "ICMP": "#f472b6",
                    "ARP": "#f59e0b",
                    "OTHER": "#94a3b8",
                },
            )
            fig_proto.update_traces(marker_line_width=0, opacity=0.92)
            fig_proto.update_xaxes(title=None, showgrid=False)
            fig_proto.update_yaxes(title=None, gridcolor="rgba(148, 163, 184, 0.16)")
            st.plotly_chart(build_plotly_layout(fig_proto), use_container_width=True)
        else:
            st.info("No protocol data available.")

with chart_col_2:
    with st.container(border=True):
        st.markdown("##### Top Source Hosts")
        st.caption("Most active hosts in the selected traffic window.")
        if not packets_df.empty and "src_ip" in packets_df.columns:
            top_sources = packets_df["src_ip"].dropna().value_counts().head(8).reset_index()
            top_sources.columns = ["src_ip", "count"]
            fig_sources = px.bar(
                top_sources.sort_values("count"),
                x="count",
                y="src_ip",
                orientation="h",
                color="count",
                color_continuous_scale=["#12324a", "#38bdf8"],
            )
            fig_sources.update_yaxes(title=None)
            fig_sources.update_xaxes(title=None, gridcolor="rgba(148, 163, 184, 0.16)")
            st.plotly_chart(build_plotly_layout(fig_sources), use_container_width=True)
        else:
            st.info("No source IP activity available.")


intel_col_1, intel_col_2 = st.columns([1, 1])

with intel_col_1:
    with st.container(border=True):
        st.markdown("##### Destination Services")
        st.caption("Most frequently targeted ports in the selected view.")
        if not packets_df.empty and "dst_port" in packets_df.columns:
            ports_df = packets_df.dropna(subset=["dst_port"]).copy()
            if not ports_df.empty:
                ports_df["dst_port"] = ports_df["dst_port"].astype(int).astype(str)
                top_ports = ports_df["dst_port"].value_counts().head(8).reset_index()
                top_ports.columns = ["dst_port", "count"]
                fig_ports = px.bar(
                    top_ports,
                    x="dst_port",
                    y="count",
                    color="count",
                    color_continuous_scale=["#173347", "#7dd3fc"],
                )
                fig_ports.update_xaxes(title="Destination Port", type="category")
                fig_ports.update_yaxes(title=None, gridcolor="rgba(148, 163, 184, 0.16)")
                st.plotly_chart(build_plotly_layout(fig_ports), use_container_width=True)
            else:
                st.info("No destination port data available.")
        else:
            st.info("No destination port data available.")

with intel_col_2:
    with st.container(border=True):
        st.markdown("##### Alert Severity Breakdown")
        st.caption("Severity mix for screenshot-friendly risk storytelling.")
        if not alerts_df.empty:
            sev_counts = alerts_df["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0).reset_index()
            sev_counts.columns = ["severity", "count"]
            fig_severity = px.pie(
                sev_counts[sev_counts["count"] > 0],
                names="severity",
                values="count",
                hole=0.62,
                color="severity",
                color_discrete_map=SEVERITY_COLOR_MAP,
            )
            fig_severity.update_traces(textinfo="label+percent", pull=[0.06 if sev == "Critical" else 0 for sev in sev_counts["severity"] if sev_counts.set_index("severity").loc[sev, "count"] > 0])
            st.plotly_chart(build_plotly_layout(fig_severity), use_container_width=True)
        else:
            st.success("No alerts detected in the current selection.")


tab_packets, tab_alerts, tab_summary = st.tabs(["Packet Inspector", "Security Alerts", "Analyst Summary"])

with tab_packets:
    st.markdown("##### Recent Packets")
    st.caption("Readable, screenshot-friendly packet view for demos and interviews.")
    if packets_df.empty:
        st.info("No packet data to inspect.")
    else:
        packet_columns = [col for col in ["timestamp", "protocol", "src_ip", "dst_ip", "src_port", "dst_port", "size", "tcp_flags"] if col in packets_df.columns]
        display_packets = packets_df[packet_columns].tail(80).iloc[::-1].reset_index(drop=True)
        st.dataframe(style_packets_table(display_packets), use_container_width=True, height=420, hide_index=True)

with tab_alerts:
    left_alerts, right_alerts = st.columns([1.15, 1])

    with left_alerts:
        st.markdown("##### Recent Security Incidents")
        if alerts_df.empty:
            st.success("No suspicious alerts in the current view.")
        else:
            recent_alerts = alerts_df.sort_values("timestamp", ascending=False).head(8)
            for _, row in recent_alerts.iterrows():
                render_alert_card(row)

    with right_alerts:
        st.markdown("##### Alert Table")
        if alerts_df.empty:
            st.info("Alert table will appear when suspicious activity is detected.")
        else:
            alert_columns = [col for col in ["timestamp", "severity", "category", "type", "source_ip", "message"] if col in alerts_df.columns]
            display_alerts = alerts_df[alert_columns].sort_values("timestamp", ascending=False).reset_index(drop=True)
            st.dataframe(style_alerts_table(display_alerts), use_container_width=True, height=420, hide_index=True)

with tab_summary:
    summary_left, summary_right = st.columns([1, 1])

    with summary_left:
        with st.container(border=True):
            st.markdown("##### Monitoring Snapshot")
            st.caption("Short analyst summary suitable for GitHub and recruiter walkthroughs.")
            if alerts_df.empty:
                st.success("The selected monitoring window shows normal traffic patterns with no suspicious alerts.")
            else:
                top_category = alerts_df["category"].value_counts().idxmax()
                top_attacker = alerts_df["source_ip"].value_counts().idxmax()
                st.markdown(
                    f"""
                    - The dashboard is currently showing **{total_packets:,} packets** and **{total_alerts:,} security alerts**.
                    - The most common suspicious category is **{top_category}**.
                    - The most active risky host in this filtered view is **{top_attacker}**.
                    - The current system posture is **{posture_label}**, which is useful for quick demo narration.
                    """
                )

    with summary_right:
        with st.container(border=True):
            st.markdown("##### Data Sources")
            st.caption("Operational context for beginner-friendly project explanation.")
            st.markdown(
                f"""
                - Packet log source: `{PACKETS_LOG_FILE}`
                - Alert log source: `{ALERTS_LOG_FILE}`
                - Dashboard mode: `{"Demo Mode" if demo_mode else "Live Mode"}`
                - Auto refresh: `{"On" if auto_refresh else "Off"}` every `{refresh_rate}` seconds
                """
            )


st.markdown("---")
st.markdown(
    f'<div class="footer-note">NetSentry Streamlit console | Mode: {"Demo" if demo_mode else "Live"} | Refreshed at {datetime.now().strftime("%H:%M:%S")}</div>',
    unsafe_allow_html=True,
)

if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()
