#!/usr/bin/env python3
"""
Federated Threat Monitor -- Streamlit Dashboard
Reads alerts from SQLite and displays them in real time.
"""

import sqlite3
import os
import pandas as pd
import streamlit as st
from datetime import datetime

# -- Configuration ------------------------------------------------
DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "../central-manager/alerts.db"
)

# -- Page Config --------------------------------------------------
st.set_page_config(
    page_title="Federated Threat Monitor",
    layout="wide"
)

# -- Header -------------------------------------------------------
st.title("Federated Threat Monitor")
st.caption("Real-time DDoS anomaly detection dashboard -- Z-score statistical baseline profiling")
st.divider()

# -- Load Data ----------------------------------------------------
def load_alerts():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY timestamp DESC",
            conn
        )
        conn.close()
        return df
    except Exception as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame()

def load_nodes():
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM nodes", conn)
        conn.close()
        return df
    except Exception as e:
        return pd.DataFrame()

# -- Load data ----------------------------------------------------
df = load_alerts()
nodes_df = load_nodes()

# -- Metrics Row --------------------------------------------------
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="Total Alerts",
        value=len(df)
    )
with col2:
    st.metric(
        label="Active Nodes",
        value=len(nodes_df)
    )
with col3:
    if not df.empty:
        st.metric(
            label="Highest Z-Score",
            value=f"{df['z_score'].max():.2f}"
        )
    else:
        st.metric(label="Highest Z-Score", value="--")
with col4:
    if not df.empty:
        st.metric(
            label="Last Alert",
            value=df['timestamp'].iloc[0]
        )
    else:
        st.metric(label="Last Alert", value="--")

st.divider()

# -- Alert Table --------------------------------------------------
st.subheader("Alert Log")

if df.empty:
    st.info("No alerts recorded yet. Waiting for edge agents to detect anomalies.")
else:
    def highlight_zscore(val):
        if isinstance(val, float) and val > 5:
            return "background-color: #ff4444; color: white"
        elif isinstance(val, float) and val > 3:
            return "background-color: #ffaa00; color: black"
        return ""

    styled_df = df.style.map(highlight_zscore, subset=["z_score"])
    st.dataframe(styled_df, use_container_width=True)

st.divider()

# -- Charts -------------------------------------------------------
if not df.empty:
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Z-Score Over Time")
        chart_df = df[["timestamp", "z_score"]].copy()
        chart_df = chart_df.sort_values("timestamp")
        chart_df = chart_df.rename(
            columns={"timestamp": "index"}
        ).set_index("index")
        st.line_chart(chart_df)

    with col_right:
        st.subheader("Alerts Per Node")
        node_counts = df["node_id"].value_counts().reset_index()
        node_counts.columns = ["node_id", "alert_count"]
        st.bar_chart(node_counts.set_index("node_id"))

    st.subheader("Resource Usage")
    res_col1, res_col2 = st.columns(2)

    with res_col1:
        st.subheader("CPU Usage Percent Per Alert")
        cpu_df = df[["timestamp", "cpu_percent"]].copy()
        cpu_df = cpu_df.sort_values("timestamp").set_index("timestamp")
        st.line_chart(cpu_df)

    with res_col2:
        st.subheader("RAM Usage MB Per Alert")
        ram_df = df[["timestamp", "ram_mb"]].copy()
        ram_df = ram_df.sort_values("timestamp").set_index("timestamp")
        st.line_chart(ram_df)

st.divider()

# -- Auto-refresh -------------------------------------------------
st.caption(
    f"Last refreshed: {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC"
)
st.button("Refresh Now")
