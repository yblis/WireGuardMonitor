import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from database import Database
from log_parser import WireGuardLogParser
from utils import create_connection_timeline, create_traffic_graph

# Initialize database and parser
db = Database()
parser = WireGuardLogParser()

# Page configuration
st.set_page_config(
    page_title="WireGuard Monitor",
    page_icon="🔒",
    layout="wide"
)

# Title and description
st.title("🔒 WireGuard Monitor")
st.markdown("""
    Monitor your WireGuard VPN connections in real-time. View connection history,
    active connections, and network statistics.
""")

# Sidebar filters
st.sidebar.header("Filters")
time_filter = st.sidebar.selectbox(
    "Time Range",
    ["Last Hour", "Last 24 Hours", "Last 7 Days", "All Time"]
)

# Get data based on filters
now = datetime.now()
if time_filter == "Last Hour":
    start_time = now - timedelta(hours=1)
elif time_filter == "Last 24 Hours":
    start_time = now - timedelta(days=1)
elif time_filter == "Last 7 Days":
    start_time = now - timedelta(days=7)
else:
    start_time = datetime.min

# Get active connections
active_connections = db.get_active_connections()

# Display active connections
st.header("Active Connections")
if active_connections:
    active_df = pd.DataFrame([
        {
            'Peer ID': conn.peer_id,
            'IP Address': conn.ip_address,
            'Connected Since': conn.timestamp,
            'Duration': str(now - conn.timestamp).split('.')[0]
        }
        for conn in active_connections
    ])
    st.dataframe(active_df)
else:
    st.info("No active connections")

# Connection timeline
st.header("Connection History")
connections = db.get_connections()
if connections:
    timeline = create_connection_timeline(connections)
    st.plotly_chart(timeline, use_container_width=True)
else:
    st.info("No connection history available")

# Traffic statistics
st.header("Network Traffic")
traffic_graph = create_traffic_graph(connections)
st.plotly_chart(traffic_graph, use_container_width=True)

# Connection logs table
st.header("Detailed Connection Logs")
if connections:
    logs_df = pd.DataFrame([
        {
            'Timestamp': conn.timestamp,
            'Peer ID': conn.peer_id,
            'Event': conn.event_type.capitalize(),
            'IP Address': conn.ip_address,
            'Bytes Sent': conn.bytes_sent,
            'Bytes Received': conn.bytes_received
        }
        for conn in connections
    ])
    
    # Add search/filter functionality
    search = st.text_input("Search by Peer ID or IP Address")
    if search:
        logs_df = logs_df[
            logs_df['Peer ID'].str.contains(search, case=False) |
            logs_df['IP Address'].str.contains(search, case=False)
        ]
    
    st.dataframe(logs_df)
else:
    st.info("No connection logs available")

# Auto-refresh every 30 seconds
st.empty()
st.markdown("*Dashboard auto-refreshes every 30 seconds*")
st.experimental_rerun()
