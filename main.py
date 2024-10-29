import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from database import Database
from log_parser import WireGuardLogParser
from utils import create_connection_timeline, create_traffic_graph
from security_monitor import SecurityMonitor
from models import AlertRule

# Initialize database, parser and security monitor
db = Database()
parser = WireGuardLogParser()
security_monitor = SecurityMonitor(db)

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

# Sidebar navigation
page = st.sidebar.radio("Navigation", ["Dashboard", "Connections", "Bandwidth", "Alert Rules"])

if page == "Alert Rules":
    st.header("Custom Alert Rules")
    
    # Add new rule form
    with st.expander("Add New Alert Rule"):
        with st.form("new_rule"):
            name = st.text_input("Rule Name")
            event_type = st.selectbox(
                "Event Type",
                ["connection", "traffic", "bandwidth", "time_based"],
                format_func=lambda x: {
                    'connection': 'Connection Count',
                    'traffic': 'Traffic Rate',
                    'bandwidth': 'Total Bandwidth',
                    'time_based': 'Time-Based'
                }[x]
            )
            condition = st.selectbox(
                "Condition",
                ["gt", "lt", "eq", "contains", "outside"],
                format_func=lambda x: {
                    'gt': 'Greater Than',
                    'lt': 'Less Than',
                    'eq': 'Equal To',
                    'contains': 'Contains',
                    'outside': 'Outside Of'
                }[x]
            )
            threshold = st.number_input("Threshold", min_value=0.0)
            time_window = st.number_input("Time Window (minutes)", min_value=1, value=5)
            action = st.selectbox("Action", ["email", "log"])
            description = st.text_area("Description")
            
            if st.form_submit_button("Add Rule"):
                try:
                    rule = AlertRule(
                        id=None,
                        name=name,
                        event_type=event_type,
                        condition=condition,
                        threshold=float(threshold),
                        time_window=int(time_window),
                        action=action,
                        enabled=True,
                        last_triggered=None,
                        description=description
                    )
                    db.add_alert_rule(rule)
                    st.success("Rule added successfully!")
                except Exception as e:
                    st.error(f"Error adding rule: {str(e)}")

    # Display existing rules
    rules = db.get_alert_rules()
    if rules:
        for rule in rules:
            with st.expander(f"Rule: {rule.name}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**Event Type:**", rule.get_event_type_display())
                    st.write("**Condition:**", rule.get_condition_display())
                    st.write("**Threshold:**", rule.get_threshold_display())
                with col2:
                    st.write("**Time Window:**", f"{rule.time_window} minutes")
                    st.write("**Action:**", rule.action.capitalize())
                    st.write("**Status:**", "Active" if rule.enabled else "Disabled")
                
                st.write("**Description:**", rule.description)
                
                col3, col4 = st.columns(2)
                with col3:
                    if st.button(f"{'Disable' if rule.enabled else 'Enable'} Rule", key=f"toggle_{rule.id}"):
                        rule.enabled = not rule.enabled
                        db.update_alert_rule(rule)
                        st.experimental_rerun()
                with col4:
                    if st.button("Delete Rule", key=f"delete_{rule.id}"):
                        if db.delete_alert_rule(rule.id):
                            st.success("Rule deleted successfully!")
                            st.experimental_rerun()
                        else:
                            st.error("Error deleting rule")
    else:
        st.info("No alert rules configured. Add your first rule using the form above.")

elif page == "Dashboard":
    # Active connections
    st.header("Active Connections")
    active_connections = db.get_active_connections()
    if active_connections:
        active_df = pd.DataFrame([
            {
                'Peer ID': conn.peer_id,
                'IP Address': conn.ip_address,
                'Connected Since': conn.timestamp,
                'Duration': str(datetime.now() - conn.timestamp).split('.')[0]
            }
            for conn in active_connections
        ])
        st.dataframe(active_df)
    else:
        st.info("No active connections")

    # Connection history
    st.header("Connection History")
    connections = db.get_connections()
    if connections:
        timeline = create_connection_timeline(connections)
        st.plotly_chart(timeline, use_container_width=True)
    else:
        st.info("No connection history available")

    # Traffic statistics
    st.header("Network Traffic")
    if connections:
        traffic_graph = create_traffic_graph(connections)
        st.plotly_chart(traffic_graph, use_container_width=True)
    else:
        st.info("No traffic data available")

elif page == "Connections":
    st.header("Connection History")
    connections = db.get_connections()
    if connections:
        timeline = create_connection_timeline(connections)
        st.plotly_chart(timeline, use_container_width=True)
        
        # Detailed logs
        st.subheader("Detailed Connection Logs")
        logs_df = pd.DataFrame([
            {
                'Timestamp': conn.timestamp,
                'Peer ID': conn.peer_id,
                'Event': conn.event_type.capitalize(),
                'IP Address': conn.ip_address,
            }
            for conn in connections
        ])
        st.dataframe(logs_df)
    else:
        st.info("No connection history available")

elif page == "Bandwidth":
    st.header("Bandwidth Usage")
    time_range = st.selectbox(
        "Time Range",
        ["hour", "day", "week", "month", "all"],
        format_func=lambda x: {
            'hour': 'Last Hour',
            'day': 'Last 24 Hours',
            'week': 'Last 7 Days',
            'month': 'Last 30 Days',
            'all': 'All Time'
        }[x]
    )
    
    usage = db.get_bandwidth_usage(time_range)
    if usage:
        usage_df = pd.DataFrame(usage)
        usage_df['Total Traffic'] = usage_df['total_bytes_sent'] + usage_df['total_bytes_received']
        st.dataframe(usage_df)
    else:
        st.info("No bandwidth usage data available")

# Initialize default alert rules if none exist
security_monitor.start_monitoring()
