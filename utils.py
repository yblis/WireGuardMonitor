import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List
from models import WireGuardConnection

def create_connection_timeline(connections: List[WireGuardConnection]):
    df = pd.DataFrame([
        {
            'Peer ID': conn.peer_id,
            'Timestamp': conn.timestamp,
            'Event': conn.event_type.capitalize(),
            'IP Address': conn.ip_address
        }
        for conn in connections
    ])
    
    fig = px.timeline(
        df,
        x_start='Timestamp',
        y='Peer ID',
        color='Event',
        hover_data=['IP Address'],
        title='Connection Timeline'
    )
    return fig

def create_traffic_graph(connections: List[WireGuardConnection]):
    df = pd.DataFrame([
        {
            'Peer ID': conn.peer_id,
            'Timestamp': conn.timestamp,
            'Bytes Sent': conn.bytes_sent,
            'Bytes Received': conn.bytes_received
        }
        for conn in connections
        if conn.event_type == 'transfer'
    ])
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['Timestamp'],
        y=df['Bytes Sent'],
        name='Bytes Sent',
        mode='lines'
    ))
    fig.add_trace(go.Scatter(
        x=df['Timestamp'],
        y=df['Bytes Received'],
        name='Bytes Received',
        mode='lines'
    ))
    
    fig.update_layout(
        title='Network Traffic Over Time',
        xaxis_title='Timestamp',
        yaxis_title='Bytes'
    )
    
    return fig
