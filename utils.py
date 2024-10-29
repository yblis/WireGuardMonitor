import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from typing import List
from models import WireGuardConnection

def create_connection_timeline(connections: List[WireGuardConnection]):
    if not connections:
        return go.Figure()  # Return empty figure if no data
        
    # Create DataFrame with consistent column names
    df = pd.DataFrame([
        {
            'peer_id': conn.peer_id,  # Changed from 'Peer ID' to 'peer_id'
            'start': conn.timestamp,  # Changed from 'Timestamp' to 'start'
            'event_type': conn.event_type.capitalize(),  # Changed from 'Event' to 'event_type'
            'ip_address': conn.ip_address
        }
        for conn in connections
    ])
    
    try:
        fig = px.timeline(
            df,
            x_start='start',
            y='peer_id',  # Match the column name in DataFrame
            color='event_type',
            hover_data=['ip_address'],
            title='Connection Timeline'
        )
        
        # Customize layout
        fig.update_layout(
            yaxis_title="Peer ID",
            xaxis_title="Time",
            height=400
        )
        return fig
    except Exception as e:
        print(f"Error creating timeline: {str(e)}")
        return go.Figure()  # Return empty figure on error

def create_traffic_graph(connections: List[WireGuardConnection]):
    if not connections:
        return go.Figure()  # Return empty figure if no data
        
    try:
        # Filter transfer events and create DataFrame
        transfer_data = [
            {
                'peer_id': conn.peer_id,
                'timestamp': conn.timestamp,
                'bytes_sent': conn.bytes_sent,
                'bytes_received': conn.bytes_received
            }
            for conn in connections
            if conn.event_type == 'transfer'
        ]
        
        if not transfer_data:
            return go.Figure()  # Return empty figure if no transfer data
            
        df = pd.DataFrame(transfer_data)
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['bytes_sent'],
            name='Bytes Sent',
            mode='lines'
        ))
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['bytes_received'],
            name='Bytes Received',
            mode='lines'
        ))
        
        fig.update_layout(
            title='Network Traffic Over Time',
            xaxis_title='Timestamp',
            yaxis_title='Bytes',
            showlegend=True,
            height=400
        )
        
        return fig
    except Exception as e:
        print(f"Error creating traffic graph: {str(e)}")
        return go.Figure()  # Return empty figure on error
