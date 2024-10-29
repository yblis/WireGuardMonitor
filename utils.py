import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import logging
from typing import List
from models import WireGuardConnection

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Utils')

def create_connection_timeline(connections: List[WireGuardConnection]):
    """Create a timeline visualization of connections"""
    logger.debug("Creating connection timeline visualization")
    
    if not connections:
        logger.warning("No connection data available for timeline")
        fig = go.Figure()
        fig.update_layout(
            title='Connection Timeline - No Data Available',
            annotations=[{
                'text': 'No connection data available',
                'xref': 'paper',
                'yref': 'paper',
                'showarrow': False,
                'font': {'size': 20}
            }]
        )
        return fig
        
    try:
        # Create DataFrame with consistent column names
        df = pd.DataFrame([
            {
                'peer_id': conn.peer_id,
                'start': conn.timestamp,
                'event_type': conn.event_type.capitalize(),
                'ip_address': conn.ip_address
            }
            for conn in connections
        ])
        
        logger.debug(f"Created timeline DataFrame with {len(df)} rows")
        
        if df.empty:
            logger.warning("Timeline DataFrame is empty")
            fig = go.Figure()
            fig.update_layout(title='Connection Timeline - No Data')
            return fig
            
        fig = px.timeline(
            df,
            x_start='start',
            y='peer_id',
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
        
        logger.debug("Successfully created timeline visualization")
        return fig
        
    except Exception as e:
        logger.error(f"Error creating timeline: {str(e)}")
        fig = go.Figure()
        fig.update_layout(
            title='Connection Timeline - Error',
            annotations=[{
                'text': 'Error creating timeline visualization',
                'xref': 'paper',
                'yref': 'paper',
                'showarrow': False,
                'font': {'size': 20}
            }]
        )
        return fig

def create_traffic_graph(connections: List[WireGuardConnection]):
    """Create a traffic visualization graph"""
    logger.debug("Creating traffic visualization")
    
    if not connections:
        logger.warning("No connection data available for traffic graph")
        fig = go.Figure()
        fig.update_layout(
            title='Network Traffic - No Data Available',
            annotations=[{
                'text': 'No traffic data available',
                'xref': 'paper',
                'yref': 'paper',
                'showarrow': False,
                'font': {'size': 20}
            }]
        )
        return fig
        
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
        
        logger.debug(f"Created traffic DataFrame with {len(transfer_data)} records")
        
        if not transfer_data:
            logger.warning("No transfer data available")
            fig = go.Figure()
            fig.update_layout(
                title='Network Traffic - No Transfer Data',
                annotations=[{
                    'text': 'No transfer data available',
                    'xref': 'paper',
                    'yref': 'paper',
                    'showarrow': False,
                    'font': {'size': 20}
                }]
            )
            return fig
            
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
        
        logger.debug("Successfully created traffic visualization")
        return fig
        
    except Exception as e:
        logger.error(f"Error creating traffic graph: {str(e)}")
        fig = go.Figure()
        fig.update_layout(
            title='Network Traffic - Error',
            annotations=[{
                'text': 'Error creating traffic visualization',
                'xref': 'paper',
                'yref': 'paper',
                'showarrow': False,
                'font': {'size': 20}
            }]
        )
        return fig
