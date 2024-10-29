from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

@dataclass
class WireGuardConnection:
    id: int
    peer_id: str
    public_key: str
    timestamp: datetime
    event_type: str  # 'connect', 'disconnect', or 'transfer'
    ip_address: str
    bytes_received: int
    bytes_sent: int

@dataclass
class AlertRule:
    id: Optional[int]
    name: str
    event_type: str  # 'connection', 'traffic', 'bandwidth', 'time_based'
    condition: str  # 'gt', 'lt', 'eq', 'contains', 'outside'
    threshold: float
    time_window: int  # in minutes
    action: str  # 'email', 'log'
    enabled: bool
    last_triggered: Optional[datetime]
    description: str

    def get_condition_display(self) -> str:
        """Get human-readable condition text"""
        conditions = {
            'gt': 'Greater Than',
            'lt': 'Less Than',
            'eq': 'Equal To',
            'contains': 'Contains',
            'outside': 'Outside Of'
        }
        return conditions.get(self.condition, self.condition)

    def get_event_type_display(self) -> str:
        """Get human-readable event type text"""
        event_types = {
            'connection': 'Connection Count',
            'traffic': 'Traffic Rate',
            'bandwidth': 'Total Bandwidth',
            'time_based': 'Time-Based'
        }
        return event_types.get(self.event_type, self.event_type)

    def get_threshold_display(self) -> str:
        """Get formatted threshold value with units"""
        if self.event_type == 'traffic':
            return f"{self.threshold:,.0f} bytes/s"
        elif self.event_type == 'bandwidth':
            return f"{self.threshold:,.0f} bytes"
        elif self.event_type == 'connection':
            return f"{self.threshold:,.0f} connections"
        return str(self.threshold)
