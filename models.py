from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

@dataclass
class WireGuardConnection:
    id: int
    peer_id: str
    public_key: str
    timestamp: datetime
    event_type: str  # 'connect' or 'disconnect'
    ip_address: str
    bytes_received: int
    bytes_sent: int

@dataclass
class AlertRule:
    id: Optional[int]
    name: str
    event_type: str  # 'connection', 'traffic', 'bandwidth'
    condition: str  # 'gt', 'lt', 'eq', 'contains'
    threshold: float
    time_window: int  # in minutes
    action: str  # 'email', 'log'
    enabled: bool
    last_triggered: Optional[datetime]
    description: str
    
    def evaluate(self, data: Dict[str, Any]) -> bool:
        """Evaluate if the rule condition is met"""
        value = float(data.get('value', 0))
        
        if self.condition == 'gt':
            return value > self.threshold
        elif self.condition == 'lt':
            return value < self.threshold
        elif self.condition == 'eq':
            return abs(value - self.threshold) < 0.0001
        elif self.condition == 'contains':
            return str(self.threshold) in str(value)
        
        return False
