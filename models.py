from dataclasses import dataclass
from datetime import datetime

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
