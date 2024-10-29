import re
from datetime import datetime
from typing import Optional
from models import WireGuardConnection

class WireGuardLogParser:
    def __init__(self):
        self.connection_pattern = re.compile(
            r'peer ([\w+/=]+) \(([\d.]+)\): (connection established|disconnected)'
        )
        self.transfer_pattern = re.compile(
            r'peer ([\w+/=]+): tx: (\d+) B, rx: (\d+) B'
        )

    def parse_line(self, line: str) -> Optional[WireGuardConnection]:
        timestamp = datetime.now()
        
        # Try to match connection events
        conn_match = self.connection_pattern.search(line)
        if conn_match:
            public_key, ip_address, event = conn_match.groups()
            event_type = 'connect' if event == 'connection established' else 'disconnect'
            
            return WireGuardConnection(
                id=0,  # Will be set by database
                peer_id=public_key[:8],  # Use first 8 chars as ID
                public_key=public_key,
                timestamp=timestamp,
                event_type=event_type,
                ip_address=ip_address,
                bytes_received=0,
                bytes_sent=0
            )

        # Try to match transfer statistics
        transfer_match = self.transfer_pattern.search(line)
        if transfer_match:
            public_key, sent, received = transfer_match.groups()
            
            return WireGuardConnection(
                id=0,
                peer_id=public_key[:8],
                public_key=public_key,
                timestamp=timestamp,
                event_type='transfer',
                ip_address='',
                bytes_received=int(received),
                bytes_sent=int(sent)
            )

        return None
