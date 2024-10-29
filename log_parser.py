import re
from datetime import datetime
from typing import Optional
from models import WireGuardConnection

class WireGuardLogParser:
    def __init__(self):
        # Updated patterns to handle both standard and Docker log formats
        self.connection_pattern = re.compile(
            r'(?:\[.*?\] )?(?:\w+ \w+ \d+ \d+:\d+:\d+ \w+ )?'  # Optional Docker timestamp
            r'(?:\[\d+\] )?'  # Optional Docker/systemd process ID
            r'(?:\w+: )?'  # Optional container name
            r'peer ([\w+/=]+) \(([\d.]+)\): (connection established|disconnected)'
        )
        self.transfer_pattern = re.compile(
            r'(?:\[.*?\] )?(?:\w+ \w+ \d+ \d+:\d+:\d+ \w+ )?'  # Optional Docker timestamp
            r'(?:\[\d+\] )?'  # Optional Docker/systemd process ID
            r'(?:\w+: )?'  # Optional container name
            r'peer ([\w+/=]+): tx: (\d+) B, rx: (\d+) B'
        )
        
        # Additional pattern for Docker container ID
        self.container_id_pattern = re.compile(r'container_id=([a-f0-9]+)')

    def extract_timestamp(self, line: str) -> datetime:
        """Extract timestamp from log line or return current time"""
        timestamp_pattern = re.compile(
            r'\[?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?)\]?'
        )
        match = timestamp_pattern.search(line)
        
        if match:
            try:
                # Try parsing Docker/standard log timestamp
                timestamp_str = match.group(1)
                current_year = datetime.now().year
                return datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
            except ValueError:
                pass
        
        return datetime.now()

    def parse_line(self, line: str) -> Optional[WireGuardConnection]:
        timestamp = self.extract_timestamp(line)
        
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

    def parse_docker_line(self, line: str) -> Optional[WireGuardConnection]:
        """Parse a log line specifically from Docker logs"""
        # First try standard parsing
        connection = self.parse_line(line)
        if connection:
            # Check for container ID
            container_match = self.container_id_pattern.search(line)
            if container_match:
                # Could store container ID in the connection object if needed
                # For now, we'll just parse the log normally
                pass
            return connection
        return None
