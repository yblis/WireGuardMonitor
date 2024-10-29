import re
import os
import logging
from datetime import datetime
from typing import Optional, List
from models import WireGuardConnection

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('WireGuardLogParser')

class WireGuardLogParser:
    def __init__(self):
        self.log_file = os.getenv('LOG_FILE_PATH', '/var/log/wireguard/wg0.log')
        self.connection_pattern = re.compile(
            r'peer ([\w+/=]+) \(([\d.]+)\): (connection established|disconnected)'
        )
        self.transfer_pattern = re.compile(
            r'peer ([\w+/=]+): tx: (\d+) B, rx: (\d+) B'
        )
        logger.info(f"Initialized WireGuard log parser with log file: {self.log_file}")

    def read_log_file(self) -> List[str]:
        """Read the WireGuard log file"""
        try:
            if not os.path.exists(self.log_file):
                logger.error(f"Log file not found: {self.log_file}")
                return []

            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            logger.debug(f"Read {len(lines)} lines from log file")
            return lines
        except PermissionError:
            logger.error(f"Permission denied accessing log file: {self.log_file}")
            return []
        except Exception as e:
            logger.error(f"Error reading log file: {str(e)}")
            return []

    def parse_line(self, line: str) -> Optional[WireGuardConnection]:
        """Parse a single line from the WireGuard log"""
        try:
            timestamp = datetime.now()
            
            # Try to match connection events
            conn_match = self.connection_pattern.search(line)
            if conn_match:
                public_key, ip_address, event = conn_match.groups()
                event_type = 'connect' if event == 'connection established' else 'disconnect'
                
                logger.debug(f"Parsed connection event: {event_type} from {ip_address}")
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
                
                logger.debug(f"Parsed transfer stats for peer {public_key[:8]}")
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

        except Exception as e:
            logger.error(f"Error parsing log line: {str(e)}\nLine: {line}")
            return None

        return None

    def parse_logs(self) -> List[WireGuardConnection]:
        """Parse all new log entries"""
        connections = []
        for line in self.read_log_file():
            conn = self.parse_line(line)
            if conn:
                connections.append(conn)
        
        logger.info(f"Parsed {len(connections)} connections from logs")
        return connections
