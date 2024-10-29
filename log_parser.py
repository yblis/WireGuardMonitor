import re
import os
import logging
import subprocess
from datetime import datetime
from typing import Optional, List, Tuple
from models import WireGuardConnection

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
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
        self.wg_dump_pattern = re.compile(
            r'^([\w+/=]+)\t([\d.]+:\d+)?\t\d+\t(\d+)\t(\d+)$'
        )
        logger.info(f"Initialized WireGuard log parser with log file: {self.log_file}")

    def get_wg_dump(self) -> List[WireGuardConnection]:
        """Get current connections using 'wg show all dump' command"""
        try:
            logger.debug("Attempting to get WireGuard status using 'wg show all dump'")
            result = subprocess.run(['wg', 'show', 'all', 'dump'], 
                                 capture_output=True, text=True, check=True)
            connections = []
            timestamp = datetime.now()

            for line in result.stdout.splitlines():
                match = self.wg_dump_pattern.match(line)
                if match:
                    public_key, endpoint, rx_bytes, tx_bytes = match.groups()
                    ip_address = endpoint.split(':')[0] if endpoint else ''
                    
                    conn = WireGuardConnection(
                        id=0,
                        peer_id=public_key[:8],
                        public_key=public_key,
                        timestamp=timestamp,
                        event_type='transfer',
                        ip_address=ip_address,
                        bytes_received=int(rx_bytes),
                        bytes_sent=int(tx_bytes)
                    )
                    connections.append(conn)
                    logger.debug(f"Parsed connection from wg dump: peer_id={conn.peer_id}")

            return connections
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running 'wg show all dump': {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error parsing wg dump output: {str(e)}")
            return []

    def read_log_file(self) -> Tuple[List[str], str]:
        """Read the WireGuard log file or fall back to wg dump"""
        try:
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r') as f:
                    lines = f.readlines()
                logger.debug(f"Read {len(lines)} lines from log file: {self.log_file}")
                return lines, 'log_file'
            else:
                logger.warning(f"Log file not found: {self.log_file}, falling back to wg dump")
                return [], 'wg_dump'
        except PermissionError:
            logger.warning(f"Permission denied accessing log file: {self.log_file}, falling back to wg dump")
            return [], 'wg_dump'
        except Exception as e:
            logger.error(f"Error reading log file: {str(e)}, falling back to wg dump")
            return [], 'wg_dump'

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
                    id=0,
                    peer_id=public_key[:8],
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
        """Parse all new log entries with fallback to wg dump"""
        connections = []
        
        # Try reading from log file first
        lines, source = self.read_log_file()
        
        if source == 'log_file':
            logger.info("Using log file as data source")
            for line in lines:
                conn = self.parse_line(line)
                if conn:
                    connections.append(conn)
        else:
            logger.info("Using wg dump as data source")
            connections = self.get_wg_dump()
        
        logger.info(f"Parsed {len(connections)} connections from {source}")
        return connections
