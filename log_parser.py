import re
import os
import logging
import subprocess
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from models import WireGuardConnection

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('WireGuardLogParser')

class WireGuardLogParser:
    def __init__(self):
        self.log_locations = [
            '/var/log/wireguard/wg0.log',
            '/var/log/syslog',
            '/var/log/messages'
        ]
        self.connection_pattern = re.compile(
            r'peer ([\w+/=]+) \(([\d.]+)\): (connection established|disconnected)'
        )
        self.transfer_pattern = re.compile(
            r'peer ([\w+/=]+): tx: (\d+) B, rx: (\d+) B'
        )
        self.wg_dump_pattern = re.compile(
            r'^([\w+/=]+)\t([\d.]+:\d+)?\t\d+\t(\d+)\t(\d+)$'
        )
        self.current_source = None
        logger.info("Initialized WireGuard log parser")

    def get_wg_dump(self, sudo: bool = False) -> List[WireGuardConnection]:
        """Get current connections using WireGuard commands"""
        connections = []
        commands = [
            ['wg', 'show', 'all', 'dump'],
            ['sudo', 'wg', 'show', 'all', 'dump'] if sudo else None
        ]

        for cmd in commands:
            if not cmd:
                continue

            try:
                logger.debug(f"Attempting to get WireGuard status using: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
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

                if connections:
                    self.current_source = f"wg dump ({'sudo' if sudo else 'normal'})"
                    return connections

            except subprocess.CalledProcessError as e:
                logger.warning(f"Error running {cmd[0]}: {str(e)}")
            except Exception as e:
                logger.error(f"Error parsing wg dump output from {cmd[0]}: {str(e)}")

        return []

    def get_journalctl_logs(self) -> List[str]:
        """Get WireGuard logs from journalctl"""
        try:
            logger.debug("Attempting to get WireGuard logs from journalctl")
            cmd = ['journalctl', '-u', 'wg-quick@wg0', '--no-pager', '-n', '1000']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if result.stdout:
                self.current_source = "journalctl"
                return result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            logger.warning(f"Error getting journalctl logs: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing journalctl output: {str(e)}")
        return []

    def read_log_file(self) -> Tuple[List[str], str]:
        """Try reading from multiple log file locations"""
        for log_file in self.log_locations:
            try:
                if os.path.exists(log_file):
                    logger.debug(f"Attempting to read log file: {log_file}")
                    with open(log_file, 'r') as f:
                        lines = f.readlines()
                    self.current_source = f"log file ({log_file})"
                    logger.info(f"Successfully read {len(lines)} lines from {log_file}")
                    return lines, self.current_source
            except PermissionError:
                logger.warning(f"Permission denied accessing log file: {log_file}")
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {str(e)}")

        logger.warning("No readable log files found")
        return [], "none"

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

    def get_data_source(self) -> str:
        """Return the current data source being used"""
        return self.current_source or "unknown"

    def parse_logs(self) -> List[WireGuardConnection]:
        """Parse WireGuard data from all available sources"""
        connections = []
        self.current_source = None

        # Try wg dump command first
        connections = self.get_wg_dump(sudo=False)
        if connections:
            return connections

        # Try sudo wg dump
        connections = self.get_wg_dump(sudo=True)
        if connections:
            return connections

        # Try reading from log files
        lines, source = self.read_log_file()
        if lines:
            for line in lines:
                conn = self.parse_line(line)
                if conn:
                    connections.append(conn)
            if connections:
                return connections

        # Try journalctl as last resort
        journal_lines = self.get_journalctl_logs()
        if journal_lines:
            for line in journal_lines:
                conn = self.parse_line(line)
                if conn:
                    connections.append(conn)

        if not connections:
            logger.warning("No WireGuard data could be obtained from any source")
            self.current_source = "none"

        return connections
