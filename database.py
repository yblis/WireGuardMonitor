import sqlite3
from datetime import datetime
from typing import List
from models import WireGuardConnection

class Database:
    def __init__(self, db_path: str = "wireguard_monitor.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    event_type TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    bytes_received INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0
                )
            """)
            conn.commit()

    def add_connection(self, connection: WireGuardConnection):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO connections 
                (peer_id, public_key, timestamp, event_type, ip_address, bytes_received, bytes_sent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                connection.peer_id,
                connection.public_key,
                connection.timestamp,
                connection.event_type,
                connection.ip_address,
                connection.bytes_received,
                connection.bytes_sent
            ))
            conn.commit()

    def get_connections(self, limit: int = 1000) -> List[WireGuardConnection]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM connections 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            return [WireGuardConnection(
                id=row['id'],
                peer_id=row['peer_id'],
                public_key=row['public_key'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                event_type=row['event_type'],
                ip_address=row['ip_address'],
                bytes_received=row['bytes_received'],
                bytes_sent=row['bytes_sent']
            ) for row in cursor.fetchall()]

    def get_active_connections(self) -> List[WireGuardConnection]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM connections 
                WHERE event_type = 'connect' 
                AND peer_id NOT IN (
                    SELECT peer_id 
                    FROM connections 
                    WHERE event_type = 'disconnect' 
                    AND timestamp > (
                        SELECT MAX(timestamp) 
                        FROM connections c2 
                        WHERE c2.peer_id = connections.peer_id 
                        AND c2.event_type = 'connect'
                    )
                )
            """)
            
            return [WireGuardConnection(
                id=row['id'],
                peer_id=row['peer_id'],
                public_key=row['public_key'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                event_type=row['event_type'],
                ip_address=row['ip_address'],
                bytes_received=row['bytes_received'],
                bytes_sent=row['bytes_sent']
            ) for row in cursor.fetchall()]
