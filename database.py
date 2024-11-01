import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
from models import WireGuardConnection, AlertRule

class Database:
    def __init__(self, db_path: str = "wireguard_monitor.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            # Existing connections table
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
            
            # New alert_rules table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    condition TEXT NOT NULL,
                    threshold REAL NOT NULL,
                    time_window INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT 1,
                    last_triggered DATETIME,
                    description TEXT
                )
            """)
            
            # Create indexes
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_peer_timestamp 
                ON connections(peer_id, timestamp)
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

    def get_bandwidth_usage(self, time_range: str = 'day') -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            time_filters = {
                'hour': "AND timestamp >= datetime('now', '-1 hour')",
                'day': "AND timestamp >= datetime('now', '-1 day')",
                'week': "AND timestamp >= datetime('now', '-7 days')",
                'month': "AND timestamp >= datetime('now', '-30 days')",
                'all': ""
            }
            
            time_filter = time_filters.get(time_range, time_filters['day'])
            
            query = f"""
                SELECT 
                    peer_id,
                    SUM(bytes_sent) as total_bytes_sent,
                    SUM(bytes_received) as total_bytes_received,
                    COUNT(*) as connection_count,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM connections 
                WHERE event_type = 'transfer'
                {time_filter}
                GROUP BY peer_id
                ORDER BY (total_bytes_sent + total_bytes_received) DESC
            """
            
            cursor = conn.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    def add_alert_rule(self, rule: AlertRule) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO alert_rules 
                (name, event_type, condition, threshold, time_window, action, enabled, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.name,
                rule.event_type,
                rule.condition,
                rule.threshold,
                rule.time_window,
                rule.action,
                rule.enabled,
                rule.description
            ))
            conn.commit()
            return cursor.lastrowid

    def update_alert_rule(self, rule: AlertRule) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                UPDATE alert_rules 
                SET name=?, event_type=?, condition=?, threshold=?, 
                    time_window=?, action=?, enabled=?, description=?
                WHERE id=?
            """, (
                rule.name,
                rule.event_type,
                rule.condition,
                rule.threshold,
                rule.time_window,
                rule.action,
                rule.enabled,
                rule.description,
                rule.id
            ))
            conn.commit()
            return cursor.rowcount > 0

    def delete_alert_rule(self, rule_id: int) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_alert_rules(self) -> List[AlertRule]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM alert_rules ORDER BY name")
            
            return [AlertRule(
                id=row['id'],
                name=row['name'],
                event_type=row['event_type'],
                condition=row['condition'],
                threshold=row['threshold'],
                time_window=row['time_window'],
                action=row['action'],
                enabled=bool(row['enabled']),
                last_triggered=datetime.fromisoformat(row['last_triggered']) if row['last_triggered'] else None,
                description=row['description']
            ) for row in cursor.fetchall()]

    def update_rule_trigger_time(self, rule_id: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE alert_rules SET last_triggered=? WHERE id=?",
                (datetime.now().isoformat(), rule_id)
            )
            conn.commit()
