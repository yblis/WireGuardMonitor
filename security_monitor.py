import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import os
import logging
from typing import List, Dict
from collections import defaultdict
import threading
import time
from models import WireGuardConnection, AlertRule

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecurityMonitor')

class SecurityMonitor:
    def __init__(self, db):
        self.db = db
        # Use standard SMTP settings from environment variables
        self.smtp_server = os.getenv("SMTP_SERVER", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "25"))
        self.sender_email = os.getenv("SMTP_EMAIL")
        self.sender_password = os.getenv("SMTP_PASSWORD")  # Optional
        self.recipient_email = os.getenv("ALERT_EMAIL")
        
        # Default thresholds
        self.max_connections_per_hour = 10
        self.max_failed_attempts = 5
        self.traffic_spike_threshold = 1000000  # 1MB sudden increase
        
        # Monitoring thread
        self.monitoring_thread = None
        self.stop_monitoring = False
        
        logger.info("SecurityMonitor initialized with SMTP configuration")
        
    def send_alert(self, subject: str, message: str, rule: AlertRule = None):
        if rule and rule.action == 'log':
            logger.warning(f"Alert Rule '{rule.name}' triggered: {message}")
            return
            
        if not all([self.sender_email, self.recipient_email]):
            logger.error("Email configuration missing. Please set SMTP_EMAIL and ALERT_EMAIL")
            return
            
        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = self.recipient_email
        msg['Subject'] = f"WireGuard Security Alert: {subject}"
        
        if rule:
            message = f"Alert Rule '{rule.name}' triggered:\n\n{message}"
        
        msg.attach(MIMEText(message, 'plain'))
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.sender_password:
                server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
            logger.info(f"Security alert sent: {subject}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
    
    def check_custom_rules(self):
        """Check all enabled custom alert rules"""
        try:
            rules = self.db.get_alert_rules()
            now = datetime.now()
            
            for rule in rules:
                if not rule.enabled:
                    continue
                    
                # Skip if rule was triggered recently within its time window
                if rule.last_triggered and (now - rule.last_triggered).total_seconds() < rule.time_window * 60:
                    continue
                
                # Prepare data for rule evaluation
                data = {'value': 0}
                
                if rule.event_type == 'connection':
                    # Count connections in time window
                    connections = self.db.get_connections()
                    window_start = now - timedelta(minutes=rule.time_window)
                    count = sum(1 for conn in connections 
                              if conn.timestamp >= window_start 
                              and conn.event_type == 'connect')
                    data['value'] = count
                    
                elif rule.event_type == 'traffic':
                    # Calculate traffic in time window
                    connections = self.db.get_connections()
                    window_start = now - timedelta(minutes=rule.time_window)
                    total_traffic = sum(
                        conn.bytes_sent + conn.bytes_received
                        for conn in connections
                        if conn.timestamp >= window_start
                    )
                    data['value'] = total_traffic
                    
                elif rule.event_type == 'bandwidth':
                    # Get bandwidth usage
                    usage = self.db.get_bandwidth_usage('hour')
                    if usage:
                        max_bandwidth = max(
                            (u['total_bytes_sent'] + u['total_bytes_received'])
                            for u in usage
                        )
                        data['value'] = max_bandwidth
                
                # Evaluate rule
                if rule.evaluate(data):
                    message = (
                        f"Rule Condition: {rule.condition} {rule.threshold}\n"
                        f"Current Value: {data['value']}\n"
                        f"Time Window: {rule.time_window} minutes\n"
                        f"Description: {rule.description}"
                    )
                    self.send_alert(f"Custom Rule: {rule.name}", message, rule)
                    self.db.update_rule_trigger_time(rule.id)
                    logger.info(f"Alert rule '{rule.name}' triggered")
        except Exception as e:
            logger.error(f"Error checking custom rules: {str(e)}")
    
    def check_rapid_connections(self, connections: List[WireGuardConnection]) -> None:
        """Check for unusually rapid connection attempts from the same peer"""
        try:
            peer_connections = defaultdict(list)
            now = datetime.now()
            hour_ago = now - timedelta(hours=1)
            
            for conn in connections:
                if conn.timestamp >= hour_ago:
                    peer_connections[conn.peer_id].append(conn)
            
            for peer_id, conns in peer_connections.items():
                if len(conns) > self.max_connections_per_hour:
                    message = (
                        f"Suspicious activity detected for peer {peer_id}:\n"
                        f"- {len(conns)} connection attempts in the last hour\n"
                        f"- Latest IP: {conns[-1].ip_address}\n"
                        f"- First attempt: {conns[0].timestamp}\n"
                        f"- Latest attempt: {conns[-1].timestamp}"
                    )
                    self.send_alert("Rapid Connection Attempts", message)
                    logger.warning(f"Rapid connection attempts detected from peer {peer_id}")
        except Exception as e:
            logger.error(f"Error checking rapid connections: {str(e)}")
    
    def check_traffic_spikes(self, connections: List[WireGuardConnection]) -> None:
        """Check for sudden spikes in traffic"""
        try:
            peer_traffic = defaultdict(lambda: {"last_bytes": 0, "timestamp": None})
            
            for conn in sorted(connections, key=lambda x: x.timestamp):
                if conn.event_type != 'transfer':
                    continue
                    
                peer = peer_traffic[conn.peer_id]
                total_bytes = conn.bytes_sent + conn.bytes_received
                
                if peer["timestamp"]:
                    time_diff = (conn.timestamp - peer["timestamp"]).total_seconds()
                    if time_diff > 0:
                        bytes_diff = total_bytes - peer["last_bytes"]
                        if bytes_diff > self.traffic_spike_threshold:
                            message = (
                                f"Traffic spike detected for peer {conn.peer_id}:\n"
                                f"- Bytes transferred: {bytes_diff:,} bytes\n"
                                f"- Time period: {time_diff:.2f} seconds\n"
                                f"- Rate: {bytes_diff/time_diff:,.2f} bytes/second"
                            )
                            self.send_alert("Traffic Spike Detected", message)
                            logger.warning(f"Traffic spike detected for peer {conn.peer_id}")
                
                peer["last_bytes"] = total_bytes
                peer["timestamp"] = conn.timestamp
        except Exception as e:
            logger.error(f"Error checking traffic spikes: {str(e)}")
    
    def monitor(self):
        """Run all security checks"""
        try:
            connections = self.db.get_connections(limit=1000)  # Get last 1000 connections
            logger.debug(f"Retrieved {len(connections)} connections for monitoring")
            self.check_rapid_connections(connections)
            self.check_traffic_spikes(connections)
            self.check_custom_rules()
        except Exception as e:
            logger.error(f"Error in monitoring routine: {str(e)}")
    
    def run_monitoring_thread(self):
        """Background thread function to run periodic monitoring"""
        logger.info("Starting monitoring thread")
        while not self.stop_monitoring:
            try:
                self.monitor()
            except Exception as e:
                logger.error(f"Error in monitoring thread: {str(e)}")
            time.sleep(60)  # Check every minute
    
    def start_monitoring(self):
        """Start the background monitoring thread"""
        if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
            self.stop_monitoring = False
            self.monitoring_thread = threading.Thread(target=self.run_monitoring_thread)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
            logger.info("Security monitoring started")
    
    def stop_monitoring_thread(self):
        """Stop the background monitoring thread"""
        self.stop_monitoring = True
        if self.monitoring_thread:
            try:
                self.monitoring_thread.join(timeout=2.0)  # Add 2-second timeout
            except KeyboardInterrupt:
                pass  # Gracefully handle interrupt
            except Exception as e:
                logger.error(f"Error stopping monitoring thread: {e}")
            logger.info("Security monitoring stopped")
