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
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SecurityMonitor')

class SecurityMonitor:
    def __init__(self, db):
        self.db = db
        self.smtp_server = os.getenv("SMTP_SERVER", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "25"))
        self.sender_email = os.getenv("SMTP_EMAIL")
        self.sender_password = os.getenv("SMTP_PASSWORD")
        self.recipient_email = os.getenv("ALERT_EMAIL")
        
        # Business hours (9 AM - 5 PM)
        self.business_hours_start = 9
        self.business_hours_end = 17
        
        # Monitoring thread
        self.monitoring_thread = None
        self.stop_monitoring = False
        
        logger.info("SecurityMonitor initialized with SMTP configuration")

    def is_business_hours(self) -> bool:
        """Check if current time is within business hours"""
        current_hour = datetime.now().hour
        return self.business_hours_start <= current_hour < self.business_hours_end

    def check_time_based_rules(self, rule: AlertRule) -> bool:
        """Evaluate time-based alert rules"""
        if rule.condition == 'outside':
            return not self.is_business_hours()
        return False

    def check_traffic_rules(self, rule: AlertRule, connections: List[WireGuardConnection]) -> bool:
        """Evaluate traffic-based alert rules"""
        now = datetime.now()
        window_start = now - timedelta(minutes=rule.time_window)
        
        # Calculate traffic rate in the time window
        window_connections = [c for c in connections if c.timestamp >= window_start]
        if not window_connections:
            return False
            
        total_bytes = sum(c.bytes_sent + c.bytes_received for c in window_connections)
        time_span = (max(c.timestamp for c in window_connections) - 
                    min(c.timestamp for c in window_connections)).total_seconds()
        
        if time_span <= 0:
            return False
            
        bytes_per_second = total_bytes / time_span
        return self.evaluate_threshold(bytes_per_second, rule.threshold, rule.condition)

    def check_connection_rules(self, rule: AlertRule, connections: List[WireGuardConnection]) -> bool:
        """Evaluate connection-based alert rules"""
        now = datetime.now()
        window_start = now - timedelta(minutes=rule.time_window)
        
        # Count connections in the time window
        connection_count = sum(1 for c in connections 
                             if c.timestamp >= window_start and c.event_type == 'connect')
                             
        return self.evaluate_threshold(connection_count, rule.threshold, rule.condition)

    def check_bandwidth_rules(self, rule: AlertRule) -> bool:
        """Evaluate bandwidth-based alert rules"""
        usage = self.db.get_bandwidth_usage('hour')
        if not usage:
            return False
            
        max_bandwidth = max(u['total_bytes_sent'] + u['total_bytes_received'] 
                          for u in usage)
        return self.evaluate_threshold(max_bandwidth, rule.threshold, rule.condition)

    def evaluate_threshold(self, value: float, threshold: float, condition: str) -> bool:
        """Evaluate a value against a threshold with a given condition"""
        if condition == 'gt':
            return value > threshold
        elif condition == 'lt':
            return value < threshold
        elif condition == 'eq':
            return abs(value - threshold) < 0.0001
        elif condition == 'contains':
            return str(threshold) in str(value)
        return False

    def send_alert(self, subject: str, message: str, rule: AlertRule = None):
        """Send alert via email or log"""
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

    def check_rule(self, rule: AlertRule, connections: List[WireGuardConnection]) -> bool:
        """Check if a specific rule is triggered"""
        if not rule.enabled:
            return False
            
        now = datetime.now()
        if (rule.last_triggered and 
            (now - rule.last_triggered).total_seconds() < rule.time_window * 60):
            return False
            
        triggered = False
        if rule.event_type == 'traffic':
            triggered = self.check_traffic_rules(rule, connections)
        elif rule.event_type == 'connection':
            triggered = self.check_connection_rules(rule, connections)
        elif rule.event_type == 'bandwidth':
            triggered = self.check_bandwidth_rules(rule)
        elif rule.event_type == 'time_based':
            triggered = self.check_time_based_rules(rule)
            
        return triggered

    def monitor(self):
        """Run all security checks"""
        try:
            connections = self.db.get_connections(limit=1000)
            rules = self.db.get_alert_rules()
            
            for rule in rules:
                if self.check_rule(rule, connections):
                    message = self.generate_alert_message(rule, connections)
                    self.send_alert(f"Rule Triggered: {rule.name}", message, rule)
                    self.db.update_rule_trigger_time(rule.id)
                    logger.info(f"Alert rule '{rule.name}' triggered")
                    
        except Exception as e:
            logger.error(f"Error in monitoring routine: {str(e)}")

    def generate_alert_message(self, rule: AlertRule, connections: List[WireGuardConnection]) -> str:
        """Generate detailed alert message based on rule type"""
        now = datetime.now()
        window_start = now - timedelta(minutes=rule.time_window)
        window_connections = [c for c in connections if c.timestamp >= window_start]
        
        message = f"Rule Type: {rule.event_type}\n"
        message += f"Condition: {rule.condition}\n"
        message += f"Threshold: {rule.threshold}\n"
        message += f"Time Window: {rule.time_window} minutes\n\n"
        
        if rule.event_type == 'traffic':
            total_bytes = sum(c.bytes_sent + c.bytes_received for c in window_connections)
            message += f"Total Traffic: {total_bytes:,} bytes\n"
            message += "Recent Connections:\n"
            for conn in window_connections[-5:]:
                message += f"- Peer {conn.peer_id}: {conn.bytes_sent + conn.bytes_received:,} bytes\n"
                
        elif rule.event_type == 'connection':
            connect_count = sum(1 for c in window_connections if c.event_type == 'connect')
            message += f"Connection Count: {connect_count}\n"
            message += "Recent Connections:\n"
            for conn in window_connections[-5:]:
                message += f"- {conn.timestamp}: {conn.peer_id} ({conn.ip_address})\n"
                
        elif rule.event_type == 'bandwidth':
            usage = self.db.get_bandwidth_usage('hour')
            if usage:
                message += "Bandwidth Usage:\n"
                for u in usage[:5]:
                    message += f"- Peer {u['peer_id']}: {u['total_bytes_sent'] + u['total_bytes_received']:,} bytes\n"
                    
        elif rule.event_type == 'time_based':
            message += f"Current Hour: {now.hour:02d}:00\n"
            message += f"Business Hours: {self.business_hours_start:02d}:00 - {self.business_hours_end:02d}:00\n"
            message += "Recent Connections:\n"
            for conn in window_connections[-5:]:
                message += f"- {conn.timestamp}: {conn.peer_id} ({conn.ip_address})\n"
                
        return message

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
                self.monitoring_thread.join(timeout=2.0)
            except Exception as e:
                logger.error(f"Error stopping monitoring thread: {e}")
            logger.info("Security monitoring stopped")
