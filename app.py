from flask import Flask, render_template, jsonify, request, flash
from datetime import datetime, timedelta
import pandas as pd
from database import Database
from log_parser import WireGuardLogParser
from utils import create_connection_timeline, create_traffic_graph
from security_monitor import SecurityMonitor
from models import AlertRule
import sqlite3
import traceback
import atexit
import logging
import os
from typing import List
import ipaddress
import geoip2.database
import requests

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('WireGuardMonitor')

app = Flask(__name__)
app.secret_key = os.urandom(24)
db = Database()
parser = WireGuardLogParser()
security_monitor = SecurityMonitor(db)

# Default alert rules
DEFAULT_ALERT_RULES = [
    {
        'name': 'Traffic Spike Detection',
        'event_type': 'traffic',
        'condition': 'gt',
        'threshold': 1000000,  # 1MB/s
        'time_window': 5,  # 5 minutes
        'action': 'email',
        'description': 'Alert when traffic exceeds 1MB/s in 5 minutes'
    },
    {
        'name': 'Rapid Connection Attempts',
        'event_type': 'connection',
        'condition': 'gt',
        'threshold': 5,  # connections
        'time_window': 1,  # 1 minute
        'action': 'email',
        'description': 'Alert when more than 5 connection attempts occur within 1 minute'
    },
    {
        'name': 'High Bandwidth Usage',
        'event_type': 'bandwidth',
        'condition': 'gt',
        'threshold': 1000000000,  # 1GB
        'time_window': 60,  # 1 hour
        'action': 'email',
        'description': 'Alert when total bandwidth exceeds 1GB in an hour'
    },
    {
        'name': 'After Hours Connection',
        'event_type': 'time_based',
        'condition': 'outside',
        'threshold': 0,  # Not used for time-based
        'time_window': 0,  # Not used for time-based
        'action': 'email',
        'description': 'Alert when connections occur outside business hours (9 AM - 5 PM)'
    }
]

def initialize_default_rules():
    """Initialize default alert rules if none exist"""
    try:
        existing_rules = db.get_alert_rules()
        if not existing_rules:
            logger.info("Initializing default alert rules")
            for rule_data in DEFAULT_ALERT_RULES:
                rule = AlertRule(
                    id=None,
                    name=rule_data['name'],
                    event_type=rule_data['event_type'],
                    condition=rule_data['condition'],
                    threshold=float(rule_data['threshold']),
                    time_window=int(rule_data['time_window']),
                    action=rule_data['action'],
                    enabled=True,
                    last_triggered=None,
                    description=rule_data['description']
                )
                db.add_alert_rule(rule)
            logger.info("Default alert rules initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing default rules: {str(e)}")

# Rest of the existing app.py code remains the same...

def cleanup():
    """Stop the security monitoring thread when the application exits"""
    security_monitor.stop_monitoring_thread()

if __name__ == '__main__':
    initialize_default_rules()
    security_monitor.start_monitoring()
    atexit.register(cleanup)
    app.run(host='0.0.0.0', port=5000, debug=True)
