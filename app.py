from flask import Flask, render_template, jsonify, request
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

app = Flask(__name__)
db = Database()
parser = WireGuardLogParser()
security_monitor = SecurityMonitor(db)

def handle_db_error(error):
    app.logger.error(f"Database error: {str(error)}\n{traceback.format_exc()}")
    return "Database error occurred", 500

def format_bytes(bytes_value):
    """Format bytes to human-readable format"""
    if bytes_value == 0:
        return "0 B"
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while bytes_value >= 1024 and i < len(units)-1:
        bytes_value /= 1024.
        i += 1
    return f"{bytes_value:.2f} {units[i]}"

def format_timestamp(timestamp):
    """Format timestamp to human-readable format"""
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')

@app.route('/')
def dashboard():
    try:
        active_connections = db.get_active_connections()
        now = datetime.now()
        active_data = [{
            'peer_id': conn.peer_id,
            'ip_address': conn.ip_address,
            'connected_since': conn.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': str(now - conn.timestamp).split('.')[0]
        } for conn in active_connections]
        
        return render_template('dashboard.html', active_connections=active_data)
    except sqlite3.Error as e:
        return handle_db_error(e)

@app.route('/bandwidth')
def bandwidth():
    try:
        bandwidth_stats = db.get_bandwidth_usage()
        return render_template('bandwidth.html', 
                             bandwidth_stats=bandwidth_stats,
                             format_bytes=format_bytes,
                             format_timestamp=format_timestamp)
    except sqlite3.Error as e:
        return handle_db_error(e)

@app.route('/api/bandwidth')
def api_bandwidth():
    try:
        time_range = request.args.get('range', 'day')
        bandwidth_stats = db.get_bandwidth_usage(time_range)
        return jsonify({'stats': bandwidth_stats})
    except sqlite3.Error as e:
        app.logger.error(f"Database error in bandwidth API: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Database error occurred'}), 500

@app.route('/connections')
def connections():
    try:
        connections = db.get_connections()
        timeline = create_connection_timeline(connections)
        graph_json = timeline.to_json()
        return render_template('connections.html', graph_json=graph_json)
    except sqlite3.Error as e:
        return handle_db_error(e)
    except Exception as e:
        app.logger.error(f"Error generating connection timeline: {str(e)}\n{traceback.format_exc()}")
        return render_template('connections.html', graph_json='{}')

@app.route('/traffic')
def traffic():
    try:
        connections = db.get_connections()
        traffic_graph = create_traffic_graph(connections)
        graph_json = traffic_graph.to_json()
        return render_template('traffic.html', graph_json=graph_json)
    except sqlite3.Error as e:
        return handle_db_error(e)
    except Exception as e:
        app.logger.error(f"Error generating traffic graph: {str(e)}\n{traceback.format_exc()}")
        return render_template('traffic.html', graph_json='{}')

@app.route('/logs')
def logs():
    try:
        connections = db.get_connections()
        logs_data = [{
            'timestamp': conn.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'peer_id': conn.peer_id,
            'event': conn.event_type.capitalize(),
            'ip_address': conn.ip_address,
            'bytes_sent': conn.bytes_sent,
            'bytes_received': conn.bytes_received
        } for conn in connections]
        return render_template('logs.html', logs=logs_data)
    except sqlite3.Error as e:
        return handle_db_error(e)

@app.route('/alert-rules')
def alert_rules():
    try:
        rules = db.get_alert_rules()
        return render_template('alert_rules.html', alert_rules=rules)
    except sqlite3.Error as e:
        return handle_db_error(e)

@app.route('/api/alert-rules', methods=['GET', 'POST'])
def api_alert_rules():
    try:
        if request.method == 'POST':
            data = request.json
            rule = AlertRule(
                id=None,
                name=data['name'],
                event_type=data['event_type'],
                condition=data['condition'],
                threshold=float(data['threshold']),
                time_window=int(data['time_window']),
                action=data['action'],
                enabled=True,
                last_triggered=None,
                description=data.get('description', '')
            )
            rule_id = db.add_alert_rule(rule)
            return jsonify({'id': rule_id})
        else:
            rules = db.get_alert_rules()
            return jsonify([vars(rule) for rule in rules])
    except Exception as e:
        app.logger.error(f"Error in alert rules API: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert-rules/<int:rule_id>', methods=['GET', 'PUT', 'DELETE'])
def api_alert_rule(rule_id):
    try:
        if request.method == 'GET':
            rules = db.get_alert_rules()
            rule = next((r for r in rules if r.id == rule_id), None)
            if rule:
                return jsonify(vars(rule))
            return jsonify({'error': 'Rule not found'}), 404
            
        elif request.method == 'PUT':
            data = request.json
            rule = AlertRule(
                id=rule_id,
                name=data['name'],
                event_type=data['event_type'],
                condition=data['condition'],
                threshold=float(data['threshold']),
                time_window=int(data['time_window']),
                action=data['action'],
                enabled=True,
                last_triggered=None,
                description=data.get('description', '')
            )
            success = db.update_alert_rule(rule)
            if success:
                return jsonify({'status': 'success'})
            return jsonify({'error': 'Rule not found'}), 404
            
        elif request.method == 'DELETE':
            success = db.delete_alert_rule(rule_id)
            if success:
                return jsonify({'status': 'success'})
            return jsonify({'error': 'Rule not found'}), 404
            
    except Exception as e:
        app.logger.error(f"Error in alert rule API: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert-rules/<int:rule_id>/toggle', methods=['POST'])
def api_toggle_rule(rule_id):
    try:
        data = request.json
        rules = db.get_alert_rules()
        rule = next((r for r in rules if r.id == rule_id), None)
        if rule:
            rule.enabled = data['enabled']
            success = db.update_alert_rule(rule)
            if success:
                return jsonify({'status': 'success'})
        return jsonify({'error': 'Rule not found'}), 404
    except Exception as e:
        app.logger.error(f"Error toggling rule: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/data')
def api_data():
    try:
        active_connections = db.get_active_connections()
        connections = db.get_connections()
        now = datetime.now()
        
        return jsonify({
            'active_connections': [{
                'peer_id': conn.peer_id,
                'ip_address': conn.ip_address,
                'connected_since': conn.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'duration': str(now - conn.timestamp).split('.')[0]
            } for conn in active_connections],
            'connection_timeline': create_connection_timeline(connections).to_json(),
            'traffic_graph': create_traffic_graph(connections).to_json()
        })
    except sqlite3.Error as e:
        app.logger.error(f"Database error in API: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Database error occurred'}), 500
    except Exception as e:
        app.logger.error(f"API error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500

def cleanup():
    """Stop the security monitoring thread when the application exits"""
    security_monitor.stop_monitoring_thread()

if __name__ == '__main__':
    # Start security monitoring
    security_monitor.start_monitoring()
    
    # Register cleanup function
    atexit.register(cleanup)
    
    app.run(host='0.0.0.0', port=5000, debug=True)
