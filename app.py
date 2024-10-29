from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta
import pandas as pd
from database import Database
from log_parser import WireGuardLogParser
from utils import create_connection_timeline, create_traffic_graph

app = Flask(__name__)
db = Database()
parser = WireGuardLogParser()

@app.route('/')
def dashboard():
    active_connections = db.get_active_connections()
    now = datetime.now()
    active_data = [{
        'peer_id': conn.peer_id,
        'ip_address': conn.ip_address,
        'connected_since': conn.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'duration': str(now - conn.timestamp).split('.')[0]
    } for conn in active_connections]
    
    return render_template('dashboard.html', active_connections=active_data)

@app.route('/connections')
def connections():
    connections = db.get_connections()
    timeline = create_connection_timeline(connections)
    graph_json = timeline.to_json()
    return render_template('connections.html', graph_json=graph_json)

@app.route('/traffic')
def traffic():
    connections = db.get_connections()
    traffic_graph = create_traffic_graph(connections)
    graph_json = traffic_graph.to_json()
    return render_template('traffic.html', graph_json=graph_json)

@app.route('/logs')
def logs():
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

@app.route('/api/data')
def api_data():
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
