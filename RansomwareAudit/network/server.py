import hmac
import json
import secrets
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify
import os

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

# Clients must send this token in X-Auth-Token. Set RA_SERVER_TOKEN on the
# server and every client; if unset, a random one is printed at startup.
API_TOKEN = os.environ.get("RA_SERVER_TOKEN") or secrets.token_urlsafe(24)


@app.before_request
def require_token():
    if request.path.startswith("/api/") and request.path != "/api/health":
        if not hmac.compare_digest(request.headers.get("X-Auth-Token", ""), API_TOKEN):
            return jsonify({"error": "Unauthorized"}), 401

DATABASE = 'ransomware_central.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT NOT NULL,
                  hostname TEXT,
                  timestamp TEXT,
                  risk_level TEXT,
                  total_score REAL,
                  files_scanned INTEGER,
                  flagged_files INTEGER,
                  scan_data TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT NOT NULL,
                  timestamp TEXT,
                  alert_level TEXT,
                  message TEXT)''')
    
    conn.commit()
    conn.close()

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'service': 'ransomware-audit-server'})

@app.route('/api/submit_scan', methods=['POST'])
def submit_scan():
    data = request.get_json(silent=True) or {}
    
    client_id = data.get('client_id', 'unknown')
    hostname = data.get('hostname', 'unknown')
    scan_report = data.get('scan_report', {})
    
    risk_summary = scan_report.get('risk_summary', {})
    stats = scan_report.get('statistics', {})
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''INSERT INTO scans 
                 (client_id, hostname, timestamp, risk_level, total_score, 
                  files_scanned, flagged_files, scan_data)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (client_id, hostname, datetime.now().isoformat(),
               risk_summary.get('risk_level', 'UNKNOWN'),
               risk_summary.get('total_score', 0),
               stats.get('total_files_scanned', 0),
               stats.get('high_risk_file_count', 0),
               json.dumps(scan_report)))
    
    scan_id = c.lastrowid
    
    if risk_summary.get('risk_level') in ['HIGH', 'CRITICAL']:
        c.execute('''INSERT INTO alerts (client_id, timestamp, alert_level, message)
                     VALUES (?, ?, ?, ?)''',
                  (client_id, datetime.now().isoformat(),
                   risk_summary.get('risk_level'),
                   f"High risk detected on {hostname}: Score {risk_summary.get('total_score', 0)}"))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'status': 'success',
        'scan_id': scan_id,
        'message': 'Scan submitted successfully'
    })

@app.route('/api/scans', methods=['GET'])
def get_scans():
    limit = max(1, min(request.args.get('limit', 50, type=int), 500))
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''SELECT id, client_id, hostname, timestamp, risk_level, 
                        total_score, files_scanned, flagged_files
                 FROM scans 
                 ORDER BY timestamp DESC 
                 LIMIT ?''', (limit,))
    
    scans = []
    for row in c.fetchall():
        scans.append({
            'id': row[0],
            'client_id': row[1],
            'hostname': row[2],
            'timestamp': row[3],
            'risk_level': row[4],
            'total_score': row[5],
            'files_scanned': row[6],
            'flagged_files': row[7]
        })
    
    conn.close()
    
    return jsonify({'scans': scans, 'total': len(scans)})

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = max(1, min(request.args.get('limit', 20, type=int), 500))
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''SELECT id, client_id, timestamp, alert_level, message
                 FROM alerts 
                 ORDER BY timestamp DESC 
                 LIMIT ?''', (limit,))
    
    alerts = []
    for row in c.fetchall():
        alerts.append({
            'id': row[0],
            'client_id': row[1],
            'timestamp': row[2],
            'alert_level': row[3],
            'message': row[4]
        })
    
    conn.close()
    
    return jsonify({'alerts': alerts, 'total': len(alerts)})

@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan_detail(scan_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT scan_data FROM scans WHERE id = ?', (scan_id,))
    row = c.fetchone()
    conn.close()
    
    if row:
        return jsonify(json.loads(row[0]))
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM scans')
    total_scans = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM alerts')
    total_alerts = c.fetchone()[0]
    
    c.execute('SELECT COUNT(DISTINCT client_id) FROM scans')
    total_clients = c.fetchone()[0]
    
    c.execute('''SELECT risk_level, COUNT(*) 
                 FROM scans 
                 GROUP BY risk_level''')
    risk_distribution = dict(c.fetchall())
    
    conn.close()
    
    return jsonify({
        'total_scans': total_scans,
        'total_alerts': total_alerts,
        'total_clients': total_clients,
        'risk_distribution': risk_distribution
    })

@app.route('/')
def index():
    return '''
    <html>
    <head><title>Ransomware Audit Central Server</title></head>
    <body style="font-family: Arial; max-width: 800px; margin: 50px auto;">
        <h1>Ransomware Audit Central Server</h1>
        <p>Server is running. Available endpoints:</p>
        <ul>
            <li>GET /api/health - Health check</li>
            <li>POST /api/submit_scan - Submit a scan report</li>
            <li>GET /api/scans - Get recent scans</li>
            <li>GET /api/alerts - Get recent alerts</li>
            <li>GET /api/scan/&lt;id&gt; - Get scan details</li>
            <li>GET /api/stats - Get statistics</li>
        </ul>
    </body>
    </html>
    '''

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Ransomware Audit Central Server")
    parser.add_argument('--host', default=os.environ.get('RA_HOST', '127.0.0.1'),
                        help='Host to bind to (use 0.0.0.0 to accept other machines)')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("RANSOMWARE AUDIT CENTRAL SERVER")
    print("="*70)
    print(f"[*] Initializing database...")
    init_db()
    print(f"[+] Database initialized")
    print(f"[*] Starting server on {args.host}:{args.port}")
    print(f"[*] API endpoints available at http://{args.host}:{args.port}/api/")
    if not os.environ.get("RA_SERVER_TOKEN"):
        print(f"[*] Client token (set RA_SERVER_TOKEN on clients): {API_TOKEN}")
    print("="*70 + "\n")
    
    app.run(host=args.host, port=args.port, debug=False)

if __name__ == '__main__':
    main()
