import os
import sqlite3

DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "alerts.db")

def get_db_connection():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT NOT NULL,
            flag TEXT NOT NULL,
            src_bytes INTEGER NOT NULL,
            dst_bytes INTEGER NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            priority_score INTEGER NOT NULL,
            priority_level TEXT NOT NULL,
            priority_reason TEXT,
            playbook_action TEXT,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            src_port INTEGER,
            dest_port INTEGER
        )
    """)
    conn.commit()
    conn.close()
    print("Database alerts table initialized successfully.")

def insert_alerts(alerts_list):
    if not alerts_list:
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        INSERT INTO alerts (
            timestamp, protocol, service, flag, src_bytes, dst_bytes,
            prediction, confidence, priority_score, priority_level,
            priority_reason, playbook_action, source_ip, dest_ip, src_port, dest_port
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    records = []
    for a in alerts_list:
        records.append((
            a.get('timestamp'),
            a.get('protocol'),
            a.get('service'),
            a.get('flag'),
            a.get('src_bytes', 0),
            a.get('dst_bytes', 0),
            a.get('prediction'),
            a.get('confidence'),
            a.get('priority_score', 0),
            a.get('priority_level'),
            a.get('priority_reason'),
            a.get('playbook_action'),
            a.get('source_ip', '0.0.0.0'),
            a.get('dest_ip', '0.0.0.0'),
            a.get('src_port'),
            a.get('dest_port')
        ))
        
    cursor.executemany(query, records)
    conn.commit()
    conn.close()

def get_alerts(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    alerts = []
    for r in rows:
        alerts.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "protocol": r["protocol"],
            "service": r["service"],
            "flag": r["flag"],
            "src_bytes": r["src_bytes"],
            "dst_bytes": r["dst_bytes"],
            "prediction": r["prediction"],
            "confidence": r["confidence"],
            "priority_score": r["priority_score"],
            "priority_level": r["priority_level"],
            "priority_reason": r["priority_reason"],
            "playbook_action": r["playbook_action"],
            "source_ip": r["source_ip"],
            "dest_ip": r["dest_ip"],
            "src_port": r["src_port"],
            "dest_port": r["dest_port"]
        })
    return alerts
