import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(__file__), "threats.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            domain TEXT,
            risk TEXT,
            score INTEGER,
            entropy REAL,
            flags TEXT,
            client_ip TEXT
        )
    ''')
    conn.commit()
    conn.close()

def write_threat(domain_result):
    """Writes a threat to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    flags_str = ",".join(domain_result.get('flags', []))
    cursor.execute('''
        INSERT INTO detections (timestamp, domain, risk, score, entropy, flags, client_ip)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        domain_result['timestamp'],
        domain_result['domain'],
        domain_result['risk'],
        domain_result['score'],
        domain_result['entropy'],
        flags_str,
        domain_result.get('client_ip', 'Unknown')
    ))
    conn.commit()
    conn.close()

def get_threats():
    """Returns all recorded threats."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM detections ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    
    threats = []
    for row in rows:
        threats.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "domain": row["domain"],
            "risk": row["risk"],
            "score": row["score"],
            "entropy": row["entropy"],
            "flags": row["flags"].split(",") if row["flags"] else [],
            "client_ip": row["client_ip"]
        })
    return threats

def get_stats():
    """Returns counts of detected threats grouped by risk level."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT risk, COUNT(*) FROM detections GROUP BY risk')
    rows = cursor.fetchall()
    conn.close()
    
    stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in rows:
        stats[row[0]] = row[1]
    return stats
