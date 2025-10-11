import sqlite3
import json
import uuid
from datetime import datetime
from pathlib import Path

DB_PATH = Path('data/results.db')
DB_PATH.parent.mkdir(exist_ok=True)

SCHEMA = '''
CREATE TABLE IF NOT EXISTS results (
    id TEXT PRIMARY KEY,
    target TEXT,
    created_at TEXT,
    summary TEXT,
    score INTEGER,
    scan_type TEXT,
    details TEXT
);
'''

def init_db(app=None):
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()

def save_result(result: dict):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('INSERT INTO results (id, target, created_at, summary, score, scan_type, details) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (result['id'], result['target'], result['created_at'], result['summary'], result['score'], result.get('scan_type', 'general'), json.dumps(result['details'])))
    conn.commit()
    conn.close()

def list_results():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, target, created_at, summary, score, scan_type FROM results ORDER BY created_at DESC')
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({'id': r[0], 'target': r[1], 'created_at': r[2], 'summary': r[3], 'score': r[4], 'scan_type': r[5] or 'general'})
    return out

def get_result(rid):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('SELECT id, target, created_at, summary, score, scan_type, details FROM results WHERE id=?', (rid,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    import json
    return {'id': r[0], 'target': r[1], 'created_at': r[2], 'summary': r[3], 'score': r[4], 'scan_type': r[5] or 'general', 'details': json.loads(r[6])}

