import json
import re
import sqlite3
from pathlib import Path

BASE = Path(__file__).resolve().parent
SOC_HTML = BASE / 'SOC.html'
DB_PATH = BASE / 'soc.db'

if not SOC_HTML.exists():
    raise SystemExit('SOC.html not found')

text = SOC_HTML.read_text(encoding='utf-8', errors='ignore')
match = re.search(r'let\s+userRules\s*=\s*(\[.*?\]);', text, re.S)
if not match:
    raise SystemExit('userRules array not found')

raw = match.group(1)
try:
    rules = json.loads(raw)
except Exception as exc:
    raise SystemExit(f'JSON parse failed: {exc}')

conn = sqlite3.connect(DB_PATH)
try:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            tactic TEXT NOT NULL,
            tech TEXT NOT NULL,
            source TEXT NOT NULL
        );
        """
    )
    cur = conn.cursor()
    inserted = 0
    for r in rules:
        name = (r.get('name') or '').strip()
        tactic = (r.get('tactic') or '').strip()
        tech = (r.get('tech') or '').strip()
        source = (r.get('source') or '').strip() or 'Other'
        if not name or not tactic or not tech:
            continue
        cur.execute(
            'INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)',
            (name, tactic, tech, source),
        )
        inserted += 1
    conn.commit()
    print(f'Inserted {inserted} rules')
finally:
    conn.close()
