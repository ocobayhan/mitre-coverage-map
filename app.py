from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, render_template, g

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "soc.db"
MITRE_PATH = DATA_DIR / "mitre.json"
SEED_RULES_PATH = DATA_DIR / "rules_seed.json"
LEGACY_SOC_HTML = BASE_DIR / "SOC.html"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_MIMETYPE"] = "application/json; charset=utf-8"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    try:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                tech TEXT NOT NULL,
                source TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mitigation_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL,
                mitigation_id TEXT NOT NULL,
                checked INTEGER NOT NULL DEFAULT 0,
                comment TEXT NOT NULL DEFAULT "",
                UNIQUE(technique_id, mitigation_id)
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                color TEXT NOT NULL
            );
            """
        )
        db.commit()
        ensure_products(db)
    finally:
        db.close()



def ensure_products(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT COUNT(*) AS cnt FROM products").fetchone()[0]
    if existing:
        return
    defaults = [
        ("QRadar", "#2e7d32"),
        ("DFE", "#1565c0"),
        ("DefO365", "#ef6c00"),
        ("DefIdentity", "#6a1b9a"),
        ("Other", "#546e7a"),
    ]
    db.executemany("INSERT INTO products (name, color) VALUES (?, ?)", defaults)
    db.commit()


def _load_seed_rules() -> list[dict[str, Any]]:
    if SEED_RULES_PATH.exists():
        try:
            return json.loads(SEED_RULES_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []

    if LEGACY_SOC_HTML.exists():
        try:
            text = LEGACY_SOC_HTML.read_text(encoding="utf-8", errors="ignore")
            match = None
            import re
            match = re.search(r"let\s+userRules\s*=\s*(\[.*?\]);", text, re.S)
            if not match:
                return []
            return json.loads(match.group(1))
        except Exception:
            return []

    return []


def _reseed_rules(db: sqlite3.Connection) -> int:
    rules = _load_seed_rules()
    inserted = 0
    for r in rules:
        name = (r.get("name") or "").strip()
        tactic = (r.get("tactic") or "").strip()
        tech = (r.get("tech") or "").strip()
        source = (r.get("source") or "").strip() or "Other"
        if not name or not tactic or not tech:
            continue
        db.execute(
            "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
            (name, tactic, tech, source),
        )
        inserted += 1
    db.commit()
    return inserted


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/mitre")
def mitre_json():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found. Place mitre.json in data/mitre.json."}), 500
    try:
        with MITRE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": f"MITRE data load failed: {exc}"}), 500


@app.route("/api/rules", methods=["GET", "POST"])
def rules():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT id, name, tactic, tech, source FROM rules ORDER BY id ASC").fetchall()
        return jsonify([dict(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    tactic = (payload.get("tactic") or "").strip()
    tech = (payload.get("tech") or "").strip()
    source = (payload.get("source") or "").strip()

    if not name or not tactic or not tech or not source:
        return jsonify({"error": "Missing fields: name, tactic, tech, source"}), 400

    cur = db.execute(
        "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
        (name, tactic, tech, source),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "tactic": tactic, "tech": tech, "source": source}), 201




@app.route("/api/rules/bulk", methods=["POST"])
def rules_bulk():
    db = get_db()
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "Missing CSV file"}), 400

    import csv
    try:
        content = file.read().decode("utf-8")
    except Exception:
        return jsonify({"error": "CSV must be UTF-8 encoded"}), 400

    reader = csv.DictReader(content.splitlines())
    required = {"name", "tactic", "tech", "source"}
    if not reader.fieldnames:
        return jsonify({"error": "CSV header must include: name,tactic,tech,source"}), 400

    header_map = {h.strip().lower(): h for h in reader.fieldnames}
    if not required.issubset(set(header_map.keys())):
        return jsonify({"error": "CSV header must include: name,tactic,tech,source"}), 400

    products = {r["name"]: True for r in db.execute("SELECT name FROM products").fetchall()}

    inserted = 0
    errors = []
    for i, row in enumerate(reader, start=2):
        norm = {k.strip().lower(): (v or "") for k, v in row.items()}
        name = norm.get("name", "").strip()
        tactic = norm.get("tactic", "").strip()
        tech = norm.get("tech", "").strip()
        source = norm.get("source", "").strip()
        if not name or not tactic or not tech or not source:
            errors.append(f"Satir {i}: eksik alan")
            continue
        if source not in products:
            errors.append(f"Satir {i}: kaynak bulunamadi ({source})")
            continue
        db.execute(
            "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
            (name, tactic, tech, source),
        )
        inserted += 1
    db.commit()
    return jsonify({"ok": True, "inserted": inserted, "errors": errors})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id: int):
    db = get_db()
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    db.commit()
    return jsonify({"ok": True})




@app.route("/api/products", methods=["GET", "POST"])
def products():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT id, name, color FROM products ORDER BY name ASC").fetchall()
        return jsonify([dict(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    color = (payload.get("color") or "").strip()
    if not name or not color:
        return jsonify({"error": "Missing fields: name, color"}), 400
    try:
        cur = db.execute("INSERT INTO products (name, color) VALUES (?, ?)", (name, color))
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Product already exists"}), 400
    return jsonify({"id": cur.lastrowid, "name": name, "color": color}), 201


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
def delete_product(product_id: int):
    db = get_db()
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
    return jsonify({"ok": True})




@app.route("/api/products/<int:product_id>", methods=["PUT"])
def update_product(product_id: int):
    db = get_db()
    payload = request.get_json(silent=True) or {}
    color = (payload.get("color") or "").strip()
    if not color:
        return jsonify({"error": "Missing fields: color"}), 400
    db.execute("UPDATE products SET color = ? WHERE id = ?", (color, product_id))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/mitigation-notes", methods=["GET", "POST"])
def mitigation_notes():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT technique_id, mitigation_id, checked, comment FROM mitigation_notes"
        ).fetchall()
        result = []
        for r in rows:
            result.append(
                {
                    "technique_id": r["technique_id"],
                    "mitigation_id": r["mitigation_id"],
                    "checked": bool(r["checked"]),
                    "comment": r["comment"],
                }
            )
        return jsonify(result)

    payload = request.get_json(silent=True) or {}
    technique_id = (payload.get("technique_id") or "").strip()
    mitigation_id = (payload.get("mitigation_id") or "").strip()
    checked = 1 if payload.get("checked") else 0
    comment = (payload.get("comment") or "").strip()

    if not technique_id or not mitigation_id:
        return jsonify({"error": "Missing fields: technique_id, mitigation_id"}), 400

    db.execute(
        """
        INSERT INTO mitigation_notes (technique_id, mitigation_id, checked, comment)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(technique_id, mitigation_id)
        DO UPDATE SET checked=excluded.checked, comment=excluded.comment
        """,
        (technique_id, mitigation_id, checked, comment),
    )
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/admin/reset", methods=["POST"])
def admin_reset():
    payload = request.get_json(silent=True) or {}
    confirm = (payload.get("confirm") or "").strip()
    reseed = bool(payload.get("reseed"))
    if confirm != "RESET":
        return jsonify({"error": "Confirmation required. Send confirm=RESET."}), 400

    db = get_db()
    db.execute("DELETE FROM mitigation_notes")
    db.execute("DELETE FROM rules")
    db.commit()

    inserted = 0
    if reseed:
        inserted = _reseed_rules(db)

    return jsonify({"ok": True, "reseeded": reseed, "inserted": inserted})


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    host = os.environ.get("SOC_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_PORT", "8000"))
    app.run(host=host, port=port, debug=True)
