from __future__ import annotations

import json
import os
import sqlite3
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request, render_template, g, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "soc.db"
MITRE_PATH = DATA_DIR / "mitre.json"
SEED_RULES_PATH = DATA_DIR / "rules_seed.json"
LEGACY_SOC_HTML = BASE_DIR / "SOC.html"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_MIMETYPE"] = "application/json; charset=utf-8"
app.secret_key = os.environ.get("SOC_SECRET_KEY", "change-this-in-production")


MITRE_CACHE = {"mtime": None, "data": None}
ROLE_LEVELS = {"viewer": 1, "editor": 2, "admin": 3}



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


def ensure_mitigation_team_column(db: sqlite3.Connection) -> None:
    cols = [r[1] for r in db.execute("PRAGMA table_info(mitigation_notes)").fetchall()]
    if "team" not in cols:
        db.execute("ALTER TABLE mitigation_notes ADD COLUMN team TEXT NOT NULL DEFAULT ''")
        db.commit()


def ensure_mitigation_global_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_global (
            mitigation_id TEXT PRIMARY KEY,
            checked INTEGER NOT NULL DEFAULT 0,
            comment TEXT NOT NULL DEFAULT "",
            team TEXT NOT NULL DEFAULT ""
        )
        """
    )
    db.commit()


def ensure_mitigation_global_seed(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT COUNT(*) AS cnt FROM mitigation_global").fetchone()[0]
    if existing:
        return
    rows = db.execute(
        "SELECT mitigation_id, checked, comment, team FROM mitigation_notes"
    ).fetchall()
    if not rows:
        return
    merged: dict[str, dict[str, Any]] = {}
    for r in rows:
        mid = r["mitigation_id"]
        checked = 1 if r["checked"] else 0
        comment = r["comment"] or ""
        team = r["team"] or ""
        if mid not in merged:
            merged[mid] = {"checked": checked, "comment": comment, "team": team}
            continue
        # prefer checked if any row checked
        merged[mid]["checked"] = max(merged[mid]["checked"], checked)
        # prefer longer comment/team if present
        if len(comment) > len(merged[mid]["comment"]):
            merged[mid]["comment"] = comment
        if len(team) > len(merged[mid]["team"]):
            merged[mid]["team"] = team
    db.executemany(
        "INSERT INTO mitigation_global (mitigation_id, checked, comment, team) VALUES (?, ?, ?, ?)",
        [(k, v["checked"], v["comment"], v["team"]) for k, v in merged.items()],
    )
    db.commit()


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
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
                team TEXT NOT NULL DEFAULT "",
                UNIQUE(technique_id, mitigation_id)
            );

            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                color TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mitigation_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mitigation_id TEXT NOT NULL,
                team TEXT NOT NULL DEFAULT "",
                comment TEXT NOT NULL DEFAULT ""
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('viewer','editor','admin')),
                is_active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        db.commit()
        ensure_mitigation_team_column(db)
        ensure_mitigation_global_table(db)
        ensure_mitigation_global_seed(db)
        ensure_products(db)
        ensure_users(db)
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


def ensure_users(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT COUNT(*) AS cnt FROM users").fetchone()[0]
    if existing:
        return
    defaults = [
        ("admin", generate_password_hash("Admin123!"), "admin", 1),
        ("editor", generate_password_hash("Editor123!"), "editor", 1),
        ("viewer", generate_password_hash("Viewer123!"), "viewer", 1),
    ]
    db.executemany(
        "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, ?)",
        defaults,
    )
    db.commit()


def get_current_user() -> dict[str, Any] | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, is_active FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row or not row["is_active"]:
        session.clear()
        return None
    return dict(row)


def write_audit_log(
    db: sqlite3.Connection,
    action: str,
    target_type: str,
    target_id: str = "",
    detail: str = "",
    user: dict[str, Any] | None = None,
) -> None:
    actor = user or getattr(g, "current_user", None)
    user_id = actor["id"] if actor else None
    username = actor["username"] if actor else ""
    db.execute(
        """
        INSERT INTO audit_logs (user_id, username, action, target_type, target_id, detail)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, username, action, target_type, target_id, detail),
    )


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login_page"))
        g.current_user = user
        return fn(*args, **kwargs)

    return wrapper


def role_required(min_role: str):
    min_level = ROLE_LEVELS[min_role]

    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user = g.current_user
            level = ROLE_LEVELS.get(user["role"], 0)
            if level < min_level:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator




def _minify_mitre(raw: dict) -> dict:
    objects = raw.get("objects", [])
    out = {"objects": []}
    for obj in objects:
        t = obj.get("type")
        if t == "attack-pattern":
            out["objects"].append({
                "type": "attack-pattern",
                "id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "x_mitre_is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                "external_references": obj.get("external_references", []),
                "revoked": obj.get("revoked", False),
                "x_mitre_deprecated": obj.get("x_mitre_deprecated", False),
            })
        elif t == "course-of-action":
            out["objects"].append({
                "type": "course-of-action",
                "id": obj.get("id"),
                "name": obj.get("name"),
                "description": obj.get("description"),
                "external_references": obj.get("external_references", []),
                "revoked": obj.get("revoked", False),
                "x_mitre_deprecated": obj.get("x_mitre_deprecated", False),
            })
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            out["objects"].append({
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": obj.get("source_ref"),
                "target_ref": obj.get("target_ref"),
            })
    return out


def get_minified_mitre() -> dict:
    if not MITRE_PATH.exists():
        raise FileNotFoundError("MITRE data not found")
    mtime = MITRE_PATH.stat().st_mtime
    if MITRE_CACHE["data"] is None or MITRE_CACHE["mtime"] != mtime:
        raw = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
        MITRE_CACHE["data"] = _minify_mitre(raw)
        MITRE_CACHE["mtime"] = mtime
    return MITRE_CACHE["data"]


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
            (name, tactic, tech, source)
        )
        inserted += 1
    db.commit()
    return inserted


@app.route("/")
@login_required
def index() -> str:
    return render_template("index.html")


@app.route("/login")
def login_page() -> str:
    user = get_current_user()
    if user:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def login_api():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Missing fields: username, password"}), 400
    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    session.clear()
    session["user_id"] = row["id"]
    write_audit_log(
        db,
        action="login",
        target_type="session",
        target_id=str(row["id"]),
        detail="Login successful",
        user={"id": row["id"], "username": row["username"]},
    )
    db.commit()
    return jsonify({"ok": True, "user": {"id": row["id"], "username": row["username"], "role": row["role"]}})


@app.route("/api/logout", methods=["POST"])
@login_required
def logout_api():
    db = get_db()
    write_audit_log(db, action="logout", target_type="session", detail="Logout")
    db.commit()
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
@login_required
def me():
    user = g.current_user
    return jsonify({"id": user["id"], "username": user["username"], "role": user["role"]})




@app.route("/api/mitre-min")
@role_required("viewer")
def mitre_min():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found. Place mitre.json in data/mitre.json."}), 500
    try:
        return jsonify(get_minified_mitre())
    except Exception as exc:
        return jsonify({"error": f"MITRE data load failed: {exc}"}), 500


@app.route("/api/mitre")
@role_required("viewer")
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
@role_required("viewer")
def rules():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT id, name, tactic, tech, source FROM rules ORDER BY id ASC").fetchall()
        return jsonify([dict(r) for r in rows])

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    tactic = (payload.get("tactic") or "").strip()
    tech = (payload.get("tech") or "").strip()
    source = (payload.get("source") or "").strip()

    if not name or not tactic or not tech or not source:
        return jsonify({"error": "Missing fields: name, tactic, tech, source"}), 400

    cur = db.execute(
        "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
        (name, tactic, tech, source)
    )
    write_audit_log(
        db,
        action="create",
        target_type="rule",
        target_id=str(cur.lastrowid),
        detail=f"name={name};tech={tech};source={source}",
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "tactic": tactic, "tech": tech, "source": source}), 201




@app.route("/api/rules/bulk", methods=["POST"])
@role_required("editor")
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
            (name, tactic, tech, source)
        )
        inserted += 1
    write_audit_log(
        db,
        action="bulk_create",
        target_type="rule",
        detail=f"inserted={inserted};errors={len(errors)}",
    )
    db.commit()
    return jsonify({"ok": True, "inserted": inserted, "errors": errors})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@role_required("editor")
def delete_rule(rule_id: int):
    db = get_db()
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    write_audit_log(db, action="delete", target_type="rule", target_id=str(rule_id))
    db.commit()
    return jsonify({"ok": True})




@app.route("/api/products", methods=["GET", "POST"])
@role_required("viewer")
def products():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("SELECT id, name, color FROM products ORDER BY name ASC").fetchall()
        return jsonify([dict(r) for r in rows])

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["admin"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    color = (payload.get("color") or "").strip()
    if not name or not color:
        return jsonify({"error": "Missing fields: name, color"}), 400
    try:
        cur = db.execute("INSERT INTO products (name, color) VALUES (?, ?)", (name, color))
        write_audit_log(
            db,
            action="create",
            target_type="product",
            target_id=str(cur.lastrowid),
            detail=f"name={name};color={color}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Product already exists"}), 400
    return jsonify({"id": cur.lastrowid, "name": name, "color": color}), 201


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@role_required("admin")
def delete_product(product_id: int):
    db = get_db()
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    write_audit_log(db, action="delete", target_type="product", target_id=str(product_id))
    db.commit()
    return jsonify({"ok": True})




@app.route("/api/products/<int:product_id>", methods=["PUT"])
@role_required("admin")
def update_product(product_id: int):
    db = get_db()
    payload = request.get_json(silent=True) or {}
    color = (payload.get("color") or "").strip()
    if not color:
        return jsonify({"error": "Missing fields: color"}), 400
    db.execute("UPDATE products SET color = ? WHERE id = ?", (color, product_id))
    write_audit_log(
        db,
        action="update",
        target_type="product",
        target_id=str(product_id),
        detail=f"color={color}",
    )
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/mitigation-notes", methods=["GET", "POST"])
@role_required("viewer")
def mitigation_notes():
    db = get_db()
    if request.method == "GET":
        ensure_mitigation_global_table(db)
        ensure_mitigation_global_seed(db)
        rows = db.execute(
            "SELECT mitigation_id, checked, comment, team FROM mitigation_global"
        ).fetchall()
        result = []
        for r in rows:
            result.append(
                {
                    "mitigation_id": r["mitigation_id"],
                    "checked": bool(r["checked"]),
                    "comment": r["comment"],
                    "team": r["team"],
                }
            )
        return jsonify(result)

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    mitigation_id = (payload.get("mitigation_id") or "").strip()
    checked = 1 if payload.get("checked") else 0
    comment = (payload.get("comment") or "").strip()
    team = (payload.get("team") or "").strip()

    if not mitigation_id:
        return jsonify({"error": "Missing fields: mitigation_id"}), 400

    ensure_mitigation_global_table(db)
    db.execute(
        """
        INSERT INTO mitigation_global (mitigation_id, checked, comment, team)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(mitigation_id)
        DO UPDATE SET checked=excluded.checked, comment=excluded.comment, team=excluded.team
        """,
        (mitigation_id, checked, comment, team),
    )
    write_audit_log(
        db,
        action="upsert",
        target_type="mitigation_note",
        target_id=mitigation_id,
        detail=f"checked={checked};team={team}",
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/mitigation-entries", methods=["GET", "POST"])
@role_required("viewer")
def mitigation_entries():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, mitigation_id, team, comment FROM mitigation_entries ORDER BY id ASC"
        ).fetchall()
        result = []
        for r in rows:
            result.append(
                {
                    "id": r["id"],
                    "mitigation_id": r["mitigation_id"],
                    "team": r["team"],
                    "comment": r["comment"],
                }
            )
        return jsonify(result)

    if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True) or {}
    mitigation_id = (payload.get("mitigation_id") or "").strip()
    team = (payload.get("team") or "").strip()
    comment = (payload.get("comment") or "").strip()
    if not mitigation_id or not team or not comment:
        return jsonify({"error": "Missing fields: mitigation_id, team, comment"}), 400

    cur = db.execute(
        "INSERT INTO mitigation_entries (mitigation_id, team, comment) VALUES (?, ?, ?)",
        (mitigation_id, team, comment),
    )
    write_audit_log(
        db,
        action="create",
        target_type="mitigation_entry",
        target_id=str(cur.lastrowid),
        detail=f"mitigation_id={mitigation_id};team={team}",
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "mitigation_id": mitigation_id, "team": team, "comment": comment}), 201


@app.route("/api/mitigation-entries/<int:entry_id>", methods=["DELETE"])
@role_required("editor")
def delete_mitigation_entry(entry_id: int):
    db = get_db()
    db.execute("DELETE FROM mitigation_entries WHERE id = ?", (entry_id,))
    write_audit_log(
        db,
        action="delete",
        target_type="mitigation_entry",
        target_id=str(entry_id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/users", methods=["GET", "POST"])
@role_required("admin")
def users_api():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, username, role, is_active FROM users ORDER BY username ASC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = (payload.get("password") or "").strip()
    role = (payload.get("role") or "").strip()
    if not username or not password or role not in ROLE_LEVELS:
        return jsonify({"error": "Missing/invalid fields: username, password, role"}), 400

    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role, is_active) VALUES (?, ?, ?, 1)",
            (username, generate_password_hash(password), role),
        )
        write_audit_log(
            db,
            action="create",
            target_type="user",
            target_id=str(cur.lastrowid),
            detail=f"username={username};role={role}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400

    return jsonify({"id": cur.lastrowid, "username": username, "role": role, "is_active": 1}), 201


@app.route("/api/users/<int:user_id>", methods=["PUT"])
@role_required("admin")
def users_update_api(user_id: int):
    db = get_db()
    row = db.execute("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    payload = request.get_json(silent=True) or {}
    next_role = (payload.get("role") or row["role"]).strip()
    is_active = payload.get("is_active")
    new_password = (payload.get("password") or "").strip()

    if next_role not in ROLE_LEVELS:
        return jsonify({"error": "Invalid role"}), 400
    if is_active is None:
        is_active = row["is_active"]
    is_active = 1 if bool(is_active) else 0

    if user_id == g.current_user["id"] and is_active == 0:
        return jsonify({"error": "You cannot deactivate your own account"}), 400

    db.execute(
        "UPDATE users SET role = ?, is_active = ? WHERE id = ?",
        (next_role, is_active, user_id),
    )
    if new_password:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id),
        )
    write_audit_log(
        db,
        action="update",
        target_type="user",
        target_id=str(user_id),
        detail=f"role={next_role};is_active={is_active};password_changed={bool(new_password)}",
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/audit-logs", methods=["GET"])
@role_required("admin")
def audit_logs_api():
    db = get_db()
    limit_raw = request.args.get("limit", "200")
    try:
        limit = max(1, min(1000, int(limit_raw)))
    except ValueError:
        limit = 200

    rows = db.execute(
        """
        SELECT id, user_id, username, action, target_type, target_id, detail, created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/reset", methods=["POST"])
@role_required("admin")
def admin_reset():
    payload = request.get_json(silent=True) or {}
    confirm = (payload.get("confirm") or "").strip()
    reseed = bool(payload.get("reseed"))
    if confirm != "RESET":
        return jsonify({"error": "Confirmation required. Send confirm=RESET."}), 400

    db = get_db()
    db.execute("DELETE FROM mitigation_notes")
    db.execute("DELETE FROM mitigation_global")
    db.execute("DELETE FROM mitigation_entries")
    db.execute("DELETE FROM rules")
    db.commit()

    inserted = 0
    if reseed:
        inserted = _reseed_rules(db)

    write_audit_log(
        db,
        action="reset",
        target_type="admin",
        detail=f"reseed={reseed};inserted={inserted}",
    )
    db.commit()

    return jsonify({"ok": True, "reseeded": reseed, "inserted": inserted})


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    host = os.environ.get("SOC_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_PORT", "8000"))
    app.run(host=host, port=port, debug=True)
