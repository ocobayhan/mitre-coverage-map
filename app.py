from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, render_template, g, session, redirect, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from qradar_connector import QRadarClient, QRadarConnectorError

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", str(BASE_DIR / "data")))
DB_PATH = Path(os.environ.get("SOC_DB_PATH", str(BASE_DIR / "soc.db")))
MITRE_PATH = DATA_DIR / "mitre.json"
SEED_RULES_PATH = DATA_DIR / "rules_seed.json"

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False
app.config["JSONIFY_MIMETYPE"] = "application/json; charset=utf-8"
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SOC_COOKIE_SECURE", "0") == "1"
app.secret_key = os.environ.get("SOC_SECRET_KEY", "change-this-in-production")


MITRE_CACHE = {"mtime": None, "data": None}
THREAT_ACTOR_CACHE: dict[str, Any] = {"mtime": None, "data": None}
TTP_LIST_CACHE: dict[str, Any] = {"data": None, "dirty": True}
LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_ATTEMPTS_LOCK = threading.Lock()
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_FAILURES = 5
ROLE_LEVELS = {"viewer": 1, "editor": 2, "admin": 3}

# Urun kategorileri — haritayi yalnizca tespit kaynaklari boyar.
#   tespit_kaynagi   : alarm/kural uretir, ATT&CK teknigine eslenir (QRadar, DFE, DFI, Wazuh...)
#   onleyici_kontrol : teknigi zorlastirir ama tespit uretmez (firewall, AV, yama, MFA)
#   zenginlestirme   : onceliklendirmeyi besler, kapsamayi degil (CTI)
PRODUCT_CATEGORIES = ("tespit_kaynagi", "onleyici_kontrol", "zenginlestirme")
PRODUCT_CATEGORY_DEFAULT = "tespit_kaynagi"

# Bir teknik icin "yeterli kapsama" sayilacak tespit sayisi. Tum teknikler bu
# degerle baslar; admin teknik bazinda degistirebilir (technique_config).
# static/app.js DEFAULT_RULE_THRESHOLD ile ayni olmali.
DEFAULT_RULE_THRESHOLD = 2

# Urun seviyesi toplu iddia (origin='product_claim') hucre skoruna tam degil,
# indirimli agirlikla katkida bulunur. Adi olan gercek tespiti (named) olmayan
# bir teknik artik yalnizca toplu iddiayla %100 skor gosteremez — "Tespit"
# kovasi zaten sert kanit istiyordu (bkz. ensure_rule_origin()), skor bu
# degisiklikten once ayni tekniğe tam kredi veriyordu ve ikisi celisiyordu.
# Kullanici karari (2026-07-29). static/app.js PRODUCT_CLAIM_SCORE_WEIGHT ile
# ayni olmali.
PRODUCT_CLAIM_SCORE_WEIGHT = 0.75

# Ozet "Ortalama Skor" (genel + taktik bazli) artik esik-agirlikli ortalama:
# her tekniğin katkisi kendi rule_threshold'uyla orantili — "gerekli değil"
# (0) isaretli teknikler zaten agirliksiz kalir, cok tespit gerektiren
# teknikler ortalamayi daha fazla etkiler. Alt teknikler dahil olur ama daha
# dusuk carpanla (kurallar neredeyse tamamen ana teknige eslendigi icin
# agirliksiz dahil etmek ortalamayi yapay dusururdu). Kullanici karari
# (2026-07-29). static/app.js SUBTECHNIQUE_AVG_WEIGHT ile ayni olmali.
SUBTECHNIQUE_AVG_WEIGHT = 0.3

# rules.source ile products.name arasinda FK yok; kopru yalnizca isim esitligi.
# Eslesmeyen bir kaynak, ortam bazli kapsama hesabinda hicbir varlik grubuna
# baglanamaz ve teknik sessizce kapsanmamis gorunur — bu yuzden yazma aninda
# reddedilir (bkz. docs/rbac.md, PROJECT_STATE.md Faz 2).
_UNKNOWN_SOURCE_ERROR = (
    "'{source}' urun katalogunda yok. Once Ayarlar > Urun Yonetimi'nden ekleyin; "
    "aksi halde tespit hicbir ortamda kapsama saglamaz."
)
TECHNIQUE_NAME_ALIASES = {
    "data from cloud storage object": "T1530",
    "remote access software": "T1219",
}
AUDIT_COLUMNS = {
    "request_id": "TEXT NOT NULL DEFAULT ''",
    "ip_address": "TEXT NOT NULL DEFAULT ''",
    "user_agent": "TEXT NOT NULL DEFAULT ''",
    "before_json": "TEXT NOT NULL DEFAULT ''",
    "after_json": "TEXT NOT NULL DEFAULT ''",
    "prev_hash": "TEXT NOT NULL DEFAULT ''",
    "entry_hash": "TEXT NOT NULL DEFAULT ''",
}

# ATT&CK v19 (Nisan 2026): eski "Defense Evasion" (TA0005) ikiye ayrildi —
# ayni TA0005 ID'si "Stealth" oldu, yeni TA0112 "Defense Impairment" eklendi.
# Sira MITRE'nin resmi matrisiyle ayni: Stealth, sonra Defense Impairment.
_TACTIC_LABEL_MAP: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "stealth": "Stealth",
    "defense-impairment": "Defense Impairment",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


@app.before_request
def assign_request_id() -> None:
    supplied = request.headers.get("X-Request-ID", "").strip()
    g.request_id = supplied[:128] if supplied else uuid.uuid4().hex


@app.after_request
def add_security_headers(response: Response) -> Response:
    response.headers["X-Request-ID"] = getattr(g, "request_id", "")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else response.headers.get("Cache-Control", "no-cache")
    return response


def _login_attempt_key(username: str) -> str:
    return f"{request.remote_addr or '-'}|{username.casefold()}"


def _login_is_limited(key: str) -> bool:
    cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
    with LOGIN_ATTEMPTS_LOCK:
        attempts = LOGIN_ATTEMPTS[key]
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        return len(attempts) >= LOGIN_MAX_FAILURES


def _record_login_failure(key: str) -> None:
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS[key].append(time.monotonic())


def _clear_login_failures(key: str) -> None:
    with LOGIN_ATTEMPTS_LOCK:
        LOGIN_ATTEMPTS.pop(key, None)



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


def drop_legacy_mitigation_tables(db: sqlite3.Connection) -> None:
    """mitigation_notes ve mitigation_global tablolarini dusurur.

    Ikisi de olu agirlikti: bir mitigation'in "isaretli" olmasi zaten
    mitigation_entries'te kaydi olmasindan tureniyordu, comment/team alanlari
    ise hicbir kurulumda doldurulmamisti. Iki paralel gercek kaynagi yerine
    tek kaynak birakiliyor: mitigation_entries.
    """
    db.execute("DROP TABLE IF EXISTS mitigation_global")
    db.execute("DROP TABLE IF EXISTS mitigation_notes")
    db.commit()


def ensure_mitigation_entry_product(db: sqlite3.Connection) -> None:
    """mitigation_entries.product_id — mitigation'i hangi urunle sagliyoruz.

    NULL = urun disi (surec, egitim, politika). FK products(id) uzerine.
    """
    cols = [r[1] for r in db.execute("PRAGMA table_info(mitigation_entries)").fetchall()]
    if "product_id" not in cols:
        db.execute(
            "ALTER TABLE mitigation_entries ADD COLUMN product_id INTEGER REFERENCES products(id)"
        )
        db.commit()


def ensure_action_items_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS action_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tech_id TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            priority INTEGER NOT NULL DEFAULT 2
                CHECK(priority IN (1, 2, 3, 4)),
            status TEXT NOT NULL DEFAULT 'open'
                CHECK(status IN ('open','in_progress','done','cancelled')),
            assigned_team_id INTEGER,
            due_date TEXT,
            created_by_username TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


def ensure_teams_table(db: sqlite3.Connection) -> None:
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


# ── Migration: Kural Birleştirme ─────────────────────────────────────────────
# CSV import veya bulk add sırasında aynı (name, source) çiftine sahip birden
# fazla satır oluşabilir. Bu fonksiyon ilk çalıştığında:
#   1. Aynı (name, source) olan satırları tespit eder.
#   2. En küçük id'yi "canonical" kural olarak tutar; diğerlerini siler.
#   3. Silinen kuralların rule_techniques kayıtlarını canonical kurala taşır.
#   4. idx_rules_name_source UNIQUE index ekler → gelecekte çift kural oluşmaz.
# Idempotent: index zaten varsa hiçbir şey yapmaz.
def migrate_consolidate_rules(db: sqlite3.Connection) -> None:
    """Merge duplicate (name, source) rules into one row, combining techniques."""
    indexes = [r[1] for r in db.execute("PRAGMA index_list(rules)").fetchall()]
    if "idx_rules_name_source" in indexes:
        return
    groups = db.execute(
        "SELECT name, source FROM rules GROUP BY name, source HAVING COUNT(*) > 1"
    ).fetchall()
    for g in groups:
        rows = db.execute(
            "SELECT id, tech FROM rules WHERE name=? AND source=? ORDER BY id ASC",
            (g["name"], g["source"])
        ).fetchall()
        keep_id = rows[0]["id"]
        for dup in rows[1:]:
            if dup["tech"]:
                db.execute(
                    "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?,?)",
                    (keep_id, dup["tech"])
                )
            for t in db.execute(
                "SELECT tech_id FROM rule_techniques WHERE rule_id=?", (dup["id"],)
            ).fetchall():
                db.execute(
                    "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?,?)",
                    (keep_id, t["tech_id"])
                )
            db.execute("DELETE FROM rule_techniques WHERE rule_id=?", (dup["id"],))
            db.execute("DELETE FROM rules WHERE id=?", (dup["id"],))
    db.commit()
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_name_source ON rules(name, source)"
    )
    db.commit()


# ── Migration: rules.tech → rule_techniques ──────────────────────────────────
# Eski şema rules.tech TEXT sütunuyla tek teknik tutuyordu. Bu migration
# mevcut rules satırlarından rule_techniques join tablosuna veri kopyalar.
# Idempotent: tabloda kayıt varsa atlanır.
def migrate_rule_techniques(db: sqlite3.Connection) -> None:
    existing = db.execute("SELECT rule_id FROM rule_techniques LIMIT 1").fetchone()
    if existing:
        return  # already migrated
    rows = db.execute("SELECT id, tech FROM rules").fetchall()
    for r in rows:
        db.execute(
            "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
            (r["id"], r["tech"])
        )
    db.commit()


def drop_technique_importance(db: sqlite3.Connection) -> None:
    """technique_config.importance sutununu kaldirir (idempotent).

    "Onem seviyesi" kavrami opak ve yonetilemezdi (0.3-1.0 arasi, mitre.json'daki
    grup/arac sayilarindan turetiliyordu); kaldirildi. Ayni migration'da
    otomatik hesaplanmis rule_threshold degerleri de tek varsayilana cekilir —
    eski degerler (1-5) artik anlamini yitirmis auto-turetimlerdi. Admin'in elle
    ayarladiklari (source='admin') korunur.
    """
    cols = {r[1] for r in db.execute("PRAGMA table_info(technique_config)").fetchall()}
    if "importance" not in cols:
        return
    db.execute("ALTER TABLE technique_config DROP COLUMN importance")
    db.execute(
        "UPDATE technique_config SET rule_threshold=? WHERE source='auto'",
        (DEFAULT_RULE_THRESHOLD,),
    )
    db.commit()


def build_technique_config(db: sqlite3.Connection) -> None:
    """Teknik bazli hedef tespit sayisini ve MITRE kullanim sayaclarini kurar.

    Hedef (rule_threshold) her teknik icin ayni degerle (DEFAULT_RULE_THRESHOLD)
    baslar; admin dilerse teknik bazinda degistirir. Onceden hem bu hedef hem de
    bir "onem" puani mitre.json'daki grup/arac iliskilerinden otomatik
    turetiliyordu — opak ve yonetilemez oldugu icin kaldirildi (Faz 4 karari).

    group_count / tool_count bilgi olarak korunur: tespitsiz teknikleri
    onceliklendirirken "kac tehdit grubu bu teknigi kullaniyor" objektif bir
    sinyal saglar. Bu bir ayar degildir, siralama icin veridir.

    Idempotent ama "sadece bir kez calis" DEGIL: MITRE veri seti guncellenip
    (mitre.json degisip) init_db() tekrar calistiginda eksik tech_id'leri
    ekler — INSERT OR IGNORE, tech_id PRIMARY KEY oldugu icin var olan
    satirlar (admin override'lari dahil) asla ezilmez. Eskiden "source='auto'
    satiri varsa hic calisma" seklinde tek seferlik bir korumasi vardi; bu,
    MITRE bir surum atlayip yeni teknik ekledigi zaman (orn. v19'daki
    Defense Impairment/Stealth ayrimi, T1685/T1686) yeni tekniklerin sessizce
    taninmamasina yol aciyordu — kok neden buydu, korumayi kaldirdik.
    """
    if not MITRE_PATH.exists():
        return  # no mitre data available yet

    data = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    objects = data.get("objects", [])

    # Map STIX id → T-code for non-deprecated attack-patterns
    tech_stix: dict[str, str] = {}
    group_stix: set[str] = set()
    tool_stix: set[str] = set()

    for obj in objects:
        t = obj.get("type", "")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    eid = ref.get("external_id", "")
                    if eid.startswith("T"):
                        tech_stix[obj["id"]] = eid
        elif t == "intrusion-set":
            group_stix.add(obj["id"])
        elif t in ("malware", "tool"):
            tool_stix.add(obj["id"])

    # Count "uses" relationships per technique
    group_counts: dict[str, set[str]] = {}
    tool_counts: dict[str, set[str]] = {}

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        tid = tech_stix.get(tgt)
        if not tid:
            continue
        if src in group_stix:
            group_counts.setdefault(tid, set()).add(src)
        elif src in tool_stix:
            tool_counts.setdefault(tid, set()).add(src)

    # Her teknik ayni hedefle baslar; grup/arac sayaclari bilgi olarak yazilir.
    rows = [
        (tid, DEFAULT_RULE_THRESHOLD, "auto",
         len(group_counts.get(tid, set())), len(tool_counts.get(tid, set())))
        for _stix_id, tid in tech_stix.items()
    ]
    db.executemany(
        "INSERT OR IGNORE INTO technique_config "
        "(tech_id, rule_threshold, source, group_count, tool_count) VALUES (?,?,?,?,?)",
        rows,
    )
    db.commit()


def ensure_subtechnique_default_threshold(db: sqlite3.Connection) -> None:
    """Alt tekniklerin varsayilan tespit hedefini 1'e ceker (ana teknikler
    DEFAULT_RULE_THRESHOLD=2'de kalir).

    Kurallar neredeyse tamamen ana teknige eslendigi icin (475 alt teknikten
    yalnizca birkacinin kendi kurali var) alt teknik basina 2 ayri kural
    beklemek gercekci degildi. Yalnizca source='auto' satirlar degisir —
    admin'in elle ayarladigi bir alt teknik esigi asla ezilmez. Kullanici
    karari (2026-07-29).

    build_technique_config()'ten HEMEN SONRA cagrilir ve her init_db()
    calismasinda tekrar uygulanir (yalniz bir kerelik migration DEGIL) —
    boylece MITRE yeni bir alt teknik ekledikce (build_technique_config
    onu once DEFAULT_RULE_THRESHOLD=2 ile ekler) bu fonksiyon onu hemen 1'e
    ceker. Alt teknik tespiti: ATT&CK ID'sinde nokta olmasi ("T1078.001"),
    technique_config tablosunda ayri bir is_subtechnique sutunu yok.
    """
    db.execute(
        "UPDATE technique_config SET rule_threshold=1 "
        "WHERE source='auto' AND rule_threshold != 1 AND tech_id LIKE '%.%'"
    )
    db.commit()


def drop_soc_cmm_schema(db: sqlite3.Connection) -> None:
    """SOC-CMM KPI modelini kaldiran temizlik migration'i (idempotent).

    Kod tarafi tamamen sokuldu, ancak CREATE TABLE satirlarini silmek mevcut
    soc.db dosyalarindaki tablolari dusurmuyor; kpi_snapshots uzerindeki
    append-only trigger'lar da yerinde kaliyordu. Tum kurulumlar bir kez
    calistirdiktan sonra bu fonksiyon guvenle silinebilir."""
    db.executescript(
        """
        DROP TRIGGER IF EXISTS kpi_snapshots_no_update;
        DROP TRIGGER IF EXISTS kpi_snapshots_no_delete;
        DROP TABLE IF EXISTS kpi_snapshots;
        DROP TABLE IF EXISTS visibility_overrides;
        DROP TABLE IF EXISTS telemetry_components;
        DROP TABLE IF EXISTS telemetry_sources;
        DROP TABLE IF EXISTS detection_assessments;
        DROP TABLE IF EXISTS soc_profile_techniques;
        DROP TABLE IF EXISTS soc_profiles;
        """
    )
    db.commit()


def ensure_connector_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS connectors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK(kind IN ('qradar')),
            name TEXT NOT NULL UNIQUE,
            base_url TEXT NOT NULL,
            secret_env TEXT NOT NULL,
            product_name TEXT NOT NULL DEFAULT 'QRadar',
            mappings_path TEXT NOT NULL DEFAULT '/console/plugins/app_proxy:UseCaseManager_Service/api/mappings',
            verify_tls INTEGER NOT NULL DEFAULT 1,
            ca_bundle TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            import_new_rules INTEGER NOT NULL DEFAULT 1,
            last_status TEXT NOT NULL DEFAULT 'never',
            last_sync_at TEXT,
            last_error TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS connector_sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('running','success','failed')),
            triggered_by TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL,
            finished_at TEXT,
            received INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL DEFAULT 0,
            updated INTEGER NOT NULL DEFAULT 0,
            unchanged INTEGER NOT NULL DEFAULT 0,
            linked_existing INTEGER NOT NULL DEFAULT 0,
            rules_created INTEGER NOT NULL DEFAULT 0,
            stale INTEGER NOT NULL DEFAULT 0,
            mapping_count INTEGER NOT NULL DEFAULT 0,
            payload_hash TEXT NOT NULL DEFAULT '',
            error TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS external_detections (
            connector_id INTEGER NOT NULL,
            native_id TEXT NOT NULL,
            name TEXT NOT NULL,
            origin TEXT NOT NULL DEFAULT 'unknown',
            enabled INTEGER NOT NULL DEFAULT 1,
            rule_type TEXT NOT NULL DEFAULT 'rule',
            severity TEXT NOT NULL DEFAULT '',
            offense_count INTEGER NOT NULL DEFAULT 0,
            last_offense_at TEXT NOT NULL DEFAULT '',
            payload_hash TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            missing_sync_count INTEGER NOT NULL DEFAULT 0,
            stale INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (connector_id, native_id),
            FOREIGN KEY (connector_id) REFERENCES connectors(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS external_detection_techniques (
            connector_id INTEGER NOT NULL,
            native_id TEXT NOT NULL,
            tech_id TEXT NOT NULL,
            mapping_source TEXT NOT NULL DEFAULT 'qradar',
            PRIMARY KEY (connector_id, native_id, tech_id),
            FOREIGN KEY (connector_id, native_id)
                REFERENCES external_detections(connector_id, native_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS rule_external_refs (
            rule_id INTEGER NOT NULL,
            connector_id INTEGER NOT NULL,
            native_id TEXT NOT NULL,
            match_method TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, native_id),
            FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
            FOREIGN KEY (connector_id, native_id)
                REFERENCES external_detections(connector_id, native_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_connector_runs_connector ON connector_sync_runs(connector_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_external_detections_state ON external_detections(connector_id, stale, enabled);
        CREATE INDEX IF NOT EXISTS idx_rule_external_refs_rule ON rule_external_refs(rule_id);
        """
    )
    db.commit()


def ensure_scope_registry_schema(db: sqlite3.Connection) -> None:
    """Kapsam envanteri: tek seviye Ortam -> Urun izleme.

    Onceden Ortam > Varlik Grubu > Urun seklinde uc seviyeydi; surec asiri
    dallandigi icin varlik grubu seviyesi kaldirildi (bkz. flatten_asset_groups).
    """
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS environments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            code TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            criticality INTEGER NOT NULL DEFAULT 3 CHECK(criticality BETWEEN 1 AND 5),
            owner TEXT NOT NULL DEFAULT '',
            asset_count INTEGER NOT NULL DEFAULT 0 CHECK(asset_count >= 0),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS product_deployments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            connector_id INTEGER,
            monitoring_status TEXT NOT NULL DEFAULT 'unknown'
                CHECK(monitoring_status IN ('unknown','none','partial','full')),
            coverage_percent INTEGER NOT NULL DEFAULT 0 CHECK(coverage_percent BETWEEN 0 AND 100),
            monitoring_mode TEXT NOT NULL DEFAULT 'other'
                CHECK(monitoring_mode IN ('agent','log_forwarding','api','network','hybrid','other')),
            owner TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            reviewed_by TEXT NOT NULL DEFAULT '',
            reviewed_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(environment_id, product_id),
            FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (connector_id) REFERENCES connectors(id)
        );

        CREATE INDEX IF NOT EXISTS idx_product_deployments_environment ON product_deployments(environment_id);
        CREATE INDEX IF NOT EXISTS idx_product_deployments_connector ON product_deployments(connector_id);
        CREATE INDEX IF NOT EXISTS idx_product_deployments_product ON product_deployments(product_id);
        """
    )
    db.commit()


def flatten_asset_groups(db: sqlite3.Connection) -> None:
    """Varlik grubu seviyesini kaldirir (idempotent).

    Eski model: Ortam > Varlik Grubu > Urun izleme.
    Yeni model: Ortam > Urun izleme.

    Bir ortamin altindaki gruplar CAKISAN izleme durumlari tasiyabilir —
    orn. QRadar 'Kurumsal Serverlar'da full ama 'Client Makineler'de none.
    Birini secip digerini atmak bu bilgiyi sessizce yok ederdi; bunun yerine
    VARLIK SAYISI AGIRLIKLI ortalama alinir:

        agirlik = SUM(grup_varlik_sayisi * izleme_agirligi) / ortam_toplam_varlik

    Boylece yukaridaki ornek 'partial %20' olur (QRadar 1500 varligin yalnizca
    300'unu goruyor) — client korlugu kaybolmaz, sayiya doner.
    """
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "asset_groups" not in tables:
        return
    cols = {r[1] for r in db.execute("PRAGMA table_info(product_deployments)").fetchall()}
    if "environment_id" in cols:
        return

    db.row_factory = sqlite3.Row
    groups = db.execute("SELECT id, environment_id, asset_count FROM asset_groups").fetchall()
    group_env = {g["id"]: g["environment_id"] for g in groups}
    group_assets = {g["id"]: max(g["asset_count"], 0) for g in groups}

    env_total: dict[int, int] = {}
    for g in groups:
        env_total[g["environment_id"]] = env_total.get(g["environment_id"], 0) + max(g["asset_count"], 0)

    # (environment_id, product_id) -> agirlikli toplam + tasinacak yardimci alanlar
    merged: dict[tuple[int, int], dict[str, Any]] = {}
    for row in db.execute("SELECT * FROM product_deployments").fetchall():
        env_id = group_env.get(row["asset_group_id"])
        if env_id is None:
            continue
        status = row["monitoring_status"]
        weight = 1.0 if status == "full" else (row["coverage_percent"] / 100 if status == "partial" else 0.0)
        assets = group_assets.get(row["asset_group_id"], 0)
        key = (env_id, row["product_id"])
        acc = merged.setdefault(key, {
            "weighted": 0.0, "connector_id": None, "monitoring_mode": "other",
            "owner": "", "notes": "", "reviewed_by": "", "reviewed_at": None,
        })
        # Varlik sayisi girilmemisse (0) esit agirlikli say, yoksa her sey 0 cikar.
        acc["weighted"] += weight * (assets if env_total.get(env_id, 0) else 1)
        if row["connector_id"] and not acc["connector_id"]:
            acc["connector_id"] = row["connector_id"]
        if row["monitoring_mode"] != "other":
            acc["monitoring_mode"] = row["monitoring_mode"]
        for field in ("owner", "notes", "reviewed_by"):
            if row[field] and not acc[field]:
                acc[field] = row[field]
        if row["reviewed_at"] and not acc["reviewed_at"]:
            acc["reviewed_at"] = row["reviewed_at"]

    db.executescript(
        """
        ALTER TABLE product_deployments RENAME TO product_deployments_old;
        DROP INDEX IF EXISTS idx_asset_groups_environment;
        DROP INDEX IF EXISTS idx_product_deployments_group;
        DROP INDEX IF EXISTS idx_product_deployments_connector;
        DROP INDEX IF EXISTS idx_product_deployments_product;
        """
    )
    if "asset_count" not in {r[1] for r in db.execute("PRAGMA table_info(environments)").fetchall()}:
        db.execute("ALTER TABLE environments ADD COLUMN asset_count INTEGER NOT NULL DEFAULT 0")
    ensure_scope_registry_schema(db)

    for (env_id, product_id), acc in merged.items():
        total = env_total.get(env_id, 0)
        pct = round(acc["weighted"] / total * 100) if total else round(acc["weighted"] * 100)
        pct = max(0, min(100, pct))
        status = "full" if pct >= 100 else ("none" if pct == 0 else "partial")
        db.execute(
            """
            INSERT INTO product_deployments
                (environment_id, product_id, connector_id, monitoring_status,
                 coverage_percent, monitoring_mode, owner, notes, reviewed_by, reviewed_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (env_id, product_id, acc["connector_id"], status,
             0 if status == "none" else (100 if status == "full" else pct),
             acc["monitoring_mode"], acc["owner"], acc["notes"],
             acc["reviewed_by"], acc["reviewed_at"]),
        )
    for env_id, total in env_total.items():
        db.execute("UPDATE environments SET asset_count=? WHERE id=?", (total, env_id))

    db.executescript(
        """
        DROP TABLE IF EXISTS product_deployments_old;
        DROP TABLE IF EXISTS asset_groups;
        """
    )
    db.commit()


def _attack_catalog() -> dict[str, Any]:
    """Return the ATT&CK techniques, data components and v18 detection links."""
    if not MITRE_PATH.exists():
        return {"techniques": {}, "components": {}, "tech_components": {}, "version": ""}
    raw = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    objects = [
        obj for obj in raw.get("objects", [])
        if not obj.get("revoked") and not obj.get("x_mitre_deprecated")
    ]
    by_id = {obj.get("id"): obj for obj in objects if obj.get("id")}

    def external_id(obj: dict[str, Any], prefix: str) -> str:
        return next((
            ref.get("external_id", "")
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
            and ref.get("external_id", "").startswith(prefix)
        ), "")

    techniques: dict[str, Any] = {}
    components: dict[str, Any] = {}
    analytic_components: dict[str, set[str]] = {}
    strategy_components: dict[str, set[str]] = {}
    versions: list[str] = []
    attack_version = ""
    for obj in objects:
        obj_type = obj.get("type")
        if obj_type == "attack-pattern":
            tech_id = external_id(obj, "T")
            if tech_id:
                techniques[tech_id] = {
                    "id": tech_id,
                    "name": obj.get("name", ""),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [
                        phase.get("phase_name", "")
                        for phase in obj.get("kill_chain_phases", [])
                        if phase.get("kill_chain_name") == "mitre-attack"
                    ],
                    "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
                    "stix_id": obj.get("id", ""),
                }
                if obj.get("x_mitre_attack_spec_version"):
                    versions.append(str(obj["x_mitre_attack_spec_version"]))
        elif obj_type == "x-mitre-data-component":
            component_id = external_id(obj, "DC")
            if component_id:
                components[component_id] = {
                    "id": component_id,
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "log_sources": obj.get("x_mitre_log_sources", []),
                    "stix_id": obj.get("id", ""),
                }
        elif obj_type == "x-mitre-analytic":
            analytic_components[obj.get("id", "")] = {
                ref.get("x_mitre_data_component_ref", "")
                for ref in obj.get("x_mitre_log_source_references", [])
                if ref.get("x_mitre_data_component_ref")
            }
        elif obj_type == "x-mitre-collection" and obj.get("name") == "Enterprise ATT&CK":
            attack_version = str(obj.get("x_mitre_version", ""))

    for obj in objects:
        if obj.get("type") == "x-mitre-detection-strategy":
            refs: set[str] = set()
            for analytic_ref in obj.get("x_mitre_analytic_refs", []):
                refs |= analytic_components.get(analytic_ref, set())
            strategy_components[obj.get("id", "")] = refs

    component_by_stix = {value["stix_id"]: key for key, value in components.items()}
    technique_by_stix = {value["stix_id"]: key for key, value in techniques.items()}
    tech_components: dict[str, set[str]] = defaultdict(set)
    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "detects":
            continue
        tech_id = technique_by_stix.get(obj.get("target_ref", ""))
        if not tech_id:
            continue
        for component_ref in strategy_components.get(obj.get("source_ref", ""), set()):
            component_id = component_by_stix.get(component_ref)
            if component_id:
                tech_components[tech_id].add(component_id)

    return {
        "techniques": techniques,
        "components": components,
        "tech_components": {key: sorted(value) for key, value in tech_components.items()},
        "version": attack_version or max(versions, default=""),
    }


def _json_text(value: Any) -> str:
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _audit_entry_hash(row: dict[str, Any], prev_hash: str) -> str:
    payload = {
        "user_id": row.get("user_id"),
        "username": row.get("username", ""),
        "action": row.get("action", ""),
        "target_type": row.get("target_type", ""),
        "target_id": row.get("target_id", ""),
        "detail": row.get("detail", ""),
        "request_id": row.get("request_id", ""),
        "ip_address": row.get("ip_address", ""),
        "user_agent": row.get("user_agent", ""),
        "before_json": row.get("before_json", ""),
        "after_json": row.get("after_json", ""),
        "created_at": row.get("created_at", ""),
    }
    canonical = _json_text(payload)
    return hashlib.sha256(f"{prev_hash}|{canonical}".encode("utf-8")).hexdigest()


def ensure_audit_integrity(db: sqlite3.Connection) -> None:
    """Upgrade legacy audit rows and make the log append-only."""
    existing = {r[1] for r in db.execute("PRAGMA table_info(audit_logs)").fetchall()}
    added_columns = False
    for name, definition in AUDIT_COLUMNS.items():
        if name not in existing:
            db.execute(f"ALTER TABLE audit_logs ADD COLUMN {name} {definition}")
            added_columns = True

    if added_columns:
        prev_hash = ""
        rows = db.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
        for row in rows:
            values = dict(row)
            entry_hash = _audit_entry_hash(values, prev_hash)
            db.execute(
                "UPDATE audit_logs SET prev_hash=?, entry_hash=? WHERE id=?",
                (prev_hash, entry_hash, row["id"]),
            )
            prev_hash = entry_hash

    db.executescript(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(username);
        CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_type, target_id);
        CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
        BEFORE UPDATE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'audit logs are append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
        BEFORE DELETE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'audit logs are append-only');
        END;
        """
    )
    db.commit()


def verify_audit_chain(db: sqlite3.Connection) -> dict[str, Any]:
    prev_hash = ""
    checked = 0
    for row in db.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall():
        values = dict(row)
        expected = _audit_entry_hash(values, prev_hash)
        if values.get("prev_hash", "") != prev_hash or values.get("entry_hash", "") != expected:
            return {"valid": False, "checked": checked, "broken_at_id": row["id"]}
        prev_hash = expected
        checked += 1
    return {"valid": True, "checked": checked, "broken_at_id": None, "head_hash": prev_hash}


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

            -- rule_techniques: bir kural birden fazla MITRE tekniğine bağlanabilir.
            -- tech_id alanı T1059 veya teknik adı (eski seed) olabilir; frontend
            -- her ikisini de nameToIdMap ile çözümler.
            CREATE TABLE IF NOT EXISTS rule_techniques (
                rule_id INTEGER NOT NULL,
                tech_id TEXT NOT NULL,
                PRIMARY KEY (rule_id, tech_id)
            );

            -- technique_config: teknik bazlı hedef tespit sayısı.
            -- rule_threshold (0–10): "yeterli kapsama" sayılacak tespit sayısı.
            --   0 = bu teknik icin tespit gerekmiyor (skor otomatik %100).
            --   Tüm teknikler DEFAULT_RULE_THRESHOLD ile başlar, admin değiştirir.
            -- group_count / tool_count: mitre.json'dan gelen kullanım sayaçları —
            --   yalnızca önceliklendirme bilgisi, skoru etkilemez.
            -- source: 'auto' (mitre.json parse) | 'admin' (el ile override).
            CREATE TABLE IF NOT EXISTS technique_config (
                tech_id          TEXT PRIMARY KEY,
                rule_threshold   INTEGER NOT NULL DEFAULT 2,
                source           TEXT NOT NULL DEFAULT 'auto',
                group_count      INTEGER NOT NULL DEFAULT 0,
                tool_count       INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        db.commit()
        drop_legacy_mitigation_tables(db)
        ensure_teams_table(db)
        ensure_action_items_table(db)
        ensure_products(db)
        ensure_product_category(db)
        ensure_mitigation_entry_product(db)
        ensure_users(db)
        ensure_audit_integrity(db)
        ensure_connector_schema(db)
        # Once duzlestirme (eski 3 seviyeli semayi tasir), sonra sema garantisi —
        # ters sirada calisirsa yeni index henuz var olmayan sutuna kurulmaya calisir.
        flatten_asset_groups(db)
        ensure_scope_registry_schema(db)
        migrate_rule_techniques(db)
        migrate_consolidate_rules(db)
        drop_technique_importance(db)
        build_technique_config(db)
        ensure_subtechnique_default_threshold(db)
        ensure_rule_coverage_level(db)
        ensure_rule_origin(db)
        drop_soc_cmm_schema(db)
    finally:
        db.close()


def ensure_rule_coverage_level(db: sqlite3.Connection) -> None:
    cols = {r[1] for r in db.execute("PRAGMA table_info(rules)").fetchall()}
    if "coverage_level" not in cols:
        db.execute(
            "ALTER TABLE rules ADD COLUMN coverage_level TEXT NOT NULL DEFAULT 'full'"
        )
        db.commit()


def ensure_rule_origin(db: sqlite3.Connection) -> None:
    """rules.origin — kanit gucu. Kova ile skoru ayirmak icin.

    'named'         : adi olan gercek bir tespit kurali. Sert kanit.
    'product_claim' : "bu urun su teknikleri kapsiyor" seklinde urun seviyesi
                      toplu iddia (ice aktarimdaki product_coverage[]).

    Bir urun iddiasi skora katkida bulunur (kart amber olur) ama teknigi
    "Tespit" kovasina SOKMAZ — tek satirlik bir iddianin 120 tekniği birden
    kapsanmis gostermesi, haritanin cevapladigi soruyla ("bu teknigi gercekten
    gorebiliyor muyuz") celisirdi.
    """
    cols = {r[1] for r in db.execute("PRAGMA table_info(rules)").fetchall()}
    if "origin" not in cols:
        db.execute(
            "ALTER TABLE rules ADD COLUMN origin TEXT NOT NULL DEFAULT 'named'"
        )
        db.commit()


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


def _product_exists(db: sqlite3.Connection, name: str) -> bool:
    return db.execute("SELECT 1 FROM products WHERE name = ?", (name,)).fetchone() is not None


def _detection_source_names(db: sqlite3.Connection) -> set[str]:
    """Yalnizca haritayi boyan urunler (tespit kaynaklari)."""
    return {
        r["name"] for r in db.execute(
            "SELECT name FROM products WHERE category = ?", ("tespit_kaynagi",)
        ).fetchall()
    }


def ensure_product_category(db: sqlite3.Connection) -> None:
    """products.category sutununu ekler (idempotent).

    Mevcut kayitlar PRODUCT_CATEGORY_DEFAULT olarak isaretlenir; migration
    kimsenin kapsama sayisini sessizce degistirmemeli. Firewall/AV gibi tespit
    uretmeyen urunleri admin, Ayarlar > Urun Yonetimi'nden yeniden siniflandirir.
    """
    cols = {r[1] for r in db.execute("PRAGMA table_info(products)").fetchall()}
    if "category" in cols:
        return
    db.execute(
        f"ALTER TABLE products ADD COLUMN category TEXT NOT NULL "
        f"DEFAULT '{PRODUCT_CATEGORY_DEFAULT}'"
    )
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
    before: Any = None,
    after: Any = None,
) -> None:
    actor = user or getattr(g, "current_user", None)
    user_id = actor.get("id") if actor else None
    username = actor.get("username", "") if actor else ""
    request_id = getattr(g, "request_id", "")
    ip_address = request.remote_addr or ""
    user_agent = request.user_agent.string[:500]
    before_json = _json_text(before)
    after_json = _json_text(after)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    previous = db.execute(
        "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = previous["entry_hash"] if previous else ""
    values = {
        "user_id": user_id,
        "username": username,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "detail": detail[:4000],
        "request_id": request_id,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "before_json": before_json,
        "after_json": after_json,
        "created_at": created_at,
    }
    entry_hash = _audit_entry_hash(values, prev_hash)
    db.execute(
        """
        INSERT INTO audit_logs (
            user_id, username, action, target_type, target_id, detail,
            request_id, ip_address, user_agent, before_json, after_json,
            prev_hash, entry_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id, username, action, target_type, target_id, detail[:4000],
            request_id, ip_address, user_agent, before_json, after_json,
            prev_hash, entry_hash, created_at,
        ),
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


def role_required_methods(role_map: dict[str, str]):
    """Per-HTTP-method minimum role for one view function that handles
    several methods with different privilege levels (e.g. GET=viewer,
    POST=editor). Every method the route accepts must have an entry here —
    a method missing from role_map is rejected with 403 (fail closed), so a
    method added to @app.route(methods=[...]) later without updating this
    map can't silently inherit the lowest configured role. Replaces the old
    pattern of a blanket @role_required(lowest_role) plus an inline
    `if ROLE_LEVELS[...] < ROLE_LEVELS[...]` check buried in the function
    body for the write branch — that pattern is easy to forget when adding
    a new route. See docs/rbac.md."""
    for role in role_map.values():
        if role not in ROLE_LEVELS:
            raise ValueError(f"Unknown role in role_required_methods: {role!r}")

    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            user = g.current_user
            min_role = role_map.get(request.method)
            if min_role is None:
                return jsonify({"error": "Forbidden"}), 403
            if ROLE_LEVELS.get(user["role"], 0) < ROLE_LEVELS[min_role]:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def _environment_weight_map(
    db: sqlite3.Connection, environment_id: int | None
) -> dict[str, float] | None:
    """Bir varlik grubunda urun adi -> izleme agirligi haritasi.

    None doner => ortam filtresi yok, tum tespitler tam agirlikla sayilir.
    full 1.0 / partial coverage_percent/100 / none|unknown haritada yok (0).
    """
    if not environment_id:
        return None
    rows = db.execute(
        """
        SELECT p.name AS product_name, pd.monitoring_status, pd.coverage_percent
        FROM product_deployments pd JOIN products p ON p.id = pd.product_id
        WHERE pd.environment_id = ?
        """,
        (environment_id,),
    ).fetchall()
    weights: dict[str, float] = {}
    for row in rows:
        if row["monitoring_status"] == "full":
            weights[row["product_name"]] = 1.0
        elif row["monitoring_status"] == "partial":
            weights[row["product_name"]] = max(0, min(100, row["coverage_percent"] or 0)) / 100
    return weights


def _compute_gap_analysis(
    mitre_data: dict, db: sqlite3.Connection, environment_id: int | None = None
) -> dict:
    """Shared logic for /api/gap-analysis and /report.
    Returns dict with overview, by_tactic, critical_gaps."""
    tech_by_stix: dict[str, dict] = {}
    mitigation_stix_to_ext: dict[str, str] = {}
    tech_to_mitigations: dict[str, set] = {}

    for obj in mitre_data["objects"]:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("T")
                ),
                None,
            )
            if not ext_id:
                continue
            tactics = [
                ph["phase_name"]
                for ph in obj.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            ]
            is_sub = obj.get("x_mitre_is_subtechnique", False)
            tech_by_stix[obj["id"]] = {
                "external_id": ext_id,
                "name": obj.get("name", ""),
                "is_subtechnique": is_sub,
                "parent_id": ext_id.split(".")[0] if is_sub and "." in ext_id else None,
                "tactics": tactics,
            }
        elif t == "course-of-action":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("M")
                ),
                None,
            )
            if ext_id:
                mitigation_stix_to_ext[obj["id"]] = ext_id
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            mit_ext = mitigation_stix_to_ext.get(obj.get("source_ref", ""))
            tech_info = tech_by_stix.get(obj.get("target_ref", ""))
            if mit_ext and tech_info:
                tech_to_mitigations.setdefault(tech_info["external_id"], set()).add(mit_ext)

    # Ortam boyutu: bir varlik grubu secildiyse, o grubu izlemeyen urunlerin
    # tespitleri hesaba katilmaz; kismi izleme coverage_percent ile agirliklanir.
    # Ayrica cesitlilige yalnizca tespit kaynagi kategorisindeki urunler sayilir.
    # Ayni kural istemci tarafinda da uygulanir (static/app.js scopeWeightMap).
    scope_weights = _environment_weight_map(db, environment_id)
    detection_sources = _detection_source_names(db)

    rule_stats_by_tech: dict[str, dict[str, Any]] = {}
    for row in db.execute(
        """
        SELECT rt.tech_id, r.source, r.coverage_level, r.origin,
               COUNT(DISTINCT r.id) AS rule_count
        FROM rule_techniques rt
        JOIN rules r ON r.id = rt.rule_id
        GROUP BY rt.tech_id, r.source, r.coverage_level, r.origin
        """
    ).fetchall():
        weight = 1.0 if scope_weights is None else scope_weights.get(row["source"], 0.0)
        if weight <= 0:
            continue
        level_weight = {"low": 0.25, "partial": 0.60}.get(row["coverage_level"], 1.00)
        origin_weight = 1.0 if row["origin"] != "product_claim" else PRODUCT_CLAIM_SCORE_WEIGHT
        stats = rule_stats_by_tech.setdefault(
            row["tech_id"],
            {"rule_count": 0, "named_rule_count": 0, "effective_rule_count": 0.0,
             "_products": set()},
        )
        stats["rule_count"] += int(row["rule_count"])
        if row["origin"] != "product_claim":
            stats["named_rule_count"] += int(row["rule_count"])
        stats["effective_rule_count"] += level_weight * weight * origin_weight * int(row["rule_count"])
        if row["source"] in detection_sources:
            stats["_products"].add(row["source"])
    for stats in rule_stats_by_tech.values():
        stats["products"] = sorted(stats["_products"])
        stats["product_count"] = len(stats.pop("_products"))

    covered_mits: set = set(
        r["mitigation_id"]
        for r in db.execute(
            "SELECT DISTINCT mitigation_id FROM mitigation_entries"
        ).fetchall()
    )

    tech_config = {
        r["tech_id"]: {"rule_threshold": r["rule_threshold"], "group_count": r["group_count"]}
        for r in db.execute(
            "SELECT tech_id, rule_threshold, group_count FROM technique_config"
        ).fetchall()
    }

    all_techs = []
    for _stix_id, info in tech_by_stix.items():
        teid = info["external_id"]
        rule_stats = rule_stats_by_tech.get(teid, {})
        rule_count = int(rule_stats.get("rule_count", 0))
        named_rule_count = int(rule_stats.get("named_rule_count", 0))
        effective_rule_count = float(rule_stats.get("effective_rule_count", 0.0))
        product_count = int(rule_stats.get("product_count", 0))
        products_for_tech = rule_stats.get("products", [])
        mits_for_tech = tech_to_mitigations.get(teid, set())
        covered_mitigation_count = len(mits_for_tech & covered_mits)
        mitigation_checked = covered_mitigation_count > 0
        tc = tech_config.get(teid, {})
        rule_threshold = int(tc.get("rule_threshold", DEFAULT_RULE_THRESHOLD))
        # ── Kapsama skoru — tek satirda aciklanabilir ────────────────────────
        #   skor = min(etkin tespit sayisi / teknik hedefi, 1)
        # Mitigation skora GIRMEZ (haritada ayri kalkan isareti olarak gosterilir),
        # urun cesitliligi de girmez (urun noktalari olarak zaten gorunuyor).
        # Onceki 3 bilesenli agirlikli harman (0.50/0.30/0.20) ve MITRE'den
        # turetilen "onem" kavrami kaldirildi — kullanici karari, bkz.
        # PROJECT_STATE.md Faz 4.
        #
        # Hedef 0 = "bu teknik icin tespit gerekmiyor" (admin karari — kapsam
        # disi, tamamen mitigation/surecle karsilaniyor vb.). Skor dogrudan
        # %100'dur; boleni sifir yapmamak icin ayri bir dal.
        if rule_threshold <= 0:
            coverage_score = 1.0
        else:
            coverage_score = min(effective_rule_count / rule_threshold, 1.0)
        # Kova SERT kanit ister: adi olan en az bir tespit. Urun seviyesi toplu
        # iddia (origin='product_claim') skora katkida bulunur ama teknigi
        # "Tespit" kovasina sokmaz — yoksa tek satirlik bir iddia 120 tekniği
        # birden kapsanmis gosterirdi. Bkz. ensure_rule_origin().
        detected = named_rule_count > 0
        mature = coverage_score >= 1.0
        all_techs.append({
            "tech_id": teid,
            "name": info["name"],
            "is_subtechnique": info["is_subtechnique"],
            "parent_id": info.get("parent_id"),
            "tactics": info["tactics"],
            "rule_count": rule_count,
            "named_rule_count": named_rule_count,
            "effective_rule_count": round(effective_rule_count, 2),
            "rule_threshold": rule_threshold,
            "product_count": product_count,
            "sources": products_for_tech,
            "mitigation_checked": mitigation_checked,
            "mitigation_count": covered_mitigation_count,
            "coverage_score": round(coverage_score, 3),
            "covered": detected,
            "mature": mature,
            # Onceliklendirme icin objektif MITRE sinyali — ayar degil, bilgi.
            "group_count": int(tc.get("group_count", 0) or 0),
        })

    parents = [t for t in all_techs if not t["is_subtechnique"]]
    subs = [t for t in all_techs if t["is_subtechnique"]]

    # ── Üst teknik ailesi (rollup) ───────────────────────────────────────────
    # Alt tekniği OLAN bir üst teknik artık yalnızca kendi payıyla değil,
    # kendi payı + TÜM alt tekniklerinin toplamıyla değerlendirilir: skor,
    # hedef, etkin tespit ve "tespitli mi" (kova) hepsi bu aileyi yansıtır.
    # Alt tekniği olmayan teknikler etkilenmez (toplam sıfır alt teknikle
    # "kendi" değerine indirgenir, ayrı bir dal gerekmez).
    #
    # Her alt teknik KENDİ HEDEFİNDE TAVANLANIR — bir alt tekniğin fazla
    # tespiti başka bir kardeşin eksiğini örtmez (bilinçli, muhafazakâr
    # seçim: aile "ortalaması" telafi ile şişmesin). "Gerekli değil" (hedef=0)
    # işaretli bir alt teknik aileye ne katkı ne yük getirir, tamamen
    # dışarıda kalır.
    #
    # "Tespit" kovası da aileye genişler: üst teknik, kendisine doğrudan
    # yazılmış bir kural VARSA ya da en az bir alt tekniği zaten tespitliyse
    # tespitli sayılır — böylece skor (kart rengi) ile kova (Boşluklar
    # listesi) her zaman aynı sonuca varır, birbirini yalanlamaz. Bu, aşağıdaki
    # "sert kanıt" ilkesini bozmaz — kanıt hâlâ gerekiyor, sadece ailenin
    # herhangi bir üyesinden gelebiliyor.
    #
    # Kullanıcı kararı (2026-07-29, bkz. PROJECT_STATE.md). static/app.js
    # renderMatrix()/updateTechniqueCard() aynı formülle eşitlenmeli.
    children_by_parent: dict[str, list] = {}
    for s in subs:
        pid = s.get("parent_id")
        if pid:
            children_by_parent.setdefault(pid, []).append(s)

    for p in parents:
        kids = children_by_parent.get(p["tech_id"])
        if not kids:
            continue
        kids_threshold_sum = sum(k["rule_threshold"] for k in kids if k["rule_threshold"] > 0)
        kids_effective_sum = sum(
            min(k["effective_rule_count"], k["rule_threshold"])
            for k in kids if k["rule_threshold"] > 0
        )
        rollup_threshold = p["rule_threshold"] + kids_threshold_sum
        rollup_effective = p["effective_rule_count"] + kids_effective_sum
        p["effective_rule_count"] = round(rollup_effective, 2)
        p["rule_threshold"] = rollup_threshold
        p["coverage_score"] = (
            round(min(rollup_effective / rollup_threshold, 1.0), 3)
            if rollup_threshold > 0 else 1.0
        )
        p["covered"] = p["named_rule_count"] > 0 or any(k["covered"] for k in kids)
        p["mature"] = p["coverage_score"] >= 1.0

    # ── Kapsama tanımı (tek doğru kaynak) ───────────────────────────────────
    # Payda: ANA teknikler. Alt teknikler paydaya girmez çünkü kurallar
    # neredeyse tamamen ana tekniğe eşleniyor (475 alt teknikten yalnızca
    # birkaçının kendi kuralı var) — paydaya katmak oranı yapay düşürür.
    # "Tespitli" olmak yukarıdaki aile kuralına göre belirlenir: doğrudan
    # kendi kuralı VEYA en az bir alt tekniğin kendi kuralı yeterli — sert
    # kanıt ilkesi bozulmaz, kanıt sadece aileden gelebilir.
    #
    # İki ayrık kova (toplamı = ana teknik sayısı):
    #   detected  → tespit var (görebiliyoruz)
    #   uncovered → tespit yok (asıl aksiyon listesi)
    # Mitigation ayrı bir kova DEĞİL — haritada kalkan işareti olarak gösterilir;
    # "yalnız mitigation ile kapsanan" kavramından vazgeçildi (Faz 4 kararı).
    total_techniques = len(parents)
    detected_techniques = sum(1 for t in parents if t["covered"])
    uncovered_techniques = total_techniques - detected_techniques
    mitigated_techniques = sum(1 for t in parents if t["mitigation_checked"])

    total_subtechniques = len(subs)
    detected_subtechniques = sum(1 for t in subs if t["covered"])

    mature_techniques = sum(1 for t in parents if t["mature"])

    # "Ortalama Skor" — yukaridaki Tespit/Kapsamsiz kovasindan FARKLI bir
    # soruya cevap verir ("genel olgunluk ne kadar iyi", kova ise "gorebiliyor
    # muyuz"). Alt teknikler burada dahil olur (kovaya girmezler, skora
    # girerler) ve her teknigin katkisi kendi rule_threshold'uyla agirliklanir
    # — "gerekli değil" (0) isaretli teknikler agirliksiz kalir, cok tespit
    # gerektiren teknikler ortalamayi daha fazla etkiler. Kullanici karari
    # (2026-07-29, bkz. PROJECT_STATE.md).
    def _avg_weight(t: dict) -> float:
        w = max(t["rule_threshold"], 0)
        return w * SUBTECHNIQUE_AVG_WEIGHT if t["is_subtechnique"] else w

    _avg_weight_total = sum(_avg_weight(t) for t in all_techs)
    average_score = round(
        sum(t["coverage_score"] * _avg_weight(t) for t in all_techs) / _avg_weight_total * 100, 1
    ) if _avg_weight_total else 0.0
    # Tespitsiz teknikler — "önem seviyesi" kavramı kaldırıldığı için artık
    # eşik yok: hiç tespiti olmayan her ana teknik listeye girer. Sıralama,
    # MITRE'den gelen objektif sinyalle yapılır (kaç tehdit grubu kullanıyor).
    critical_gaps_list = [t for t in parents if not t["covered"]]
    coverage_pct = (
        round(detected_techniques / total_techniques * 100, 1) if total_techniques else 0.0
    )

    # Taktik bazlı: parent + alt teknikler birlikte. "total"/"covered"/"mature"
    # bilinçli olarak eşit ağırlıklı kalır (Faz 3'te karara bağlanan tanım,
    # bkz. yukarısı) — yalnızca average_score_pct, genel Ortalama Skor ile
    # aynı eşik-ağırlıklı formülü kullanır (score_weight_total/weight_total).
    by_tactic_map: dict[str, dict] = {}
    for t in all_techs:
        w = _avg_weight(t)
        for tactic in t["tactics"]:
            entry = by_tactic_map.setdefault(
                tactic, {"total": 0, "covered": 0, "mature": 0, "score_total": 0.0,
                         "score_weight_total": 0.0, "weight_total": 0.0}
            )
            entry["total"] += 1
            entry["score_total"] += t["coverage_score"]
            entry["score_weight_total"] += t["coverage_score"] * w
            entry["weight_total"] += w
            if t["covered"]:
                entry["covered"] += 1
            if t["mature"]:
                entry["mature"] += 1

    by_tactic = []
    for tactic in _TACTIC_ORDER:
        if tactic in by_tactic_map:
            entry = by_tactic_map[tactic]
            pct = round(entry["covered"] / entry["total"] * 100, 1) if entry["total"] else 0.0
            by_tactic.append({
                "tactic": tactic,
                "label": _TACTIC_LABEL_MAP.get(tactic, tactic),
                "total": entry["total"],
                "covered": entry["covered"],
                "pct": pct,
                "mature": entry["mature"],
                "maturity_pct": round(entry["mature"] / entry["total"] * 100, 1),
                "average_score_pct": (
                    round(entry["score_weight_total"] / entry["weight_total"] * 100, 1)
                    if entry["weight_total"] else 0.0
                ),
            })
    for tactic, entry in by_tactic_map.items():
        if tactic not in _TACTIC_ORDER:
            pct = round(entry["covered"] / entry["total"] * 100, 1) if entry["total"] else 0.0
            by_tactic.append({
                "tactic": tactic,
                "label": _TACTIC_LABEL_MAP.get(tactic, tactic),
                "total": entry["total"],
                "covered": entry["covered"],
                "pct": pct,
                "mature": entry["mature"],
                "maturity_pct": round(entry["mature"] / entry["total"] * 100, 1),
                "average_score_pct": (
                    round(entry["score_weight_total"] / entry["weight_total"] * 100, 1)
                    if entry["weight_total"] else 0.0
                ),
            })

    # Sıralama: en çok tehdit grubunun kullandığı teknik başta — objektif
    # MITRE sinyali, kullanıcının yöneteceği bir ayar değil.
    critical_gaps_sorted = sorted(
        critical_gaps_list, key=lambda x: (-x["group_count"], x["name"])
    )[:50]
    critical_gaps_out = [
        {
            "tech_id": t["tech_id"],
            "name": t["name"],
            "tactic": t["tactics"][0] if t["tactics"] else "",
            "group_count": t["group_count"],
            "rule_count": t["rule_count"],
            "named_rule_count": t["named_rule_count"],
            "effective_rule_count": t["effective_rule_count"],
            "rule_threshold": t["rule_threshold"],
            "product_count": t["product_count"],
            "coverage_score": t["coverage_score"],
            "mitigation_checked": t["mitigation_checked"],
        }
        for t in critical_gaps_sorted
    ]

    return {
        "overview": {
            # Payda: ana teknikler (bkz. yukarıdaki kapsama tanımı)
            "total_techniques": total_techniques,
            # İki ayrık kova — toplamı total_techniques
            "detected_techniques": detected_techniques,
            "uncovered_techniques": uncovered_techniques,
            # Bilgi: kaç teknikte işaretli mitigation var (kovalarla kesişir)
            "mitigated_techniques": mitigated_techniques,
            "coverage_pct": coverage_pct,           # tespit / ana teknik
            "mature_techniques": mature_techniques,
            "maturity_pct": (
                round(mature_techniques / total_techniques * 100, 1) if total_techniques else 0.0
            ),
            "average_score_pct": average_score,
            # Alt teknikler paydaya girmez, bilgi olarak raporlanır
            "total_subtechniques": total_subtechniques,
            "detected_subtechniques": detected_subtechniques,
            "critical_gap_count": len(critical_gaps_list),
        },
        "by_tactic": by_tactic,
        "critical_gaps": critical_gaps_out,
        # Tam liste (parent+alt), /report ekranindaki matris ve teknik
        # listesi eklerinde kullanilir. /api/gap-analysis bunu yoksayabilir
        # (eklemek geriye donuk uyumlu, mevcut alanlarin hicbiri degismedi).
        "techniques": all_techs,
    }


def _get_threat_actors() -> list:
    """Parse mitre.json for intrusion-sets and their technique usage. Cached."""
    if not MITRE_PATH.exists():
        return []
    mtime = MITRE_PATH.stat().st_mtime
    if THREAT_ACTOR_CACHE["data"] is not None and THREAT_ACTOR_CACHE["mtime"] == mtime:
        return THREAT_ACTOR_CACHE["data"]  # type: ignore[return-value]

    data = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    objects = data.get("objects", [])

    tech_stix_to_ext: dict[str, str] = {}
    actors: dict[str, dict] = {}

    for obj in objects:
        t = obj.get("type", "")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                    tech_stix_to_ext[obj["id"]] = ref["external_id"]
                    break
        elif t == "intrusion-set":
            stix_id = obj["id"]
            name = obj.get("name", "")
            aliases = obj.get("aliases", [name])
            g_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("G"):
                    g_id = ref["external_id"]
                    break
            actors[stix_id] = {
                "id": g_id,
                "stix_id": stix_id,
                "name": name,
                "aliases": aliases,
                "technique_ids": set(),
            }

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        if src in actors:
            t_ext = tech_stix_to_ext.get(tgt)
            if t_ext:
                actors[src]["technique_ids"].add(t_ext)

    result = [
        {
            "id": a["id"],
            "stix_id": a["stix_id"],
            "name": a["name"],
            "aliases": a["aliases"],
            "technique_ids": sorted(a["technique_ids"]),
        }
        for a in actors.values()
    ]
    result.sort(key=lambda x: x["name"])

    THREAT_ACTOR_CACHE["mtime"] = mtime
    THREAT_ACTOR_CACHE["data"] = result
    return result


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
                "x_mitre_platforms": obj.get("x_mitre_platforms", []),
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


@app.route("/docs")
@login_required
def docs_page() -> str:
    """Bilgilendirme wiki'si. Onceden index.html icinde bir paneldi ve tek
    basina dosyanin yarisiydi (1027/1943 satir); statik icerik oldugu icin
    SPA'dan ayrildi."""
    return render_template("docs.html")


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
    attempt_key = _login_attempt_key(username)
    if _login_is_limited(attempt_key):
        write_audit_log(
            db,
            action="login_blocked",
            target_type="session",
            detail="Too many failed login attempts",
            user={"id": None, "username": username},
        )
        db.commit()
        response = jsonify({"error": "Too many failed attempts. Try again later."})
        response.headers["Retry-After"] = str(LOGIN_WINDOW_SECONDS)
        return response, 429
    row = db.execute(
        "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not row or not row["is_active"] or not check_password_hash(row["password_hash"], password):
        _record_login_failure(attempt_key)
        write_audit_log(
            db,
            action="login_failed",
            target_type="session",
            detail="Invalid credentials or inactive account",
            user={"id": row["id"] if row else None, "username": username},
        )
        db.commit()
        return jsonify({"error": "Invalid credentials"}), 401
    _clear_login_failures(attempt_key)
    session.clear()
    session["user_id"] = row["id"]
    write_audit_log(
        db,
        action="login",
        target_type="session",
        target_id=str(row["id"]),
        detail="Login successful",
        user={"id": row["id"], "username": row["username"]},
        after={"role": row["role"]},
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
@role_required_methods({"GET": "viewer", "POST": "editor"})
def rules():
    db = get_db()
    if request.method == "GET":
        rows = db.execute("""
            SELECT r.id, r.name, r.tactic, r.tech, r.source, r.coverage_level, r.origin,
                   GROUP_CONCAT(rt.tech_id) as techs
            FROM rules r
            LEFT JOIN rule_techniques rt ON rt.rule_id = r.id
            GROUP BY r.id ORDER BY r.id ASC
        """).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            techs_raw = d.pop("techs", None)
            d["techniques"] = sorted(set(techs_raw.split(","))) if techs_raw else []
            result.append(d)
        return jsonify(result)

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    # tactic ve tech opsiyonel: Kurallar sayfasından tekniksiz kural oluşturulabilir,
    # teknikler sonradan rule_techniques üzerinden eklenir.
    tactic = (payload.get("tactic") or "none").strip() or "none"
    tech = (payload.get("tech") or "").strip()
    source = (payload.get("source") or "").strip()

    if not name or not source:
        return jsonify({"error": "Missing fields: name, source"}), 400
    if not _product_exists(db, source):
        return jsonify({"error": _UNKNOWN_SOURCE_ERROR.format(source=source)}), 400

    try:
        cur = db.execute(
            "INSERT INTO rules (name, tactic, tech, source) VALUES (?, ?, ?, ?)",
            (name, tactic, tech or "none", source)
        )
    except sqlite3.IntegrityError:
        # idx_rules_name_source UNIQUE index ihlali → aynı (name, source) zaten var.
        return jsonify({"error": "Bu isim ve kaynak için kural zaten mevcut. Teknik eklemek için mevcut kuralı kullanın."}), 409
    if tech:
        db.execute("INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
                   (cur.lastrowid, tech))
    write_audit_log(
        db,
        action="create",
        target_type="rule",
        target_id=str(cur.lastrowid),
        detail=f"name={name};tech={tech or '-'};source={source}",
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({
        "id": cur.lastrowid, "name": name, "tactic": tactic, "tech": tech,
        "source": source, "techniques": [tech] if tech else [],
        "coverage_level": "full",
    }), 201




# ── Kapsama Ice Aktarimi ─────────────────────────────────────────────────────
# Kullanici, urun ve kural listesini bir LLM'e verip MITRE eslemesi uretiyor;
# uretilen dosya buraya yuklenip haritaya donusuyor. Sema ve prompt:
# docs/mitre_mapping_prompt.md
#
# Iki asamali: once /preview (hicbir yazma yok, plan doner), sonra /apply.
# Yanlis bir dosyanin haritayi aninda bozmamasi icin bilincli tercih.
#
# Birlestirme semantigi: mevcut bir kuralin teknikleri ASLA silinmez, yalnizca
# eksik olanlar eklenir. Uygulamada elle yapilan eslemeler korunur; bedeli,
# kaynak sistemden kaldirilan bir eslemenin burada kalmasidir.
IMPORT_SCHEMA_NAME = "soc-coverage-import"
IMPORT_SCHEMA_VERSION = 1
_BUILTIN_RULE_SUFFIX = "Built-in kapsama"
_TECH_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _known_technique_ids(db: sqlite3.Connection) -> set[str]:
    """Ice aktarimda 'gecerli teknik ID' saymanin tek dogru kaynagi.

    Bilerek technique_config TABLOSUNU degil, canli _mitre_catalog()'u okur
    (mitre.json'dan mtime ile invalidate olan cache). technique_config bir
    anlik goruntudur ve MITRE surum atladiginda (v19'daki Defense Impairment
    gibi) geride kalabilir; canli katalog ise dosya degisir degismez
    guncelliyor, ayrica revoked/deprecated ID'leri otomatik disliyor.
    """
    return _mitre_catalog()["technique_ids"]


def _normalize_import_payload(raw: Any) -> tuple[dict, list[str]]:
    """Yuklenen dosyayi kanonik yapiya cevirir ve bicim hatalarini toplar."""
    errors: list[str] = []
    if not isinstance(raw, dict):
        return {}, ["Dosya bir JSON nesnesi olmali."]

    schema = (raw.get("schema") or "").strip()
    if schema != IMPORT_SCHEMA_NAME:
        errors.append(
            f"'schema' alani '{IMPORT_SCHEMA_NAME}' olmali (gelen: '{schema or '-'}')."
        )
    try:
        version = int(raw.get("version") or 0)
    except (TypeError, ValueError):
        version = 0
    if version != IMPORT_SCHEMA_VERSION:
        errors.append(
            f"'version' alani {IMPORT_SCHEMA_VERSION} olmali (gelen: {version or '-'})."
        )

    def as_list(key: str) -> list:
        value = raw.get(key) or []
        if not isinstance(value, list):
            errors.append(f"'{key}' bir dizi olmali.")
            return []
        return value

    return (
        {
            "products": as_list("products"),
            "rules": as_list("rules"),
            "product_coverage": as_list("product_coverage"),
        },
        errors,
    )


def _plan_coverage_import(db: sqlite3.Connection, raw: Any) -> dict:
    """Dosyayi dogrular ve ne olacagini anlatan bir plan uretir. Yazma yapmaz.

    Plan hem onizlemede gosterilir hem de apply tarafindan aynen uygulanir —
    boylece "onizlemede gordugun ile olan" ayrisamaz.
    """
    payload, errors = _normalize_import_payload(raw)
    if errors:
        return {"ok": False, "errors": errors, "warnings": [], "products": [], "rules": [], "summary": {}}
    warnings: list[str] = []

    known_techs = _known_technique_ids(db)
    existing_products = {
        r["name"].casefold(): r["name"]
        for r in db.execute("SELECT name FROM products").fetchall()
    }
    existing_rules = {
        (r["name"].casefold(), r["source"].casefold()): {
            "id": r["id"], "name": r["name"], "source": r["source"],
        }
        for r in db.execute("SELECT id, name, source FROM rules").fetchall()
    }
    existing_techs_by_rule: dict[int, set[str]] = {}
    for row in db.execute("SELECT rule_id, tech_id FROM rule_techniques").fetchall():
        existing_techs_by_rule.setdefault(row["rule_id"], set()).add(row["tech_id"])

    # ── Urunler ──────────────────────────────────────────────────────────
    product_plan = []
    declared_products: dict[str, str] = {}
    for i, item in enumerate(payload["products"], start=1):
        if not isinstance(item, dict):
            errors.append(f"products[{i}]: nesne olmali.")
            continue
        name = (item.get("name") or "").strip()
        if not name:
            errors.append(f"products[{i}]: 'name' zorunlu.")
            continue
        category = (item.get("category") or PRODUCT_CATEGORY_DEFAULT).strip()
        if category not in PRODUCT_CATEGORIES:
            errors.append(
                f"products[{i}] ({name}): gecersiz kategori '{category}'. "
                f"Gecerli: {', '.join(PRODUCT_CATEGORIES)}"
            )
            continue
        declared_products[name.casefold()] = name
        if name.casefold() in existing_products:
            product_plan.append({"name": name, "action": "noop", "category": category})
        else:
            product_plan.append({
                "name": name, "action": "create", "category": category,
                "color": (item.get("color") or "").strip() or _next_product_color(db, len(product_plan)),
            })

    known_product_names = {**existing_products, **declared_products}

    # ── Kurallar (isimli + urun seviyesi built-in setler) ────────────────
    incoming: list[dict] = []
    for i, item in enumerate(payload["rules"], start=1):
        if not isinstance(item, dict):
            errors.append(f"rules[{i}]: nesne olmali.")
            continue
        incoming.append({
            "label": f"rules[{i}]",
            "name": (item.get("name") or "").strip(),
            "product": (item.get("product") or "").strip(),
            "techniques": item.get("techniques"),
            "coverage_level": (item.get("coverage_level") or "full").strip(),
            "kind": (item.get("kind") or "custom").strip(),
            "origin": "named",
            "rationale": (item.get("rationale") or "").strip(),
            "confidence": (item.get("confidence") or "").strip(),
        })
    for i, item in enumerate(payload["product_coverage"], start=1):
        if not isinstance(item, dict):
            errors.append(f"product_coverage[{i}]: nesne olmali.")
            continue
        product = (item.get("product") or "").strip()
        # Urun seviyesi kapsama tek bir "sanal" kural olarak girer; boylece
        # hedef (rule_threshold) mantigi bozulmaz ve kaynagi belli olur.
        incoming.append({
            "label": f"product_coverage[{i}]",
            "name": f"{product} — {_BUILTIN_RULE_SUFFIX}" if product else "",
            "product": product,
            "techniques": item.get("techniques"),
            "coverage_level": (item.get("coverage_level") or "partial").strip(),
            "kind": "builtin",
            "origin": "product_claim",
            "rationale": (item.get("note") or item.get("rationale") or "").strip(),
            "confidence": (item.get("confidence") or "").strip(),
        })

    # Ayni (isim, urun) dosyada birden fazla kez gecebilir — bu bir HATA
    # DEGIL, uyaridir. Uzun listelerde bir LLM'in bir blogu tekrarlamasi
    # bilinen bir hata modu (orn. urun basina taktik basina ayri satirlar
    # uretilirken ayni satirin iki kez yazilmasi); yuzlerce gecerli satirin
    # tamami bu yuzden reddedilmesin. Tekrar eden satirlarin teknikleri
    # birlestirilir (union), ilk satirin coverage_level/kind/rationale'i
    # kullanilir — tanimayan teknik ID'sini uyariya cevirmekle ayni ilke.
    merged_incoming: dict[tuple[str, str], dict] = {}
    merge_order: list[tuple[str, str]] = []
    for item in incoming:
        label = item["label"]
        name, product = item["name"], item["product"]
        if not name or not product:
            errors.append(f"{label}: 'name' ve 'product' zorunlu.")
            continue
        if product.casefold() not in known_product_names:
            errors.append(
                f"{label} ({name}): '{product}' urun katalogunda yok ve dosyanin "
                "products[] bolumunde de tanimli degil."
            )
            continue
        if item["coverage_level"] not in ("low", "partial", "full"):
            errors.append(
                f"{label} ({name}): gecersiz coverage_level '{item['coverage_level']}'. "
                "Gecerli: low, partial, full"
            )
            continue

        # Teknik taninmasi UYARIdir, hata degil: bir LLM'in urettigi ID
        # gercekte var olmayabilir (mitre.json'da olmayan bir numara). Tek
        # satirlik bir tanima hatasi yuzunden yuzlerce satirlik dosyanin
        # tamami reddedilmesin — gecersiz ID'ler atlanir, kural (varsa kalan
        # gecerli tekniklerle, yoksa tekniksiz) yine de eklenir. Kullanici
        # Veri Kalitesi ekranindan tamamlar; ayni yol elle "tekniksiz kural"
        # eklemekle birebir aynidir.
        raw_techs = item["techniques"]
        if not isinstance(raw_techs, list):
            errors.append(f"{label} ({name}): 'techniques' bir dizi olmali.")
            continue
        if not raw_techs:
            warnings.append(
                f"{label} ({name}): teknik listesi bos — kural tekniksiz eklenecek."
            )
        techs, unknown = [], []
        for t in raw_techs:
            tid = str(t or "").strip().upper()
            if not _TECH_ID_RE.match(tid) or tid not in known_techs:
                unknown.append(str(t))
                continue
            if tid not in techs:
                techs.append(tid)
        if unknown:
            warnings.append(
                f"{label} ({name}): taninmayan teknik ID (atlandi, MITRE katalogunda yok): "
                f"{', '.join(unknown)}"
            )

        key = (name.casefold(), product.casefold())
        if key not in merged_incoming:
            merged_incoming[key] = {
                "name": name, "product": product, "techs": [],
                "coverage_level": item["coverage_level"], "kind": item["kind"],
                "origin": item["origin"], "rationale": item["rationale"],
                "confidence": item["confidence"],
            }
            merge_order.append(key)
        else:
            warnings.append(
                f"{label} ({name}): dosyada tekrar ediyor — teknikleri ilk "
                "satirla birlestirildi."
            )
        dest_techs = merged_incoming[key]["techs"]
        for t in techs:
            if t not in dest_techs:
                dest_techs.append(t)

    rule_plan = []
    for key in merge_order:
        entry = merged_incoming[key]
        name, product, techs = entry["name"], entry["product"], entry["techs"]
        canonical_product = known_product_names[product.casefold()]
        existing = existing_rules.get(key)
        if existing:
            current = existing_techs_by_rule.get(existing["id"], set())
            added = [t for t in techs if t not in current]
            rule_plan.append({
                "name": existing["name"], "product": canonical_product,
                "action": "update" if added else "noop",
                "rule_id": existing["id"],
                "existing_techniques": sorted(current),
                "added_techniques": added,
                "techniques": techs,
                "coverage_level": entry["coverage_level"],
                "kind": entry["kind"], "origin": entry["origin"],
                "rationale": entry["rationale"], "confidence": entry["confidence"],
            })
        else:
            rule_plan.append({
                "name": name, "product": canonical_product, "action": "create",
                "rule_id": None, "existing_techniques": [], "added_techniques": techs,
                "techniques": techs, "coverage_level": entry["coverage_level"],
                "kind": entry["kind"], "origin": entry["origin"],
                "rationale": entry["rationale"], "confidence": entry["confidence"],
            })

    summary = {
        "products_new": sum(1 for p in product_plan if p["action"] == "create"),
        "rules_new": sum(1 for r in rule_plan if r["action"] == "create"),
        "rules_updated": sum(1 for r in rule_plan if r["action"] == "update"),
        "rules_unchanged": sum(1 for r in rule_plan if r["action"] == "noop"),
        "techniques_added": sum(len(r["added_techniques"]) for r in rule_plan),
        # Bu satirdan sonra hicbir gecerli teknigi kalmayan kurallar — yeni
        # olsun mevcut olsun. Kullanicinin elle tamamlamasi gereken liste.
        "rules_without_technique": sum(
            1 for r in rule_plan
            if not r["existing_techniques"] and not r["added_techniques"]
        ),
        "errors": len(errors),
        "warnings": len(warnings),
    }
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "products": product_plan,
        "rules": rule_plan,
        "summary": summary,
    }


def _next_product_color(db: sqlite3.Connection, offset: int = 0) -> str:
    """Yeni urune catismayan bir renk sec — kullanici sonradan degistirir."""
    palette = [
        "#1565c0", "#2e7d32", "#6a1b9a", "#ef6c00", "#c62828",
        "#00838f", "#4527a0", "#ad1457", "#37474f", "#9e9d24",
    ]
    used = {
        (r["color"] or "").lower()
        for r in db.execute("SELECT color FROM products").fetchall()
    }
    for i in range(len(palette)):
        candidate = palette[(offset + i) % len(palette)]
        if candidate.lower() not in used:
            return candidate
    return palette[offset % len(palette)]


MAPPING_PROMPT_PATH = BASE_DIR / "docs" / "mitre_mapping_prompt.md"


@app.route("/api/import/mapping-prompt", methods=["GET"])
@role_required("viewer")
def import_mapping_prompt():
    """docs/mitre_mapping_prompt.md icindeki prompt blogunu dondurur.

    Dokuman ve arayuz ayrisamasin diye tek kaynak dosyadir; buradaki is
    yalnizca ```` ile cevrili blogu ayiklamak.
    """
    try:
        text = MAPPING_PROMPT_PATH.read_text(encoding="utf-8")
    except OSError:
        return jsonify({"error": "Prompt dokumani bulunamadi."}), 500
    match = re.search(r"^````text\n(.*?)^````$", text, re.S | re.M)
    if not match:
        return jsonify({"error": "Prompt blogu dokumanda bulunamadi."}), 500
    return jsonify({"prompt": match.group(1).strip()})


@app.route("/api/import/coverage/preview", methods=["POST"])
@role_required("editor")
def import_coverage_preview():
    raw, error = _read_import_payload()
    if error:
        return jsonify({"error": error}), 400
    return jsonify(_plan_coverage_import(get_db(), raw))


@app.route("/api/import/coverage/apply", methods=["POST"])
@role_required("editor")
def import_coverage_apply():
    raw, error = _read_import_payload()
    if error:
        return jsonify({"error": error}), 400

    db = get_db()
    plan = _plan_coverage_import(db, raw)
    if not plan["ok"]:
        # Kismi uygulama yok: hatali bir dosyanin yarisini yazmak, kullaniciyi
        # neyin girdigini bilmedigi bir duruma sokar.
        return jsonify({"error": "Dosyada hatalar var, uygulanmadi.", **plan}), 400

    is_admin = ROLE_LEVELS.get(g.current_user["role"], 0) >= ROLE_LEVELS["admin"]
    new_products = [p for p in plan["products"] if p["action"] == "create"]
    if new_products and not is_admin:
        return jsonify({
            "error": "Dosya yeni urun olusturuyor; bunun icin admin yetkisi gerekir: "
                     + ", ".join(p["name"] for p in new_products),
            **plan,
        }), 403

    applied = _apply_coverage_plan(db, plan)
    db.commit()
    return jsonify({
        "ok": True, "applied": applied,
        "summary": plan["summary"], "warnings": plan["warnings"],
    })


def _apply_coverage_plan(db: sqlite3.Connection, plan: dict) -> dict:
    """Plani yazar. Cagiran taraf yetkiyi kontrol etmis olmali; commit etmez."""
    new_products = [p for p in plan["products"] if p["action"] == "create"]
    for product in new_products:
        db.execute(
            "INSERT INTO products (name, color, category) VALUES (?, ?, ?)",
            (product["name"], product["color"], product["category"]),
        )
        write_audit_log(
            db, action="create", target_type="product", target_id=product["name"],
            detail="source=import",
            after={"name": product["name"], "color": product["color"],
                   "category": product["category"]},
        )

    created = updated = techs_added = 0
    for rule in plan["rules"]:
        if rule["action"] == "noop":
            continue
        rule_id = rule["rule_id"]
        if rule_id is None:
            rule_id = db.execute(
                "INSERT INTO rules (name, tactic, tech, source, coverage_level, origin) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (rule["name"], "none", "none", rule["product"],
                 rule["coverage_level"], rule.get("origin", "named")),
            ).lastrowid
            created += 1
        else:
            updated += 1
        for tech_id in rule["added_techniques"]:
            db.execute(
                "INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
                (rule_id, tech_id),
            )
            techs_added += 1
        write_audit_log(
            db,
            action="create" if rule["action"] == "create" else "update",
            target_type="rule", target_id=str(rule_id),
            detail=f"source=import;product={rule['product']};"
                   f"techniques={','.join(rule['added_techniques'])}",
            after={"name": rule["name"], "source": rule["product"],
                   "added_techniques": rule["added_techniques"],
                   "kind": rule["kind"], "rationale": rule["rationale"]},
        )

    write_audit_log(
        db, action="bulk_create", target_type="rule",
        detail=f"source=import;created={created};updated={updated};"
               f"techniques_added={techs_added};products={len(new_products)}",
    )
    _invalidate_ttp_cache()
    return {
        "products_created": len(new_products),
        "rules_created": created,
        "rules_updated": updated,
        "techniques_added": techs_added,
    }


def _read_import_payload() -> tuple[Any, str | None]:
    """Dosya yuklemesi veya duz JSON govdesi — ikisini de kabul et."""
    file = request.files.get("file")
    if file is not None:
        try:
            return json.loads(file.read().decode("utf-8")), None
        except UnicodeDecodeError:
            return None, "Dosya UTF-8 olmali."
        except json.JSONDecodeError as exc:
            return None, f"Gecersiz JSON: {exc.msg} (satir {exc.lineno})"
    body = request.get_json(silent=True)
    if body is None:
        return None, "JSON dosyasi veya govdesi gerekli."
    return body, None


@app.route("/api/rules/bulk", methods=["POST"])
@role_required("editor")
def rules_bulk():
    """CSV toplu ice aktarim — JSON ice aktarimla ayni planlayiciya baglanir.

    Onceden her satir icin kor bir INSERT yapiyordu; ayni (name, source) ikinci
    kez gelince UNIQUE index'e carpip 500 donuyordu. Artik ayni kuralin birden
    fazla satiri tek kurala birlestirilir (bir kural cok teknik) ve mevcut
    kurallara teknik eklenir.
    """
    db = get_db()
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "CSV dosyasi gerekli"}), 400

    import csv
    try:
        content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        return jsonify({"error": "CSV UTF-8 kodlu olmali"}), 400

    reader = csv.DictReader(content.splitlines())
    if not reader.fieldnames:
        return jsonify({"error": "CSV basligi sunlari icermeli: name,tech,source"}), 400
    headers = {h.strip().lower() for h in reader.fieldnames}
    if not {"name", "tech", "source"}.issubset(headers):
        return jsonify({"error": "CSV basligi sunlari icermeli: name,tech,source"}), 400

    # Ayni (name, source) satirlarini tek kurala topla — bir kural cok teknik.
    merged: dict[tuple[str, str], dict] = {}
    row_errors: list[str] = []
    for i, row in enumerate(reader, start=2):
        norm = {k.strip().lower(): (v or "") for k, v in row.items()}
        name = norm.get("name", "").strip()
        tech = norm.get("tech", "").strip()
        source = norm.get("source", "").strip()
        if not name or not tech or not source:
            row_errors.append(f"Satir {i}: name, tech ve source zorunlu")
            continue
        entry = merged.setdefault(
            (name.casefold(), source.casefold()),
            {"name": name, "product": source, "techniques": [],
             "coverage_level": (norm.get("coverage_level") or "full").strip() or "full"},
        )
        if tech not in entry["techniques"]:
            entry["techniques"].append(tech)

    plan = _plan_coverage_import(db, {
        "schema": IMPORT_SCHEMA_NAME,
        "version": IMPORT_SCHEMA_VERSION,
        "rules": list(merged.values()),
    })
    errors = row_errors + plan["errors"]
    if errors:
        return jsonify({"ok": False, "errors": errors, "summary": plan["summary"]}), 400

    applied = _apply_coverage_plan(db, plan)
    db.commit()
    return jsonify({
        "ok": True,
        "warnings": plan["warnings"],
        "inserted": applied["rules_created"],
        "updated": applied["rules_updated"],
        "techniques_added": applied["techniques_added"],
        "errors": [],
    })


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
@role_required("editor")
def update_rule(rule_id: int):
    """Bir tespitin adini ve/veya kaynagini (urun) sonradan degistirir.

    Ikisi de opsiyonel ama en az biri verilmeli. Urun degisirse kural,
    haritada ve Tespitler listesinde otomatik olarak yeni urunun altina
    tasinir (grup, r.source'a gore kuruluyor) — ayrica bir "tasima"
    islemi gerekmez.
    """
    payload = request.get_json(silent=True) or {}
    db = get_db()
    row = db.execute(
        "SELECT id, name, source FROM rules WHERE id=?", (rule_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "Tespit bulunamadı"}), 404

    name = payload.get("name")
    source = payload.get("source")
    if name is None and source is None:
        return jsonify({"error": "En az 'name' veya 'source' gerekli"}), 400

    new_name = (name if name is not None else row["name"]).strip()
    new_source = (source if source is not None else row["source"]).strip()
    if not new_name:
        return jsonify({"error": "'name' boş olamaz"}), 400
    if not new_source:
        return jsonify({"error": "'source' boş olamaz"}), 400
    if new_source != row["source"] and not _product_exists(db, new_source):
        return jsonify({"error": _UNKNOWN_SOURCE_ERROR.format(source=new_source)}), 400

    try:
        db.execute(
            "UPDATE rules SET name=?, source=? WHERE id=?",
            (new_name, new_source, rule_id),
        )
    except sqlite3.IntegrityError:
        # idx_rules_name_source UNIQUE — bu isim+urun zaten baska bir kuralda var.
        return jsonify({
            "error": "Bu isim ve kaynak için başka bir tespit zaten mevcut."
        }), 409

    write_audit_log(
        db, action="update", target_type="rule", target_id=str(rule_id),
        detail=f"name={new_name};source={new_source}",
        before={"name": row["name"], "source": row["source"]},
        after={"name": new_name, "source": new_source},
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"id": rule_id, "name": new_name, "source": new_source})


@app.route("/api/rules/<int:rule_id>/coverage", methods=["PATCH"])
@role_required("editor")
def update_rule_coverage(rule_id: int):
    payload = request.get_json(silent=True) or {}
    level = (payload.get("coverage_level") or "").strip()
    if level not in ("low", "partial", "full"):
        return jsonify({"error": "Geçersiz değer: low | partial | full"}), 400
    db = get_db()
    row = db.execute("SELECT id, coverage_level FROM rules WHERE id=?", (rule_id,)).fetchone()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    db.execute("UPDATE rules SET coverage_level=? WHERE id=?", (level, rule_id))
    write_audit_log(db, action="update", target_type="rule", target_id=str(rule_id),
                    detail=f"coverage_level={level}",
                    before={"coverage_level": row["coverage_level"]},
                    after={"coverage_level": level})
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@role_required("editor")
def delete_rule(rule_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, name, tactic, tech, source, coverage_level FROM rules WHERE id=?",
        (rule_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "Rule not found"}), 404
    techniques = [
        r["tech_id"] for r in db.execute(
            "SELECT tech_id FROM rule_techniques WHERE rule_id=? ORDER BY tech_id", (rule_id,)
        ).fetchall()
    ]
    db.execute("DELETE FROM rule_techniques WHERE rule_id = ?", (rule_id,))
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    before = dict(row)
    before["techniques"] = techniques
    write_audit_log(
        db, action="delete", target_type="rule", target_id=str(rule_id), before=before
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})




# ── Kural Teknik Yönetimi ─────────────────────────────────────────────────────
# Bir kurala yeni MITRE tekniği ekler veya mevcut tekniği kaldırır.
# Frontend: Kurallar sayfasında her kural satırındaki + input + × buton.
@app.route("/api/rules/<int:rule_id>/techniques", methods=["POST"])
@role_required("editor")
def add_rule_technique(rule_id: int):
    payload = request.get_json(silent=True) or {}
    tech_id = (payload.get("tech_id") or "").strip().upper()
    if not tech_id:
        return jsonify({"error": "tech_id gerekli"}), 400
    db = get_db()
    db.execute("INSERT OR IGNORE INTO rule_techniques (rule_id, tech_id) VALUES (?, ?)",
               (rule_id, tech_id))
    write_audit_log(db, action="create", target_type="rule_technique",
                    target_id=str(rule_id), detail=f"tech_id={tech_id}")
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rules/<int:rule_id>/techniques/<tech_id>", methods=["DELETE"])
@role_required("editor")
def delete_rule_technique(rule_id: int, tech_id: str):
    db = get_db()
    db.execute("DELETE FROM rule_techniques WHERE rule_id = ? AND tech_id = ?",
               (rule_id, tech_id.upper()))
    write_audit_log(db, action="delete", target_type="rule_technique",
                    target_id=str(rule_id), detail=f"tech_id={tech_id}")
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/products", methods=["GET", "POST"])
@role_required_methods({"GET": "viewer", "POST": "admin"})
def products():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, name, color, category FROM products ORDER BY name ASC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    color = (payload.get("color") or "").strip()
    category = (payload.get("category") or PRODUCT_CATEGORY_DEFAULT).strip()
    if not name or not color:
        return jsonify({"error": "Missing fields: name, color"}), 400
    if category not in PRODUCT_CATEGORIES:
        return jsonify({"error": f"Invalid category. Allowed: {', '.join(PRODUCT_CATEGORIES)}"}), 400
    try:
        cur = db.execute(
            "INSERT INTO products (name, color, category) VALUES (?, ?, ?)",
            (name, color, category),
        )
        write_audit_log(
            db,
            action="create",
            target_type="product",
            target_id=str(cur.lastrowid),
            detail=f"name={name};color={color};category={category}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Product already exists"}), 400
    return jsonify({"id": cur.lastrowid, "name": name, "color": color, "category": category}), 201


@app.route("/api/products/<int:product_id>", methods=["DELETE"])
@role_required("admin")
def delete_product(product_id: int):
    db = get_db()
    row = db.execute("SELECT id, name, color FROM products WHERE id=?", (product_id,)).fetchone()
    if not row:
        return jsonify({"error": "Product not found"}), 404
    usage_count = db.execute(
        "SELECT COUNT(*) FROM rules WHERE source=?", (row["name"],)
    ).fetchone()[0]
    if usage_count:
        return jsonify({
            "error": "Ürün tespitler tarafından kullanılıyor.",
            "rule_count": usage_count,
        }), 409
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    write_audit_log(
        db, action="delete", target_type="product", target_id=str(product_id), before=dict(row)
    )
    db.commit()
    return jsonify({"ok": True})




@app.route("/api/products/<int:product_id>", methods=["PUT"])
@role_required("admin")
def update_product(product_id: int):
    db = get_db()
    payload = request.get_json(silent=True) or {}
    row = db.execute(
        "SELECT id, name, color, category FROM products WHERE id=?", (product_id,)
    ).fetchone()
    if not row:
        return jsonify({"error": "Product not found"}), 404
    color = (payload.get("color") or row["color"]).strip()
    category = (payload.get("category") or row["category"]).strip()
    if not color:
        return jsonify({"error": "Missing fields: color"}), 400
    if category not in PRODUCT_CATEGORIES:
        return jsonify({"error": f"Invalid category. Allowed: {', '.join(PRODUCT_CATEGORIES)}"}), 400
    db.execute(
        "UPDATE products SET color = ?, category = ? WHERE id = ?",
        (color, category, product_id),
    )
    write_audit_log(
        db,
        action="update",
        target_type="product",
        target_id=str(product_id),
        detail=f"color={color};category={category}", before=dict(row),
        after={"id": product_id, "name": row["name"], "color": color, "category": category},
    )
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/teams", methods=["GET", "POST"])
@role_required_methods({"GET": "viewer", "POST": "admin"})
def teams_api():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT id, name, created_at FROM teams ORDER BY name ASC"
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Missing fields: name"}), 400
    try:
        cur = db.execute("INSERT INTO teams (name) VALUES (?)", (name,))
        write_audit_log(
            db,
            action="create",
            target_type="team",
            target_id=str(cur.lastrowid),
            detail=f"name={name}",
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Team already exists"}), 400
    return jsonify({"id": cur.lastrowid, "name": name}), 201


@app.route("/api/teams/<int:team_id>", methods=["DELETE"])
@role_required("admin")
def delete_team(team_id: int):
    db = get_db()
    row = db.execute("SELECT id, name, created_at FROM teams WHERE id=?", (team_id,)).fetchone()
    if not row:
        return jsonify({"error": "Team not found"}), 404
    usage_count = db.execute(
        "SELECT COUNT(*) FROM action_items WHERE assigned_team_id=?", (team_id,)
    ).fetchone()[0]
    if usage_count:
        return jsonify({
            "error": "Ekip aksiyon planında kullanılıyor.",
            "action_item_count": usage_count,
        }), 409
    db.execute("DELETE FROM teams WHERE id = ?", (team_id,))
    write_audit_log(
        db, action="delete", target_type="team", target_id=str(team_id), before=dict(row)
    )
    db.commit()
    return jsonify({"ok": True})


def _mitigation_entry_payload(row: sqlite3.Row) -> dict:
    keys = row.keys()
    return {
        "id": row["id"],
        "mitigation_id": row["mitigation_id"] if "mitigation_id" in keys else None,
        "team": row["team"],
        "comment": row["comment"],
        "product_id": row["product_id"],
        "product_name": row["product_name"] if "product_name" in keys else None,
    }


_MITIGATION_ENTRY_SELECT = """
    SELECT e.id, e.mitigation_id, e.team, e.comment, e.product_id, p.name AS product_name
    FROM mitigation_entries e
    LEFT JOIN products p ON p.id = e.product_id
"""


@app.route("/api/mitigation-entries", methods=["GET", "POST"])
@role_required_methods({"GET": "viewer", "POST": "editor"})
def mitigation_entries():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(_MITIGATION_ENTRY_SELECT + " ORDER BY e.id ASC").fetchall()
        return jsonify([_mitigation_entry_payload(r) for r in rows])

    payload = request.get_json(silent=True) or {}
    mitigation_id = (payload.get("mitigation_id") or "").strip()
    team = (payload.get("team") or "").strip()
    comment = (payload.get("comment") or "").strip()
    if not mitigation_id or not team or not comment:
        return jsonify({"error": "Missing fields: mitigation_id, team, comment"}), 400

    # Urun istege bagli: surec/egitim/politika ile saglanan mitigation'lar var.
    # Verilmisse katalogda bulunmak zorunda — serbest metin kabul edilmez.
    raw_product = payload.get("product_id")
    product_id = None
    if raw_product not in (None, "", "null"):
        try:
            product_id = int(raw_product)
        except (TypeError, ValueError):
            return jsonify({"error": "product_id must be an integer"}), 400
        exists = db.execute(
            "SELECT 1 FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        if not exists:
            return jsonify({"error": "Product not found"}), 400

    cur = db.execute(
        "INSERT INTO mitigation_entries (mitigation_id, team, comment, product_id) VALUES (?, ?, ?, ?)",
        (mitigation_id, team, comment, product_id),
    )
    write_audit_log(
        db,
        action="create",
        target_type="mitigation_entry",
        target_id=str(cur.lastrowid),
        detail=f"mitigation_id={mitigation_id};team={team}",
        after={
            "mitigation_id": mitigation_id, "team": team,
            "comment": comment, "product_id": product_id,
        },
    )
    _invalidate_ttp_cache()
    db.commit()
    row = db.execute(
        _MITIGATION_ENTRY_SELECT + " WHERE e.id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(_mitigation_entry_payload(row)), 201


@app.route("/api/mitigation-entries/<int:entry_id>", methods=["DELETE"])
@role_required("editor")
def delete_mitigation_entry(entry_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, mitigation_id, team, comment FROM mitigation_entries WHERE id=?",
        (entry_id,),
    ).fetchone()
    if not row:
        return jsonify({"error": "Mitigation entry not found"}), 404
    db.execute("DELETE FROM mitigation_entries WHERE id = ?", (entry_id,))
    write_audit_log(
        db,
        action="delete",
        target_type="mitigation_entry",
        target_id=str(entry_id),
        before=dict(row),
    )
    _invalidate_ttp_cache()
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
    if len(password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400

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
    if new_password and len(new_password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    if row["role"] == "admin" and row["is_active"] and (next_role != "admin" or not is_active):
        active_admins = db.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
        ).fetchone()[0]
        if active_admins <= 1:
            return jsonify({"error": "The last active admin cannot be demoted or deactivated"}), 409

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
        before=dict(row),
        after={
            "id": user_id, "username": row["username"], "role": next_role,
            "is_active": is_active, "password_changed": bool(new_password),
        },
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/me/password", methods=["PUT"])
@login_required
def change_own_password_api():
    db = get_db()
    user_id = g.current_user["id"]
    row = db.execute("SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404

    payload = request.get_json(silent=True) or {}
    current_password = str(payload.get("current_password", ""))
    new_password = str(payload.get("new_password", "")).strip()

    if not check_password_hash(row["password_hash"], current_password):
        return jsonify({"error": "Current password is incorrect"}), 400
    if len(new_password) < 10:
        return jsonify({"error": "Password must be at least 10 characters"}), 400
    if check_password_hash(row["password_hash"], new_password):
        return jsonify({"error": "New password must be different from the current password"}), 400

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), user_id),
    )
    write_audit_log(
        db,
        action="change_password",
        target_type="user",
        target_id=str(user_id),
        detail=f"username={row['username']};self_service=true",
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/audit-logs", methods=["GET"])
@role_required("admin")
def audit_logs_api():
    db = get_db()
    page_raw = request.args.get("page", "1")
    per_page_raw = request.args.get("per_page", request.args.get("limit", "50"))
    try:
        page = max(1, int(page_raw))
        per_page = max(10, min(200, int(per_page_raw)))
    except ValueError:
        page, per_page = 1, 50

    where, params = _audit_filters(request.args)
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]
    rows = db.execute(
        f"""
        SELECT id, user_id, username, action, target_type, target_id, detail,
               request_id, ip_address, user_agent, before_json, after_json,
               prev_hash, entry_hash, created_at
        FROM audit_logs {where}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        [*params, per_page, (page - 1) * per_page],
    ).fetchall()
    action_rows = db.execute(
        "SELECT action, COUNT(*) AS count FROM audit_logs GROUP BY action ORDER BY count DESC"
    ).fetchall()
    target_rows = db.execute(
        "SELECT target_type, COUNT(*) AS count FROM audit_logs GROUP BY target_type ORDER BY count DESC"
    ).fetchall()
    return jsonify({
        "items": [dict(r) for r in rows],
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": max(1, (total + per_page - 1) // per_page),
        },
        "facets": {
            "actions": [dict(r) for r in action_rows],
            "target_types": [dict(r) for r in target_rows],
        },
        "integrity": verify_audit_chain(db),
    })


def _audit_filters(args: Any) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    filters = {
        "username": "username = ?",
        "action": "action = ?",
        "target_type": "target_type = ?",
    }
    for key, clause in filters.items():
        value = (args.get(key) or "").strip()
        if value:
            clauses.append(clause)
            params.append(value)
    query = (args.get("q") or "").strip()
    if query:
        like = f"%{query}%"
        clauses.append("(target_id LIKE ? OR detail LIKE ? OR request_id LIKE ?)")
        params.extend([like, like, like])
    date_from = (args.get("date_from") or "").strip()
    date_to = (args.get("date_to") or "").strip()
    if date_from:
        clauses.append("created_at >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("created_at <= ?")
        params.append(f"{date_to}T23:59:59Z" if len(date_to) == 10 else date_to)
    return ("WHERE " + " AND ".join(clauses) if clauses else ""), params


@app.route("/api/audit-logs/export", methods=["GET"])
@role_required("admin")
def audit_logs_export_api():
    db = get_db()
    where, params = _audit_filters(request.args)
    rows = db.execute(
        f"""
        SELECT id, created_at, username, action, target_type, target_id, detail,
               request_id, ip_address, user_agent, before_json, after_json,
               prev_hash, entry_hash
        FROM audit_logs {where} ORDER BY id DESC LIMIT 10000
        """,
        params,
    ).fetchall()
    stream = io.StringIO()
    writer = csv.writer(stream)
    headers = [
        "id", "created_at", "username", "action", "target_type", "target_id",
        "detail", "request_id", "ip_address", "user_agent", "before_json",
        "after_json", "prev_hash", "entry_hash",
    ]
    writer.writerow(headers)
    writer.writerows([[row[h] for h in headers] for row in rows])
    filename = f"audit-export-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        "\ufeff" + stream.getvalue(),
        content_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/audit-logs/evidence", methods=["POST"])
@role_required("admin")
def audit_evidence_export_api():
    """Create a self-verifiable audit evidence package for external review."""
    db = get_db()
    supplied = request.get_json(silent=True) or {}
    allowed_filters = {
        key: str(supplied.get(key, "")).strip()
        for key in ("q", "username", "action", "target_type", "date_from", "date_to")
        if str(supplied.get(key, "")).strip()
    }
    write_audit_log(
        db,
        action="export",
        target_type="audit_evidence",
        detail=f"filters={_json_text(allowed_filters)}",
        after={"format": "audit-evidence-1.0", "filters": allowed_filters},
    )
    db.commit()

    where, params = _audit_filters(allowed_filters)
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]
    rows = db.execute(
        f"""
        SELECT id, user_id, username, action, target_type, target_id, detail,
               request_id, ip_address, user_agent, before_json, after_json,
               prev_hash, entry_hash, created_at
        FROM audit_logs {where} ORDER BY id ASC LIMIT 10000
        """,
        params,
    ).fetchall()
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    integrity = verify_audit_chain(db)
    manifest = {
        "schema_version": "audit-evidence-1.0",
        "generated_at": generated_at,
        "generated_by": g.current_user["username"],
        "filters": allowed_filters,
        "record_count": len(rows),
        "source_record_count": total,
        "truncated": total > len(rows),
        "hash_algorithm": "SHA-256",
        "audit_chain": integrity,
    }
    package_core = {"manifest": manifest, "records": [dict(row) for row in rows]}
    canonical = json.dumps(package_core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    package = {**package_core, "export_hash": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}
    body = json.dumps(package, ensure_ascii=False, indent=2)
    filename = f"audit-evidence-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    return Response(
        body,
        content_type="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


QRADAR_DEFAULT_MAPPINGS_PATH = "/console/plugins/app_proxy:UseCaseManager_Service/api/mappings"


def _connector_payload(payload: dict[str, Any], existing: sqlite3.Row | None = None) -> dict[str, Any]:
    current = dict(existing) if existing else {}
    data = {
        "kind": "qradar",
        "name": str(payload.get("name", current.get("name", ""))).strip(),
        "base_url": str(payload.get("base_url", current.get("base_url", ""))).strip().rstrip("/"),
        "secret_env": str(payload.get("secret_env", current.get("secret_env", "QRADAR_SEC_TOKEN"))).strip(),
        "product_name": str(payload.get("product_name", current.get("product_name", "QRadar"))).strip(),
        "mappings_path": str(payload.get("mappings_path", current.get("mappings_path", QRADAR_DEFAULT_MAPPINGS_PATH))).strip(),
        "verify_tls": int(bool(payload.get("verify_tls", current.get("verify_tls", 1)))),
        "ca_bundle": str(payload.get("ca_bundle", current.get("ca_bundle", ""))).strip(),
        "enabled": int(bool(payload.get("enabled", current.get("enabled", 1)))),
        "import_new_rules": int(bool(payload.get("import_new_rules", current.get("import_new_rules", 1)))),
    }
    parsed = urlparse(data["base_url"])
    allow_http = app.config.get("TESTING") and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if not data["name"] or not parsed.hostname or (parsed.scheme != "https" and not allow_http):
        raise ValueError("QRadar adı ve geçerli bir HTTPS base URL gereklidir")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Base URL kullanıcı bilgisi, query veya fragment içeremez")
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", data["secret_env"]):
        raise ValueError("Token ortam değişkeni yalnızca A-Z, 0-9 ve alt çizgi içermelidir")
    if not data["product_name"] or not data["mappings_path"].startswith("/"):
        raise ValueError("Ürün adı ve / ile başlayan mappings path gereklidir")
    if data["ca_bundle"] and not Path(data["ca_bundle"]).is_file():
        raise ValueError("CA bundle dosyası bulunamadı")
    return data


def _connector_view(db: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["token_configured"] = bool(os.environ.get(row["secret_env"], "").strip())
    item["inventory"] = dict(db.execute(
        """
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN stale=0 AND enabled=1 THEN 1 ELSE 0 END) AS active,
               SUM(CASE WHEN stale=1 THEN 1 ELSE 0 END) AS stale,
               SUM(CASE WHEN origin='custom' THEN 1 ELSE 0 END) AS custom,
               SUM(CASE WHEN origin='vendor_builtin' THEN 1 ELSE 0 END) AS built_in
        FROM external_detections WHERE connector_id=?
        """,
        (row["id"],),
    ).fetchone())
    item["linked_rules"] = db.execute(
        "SELECT COUNT(*) FROM rule_external_refs WHERE connector_id=?", (row["id"],)
    ).fetchone()[0]
    item["recent_runs"] = [dict(run) for run in db.execute(
        "SELECT * FROM connector_sync_runs WHERE connector_id=? ORDER BY id DESC LIMIT 10",
        (row["id"],),
    ).fetchall()]
    return item


def _qradar_client(connector: sqlite3.Row) -> QRadarClient:
    token = os.environ.get(connector["secret_env"], "").strip()
    if not token:
        raise QRadarConnectorError(f"Token ortam değişkeni tanımlı değil: {connector['secret_env']}")
    return QRadarClient(
        connector["base_url"],
        token,
        connector["mappings_path"],
        verify_tls=bool(connector["verify_tls"]),
        ca_bundle=connector["ca_bundle"],
    )


def _run_qradar_sync(db: sqlite3.Connection, connector: sqlite3.Row) -> dict[str, Any]:
    running = db.execute(
        "SELECT id,started_at FROM connector_sync_runs WHERE connector_id=? AND status='running' ORDER BY id DESC LIMIT 1",
        (connector["id"],),
    ).fetchone()
    if running:
        try:
            running_since = datetime.fromisoformat(running["started_at"].replace("Z", "+00:00"))
        except ValueError:
            running_since = datetime.now(timezone.utc)
        if datetime.now(timezone.utc) - running_since < timedelta(minutes=15):
            raise QRadarConnectorError("Bu connector için başka bir senkronizasyon çalışıyor")
        db.execute(
            "UPDATE connector_sync_runs SET status='failed',finished_at=?,error='Senkronizasyon zaman aşımına uğradı' WHERE id=?",
            (datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), running["id"]),
        )
        db.commit()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    cursor = db.execute(
        "INSERT INTO connector_sync_runs (connector_id,status,triggered_by,started_at) VALUES (?, 'running', ?, ?)",
        (connector["id"], g.current_user["username"], started_at),
    )
    run_id = cursor.lastrowid
    db.commit()
    try:
        detections = _qradar_client(connector).fetch_detections()
        if not detections:
            raise QRadarConnectorError("QRadar mapping yanıtında kullanılabilir kural bulunamadı")
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        stats = {
            "received": len(detections), "created": 0, "updated": 0, "unchanged": 0,
            "linked_existing": 0, "rules_created": 0, "stale": 0,
            "mapping_count": sum(len(item["techniques"]) for item in detections),
        }
        db.execute("INSERT OR IGNORE INTO products (name,color) VALUES (?, '#2e7d32')", (connector["product_name"],))
        seen: set[str] = set()
        catalog = _attack_catalog()["techniques"]
        for detection in detections:
            native_id = detection["native_id"]
            seen.add(native_id)
            previous = db.execute(
                "SELECT payload_hash FROM external_detections WHERE connector_id=? AND native_id=?",
                (connector["id"], native_id),
            ).fetchone()
            if previous is None:
                stats["created"] += 1
            elif previous["payload_hash"] != detection["payload_hash"]:
                stats["updated"] += 1
            else:
                stats["unchanged"] += 1
            db.execute(
                """
                INSERT INTO external_detections (
                    connector_id,native_id,name,origin,enabled,rule_type,severity,
                    offense_count,last_offense_at,payload_hash,first_seen_at,last_seen_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(connector_id,native_id) DO UPDATE SET
                    name=excluded.name, origin=excluded.origin, enabled=excluded.enabled,
                    rule_type=excluded.rule_type, severity=excluded.severity,
                    offense_count=excluded.offense_count, last_offense_at=excluded.last_offense_at,
                    payload_hash=excluded.payload_hash, last_seen_at=excluded.last_seen_at,
                    missing_sync_count=0, stale=0
                """,
                (
                    connector["id"], native_id, detection["name"], detection["origin"],
                    int(detection["enabled"]), detection["rule_type"], detection["severity"],
                    detection["offense_count"], detection["last_offense_at"], detection["payload_hash"], now, now,
                ),
            )
            db.execute(
                "DELETE FROM external_detection_techniques WHERE connector_id=? AND native_id=?",
                (connector["id"], native_id),
            )
            db.executemany(
                "INSERT INTO external_detection_techniques (connector_id,native_id,tech_id) VALUES (?,?,?)",
                [(connector["id"], native_id, tech_id) for tech_id in detection["techniques"]],
            )
            linked = db.execute(
                "SELECT rule_id FROM rule_external_refs WHERE connector_id=? AND native_id=?",
                (connector["id"], native_id),
            ).fetchone()
            if linked:
                continue
            candidates = db.execute(
                "SELECT id FROM rules WHERE source=? AND lower(trim(name))=lower(trim(?)) ORDER BY id",
                (connector["product_name"], detection["name"]),
            ).fetchall()
            if len(candidates) == 1:
                rule_id = candidates[0]["id"]
                match_method = "exact_name"
                stats["linked_existing"] += 1
            elif connector["import_new_rules"]:
                first_tech = detection["techniques"][0] if detection["techniques"] else "none"
                technique = catalog.get(first_tech, {})
                tactics = technique.get("tactics", []) if isinstance(technique, dict) else []
                tactic = tactics[0] if tactics else "none"
                rule_id = db.execute(
                    "INSERT INTO rules (name,tactic,tech,source,coverage_level) VALUES (?,?,?,?,?)",
                    (detection["name"], tactic, first_tech, connector["product_name"], "low"),
                ).lastrowid
                db.executemany(
                    "INSERT OR IGNORE INTO rule_techniques (rule_id,tech_id) VALUES (?,?)",
                    [(rule_id, tech_id) for tech_id in detection["techniques"]],
                )
                match_method = "connector_created"
                stats["rules_created"] += 1
            else:
                continue
            db.execute(
                "INSERT INTO rule_external_refs (rule_id,connector_id,native_id,match_method,linked_at) VALUES (?,?,?,?,?)",
                (rule_id, connector["id"], native_id, match_method, now),
            )

        existing_ids = [row["native_id"] for row in db.execute(
            "SELECT native_id FROM external_detections WHERE connector_id=?", (connector["id"],)
        ).fetchall()]
        for native_id in existing_ids:
            if native_id not in seen:
                db.execute(
                    """
                    UPDATE external_detections SET missing_sync_count=missing_sync_count+1,
                        stale=CASE WHEN missing_sync_count+1>=3 THEN 1 ELSE stale END
                    WHERE connector_id=? AND native_id=?
                    """,
                    (connector["id"], native_id),
                )
        stats["stale"] = db.execute(
            "SELECT COUNT(*) FROM external_detections WHERE connector_id=? AND stale=1", (connector["id"],)
        ).fetchone()[0]
        payload_hash = hashlib.sha256("".join(item["payload_hash"] for item in detections).encode("ascii")).hexdigest()
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        db.execute(
            """
            UPDATE connector_sync_runs SET status='success',finished_at=?,received=?,created=?,updated=?,
                unchanged=?,linked_existing=?,rules_created=?,stale=?,mapping_count=?,payload_hash=? WHERE id=?
            """,
            (
                finished_at, stats["received"], stats["created"], stats["updated"], stats["unchanged"],
                stats["linked_existing"], stats["rules_created"], stats["stale"], stats["mapping_count"], payload_hash, run_id,
            ),
        )
        db.execute(
            "UPDATE connectors SET last_status='success',last_sync_at=?,last_error='',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (finished_at, connector["id"]),
        )
        write_audit_log(db, "sync", "connector", str(connector["id"]), f"qradar;received={stats['received']};created={stats['created']};updated={stats['updated']};rules_created={stats['rules_created']}", after={**stats, "payload_hash": payload_hash})
        _invalidate_ttp_cache()
        db.commit()
        return {"run_id": run_id, "status": "success", **stats, "payload_hash": payload_hash}
    except Exception as exc:
        error = str(exc)[:1000]
        finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        db.rollback()
        db.execute(
            "UPDATE connector_sync_runs SET status='failed',finished_at=?,error=? WHERE id=?",
            (finished_at, error, run_id),
        )
        db.execute(
            "UPDATE connectors SET last_status='failed',last_error=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (error, connector["id"]),
        )
        write_audit_log(db, "sync_failed", "connector", str(connector["id"]), error)
        db.commit()
        raise QRadarConnectorError(error) from exc


@app.route("/api/connectors", methods=["GET", "POST"])
@role_required("admin")
def connectors_api():
    db = get_db()
    if request.method == "GET":
        return jsonify([_connector_view(db, row) for row in db.execute("SELECT * FROM connectors ORDER BY name").fetchall()])
    try:
        data = _connector_payload(request.get_json(silent=True) or {})
        columns = list(data)
        cursor = db.execute(
            f"INSERT INTO connectors ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [data[column] for column in columns],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu connector adı zaten kullanılıyor"}), 409
    write_audit_log(db, "create", "connector", str(cursor.lastrowid), "kind=qradar", after=data)
    db.commit()
    return jsonify({"id": cursor.lastrowid}), 201


@app.route("/api/connectors/<int:connector_id>", methods=["PUT"])
@role_required("admin")
def connector_api(connector_id: int):
    db = get_db()
    existing = db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not existing:
        return jsonify({"error": "Connector bulunamadı"}), 404
    try:
        data = _connector_payload(request.get_json(silent=True) or {}, existing)
        assignments = ",".join(f"{column}=?" for column in data)
        db.execute(
            f"UPDATE connectors SET {assignments},updated_at=CURRENT_TIMESTAMP WHERE id=?",
            [data[column] for column in data] + [connector_id],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu connector adı zaten kullanılıyor"}), 409
    write_audit_log(db, "update", "connector", str(connector_id), before=dict(existing), after=data)
    db.commit()
    return jsonify(_connector_view(db, db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()))


@app.route("/api/connectors/<int:connector_id>/test", methods=["POST"])
@role_required("admin")
def connector_test_api(connector_id: int):
    db = get_db()
    connector = db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not connector:
        return jsonify({"error": "Connector bulunamadı"}), 404
    try:
        result = _qradar_client(connector).test()
    except QRadarConnectorError as exc:
        write_audit_log(db, "test_failed", "connector", str(connector_id), str(exc))
        db.commit()
        return jsonify({"error": str(exc)}), 502
    write_audit_log(db, "test", "connector", str(connector_id), f"mapping_records={result['mapping_records']}")
    db.commit()
    return jsonify(result)


@app.route("/api/connectors/<int:connector_id>/sync", methods=["POST"])
@role_required("admin")
def connector_sync_api(connector_id: int):
    db = get_db()
    connector = db.execute("SELECT * FROM connectors WHERE id=?", (connector_id,)).fetchone()
    if not connector:
        return jsonify({"error": "Connector bulunamadı"}), 404
    if not connector["enabled"]:
        return jsonify({"error": "Connector devre dışı"}), 409
    try:
        return jsonify(_run_qradar_sync(db, connector))
    except QRadarConnectorError as exc:
        return jsonify({"error": str(exc)}), 502


ENV_CODE_RE = re.compile(r"[A-Z0-9][A-Z0-9_-]{1,31}")
MONITORING_STATUSES = {"unknown", "none", "partial", "full"}
MONITORING_MODES = {"agent", "log_forwarding", "api", "network", "hybrid", "other"}


def _environment_payload(payload: dict[str, Any], current: sqlite3.Row | None = None) -> dict[str, Any]:
    old = dict(current) if current else {}
    data = {
        "name": str(payload.get("name", old.get("name", ""))).strip(),
        "code": str(payload.get("code", old.get("code", ""))).strip().upper(),
        "description": str(payload.get("description", old.get("description", ""))).strip(),
        "criticality": int(payload.get("criticality", old.get("criticality", 3))),
        "owner": str(payload.get("owner", old.get("owner", ""))).strip(),
        "asset_count": int(payload.get("asset_count", old.get("asset_count", 0))),
        "active": int(bool(payload.get("active", old.get("active", 1)))),
    }
    if not data["name"] or not ENV_CODE_RE.fullmatch(data["code"]):
        raise ValueError("Ortam adı ve 2-32 karakterlik kod gereklidir")
    if not 1 <= data["criticality"] <= 5:
        raise ValueError("Kritiklik 1-5 arasında olmalıdır")
    if data["asset_count"] < 0:
        raise ValueError("Varlık sayısı negatif olamaz")
    return data


@app.route("/api/scope-registry", methods=["GET"])
@role_required("viewer")
def scope_registry_api():
    db = get_db()
    environments = []
    for environment in db.execute("SELECT * FROM environments ORDER BY active DESC,name").fetchall():
        env = dict(environment)
        env["deployments"] = [dict(row) for row in db.execute(
            """
            SELECT pd.*,p.name AS product_name,p.color AS product_color,p.category AS product_category,
                   c.name AS connector_name,
                   (SELECT COUNT(*) FROM rule_external_refs rer WHERE rer.connector_id=pd.connector_id) AS connector_detection_count
            FROM product_deployments pd JOIN products p ON p.id=pd.product_id
            LEFT JOIN connectors c ON c.id=pd.connector_id
            WHERE pd.environment_id=? ORDER BY p.name
            """,
            (environment["id"],),
        ).fetchall()]
        environments.append(env)
    connectors = [dict(row) for row in db.execute(
        "SELECT id,name,product_name,last_status,last_sync_at,enabled FROM connectors ORDER BY name"
    ).fetchall()]
    summary = {
        "environment_count": sum(1 for env in environments if env["active"]),
        "asset_count": sum(env["asset_count"] for env in environments if env["active"]),
        "reviewed_deployments": db.execute("SELECT COUNT(*) FROM product_deployments WHERE monitoring_status!='unknown'").fetchone()[0],
    }
    return jsonify({
        "environments": environments,
        "products": [dict(row) for row in db.execute(
            "SELECT id,name,color,category FROM products ORDER BY name"
        ).fetchall()],
        "connectors": connectors,
        "summary": summary,
    })


@app.route("/api/environments", methods=["POST"])
@role_required("admin")
def environments_api():
    db = get_db()
    try:
        data = _environment_payload(request.get_json(silent=True) or {})
        columns = list(data)
        cursor = db.execute(
            f"INSERT INTO environments ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            [data[column] for column in columns],
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ortam adı veya kodu zaten kullanılıyor"}), 409
    write_audit_log(db, "create", "environment", str(cursor.lastrowid), after=data)
    db.commit()
    return jsonify({"id": cursor.lastrowid}), 201


@app.route("/api/environments/<int:environment_id>", methods=["PUT"])
@role_required("admin")
def environment_api(environment_id: int):
    db = get_db()
    current = db.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    if not current:
        return jsonify({"error": "Ortam bulunamadı"}), 404
    try:
        data = _environment_payload(request.get_json(silent=True) or {}, current)
        db.execute(
            "UPDATE environments SET name=?,code=?,description=?,criticality=?,owner=?,asset_count=?,active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (*data.values(), environment_id),
        )
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except sqlite3.IntegrityError:
        return jsonify({"error": "Ortam adı veya kodu zaten kullanılıyor"}), 409
    write_audit_log(db, "update", "environment", str(environment_id), before=dict(current), after=data)
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/environments/<int:environment_id>", methods=["DELETE"])
@role_required("admin")
def delete_environment_api(environment_id: int):
    db = get_db()
    current = db.execute("SELECT * FROM environments WHERE id=?", (environment_id,)).fetchone()
    if not current:
        return jsonify({"error": "Ortam bulunamadı"}), 404
    # product_deployments FK'si ON DELETE CASCADE — izleme kayitlari birlikte gider.
    db.execute("DELETE FROM environments WHERE id=?", (environment_id,))
    write_audit_log(db, "delete", "environment", str(environment_id), before=dict(current))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/environments/<int:environment_id>/monitoring", methods=["PUT"])
@role_required("editor")
def environment_monitoring_api(environment_id: int):
    """Bir ortamda hangi urunun ne kadar izledigini kaydeder.

    Onceden varlik grubu seviyesindeydi; Faz 4'te ortam seviyesine tasindi.
    """
    db = get_db()
    if not db.execute("SELECT 1 FROM environments WHERE id=?", (environment_id,)).fetchone():
        return jsonify({"error": "Ortam bulunamadı"}), 404
    payload = request.get_json(silent=True) or {}
    rows = payload.get("deployments", [])
    if not isinstance(rows, list) or not rows:
        return jsonify({"error": "En az bir ürün değerlendirmesi gereklidir"}), 400
    before = [dict(row) for row in db.execute(
        "SELECT * FROM product_deployments WHERE environment_id=? ORDER BY product_id", (environment_id,)
    ).fetchall()]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        for row in rows:
            product_id = int(row.get("product_id"))
            product = db.execute("SELECT name FROM products WHERE id=?", (product_id,)).fetchone()
            if not product:
                raise ValueError("Geçersiz ürün")
            status = str(row.get("monitoring_status", "unknown"))
            mode = str(row.get("monitoring_mode", "other"))
            percent = int(row.get("coverage_percent", 0))
            connector_id = int(row["connector_id"]) if row.get("connector_id") else None
            if status not in MONITORING_STATUSES or mode not in MONITORING_MODES:
                raise ValueError("Geçersiz izleme durumu veya yöntemi")
            if status in {"unknown", "none"}:
                percent = 0
            elif status == "full":
                percent = 100
            elif not 1 <= percent <= 99:
                raise ValueError("Kısmi kapsam yüzdesi 1-99 arasında olmalıdır")
            if status == "none":
                connector_id = None
            if connector_id:
                connector = db.execute("SELECT product_name FROM connectors WHERE id=?", (connector_id,)).fetchone()
                if not connector or connector["product_name"] != product["name"]:
                    raise ValueError(f"Connector ürün etiketi {product['name']} ile eşleşmiyor")
            db.execute(
                """
                INSERT INTO product_deployments (
                    environment_id,product_id,connector_id,monitoring_status,coverage_percent,
                    monitoring_mode,owner,notes,reviewed_by,reviewed_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(environment_id,product_id) DO UPDATE SET
                    connector_id=excluded.connector_id,monitoring_status=excluded.monitoring_status,
                    coverage_percent=excluded.coverage_percent,monitoring_mode=excluded.monitoring_mode,
                    owner=excluded.owner,notes=excluded.notes,reviewed_by=excluded.reviewed_by,
                    reviewed_at=excluded.reviewed_at,updated_at=CURRENT_TIMESTAMP
                """,
                (
                    environment_id, product_id, connector_id, status, percent, mode,
                    str(row.get("owner", "")).strip(), str(row.get("notes", "")).strip(),
                    g.current_user["username"], now,
                ),
            )
    except (ValueError, TypeError) as exc:
        db.rollback()
        return jsonify({"error": str(exc)}), 400
    after = [dict(row) for row in db.execute(
        "SELECT * FROM product_deployments WHERE environment_id=? ORDER BY product_id", (environment_id,)
    ).fetchall()]
    write_audit_log(db, "assess", "environment_monitoring", str(environment_id),
                    f"products={len(rows)}", before=before, after=after)
    db.commit()
    return jsonify({"ok": True, "reviewed_at": now})



def _mitre_catalog() -> dict[str, Any]:
    mitre = get_minified_mitre()
    technique_ids: set[str] = set()
    technique_names: dict[str, str] = {}
    mitigation_ids: set[str] = set()
    tactics: set[str] = set()
    for obj in mitre.get("objects", []):
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "attack-pattern":
            external_id = next(
                (
                    ref.get("external_id", "")
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            if external_id.startswith("T"):
                technique_ids.add(external_id.upper())
                technique_names[obj.get("name", "").strip().casefold()] = external_id.upper()
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.add(phase.get("phase_name", ""))
        elif obj.get("type") == "course-of-action":
            external_id = next(
                (
                    ref.get("external_id", "")
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            if external_id.startswith("M"):
                mitigation_ids.add(external_id.upper())
    for legacy_name, technique_id in TECHNIQUE_NAME_ALIASES.items():
        if technique_id in technique_ids:
            technique_names[legacy_name] = technique_id
    return {
        "technique_ids": technique_ids,
        "technique_names": technique_names,
        "mitigation_ids": mitigation_ids,
        "tactics": tactics,
    }


def _compute_data_quality(db: sqlite3.Connection) -> dict[str, Any]:
    catalog = _mitre_catalog()
    valid_ids = catalog["technique_ids"]
    name_to_id = catalog["technique_names"]
    valid_tactics = catalog["tactics"]
    tactic_aliases = {label.casefold(): slug for slug, label in _TACTIC_LABEL_MAP.items()}
    products = {r["name"] for r in db.execute("SELECT name FROM products").fetchall()}
    rules = db.execute(
        "SELECT id, name, tactic, source, coverage_level FROM rules ORDER BY id"
    ).fetchall()
    relations = db.execute(
        """
        SELECT rt.rule_id, rt.tech_id, r.name AS rule_name
        FROM rule_techniques rt
        LEFT JOIN rules r ON r.id = rt.rule_id
        ORDER BY rt.rule_id, rt.tech_id
        """
    ).fetchall()
    mapped_by_rule: dict[int, int] = {}
    issues: list[dict[str, Any]] = []
    invalid_mappings = 0
    legacy_mappings = 0
    orphan_relations = 0

    for relation in relations:
        tech_value = (relation["tech_id"] or "").strip()
        if relation["rule_name"] is None:
            orphan_relations += 1
            issues.append({
                "severity": "critical", "type": "orphan_mapping",
                "entity_id": relation["rule_id"], "value": tech_value,
                "message": "Silinmiş bir tespite bağlı teknik eşlemesi.",
            })
            continue
        normalized = tech_value.upper()
        if normalized in valid_ids:
            mapped_by_rule[relation["rule_id"]] = mapped_by_rule.get(relation["rule_id"], 0) + 1
        elif tech_value.casefold() in name_to_id:
            legacy_mappings += 1
            issues.append({
                "severity": "warning", "type": "legacy_mapping",
                "entity_id": relation["rule_id"], "value": tech_value,
                "suggested_value": name_to_id[tech_value.casefold()],
                "message": "Teknik adı kullanılmış; standart MITRE ID'ye dönüştürülmeli.",
            })
        else:
            invalid_mappings += 1
            issues.append({
                "severity": "critical", "type": "invalid_mapping",
                "entity_id": relation["rule_id"], "value": tech_value,
                "message": "MITRE veri setinde bulunmayan teknik eşlemesi.",
            })

    unmapped = 0
    unknown_products = 0
    invalid_tactics = 0
    invalid_coverage = 0
    for rule in rules:
        if mapped_by_rule.get(rule["id"], 0) == 0:
            unmapped += 1
            issues.append({
                "severity": "critical", "type": "unmapped_rule",
                "entity_id": rule["id"], "value": rule["name"],
                "message": "Tespit geçerli bir MITRE tekniğine bağlı değil.",
            })
        if rule["source"] not in products:
            unknown_products += 1
            issues.append({
                # critical: katalogda olmayan kaynak, ortam bazlı kapsama hesabında
                # hiçbir varlık grubuna bağlanamaz — teknik sessizce kapsanmamış görünür.
                "severity": "critical", "type": "unknown_product",
                "entity_id": rule["id"], "value": rule["source"],
                "message": "Tespitin veri kaynağı ürün kataloğunda bulunmuyor; hiçbir ortamda kapsama sağlamaz.",
            })
        tactic = (rule["tactic"] or "").strip()
        tactic_key = tactic.casefold()
        if tactic_key not in valid_tactics and tactic_key not in tactic_aliases and tactic_key != "none":
            invalid_tactics += 1
            issues.append({
                "severity": "warning", "type": "invalid_tactic",
                "entity_id": rule["id"], "value": tactic,
                "message": "Taktik alanı MITRE Enterprise taktikleriyle eşleşmiyor.",
            })
        if rule["coverage_level"] not in ("low", "partial", "full"):
            invalid_coverage += 1
            issues.append({
                "severity": "warning", "type": "invalid_coverage",
                "entity_id": rule["id"], "value": rule["coverage_level"],
                "message": "Geçersiz tespit güven seviyesi.",
            })

    total_rules = len(rules)
    relation_count = len(relations)
    deductions = (
        (unmapped / max(total_rules, 1)) * 45
        + ((invalid_mappings + orphan_relations) / max(relation_count, 1)) * 30
        + (unknown_products / max(total_rules, 1)) * 10
        + (invalid_tactics / max(total_rules, 1)) * 10
        + (invalid_coverage / max(total_rules, 1)) * 5
    )
    quality_score = round(max(0.0, 100.0 - deductions), 1)
    mitre_stat = MITRE_PATH.stat()
    return {
        "summary": {
            "quality_score": quality_score,
            "total_rules": total_rules,
            "validly_mapped_rules": total_rules - unmapped,
            "unmapped_rules": unmapped,
            "relation_count": relation_count,
            "invalid_mappings": invalid_mappings,
            "legacy_mappings": legacy_mappings,
            "orphan_relations": orphan_relations,
            "unknown_products": unknown_products,
            "invalid_tactics": invalid_tactics,
            "invalid_coverage_levels": invalid_coverage,
            "critical_issue_count": sum(1 for issue in issues if issue["severity"] == "critical"),
            "warning_count": sum(1 for issue in issues if issue["severity"] == "warning"),
        },
        "dataset": {
            "path": "data/mitre.json",
            "size_bytes": mitre_stat.st_size,
            "modified_at": datetime.fromtimestamp(mitre_stat.st_mtime, timezone.utc).isoformat(),
            "technique_count": len(valid_ids),
            "mitigation_count": len(catalog["mitigation_ids"]),
        },
        "issues": issues[:500],
        "issue_count": len(issues),
    }


@app.route("/api/data-quality", methods=["GET"])
@role_required("viewer")
def data_quality_api():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    return jsonify(_compute_data_quality(get_db()))


@app.route("/api/data-quality/repair", methods=["POST"])
@role_required("admin")
def data_quality_repair_api():
    db = get_db()
    before = _compute_data_quality(db)["summary"]
    catalog = _mitre_catalog()
    name_to_id = catalog["technique_names"]
    repaired = {
        "legacy_mappings": 0, "placeholder_mappings": 0,
        "orphan_relations": 0, "tactics": 0,
    }

    for row in db.execute("SELECT rule_id, tech_id FROM rule_techniques").fetchall():
        canonical = name_to_id.get((row["tech_id"] or "").strip().casefold())
        if canonical:
            db.execute(
                "INSERT OR IGNORE INTO rule_techniques(rule_id, tech_id) VALUES (?, ?)",
                (row["rule_id"], canonical),
            )
            db.execute(
                "DELETE FROM rule_techniques WHERE rule_id=? AND tech_id=?",
                (row["rule_id"], row["tech_id"]),
            )
            repaired["legacy_mappings"] += 1
        elif (row["tech_id"] or "").strip().casefold() in ("", "none", "null", "-"):
            db.execute(
                "DELETE FROM rule_techniques WHERE rule_id=? AND tech_id=?",
                (row["rule_id"], row["tech_id"]),
            )
            repaired["placeholder_mappings"] += 1
    cur = db.execute(
        "DELETE FROM rule_techniques WHERE rule_id NOT IN (SELECT id FROM rules)"
    )
    repaired["orphan_relations"] = cur.rowcount
    tactic_aliases = {label.casefold(): slug for slug, label in _TACTIC_LABEL_MAP.items()}
    for row in db.execute("SELECT id, tactic FROM rules").fetchall():
        canonical = tactic_aliases.get((row["tactic"] or "").strip().casefold())
        if canonical and row["tactic"] != canonical:
            db.execute("UPDATE rules SET tactic=? WHERE id=?", (canonical, row["id"]))
            repaired["tactics"] += 1
    _invalidate_ttp_cache()
    after = _compute_data_quality(db)["summary"]
    write_audit_log(
        db, action="repair", target_type="data_quality",
        detail=_json_text(repaired), before=before, after=after,
    )
    db.commit()
    return jsonify({"ok": True, "repaired": repaired, "before": before, "after": after})

_TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


def _invalidate_ttp_cache():
    TTP_LIST_CACHE["dirty"] = True


@app.route("/api/ttp-list")
@role_required("viewer")
def ttp_list():
    if not TTP_LIST_CACHE["dirty"] and TTP_LIST_CACHE["data"] is not None:
        return jsonify(TTP_LIST_CACHE["data"])
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        mitre = get_minified_mitre()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    db = get_db()

    # Build lookup structures from minified MITRE data
    tech_by_stix: dict[str, dict] = {}
    mitigation_stix_to_ext: dict[str, str] = {}
    tech_to_mitigations: dict[str, set] = {}

    for obj in mitre["objects"]:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("T")
                ),
                None,
            )
            if not ext_id:
                continue
            tactics = [
                ph["phase_name"]
                for ph in obj.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            ]
            is_sub = obj.get("x_mitre_is_subtechnique", False)
            parent_id = ext_id.split(".")[0] if is_sub and "." in ext_id else None
            tech_by_stix[obj["id"]] = {
                "external_id": ext_id,
                "name": obj.get("name", ""),
                "is_subtechnique": is_sub,
                "parent_id": parent_id,
                "tactics": tactics,
            }
        elif t == "course-of-action":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("M")
                ),
                None,
            )
            if ext_id:
                mitigation_stix_to_ext[obj["id"]] = ext_id
        elif t == "relationship" and obj.get("relationship_type") == "mitigates":
            mit_ext = mitigation_stix_to_ext.get(obj.get("source_ref", ""))
            tech_info = tech_by_stix.get(obj.get("target_ref", ""))
            if mit_ext and tech_info:
                tech_to_mitigations.setdefault(tech_info["external_id"], set()).add(mit_ext)

    # Rule counts per tech_id
    rule_rows = db.execute(
        "SELECT tech_id, COUNT(DISTINCT rule_id) AS cnt FROM rule_techniques GROUP BY tech_id"
    ).fetchall()
    rule_count_by_tech = {r["tech_id"]: r["cnt"] for r in rule_rows}

    # Covered mitigations (has entries or globally checked)
    covered_mits = set(
        r["mitigation_id"]
        for r in db.execute(
            "SELECT DISTINCT mitigation_id FROM mitigation_entries"
        ).fetchall()
    )

    # Technique config
    tc_rows = db.execute(
        "SELECT tech_id, rule_threshold, group_count FROM technique_config"
    ).fetchall()
    technique_config_map = {
        r["tech_id"]: {"rule_threshold": r["rule_threshold"], "group_count": r["group_count"]}
        for r in tc_rows
    }

    # Build tactic groups
    tactic_techs: dict[str, list] = {}
    for _stix_id, info in tech_by_stix.items():
        teid = info["external_id"]
        tc = technique_config_map.get(teid, {})
        rule_threshold = tc.get("rule_threshold", DEFAULT_RULE_THRESHOLD)
        mits_for_tech = tech_to_mitigations.get(teid, set())
        tech_data = {
            "tech_id": teid,
            "name": info["name"],
            "is_subtechnique": info["is_subtechnique"],
            "parent_id": info["parent_id"],
            "rule_count": rule_count_by_tech.get(teid, 0),
            "mitigation_entry_count": len(mits_for_tech & covered_mits),
            "total_mitigations": len(mits_for_tech),
            "rule_threshold": rule_threshold,
            "group_count": tc.get("group_count", 0) or 0,
        }
        for tactic in info["tactics"]:
            tactic_techs.setdefault(tactic, []).append(tech_data)

    result = []
    for tactic in _TACTIC_ORDER:
        if tactic in tactic_techs:
            result.append({
                "tactic": tactic,
                "techniques": sorted(tactic_techs[tactic], key=lambda x: x["tech_id"]),
            })
    for tactic, techs in tactic_techs.items():
        if tactic not in _TACTIC_ORDER:
            result.append({
                "tactic": tactic,
                "techniques": sorted(techs, key=lambda x: x["tech_id"]),
            })
    TTP_LIST_CACHE["data"] = result
    TTP_LIST_CACHE["dirty"] = False
    return jsonify(result)


@app.route("/api/technique-detail/<tech_id>")
@role_required("viewer")
def technique_detail(tech_id: str):
    tech_id = tech_id.upper()
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        mitre = get_minified_mitre()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    db = get_db()

    tech_obj: dict | None = None
    mitigation_stix_to_info: dict[str, dict] = {}
    tech_mitigations: list[str] = []

    for obj in mitre["objects"]:
        t = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if t == "attack-pattern":
            for ref in obj.get("external_references", []):
                if (
                    ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").upper() == tech_id
                ):
                    tech_obj = obj
                    break
        elif t == "course-of-action":
            ext_id = next(
                (
                    ref["external_id"]
                    for ref in obj.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                    and ref.get("external_id", "").startswith("M")
                ),
                None,
            )
            if ext_id:
                mitigation_stix_to_info[obj["id"]] = {
                    "mitigation_id": ext_id,
                    "name": obj.get("name", ""),
                    "description": (obj.get("description") or "")[:200],
                }

    if not tech_obj:
        return jsonify({"error": f"Technique {tech_id} not found"}), 404

    tech_stix_id = tech_obj["id"]
    for obj in mitre["objects"]:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
            and obj.get("target_ref") == tech_stix_id
        ):
            mit_stix = obj.get("source_ref", "")
            if mit_stix in mitigation_stix_to_info:
                tech_mitigations.append(mit_stix)

    # MITRE URL
    mitre_url = next(
        (
            ref.get("url", "")
            for ref in tech_obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ),
        "",
    )

    # Linked rules
    rule_rows = db.execute(
        """
        SELECT r.name, r.source
        FROM rules r
        JOIN rule_techniques rt ON rt.rule_id = r.id
        WHERE rt.tech_id = ?
        ORDER BY r.name ASC
        """,
        (tech_id,),
    ).fetchall()
    linked_rules = [{"name": r["name"], "source": r["source"]} for r in rule_rows]

    # Mitigation details with entries
    mitigation_data = []
    for mit_stix in tech_mitigations:
        mit_info = mitigation_stix_to_info[mit_stix]
        mid = mit_info["mitigation_id"]
        entries = db.execute(
            """
            SELECT e.id, e.team, e.comment, e.product_id, p.name AS product_name
            FROM mitigation_entries e
            LEFT JOIN products p ON p.id = e.product_id
            WHERE e.mitigation_id = ? ORDER BY e.id ASC
            """,
            (mid,),
        ).fetchall()
        mitigation_data.append({
            "mitigation_id": mid,
            "name": mit_info["name"],
            "description": mit_info["description"],
            "entries": [_mitigation_entry_payload(e) for e in entries],
            # Isaretli olmak = kaydi olmak. Ayri bir "checked" bayragi yok.
            "global_checked": len(entries) > 0,
        })

    # Technique config
    tc = db.execute(
        "SELECT rule_threshold, group_count, tool_count FROM technique_config WHERE tech_id = ?",
        (tech_id,),
    ).fetchone()

    return jsonify({
        "tech_id": tech_id,
        "name": tech_obj.get("name", ""),
        "description": (tech_obj.get("description") or "")[:500],
        "platforms": tech_obj.get("x_mitre_platforms", []),
        "mitre_url": mitre_url,
        "rule_threshold": tc["rule_threshold"] if tc else DEFAULT_RULE_THRESHOLD,
        # Bilgi amaçlı MITRE sinyalleri — önceliklendirmeye yardımcı olur,
        # skoru veya rengi etkilemez.
        "group_count": (tc["group_count"] if tc else 0) or 0,
        "tool_count": (tc["tool_count"] if tc else 0) or 0,
        "linked_rules": linked_rules,
        "mitigations": mitigation_data,
    })


@app.route("/api/admin/reset", methods=["POST"])
@role_required("admin")
def admin_reset():
    payload = request.get_json(silent=True) or {}
    confirm = (payload.get("confirm") or "").strip()
    reseed = bool(payload.get("reseed"))
    if confirm != "RESET":
        return jsonify({"error": "Confirmation required. Send confirm=RESET."}), 400

    db = get_db()
    db.execute("DELETE FROM mitigation_entries")
    db.execute("DELETE FROM rule_techniques")
    db.execute("DELETE FROM rules")
    _invalidate_ttp_cache()
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


@app.route("/api/technique-config", methods=["GET"])
@login_required
def get_technique_config():
    """Teknik bazlı hedef tespit sayısını ve MITRE kullanım sayaçlarını döner.
    Viewer dahil tüm giriş yapmış kullanıcılar okuyabilir."""
    db = get_db()
    rows = db.execute(
        "SELECT tech_id, rule_threshold, source, group_count, tool_count "
        "FROM technique_config"
    ).fetchall()
    return jsonify({r["tech_id"]: dict(r) for r in rows})


@app.route("/api/technique-config/<tech_id>", methods=["PUT"])
@role_required("admin")
def update_technique_config(tech_id: str):
    """Bir teknik için hedef tespit sayısını admin'in elle ayarlamasına izin verir.

    Önceki "önem seviyesi" (1-5 / 0.3-1.0) kavramı kaldırıldı — opak ve
    yönetilemezdi. Geriye tek bir anlaşılır ayar kaldı: bu teknik için kaç
    tespit yeterli sayılsın.
    """
    payload = request.get_json(silent=True) or {}
    try:
        rule_threshold = int(payload.get("rule_threshold", DEFAULT_RULE_THRESHOLD))
    except (TypeError, ValueError):
        return jsonify({"error": "rule_threshold sayı olmalıdır"}), 400
    # 0 bilinçli bir deger: "bu teknik icin tespit gerekmiyor" (skor otomatik
    # %100 olur, bkz. _compute_gap_analysis). Alt sinir bu yuzden 0.
    rule_threshold = max(0, min(10, rule_threshold))
    db = get_db()
    db.execute(
        "UPDATE technique_config SET rule_threshold=?, source='admin' WHERE tech_id=?",
        (rule_threshold, tech_id.upper()),
    )
    # teknik henüz tabloda yoksa INSERT
    db.execute(
        "INSERT OR IGNORE INTO technique_config "
        "(tech_id, rule_threshold, source) VALUES (?,?,'admin')",
        (tech_id.upper(), rule_threshold),
    )
    write_audit_log(
        db,
        action="update",
        target_type="technique_config",
        target_id=tech_id.upper(),
        detail=f"rule_threshold={rule_threshold}",
    )
    _invalidate_ttp_cache()
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/gap-analysis")
@role_required("viewer")
def gap_analysis_api():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        mitre = get_minified_mitre()
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    db = get_db()
    try:
        environment_id = request.args.get("environment_id", type=int)
    except (TypeError, ValueError):
        environment_id = None
    try:
        result = _compute_gap_analysis(mitre, db, environment_id)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    result["environment_id"] = environment_id
    return jsonify(result)


@app.route("/api/threat-actors")
@role_required("viewer")
def threat_actors_api():
    if not MITRE_PATH.exists():
        return jsonify({"error": "MITRE data not found"}), 500
    try:
        actors = _get_threat_actors()
        return jsonify(actors)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/action-items", methods=["GET", "POST"])
@role_required_methods({"GET": "viewer", "POST": "editor"})
def action_items_api():
    db = get_db()
    if request.method == "GET":
        status_filter = request.args.get("status", "").strip()
        tech_id_filter = request.args.get("tech_id", "").strip()
        query = """
            SELECT ai.id, ai.tech_id, ai.title, ai.description, ai.priority,
                   ai.status, ai.assigned_team_id, ai.due_date,
                   ai.created_by_username, ai.created_at, ai.updated_at,
                   t.name AS assigned_team_name
            FROM action_items ai
            LEFT JOIN teams t ON t.id = ai.assigned_team_id
            WHERE 1=1
        """
        params: list = []
        if status_filter:
            query += " AND ai.status = ?"
            params.append(status_filter)
        if tech_id_filter:
            query += " AND ai.tech_id = ?"
            params.append(tech_id_filter.upper())
        query += " ORDER BY ai.priority DESC, ai.created_at DESC"
        rows = db.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows])

    # POST — create
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or "").strip()
    if not title:
        return jsonify({"error": "Missing fields: title"}), 400

    tech_id = (payload.get("tech_id") or "").strip().upper()
    description = (payload.get("description") or "").strip()
    try:
        priority = max(1, min(4, int(payload.get("priority", 2))))
    except (ValueError, TypeError):
        priority = 2
    status = payload.get("status", "open")
    if status not in ("open", "in_progress", "done", "cancelled"):
        status = "open"
    assigned_team_id = payload.get("assigned_team_id")
    if assigned_team_id is not None:
        try:
            assigned_team_id = int(assigned_team_id)
        except (ValueError, TypeError):
            assigned_team_id = None
    due_date = (payload.get("due_date") or "").strip() or None

    cur = db.execute(
        """INSERT INTO action_items
           (tech_id, title, description, priority, status, assigned_team_id, due_date, created_by_username)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (tech_id, title, description, priority, status, assigned_team_id, due_date,
         g.current_user["username"]),
    )
    write_audit_log(
        db, action="create", target_type="action_item",
        target_id=str(cur.lastrowid),
        detail=f"title={title};tech_id={tech_id};priority={priority}",
        after={
            "tech_id": tech_id, "title": title, "description": description,
            "priority": priority, "status": status,
            "assigned_team_id": assigned_team_id, "due_date": due_date,
        },
    )
    db.commit()

    item = db.execute(
        """SELECT ai.id, ai.tech_id, ai.title, ai.description, ai.priority,
                  ai.status, ai.assigned_team_id, ai.due_date,
                  ai.created_by_username, ai.created_at, ai.updated_at,
                  t.name AS assigned_team_name
           FROM action_items ai
           LEFT JOIN teams t ON t.id = ai.assigned_team_id
           WHERE ai.id = ?""",
        (cur.lastrowid,),
    ).fetchone()
    return jsonify(dict(item)), 201


@app.route("/api/action-items/<int:item_id>", methods=["PUT", "DELETE"])
@role_required("editor")
def action_item_detail(item_id: int):
    db = get_db()
    row = db.execute("SELECT * FROM action_items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404

    if request.method == "DELETE":
        db.execute("DELETE FROM action_items WHERE id = ?", (item_id,))
        write_audit_log(
            db, action="delete", target_type="action_item",
            target_id=str(item_id), before=dict(row),
        )
        db.commit()
        return jsonify({"ok": True})

    # PUT — update
    payload = request.get_json(silent=True) or {}
    title = (payload.get("title") or row["title"]).strip()
    tech_id = (payload["tech_id"] if "tech_id" in payload else row["tech_id"] or "").strip().upper()
    description = payload.get("description") if "description" in payload else (row["description"] or "")
    try:
        priority = max(1, min(4, int(payload.get("priority", row["priority"]))))
    except (ValueError, TypeError):
        priority = row["priority"]
    status = payload.get("status", row["status"])
    if status not in ("open", "in_progress", "done", "cancelled"):
        status = row["status"]
    assigned_team_id = payload.get("assigned_team_id", row["assigned_team_id"])
    if assigned_team_id is not None:
        try:
            assigned_team_id = int(assigned_team_id)
        except (ValueError, TypeError):
            assigned_team_id = None
    due_date = payload.get("due_date", row["due_date"]) or None

    db.execute(
        """UPDATE action_items SET tech_id=?, title=?, description=?, priority=?,
           status=?, assigned_team_id=?, due_date=?,
           updated_at=CURRENT_TIMESTAMP WHERE id=?""",
        (tech_id, title, description, priority, status, assigned_team_id, due_date, item_id),
    )
    write_audit_log(
        db, action="update", target_type="action_item",
        target_id=str(item_id),
        detail=f"status={status};priority={priority}",
        before=dict(row),
        after={
            "id": item_id, "tech_id": tech_id, "title": title,
            "description": description, "priority": priority, "status": status,
            "assigned_team_id": assigned_team_id, "due_date": due_date,
        },
    )
    db.commit()
    return jsonify({"ok": True})


_REPORT_SCORE_STOPS = [
    (0.00, (0xEC, 0xEF, 0xF1)),  # notr gri — hic tespit yok
    (0.30, (0xF8, 0xD3, 0xD3)),  # acik kirmizi
    (0.50, (0xFD, 0xE3, 0xC8)),  # acik turuncu
    (0.70, (0xEE, 0xF2, 0xC1)),  # acik sari-yesil
    (1.00, (0xD1, 0xEE, 0xD8)),  # acik yesil
]


def _score_to_report_color(score: float) -> str:
    """Kapsama skorunu PDF/print icin acik, siyah metinle okunabilir bir
    renge cevirir. Uygulamanin koyu temadaki scoreToColor() ile ayni 5
    durakli gradyani kullanir (0/0.30/0.50/0.70/1.00) — ekranda gordugun
    renk mantigi kagitta da ayni anlama gelsin diye."""
    stops = _REPORT_SCORE_STOPS
    score = max(0.0, min(1.0, score))
    if score <= stops[0][0]:
        r, g, b = stops[0][1]
        return f"#{r:02x}{g:02x}{b:02x}"
    for i in range(len(stops) - 1):
        s0, c0 = stops[i]
        s1, c1 = stops[i + 1]
        if score <= s1:
            t = (score - s0) / (s1 - s0) if s1 != s0 else 0.0
            r = round(c0[0] + (c1[0] - c0[0]) * t)
            g = round(c0[1] + (c1[1] - c0[1]) * t)
            b = round(c0[2] + (c1[2] - c0[2]) * t)
            return f"#{r:02x}{g:02x}{b:02x}"
    r, g, b = stops[-1][1]
    return f"#{r:02x}{g:02x}{b:02x}"


@app.route("/report")
@login_required
def report_page():
    """Yönetici raporu — kapsama haritası (Navigator tarzı), taktik özeti,
    tam teknik listesi, tespitsiz teknikler ve aksiyon planı.

    Coverage haritasindaki ile ayni _compute_gap_analysis() ciktisini
    kullanir; sayfa yalnizca bunu yazdirmaya uygun sekilde yeniden
    duzenler (Navigator tarzi tek parca yogun matris + tam liste eki).
    """
    from datetime import datetime

    gap_data: dict = {"overview": {}, "by_tactic": [], "critical_gaps": [], "techniques": []}
    action_items_data: list = []
    environments: list = []
    matrix_tactics: list = []
    full_list_sections: list = []
    environment_id = request.args.get("environment_id", type=int)
    environment_name = "Tüm ortamlar (birleşik)"

    try:
        if MITRE_PATH.exists():
            mitre = get_minified_mitre()
            db = get_db()
            environments = [
                dict(r) for r in db.execute(
                    "SELECT id, name, active FROM environments ORDER BY active DESC, name"
                ).fetchall()
            ]
            if environment_id:
                env_row = db.execute(
                    "SELECT name FROM environments WHERE id=?", (environment_id,)
                ).fetchone()
                if env_row:
                    environment_name = env_row["name"]
                else:
                    environment_id = None  # gecersiz id — birlesik moda don

            gap_data = _compute_gap_analysis(mitre, db, environment_id)
            rows = db.execute(
                """SELECT ai.id, ai.tech_id, ai.title, ai.priority, ai.status,
                          ai.due_date, t.name AS team_name
                   FROM action_items ai
                   LEFT JOIN teams t ON t.id = ai.assigned_team_id
                   WHERE ai.status IN ('open', 'in_progress')
                   ORDER BY ai.priority DESC, ai.created_at DESC"""
            ).fetchall()
            action_items_data = [dict(r) for r in rows]

            techs = gap_data.get("techniques", [])
            parents = {t["tech_id"]: t for t in techs if not t["is_subtechnique"]}
            children_by_parent: dict[str, list] = {}
            for t in techs:
                if t["is_subtechnique"] and t.get("parent_id"):
                    children_by_parent.setdefault(t["parent_id"], []).append(t)
            for kids in children_by_parent.values():
                kids.sort(key=lambda x: x["tech_id"])

            def _cell(t: dict) -> dict:
                return {**t, "color": _score_to_report_color(t["coverage_score"])}

            # ── Matris: taktik basina sutun, teknik fan-out (coklu taktikli
            # teknik her sutununda ayri ayri gorunur — canli haritayla ayni).
            # Navigator gibi TEK parca yatay serit: yapay sayfa gruplarina
            # bolunmez, tasan uzun sutunlar yazdirma sirasinda dogal olarak
            # bir sonraki sayfaya akar (CSS break-inside kurallariyla). ──
            matrix_tactics = []
            for tactic in _TACTIC_ORDER:
                items = sorted(
                    (p for p in parents.values() if tactic in p["tactics"]),
                    key=lambda x: x["tech_id"],
                )
                if not items:
                    continue
                matrix_tactics.append({
                    "label": _TACTIC_LABEL_MAP.get(tactic, tactic),
                    "count": len(items),
                    "techniques": [
                        {
                            **_cell(p),
                            "children": [_cell(c) for c in children_by_parent.get(p["tech_id"], [])],
                        }
                        for p in items
                    ],
                })

            # ── Tam teknik listesi eki: taktik basina bolum, TEK satir/teknik
            # (fan-out yok — coklu taktikli teknik taktiklerini tek hucrede
            # virgulle listeler, ek gereksiz tekrar etmesin diye). ──
            for tactic in _TACTIC_ORDER:
                items = sorted(
                    (p for p in parents.values() if tactic in p["tactics"]),
                    key=lambda x: x["tech_id"],
                )
                if not items:
                    continue
                full_list_sections.append({
                    "label": _TACTIC_LABEL_MAP.get(tactic, tactic),
                    "techniques": [_cell(p) for p in items],
                })
    except Exception:
        pass

    priority_labels = {1: "Düşük", 2: "Orta", 3: "Yüksek", 4: "Kritik"}
    status_labels = {"open": "Açık", "in_progress": "Devam", "done": "Tamamlandı", "cancelled": "İptal"}

    return render_template(
        "report.html",
        gap=gap_data,
        action_items=action_items_data,
        environments=environments,
        environment_id=environment_id,
        environment_name=environment_name,
        matrix_tactics=matrix_tactics,
        full_list_sections=full_list_sections,
        priority_labels=priority_labels,
        status_labels=status_labels,
        generated_at=datetime.utcnow().strftime("%d.%m.%Y %H:%M UTC"),
        current_user=g.current_user,
    )


if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    host = os.environ.get("SOC_HOST", "0.0.0.0")
    port = int(os.environ.get("SOC_PORT", "8000"))
    app.run(host=host, port=port, debug=True)
