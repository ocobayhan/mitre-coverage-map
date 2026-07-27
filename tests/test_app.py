import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import app as application


def mitre_fixture():
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--one",
                "name": "Test Technique One",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1000"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_is_subtechnique": False,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--two",
                "name": "Test Technique Two",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}
                ],
                "x_mitre_is_subtechnique": False,
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--one",
                "name": "Test Mitigation",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "M1000"}
                ],
            },
            {
                "type": "relationship",
                "id": "relationship--one",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--one",
                "target_ref": "attack-pattern--one",
            },
            {
                "type": "x-mitre-data-component",
                "id": "x-mitre-data-component--one",
                "name": "Process Creation",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "DC1000"}
                ],
                "x_mitre_log_sources": [{"name": "TestLog", "channel": "Process"}],
            },
            {
                "type": "x-mitre-analytic",
                "id": "x-mitre-analytic--one",
                "name": "Test Analytic",
                "x_mitre_log_source_references": [
                    {"x_mitre_data_component_ref": "x-mitre-data-component--one"}
                ],
            },
            {
                "type": "x-mitre-detection-strategy",
                "id": "x-mitre-detection-strategy--one",
                "name": "Test Strategy",
                "x_mitre_analytic_refs": ["x-mitre-analytic--one"],
            },
            {
                "type": "relationship",
                "id": "relationship--detects-one",
                "relationship_type": "detects",
                "source_ref": "x-mitre-detection-strategy--one",
                "target_ref": "attack-pattern--one",
            },
        ],
    }


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.original_db_path = application.DB_PATH
        self.original_mitre_path = application.MITRE_PATH
        self.original_seed_path = application.SEED_RULES_PATH
        application.DB_PATH = self.root / "test.db"
        application.MITRE_PATH = self.root / "mitre.json"
        application.SEED_RULES_PATH = self.root / "missing-seed.json"
        application.MITRE_PATH.write_text(
            json.dumps(mitre_fixture()), encoding="utf-8"
        )
        application.MITRE_CACHE.update({"mtime": None, "data": None})
        application.THREAT_ACTOR_CACHE.update({"mtime": None, "data": None})
        application.TTP_LIST_CACHE.update({"data": None, "dirty": True})
        application.LOGIN_ATTEMPTS.clear()
        application.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        application.init_db()
        self.client = application.app.test_client()

    def tearDown(self):
        application.DB_PATH = self.original_db_path
        application.MITRE_PATH = self.original_mitre_path
        application.SEED_RULES_PATH = self.original_seed_path
        application.MITRE_CACHE.update({"mtime": None, "data": None})
        os.environ.pop("QRADAR_TEST_TOKEN", None)
        self.temp_dir.cleanup()

    def login(self, username="admin", password="Admin123!"):
        return self.client.post(
            "/api/login", json={"username": username, "password": password}
        )

    def test_audit_chain_records_success_and_failure(self):
        failed = self.client.post(
            "/api/login", json={"username": "admin", "password": "wrong"}
        )
        self.assertEqual(failed.status_code, 401)
        self.assertEqual(self.login().status_code, 200)

        response = self.client.get("/api/audit-logs")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["integrity"]["valid"])
        self.assertEqual(payload["integrity"]["checked"], 2)
        self.assertEqual(
            {item["action"] for item in payload["items"]},
            {"login", "login_failed"},
        )
        self.assertTrue(all(item["request_id"] for item in payload["items"]))

    def test_audit_rows_are_append_only(self):
        self.login()
        db = sqlite3.connect(application.DB_PATH)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE audit_logs SET detail='changed' WHERE id=1")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM audit_logs WHERE id=1")
        db.close()

    def test_audit_evidence_package_is_self_verifiable(self):
        self.assertEqual(self.login().status_code, 200)
        response = self.client.post("/api/audit-logs/evidence", json={})
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        package = response.get_json()
        export_hash = package.pop("export_hash")
        canonical = json.dumps(
            package, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        self.assertEqual(
            export_hash, hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        )
        self.assertEqual(package["manifest"]["schema_version"], "audit-evidence-1.0")
        self.assertTrue(package["manifest"]["audit_chain"]["valid"])
        self.assertEqual(package["manifest"]["record_count"], 2)
        self.assertTrue(all("prev_hash" in row for row in package["records"]))
        self.assertEqual(package["records"][-1]["action"], "export")

    def test_qradar_connector_syncs_and_reconciles_without_duplicates(self):
        payload = {
            "mappings": [
                {
                    "ruleUUID": "qradar-1",
                    "ruleName": "Existing QRadar Detection",
                    "isCustom": True,
                    "enabled": True,
                    "techniques": [{"techniqueId": "T1000"}],
                },
                {
                    "ruleUUID": "qradar-2",
                    "ruleName": "New QRadar Detection",
                    "mappingType": "IBM default",
                    "enabled": True,
                    "techniques": ["T1001"],
                },
            ]
        }

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.headers.get("SEC") != "test-token":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            os.environ["QRADAR_TEST_TOKEN"] = "test-token"
            self.assertEqual(self.login().status_code, 200)
            existing = self.client.post(
                "/api/rules",
                json={
                    "name": "Existing QRadar Detection",
                    "tactic": "execution",
                    "tech": "T1000",
                    "source": "QRadar",
                },
            )
            self.assertEqual(existing.status_code, 201)
            connector = self.client.post(
                "/api/connectors",
                json={
                    "name": "Test QRadar",
                    "base_url": f"http://127.0.0.1:{server.server_port}",
                    "secret_env": "QRADAR_TEST_TOKEN",
                    "mappings_path": "/api/mappings",
                },
            )
            self.assertEqual(connector.status_code, 201)
            connector_id = connector.get_json()["id"]
            connection_test = self.client.post(f"/api/connectors/{connector_id}/test")
            self.assertEqual(connection_test.status_code, 200)
            self.assertEqual(connection_test.get_json()["mapping_records"], 2)

            first = self.client.post(f"/api/connectors/{connector_id}/sync")
            self.assertEqual(first.status_code, 200, first.get_json())
            self.assertEqual(first.get_json()["received"], 2)
            self.assertEqual(first.get_json()["linked_existing"], 1)
            self.assertEqual(first.get_json()["rules_created"], 1)
            second = self.client.post(f"/api/connectors/{connector_id}/sync")
            self.assertEqual(second.status_code, 200)
            self.assertEqual(second.get_json()["unchanged"], 2)
            self.assertEqual(second.get_json()["rules_created"], 0)

            payload["mappings"] = payload["mappings"][:1]
            for _ in range(3):
                missing = self.client.post(f"/api/connectors/{connector_id}/sync")
                self.assertEqual(missing.status_code, 200, missing.get_json())
            self.assertEqual(missing.get_json()["stale"], 1)

            inventory = self.client.get("/api/connectors").get_json()[0]
            self.assertTrue(inventory["token_configured"])
            self.assertEqual(inventory["inventory"]["total"], 2)
            self.assertEqual(inventory["inventory"]["stale"], 1)
            self.assertEqual(inventory["linked_rules"], 2)
            db = sqlite3.connect(application.DB_PATH)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM rule_external_refs").fetchone()[0], 2)
            db.close()
            self.assertTrue(self.client.get("/api/audit-logs").get_json()["integrity"]["valid"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scope_registry_records_environment_and_monitoring_survey(self):
        self.assertEqual(self.login().status_code, 200)
        environment = self.client.post(
            "/api/environments",
            json={
                "name": "Lumos Serverlar",
                "code": "LUMOS-SRV",
                "description": "Lumos ortamındaki Linux sunucular",
                "criticality": 5,
                "owner": "Platform Ekibi",
                "asset_count": 42,
            },
        )
        self.assertEqual(environment.status_code, 201)
        environment_id = environment.get_json()["id"]
        connector = self.client.post(
            "/api/connectors",
            json={
                "name": "QRadar DIAS",
                "base_url": "https://qradar-dias.example.local",
                "secret_env": "QRADAR_DIAS_TOKEN",
                "product_name": "QRadar",
            },
        )
        self.assertEqual(connector.status_code, 201)
        connector_id = connector.get_json()["id"]
        registry = self.client.get("/api/scope-registry").get_json()
        product_ids = {item["name"]: item["id"] for item in registry["products"]}
        survey = self.client.put(
            f"/api/environments/{environment_id}/monitoring",
            json={
                "deployments": [
                    {
                        "product_id": product_ids["QRadar"],
                        "connector_id": connector_id,
                        "monitoring_status": "full",
                        "coverage_percent": 100,
                        "monitoring_mode": "log_forwarding",
                        "owner": "SOC",
                        "notes": "Tüm Linux sunucular log gönderiyor",
                    },
                    {
                        "product_id": product_ids["DFE"],
                        "monitoring_status": "none",
                        "coverage_percent": 0,
                        "monitoring_mode": "agent",
                    },
                ]
            },
        )
        self.assertEqual(survey.status_code, 200, survey.get_json())
        registry = self.client.get("/api/scope-registry").get_json()
        self.assertEqual(registry["summary"]["environment_count"], 1)
        self.assertEqual(registry["summary"]["asset_count"], 42)
        saved = registry["environments"][0]
        self.assertEqual(saved["name"], "Lumos Serverlar")
        deployments = {item["product_name"]: item for item in saved["deployments"]}
        self.assertEqual(deployments["QRadar"]["monitoring_status"], "full")
        self.assertEqual(deployments["QRadar"]["connector_id"], connector_id)
        self.assertEqual(deployments["DFE"]["monitoring_status"], "none")
        self.assertTrue(self.client.get("/api/audit-logs").get_json()["integrity"]["valid"])

    def test_flatten_asset_groups_merges_conflicting_groups_by_asset_count(self):
        """Eski 3 seviyeli semadan gecis: bir ortamin altindaki gruplar
        CAKISAN izleme durumlari tasiyorsa, varlik sayisi agirlikli ortalama
        alinir — 'QRadar client'lardan log almiyor' bilgisi kaybolmaz."""
        self.login()
        db = sqlite3.connect(application.DB_PATH)
        db.row_factory = sqlite3.Row
        products = {r["name"]: r["id"] for r in db.execute("SELECT id,name FROM products")}
        # Yeni semayi eski haline dondur (migration'i tetiklemek icin)
        db.executescript(
            """
            DROP TABLE IF EXISTS product_deployments;
            CREATE TABLE asset_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT, environment_id INTEGER NOT NULL,
                name TEXT NOT NULL, platform TEXT DEFAULT 'Other', asset_type TEXT DEFAULT 'Other',
                asset_count INTEGER DEFAULT 0, criticality INTEGER DEFAULT 3,
                owner TEXT DEFAULT '', active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE product_deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT, asset_group_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL, connector_id INTEGER,
                monitoring_status TEXT DEFAULT 'unknown', coverage_percent INTEGER DEFAULT 0,
                monitoring_mode TEXT DEFAULT 'other', owner TEXT DEFAULT '', notes TEXT DEFAULT '',
                reviewed_by TEXT DEFAULT '', reviewed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(asset_group_id, product_id));
            INSERT INTO environments (name, code) VALUES ('Kurumsal', 'KURUMSAL');
            """
        )
        env_id = db.execute("SELECT id FROM environments WHERE code='KURUMSAL'").fetchone()["id"]
        # Serverlar: 300 varlik, QRadar full | Client: 1200 varlik, QRadar none
        db.execute("INSERT INTO asset_groups (environment_id,name,asset_count) VALUES (?,?,?)", (env_id, "Serverlar", 300))
        db.execute("INSERT INTO asset_groups (environment_id,name,asset_count) VALUES (?,?,?)", (env_id, "Client", 1200))
        srv = db.execute("SELECT id FROM asset_groups WHERE name='Serverlar'").fetchone()["id"]
        cli = db.execute("SELECT id FROM asset_groups WHERE name='Client'").fetchone()["id"]
        db.execute("INSERT INTO product_deployments (asset_group_id,product_id,monitoring_status,coverage_percent) VALUES (?,?,?,?)",
                   (srv, products["QRadar"], "full", 100))
        db.execute("INSERT INTO product_deployments (asset_group_id,product_id,monitoring_status,coverage_percent) VALUES (?,?,?,?)",
                   (cli, products["QRadar"], "none", 0))
        db.execute("INSERT INTO product_deployments (asset_group_id,product_id,monitoring_status,coverage_percent) VALUES (?,?,?,?)",
                   (cli, products["DFE"], "full", 100))
        db.commit()
        db.close()

        application.init_db()  # flatten_asset_groups burada calisir

        db = sqlite3.connect(application.DB_PATH)
        db.row_factory = sqlite3.Row
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("asset_groups", tables, "varlik grubu tablosu dusmus olmali")
        rows = {r["name"]: r for r in db.execute(
            """SELECT p.name, pd.monitoring_status, pd.coverage_percent
               FROM product_deployments pd JOIN products p ON p.id=pd.product_id
               WHERE pd.environment_id=?""", (env_id,))}
        # QRadar 1500 varligin yalnizca 300'unu goruyor -> partial %20
        self.assertEqual(rows["QRadar"]["monitoring_status"], "partial")
        self.assertEqual(rows["QRadar"]["coverage_percent"], 20)
        # DFE 1200/1500 -> partial %80
        self.assertEqual(rows["DFE"]["monitoring_status"], "partial")
        self.assertEqual(rows["DFE"]["coverage_percent"], 80)
        self.assertEqual(db.execute("SELECT asset_count FROM environments WHERE id=?", (env_id,)).fetchone()[0], 1500)
        db.close()

    def test_data_quality_detects_invalid_mapping(self):
        self.login()
        valid = self.client.post(
            "/api/rules",
            json={
                "name": "Valid detection",
                "tactic": "execution",
                "tech": "T1000",
                "source": "QRadar",
            },
        )
        invalid = self.client.post(
            "/api/rules",
            json={
                "name": "Invalid detection",
                "tactic": "unknown",
                "tech": "T9999",
                "source": "QRadar",
            },
        )
        self.assertEqual(valid.status_code, 201)
        self.assertEqual(invalid.status_code, 201)

        payload = self.client.get("/api/data-quality").get_json()
        self.assertEqual(payload["summary"]["total_rules"], 2)
        self.assertEqual(payload["summary"]["validly_mapped_rules"], 1)
        self.assertEqual(payload["summary"]["invalid_mappings"], 1)
        self.assertEqual(payload["summary"]["invalid_tactics"], 1)

    def test_gap_metrics_distinguish_detection_and_maturity(self):
        self.login()
        self.client.post(
            "/api/rules",
            json={
                "name": "Partial detection",
                "tactic": "execution",
                "tech": "T1000",
                "source": "QRadar",
            },
        )
        rule_id = self.client.get("/api/rules").get_json()[0]["id"]
        self.client.patch(
            f"/api/rules/{rule_id}/coverage", json={"coverage_level": "low"}
        )

        overview = self.client.get("/api/gap-analysis").get_json()["overview"]
        self.assertEqual(overview["total_techniques"], 2)
        self.assertEqual(overview["detected_techniques"], 1)
        self.assertEqual(overview["coverage_pct"], 50.0)
        self.assertEqual(overview["mature_techniques"], 0)
        self.assertLess(overview["average_score_pct"], 20)

    def test_coverage_buckets_are_disjoint_and_sum_to_total(self):
        """Tespit / kapsamsız birbirini dışlar ve toplamları ana teknik
        sayısını verir. Mitigation ayrı bir kova DEĞİL — haritada kalkan
        işareti olarak gösterilir, skora ve renge girmez (Faz 4 kararı)."""
        self.login()
        self.client.post("/api/rules", json={
            "name": "Sadece T1000", "tactic": "execution", "tech": "T1000", "source": "QRadar"})
        # M1000 -> T1000'i mitige eder; T1000'in zaten tespiti var.
        self.client.post("/api/mitigation-entries", json={
            "mitigation_id": "M1000", "team": "SOC", "comment": "uygulandi"})

        ov = self.client.get("/api/gap-analysis").get_json()["overview"]
        total = ov["total_techniques"]
        self.assertEqual(
            ov["detected_techniques"] + ov["uncovered_techniques"], total,
            "iki kova toplamı ana teknik sayısını vermeli",
        )
        self.assertEqual(ov["detected_techniques"], 1)
        self.assertEqual(ov["uncovered_techniques"], 1)
        # Mitigation bilgi olarak raporlanır ama kovaları etkilemez.
        self.assertEqual(ov["mitigated_techniques"], 1)

    def test_mitigation_entry_records_optional_product(self):
        """Mitigation'ı hangi ürünle sağladığımız kaydedilir.

        Ürün isteğe bağlıdır (süreç/eğitim/politika ile sağlananlar var) ama
        verildiğinde katalogda bulunmak zorundadır — serbest metin kabul
        edilmez, yoksa `rules.source`'taki isim eşleşmesi sorunu tekrarlanır.
        """
        self.login()
        product_id = self.client.post(
            "/api/products", json={"name": "Wazuh", "color": "#123456"}
        ).get_json()["id"]

        with_product = self.client.post("/api/mitigation-entries", json={
            "mitigation_id": "M1000", "team": "SOC",
            "comment": "EDR politikasi", "product_id": product_id})
        self.assertEqual(with_product.status_code, 201)
        self.assertEqual(with_product.get_json()["product_name"], "Wazuh")

        # Urunsuz kayit da gecerli
        without = self.client.post("/api/mitigation-entries", json={
            "mitigation_id": "M1000", "team": "BT", "comment": "Elle surec"})
        self.assertEqual(without.status_code, 201)
        self.assertIsNone(without.get_json()["product_id"])

        # Katalogda olmayan urun reddedilir
        bogus = self.client.post("/api/mitigation-entries", json={
            "mitigation_id": "M1000", "team": "SOC",
            "comment": "x", "product_id": 99999})
        self.assertEqual(bogus.status_code, 400)

        listed = self.client.get("/api/mitigation-entries").get_json()
        self.assertEqual(len(listed), 2)
        self.assertEqual(
            {e["product_name"] for e in listed}, {"Wazuh", None},
            "urun adi listede birlikte donmeli",
        )

    def test_legacy_mitigation_tables_are_dropped(self):
        """mitigation_notes / mitigation_global ölü ağırlıktı ve düşürüldü.

        Bir mitigation'ın "işaretli" olması artık yalnızca mitigation_entries
        kaydının varlığından türer — iki paralel gerçek kaynağı yok.
        """
        with application.app.app_context():
            db = application.get_db()
            tables = {
                r["name"] for r in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        self.assertNotIn("mitigation_notes", tables)
        self.assertNotIn("mitigation_global", tables)
        self.login()
        self.assertEqual(self.client.get("/api/mitigation-notes").status_code, 404)

    def test_score_is_detection_only_and_uses_per_technique_threshold(self):
        """Skor = min(etkin tespit / teknik hedefi, 1). Mitigation ve ürün
        çeşitliliği skora girmez; hedef teknik bazında admin tarafından
        ayarlanabilir."""
        self.login()
        # Varsayilan hedef 2 -> tek tespit %50 skor
        self.client.post("/api/rules", json={
            "name": "Tek tespit", "tactic": "execution", "tech": "T1000", "source": "QRadar"})
        gaps = {g["tech_id"]: g for g in self.client.get("/api/gap-analysis").get_json()["critical_gaps"]}
        self.assertNotIn("T1000", gaps, "tespiti olan teknik tespitsiz listesine girmemeli")

        ov = self.client.get("/api/gap-analysis").get_json()["overview"]
        # 2 teknik var: T1000 skor 0.5, T1001 skor 0 -> ortalama %25
        self.assertEqual(ov["average_score_pct"], 25.0)

        # Mitigation eklemek skoru DEGISTIRMEMELI
        self.client.post("/api/mitigation-entries", json={
            "mitigation_id": "M1000", "team": "SOC", "comment": "uygulandi"})
        self.assertEqual(
            self.client.get("/api/gap-analysis").get_json()["overview"]["average_score_pct"], 25.0,
            "mitigation skora girmemeli",
        )

        # Hedefi 1'e cekince tek tespit yeterli olur -> T1000 skoru %100
        self.assertEqual(self.client.put(
            "/api/technique-config/T1000", json={"rule_threshold": 1}).status_code, 200)
        self.assertEqual(
            self.client.get("/api/gap-analysis").get_json()["overview"]["average_score_pct"], 50.0)

    def test_gap_analysis_is_scoped_to_environment_monitoring(self):
        """Kurumsal gerçek: her ürün her yerde yok.

        QRadar tüm server'lardan log alıyor ama client'lardan almıyor; Defender
        client'ta var. Dolayısıyla yalnızca QRadar'ın kapsadığı bir teknik,
        client varlık grubunda kapsanmamış sayılmalı.
        """
        self.login()
        # T1000 -> yalnizca QRadar, T1001 -> yalnizca DFE
        self.client.post("/api/rules", json={
            "name": "QRadar CRE", "tactic": "execution", "tech": "T1000", "source": "QRadar"})
        self.client.post("/api/rules", json={
            "name": "Defender EDR", "tactic": "persistence", "tech": "T1001", "source": "DFE"})

        clients = self.client.post("/api/environments", json={
            "name": "Client Makineler", "code": "CLIENT"}).get_json()["id"]
        servers = self.client.post("/api/environments", json={
            "name": "Kurumsal Serverlar", "code": "KURUMSAL-SRV"}).get_json()["id"]

        products = {p["name"]: p["id"] for p in self.client.get("/api/products").get_json()}
        # Client: Defender var, QRadar log almiyor
        self.assertEqual(self.client.put(f"/api/environments/{clients}/monitoring", json={"deployments": [
            {"product_id": products["DFE"], "monitoring_status": "full"},
            {"product_id": products["QRadar"], "monitoring_status": "none"},
        ]}).status_code, 200)
        # Server: ikisi de var
        self.assertEqual(self.client.put(f"/api/environments/{servers}/monitoring", json={"deployments": [
            {"product_id": products["DFE"], "monitoring_status": "full"},
            {"product_id": products["QRadar"], "monitoring_status": "full"},
        ]}).status_code, 200)

        # Filtresiz: iki teknik de kapsanir
        overview = self.client.get("/api/gap-analysis").get_json()["overview"]
        self.assertEqual(overview["detected_techniques"], 2)

        # Client grubunda QRadar yok -> yalnizca Defender'in teknigi kapsanir
        client_overview = self.client.get(
            f"/api/gap-analysis?environment_id={clients}").get_json()["overview"]
        self.assertEqual(client_overview["detected_techniques"], 1)

        # Server grubunda ikisi de izleniyor -> iki teknik de kapsanir
        server_overview = self.client.get(
            f"/api/gap-analysis?environment_id={servers}").get_json()["overview"]
        self.assertEqual(server_overview["detected_techniques"], 2)

    def test_partial_monitoring_weights_coverage_score(self):
        """Kismi izleme (partial) skoru coverage_percent oraninda dusurur."""
        self.login()
        self.client.post("/api/rules", json={
            "name": "QRadar CRE", "tactic": "execution", "tech": "T1000", "source": "QRadar"})
        group = self.client.post("/api/environments", json={
            "name": "Kurumsal Serverlar", "code": "KURUMSAL-SRV"}).get_json()["id"]
        products = {p["name"]: p["id"] for p in self.client.get("/api/products").get_json()}

        def score_for(status, percent=0):
            self.client.put(f"/api/environments/{group}/monitoring", json={"deployments": [
                {"product_id": products["QRadar"], "monitoring_status": status,
                 "coverage_percent": percent},
            ]})
            data = self.client.get(f"/api/gap-analysis?environment_id={group}").get_json()
            return data["overview"]["average_score_pct"]

        full = score_for("full")
        partial = score_for("partial", 50)
        none = score_for("none")
        self.assertGreater(full, partial, "tam izleme kismi izlemeden yuksek olmali")
        self.assertGreater(partial, none, "kismi izleme izlemeyenden yuksek olmali")
        self.assertEqual(none, 0.0)

    def test_rule_source_must_exist_in_product_catalog(self):
        """Katalogda olmayan kaynak reddedilir — aksi halde tespit hicbir
        ortamda kapsama saglamaz ve sessizce kaybolur."""
        self.login()
        bad = self.client.post("/api/rules", json={
            "name": "Hayalet", "tactic": "execution", "tech": "T1000", "source": "YokBoyleUrun"})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("urun katalogunda yok", bad.get_json()["error"])

        ok = self.client.post("/api/rules", json={
            "name": "Gercek", "tactic": "execution", "tech": "T1000", "source": "QRadar"})
        self.assertEqual(ok.status_code, 201)

    def test_product_category_defaults_and_validates(self):
        self.login()
        listed = self.client.get("/api/products").get_json()
        self.assertTrue(all(p["category"] == "tespit_kaynagi" for p in listed),
                        "migration mevcut urunlerin davranisini degistirmemeli")

        bad = self.client.post("/api/products", json={
            "name": "Yeni", "color": "#fff", "category": "gecersiz"})
        self.assertEqual(bad.status_code, 400)

        fw = self.client.post("/api/products", json={
            "name": "Fortigate", "color": "#c00", "category": "onleyici_kontrol"})
        self.assertEqual(fw.status_code, 201)
        self.assertEqual(fw.get_json()["category"], "onleyici_kontrol")

    def test_viewer_cannot_mutate_rules_or_read_audit(self):
        self.assertEqual(self.login("viewer", "Viewer123!").status_code, 200)
        create = self.client.post(
            "/api/rules", json={"name": "Blocked", "source": "QRadar"}
        )
        self.assertEqual(create.status_code, 403)
        self.assertEqual(self.client.get("/api/audit-logs").status_code, 403)

    def test_per_method_role_map_blocks_writes_but_allows_reads(self):
        # Bu route'lar tek bir view function icinde GET (viewer) ve yazma
        # (editor/admin) metodlarini birlikte barindiriyor. Once inline
        # `if ROLE_LEVELS[...] < ...` kontrolleriyle yapiliyordu, artik
        # role_required_methods() decorator'i ile merkezi. Bu test hem GET'in
        # viewer'a acik kaldigini hem yazmanin hala engellendigini dogruluyor —
        # decorator'a method eklenip role_map guncellenmezse (fail-closed
        # 403) bu test GET tarafinda kirilir.
        self.login("viewer", "Viewer123!")

        read_only_ok = [
            ("/api/rules", "GET"),
            ("/api/products", "GET"),
            ("/api/teams", "GET"),
            ("/api/mitigation-entries", "GET"),
            ("/api/action-items", "GET"),
        ]
        for path, method in read_only_ok:
            response = self.client.open(path, method=method)
            self.assertEqual(response.status_code, 200, f"{method} {path} should be readable by viewer")

        writes_blocked = [
            ("/api/rules", "POST", {"name": "x", "source": "QRadar"}, "editor"),
            ("/api/products", "POST", {"name": "x", "color": "#000"}, "admin"),
            ("/api/teams", "POST", {"name": "x"}, "admin"),
            ("/api/mitigation-entries", "POST", {"mitigation_id": "M1000", "team": "x", "comment": "x"}, "editor"),
            ("/api/action-items", "POST", {"title": "x"}, "editor"),
        ]
        for path, method, payload, required_role in writes_blocked:
            response = self.client.open(path, method=method, json=payload)
            self.assertEqual(
                response.status_code, 403,
                f"{method} {path} should require {required_role}, viewer got {response.status_code}",
            )

    def test_role_required_methods_rejects_unknown_role_at_decoration_time(self):
        with self.assertRaises(ValueError):
            application.role_required_methods({"GET": "not-a-real-role"})

    def test_last_active_admin_is_protected(self):
        self.login()
        response = self.client.put(
            "/api/users/1", json={"role": "viewer", "is_active": True}
        )
        self.assertEqual(response.status_code, 409)

    def test_login_rate_limit_is_audited(self):
        for _ in range(application.LOGIN_MAX_FAILURES):
            response = self.client.post(
                "/api/login", json={"username": "admin", "password": "wrong"}
            )
            self.assertEqual(response.status_code, 401)
        blocked = self.client.post(
            "/api/login", json={"username": "admin", "password": "wrong"}
        )
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["Retry-After"], str(application.LOGIN_WINDOW_SECONDS))

    def test_self_service_password_change_requires_correct_current_password(self):
        self.login("viewer", "Viewer123!")

        wrong_current = self.client.put(
            "/api/me/password",
            json={"current_password": "wrong-password", "new_password": "NewPassw0rd!"},
        )
        self.assertEqual(wrong_current.status_code, 400)

        too_short = self.client.put(
            "/api/me/password",
            json={"current_password": "Viewer123!", "new_password": "short"},
        )
        self.assertEqual(too_short.status_code, 400)

        same_password = self.client.put(
            "/api/me/password",
            json={"current_password": "Viewer123!", "new_password": "Viewer123!"},
        )
        self.assertEqual(same_password.status_code, 400)

        ok = self.client.put(
            "/api/me/password",
            json={"current_password": "Viewer123!", "new_password": "NewPassw0rd!"},
        )
        self.assertEqual(ok.status_code, 200)

        self.client.post("/api/logout")
        old_login = self.login("viewer", "Viewer123!")
        self.assertEqual(old_login.status_code, 401)
        new_login = self.login("viewer", "NewPassw0rd!")
        self.assertEqual(new_login.status_code, 200)
        self.client.post("/api/logout")

        self.login()  # admin
        audit = self.client.get("/api/audit-logs").get_json()
        change_events = [item for item in audit["items"] if item["action"] == "change_password"]
        self.assertEqual(len(change_events), 1)
        self.assertNotIn("NewPassw0rd", json.dumps(change_events[0]))

    def test_self_service_password_change_requires_login(self):
        response = self.client.put(
            "/api/me/password",
            json={"current_password": "Viewer123!", "new_password": "NewPassw0rd!"},
        )
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
