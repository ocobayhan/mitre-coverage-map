import hashlib
import io
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

    # ── Kapsama içe aktarımı ────────────────────────────────────────────
    def _import_payload(self, **overrides):
        payload = {
            "schema": application.IMPORT_SCHEMA_NAME,
            "version": application.IMPORT_SCHEMA_VERSION,
            "products": [{"name": "Defender for Identity", "category": "tespit_kaynagi"}],
            "rules": [
                {"name": "Suspicious LDAP enumeration",
                 "product": "Defender for Identity",
                 "techniques": ["T1000", "T1001"],
                 "coverage_level": "partial", "kind": "builtin"},
            ],
            "product_coverage": [
                {"product": "Defender for Identity", "techniques": ["T1001"],
                 "coverage_level": "partial", "note": "built-in alert seti"},
            ],
        }
        payload.update(overrides)
        return payload

    def test_import_preview_does_not_write_anything(self):
        """Önizleme bir plan döner ama DB'ye dokunmaz — hatalı bir dosyayı
        geri almak zorunda kalmamanın tek yolu bu."""
        self.login()
        before = len(self.client.get("/api/rules").get_json())

        plan = self.client.post(
            "/api/import/coverage/preview", json=self._import_payload()
        ).get_json()

        self.assertTrue(plan["ok"], plan["errors"])
        self.assertEqual(plan["summary"]["products_new"], 1)
        self.assertEqual(plan["summary"]["rules_new"], 2)  # isimli + built-in seti
        self.assertEqual(plan["summary"]["techniques_added"], 3)
        self.assertEqual(len(self.client.get("/api/rules").get_json()), before)
        self.assertIsNone(
            self.client.get("/api/products").get_json() and next(
                (p for p in self.client.get("/api/products").get_json()
                 if p["name"] == "Defender for Identity"), None),
            "önizleme ürün oluşturmamalı",
        )

    def test_import_apply_creates_product_rules_and_builtin_set(self):
        self.login()
        result = self.client.post(
            "/api/import/coverage/apply", json=self._import_payload()
        )
        self.assertEqual(result.status_code, 200, result.get_json())
        applied = result.get_json()["applied"]
        self.assertEqual(applied["products_created"], 1)
        self.assertEqual(applied["rules_created"], 2)

        rules = {r["name"]: r for r in self.client.get("/api/rules").get_json()}
        self.assertEqual(
            sorted(rules["Suspicious LDAP enumeration"]["techniques"]),
            ["T1000", "T1001"],
            "bir kural birden fazla tekniğe eşlenebilmeli",
        )
        # Ürün seviyesi kapsama tek bir sanal kural olarak girer
        builtin_name = f"Defender for Identity — {application._BUILTIN_RULE_SUFFIX}"
        self.assertIn(builtin_name, rules)
        self.assertEqual(rules[builtin_name]["techniques"], ["T1001"])
        self.assertEqual(rules[builtin_name]["coverage_level"], "partial")

    def test_product_claim_scores_but_does_not_fill_detection_bucket(self):
        """Ürün seviyesi toplu iddia skora katkı yapar ama "Tespit" kovasına
        girmez.

        Aksi halde tek satırlık bir `product_coverage` kaydı 120 tekniği birden
        kapsanmış gösterir ve manşet metrik, yazılmış tek bir kural olmadan
        şişerdi. Kova sert kanıt ister: adı olan bir tespit.
        """
        self.login()
        self.client.post("/api/import/coverage/apply", json=self._import_payload(
            products=[], rules=[],
            product_coverage=[{"product": "QRadar", "techniques": ["T1000"],
                               "coverage_level": "partial"}],
        ))

        ov = self.client.get("/api/gap-analysis").get_json()
        overview = ov["overview"]
        self.assertEqual(overview["detected_techniques"], 0,
                         "ürün iddiası tek başına tekniği tespitli saymamalı")
        self.assertEqual(overview["uncovered_techniques"], 2)

        # Tespitsiz teknikler listesinde, ama skoru var
        gaps = {g["tech_id"]: g for g in ov["critical_gaps"]}
        self.assertIn("T1000", gaps, "ürün iddiası tekniği boşluk listesinden çıkarmamalı")
        self.assertEqual(gaps["T1000"]["rule_count"], 1)
        self.assertEqual(gaps["T1000"]["named_rule_count"], 0)
        # ...skoru var: partial (0.60) / hedef 2 = %30 -> kart amber, gri degil
        self.assertAlmostEqual(gaps["T1000"]["coverage_score"], 0.3, places=2)

        # Adi olan bir tespit eklenince kova dolar
        self.client.post("/api/import/coverage/apply", json=self._import_payload(
            products=[], product_coverage=[],
            rules=[{"name": "Gercek kural", "product": "QRadar",
                    "techniques": ["T1000"]}],
        ))
        after = self.client.get("/api/gap-analysis").get_json()
        self.assertNotIn("T1000", {g["tech_id"] for g in after["critical_gaps"]})
        self.assertEqual(after["overview"]["detected_techniques"], 1)

    def test_import_merges_techniques_without_dropping_manual_ones(self):
        """İkinci yükleme mevcut kuralın tekniklerini SİLMEZ, eksikleri ekler.

        Kullanıcının kararı: uygulamada elle yapılan eşlemeler asla
        kaybolmamalı (bkz. docs/mitre_mapping_prompt.md).
        """
        self.login()
        self.client.post("/api/import/coverage/apply", json=self._import_payload(
            product_coverage=[],
            rules=[{"name": "A kuralı", "product": "QRadar", "techniques": ["T1000"]}],
        ))
        rule_id = self.client.get("/api/rules").get_json()[0]["id"]
        # Elle bir teknik daha ekle
        self.client.post(f"/api/rules/{rule_id}/techniques", json={"tech_id": "T1001"})

        # Aynı kural yeniden yüklenir, dosyada T1001 yok
        plan = self.client.post("/api/import/coverage/preview", json=self._import_payload(
            products=[], product_coverage=[],
            rules=[{"name": "A kuralı", "product": "QRadar", "techniques": ["T1000"]}],
        )).get_json()
        self.assertEqual(plan["summary"]["rules_unchanged"], 1)
        self.assertEqual(plan["summary"]["techniques_added"], 0)

        self.client.post("/api/import/coverage/apply", json=self._import_payload(
            products=[], product_coverage=[],
            rules=[{"name": "A kuralı", "product": "QRadar", "techniques": ["T1000"]}],
        ))
        techs = self.client.get("/api/rules").get_json()[0]["techniques"]
        self.assertEqual(sorted(techs), ["T1000", "T1001"], "elle eklenen teknik silinmemeli")

    def test_import_treats_unknown_technique_as_warning_not_blocking_error(self):
        """Tanınmayan teknik ID'si TÜM dosyayı reddettirmez.

        Bir LLM'in ürettiği ID gerçekte var olmayabilir (mitre.json'da
        bulunmayan bir numara). Geçersiz ID'ler o satırdan atlanır; kural
        varsa kalan geçerli tekniklerle, hiç kalmadıysa tekniksiz eklenir —
        elle "tekniksiz kural" eklemekle birebir aynı yol. Kullanıcı bunu
        Veri Kalitesi ekranından tamamlar. Yapısal hatalar (katalogda
        olmayan ürün gibi) hâlâ tüm dosyayı reddettirir.
        """
        self.login()
        payload = self._import_payload(products=[], product_coverage=[], rules=[
            {"name": "Iyi kural", "product": "QRadar", "techniques": ["T1000"]},
            {"name": "Kismen taninan", "product": "QRadar", "techniques": ["T1000", "T9999"]},
            {"name": "Hic taninmayan", "product": "QRadar", "techniques": ["T9999"]},
        ])
        preview = self.client.post("/api/import/coverage/preview", json=payload).get_json()
        self.assertTrue(preview["ok"], preview["errors"])
        self.assertEqual(preview["errors"], [])
        self.assertEqual(len(preview["warnings"]), 2)
        self.assertEqual(preview["summary"]["rules_without_technique"], 1)

        response = self.client.post("/api/import/coverage/apply", json=payload)
        self.assertEqual(response.status_code, 200, response.get_json())

        rules = {r["name"]: r for r in self.client.get("/api/rules").get_json()}
        self.assertEqual(rules["Iyi kural"]["techniques"], ["T1000"])
        self.assertEqual(rules["Kismen taninan"]["techniques"], ["T1000"])
        self.assertEqual(rules["Hic taninmayan"]["techniques"], [],
                         "tekniksiz de olsa kural eklenmeli, sonradan elle eslenir")

    def test_import_merges_duplicate_name_product_pairs_instead_of_blocking(self):
        """Dosyada aynı (isim, ürün) çifti birden fazla kez geçmesi HATA
        değil, uyarıdır — teknikleri birleştirilir.

        Gerçek olay: kullanıcı "Defender for Endpoint EDR – <Taktik>" adlı
        13 satırın hepsi ikişer kez tekrar ettiği bir dosya yükledi (uzun
        listede LLM'in bir bloğu tekrarlaması). Eskiden bu TÜM dosyayı
        (300+ geçerli satır dahil) reddediyordu. Artık tekrar eden satırlar
        birleşiyor, dosyanın geri kalanı etkilenmiyor.
        """
        self.login()
        payload = self._import_payload(products=[], product_coverage=[], rules=[
            {"name": "Defender EDR – Collection", "product": "QRadar",
             "techniques": ["T1000"]},
            {"name": "Defender EDR – Collection", "product": "QRadar",
             "techniques": ["T1001"]},  # ayni isim+urun, farkli teknik
            {"name": "Iyi kural", "product": "QRadar", "techniques": ["T1000"]},
        ])
        preview = self.client.post("/api/import/coverage/preview", json=payload).get_json()
        self.assertTrue(preview["ok"], preview["errors"])
        self.assertEqual(preview["errors"], [])
        self.assertEqual(len(preview["warnings"]), 1)
        self.assertIn("tekrar ediyor", preview["warnings"][0])
        self.assertEqual(preview["summary"]["rules_new"], 2)

        response = self.client.post("/api/import/coverage/apply", json=payload)
        self.assertEqual(response.status_code, 200, response.get_json())
        rules = {r["name"]: r for r in self.client.get("/api/rules").get_json()}
        self.assertEqual(
            sorted(rules["Defender EDR – Collection"]["techniques"]),
            ["T1000", "T1001"],
            "tekrar eden satirlarin teknikleri birlesmeli",
        )

    def test_import_still_rejects_unknown_product_atomically(self):
        """Yapısal hatalar (katalogda olmayan ürün gibi) hâlâ tüm dosyayı
        reddettirir — kısmi uygulama yoktur, sadece teknik tanıma gevşetildi."""
        self.login()
        bad = self._import_payload(products=[], product_coverage=[], rules=[
            {"name": "Iyi kural", "product": "QRadar", "techniques": ["T1000"]},
            {"name": "Uydurma urun", "product": "Yok Boyle Urun", "techniques": ["T1000"]},
        ])
        preview = self.client.post("/api/import/coverage/preview", json=bad).get_json()
        self.assertFalse(preview["ok"])
        self.assertEqual(len(preview["errors"]), 1)

        response = self.client.post("/api/import/coverage/apply", json=bad)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            self.client.get("/api/rules").get_json(), [],
            "yapisal hatali dosyanin gecerli satirlari da yazilmamali",
        )

    def test_import_rejects_wrong_schema_header(self):
        self.login()
        preview = self.client.post(
            "/api/import/coverage/preview",
            json={"version": 1, "rules": []},
        ).get_json()
        self.assertFalse(preview["ok"])
        self.assertTrue(any("schema" in e for e in preview["errors"]))

    def test_rule_rename_and_move_to_different_product(self):
        """Tespit oluşturulduktan sonra adı ve ürünü (kaynağı) değiştirilebilir.

        Kullanıcı: "yönetim alanında her şeyi ekle, elimiz kolumuz
        bağlanmasın" — ilk girişte yanlış yazılan bir isim ya da yanlış
        ürüne bağlanan bir kural elle düzeltilebilmeli.
        """
        self.login()
        created = self.client.post("/api/rules", json={
            "name": "Yanlis isim", "source": "QRadar"}).get_json()
        rule_id = created["id"]

        # Sadece adi degistir
        r1 = self.client.put(f"/api/rules/{rule_id}", json={"name": "Dogru isim"})
        self.assertEqual(r1.status_code, 200)
        rules = {r["id"]: r for r in self.client.get("/api/rules").get_json()}
        self.assertEqual(rules[rule_id]["name"], "Dogru isim")
        self.assertEqual(rules[rule_id]["source"], "QRadar")

        # Urunu degistir (tasima)
        self.client.post("/api/products", json={"name": "DFE", "color": "#111111"})
        r2 = self.client.put(f"/api/rules/{rule_id}", json={"source": "DFE"})
        self.assertEqual(r2.status_code, 200)
        rules = {r["id"]: r for r in self.client.get("/api/rules").get_json()}
        self.assertEqual(rules[rule_id]["source"], "DFE")
        self.assertEqual(rules[rule_id]["name"], "Dogru isim", "urun degisince isim degismemeli")

        # Katalogda olmayan urune tasinamaz
        r3 = self.client.put(f"/api/rules/{rule_id}", json={"source": "Yok Boyle Urun"})
        self.assertEqual(r3.status_code, 400)

        # Ayni (isim, urun) baska bir kuralda varsa 409
        self.client.post("/api/rules", json={"name": "Cakisan isim", "source": "DFE"})
        r4 = self.client.put(f"/api/rules/{rule_id}", json={"name": "Cakisan isim"})
        self.assertEqual(r4.status_code, 409)

        # Bos isim reddedilir
        r5 = self.client.put(f"/api/rules/{rule_id}", json={"name": "  "})
        self.assertEqual(r5.status_code, 400)

        # Viewer degistiremez
        self.login("viewer", "Viewer123!")
        r6 = self.client.put(f"/api/rules/{rule_id}", json={"name": "Viewer deneme"})
        self.assertEqual(r6.status_code, 403)

    # ── /report (PDF Export'un yerine gecen zengin rapor) ────────────────
    def test_report_page_renders_matrix_and_full_technique_list(self):
        """PDF Export artik DOM kazima degil, bu sayfaya yonlendiriyor.

        Rapor: yonetici ozeti, Navigator tarzi kapsama haritasi (alt
        teknikler dahil), taktik tablosu, tespitsiz teknikler, tam teknik
        listesi eki ve aksiyon plani icermeli. Eski "onem" dili kalmamali
        (Faz 4b'de kaldirildi).
        """
        self.login()
        self.client.post("/api/rules", json={
            "name": "Rapor testi", "tactic": "execution", "tech": "T1000",
            "source": "QRadar"})

        response = self.client.get("/report")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        self.assertIn("Kapsama Haritası", html)
        self.assertIn("Tam Teknik Listesi", html)
        self.assertIn("Tespitsiz Teknikler", html)
        self.assertIn("T1000", html)
        # Eski, kaldirilmis "onem seviyesi" kavrami rapora sizmamali
        self.assertNotIn("Önem", html)
        self.assertNotIn("Kritik Boşluklar (Önem", html)

    def test_report_page_scopes_to_environment_query_param(self):
        """?environment_id= verilirse rapor o ortamin adini ve kapsamini
        gosterir; gecersiz id sessizce birlesik moda doner (crash yerine)."""
        self.login()
        env = self.client.post("/api/environments", json={
            "name": "Test Ortami", "code": "TST", "asset_count": 10}).get_json()

        combined = self.client.get("/report").get_data(as_text=True)
        self.assertIn("Tüm ortamlar (birleşik)", combined)

        scoped = self.client.get(f"/report?environment_id={env['id']}").get_data(as_text=True)
        self.assertIn("Test Ortami", scoped)

        invalid = self.client.get("/report?environment_id=999999")
        self.assertEqual(invalid.status_code, 200, "gecersiz id 500 degil, birlesik moda donmeli")

    def test_gap_analysis_techniques_expose_sources_for_report(self):
        """_compute_gap_analysis artik her teknik icin urun isimlerini de
        (yalnizca sayisini degil) dondurur — raporun 'Ürünler' sutunu icin."""
        self.login()
        self.client.post("/api/rules", json={
            "name": "Kaynak testi", "tactic": "execution", "tech": "T1000",
            "source": "QRadar"})
        gap = self.client.get("/api/gap-analysis").get_json()
        techs = {t["tech_id"]: t for t in gap.get("techniques", [])}
        self.assertIn("T1000", techs)
        self.assertEqual(techs["T1000"]["sources"], ["QRadar"])

    def test_import_new_product_requires_admin(self):
        """Ürün oluşturma admin işi; editor kural yükleyebilir ama katalogu
        genişletemez (POST /api/products ile aynı kural)."""
        self.login("editor", "Editor123!")
        response = self.client.post(
            "/api/import/coverage/apply", json=self._import_payload()
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("admin", response.get_json()["error"])

    def test_csv_bulk_import_merges_duplicate_rows_instead_of_crashing(self):
        """Aynı (name, source) ikinci kez gelince eskiden UNIQUE index'e
        çarpıp 500 dönüyordu; artık tek kurala birleşiyor."""
        self.login()
        csv_body = (
            "name,tactic,tech,source\n"
            "Coklu teknik kurali,execution,T1000,QRadar\n"
            "Coklu teknik kurali,persistence,T1001,QRadar\n"
        )
        response = self.client.post(
            "/api/rules/bulk",
            data={"file": (io.BytesIO(csv_body.encode("utf-8")), "rules.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["inserted"], 1)
        rules = self.client.get("/api/rules").get_json()
        self.assertEqual(len(rules), 1)
        self.assertEqual(sorted(rules[0]["techniques"]), ["T1000", "T1001"])

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

    def test_rule_threshold_zero_means_score_is_always_full(self):
        """Admin bir teknik için hedefi 0 yapabilir: "bu teknik için tespit
        gerekmiyor" (kapsam dışı / başka bir kontrolle karşılanıyor). Skor
        hiç tespit olmadan da %100 olmalı — bölen sıfır olduğu için ayrı bir
        dal gerekir, aksi halde ZeroDivisionError.
        """
        self.login()
        response = self.client.put(
            "/api/technique-config/T1000", json={"rule_threshold": 0}
        )
        self.assertEqual(response.status_code, 200)

        gaps = self.client.get("/api/gap-analysis").get_json()
        tech = next(t for t in gaps["critical_gaps"] if t["tech_id"] == "T1000")
        self.assertEqual(tech["rule_threshold"], 0)
        self.assertEqual(tech["coverage_score"], 1.0)
        # 0 tespitle de "Tespit" kovasina GIRMEZ — skor ile kova farkli
        # sorulara cevap veriyor (bkz. Faz 5 origin ayrimi). Hedefi
        # dusurmek "gorebiliyoruz" demek degil, "aramiyoruz" demek.
        self.assertEqual(gaps["overview"]["detected_techniques"], 0)

        # Negatif deger 0'a, 10 ustu 10'a kirpilir
        self.client.put("/api/technique-config/T1001", json={"rule_threshold": -5})
        cfg = self.client.get("/api/technique-config").get_json()
        self.assertEqual(cfg["T1001"]["rule_threshold"], 0)

    def test_technique_config_picks_up_new_techniques_after_mitre_update(self):
        """MITRE veri seti güncellendiğinde (yeni teknik eklendiğinde)
        technique_config bunu görmeli — eskiden 'source=auto satırı varsa hiç
        çalışma' koruması vardı ve bu, MITRE bir sürüm atlayınca (v19'daki
        Defense Impairment/Stealth ayrımı, T1685/T1686) yeni tekniklerin
        sessizce tanınmamasına yol açan gerçek bir prod bug'ıydı.

        Ayrıca admin override'ların (rule_threshold) MITRE güncellemesi
        sırasında ASLA ezilmediğini doğrular (tech_id PRIMARY KEY + INSERT OR
        IGNORE).
        """
        self.login()
        # Admin bir tekniğin hedefini degistirir
        self.assertEqual(self.client.put(
            "/api/technique-config/T1000", json={"rule_threshold": 5}
        ).status_code, 200)

        with application.app.app_context():
            db = application.get_db()
            before_ids = {r["tech_id"] for r in db.execute(
                "SELECT tech_id FROM technique_config"
            ).fetchall()}
        self.assertNotIn("T1002", before_ids, "henuz eklenmemis olmali")

        # MITRE veri setine yeni bir teknik eklenmis gibi davran (gercek
        # senaryo: v18.1 -> v19.1, T1685/T1686 gibi)
        fixture = mitre_fixture()
        fixture["objects"].append({
            "type": "attack-pattern", "id": "attack-pattern--three",
            "name": "Test Technique Three",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1002"}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
            ],
            "x_mitre_is_subtechnique": False,
        })
        application.MITRE_PATH.write_text(json.dumps(fixture), encoding="utf-8")
        application.MITRE_CACHE.update({"mtime": None, "data": None})

        with application.app.app_context():
            db = application.get_db()
            application.build_technique_config(db)
            db.commit()
            after = {r["tech_id"]: r["rule_threshold"] for r in db.execute(
                "SELECT tech_id, rule_threshold FROM technique_config"
            ).fetchall()}

        self.assertIn("T1002", after, "yeni teknik eklenmis olmali")
        self.assertEqual(after["T1000"], 5, "admin override ezilmemis olmali")

        # Ice aktarim da artik T1002'yi taniyor olmali (canli katalogdan okur)
        preview = self.client.post("/api/import/coverage/preview", json={
            "schema": application.IMPORT_SCHEMA_NAME,
            "version": application.IMPORT_SCHEMA_VERSION,
            "rules": [{"name": "Yeni teknik testi", "product": "QRadar",
                       "techniques": ["T1002"]}],
        }).get_json()
        self.assertTrue(preview["ok"], preview["errors"])
        self.assertEqual(preview["warnings"], [])

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
