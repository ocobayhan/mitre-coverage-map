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

    def test_scope_registry_records_environment_group_and_monitoring_survey(self):
        self.assertEqual(self.login().status_code, 200)
        environment = self.client.post(
            "/api/environments",
            json={
                "name": "DIAS Lumos",
                "code": "DIAS-LUMOS",
                "description": "DIAS Lumos ortamı",
                "criticality": 5,
                "owner": "Platform Ekibi",
            },
        )
        self.assertEqual(environment.status_code, 201)
        environment_id = environment.get_json()["id"]
        group = self.client.post(
            f"/api/environments/{environment_id}/asset-groups",
            json={
                "name": "Linux Serverler",
                "platform": "Linux",
                "asset_type": "Server",
                "asset_count": 42,
                "criticality": 5,
                "owner": "Linux Ekibi",
            },
        )
        self.assertEqual(group.status_code, 201)
        group_id = group.get_json()["id"]
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
            f"/api/asset-groups/{group_id}/monitoring",
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
        saved_group = registry["environments"][0]["groups"][0]
        self.assertEqual(saved_group["name"], "Linux Serverler")
        deployments = {item["product_name"]: item for item in saved_group["deployments"]}
        self.assertEqual(deployments["QRadar"]["monitoring_status"], "full")
        self.assertEqual(deployments["QRadar"]["connector_id"], connector_id)
        self.assertEqual(deployments["DFE"]["monitoring_status"], "none")
        self.assertTrue(self.client.get("/api/audit-logs").get_json()["integrity"]["valid"])

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
        self.assertEqual(overview["covered_techniques"], 1)
        self.assertEqual(overview["coverage_pct"], 50.0)
        self.assertEqual(overview["mature_techniques"], 0)
        self.assertLess(overview["average_score_pct"], 20)

    def test_viewer_cannot_mutate_rules_or_read_audit(self):
        self.assertEqual(self.login("viewer", "Viewer123!").status_code, 200)
        create = self.client.post(
            "/api/rules", json={"name": "Blocked", "source": "QRadar"}
        )
        self.assertEqual(create.status_code, 403)
        self.assertEqual(self.client.get("/api/audit-logs").status_code, 403)

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

    def test_soc_kpi_requires_validated_detection_evidence(self):
        self.login()
        self.client.post(
            "/api/rules",
            json={"name": "Process analytic", "tactic": "execution", "tech": "T1000", "source": "QRadar"},
        )
        rule_id = self.client.get("/api/rules").get_json()[0]["id"]

        initial = self.client.get("/api/soc-kpi").get_json()["metrics"]
        self.assertEqual(initial["mapped_coverage"], 50.0)
        self.assertEqual(initial["validated_coverage"], 0.0)

        rejected = self.client.put(
            f"/api/detection-assessments/{rule_id}",
            json={"validation_status": "validated", "detection_score": 3},
        )
        self.assertEqual(rejected.status_code, 400)

        accepted = self.client.put(
            f"/api/detection-assessments/{rule_id}",
            json={
                "lifecycle_status": "active",
                "validation_status": "validated",
                "detection_score": 3,
                "applicable_scope": "Kurum geneli",
                "owner": "SOC Engineering",
                "validation_method": "Atomic test",
                "evidence_ref": "CASE-100",
                "last_validated_at": "2026-07-19",
                "expires_at": "2099-07-19",
            },
        )
        self.assertEqual(accepted.status_code, 200)
        rule = self.client.get("/api/rules").get_json()[0]
        self.assertEqual(rule["validation_status"], "validated")
        self.assertEqual(rule["detection_score"], 3)
        self.assertEqual(rule["owner"], "SOC Engineering")
        metrics = self.client.get("/api/soc-kpi").get_json()["metrics"]
        self.assertEqual(metrics["validated_coverage"], 50.0)
        self.assertEqual(metrics["weighted_detection"], 30.0)

    def test_visibility_uses_data_components_and_quality(self):
        self.login()
        response = self.client.post(
            "/api/telemetry-sources",
            json={
                "name": "Endpoint process events",
                "producer": "Windows",
                "destination": "SIEM",
                "scope": "Kurum geneli",
                "owner": "Platform",
                "active": True,
                "analytics_ready": True,
                "components": ["DC1000"],
                "device_completeness": 5,
                "field_completeness": 5,
                "timeliness": 5,
                "consistency": 5,
                "retention": 5,
            },
        )
        self.assertEqual(response.status_code, 201)
        payload = self.client.get("/api/soc-kpi").get_json()
        technique = next(item for item in payload["techniques"] if item["tech_id"] == "T1000")
        self.assertEqual(technique["visibility_score"], 4.0)
        self.assertEqual(payload["metrics"]["visibility"], 50.0)
        self.assertEqual(payload["metrics"]["visible_threshold_coverage"], 50.0)

    def test_approved_profile_snapshot_is_append_only(self):
        self.login()
        profile_id = self.client.get("/api/soc-profiles").get_json()[0]["id"]
        draft_snapshot = self.client.post("/api/soc-kpi/snapshots", json={"profile_id": profile_id})
        self.assertEqual(draft_snapshot.status_code, 409)
        self.assertEqual(self.client.post(f"/api/soc-profiles/{profile_id}/approve").status_code, 200)
        snapshot = self.client.post("/api/soc-kpi/snapshots", json={"profile_id": profile_id})
        self.assertEqual(snapshot.status_code, 201)
        self.assertEqual(len(snapshot.get_json()["payload_hash"]), 64)
        detail = self.client.get(f"/api/soc-kpi/snapshots/{snapshot.get_json()['id']}").get_json()
        self.assertTrue(detail["integrity"]["valid"])
        layer = self.client.get(f"/api/soc-kpi/layer?profile_id={profile_id}&mode=combined").get_json()
        self.assertEqual(len(layer["techniques"]), 2)

        db = sqlite3.connect(application.DB_PATH)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("UPDATE kpi_snapshots SET visibility=99 WHERE id=1")
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute("DELETE FROM kpi_snapshots WHERE id=1")
        db.close()


if __name__ == "__main__":
    unittest.main()
