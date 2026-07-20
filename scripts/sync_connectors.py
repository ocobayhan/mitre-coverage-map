import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as application
from qradar_connector import QRadarConnectorError


def main() -> int:
    parser = argparse.ArgumentParser(description="Enabled QRadar connector sync runner")
    parser.add_argument("--connector-id", type=int, help="Sync only one connector")
    args = parser.parse_args()
    application.init_db()
    results = []
    failed = False
    with application.app.test_request_context(
        "/system/connector-sync", environ_base={"REMOTE_ADDR": "127.0.0.1"}
    ):
        application.g.current_user = {
            "id": None,
            "username": "system:connector",
            "role": "admin",
        }
        db = application.get_db()
        if args.connector_id:
            connectors = db.execute(
                "SELECT * FROM connectors WHERE id=? AND enabled=1", (args.connector_id,)
            ).fetchall()
        else:
            connectors = db.execute(
                "SELECT * FROM connectors WHERE enabled=1 ORDER BY id"
            ).fetchall()
        for connector in connectors:
            try:
                result = application._run_qradar_sync(db, connector)
                results.append({"connector_id": connector["id"], "name": connector["name"], **result})
            except QRadarConnectorError as exc:
                failed = True
                results.append({
                    "connector_id": connector["id"],
                    "name": connector["name"],
                    "status": "failed",
                    "error": str(exc),
                })
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
