import gzip
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import backup_db


class BackupDbTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "source.db"
        self.backup_dir = self.root / "backups"

        conn = sqlite3.connect(self.db_path)
        conn.execute("CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT)")
        conn.execute("INSERT INTO rules (name) VALUES ('test rule')")
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_backup_is_valid_and_restorable(self):
        backup_path = backup_db.take_backup(self.db_path, self.backup_dir)
        self.assertTrue(backup_path.exists())

        sidecar = backup_path.with_name(backup_path.name + ".sha256")
        self.assertTrue(sidecar.exists())

        restored_path = self.root / "restored.db"
        with gzip.open(backup_path, "rb") as src, open(restored_path, "wb") as dst:
            dst.write(src.read())

        conn = sqlite3.connect(restored_path)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM rules").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        finally:
            conn.close()

    def test_missing_source_raises(self):
        with self.assertRaises(FileNotFoundError):
            backup_db.take_backup(self.root / "does-not-exist.db", self.backup_dir)

    def test_retention_keeps_newest_and_removes_old(self):
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        old = self.backup_dir / "soc-20200101-000000.db.gz"
        old.write_bytes(b"x")
        (self.backup_dir / (old.name + ".sha256")).write_text("dummy")
        old_time = time.time() - 100 * 86400
        os.utime(old, (old_time, old_time))

        newest = self.backup_dir / "soc-20990101-000000.db.gz"
        newest.write_bytes(b"y")

        removed = backup_db.enforce_retention(self.backup_dir, retention_days=30)

        self.assertEqual([p.name for p in removed], [old.name])
        self.assertFalse(old.exists())
        self.assertTrue(newest.exists())

    def test_retention_never_deletes_the_last_remaining_backup(self):
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        only = self.backup_dir / "soc-20200101-000000.db.gz"
        only.write_bytes(b"x")
        old_time = time.time() - 1000 * 86400
        os.utime(only, (old_time, old_time))

        removed = backup_db.enforce_retention(self.backup_dir, retention_days=30)

        self.assertEqual(removed, [])
        self.assertTrue(only.exists())


if __name__ == "__main__":
    unittest.main()
