"""SOC Coverage Map icin canli veritabanindan (soc.db) guvenli, dogrulanabilir
yedek alir.

Docker'in yonettigi named volume'den ayri olarak, bu script'in ciktisi Docker'in
hic bilmedigi bir host klasorune (docker-compose.yml'de sadece backup amaciyla
bind mount edilen /app/backups) yazilir. Bu sayede `docker system prune -a --volumes`,
`docker compose down -v` veya image/container silme gibi hicbir Docker islemi
yedekleri etkilemez.

Calistirma (container disaridan, host'ta Windows Task Scheduler ile):
    docker exec soc-app python scripts/backup_db.py

Ortam degiskenleri:
    SOC_DB_PATH              kaynak veritabani (varsayilan: /app/instance/soc.db)
    SOC_BACKUP_DIR            yedeklerin yazilacagi klasor (varsayilan: /app/backups)
    SOC_BACKUP_RETENTION_DAYS bu gunden eski yedekler silinir (varsayilan: 30)
"""

from __future__ import annotations

import gzip
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


def take_backup(db_path: Path, backup_dir: Path) -> Path:
    if not db_path.exists():
        raise FileNotFoundError(f"Kaynak veritabani bulunamadi: {db_path}")

    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    with tempfile.TemporaryDirectory() as tmp:
        raw_path = Path(tmp) / "snapshot.db"

        # sqlite3'un resmi backup API'si: kaynak ayni anda yaziliyor olsa bile
        # (WAL/journal) tutarli bir kopya alir. Duz dosya kopyalama (shutil.copy)
        # yarim yazilmis sayfalari kopyalayip bozuk bir yedek uretebilir.
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            dest = sqlite3.connect(str(raw_path))
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()

        integrity_conn = sqlite3.connect(str(raw_path))
        try:
            integrity = integrity_conn.execute("PRAGMA integrity_check").fetchone()
        finally:
            integrity_conn.close()
        if not integrity or integrity[0] != "ok":
            raise RuntimeError(f"Alinan yedek integrity_check'i gecmedi: {integrity}")

        compressed_name = f"soc-{timestamp}.db.gz"
        compressed_path = backup_dir / compressed_name
        with open(raw_path, "rb") as src, gzip.open(compressed_path, "wb") as dst:
            shutil.copyfileobj(src, dst)

    digest = hashlib.sha256(compressed_path.read_bytes()).hexdigest()
    (backup_dir / f"{compressed_name}.sha256").write_text(f"{digest}  {compressed_name}\n", encoding="utf-8")

    return compressed_path


def enforce_retention(backup_dir: Path, retention_days: int) -> list[Path]:
    """retention_days'ten eski yedekleri siler; en az bir yedegi her zaman tutar."""
    backups = sorted(backup_dir.glob("soc-*.db.gz"), key=lambda p: p.stat().st_mtime)
    if len(backups) <= 1:
        return []

    cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
    removed: list[Path] = []
    for path in backups[:-1]:  # en yeni yedek asla silinmez
        if path.stat().st_mtime < cutoff:
            path.unlink(missing_ok=True)
            sidecar = path.with_name(path.name + ".sha256")
            sidecar.unlink(missing_ok=True)
            removed.append(path)
    return removed


def main() -> int:
    db_path = _env_path("SOC_DB_PATH", "/app/instance/soc.db")
    backup_dir = _env_path("SOC_BACKUP_DIR", "/app/backups")
    retention_days = int(os.environ.get("SOC_BACKUP_RETENTION_DAYS", "30"))

    try:
        backup_path = take_backup(db_path, backup_dir)
    except Exception as exc:
        print(f"[backup_db] HATA: yedekleme basarisiz: {exc}", file=sys.stderr)
        return 1

    size_kb = backup_path.stat().st_size / 1024
    print(f"[backup_db] OK: {backup_path.name} ({size_kb:.1f} KB)")

    removed = enforce_retention(backup_dir, retention_days)
    if removed:
        print(f"[backup_db] retention: {len(removed)} eski yedek silindi (> {retention_days} gun)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
