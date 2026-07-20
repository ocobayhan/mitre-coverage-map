# Docker Dagitimi, Yedekleme ve Geri Yukleme

## Mimari

```
docker-compose.yml
  app (container)
    /app/instance/soc.db   <-- named volume "soc_data"   (canli veri)
    /app/backups/          <-- bind mount "./backups"     (yedekler, HOST'ta)
```

Iki farkli kalicilik mekanizmasi bilincli olarak ayri tutuluyor:

- **Canli veri (`soc_data` named volume):** Docker'in kendi yonettigi depolama. Container yeniden baslatildiginda/guncellendiginde kalir. Ama `docker compose down -v`, `docker volume rm soc_data` veya `docker system prune -a --volumes` gibi bir komut bilerek ya da yanlislikla calistirilirsa **silinebilir**.
- **Yedekler (`./backups` bind mount):** Docker'in hic bilmedigi duz bir host klasoru. Docker'in hicbir "purge"/"prune"/volume silme komutu bu klasore dokunamaz — cunku Docker bunu kendi yonettigi bir kaynak olarak gormuyor, sadece bir bind mount. Bu yuzden gercek kurtarma garantisi buradan gelir, named volume'den degil.

`scripts/backup_db.py`, `soc.db`'nin SQLite'in resmi backup API'siyle (canli yazma sirasinda bile guvenli — duz dosya kopyalama gibi yarim sayfa riski yok) tutarli bir anlik goruntusunu alir, `PRAGMA integrity_check` ile dogrular, gzip'ler, SHA-256 imzalar ve `/app/backups` altina zaman damgali olarak yazar. Varsayilan 30 gunden eski yedekleri temizler (en az bir yedek her zaman tutulur).

## Kurulum

```powershell
copy .env.example .env
# .env icine SOC_SECRET_KEY degerini doldur (bkz. .env.example icindeki komut)

docker compose up -d --build
```

Uygulama `http://localhost:8000` uzerinde ayaga kalkar. Ilk calistirmada `soc_data` volume'u bos oldugu icin `init_db()` varsayilan admin/editor/viewer hesaplarini ve seed tespitleri olusturur (bkz. README).

## Zamanlanmis Yedekleme

Bu proje in-app bir job scheduler icermiyor (bkz. CLAUDE.md) — `scripts/sync_connectors.py` gibi, yedekleme de **host'tan** tetiklenen bir dis islem olarak calistirilir:

```powershell
docker exec soc-app python scripts/backup_db.py
```

Windows Task Scheduler'da gunluk (ornegin 03:00) calisacak bir gorev olarak ekle. Basari/hata `stdout`/`stderr` uzerinden raporlanir (exit code 0 = basarili, 1 = basarisiz) — Task Scheduler'in "Son Calistirma Sonucu" alaninda gorunur.

Ortam degiskenleriyle ayarlanabilir (docker-compose.yml'de veya `.env`'de):
- `SOC_BACKUP_DIR` — varsayilan `/app/backups`
- `SOC_BACKUP_RETENTION_DAYS` — varsayilan `30`

## Geri Yukleme

1. Uygulamayi durdur: `docker compose stop app`
2. Geri yuklenecek yedegi `./backups/` altinda bul (ornegin `soc-20260720-030000.db.gz`) ve dogrula:
   ```powershell
   certutil -hashfile backups\soc-20260720-030000.db.gz SHA256
   # backups\soc-20260720-030000.db.gz.sha256 icindeki degerle karsilastir
   ```
3. Aciyorsan gzip'i cikar ve mevcut volume'e kopyala:
   ```powershell
   docker run --rm -v soc-coverage-map_soc_data:/instance -v ${PWD}/backups:/backups python:3.12-slim `
     python -c "import gzip,shutil; shutil.copyfileobj(gzip.open('/backups/soc-20260720-030000.db.gz','rb'), open('/instance/soc.db','wb'))"
   ```
4. Uygulamayi tekrar baslat: `docker compose start app`
5. Girisi ve verinin geldigini dogrula; admin olarak Audit ekranindan **Zincir Bütünlüğü** kontrolunu calistir (`verify_audit_chain`, `/api/audit-logs/evidence`) — geri yuklenen dosyanin audit zinciri bozulmamis olmali (backup, dosyanin tamamini aldigi icin zincir de dahil tutarli kalir; sorun sadece hangi zaman noktasindan geri yuklendigiyle ilgilidir).

## Test Edildi

`scripts/backup_db.py`, gercek `soc.db` (438 tespit) uzerinde manuel olarak calistirilip dogrulandi: alinan yedek gzip'ten geri acilip `PRAGMA integrity_check` = `ok` ve satir sayisi kaynakla ayni cikti. Retention fonksiyonu senkron bir testte, 30 gunden eski sahte bir dosyayi silip en yeni yedegi koruyarak dogrulandi.
