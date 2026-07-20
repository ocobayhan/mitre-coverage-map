# Audit Logging — Route'lara Nasıl Eklenir

## Neden Var

`audit_logs` tablosu değiştirilemez (append-only) bir zincir olacak şekilde tasarlandı: her satır SHA-256 ile önceki satırın hash'ine bağlanır (`prev_hash`/`entry_hash`, bkz. `_audit_entry_hash` app.py:776), ve veritabanı trigger'ları (`audit_logs_no_update`, `audit_logs_no_delete`, `ensure_audit_integrity` app.py:795) satırların UPDATE/DELETE edilmesini SQLite seviyesinde engeller. `verify_audit_chain()` (app.py:836) zincirin bozulup bozulmadığını uçtan uca doğrular ve `/api/audit-logs/evidence` bunu dışa aktarılabilir bir kanıt paketine çevirir.

Bu güvenceler yalnızca **her yazma işleminin gerçekten `write_audit_log()` çağırmasına** bağlıdır — çağrı atlanırsa o işlem sessizce iz bırakmadan geçer, zincir kırılmaz ama eksik kalır.

## Fonksiyon

```python
write_audit_log(
    db,
    action: str,        # "create" | "update" | "delete" | "approve" | "assess" | "sync" | "override" | ...
    target_type: str,    # "rule" | "user" | "connector" | "soc_profile" | "telemetry_source" | ...
    target_id: str = "",
    detail: str = "",     # kısa, insan-okunur özet (username=..;role=.. gibi key=value parçaları)
    user=None,             # verilmezse g.current_user kullanılır
    before=None,           # değişiklik öncesi state (dict/list) — JSON'a çevrilip saklanır
    after=None,            # değişiklik sonrası state
)
```

`request_id`, `ip_address`, `user_agent` otomatik olarak Flask `request`/`g` içinden alınır — çağıran taraf bunları geçmez.

## Sanitizasyon Kuralı — İHLAL ETME

`before`/`after`/`detail` içine **asla ham payload dict'i olduğu gibi geçirme**. `users` route'larına bak (app.py:2112, 2165): parola hiçbir zaman `before`/`after`'a girmiyor, sadece `detail=f"username={username};role={role}"` gibi beyaz listeye alınmış alanlar yazılıyor. Yeni bir route eklerken:

- Payload'da parola, token, secret, API key gibi bir alan varsa **whitelist** yaklaşımı kullan: sadece loglanması güvenli alanları elle seç, `**payload` gibi spread etme.
- `before`/`after` için genelde DB'den okunan satırı `dict(row)` olarak geçirmek güvenlidir (zaten şemada hassas alan yoksa) — ama şema hassas bir alan (`password_hash` gibi) içeriyorsa önce çıkar.
- `detail` alanı DB'de `[:4000]` karaktere kırpılır (app.py:1033) — uzun JSON'u `detail`'e değil `after`'a koy.

## Action / Target Adlandırma Kuralı

Kod tabanında gözlemlenen konvansiyon:
- `action`: fiil, geniş zaman değil emir/isim kökü — `create`, `update`, `delete`, `approve`, `assess`, `sync`, `sync_failed`, `test`, `test_failed`, `override`, `snapshot`.
- `target_type`: tekil, snake_case kaynak adı — `rule`, `rule_technique`, `user`, `connector`, `environment`, `asset_group`, `asset_group_monitoring`, `soc_profile`, `soc_profile_techniques`, `detection`, `telemetry_source`, `visibility_override`, `soc_kpi`.
- `target_id`: genelde `str(row_id)`; birleşik anahtarlarda `f"{profile_id}:{tech_id}"` gibi `:` ile birleştirilir (bkz. `visibility_override`).

Yeni bir kaynak eklerken bu ikiliyi mevcut adlandırmayla tutarlı seç — Audit ekranındaki filtreleme `target_type` üzerinden çalışıyor.

## Yeni Bir Yazma Route'u Eklerken Kontrol Listesi

1. Route zaten `@role_required(...)` ile korunuyor mu? (bkz. [rbac.md](rbac.md))
2. DB değişikliğinden **önce** eski state'i oku (varsa) → `before`.
3. `db.execute(...)` ile değişikliği yap.
4. `write_audit_log(db, action=..., target_type=..., target_id=..., detail=..., before=..., after=...)` çağır — `db.commit()`'ten **önce**, aynı transaction içinde (audit satırı ile veri değişikliği atomik olsun).
5. Payload'da hassas alan var mı kontrol et, varsa whitelist'le.
6. `tests/test_app.py`'a bu action için en az bir doğrulama ekle (zincirin bozulmadığını veya audit satırının oluştuğunu kontrol eden bir test — örnek: `test_audit_chain_records_success_and_failure`).

## İlgili Uçlar

- `GET /api/audit-logs` — filtreleme + sayfalama (app.py:2183, filtre inşası `_audit_filters` app.py:2228)
- `GET /api/audit-logs/export` — CSV export
- `POST /api/audit-logs/evidence` — filtrelenmiş kayıtlar + tam zincir durumu + bağımsız doğrulanabilir paket hash'i içeren "Kanıt Paketi" (üretim manifesti ile)
