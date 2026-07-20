# RBAC — Roller ve Yetkilendirme

## Roller

```python
ROLE_LEVELS = {"viewer": 1, "editor": 2, "admin": 3}
```

Sayısal karşılaştırma kullanılır: bir rolün yetkisi olup olmadığı `ROLE_LEVELS[user_role] >= ROLE_LEVELS[min_role]` ile kontrol edilir. Yeni bir rol eklemek gerekirse tek değişiklik noktası burasıdır — ama şu anki üç seviyeli model dört yerde (backend decorator, backend inline check, frontend `hasRole()`, `users` tablosu CHECK'i varsa) birbirinden bağımsız kopyalar halinde durur; biri değişirse diğerleri elle senkron tutulmalı.

## Backend Uygulaması (`app.py`)

İki mekanizma bir arada kullanılıyor:

1. **Route-level decorator** — çoğu route için:
   ```python
   @app.route("/api/rules", methods=["GET", "POST"])
   @role_required("viewer")
   def rules():
       ...
   ```
   `role_required(min_role)` (app.py:1072) route'a girmeden önce `g.current_user`'ın rolünü kontrol eder, yetersizse `403 Forbidden` döner. `login_required` (app.py:1058) ise sadece oturum var mı diye bakar.

2. **Inline yükseltilmiş kontrol** — aynı fonksiyon hem okuma hem yazma metodunu işliyorsa (örn. `GET+POST /api/rules`, `GET+POST /api/products`), decorator en düşük gereksinimi (`viewer`) karşılar, yazma dalının başında ayrıca:
   ```python
   if ROLE_LEVELS[g.current_user["role"]] < ROLE_LEVELS["editor"]:
       return jsonify({"error": "Forbidden"}), 403
   ```
   eklenir. **Yeni bir GET+POST/PUT/DELETE route yazarken bu ikinci kontrolü unutmak en sık RBAC hatasıdır** — decorator'ı `viewer` bırakıp inline kontrolü eklemeyi atlarsan, viewer rolü de yazabilir hale gelir.

## Yetki Matrisi (route → gereken minimum rol)

| Kaynak | GET | Yazma (POST/PUT/DELETE) |
|---|---|---|
| `mitre-min`, `mitre` | viewer | — |
| `rules` | viewer | editor |
| `rules/bulk`, `rules/<id>/coverage`, `rules/<id>` (DELETE), `rules/<id>/techniques` | — | editor |
| `products` | viewer | admin |
| `teams` | viewer | admin |
| `mitigation-notes`, `mitigation-entries` | viewer | editor |
| `users` | admin | admin |
| `audit-logs`, `audit-logs/export`, `audit-logs/evidence` | admin | admin |
| `connectors` (tüm alt route'lar) | admin | admin |
| `scope-registry` | viewer | — |
| `environments`, `asset-groups` (CRUD) | — | admin |
| `asset-groups/<id>/monitoring` | — | editor |
| `data-quality` | viewer | admin (repair) |
| `ttp-list`, `technique-detail` | viewer | — |
| `admin/reset` | — | admin |
| `soc-profiles` (liste/detay) | viewer | — |
| `soc-profiles/<id>/techniques`, `/approve` | — | admin |
| `detection-assessments` (liste) | viewer | editor (tekil güncelleme) |
| `attack-data-components` | viewer | — |
| `telemetry-sources` | viewer | editor |
| `visibility-overrides` | — | admin |
| `soc-kpi`, `soc-kpi/layer`, snapshot detay | viewer | admin (snapshot oluşturma) |
| `technique-config` | viewer | admin |
| `gap-analysis`, `threat-actors` | viewer | — |
| `action-items` | viewer | editor |

Genel kural: **viewer** her şeyi okuyabilir (audit, connector, kullanıcı yönetimi hariç), **editor** operasyonel veriyi (tespit, mitigation, telemetri, aksiyon, kapsam anketi) yazabilir, **admin** yapısal/yönetsel şeyleri (kullanıcı, ürün, ekip, connector, ortam/varlık grubu, SOC profili onayı, KPI snapshot, teknik config) değiştirir.

## Frontend Uygulaması (`static/app.js`)

`applyRoleUI()` (app.js:72) — `currentUser.role` `/api/me`'den alınır, `hasRole(minRole)` ile karşılaştırılır, izin yoksa ilgili DOM elemanı `hidden` class'ı ile gizlenir (silinmez — sadece görsel). **Frontend gizleme bir güvenlik sınırı değildir**, backend her zaman kendi kontrolünü yapar; bu yüzden yeni bir admin-only özellik eklerken hem `applyRoleUI()`'a hem backend route'a ayrı ayrı eklemeyi unutma.

Gizlenen öğeler: reset butonu, Ayarlar sekmeleri (CSV, Kullanıcılar, Audit, Ekipler, Connector'lar), Audit nav item'ı, veri kalitesi onarım butonu, SOC-CMM snapshot/onay/profil butonları, telemetri ekleme butonu.

## Yeni Bir Yetkili Route Eklerken Kontrol Listesi

1. Route'a `@role_required("<min_rol>")` ekle (GET dahil en düşük gereken seviye).
2. Route aynı fonksiyonda daha yüksek yetki gerektiren bir yazma metodu da barındırıyorsa, o dal içine inline `ROLE_LEVELS[...] < ROLE_LEVELS["<üst_rol>"]` kontrolü ekle.
3. Yazma işlemiyse `write_audit_log(...)` çağrısı ekle — bkz. [audit_logging.md](audit_logging.md).
4. Frontend'te ilgili buton/sekme/alanı `applyRoleUI()` içinde `hasRole()` ile gizle.
5. `tests/test_app.py`'a en az bir "düşük rol reddedilir" testi ekle (örnek: `test_viewer_cannot_mutate_rules_or_read_audit`).
