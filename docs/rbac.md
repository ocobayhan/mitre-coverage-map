# RBAC — Roller ve Yetkilendirme

## Roller

```python
ROLE_LEVELS = {"viewer": 1, "editor": 2, "admin": 3}
```

Sayısal karşılaştırma kullanılır: bir rolün yetkisi olup olmadığı `ROLE_LEVELS[user_role] >= ROLE_LEVELS[min_role]` ile kontrol edilir. Yeni bir rol eklemek gerekirse tek değişiklik noktası burasıdır — ama şu anki üç seviyeli model üç yerde (backend decorator'ları, frontend `hasRole()`, `users` tablosu CHECK'i varsa) birbirinden bağımsız kopyalar halinde durur; biri değişirse diğerleri elle senkron tutulmalı.

## Backend Uygulaması (`app.py`)

İki decorator kullanılıyor:

1. **Tek rol için `role_required(min_role)`** (app.py:1072) — route'un tüm metodları aynı minimum rolü gerektiriyorsa:
   ```python
   @app.route("/api/mitre-min")
   @role_required("viewer")
   def mitre_min():
       ...
   ```
   Route'a girmeden önce `g.current_user`'ın rolünü kontrol eder, yetersizse `403 Forbidden` döner. `login_required` (app.py:1058) ise sadece oturum var mı diye bakar.

2. **Metod bazlı `role_required_methods(role_map)`** — aynı view function hem okuma hem yazma metodunu birlikte işliyorsa (örn. `GET+POST /api/rules`, `GET+POST /api/products`):
   ```python
   @app.route("/api/rules", methods=["GET", "POST"])
   @role_required_methods({"GET": "viewer", "POST": "editor"})
   def rules():
       ...
   ```
   Her HTTP metodu için ayrı minimum rol tanımlanır. **Fail-closed** çalışır: `role_map`'te karşılığı olmayan bir metod (örn. route'a sonradan `DELETE` eklenip `role_map` güncellenmezse) otomatik olarak `403` döner — sessizce en düşük role miras kalmaz. Ayrıca `role_map` içinde geçersiz bir rol adı geçerse decorator, route tanımlanırken (import/başlangıç anında) `ValueError` fırlatır.

   Bu, eskiden route gövdesinin içine gömülü `if ROLE_LEVELS[...] < ROLE_LEVELS[...]` satırlarıyla yapılıyordu (2026-07-20'de `role_required_methods`'a taşındı — bkz. `tests/test_app.py:test_per_method_role_map_blocks_writes_but_allows_reads`) — o pattern'de decorator'ı `viewer` bırakıp inline kontrolü eklemeyi unutmak en sık RBAC hatasıydı. Artık route'un tüm metod/rol eşlemesi tek bir yerde, decorator satırında görünür.

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
| `me/password` (kendi parolanı değiştir) | — | herhangi bir oturum açmış kullanıcı (`login_required`, rol şartı yok) |
| `audit-logs`, `audit-logs/export`, `audit-logs/evidence` | admin | admin |
| `connectors` (tüm alt route'lar) | admin | admin |
| `scope-registry` | viewer | — |
| `environments` (CRUD) | — | admin |
| `environments/<id>/monitoring` | — | editor |
| `data-quality` | viewer | admin (repair) |
| `ttp-list`, `technique-detail` | viewer | — |
| `admin/reset` | — | admin |
| `technique-config` | viewer | admin |
| `gap-analysis` (`?environment_id=` ile ortam bazlı), `threat-actors` | viewer | — |
| `action-items` | viewer | editor |

Genel kural: **viewer** her şeyi okuyabilir (audit, connector, kullanıcı yönetimi hariç), **editor** operasyonel veriyi (tespit, mitigation, aksiyon, kapsam anketi) yazabilir, **admin** yapısal/yönetsel şeyleri (kullanıcı, ürün, ekip, connector, ortam, teknik config) değiştirir.

## Frontend Uygulaması (`static/app.js`)

`applyRoleUI()` (app.js:72) — `currentUser.role` `/api/me`'den alınır, `hasRole(minRole)` ile karşılaştırılır, izin yoksa ilgili DOM elemanı `hidden` class'ı ile gizlenir (silinmez — sadece görsel). **Frontend gizleme bir güvenlik sınırı değildir**, backend her zaman kendi kontrolünü yapar; bu yüzden yeni bir admin-only özellik eklerken hem `applyRoleUI()`'a hem backend route'a ayrı ayrı eklemeyi unutma.

Gizlenen öğeler: reset butonu, Ayarlar alt sekmeleri (CSV, Kullanıcılar, Ekipler, Connector'lar), veri kalitesi onarım butonu.

**Bölüm alt sekmeleri (Faz 3):** Nav 4 bölümden oluşur (Harita / Envanter / Boşluklar / Ayarlar); her bölümün alt sekmeleri `SECTIONS` sabitinde tanımlıdır (`static/app.js`). Bir sekmeye `role: 'admin'` verilirse `visibleTabs()` onu düşük rollerde hiç render etmez — örn. Audit sekmesi. Bölümde tek görünür sekme kalırsa çubuk tamamen gizlenir.

> `applyRoleUI()` toplam yetkilendirmenin yalnızca bir kısmıdır — geri kalan ~40 kontrol render fonksiyonlarının içindeki inline `hasRole()` çağrılarıdır (kural satırları, modal formları, mitigation girişleri, connector işlemleri, kapsam anketi). Ekran birleştirme/taşıma yaparken bunların her biri taşınmalıdır.

## Yeni Bir Yetkili Route Eklerken Kontrol Listesi

1. Route'un tüm metodları aynı role mi ihtiyaç duyuyor? Evetse `@role_required("<min_rol>")`, hayırsa (örn. GET+POST farklı rol) `@role_required_methods({"GET": "viewer", "POST": "editor"})` kullan — route'un kabul ettiği **her** metod `role_map`'te olmalı, yoksa o metod fail-closed 403 döner.
2. Yazma işlemiyse `write_audit_log(...)` çağrısı ekle — bkz. [audit_logging.md](audit_logging.md).
3. Frontend'te ilgili buton/sekme/alanı `applyRoleUI()` içinde `hasRole()` ile gizle.
4. `tests/test_app.py`'a en az bir "düşük rol reddedilir" testi ekle (örnek: `test_viewer_cannot_mutate_rules_or_read_audit`, çoklu-route için `test_per_method_role_map_blocks_writes_but_allows_reads`).
