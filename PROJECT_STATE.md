# Project State

Son güncelleme: 2026-07-19

## Ürün Amacı

SOC Coverage Map, kurum genelindeki tespit teknolojilerini, MITRE ATT&CK tekniklerini, mitigation uygulamalarını, sorumlu ekipleri ve iyileştirme aksiyonlarını tek bir güvenilir envanterde birleştirir.

## Teknik Yapı

- Backend: Flask 3 + SQLite
- Üretim WSGI: Waitress
- Frontend: sunucu tarafından sunulan HTML, vanilla JavaScript ve CSS
- Yetkilendirme: `viewer`, `editor`, `admin`
- Veri kaynağı: yerel MITRE Enterprise ATT&CK STIX JSON
- Test: Python `unittest` ve Selenium tarayıcı smoke testi

## Güncel Veri Durumu

2026-07-19 veri standardizasyonu sonrasında:

- 438 tespit kaydı
- 433 tespit geçerli MITRE tekniğine bağlı
- 5 tespit analist eşlemesi bekliyor
- Veri güvenilirlik skoru: %99,5
- Geçersiz teknik ilişkisi: 0
- Tespit bulunan teknik oranı: %15,6
- Olgun kapsama oranı: %8,1
- Ortalama kapsam skoru: %20,4
- Kritik GAP: 92

Eski teknik adlarıyla saklanan 479 ilişki standart MITRE ID'lerine dönüştürüldü. 46 adet `None` placeholder ilişkisi kaldırıldı ve 436 taktik değeri canonical slug formatına çevrildi. İşlemler audit kaydına yazıldı. Migrasyon öncesi veritabanı yedeği sistem geçici klasöründe tutuluyor.

## Audit Güvenceleri

- Audit kayıtları append-only veritabanı trigger'larıyla korunuyor.
- Her kayıt önceki hash'e bağlı SHA-256 zincir hash'i taşıyor.
- Başarılı, başarısız ve bloke edilen giriş denemeleri kaydediliyor.
- Kayıtlarda request ID, IP, user-agent ve desteklenen işlemlerde önce/sonra veri bulunuyor.
- Audit ekranı filtreleme, sayfalama, detay, bütünlük kontrolü ve CSV export sunuyor.
- Aynı kullanıcı/IP için 5 dakikada 5 başarısız girişten sonra geçici rate-limit uygulanıyor.

## Veri Güvenilirliği

Veri Kalitesi ekranı aşağıdaki sorunları denetliyor:

- Geçersiz veya eski MITRE teknik eşlemeleri
- MITRE tekniğine bağlanmamış tespitler
- Silinmiş tespite bağlı orphan ilişkiler
- Ürün kataloğunda bulunmayan kaynaklar
- Geçersiz taktik ve güven seviyesi değerleri
- MITRE veri setinin boyutu, tarihi ve katalog sayıları

GAP analizi artık üç farklı metriği ayırıyor:

- Tespit kapsamı: en az bir tespit bulunan teknikler
- Olgun kapsam: birleşik skoru en az %70 olan teknikler
- Ortalama skor: tespit güven seviyesi, teknik eşiği, mitigation ve ürün çeşitliliği

## Güvenlik

- Session cookie: `HttpOnly`, `SameSite=Lax`, opsiyonel `Secure`
- Güvenlik başlıkları: frame engeli, MIME sniffing engeli, referrer ve permissions policy
- Üretim sunucusu `SOC_SECRET_KEY` olmadan başlamıyor.
- Son aktif admin pasifleştirilemiyor veya rolü düşürülemiyor.
- Kullanılan ürün ve ekip kayıtları ilişkili veri varken silinemiyor.
- Yeni ve değiştirilen kullanıcı parolaları en az 10 karakter olmalı.

## Doğrulanan Akışlar

- Login ve rol sınırları
- Audit zincir bütünlüğü ve append-only koruma
- Başarısız giriş rate-limit'i
- Veri kalitesi hata tespiti ve güvenli onarım
- Tespit güven seviyesine göre kapsam skoru
- Son admin koruması
- Matrix, Veri Kalitesi ve Audit ekranlarının masaüstü/mobil yüklenmesi
- Tarayıcı konsolunda sıfır severe hata

## Sadeleştirme — SOC-CMM Sökümü (2026-07-26, Faz 1)

Ürün 12 nav ekranına ulaşmış, her ekran kendi doğrusunu anlatır hale gelmişti. SOC-CMM olgunluk/kanıt katmanı zorunlu validasyon alanları yüzünden `validated coverage %0` gösteriyor, araç "bozuk" hissettiriyordu. Ürünün tek bir soruya odaklanması kararı alındı:

> **"Hangi ortamda, hangi ATT&CK tekniğini görebiliyoruz; nerede körüz?"**

Kaldırılanlar (7 tablo, 14 endpoint, ~780 satır backend + ~600 satır frontend):

- `soc_profiles`, `soc_profile_techniques`, `detection_assessments`, `telemetry_sources`, `telemetry_components`, `visibility_overrides`, `kpi_snapshots`
- SOC-CMM KPI çalışma alanı, profil onay/snapshot akışı, telemetri envanteri, visibility override
- Matrix'in 4 görünüm modu → tek operasyonel görünüm

**Veri kaybı olmadı:** söküm öncesi canlı `soc.db` sorgulandı — `telemetry_sources` / `visibility_overrides` / `kpi_snapshots` tamamen boştu; `detection_assessments`'ın 438 satırının hepsi `untested`, sıfır kanıt / sıfır sahip / sıfır skordu (kural eklendikçe otomatik açılan boş kayıtlar). Söküm öncesi `scripts/backup_db.py` ile doğrulanmış yedek alındı.

`drop_soc_cmm_schema()` idempotent temizlik migration'ı mevcut kurulumlardaki tabloları ve `kpi_snapshots` append-only trigger'larını düşürür; tüm kurulumlar bir kez çalıştırdıktan sonra silinebilir.

## Ortam Bazlı Kapsama (2026-07-26, Faz 2)

Uygulamanın en büyük yalanı tek bir global "%15,6 kapsama" sayısıydı — halbuki kapsama ortama göre değişiyor. Artık matrisin üstünde **Ortam / Varlık Grubu** seçicisi var:

> Bir teknik bir varlık grubunda kapsanır ⟺ o tekniğe bağlı bir tespit vardır **ve** tespitin ürünü o varlık grubunu izlemektedir.

`etkin ağırlık = kapsam seviyesi (low .25 / partial .60 / full 1.0) × izleme (full 1.0 / partial %/100 / none 0)`

Eklenenler:
- `products.category`: `tespit_kaynagi` / `onleyici_kontrol` / `zenginlestirme` — yalnızca tespit kaynakları haritayı boyar ve ürün çeşitliliğine sayılır. Migration mevcut ürünleri varsayılan olarak `tespit_kaynagi` işaretler (davranış sessizce değişmesin diye).
- `rules.source` → `products.name` köprüsü zorunlu kılındı: katalogda olmayan kaynakla kural yazılamaz (400), mevcut uyumsuzluklar Veri Kalitesi'nde **kritik**e yükseltildi. Sebep: eşleşmeyen kaynak hiçbir varlık grubuna bağlanamaz ve teknik sessizce kapsanmamış görünür.
- `GET /api/gap-analysis?asset_group_id=<id>` — GAP ekranı ve rapor matrisle aynı kapsamı kullanır.
- `isCriticalGap()` tek helper'a alındı (4 kopya vardı).
- `idx_product_deployments_product` index'i eklendi.

**Gerçek veriyle doğrulandı** (Kurumsal>Client Makineler + Kurumsal Serverlar, Lumos>Lumos Serverlar):

| Kapsam | Kapsanan (matris) | Kritik boşluk |
|---|---|---|
| Tüm ortamlar | 188/250 (75%) | 23 |
| Client Makineler (QRadar log almıyor) | 154/250 (62%) | **43** |
| Kurumsal Serverlar | 184/250 (74%) | 23 |
| Lumos Serverlar (Defender yok) | 176/250 (70%) | 26 |

Teknik bazında: yalnızca QRadar'ın kapsadığı T1531 client'ta %60 → **%0**; yalnızca Defender'ın kapsadığı T1012 Lumos'ta %27 → **%0**.

### Bilinen tutarsızlık (Faz 3'te çözülecek)

Matris ve GAP ekranı "Kapsanan" kelimesiyle **farklı şey ölçüyor** — bu Faz 2'den önce de böyleydi:

| | Pay | Payda |
|---|---|---|
| Matris (`ms-covered`) | kural **veya** mitigation var | 250 (yalnız ana teknik) |
| GAP / rapor (`coverage_pct`) | yalnız kural var | 691 (alt teknikler dahil) |

Hangi tanımın kazanacağı ürün kararıdır; ekranlar birleşirken tek kaynağa indirilecek. Backend zaten `parent_total` / `parent_covered` alanlarını da döndürüyor.

## Ekran Birleştirme (2026-07-26, Faz 3)

12 nav ekranı **4 bölüme** indirildi:

| Bölüm | Alt sekmeler |
|---|---|
| **Harita** | Matris · Liste Görünümü |
| **Envanter** | Tespitler · Ortam & Kapsam · Mitigation |
| **Boşluklar** | GAP Analizi · Aksiyon Planı · Veri Kalitesi |
| **Ayarlar** | Ayarlar · Audit *(admin)* |

**Yaklaşım — düşük risk:** Paneller fiziksel olarak birleştirilmedi. ID'leri, render fonksiyonları ve içlerindeki ~40 inline `hasRole()` kontrolü aynen duruyor; yalnızca üst seviyede gruplandılar (`SECTIONS` + `showPanel()`). Panel veri yükleyicileri `PANEL_LOADERS` üzerinden merkezîleşti.

- Rol bazlı sekme: `SECTIONS[].tabs[].role` — Audit yalnızca admin'de görünür, bölümde tek sekme kalırsa çubuk gizlenir
- Bölüme geri dönüldüğünde en son bakılan sekme hatırlanır
- Bilgilendirme wiki'si `/docs` route'una taşındı (`templates/docs.html`) — `index.html` **1708 → 791 satır**

### Teknik detay modalı düzeltmeleri
- "Tespit Ekle" formu `body`'ye ekleniyordu, yani Mitigations sekmesindeyken de görünüyordu → `rulesTab`'e taşındı
- "Mitigations (Ekip/Yorum)" özeti Tespitler sekmesinde **ikinci kez** render ediliyordu → kaldırıldı
- Yeni **Aksiyonlar** sekmesi: o tekniğe açılmış aksiyonlar + "bu teknik için aksiyon aç" (boşluğu görmek ile aksiyon açmak aynı yerde)

## "Kapsanan" Tanımı Tek Doğruya İndirildi (2026-07-26)

Matris ve GAP/rapor aynı kelimeyle farklı şey ölçüyordu: matris `kural VEYA mitigation / 250` (%75), GAP `yalnız kural / 691` (%15,6). Ayrıca matris aynı tekniği birden fazla taktikte tekrar sayıyordu (28 teknik; T1078 dört kez).

**Karar — tek "kapsanan" sayısı yerine üç ayrık kova:**

| Metrik | Anlamı |
|---|---|
| **Tespit** | Kuralı var — *görebiliyoruz* |
| **Yalnız Mitigation** | Tespiti yok, işaretli mitigation'ı var — *önlemişiz ama göremiyoruz* |
| **Kapsamsız** | İkisi de yok — *asıl aksiyon listesi* |

Toplamları ana teknik sayısını verir; bilgi kaybolmaz, hiçbir sayı şişmez.

- **Payda: ana teknikler** (benzersiz). Alt teknikler paydaya girmez — 475 alt teknikten yalnızca 5'inin kendi kuralı var; kurallar ana tekniğe eşleniyor ve alt tekniğe yazılan kural zaten ana tekniğe sayılıyor. Alt teknikler ayrı bir metrikte bilgi olarak gösterilir (düşük sayı = "alt teknik eşlemesi yapılmamış" uyarısı).
- **Skor formülü değişmedi:** mitigation %30 ağırlıkla skorda kalmaya devam ediyor. Sadece mitigation'ı olan teknik ortalama %20 skor alıyor (kart turuncu/kırmızı) — "önlemişsin ama göremiyorsun" mesajı doğru veriliyor.
- **Kritik boşluk eşiği hizalandı:** backend `importance_level >= 4` (0.73'ten başlıyor) kullanıyordu, frontend `importance >= 0.70`. Artık ikisi de `CRITICAL_GAP_IMPORTANCE = 0.70`. Backend ayrıca alt teknikleri de sayıyordu (92 vs 21) — o da ana tekniklerle sınırlandı.

**Doğrulama:** altı metriğin altısı da iki tarafta birebir aynı — 216 teknik · 103 tespit (%48) · 55 yalnız mitigation · 58 kapsamsız · 21 kritik boşluk · 5/475 alt teknik.

## Skor Sadeleştirme — Önem Seviyesi Kaldırıldı (2026-07-27, Faz 4b)

Kullanıcı: *"importance level kısmını kaldıralım, 0.70 falan filan hiç gerek yok, süreci karmaşıklaştırıyoruz."*

**Yeni skor:**
```
skor = min(etkin tespit sayısı / teknik hedefi, 1)
```

- **Mitigation skora girmez** — haritada ayrı **M** rozeti. "Yalnız mitigation ile kapsanan" kovası kaldırıldı; kullanıcı bu kavramdan vazgeçti. Renk yalnızca tespite bakar çünkü haritanın sorusu "görebiliyor muyuz".
- **Ürün çeşitliliği skora girmez** — ürün noktaları zaten gösteriyor.
- **Kaldırılanlar:** `technique_config.importance` (sütun `ALTER TABLE ... DROP COLUMN` ile düşürüldü), `_importance_to_level`, `_LEVEL_TO_FLOAT`, `CRITICAL_GAP_IMPORTANCE/SCORE`, `isCriticalGap()`, kritik boşluk kavramı.
- **Teknik hedefi:** `rule_threshold` tüm teknikler için `DEFAULT_RULE_THRESHOLD = 2` ile başlar (önceden mitre.json'dan otomatik türetiliyordu). Admin teknik detayı modalinden değiştirir; migration eski `auto` değerleri 2'ye çeker, `admin` override'ları korur (9 satır korundu).
- **"Kritik Boşluk" → "Tespitsiz Teknik"** (0 tespit). Sıralama: kaç tehdit grubu kullanıyor (`group_count`) — ayar değil, MITRE verisi.
- **Metrikler 3 kova → 2:** Tespit / Kapsamsız. Mitigation bilgi olarak ayrıca sayılır.

**Doğrulandı:** Yalnız mitigation'ı olan T1583 artık **%0** (eskiden %30 alıp "kapsanmış" görünüyordu). Teknik hedefini 2→6 yapınca T1133 %50 turuncudan %17 kırmızıya döndü. Matris ve backend birebir aynı: 216 / 103 tespit / 113 kapsamsız / 111 mitigation / %39 ort.

## Harita Yeniden Tasarımı (2026-07-27, Faz 4c)

Kullanıcı: *"Harita kısmında görselliği değiştirmek istiyorum, kutu boyutları ve arkaplan renklendirmesi MITRE için uygun değil"* + düzeltme: *"alt teknikler her zaman görünür yok bunu yap demedim, açılır kapanır yap ya, üst tekniklerde ağaç gibi olsun."*

**Yeni hücre:** MITRE Navigator'a yakın yoğun ızgara. Sütun genişliği 200–240px → 176–208px, kart min-height 52px → 38px. İçerik iki satıra indi: üstte teknik adı (tek satır, taşarsa `…`), altta `ID · M rozeti · ortam rozeti · etkin/hedef`. Tek fonksiyon üretiyor — `fillTechniqueCell()` — ana teknik ve alt teknik aynı düzeni paylaşıyor.

- **"Detay" butonu kalktı.** Kart gövdesine tıklamak modali açar, sol kenardaki ok alt teknik ağacını açar/kapatır (`.tc-toggle`, açıkken 90° döner). Ağaç davranışı korundu — kullanıcının açık talebi.
- **Mitigation `M` rozeti** (mor pill). `⛨` (U+26E8) Windows'ta tofu çiziyordu; harf rozeti her fontta aynı görünüyor.
- **Ortam rozeti** yalnızca birleşik modda **ve** en az bir ortamda tespit varken çıkıyor. Her karta `0/2` basmak gürültüydü.
- **Zengin tooltip** artık `T1078 · Valid Accounts` başlığı taşıyor; native `title` kaldırıldı (ikisi üst üste biniyordu).
- Ürün noktaları hücrenin sağ üstüne taşındı — alt satır artık sayaca ait.

**Bu arada bulunan iki tutarsızlık düzeltildi:**
1. Üst bardaki "Kapsanan: 103" ortam seçiminden etkilenmiyordu; Lumos seçiliyken şerit 80 derken üst bar 103 diyordu. Artık tek kaynak `updateMatrixStats()` — ikisi de `103 / 216` ↔ `80 / 216`. Etiket "Tespitli teknik" oldu.
2. Liste Görünümü hâlâ emekli tanımı (`rule_count > 0 || mitigation_entry_count > 0`) kullanıyordu — tespite indirildi.

**Doğrulandı:** 25/25 test, browser smoke sıfır konsol hatası, 14 taktik sütunu, 123 aç/kapa oku, ağaç açılıp kapanıyor (6 konteyner / 23 alt kart), ortam değişimi rozetleri gizliyor ve sayıları 103→80 düşürüyor. `styles.css`/`app.js` → `?v=110`.

## Sonraki Öncelikler

1. **Faz 4 — Ürün yetenek şablonları:** DFI/MDO365/MDCA gibi sabit katalogu olan ürünler için hazır teknik eşlemesi (elle giriş yerine).
2. Açık sorular: bkz. **[docs/ACIK_SORULAR.md](docs/ACIK_SORULAR.md)** — özellikle mitigation kapsamasının teknik bazında bilinçli karar haline getirilmesi.
3. Ürünlerin doğru kategorilere alınması (Fortigate Firewall → `onleyici_kontrol` vb.)
4. Kapsam Envanteri'nde kalan gerçek ortam/varlık gruplarının doldurulması
5. QRadar connector'ın kurum test instance'ında kabul testi (kullanıcı yürütecek)
6. Kalan 5 tespitin analist tarafından MITRE tekniklerine bağlanması
7. Kurumsal SSO/OIDC ve merkezi kullanıcı yaşam döngüsü
8. PostgreSQL geçişi ve çoklu uygulama instance desteği
9. CI pipeline ve test veritabanıyla otomatik release kontrolü
10. MITRE veri seti sürümleme ve kontrollü güncelleme iş akışı

## Dağıtım ve Yedekleme (2026-07-20)

- Docker desteği eklendi: `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `.env.example`
- Canlı veritabanı yolu artık `SOC_DB_PATH` (varsayılan `data/`'ya paralel `instance/soc.db`) ve MITRE veri klasörü `SOC_DATA_DIR` ortam değişkenleriyle override edilebilir
- Yedekleme: `scripts/backup_db.py` — SQLite'ın resmi backup API'siyle tutarlı anlık görüntü alır, `PRAGMA integrity_check` ile doğrular, gzip + SHA-256 imzalar, retention uygular (varsayılan 30 gün, en az 1 yedek her zaman tutulur)
- Yedekler bilinçli olarak canlı verinin named volume'ünden ayrı, Docker'ın hiç bilmediği bir host klasörüne (bind mount) yazılır — `docker compose down -v` / `docker system prune --volumes` yedekleri etkilemez
- Zamanlama in-app değil, dışarıdan tetiklenir (`docker exec soc-app python scripts/backup_db.py`, Windows Task Scheduler ile — `scripts/sync_connectors.py` ile aynı model)
- Ayrıntı ve kurtarma adımları: `docs/backup_restore.md`

## Connector Yol Haritası

- **Faz 1 — QRadar:** Use Case Manager mapping API, native rule ID uzlaştırma, sync geçmişi, stale yönetimi ve Audit tamamlandı. Mock QRadar HTTP servisiyle duplicate önleme doğrulandı; kurum QRadar instance kabul testi bekliyor.
- **Faz 2 — QRadar genişletme:** log source activity/coverage, tuning findings, offense count ve son aktivite metrikleri.
- **Faz 3 — Defender (beklemede):** Microsoft Graph `alerts_v2` ile built-in aktivite; custom detection envanteri için Git/JSON öncelikli model. QRadar kabulü tamamlanana kadar uygulanmayacak.
- **Faz 4 — Detection as Code:** custom detection repository, sürüm ve deployment durumunun connector kayıtlarına bağlanması.
