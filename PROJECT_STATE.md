# Project State

Son güncelleme: 2026-08-15

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

## Mitigation UI + Ürün Alanı (2026-07-27, Faz 4d)

Kullanıcı: *"ürünleri düzenleyeceğim… ama onun arayüzünüde yeniler misin, bir kutucuk var çok çirkin duruyor."*

**"Çirkin"in teknik sebebi bulundu:** `.mitigation-list-row` ızgarası CSS'te **üç ayrı yerde** tanımlıydı (`110px 0.9fr 0.9fr 3fr` → `110px minmax(200px,.8fr)…` → `80px minmax(170px,1fr)…`), sonuncusu kazanıyordu ve başlık ile satırlar farklı hizalanıyordu. Üçü tek yetkili bloğa indirildi; medya sorguları artık yalnızca onu daraltıyor.

**Şema — iki ölü tablo düştü:** `mitigation_notes` ve `mitigation_global` canlı veride **0 satır**dı. Bir mitigation'ın "işaretli" olması zaten `mitigation_entries` kaydının varlığından türüyordu; iki paralel gerçek kaynağı vardı. `drop_legacy_mitigation_tables()` ikisini de düşürdü, `/api/mitigation-notes` endpoint'i ve frontend'deki `mitigationNotes` katmanı (`normalizeNotes`, `getMitigationNote`, `saveMitigationNote`) tamamen kalktı. Tek kaynak: `isMitigationChecked(id) = entries.length > 0`.

**Yeni alan:** `mitigation_entries.product_id` (nullable FK → `products.id`). Ürün **isteğe bağlı** — süreç/eğitim/politika ile sağlanan mitigation'lar var, zorunlu tutmak uydurma ürün seçtirirdi. Ama verildiğinde katalogda bulunmak zorunda (400 döner), yoksa `rules.source`'taki isim eşleşmesi sorunu tekrarlanırdı.

**UI:** kayıt artık kart — ekip + ürün rozeti üstte, açıklama altta, sil `×` köşede. Form iki satır (ekip/ürün, açıklama) + sağda Ekle. Panel ve modal aynı `mitigationEntryHtml()` / `buildProductSelectEl()` fonksiyonlarını kullanıyor. Kaydı olan satırın ID'si yeşil.

**İki bug düzeltildi:**
1. `e.team` / `e.comment` `_esc`siz interpolate ediliyordu (XSS) — mitigation adı, ID'si ve teknik çipleri de kaçırılmamıştı, hepsi düzeltildi.
2. Mitigation panelindeki ekleme formu rol korumasızdı; viewer formu görüyor ama backend reddediyordu. Form artık `hasRole('editor')` olmadan basılmıyor (doğrulandı: viewer 44 satır görüyor, 0 form / 0 sil butonu).

**Doğrulandı:** 27/27 test (2 yeni: ürün alanı + ölü tabloların düşmesi), browser smoke sıfır konsol hatası, migration sonrası 11 mevcut kayıt korundu, DFE ürünlü kayıt ekleme/silme uçtan uca çalışıyor. `?v=112`.

> **Veri notu:** Lumos ortamı `active=0` durumundaydı (27 Temmuz 14:10'daki bir PUT), bu yüzden harita ortam seçicisinde görünmüyordu. Aktif hale getirildi. Ayrıca 11 mitigation kaydının 3'ü artık var olmayan ekiplere bağlı (`DENBEME`, `DENEM`, `DENEME`) — `team` FK değil serbest metin, kullanıcı temizleyecek.

## LLM Eşleme İçe Aktarımı (2026-07-27, Faz 5)

Kullanıcı: *"QRadar'da kuralları export aldığımda… Claude bana bir MITRE sınıflandırması versin, bir kural birden fazla teknikte tespit yapabilir… bu çıktıyı uygulamaya upload ettiğimde uygulama tamamen anlayıp haritalandırmayı ayarlasın."*

**Akış:** kuralları dışa aktar → `Ayarlar > İçe Aktarım`'dan prompt'u kopyala → Claude'a ürün + kural listesiyle ver → dönen JSON'u yükle → önizle → uygula.

**Şema** (`docs/mitre_mapping_prompt.md`, `schema: "soc-coverage-import"`, `version: 1`):
- `products[]` — yeni ürün katalogu (oluşturmak **admin** ister; editor kural yükleyebilir ama katalogu genişletemez)
- `rules[]` — isimli kurallar, `techniques[]` dizisi (bir kural N tekniğe eşlenebilir)
- `product_coverage[]` — ürünün built-in setinin toplu kapsaması; `"<Ürün> — Built-in kapsama"` adlı tek kayda dönüşür. Kullanıcının kararı: her ikisi de desteklensin.

**İki aşamalı, tek planlayıcı:** `/api/import/coverage/preview` hiçbir şey yazmaz, plan döner; `/apply` aynı `_plan_coverage_import()` çıktısını uygular. "Önizlemede gördüğün" ile "olan" ayrışamaz.

**Doğrulama:** teknik ID'leri `technique_config`'e karşı denetlenir (LLM'in ID uydurması bilinen risk — `T9999` test edildi, yakalandı), ürün katalogda veya dosyada olmalı, aynı `(name, product)` iki kez geçemez. Yapısal hatalarda (ürün, şema) **kısmi uygulama yok** — tek hata varsa hiçbir satır yazılmaz. Tanınmayan teknik ID'si ise **uyarıdır**, dosyayı durdurmaz — bkz. aşağıdaki "Teknik tanıma artık uyarı" bölümü (gerçek veriyle karşılaşılan sorun sonrası eklendi).

**Birleştirme (kullanıcının kararı):** mevcut kuralın teknikleri asla silinmez, eksikler eklenir. Aynı dosya ikinci kez yüklendiğinde her şey `noop`. Bedeli: kaynak sistemden kaldırılan eşleme uygulamada kalır.

**Bu arada CSV import düzeltildi:** aynı `(name, source)` ikinci kez gelince UNIQUE index'e çarpıp **500** dönüyordu. Artık aynı planlayıcıya bağlı ve çoklu satır tek kurala birleşiyor.

**Doğrulandı:** 34/34 test (7 yeni), gerçek MITRE verisiyle uçtan uca — alt teknikler (`T1114.003`) kabul edildi, uydurma ID reddedildi, ikinci yükleme idempotent, mükerrer test verisi temizlendi. `/docs` artık hash ile derin bağlantı destekliyor; bayat "CSV Format" sayfası İçe Aktarım olarak yeniden yazıldı.

## Arayüz Tazeleme (2026-07-27, Faz 6)

Kullanıcı: *"matrix hariç genel tüm arayüzde bir görsellik eksikliği var… özellikle bazı kutucuklar ve yazı yazılacak alanlar çok basit duruyor."*

`design-system/soc-ui.css`'in kendi README'sinde önerdiği kademeli yol izlendi: **önce token'lar** (her şey onlara referans verdiği için tek dokunuşla bütün ekranlar tazelenir), sonra en çok göze batan bileşenler.

- **Kenarlıklar** düz gri (`#3b3a39`) yerine saydam beyaz (`rgba(255,255,255,.09/.13/.18)`) — koyu zeminde "çizik" değil "hafif ayrım" olarak okunuyor.
- **Girdi alanları** artık yüzeyden **daha koyu** (`--d-input-bg: #151716`). "Çok basit duruyor" şikayetinin asıl sebebi buydu: kutular yüzeyle aynı tondaydı, sınırları görünmüyordu. Odakta 3px'lik yumuşak mavi halka.
- **Select okları** yerleşik tarayıcı oku yerine SVG. Kendi `background`'unu tanımlayan üç yerde (kapsam anketi, ürün satırları, mitigation formu) ok siliniyordu — hepsine geri verildi.
- Mikro etiketler (küçük, kalın, harf aralıklı, büyük harf), yumuşatılmış köşe ölçeği (5/7/10px), kart gölgeleri, tablo satır hover'ı, kesikli çerçeveli boş durumlar, ince kaydırma çubuğu.

**Matris bilinçli olarak dışarıda bırakıldı** — `.technique-card` / `.subtech-card` / `.tactic-*` kendi rengini ve ölçüsünü koruyor (kullanıcının kararı: "matrix hariç"). Smoke ile doğrulandı: 14 taktik sütunu, 123 aç/kapa oku, mobil taşma yok, sıfır konsol hatası. `?v=114`.

## Kapsama İçe Aktarımı (2026-07-27, Faz 5)

Kullanıcının ihtiyacı: QRadar/Defender kural listelerini bir LLM'e verip MITRE eşlemesi ürettirmek, çıkan dosyayı uygulamaya yükleyip haritayı otomatik kurmak. Bir kural birden fazla tekniğe eşlenebilmeli.

**Şema:** `soc-coverage-import` v1 — `products[]` + `rules[]` + `product_coverage[]`. Prompt ve şema referansı: **[docs/mitre_mapping_prompt.md](docs/mitre_mapping_prompt.md)**. Uygulama prompt'u `GET /api/import/mapping-prompt` ile o dosyadan okuyup kopyalatıyor; doküman ve arayüz ayrışamıyor.

**İki aşamalı akış (kullanıcı kararı):** `POST /api/import/coverage/preview` hiçbir şey yazmadan bir plan döner (N yeni kural, M güncellenecek, hatalar, değişecek teknikler); `…/apply` aynı planı uygular. Aynı `_plan_coverage_import()` ikisini de besliyor, yani "önizlemede gördüğün" ile "olan" ayrışamaz.

**Birleştirme semantiği (kullanıcı kararı):** mevcut kuralın teknikleri **asla silinmez**, eksikler eklenir. Uygulamada elle yapılan eşlemeler korunur; bedeli, kaynak sistemden kaldırılan bir eşlemenin burada kalması.

**Yapısal hatalarda kısmi uygulama yok:** bir tek hata varsa 400 döner, geçerli satırlar da yazılmaz. (27 Temmuz'daki bu karar tanınmayan teknik ID'sini de "hata" sayıyordu — 28 Temmuz'da gerçek veriyle bunun pratikte çalışmadığı görüldü, aşağıya bakın.)

### Ürün iddiası ≠ tespit (Faz 5 sonu, kullanıcı kararı)

İnceleme sırasında çıkan sorun: `detected = rule_count > 0` ikiliydi, ağırlığa bakmıyordu. Tek bir `product_coverage` satırı ("DfE built-in şu 120 tekniği kapsıyor") manşet metriği `0/216` → `120/216` yapardı — hem de arkasında yazılmış tek bir kural olmadan. Kart renkleri dürüst kalıyordu (`partial` 0.60 / hedef 2 = %30, amber) ama üstteki sayı yalan söylüyordu.

Çözüm: **`rules.origin`** sütunu (`named` | `product_claim`).

| | İsimli kural | Ürün iddiası |
|---|---|---|
| "Tespit" kovası | girer | **girmez** |
| Kapsama skoru | girer | girer (`partial` = 0.60) |
| Harita | normal çerçeve | **kesikli amber çerçeve** (`.claim-only`) |

Backend `detected = named_rule_count > 0`, frontend `namedRuleCount()` ile aynı kural. Tooltip'te "Yalnız ürün iddiası — adı olan tespit yok" satırı çıkıyor.

**Bu arada düzeltilen bug:** eski CSV toplu içe aktarımı her satır için kör `INSERT` yapıyordu; aynı `(name, source)` ikinci kez gelince UNIQUE index'e çarpıp **500** dönüyordu. Artık aynı planlayıcıya bağlı — aynı kuralın satırları tek kurala birleşiyor (bir kural çok teknik).

**Doğrulandı:** 35/35 test (8 yeni). Gerçek veriyle: DFE ürün iddiası (T1055/T1003/T1547) yüklendi → `Tespit 0`, üç teknik de boşluk listesinde, skor %30, kartlar kesikli amber. Sonra T1055'e isimli kural eklendi → kovaya girdi, `Tespit 1`, skor %80. `?v=115`.

### Teknik tanıma artık uyarı, hata değil (2026-07-28)

Kullanıcı gerçek QRadar kural setini (374 kural) prompt'tan geçirip yükleyince **38 satır** `taninmayan teknik ID` hatası verdi — `T1685`, `T1686` (ve `.001`/`.004`/`.005` alt teknikleri). Kontrol: kullanıcının `data/mitre.json`'ında en yüksek teknik numarası **T1681** — yani bu ID'ler gerçek MITRE ID'si değil, eşlemeyi üreten LLM'in hallüsinasyonu. O ana kadarki tasarım bunu **hata** sayıyordu, yani tek satırlık bir hallüsinasyon **374 kuralın tamamını** reddettiriyordu — hiç uygulanamıyordu.

Çözüm: `_plan_coverage_import()`'da hata/uyarı ayrımı netleştirildi.

| | Hata (engelleyici, tüm dosyayı durdurur) | Uyarı (engellemez) |
|---|---|---|
| Kapsam | bozuk şema, eksik `name`/`product`, katalogda olmayan ürün, geçersiz `category`/`coverage_level`, mükerrer `(name,product)` | **tanınmayan teknik ID'si**, boş `techniques: []` |
| Sonuç | `/apply` 400, hiçbir satır yazılmaz | o satırdan geçersiz ID atlanır; kural kalan geçerli tekniklerle veya **tekniksiz** eklenir |

Tekniksiz kalan kural yeni bir kavram değil — elle "tekniksiz kural" eklemekle birebir aynı yol, sonuç Veri Kalitesi ekranında `unmapped_rule` olarak zaten görünüyordu. Sadece içe aktarım bu yola artık **izin veriyor**, önceden tek bir hallüsinasyonda tüm dosyayı reddediyordu.

- `_plan_coverage_import()`: `warnings: list[str]` eklendi, dönen sözlükte `errors`'dan ayrı. `summary.rules_without_technique` — bu import sonrası toplam tekniği (mevcut + eklenen) sıfır kalacak kural sayısı.
- UI: yeni "Tekniksiz kalacak" ve "Uyarı" stat kutucukları (amber), ayrı uyarı kutusu (`.import-warning-box`, kırmızı hata kutusundan görsel olarak farklı), plan tablosunda tekniksiz kalan satırlarda kesikli "teknik yok" rozeti. Uygula butonu artık yalnızca gerçek `errors`'a bakıyor.
- Prompt (`docs/mitre_mapping_prompt.md`) güncellendi: "ID uydurma" talimatı hâlâ geçerli ama artık "reddedilir" değil "atlanır, kural tekniksiz kalır" diyor — LLM'e yanlış bir güvenlik ağı vaat etmiyor.

**Doğrulandı:** 36/36 test (`test_import_treats_unknown_technique_as_warning_not_blocking_error`, `test_import_still_rejects_unknown_product_atomically`), gerçek senaryo (T1685/T1686) tarayıcıda uçtan uca: önizleme `ok:true`, 3 uyarı, 2 kural tekniksiz oluştu, ikisi de Veri Kalitesi'nde `unmapped_rule` olarak çıktı. `?v=116`.

### Veri temizliği (2026-07-27)

Kullanıcı yeni sistemle baştan girmek için mevcut tespitlerin silinmesini istedi. Silmeden önce:

- `backups/soc-20260727-154403.db.gz` — tam DB yedeği
- `exports/rules_backup_20260727.json` — 438 kuralın tamamı, **içe aktarım şemasında** (olduğu gibi geri yüklenebilir)
- `exports/qradar_rules_20260727.txt` / `.md` — 374 QRadar kural adı, prompt'a yapıştırmaya hazır
- `exports/rules_without_technique_20260727.json` — hiç tekniğe bağlı olmayan 5 kural

438 kural + 462 teknik eşlemesi API üzerinden tek tek silindi (audit zincirinde iz var). Kaynak dağılımı: QRadar 374, DFE 57, Other 4, DefIdentity 2, Fortigate Firewall 1. Ürünler, ortamlar, ekipler, mitigation kayıtları ve teknik hedefleri korundu.

## MITRE veri seti v18.1 → v19.1 güncellendi (2026-07-28)

Kullanıcı gerçek QRadar kural setini yükleyip 38 satırda "tanınmayan teknik ID" uyarısı görünce (`T1685`, `T1686`) ilk teşhisim yanlıştı — "LLM hallüsinasyonu" dedim. Kullanıcı MITRE'nin kendi sitesinden T1685'in gerçek olduğunu gösterdi; haklıydı, düzeltildi. `attack.mitre.org`'dan doğrulandı: **T1685 (Disable or Modify Tools) ve T1686 (Disable or Modify System Firewall) gerçek, güncel teknikler** — yeni bir taktik altında: **Defense Impairment (TA0112)**.

**Gerçek kapsam ilk göründüğünden büyüktü.** Bu sadece "2 teknik eksik" değil: MITRE ATT&CK v19'da eski **"Defense Evasion" (TA0005) tamamen ikiye ayrıldı** — aynı TA0005 ID'si **"Stealth"** oldu, yeni **TA0112 "Defense Impairment"** eklendi. Ölçüm: 262 eski Defense Evasion tekniği → 56 Defense Impairment + 212 Stealth olarak yeniden dağıtıldı; 17 eski ID (`T1562` ailesinin tamamı — Impair Defenses — + `T1070.001`/`.002`) revoked/deprecated işaretlendi. Kullanıcının sorunlu 38 kuralının hepsi tam bu alanda (firewall/log/defans aracı devre dışı bırakma) — rastlantı değil, MITRE'nin yeniden sınıflandırdığı alanın tam ortasındaydı.

**Neden veri setimiz eskiydi:** `data/mitre.json` Enterprise ATT&CK **v18.1** (2025-10-24), MITRE'nin resmi STIX deposundan (`mitre-attack/attack-stix-data`) indirilen güncel paket ise **v19.1**. Kurallar tablosu tam o an boş olduğu için (yeni sistemle baştan girmek üzere temizlenmişti) hiçbir mevcut eşleme riske girmeden güncellenebildi — bu işlem için en uygun andı.

**Bulunan ikinci, daha derin kök neden:** `build_technique_config()` yalnızca **bir kez** çalışacak şekilde yazılmıştı (`source='auto' satırı varsa dön`). Yani `data/mitre.json` dosyasını değiştirmek tek başına yetmiyordu — `technique_config` tablosu (import doğrulamasının kaynağı) hiçbir zaman yeni teknikleri görmeyecekti. Bu koruma kaldırıldı; artık her `init_db()` çalıştığında eksik `tech_id` satırlarını ekliyor (`INSERT OR IGNORE`, `tech_id PRIMARY KEY` olduğu için var olan admin override'ları asla ezmiyor). Ayrıca `_known_technique_ids()` artık DB tablosunu değil, canlı `_mitre_catalog()`'u (dosya mtime'ıyla invalidate olan cache, revoked/deprecated'ı otomatik dışlıyor) okuyor — böylece bir sonraki MITRE güncellemesinde aynı sorun bir daha yaşanmaz.

**Kod değişiklikleri:**
- `app.py`: `_TACTIC_LABEL_MAP` ve `_TACTIC_ORDER` içinde `defense-evasion` → `stealth` + `defense-impairment` (MITRE'nin resmi sırasıyla: Privilege Escalation → Stealth → Defense Impairment → Credential Access).
- `static/app.js`: `tacticMap`, iki adet `_TTP_TACTIC_LABELS`/`TACTIC_TR` sözlüğü aynı şekilde güncellendi (4 yer, hepsi grep ile bulundu).
- `build_technique_config()`: tek seferlik koruma kaldırıldı, kalıcı olarak idempotent "eksikleri ekle" mantığına geçti.
- `_known_technique_ids()`: DB tablosu yerine canlı `_mitre_catalog()`.

**Doğrulandı:** `technique_config` 691 → 714 satır (23 yeni teknik), 10 admin override (`T1129`, `T1014`, `T1133`, `T1204.002`, `T1053`, `T1106`, `T1195`, `T1589`, `T1595`, `T1189`) bozulmadan korundu. Harita artık **15 taktik sütunu** MITRE'nin resmi sırasıyla gösteriyor, T1685/T1686 "Defense Impairment" sütununda ve `covered` (yeşil) durumda. Aynı 3 satırlık test dosyası (daha önce 3 uyarı üretmişti) şimdi **0 uyarı, 0 hata** ile uygulanıyor. 36/36 test, browser smoke sıfır konsol hatası, 15 taktik sütunu.

> **Bilinçli olarak yapılmayan:** eski `T1562` ailesi + `T1070.001`/`.002` için `technique_config`'te kalan 17 "artık revoked" `auto` satırı silinmedi (zararsız — canlı katalog zaten bunları dışlıyor, import bunları kabul etmez). Temizlik `docs/ACIK_SORULAR.md`'ye eklendi.

## Harita okunabilirliği, hedef=0, toplu işlemler (2026-07-28)

Kullanıcı canlı ortamda test ederken (375 gerçek QRadar kuralı yüklenmiş durumda) üç ayrı istek geldi.

**1. Ölü ok temizlendi.** Kartların sağ üst köşesinde işe yaramayan bir "▶" vardı — Faz 4c'den önceki tasarımdan kalma saf CSS `::after` dekorasyonu (`.technique-card.has-subtechs::after`), hiçbir click handler'ı yok. Gerçek aç/kapa oku (`.tc-toggle`) sol kenarda zaten çalışıyordu; sağdaki bu ikinci, sahte ok kafa karıştırıyordu. Kaldırıldı. Aynı yerde, Faz 4b'de zaten terk edilmiş `critical-gap` CSS'i de (hiçbir JS bu class'ı hiç eklemiyor) temizlendi.

**2. `rule_threshold = 0` desteği.** "Bazı teknikler için gereken tespit sayısını 0 yapabilmek istiyorum" — kapsam dışı veya tamamen başka bir kontrolle (mitigation, süreç) karşılanan teknikler için. Önceden hem backend (`max(1, ...)`) hem frontend (`|| DEFAULT_RULE_THRESHOLD`) 0'ı reddediyor ya da sessizce varsayılana çeviriyordu (JS'te `0 || 2` → `2`, klasik falsy-sıfır tuzağı — 3 ayrı yerde aynı hata vardı: `techniqueThreshold()`, admin modal select'in "seçili" işaretlemesi, `_ttpRowBg()`). Hepsi `??` ile düzeltildi.

- `coverage_score`: hedef ≤ 0 ise doğrudan `1.0` (bölen sıfır olmasın diye ayrı dal) — hem `app.py` hem `static/app.js`.
- Admin modalindeki `<select>`e `0 (gerekli değil)` seçeneği eklendi.
- Harita hücresinde `X/0` yerine açık bir **"gerekli değil"** etiketi (italik, soluk) — `0/0` görsel olarak "hata" gibi okunurdu.
- **Bilinçli tasarım:** hedef 0 skoru %100 yapar (kart yeşil) ama "Tespit" kovasına SOKMAZ — kova hâlâ adı olan bir tespit arıyor (Faz 5'teki `origin` ayrımıyla aynı ilke: skor ve kova farklı sorulara cevap verir). Yani hedefi düşürmek "görebiliyoruz" demek değil, "aramıyoruz" demek.

**3. Tespitler panelinde toplu kapsam değiştirme + toplu silme.** Mevcut toplu-teknik-ekleme toolbar'ı (Faz 3) genişletildi — aynı desen: tekli `PATCH /api/rules/<id>/coverage` ve `DELETE /api/rules/<id>` endpoint'leri seçili ID listesi üzerinde sırayla çağrılıyor, yeni bir bulk endpoint gerekmedi. Toplu silme **geri alınamaz** olduğu için `window.confirm()` ile sayı belirten bir onay şart koşuluyor.

**Doğrulandı:** 38/38 test (1 yeni: `test_rule_threshold_zero_means_score_is_always_full`, negatif değerin 0'a kırpıldığını da kapsıyor), browser smoke sıfır konsol hatası. Gerçek 375 kurallık veride uçtan uca: 3 geçici test kuralı oluşturuldu → toplu seçildi → toplu "Düşük" yapıldı (3/3 başarılı) → onay diyaloğuyla toplu silindi (mesaj: *"3 tespiti kalıcı olarak silmek istediğinize emin misiniz?"*) → gerçek 375 kural dokunulmadan kaldı. `?v=118/119`.

## İçe aktarımda tekrar eden satırlar artık hatayı değil uyarıyı tetikliyor (2026-07-28)

Kullanıcı 375 kurallık gerçek dosyasını yüklerken 13 hata aldı: `"Defender for Endpoint EDR – <Taktik>"` adlı satırların hepsi dosyada **ikişer kez** geçiyordu (ürün başına taktik bazlı üretilen büyük bir listede bir LLM'in bloğu tekrarlaması — bilinen bir hata modu). Önceki tasarım aynı `(name, product)` çiftinin ikinci kez görünmesini **hata** sayıyordu, yani 13 tekrar tüm dosyayı (300+ geçerli satır dahil) reddettiriyor, Uygula pasif kalıyordu.

Bu, bir önceki oturumda "tanınmayan teknik ID" için yaptığımız hata/uyarı ayrımıyla aynı kalıba giren bir sorun: **yapısal olmayan, iyileştirilebilir bir uyumsuzluk hata sayılmamalı.** Çözüm: `_plan_coverage_import()` artık aynı `(name, product)` çiftini gördüğünde hata vermek yerine **tekniklerini birleştiriyor** (union) — CSV toplu içe aktarımın zaten yaptığı şeyin aynısı (bkz. Faz 5 `rules_bulk()`), JSON yolu da aynı davranışa getirildi. İlk satırın `coverage_level`/`kind`/`rationale`'ı kullanılıyor, birleşme bir uyarı olarak raporlanıyor ("dosyada tekrar ediyor — teknikleri ilk satırla birleştirildi").

**Doğrulandı:** 39/39 test (1 yeni: `test_import_merges_duplicate_name_product_pairs_instead_of_blocking`), gerçek senaryoyla (aynı "Defender for Endpoint EDR – Collection" adı iki farklı teknikle) uçtan uca — önizleme artık `ok:true`, 1 uyarı, teknikler birleşti. `docs/mitre_mapping_prompt.md`'deki hata/uyarı tablosu güncellendi.

## Tespit yönetimi genişletildi + PDF Export → zengin `/report` (2026-07-28)

Kullanıcı üç ayrı istek getirdi: (1) toplu seçme/kapsam değiştirme/silme "çalışmıyor", (2) tespitlerin adını ve ürününü sonradan değiştirebilme, (3) PDF Export'un çok daha ayrıntılı, MITRE Navigator tarzı, çok sayfalı olması.

### 1. Toplu işlem "hatası" — kod değil, tarayıcı önbelleği

Gerçek tıklamalarla (checkbox, "Görünenleri seç", "Kapsamı değiştir") uçtan uca test edildi — hepsi doğru çalıştı. Toplu silme, `window.confirm()`'ün Claude Browser test ortamında bilinçli olarak devre dışı bırakılması yüzünden test edilemedi (konsolda açıkça yazıyor: *"native JavaScript dialogs are disabled in this browser"*) ama aynı kod yolu bu oturumda daha önce `confirm() → true` mock'lanarak zaten doğrulanmıştı. Asıl bulgu: **aynı test sekmesi, `app.js`'e yapılan bir sonraki değişiklikten sonra tam sayfa yenilemesi (F5) yapılmadan test edilince yeni özellik (`Düzenle` butonu) DOM'da hiç görünmüyordu** — tarayıcı sekmesi önceki `?v=` yüklemesinde donmuş kalıyor. Bu, kullanıcının "çalışmıyor" demesinin en olası açıklaması: `?v=` art arda birkaç kez bump edildi (116→120), sekme muhtemelen bir ara sürümde donmuş kaldı. **Çözüm kullanıcıya iletildi: sert yenileme (Ctrl+Shift+R) sonrası tekrar denemesi istendi.**

### 2. Tespit adı/ürünü sonradan değiştirme

Yeni `PUT /api/rules/<id>` — `name` ve/veya `source` günceller. Kullanıcı: *"yönetim alanında her şeyi ekle, elimiz kolumuz bağlanmasın."*

- Ürün değişince kural otomatik yeni ürünün altına taşınır (gruplama zaten `r.source`'a göre) — ayrı bir "taşıma" mantığı gerekmedi.
- Katalogda olmayan ürüne taşınamaz (400), aynı (isim, ürün) çakışırsa 409 (`idx_rules_name_source` UNIQUE).
- UI: `Tespitler` listesinde her satıra **Düzenle** butonu — satırı isim input'u + ürün seçiciye çevirir (`rulesEditingId` state), Kaydet/İptal.
- Doğrulandı: 40/40 test (1 yeni), gerçek tıklamalarla uçtan uca (isim değişti, ürün taşındı, düzenleme modu kapandı).

### 3. PDF Export → zengin, çok sayfalı `/report`

Eski "PDF Export" DOM kazıyordu (`exportMatrixPdf()`, `templates/index.html`) — yalnızca ekrandaki filtrelenmiş görünümü tek sayfalık, alt tekniksiz, skorsuz bir tabloya çeviriyordu. **`static/app.js`'teki `exportPdf()` fonksiyonu ise hiç çağrılmayan ölü koddu** (grep ile doğrulandı) — silinirken `wireExport()` içindeki `btnPdf.addEventListener('click', exportPdf)` satırının artık var olmayan bir fonksiyona referans verip sayfa yüklenirken `ReferenceError` atacağı fark edildi, o satır da kaldırıldı.

Zaten var olan `/report` sayfası (`templates/report.html`) çok daha zengindi ama kullanılmıyordu ve dili eskiydi ("Kritik Boşluklar (Önem ≥ 4)" — Faz 4b'de kaldırılan önem kavramına atıf). **PDF Export artık `/report`'u yeni sekmede açıyor**, matriste seçili ortamı `?environment_id=` ile taşıyarak.

`/report` şu şekilde genişletildi:
- `_compute_gap_analysis()` artık tam teknik listesini (`techniques` anahtarı, parent+alt) ve her teknik için ürün **isimlerini** (yalnızca sayısını değil) döndürüyor — `/api/gap-analysis` için geriye dönük uyumlu, sadece ek alan.
- **Kapsama Haritası** — MITRE Navigator tarzı, taktik başına sütun, alt teknikler ana tekniğin altında girintili ve renkli (her zaman görünür, print'te interaktiflik zaten yok). 15 taktik, sayfa başına 5 taktik olacak şekilde otomatik bölünüyor (**"birkaç sayfalık pdf" isteği** — 216 teknikle 3 sayfa çıktı). Renkler koyu temanın aynı 5 duraklı gradyanından (`_scoreRgb`) türetildi ama print/kağıt için açık, siyah metinle okunabilir tonlara çevrildi (`_score_to_report_color()`).
- **Tam Teknik Listesi (Ek)** — taktik başına bölüm, ID/Ad/Tespit/Skor/Mitigation/Ürünler sütunlu tam tablo (216 satır, fan-out yok — çoklu taktikli teknik tek satırda).
- **Ortam seçici** — `?environment_id=` query param, `<select onchange=submit>`; geçersiz id 500 yerine sessizce birleşik moda dönüyor.
- Yönetici özeti kartları güncellendi (Ortalama Skor kartı eklendi, eski "Kritik Boşluk" dili kaldırıldı), "Tespitsiz Teknikler" bölümü artık `group_count` sıralamasını ve 50 sınırını açıkça anlatıyor.
- `rule_threshold = 0` ("gerekli değil") hem matriste hem tam listede `0/0` yerine düz metinle gösteriliyor — canlı haritadaki aynı okunabilirlik düzeltmesi.
- Tüm sayfa `@page { size: A4 landscape }` — kullanıcının "export geniş olabilir" isteğiyle.

**Doğrulandı:** 43/43 test (3 yeni: matris+ek render, ortam scoping, `techniques[].sources`), gerçek 375 kurallık veriyle ekran görüntüsü — 3 matris sayfası, 254 hücre, 618 alt teknik hücresi, sıfır konsol hatası. Print-media emülasyonuyla da doğrulandı (aksiyon çubuğu gizleniyor, "gerekli değil" doğru render). `?v=120` (app.js).

## Rapor matrisi yoğunlaştırıldı — gerçek Navigator ızgarası (2026-07-28)

Kullanıcı geri bildirimi: *"pdf raporunda taktiklerin alanları çok büyük olmuş daha kompakt olsun, matrix çok bölmüşsün, mitre navigator gibi düşün daha zekice bir görselleştirme yapabilirsin."* Bir önceki maddedeki ilk `/report` sürümü, 15 taktiği `_REPORT_MATRIX_TACTICS_PER_PAGE = 5` ile zorla 3 sayfaya bölüyordu ve her hücre 3 satır (ID+M rozeti, ad 2 satır clamp, skor satırı) kaplıyordu — bu hem yapay sayfalama hem de gereğinden büyük hücreler demekti.

Kaldırılan yapay sayfalama, gerçek Navigator davranışıyla değiştirildi:
- `app.py`: `_REPORT_MATRIX_TACTICS_PER_PAGE` sabiti ve `matrix_pages` chunking'i tamamen kaldırıldı. `report_page()` artık tek düz liste üretiyor: `matrix_tactics` (15 taktik, hiçbiri sayfaya bölünmüyor).
- `report.html`: `.rpt-matrix-grid` (CSS Grid, sayfa başına 5 sütun) yerine `.rpt-matrix-wrap` (flexbox, `flex-wrap`) — tüm 15 taktik sütunu tek akışta yan yana, taşan uzun sütunlar (ör. Stealth, 148 teknik/alt teknik) yazdırma sırasında doğal olarak bir sonraki sayfaya akıyor; yapay sayfa grubu yok.
- Hücre içeriği tek satıra indirildi: `ID + ad` tek satırda `text-overflow:ellipsis` ile kesiliyor, skor satırı tamamen kaldırıldı (rengin kendisi + `title` tooltip'i + Tam Teknik Listesi ekindeki kesin sayılar yeterli). Mitigation rozeti artık hücrenin sağ üst köşesinde küçük mor bayrak (`position:absolute`), metni kesmiyor.
- Alt teknikler artık ayrı bir sarmalayıcı `div` içinde değil, doğrudan üst tekniğin altına sıralanan kardeş satırlar (`.rpt-subcell`) — ID kısaltıldı (`T1589.001` yerine `.001`), kendi rengi ve kendi `page-break-inside:avoid`'ı var (bir tekniğin tüm alt teknikleri artık tek blok halinde sayfa atlamaya zorlanmıyor, gereksiz boşluk bırakmıyor).
- Sütun genişliği (64px + 2px gap + 1px kenarlık) bilinçli olarak A4 yatay sayfanın kullanılabilir genişliğine (12mm kenar boşluklu ~1031px) göre ayarlandı — 15 taktik tam olarak tek satıra sığıyor (doğrulandı: 1103px pencere genişliğinde, ki bu ekran `padding`'i A4 kenar boşluğuna eşdeğer).
- `.rpt-section { page-break-inside: avoid }` genel kuralı matris için `.rpt-matrix-section { page-break-inside: auto }` ile eziliyor (`.rpt-fulllist-section` ile aynı desen) — önceki sürümde bu genel kural, kısmen dolu bir sayfayı bomboş bırakıp matrisin tamamını bir sonraki sayfaya iten asıl nedenlerden biriydi.

**Doğrulandı:** 43/43 test değişmeden geçti (hiçbir test `matrix_pages`/`rpt-matrix-page` yapısına bağımlı değildi — grep ile önceden doğrulandı). Gerçek 222 ana teknik/475 alt teknikli veriyle: 15 taktik sütunu tek satırda (DOM ölçümüyle doğrulandı, ekran görüntüsü bu oturumda alınamadı — Browser paneli görüntülenmiyordu), sıfır konsol hatası, tooltip'ler (`title`) tam ID/ad/skor bilgisini koruyor.

## "Ortalama Skor" formülü — eşik-ağırlıklı + alt teknik + ürün iddiası indirimi (2026-07-29)

Kullanıcının gözlemi: canlı haritada "Ort. Skor" (~%56-60) ile "Tespit" (~%30-41) arasında kafa karıştırıcı bir makas vardı — ortalama skor, tespit oranından çok daha yüksek görünüyordu. Kök neden araştırıldı (gerçek veriyle): 156 "Kapsamsız" teknikten **95'i** aslında `origin='product_claim'` (adı olan tespit değil, toplu ürün iddiası) üzerinden **skor** alıyordu — bazıları (ör. T1133 Valid Accounts benzeri External Remote Services) tam %100 skor gösterirken aynı anda "Kapsamsız" listesindeydi. Eşik-ağırlıklandırma tek başına simüle edildiğinde makası yalnızca ~2 puan kapatıyordu (222 tekniğin 197'si zaten aynı eşiğe=2 sahip); asıl kaynak ürün iddiası kredisiydi.

Kullanıcıyla birlikte 4 karar netleştirildi (AskUserQuestion), formül şu şekilde değişti:

1. **Kapsam:** Yalnızca özet "Ortalama Skor" (genel kart + taktik bazlı) değişiyor — matristeki tek tek teknik hücrelerinin rengi hâlâ tamamen kendi tespit/eşik oranını gösteriyor (bu netlik korunuyor).
2. **Alt teknikler dahil, düşük ağırlıkla:** Ortalama artık ana+alt teknikleri birlikte kapsıyor ama her tekniğin katkısı kendi `rule_threshold`'uyla orantılı; alt teknikler ek olarak **0.3×** çarpanla girer (`SUBTECHNIQUE_AVG_WEIGHT`). "Gerekli değil" (eşik=0) işaretli teknikler otomatik ağırlıksız kalır (0 × her şey = 0) — önceki düz ortalamada bunlar tam ağırlıkla %100 sayılıyordu.
3. **Ürün iddiası (`product_claim`) hücre skorunda indirimli:** Artık tam (1×) değil **0.75×** ağırlıkla sayılıyor (`PRODUCT_CLAIM_SCORE_WEIGHT`) — adı olan gerçek tespiti olmayan bir teknik artık yalnızca toplu iddiayla asla %100 gösteremez. Bu, hem hücre rengini hem "Ortalama Skor"u etkiler; "Tespit" kovasının sert-kanıt tanımına (bkz. yukarıdaki "Kapsanan Tanımı" bölümü) hiç dokunmadı.
4. **Mitigation skora hâlâ girmiyor** — kullanıcı bilinçli olarak dışarıda bıraktı; `docs/ACIK_SORULAR.md` madde 1'deki bilinen sorun (`M1018` gibi tek bir mitigation kaydı MITRE'nin geniş eşlemesi yüzünden 120 tekniği birden etkiliyor) hâlâ çözülmediği için skora eklemek suni şişmeyi büyütürdü.

**Kod:** `app.py` — `PRODUCT_CLAIM_SCORE_WEIGHT`/`SUBTECHNIQUE_AVG_WEIGHT` sabitleri (`DEFAULT_RULE_THRESHOLD` yanında), `_compute_gap_analysis()`'te `effective_rule_count` hesaplamasına `origin_weight` çarpanı, `average_score`/`by_tactic[].average_score_pct` artık `_avg_weight()` closure'ıyla eşik-ağırlıklı (bucket sayıları — `total`/`covered`/`mature` — bilinçli olarak DOKUNULMADI, Faz 3'ün "Kapsanan Tanımı" kararı geçerliliğini koruyor). `static/app.js` — aynı iki sabit, `ruleCoverageWeight()`'e origin çarpanı, `visibleExportRows` satırlarına `rule_threshold` alanı eklendi, `updateMatrixStats()`'teki `avgScore` aynı ağırlıklı formülle yeniden yazıldı (sunucuyla birebir aynı sonucu üretmesi gerekiyor — doğrulandı). `?v=121` (app.js).

**Test güncellemeleri (kullanıcı onayıyla, formül kasıtlı değişti):** `test_product_claim_scores_but_does_not_fill_detection_bucket` (0.3→0.225: partial×0.75 indirimi), `test_score_is_detection_only_and_uses_per_technique_threshold` (50.0→33.3: eşik=1 olan teknik artık ortalamayı daha az etkiliyor — tam da istenen davranış). 43/43 test geçiyor.

**Doğrulandı (gerçek veri):** Sunucu ve bağımsız istemci-taraf yeniden hesaplaması birebir aynı sonucu verdi: **%56.0 → %45.6**. `mature_techniques` (skoru tam %100 olan teknik sayısı) 72→54'e düştü — beklenen, çünkü artık salt ürün-iddiasıyla %100'e ulaşan teknikler bunu kaybetti.

**Yeni bulgu (ayrı, henüz çözülmedi):** Doğrulama sırasında canlı Matris panelinin kendi "Tespit" sayısının (90/222, istemci tarafı `updateMatrixStats()`) sunucunun `/api/gap-analysis` sayısıyla (66/222) **uyuşmadığı** ortaya çıktı — bugünkü skor değişikliğinden tamamen bağımsız, önceden var olan bir tutarsızlık. Kök neden: istemci tarafı `parentRules = enriched.filter(r => r.parentId == tech.id)` bir **alt tekniğe** yazılmış kuralı (`tid="T1552.001"`, `parentId="T1552"`) ana tekniğin (`T1552`) tespit sayımına **dahil ediyor**; sunucudaki `_compute_gap_analysis()` ise `rule_stats_by_tech`'i `rt.tech_id`'ye (kuralın yazıldığı TAM ID) göre gruplandırıyor ve alt tekniğe yazılan bir kuralı üst tekniğin sayımına **hiç eklemiyor**. CLAUDE.md'deki "alt tekniğe yazılan kural zaten ana tekniğe sayılır" notu yalnızca istemci tarafı için doğru. Örnek: T1552 (Unsecured Credentials) — QRadar'da 9 adet kural var ama hepsi `.001`/`.002`/`.004` gibi alt tekniklere yazılmış, T1552'nin kendisine yazılmış hiçbir kural yok; istemci onu "tespitli" sayıyor, sunucu saymıyor. Bu, kullanıcının orijinal "karmaşa" şikayetinin bir parçası olabilir ama bugünkü isteğin (skor formülü) kapsamı dışında — ayrı bir karar gerektiriyor (fold-up her iki tarafta da aynı mı olmalı, ve öyleyse hangi yönde). `docs/ACIK_SORULAR.md`'ye eklenmesi öneriliyor.

## Alt tekniklerin varsayılan tespit hedefi 1'e çekildi (2026-07-29)

Kullanıcı isteği: *"alt tekniklerde beklenen tespiti 1'e düşür hepsinde."* Yeni
`ensure_subtechnique_default_threshold(db)` migration'ı (`app.py`,
`build_technique_config()`'ten hemen sonra, her `init_db()`'de çalışır —
tek seferlik değil): `UPDATE technique_config SET rule_threshold=1 WHERE
source='auto' AND tech_id LIKE '%.%'`. Ana teknikler (`DEFAULT_RULE_THRESHOLD=2`)
dokunulmadan kaldı. Admin override'lar (`source='admin'`) korunur — MITRE
yeni bir alt teknik ekledikçe `build_technique_config()` onu önce eşik=2 ile
ekler, bu migration hemen ardından 1'e çeker, böylece gelecekte de tutarlı kalır.

**Doğrulandı (gerçek veritabanı):** 489 alt teknikten 488'i artık eşik=1;
kalan 1 tanesi (**T1204.002** Malicious Copy and Paste) daha önce admin
tarafından elle 2'ye ayarlanmış — kasıtlı olarak dokunulmadı (istenirse
Ayarlar'dan tek satırlık bir düzeltmeyle değiştirilebilir). Bu değişiklikten
sonra "Ortalama Skor" %45.6 → **%52.6**'ya çıktı (alt tekniklerin kendi skoru
daha kolay dolsa da, ortalamadaki ağırlıkları da düştü — `1×0.3=0.3` yerine
eskiden `2×0.3=0.6`'ydı; net etki yukarı yönlü çıktı). Yeni test:
`test_subtechniques_default_to_threshold_one_admin_override_preserved`.

## İstemci-sunucu "Tespit" fold-up tutarsızlığı çözüldü (2026-07-29)

Bir önceki maddede bulunan `docs/ACIK_SORULAR.md` madde 7 (istemci 90/222,
sunucu 66/222) kullanıcıyla konuşuldu. Kullanıcının kararı: *"alt teknik üst
tekniği kapsamasın, alt teknik kendini kapsasın"* — yani sunucunun zaten
yaptığı (tam eşleşme, fold-up yok) davranış doğru; **istemci** ona eşitlendi.

`static/app.js` `renderMatrix()`: `parentRules` (fold-up'lı, `r.parentId ==
tech.id` — üst teknik + tüm alt tekniklerine yazılan kurallar) artık yalnızca
**modal içeriği** için kullanılıyor (Direkt + alt teknik başına gruplanmış
görünüm zaten vardı, korundu — böylece bir teknik "tespitsiz" görünse bile
modalda alt tekniklerindeki kapsama görülebiliyor). Yeni `parentOwnRules`
(`r.tid == tech.id`, tam eşleşme) artık "Tespit" durumunu, hücre rengini,
kritik-boşluk işaretini, skoru ve `visibleExportRows`'u besliyor —
sunucudaki `_compute_gap_analysis()` ile birebir aynı tanım. Aynı düzeltme
`updateTechniqueCard()`'a da uygulandı (mitigation/kural ekleme sonrası tek
kart yenilemesi de artık tutarlı).

**Doğrulandı (gerçek veri, canlı sunucu):** Matris paneli ile
`/api/gap-analysis` artık **birebir aynı** 6 sayıyı gösteriyor: Teknik 222,
Tespit 66/222 (%29.7~30), Kapsamsız 156, Mitigation 163, Ort. Skor
%52.6~53, Alt Teknik 72/475. Örnek doğrulama: T1552 (Unsecured Credentials)
— hiç doğrudan kuralı yok, 9 kuralın hepsi alt tekniklere yazılmış — artık
kart `covered:false` gösteriyor (öncesinde fold-up yüzünden `true`'ydu),
modal tıklanınca hâlâ "Doğrudan Eşleşmeler" (boş) + 7 alt teknik grubu
(T1552.001, .002, .003, .004, .006, .007, .008) doğru render ediliyor —
sayım düzeldi, görünürlük kaybolmadı. Backend değişmedi (zaten doğruydu),
44/44 test aynen geçiyor. `?v=122` (app.js).

## Bilgilendirme (Wiki) — skorlama dokümantasyonu güncellendi (2026-07-29)

`templates/docs.html` (uygulama içi `/docs` sayfası) büyük ölçüde Faz 4b/4c/4d
öncesinden kalmıştı — "önem seviyesi" (1-5, kaldırıldı), eski 3 bileşenli
skor formülü (0.50 tespit + 0.30 mitigation + 0.20 çeşitlilik, kaldırıldı) ve
3 bölgeli eski renk geçişini (0/0.40/1.0) hâlâ anlatıyordu; hiçbiri bugünkü
üç değişikliği (eşik-ağırlıklı ortalama, alt teknik dahil etme, product_claim
indirimi, fold-up düzeltmesi) yansıtmıyordu. Kullanıcı isteği üzerine tüm
skorlama/kapsama ile ilgili sayfalar gerçek koddan doğrulanarak yeniden yazıldı:

- **Puanlama** — tamamen yeniden yazıldı: tek terimli güncel formül (kapsama
  seviyesi × ortam izleme × kaynak ağırlığı [named 1.0 / product_claim 0.75]),
  hedef varsayılanları (ana 2 / alt 1), yeni "Tespit mi, Ortalama Skor mü?"
  bölümü (bu oturumun asıl kafa karışıklığını doğrudan açıklıyor), yeni "Alt
  Teknikler Puanlamaya Nasıl Girer?" bölümü (fold-up yok, 0.3× ağırlık),
  gerçek sayılarla 4 örnek hesaplama.
- **Renk Kodu** — 5 duraklı gradyan (0/0.30/0.50/0.70/1.00), gerçek RGB
  değerleri (`_SCORE_STOPS`'tan alındı), %20/%13 opaklık farkı (ana/alt
  teknik), düzeltilmiş hover tooltip örneği (mitigation artık "skora girmez"
  etiketiyle, tehdit grubu ve kapsama satırları eklendi).
- **Mitigation** — "Skor Etkisi" (× 0.30) bölümü kaldırıldı, yerine "Neden
  Skora Girmiyor?" — MITRE'nin geniş eşlemesinin riskini (M1018 → 120+
  teknik) açıkça anlatıyor. "Nasıl Kayıt Eklenir?" adımlarına eksik olan
  Ürün alanı eklendi (Faz 4d'de gelmiş ama hiç dokümante edilmemişti).
- **Ekipler** (eski "Önem & Ekipler") — "Önem Seviyesi" bölümü tamamen
  kaldırıldı, sayfa/nav adı sadeleşti. Ne olduğu ve neden kaldırıldığı tek
  cümlelik bir notla açıklandı.
- **Matris** — demo mockup'taki hayali "kritik boşluk kırmızı kenarlık +
  ünlem" kartı ve "✓2" mitigation rozeti kaldırıldı (gerçek uygulamada hiç
  yok); gerçek mor "M" kalkan rozetiyle değiştirildi. Alt teknik notu
  güçlendirildi: bir alt tekniğin tespiti üst tekniği kapsamaz, ama modalda
  görünürlüğü kaybolmaz.
- **Genel Bakış / Hızlı Başlangıç / TTP Listesi** — kalan "önem seviyesi"
  referansları (kartlar, adım 6, sütun listesi) düzeltildi.
- Ayrıca: `docs.html`'in kendi `styles.css?v=106` sabitlemesi `v=120`'ye
  senkronlandı (index.html'inkiyle aynı olmalıydı, hiç bump edilmemişti).

**Bulunan ve düzeltilen bir kendi hatam:** Mitigation sayfasındaki yeni
bölümde bir `<div class="wiki-warning">` yanlışlıkla `</p>` ile kapatılmış
— tarayıcı bunu telafi ederken `w-import`'tan `w-qradar-connector`'a kadar
**sonraki 7 wiki sayfasının tamamını** `w-mitigation`'ın içine gömdü (DOM
kontrolüyle yakalandı: `el.parentElement.id` hepsinde `wiki-content` yerine
`w-mitigation` çıktı). `</div>` ile düzeltildi, dosya geneli div sayısı
374/374 dengeye geldi, 13 sayfa da tekrar `wiki-content`'in doğrudan çocuğu.

Kod değişmedi (yalnızca `templates/docs.html`), 44/44 test aynen geçiyor.

## Üst teknik skoru alt tekniklerinden "rollup" ile besleniyor (2026-07-29)

Kullanıcının gözlemi (aynı günün fold-up düzeltmesinin doğal sonucu): alt
teknikleri zengin kapsanmış bir üst teknik, kendisine doğrudan yazılmış
kural olmadığı için kart üzerinde tamamen "boş" görünüyordu — "alt
teknikleri dolu olan bir üst teknik nasıl boş olabilir, saçma" haklı tepkisi.

Kullanıcı bir rollup önerisi getirdi, 3 noktada birlikte netleştirdik
(AskUserQuestion):
1. **Telafi yok** — bir alt tekniğin fazla tespiti başka bir kardeşin
   eksiğini örtmez; her alt teknik kendi hedefinde tavanlanır, sonra toplanır
   (muhafazakâr seçim — aksi halde tek bir aşırı-kapsanmış alt teknik,
   tamamen boş 4-5 kardeşi gizleyebilirdi).
2. **Üst tekniğin kendi payı da ekleniyor** — kendi doğrudan kuralı varsa
   toplam kaybolmuyor.
3. **"Tespit" kovası da aileye genişliyor** — üst teknik, kendi doğrudan
   kuralı VARSA ya da en az bir alt tekniği zaten tespitliyse tespitli
   sayılır. Bu, sabah düzelttiğimiz fold-up prensibini bozmuyor (kanıt hâlâ
   sert — sadece aileden herhangi bir yerden gelebiliyor).

**Formül** (alt tekniği olan bir üst teknik için):
```
hedef  = kendi_hedef + Σ(alt.hedef)                     [alt.hedef=0 olan hariç]
etkin  = kendi_etkin + Σ(min(alt.etkin, alt.hedef))      [alt.hedef=0 olan hariç]
skor   = min(etkin / hedef, 1.0)
kapsandı = kendi_isimli_kural_var MI YA DA herhangi_bir_alt_teknik_kapsandı_MI
```
Alt tekniği olmayan teknikler etkilenmez (toplam sıfır alt teknikle "kendi"
değerine indirgenir, ayrı bir dal gerekmedi).

**Kod:** `app.py` `_compute_gap_analysis()` — `parents`/`subs` ayrımından
hemen sonra yeni bir döngü, her `p` için `children_by_parent` üzerinden
rollup uygulayıp `effective_rule_count`/`rule_threshold`/`coverage_score`/
`covered`/`mature`'ı YERİNDE değiştiriyor (aynı dict `all_techs` içinde de
paylaşıldığı için "Ortalama Skor" ağırlıklı ortalaması da otomatik güncel
değerleri kullanıyor — ayrı bir değişiklik gerekmedi).

`static/app.js` — yeni `familyRollup(techId, ownRules, weightMap,
enrichedRules)` paylaşılan yardımcı fonksiyonu (sunucuyla birebir aynı
formül). `computeScore()`/`applyTechniqueVisuals()`/`fillTechniqueCell()`
artık opsiyonel `thresholdOverride` (ve `applyTechniqueVisuals` için
`coveredOverride`) parametresi alıyor — geriye dönük uyumlu (varsayılan
`null`, verilmezse eski davranış). `renderMatrix()`'teki üst teknik bloğu ve
`updateTechniqueCard()` (tek kart yenileme — mitigation/kural ekleme sonrası)
artık `familyRollup()` sonucunu kullanıyor. `updateMatrixStats()`'teki
"Tespit" kovası sayımı `named_rule_count>0` yerine yeni `covered` alanını
okuyor (`visibleExportRows`'a eklendi).

**Doğrulandı (gerçek veri, canlı sunucu, T1552 örneği — 8 alt teknik, 3'ü
zengin kapsanmış, 5'i zayıf/sıfır):** Sunucu ve istemci **birebir aynı**
sonucu üretti: hedef=10, etkin=6.9, skor=%69, kapsandı=true (öncesinde
kart tamamen "kapsanmamış" görünüyordu). Genel istatistikler de iki tarafta
birebir eşleşti: Tespit 90/222 (%41), Kapsamsız 132, Ortalama Skor %61.
Yeni test: `test_parent_score_rolls_up_from_subtechniques_with_per_sub_cap`
(tavanlama + kova genişlemesini ayrı ayrı doğruluyor). 45/45 test geçiyor.
`?v=123` (app.js).

**Bulunan ama düzeltilmeyen ayrı bir tutarsızlık:** TTP Listesi paneli
(`ttp_list()` / `/api/ttp-list`, `renderTtpList()`) `_compute_gap_analysis()`
ile **hiç paylaşılmayan, tamamen ayrı** bir MITRE-parse + kural-sayma
implementasyonu kullanıyor — bugünkü rollup (ve daha önceki fold-up
düzeltmesi) oraya hiç uygulanmadı. Yani T1552 gibi bir teknik artık Matriste
ve Boşluklar/`/report`'ta tutarlı görünürken, TTP Listesi'nde hâlâ eski
(muhtemelen fold-up'sız, rollup'suz) davranışı gösterebilir. Kapsamı bugünkü
istekten (Matris renklendirmesi) ayrı ve daha büyük bir refactor — üçüncü,
bağımsız bir kod yolunu `_compute_gap_analysis()`'e taşımak gerekir.
`docs/ACIK_SORULAR.md`'ye eklenmesi öneriliyor.

## Üst tekniğin kendi hedefi de 0'a çekildi — rollup tamamen alt tekniklere devredildi (2026-07-29)

Rollup şu formülü kullanıyordu: `hedef = kendi_hedef (varsayılan 2) +
Σ(alt.hedef)`. Kullanıcının gözlemi: kimse pratikte ana teknik ID'sinin
kendisine doğrudan kural yazmıyor, yani "kendi 2"si neredeyse hiç dolmayan
sabit bir tavan gibi davranıp zaten iyi kapsanmış bir aileyi bile %100'e
ulaşmaktan alıkoyuyordu — T1552 örneği tam olarak buydu (%69, 8 alt
tekniğin çoğu dolu olmasına rağmen). Kullanıcı kararı: *"ana teknikler
ayrıca tespit istemesin, alt tekniklerden faydalansın."*

Yeni `ensure_parent_with_subtechniques_threshold_zero(db)` migration'ı
(`app.py`, `ensure_subtechnique_default_threshold()`'ten hemen sonra, her
`init_db()`'de çalışır): alt tekniği OLAN bir üst tekniğin kendi hedefini
0'a çeker (`source='auto'` satırlar, admin override'lar dokunulmaz). Rollup
kodunun kendisi HİÇ değişmedi — zaten `own_threshold + Σsub` formülü 0'ı
doğru şekilde "hiç katkı yok" olarak işliyordu, yalnızca varsayılan veriyi
değiştirmek yeterliydi. `static/app.js`'e de dokunmadı (istemci
`techniqueThreshold()` ile `/api/technique-config`'ten okuyor, DB'deki
değer 0 olunca otomatik doğru davranıyor).

**Doğrulandı (gerçek veritabanı):** 102 alt tekniği olan üst teknikten
77'si (`source='auto'`) artık hedef=0; 25'i (`source='admin'`, önceden elle
ayarlanmış) dokunulmadan kaldı. T1552'nin kendi hedefi 2→0, rollup hedefi
10→8'e düştü — aynı kapsamayla skoru artık %69 değil ~%99. Yeni test:
`test_parent_with_subtechniques_own_threshold_defaults_to_zero` (hem
varsayılan hem admin-override koruması). 46/46 test geçiyor.

## Ürün filtresi: görünürlük kapısından kapsama merceğine (2026-07-29)

Kullanıcının gözlemi: matriste bir ürüne (örn. QRadar) tıklamak, o ürünün
kapsamadığı teknikleri tamamen **gizliyordu** — matris küçülüyordu.
İstenen: "QRadar'a basınca QRadar'ın kapsadıklarını göreyim ama
kapsamadıkları kapanmasın, o ürünün haritası gibi olsun."

**Kök neden:** `matchesProduct(rules)` iki yerde (`renderMatrix()`'in
üst/alt teknik hide-kararında) bir görünürlük kapısı olarak kullanılıyordu
— eşleşmeyen teknik kartı DOM'dan tamamen çıkarılıyordu.

**Çözüm:** Ürün filtresi artık ortam (environment) filtresiyle **aynı
mekanizmayı** paylaşıyor — `rulesInScope(rules, weightMap)` şimdi ortam
ağırlığının yanı sıra seçili ürün merceğini de uyguluyor (seçili ürüne ait
olmayan kurallar buradan elenir). Bu, matris içindeki HER çağrı noktasına
(parentRules, parentOwnRules, familyRollup, updateTechniqueCard,
updateSubtechCard, tooltip) otomatik yayılıyor — tek bir yerde değişti,
her yerde tutarlı. `renderMatrix()`'teki hide-kararı artık yalnızca arama
metnine bakıyor; `matchesProduct()` fonksiyonu tamamen kaldırıldı (ölü kod).

**Ek düzeltme — tıklama etkileşimi:** Eski legend tıklaması çoklu-seçim
"dışla" modeliydi (Tümü'nden başlayıp tıklanan ürünü ÇIKARIYORDU — tam
tersi bir davranış). Artık ortam seçiciyle aynı desen: bir ürüne tıklamak
YALNIZCA onu izole ediyor (`filterProducts = new Set([p.name])`), aynı
ürüne tekrar tıklamak "Tümü"ne dönüyor, başka bir ürüne tıklamak
izolasyonu ona kaydırıyor.

**Doğrulandı (gerçek veri, canlı sunucu):** Kart sayısı ürün filtresi
her durumda **254'te sabit** (hiçbir kart kapanmıyor). QRadar izole
edilince: Tespit 90/222→79/222, Ort. Skor %61→%21 — tüm panel (hücre
rengi + üst istatistik çubuğu) "QRadar'ın kendi haritası"na dönüşüyor.
İkinci kez tıklayınca "Tümü"ne dönüyor. Kod değişmedi (yalnızca
`static/app.js` + wiki metni), 46/46 test aynen geçiyor. `?v=124`.

## PDF rapor: okunabilirlik + gerçek bir veri gösterim hatası (2026-07-29)

Kullanıcı geri bildirimi: "çok sıkışmış, hiçbir şey anlaşılmıyor" ve ayrıca
"bilgiler yanlış gibi geldi." İkisi de haklı çıktı, ama farklı sebeplerden:

**1) Okunabilirlik — gerçek sebep font boyutuydu.** Önceki sıkıştırma
(2026-07-28) hücre fontunu 6-7px'e indirmişti — CSS px'in baskıda ~×0.75
pt'ye denk geldiği unutulmuş, yani ekranda "sıkışık ama okunur" görünen
şey kağıtta ~5pt, gerçekten okunaksız çıkıyordu. Sütun genişliği 64px→108px,
hücre fontu 7px→9px, alt teknik fontu 6.5px→8px, başlık 7px→9.5px oldu.
Ayrıca mor "M" bayrağı artık hücrenin kendi `padding-right:16px` boşluğuna
oturuyor — önceden metnin üzerine mutlak konumla biniyordu, şimdi asla
metinle çakışmıyor. Bedeli: 15 taktik artık 1280px pencerede 2 satıra
sarıyor (yapay sayfalama değil, doğal taşma — bkz. 2026-07-28 kararı).

**2) Gerçek bir veri gösterim hatası bulundu ve düzeltildi.** Matris
hücresi tooltip'i ve Tam Teknik Listesi eki, "X/Y etkin tespit" oranını
`named_rule_count` (doğrudan adı olan kural SAYISI — ham, ağırlıksız,
rollup'suz) ile `rule_threshold` (artık aile rollup toplamı) birlikte
gösteriyordu. Bu iki alan birbiriyle hiç ilişkili değil: T1552 örneğinde
tooltip "%86, 0/8" gösteriyordu — kendisiyle çelişen bir sayı (0/8 = %0
olması gerekirdi). Skoru gerçekten süren alan `effective_rule_count`
(ağırlıklı, rollup'lı) idi ama hiçbir yerde gösterilmiyordu. İki alan da
`t.effective_rule_count | round(1)` olarak düzeltildi — artık "6.9/8"
gösteriyor, %86 ile tutarlı. Bu hata muhtemelen kullanıcının "veriler
yanlış" hissinin asıl kaynağıydı — alttaki toplamlar/skorlar
(`/api/gap-analysis` ile birebir karşılaştırıldı) hep doğruydu, yalnızca
bu bir gösterim satırı yanlış alanı okuyordu. Matris bölümünün açıklama
metni de düzeltildi (hâlâ "alt teknikler paydaya girmez" diyordu — Faz
4c/rollup sonrası artık girdikleri için stale'di).

**Doğrulandı (gerçek veri, canlı sunucu):** T1552 için tooltip artık
"%86, 6.9/8 etkin", appendix satırı "6.9 / 8" — ikisi de birbiriyle ve
`/api/gap-analysis`'in `effective_rule_count`/`coverage_score`
alanlarıyla tutarlı. Genel özet kartları zaten `/api/gap-analysis`
ile birebir eşleşiyordu (bu hiç bozulmamıştı). 46/46 test geçiyor
(HTML/CSS/Jinja değişikliği, Python testleri etkilenmedi).

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

## Docker Host Portu 9293'e Alındı (2026-07-29)

- `docker-compose.yml`: `ports:` eşlemesi `"8000:8000"` → `"9293:8000"`. Sadece host tarafı değişti; container içi her şey (`SOC_PORT: 8000`, healthcheck'in hedeflediği `http://localhost:8000/login`, `EXPOSE 8000` Dockerfile'da) aynı kaldı — bunlar container-içi concern, host portundan bağımsız.
- `docs/backup_restore.md`: Kurulum adımındaki `http://localhost:8000` referansı `http://localhost:9293` olarak güncellendi (bu dosya özellikle bu docker-compose akışını anlatıyor).
- Kapsam dışı bırakılanlar (bilinçli): `README.md`'deki Waitress örneği (`$env:SOC_PORT='8000'`) Docker dışı, bare-metal `serve.py` senaryosu için genel bir örnek — dokunulmadı. `.claude/launch.json`'daki yerel dev önizleme (`soc-dev`, port 8000) da ayrı bir concern (bu makinede Docker kurulu değil, kullanıcı Docker'ı kendi makinesinde kuruyor) — değiştirilmedi.
- Not: Değişiklik sadece compose dosyasında olduğu için image yeniden build gerekmiyor, `docker compose up -d` mevcut container'ı yeni port eşlemesiyle yeniden oluşturur.
- Commit/push yapılmadı — kullanıcı isteyince yapılacak.

## Matrix Görsel Yenileme — Referans Projeden İlham (2026-08-14)

Kullanıcı bir Splunk MITRE ATT&CK heatmap uygulamasını (`alatif113/mitre_attck_heatmap`, gerçek kaynağı incelendi: el yazımı jQuery/DOM, D3 değil) beğendi ve üç değişiklik istedi: görsel/etkileşim dilini ona yaklaştırmak, hücrelerdeki oran metinlerini ve "M" mitigation rozetini kaldırmak (hesaplama arka planda kalıyor, hover tooltip'e taşındı), "Tehdit Aktörü" overlay özelliğini tamamen kaldırmak. Plan dosyası: `C:\Users\Oguzhan\.claude\plans\gentle-leaping-riddle.md`.

- **Tehdit Aktörü kaldırıldı** — `app.py` (`THREAT_ACTOR_CACHE`, `_get_threat_actors()`, `/api/threat-actors`), `app.js` (6 fonksiyon + çağrı noktaları), `index.html` (`#threatActorBar`), `styles.css` (`.threat-actor-bar`, `.threat-match`/`.threat-dim`), `test_app.py`, `docs/rbac.md`.
- **Hücre yüzü sadeleşti** — `fillTechniqueCell()` artık yalnızca ad+ID basıyor (`.tc-marks`/`.tc-shield`/`.tc-env`/`.tc-count` CSS'i silindi). Tüm sayısal detay (oran, mitigation, ürünler, ortam, tehdit grubu) zaten var olan hover tooltip'te (`wireScoreTooltip()`) toplandı — `applyTechniqueVisuals()`'a hiç dokunulmadı, `card.dataset.scoreData` zaten her alanı taşıyordu.
- **Alt teknik: tıkla-aç → hover-flyout** (kullanıcı onaylı karar, referans projeye sadık). Kritik nokta: `subContainer` artık `card`'ın DOM ÇOCUĞU (`col`'un kardeşi değil) — CSS `:hover`'ın torunlarda sürmesi ve `position:absolute`'in doğru karta göre konumlanması bunu gerektiriyor. Yön aşağı (`top:100%`, sıfır boşluk — "ölü bölge" hover bug'ından kaçınmak için), `opacity/visibility/transform` ile geçiş (`display` geçiş yapamaz). "Hepsini Aç" toplu butonu kaldırıldı (kullanıcı onaylı — hover-only modelde karşılığı yok).
- **Kart hover "pop" efekti** — `scale(1.06) translateY(-2px)` + shadow + `z-index:5` (referansın `scale(1.2)`'sinden bilinçli düşük, dar kolonlarda taşmayı önlemek için).
- **Statik skor lejantı eklendi** — `renderScoreLegend()`, `_SCORE_STOPS`/`scoreToColor()`'ın kendisinden türetiliyor (ayrı bir palet elle kopyalanmadı). Referansın interaktif sürükle-vurgula ve otomatik "sweep" animasyonu bilinçli olarak PORT EDİLMEDİ (kullanıcının "basit" hedefiyle çelişiyor).
- **`.score-tooltip` iyileştirmeleri** — kenar-farkında konumlama (sol/sağ/alt clamp+flip), dolgu çubukları artık `width:0%` render edilip `requestAnimationFrame` içinde gerçek yüzdeye set ediliyor (CSS `transition` eklendi — öncesinde geçilecek "önceki değer" yoktu).
- **Tutarlılık** — `docs.html`, `README.md`, `scripts/browser_smoke.py` (`subtech_toggles` → `subtech_cards`, `.tc-toggle` artık yok) güncellendi. `styles.css?v=121`, `app.js?v=125`.
- **Doğrulama**: 46/46 test geçti. Tarayıcıda DOM/CSSOM üzerinden doğrulandı (bu ortamda Browser pane compositing yapmadığı için ekran görüntüsü alınamadı — `document.hidden===true` ile teyit edildi): `.subtech-container`'ın `card`'ın direkt çocuğu olduğu, kapalı/açık CSS kurallarının doğru ayrıştığı, tooltip'in tam sayısal dökümü gösterdiği, karta tıklamanın hâlâ doğru modalı açtığı, mouseleave'de tooltip'in temizlendiği, konsol hatası olmadığı. `requestAnimationFrame` bazlı dolgu animasyonu bu spesifik non-composited ortamda tetiklenemedi (rAF, `document.hidden` sayfalarda tarayıcı tarafından durduruluyor — izole test ile doğrulandı) ama bu ortam kısıtı; gerçek kullanıcı hover'ı yalnızca görünür/foreground bir sayfada mümkün olduğu için pratikte sorun değil.
- Commit/push yapılmadı — kullanıcı isteyince yapılacak.

### Düzeltme: Hover flyout kartın altında kayboluyordu (2026-08-14, devam)

Kullanıcı geri bildirimi: ana teknik kartı, altında açılan alt teknik flyout'unun üzerine biniyor, göremiyor. Kök neden `document.elementsFromPoint()` ile ölçülerek doğrulandı (ekran görüntüsü bu ortamda alınamadığı için): `.technique-card:hover`'daki `transform: scale(1.06)` merkezden büyüdüğü için kartın alt kenarı ~1px aşağı taşıyor, tam o noktada başlayan `.subtech-container`'ın (`top:100%`) üzerine biniyordu.

- **Kök neden düzeltmesi:** `transform-origin: center bottom` eklendi — artık scale kartın alt kenarını hiç aşağı itmiyor (üstten büyüyor), `translateY(-3px)` ile de yukarı çekiliyor.
- **Asıl algı sorunu için daha güçlü çözüm:** referans projedeki `.mtr-tactic-col:hover .mtr-technique-container{opacity:.25}` fikri port edildi — `.tactic-column:has(.technique-card:hover) .technique-card:not(:hover) { opacity:.35; filter:grayscale(.4); }`. Aynı kolondaki diğer kartlar donuklaşınca "hangisi üstte" belirsizliği tamamen kalkıyor. `:has()` bu stylesheet'te zaten kullanılıyordu (`.wiki-nav-*`), yeni bir tarayıcı desteği riski değil.
- Kart pop efekti bu vesileyle biraz güçlendirildi: `scale(1.06→1.08)`, `brightness(1.18→1.22)`, gölge derinleştirildi. Flyout de karttan biraz taşan (-4px sağ/sol), üstte vurgu renkli kenarlıklı, daha "referans projedeki gibi belirgin bir panel" hissi verecek şekilde güçlendirildi.
- Doğrulama notu: bu ortamda CSS transition'lar `document.hidden=true` olduğu için compositor hiç çalışmadığından ilerlemiyor (izole `requestAnimationFrame` testiyle doğrulandı) — bu yüzden gerçek `:hover` yerine `transition:none !important` ile geçici debug class'ları uygulanıp `elementsFromPoint` ile geometri/stacking ölçüldü, sonra debug class'ları temizlendi.

### Asıl çakışma bulundu: score-tooltip ile subtech-flyout, ikisi de kartın ALTINDA (2026-08-14, devam 2)

Önceki iki düzeltme (transform-origin, kolon içi donuklaştırma) kartın kendi kutusuyla ilgili küçük bir sorunu gerçekten çözdü ama kullanıcının asıl gördüğü şey farklıydı: `wireScoreTooltip()`'in ürettiği `.score-tooltip` (numara dökümü — `z-index:2100`, opak arka plan) ve `.subtech-container` flyout'u (alt teknik listesi — `z-index:5`) **ikisi de kartın altında aynı bölgeye** konumlanıyordu — biri `rect.bottom + 4px`'te, diğeri `top:100%`'te. Alt tekniği olan HER kart hover'landığında ikisi birden açılıyor, tooltip çok daha yüksek z-index'i sayesinde flyout'u tamamen örtüyordu. `document.elementsFromPoint()` + eksen-hizalı dikdörtgen kesişim testiyle doğrulandı.

**Çözüm:** `wireScoreTooltip()`'teki konumlama mantığı köküne kadar değişti — tooltip artık kartın ALTINA değil YANINA (sağına, sığmazsa soluna) yerleşiyor, dikeyde kartın üst kenarına hizalanıp ekrana clamp'leniyor. Böylece flyout'un yaşadığı bölgeye hiç girmiyor — iki panel de aynı anda, çakışmadan görünebiliyor. Ayrıca kullanıcının "işe yaramıyor" dediği pasif `▸` ipucu oku (`.tc-foot::after`) tamamen kaldırıldı.

Doğrulandı: `rectanglesOverlap: false` (gerçek `mouseenter` ile açılan tooltip + `transition:none` ile zorla açılan flyout, iki dikdörtgen kesişmiyor).

### Tooltip'te de sayısal detay kaldırıldı — "artık sadece renkler konuşacak" (2026-08-14, devam 3)

Kullanıcı kararı: hover tooltip'i de sadeleştir. Kaldırılanlar: tespit sayısı/hedef satırı + ilerleme çubuğu, "yalnız ürün iddiası" uyarısı, mitigation satırı + çubuğu, ortam oranı, tehdit grubu sayısı, son "Kapsama %X" satırı — hepsi sayısaldı. Ürün isimleri de metin olarak kaldırıldı, kartlardaki `.product-dots` ile aynı dilde **sadece renkli nokta** oldu (isim istenirse noktanın üzerinde native `title` tooltip'i var). Referans projedeki "hover'da rengin gradyanda nerede olduğunu göster" fikri **`.tt-spectrum`** ile eklendi: `_SCORE_STOPS`'tan türeyen aynı degrade (`_scoreGradientStops()` — `renderScoreLegend()` ile paylaşılan tek kaynak) bir çubukta çizilip üzerine skorun konumunda beyaz bir işaretçi konuyor. `wireScoreTooltip()`'teki artık kullanılmayan `requestAnimationFrame` dolgu-animasyonu bloğu silindi (o veri kaynağı da kalktığı için). İşe yaramadığı söylenen pasif `▸` ipucu oku (`.tc-foot::after`, önceki round'da eklenmişti) da tamamen kaldırıldı.

Bilinçli olarak ERTELENEN bir öneri: kullanıcı "belki teknik için bir açıklama metni olabilir" dedi (referans projenin `description` alanı gibi). Bunu hover'da göstermek ya (a) her hover'da yeni bir `/api/technique-detail/<id>` çağrısı gerektirir — hızlı fare hareketinde istek yağmuruna yol açar, ya da (b) `techDetailsMap`'i mitre.json'daki açıklama metniyle önceden doldurmak gerekir — bu da `/api/mitre-min` yükünü büyütür (700+ teknik × açıklama metni). Kullanıcının kendi ifadesi de "belki" ile hedge'liydi; büyük bir performans/boyut tradeoff'u olan bir ekleme olduğu için onaylarını almadan uygulanmadı — kullanıcıya sorulacak.

`styles.css?v=123`, `app.js?v=127`. 46/46 test, konsol hatası yok, gerçek `mouseenter` ile tooltip içeriği doğrulandı (`tooltipTextOnly` yalnızca ID+ad döndürüyor, hiç başka metin yok).

### Kendi kendine özeleştiri + referansa daha yakın görsel dil (2026-08-14, devam 4)

Kullanıcı, referans projenin görsellik dosyalarını (`visualization.css`) tekrar incelememi ve kendi kodumla dürüstçe karşılaştırmamı istedi. Bulgular ve düzeltmeler:

1. **Matrix tam ekran modu (yeni özellik)** — `#btnMatrixFullscreen`, `.ms-shell.matrix-fullscreen` sınıfı `.ms-topbar`+`.sidebar`'ı gizler, `.content` boşalan alanı otomatik doldurur (zaten `flex:1`). Gerçek Fullscreen API değil — kullanıcı özellikle "chrome sayfasının tamamı heatmap olsun, sekme/adres çubuğu değil, bizim navigasyonumuz" dedi. Esc ile çıkılıyor, `wireMatrixFullscreen()`.
2. **Stat-bar + arama çubuğu kompaktlaştırıldı** — `.matrix-stat-bar` min-height 55px→34px, `.filter-bar` padding/margin küçültüldü, arama input'u scoped override ile küçültüldü (global `input{height:30px}`'a dokunulmadı).
3. **Ortam seçici Matrix panelinden kaldırıldı** — `#matrixScopeSelect`+`#matrixScopeNote` HTML'den silindi. Tüm JS tüketicileri zaten `if (!el) return` ile korunuyordu (doğrulandı, sıfır hata) — `matrixScopeEnvId` artık hep `null`, panel her zaman birleşik modda. **Backend, Kapsam Envanteri, `/report?environment_id=` hiç dokunulmadı** — kullanıcı özellikle "tüm üründen çıkarmayı sonra yaparız" dedi. `docs/ACIK_SORULAR.md` madde 8'e not düşüldü (ürün genelinde kaldırma kararı ileride). README.md'deki artık yanlış olan "matrisin üstündeki Ortam seçicisi" cümlesi düzeltildi.
4. **Opak/doygun renk dolgusu** — `scoreToColor()`/`scoreToSubColor()` artık `rgba(...,0.20/0.13)` değil opak `rgb(...)` döndürüyor (ikisi artık aynı — referansta da ana/alt teknik farklı saydamlık almıyor). Yeni `scoreTextColor()` luminance hesaplayıp otomatik siyah/beyaz metin seçiyor (referansın `_getColor()`'ı ile birebir aynı formül: `0.299r+0.587g+0.114b`, eşik 0.65). `applyTechniqueVisuals()`'ın 3 çağrı noktasında `card.style.color` de set ediliyor artık. `.tc-id`'nin sabit rengi (`var(--d-text-3)`) `color:inherit`'e çevrildi — yoksa opak/parlak arka planlarda ID metni okunmaz kalırdı. `buildSubtechContainer()`'daki eski `scoreToSubColor` override'ı kaldırıldı (artık `scoreToColor` ile aynı değeri üretip gereksiz hale geldi). Legend ve tooltip gradyanı `scoreToColor()`'ı zaten paylaştığı için otomatik olarak da opak/doygun oldu.
5. **Hover "pop" büyütüldü** — `scale(1.08)→1.18`, `translateY(-3px→-5px)`, gölge `0 10px 22px/.5→0 7px 30px/.75` (referansın `scale(1.2)`sine kullanıcı onayıyla yaklaşıldı, komşu karta geçici taşma artık kabul ediliyor). `filter: brightness` 1.22→1.1'e düşürüldü — opak/doygun dolgu üzerinde aşırı parlaklık artık gerekmiyor, taşma+gölge zaten yeterince dramatik.

Doğrulandı (DOM/CSSOM, bu ortamda ekran görüntüsü yok): ortam seçici DOM'dan tamamen gitti, kart arka planı `rgb(218,147,48)` gibi tam opak, otomatik seçilen metin rengi luminance hesabıyla tutarlı (`rgb(255,255,255)` — hesaplanan luminance 0.615 < 0.65 eşiği), tam ekran butonu sidebar+topbar'ı gerçekten gizliyor/geri getiriyor, Esc tuşu çalışıyor, hover kuralı yeni değerlerle stylesheet'te doğru. 46/46 test. `styles.css?v=124`, `app.js?v=128`.

### Opak renk geri alındı — kullanıcı gerçek referans ekran görüntüleri paylaştı (2026-08-14, devam 5)

Yukarıdaki "opak/doygun renk" değişikliği kullanıcıya kaynak koddan (renk sabitleri) çıkarımla önerilmişti — gerçek referans ekran görüntüsü görülmeden. Kullanıcı bu kez referans projenin GERÇEK render edilmiş ekran görüntülerini paylaştı: kartlar aslında soluk/pastel tonlarda (yumuşak yeşil, krem, toz pembe, lacivert) — benim uyguladığım canlı/doygun kırmızı-turuncu-yeşil değil. "Eski saydam hali daha iyiydi" geri bildirimiyle **tamamen geri alındı**:

- `scoreToColor()` → `rgba(...,0.20)`'ye, `scoreToSubColor()` → `rgba(...,0.13)`'e (ayrı fonksiyonlar, eskisi gibi) döndü.
- `scoreTextColor()` (luminance bazlı otomatik siyah/beyaz metin) tamamen silindi, 3 çağrı noktasındaki `card.style.color=...` satırları kaldırıldı — metin rengi yine CSS class'ları (`var(--d-text-2)`/`.covered{var(--d-text-1)}`) üzerinden geliyor.
- `.tc-id`'nin rengi `color:inherit` → sabit `var(--d-text-3)`/`#9ba39d`'ye geri döndü.
- `buildSubtechContainer()`'daki alt-teknik-daha-soluk override'ı geri eklendi (scoreToSubColor tekrar ayrı bir değer ürettiği için gerekli).

**Ders:** Renk sabitlerini (hex kodları) okuyup "opak + doygun" çıkarımı yapmak, gerçek render edilmiş görüntüyü görmekle aynı şey değilmiş — CSS'teki `#53a051` gibi değerler koddan bakınca "canlı" görünebilir ama gerçek uygulamada (muhtemelen Splunk'ın kendi tema/palet ayarlarıyla) çok daha yumuşak render oluyor. Doğrulanan (rgba tonlar): `styles.css?v=125`, `app.js?v=129`, 46/46 test, konsol hatası yok.

### Pastel palet — kullanıcının paylaştığı gerçek ekran görüntülerinden gözle tahmin (2026-08-14, devam 6)

Kullanıcı "o görsellerdeki gibi tutturamıyor musun" dedi — bu sefer geri almak yerine gerçekten paylaşılan ekran görüntülerine bakıp (yumuşak deniz yosunu yeşili, krem, toz pembe, koyu lacivert) `_SCORE_STOPS`'u bu tonlara yakın **pastel** değerlerle değiştirdim: `rgb(61,69,86)` → `rgb(201,137,120)` → `rgb(224,212,168)` → `rgb(168,194,160)` → `rgb(111,168,140)`. Bu kez OPAK dolgu doğru seçim (önceki opak denemenin sorunu doygunluktu, opaklık değil — pastel renkler zaten yumuşak, saydamlığa gerek yok). `scoreToColor`/`scoreToSubColor` tekrar opak+aynı, `scoreTextColor()` (luminance bazlı) tekrar eklendi, `.tc-id` tekrar `color:inherit`.

**Açıkça belirtildi (kullanıcıya da söylenecek):** Bu renkler ekran görüntüsünden göz kararı tahmin edildi, piksel-hassas bir renk seçici kullanılmadı — birebir eşleşme garantisi yok, kullanıcı geri bildirimiyle ince ayar gerekebilir.

Doğrulandı: en yaygın 8 benzersiz arka plan rengi + karşılık gelen otomatik metin rengi örneklendi (`rgb(111,168,140)` → açık metin, `rgb(210,165,138)` → koyu metin gibi, luminance eşiğine göre tutarlı). 46/46 test, konsol hatası yok. `styles.css?v=126`, `app.js?v=130`.

### Yapısal migrasyon: sarmalanan ID-only ızgara (2026-08-14, devam 7)

Kullanıcı: "istediğim renkler değil direkt görsel yapı" — referans projenin tam kaynağını `example/mitre_attck_heatmap-master/` klasörüne koyup "görsel dil olarak tamamen buraya migrate etmek istiyorum" dedi. İki ajan (Explore doğrulama + Plan stres testi) ile bulunan kök yapısal fark: referansta taktik kolonu içinde teknikler `display:flex;flex-wrap:wrap` ile satırda 2-3 tane yan yana sarmalanıyor; bizde `.tactic-column` hep `flex-direction:column` — tek sütun. Kullanıcı onayıyla: kart yüzü artık **yalnızca ID** gösteriyor (referansın varsayılan modu), bu da kutucukları küçültüp sarmalamayı mümkün kılıyor. Plan dosyası: `C:\Users\Oguzhan\.claude\plans\gentle-leaping-riddle.md`.

- **`fillTechniqueCell()`**: ana kartlar artık tek `<span class="tc-id">` (isSub=false dalı); alt teknik kartları (flyout içinde) ad+ID ile değişmedi. Ad kaybolmasın diye `cell.dataset.techName = name` (ham, `_esc` değil — çifte kaçış riski Plan ajanı tarafından bulundu).
- **`applyTechniqueVisuals()`**: tooltip'in adı artık `card.dataset.techName`'den okunuyor (eskiden `.tc-name` DOM'undan kazınıyordu, kalkınca boş dönerdi). `applySourceDots()` artık yalnızca `.technique-card` OLMAYAN kartlarda (yani alt teknik kartlarında) çağrılıyor — 44px'lik ID-only kutuda ürün noktaları sığmazdı (Plan ajanı bulgusu); ürün bilgisi zaten hover tooltip'inin `.tt-dots-row`'unda var.
- **`renderMatrix()`**: yeni `techWrap` (`.tactic-techniques`, flex-wrap) sarmalayıcısı — kartlar `col`'a değil `techWrap`'e ekleniyor, `techWrap` boş değilse `col`'a ekleniyor (subContainer'daki koşullu-ekleme deseniyle aynı). `visibleColumns` sayacı buna göre güncellendi.
- **CSS**: `.technique-card` artık sabit `44×24px` (`flex:0 0 auto`, tek satır ortalı ID) — MITRE ana teknik ID'leri hep tam 5 karakter olduğu için sabit boyut güvenli, referansın "placeholder" hilesine gerek yok. `.subtech-container` artık üst kartla aynı genişlikte değil (`left:-4px;right:-4px` kalktı) — sabit `min-width:170px;left:0`, çünkü alt teknik kartları hâlâ tam ad+ID gösteriyor. Yeni `.technique-card.flyout-left > .subtech-container { left:auto; right:0 }` — sağ kenara yakın kartlarda flyout komşu taktik kolonuna taşmasın diye `mouseenter`'da JS ile ölçülüp class ekleniyor (tooltip'in kenar-farkında konumlama mantığının hafif versiyonu).
- **`scripts/browser_smoke.py`**: satır 72'deki `.tc-name` seçicisi (artık DOM'da yok, script'in geri kalanını hiç çalıştırmadan çökerdi) `#matrix .technique-card`'a düzeltildi — kartın tamamı zaten tıklanabilir.
- Renk paleti bilinçli olarak KAPSAM DIŞI bırakıldı (zaten bilinen-iyi `rgba(...,0.20/0.13)` tonlamasında duruyor).

**Doğrulandı (DOM/CSSOM, bu ortamda ekran görüntüsü yok):** aynı taktik kolonunda 3 kart gerçekten aynı satırda (`T1589/T1590/T1591` aynı `top:415`, sonraki 3'ü `top:442`), kart genişliği 44px, ana kartın flyout hariç görünür metni yalnızca ID (`"T1589"`), ana kartlarda doğrudan çocuk `.product-dots` yok (0/12), hover tooltip'i doğru tam adı gösteriyor (`dataset.techName` üzerinden), sağ kenara yakın bir kart (`T1055`, `left:1254` / viewport `1280px`) hover'da gerçekten `flyout-left` class'ı alıp flyout'u sola çeviriyor, karta tıklamak hâlâ doğru modalı açıyor. 46/46 test, konsol hatası yok. `styles.css?v=127`, `app.js?v=131`.

### Yapısal migrasyon + pastel renkler geri alındı — kullanıcı "eski hal + canlı renk + biraz saydamlık" istedi (2026-08-14, devam 8)

Bir önceki yapısal migrasyon (sarmalanan ID-only ızgara) VE pastel renk denemesi kullanıcı tarafından bir arada geri istendi: "kutucukları eski haline getir bide eski renklendirme yap yani çok cırtlak renkler biraz saydamlık ekle tamamdır".

**Yapı — tamamen eski hale (tek sütun, ad+ID):**
- `fillTechniqueCell()`: `isSub` dallanması kaldırıldı, ana+alt teknik yine aynı ad+ID düzenini kullanıyor. `cell.dataset.techName` mekanizması KORUNDU (daha sağlam, geriye dönük uyumlu — görünüşü etkilemiyor).
- `applyTechniqueVisuals()`: `applySourceDots()` çağrısı tekrar koşulsuz (ana kartlarda da ürün noktaları geri geldi).
- `renderMatrix()`: `.subtech-container` sağ-kenar taşma önleme `mouseenter` dinleyicisi kaldırıldı (kart tekrar geniş olduğu için `.subtech-container`'ın kartla eş genişlikte olması taşmayı zaten yapısal olarak engelliyor).
- CSS: `.tactic-techniques` `flex-wrap:wrap` → `flex-direction:column` (yeni wrapper div DOM'da kalıyor ama artık eski tek-sütun görünümünü üretiyor — ekstra bir sarmalayıcı div dışında hiçbir davranış farkı yok, hiçbir seçici buna bağımlı değildi). `.technique-card` eski `min-height:38px` + ad/ID iki satırlı düzenine döndü (44×24px sabit boyut kalktı). `.subtech-container` eski `left:-4px;right:-4px`'e döndü (`min-width:170px` kalktı), `.technique-card.flyout-left` kuralı silindi.

**Renk — canlı durak renkleri + orta saydamlık:**
- `_SCORE_STOPS` orijinal doygun değerlere döndü (koyu→kırmızı→turuncu→sarı-yeşil→koyu yeşil — `#CD3232` vb.), pastel tahminler (`rgb(201,137,120)` vb.) tamamen kaldırıldı.
- `scoreToColor`/`scoreToSubColor`: tam opak (`rgb`) değil, çok soluk `rgba(...,0.20/0.13)` de değil — **orta nokta: `rgba(...,0.55/0.35)`**. "Tam opak + canlı" daha önce reddedilmişti ("gözüm kanadı"); bu sefer aynı canlı renkler ama saydamlıkla yumuşatılmış hali deneniyor.
- `scoreTextColor()` (luminance bazlı otomatik kontrast) tamamen silindi — üç çağrı noktası da temizlendi. `.tc-id` eski sabit `var(--d-text-3)`/`#9ba39d` rengine döndü.

Doğrulandı: kartlar tekrar tek sütun (`T1589→T1590→T1591` aynı `left:250`, artan `top` 412/452/492/532, 164px genişlik, 38px yükseklik), arka plan `rgba(218,147,48,0.55)` (canlı turuncu + orta saydamlık), ana kartta doğrudan `.tc-name` VE `.product-dots` tekrar var. 46/46 test, konsol hatası yok. `styles.css?v=128`, `app.js?v=132`.

### Saydamlık ince ayarı %55→%38 + gizli kalmış bir bug (2026-08-14, devam 9)

Kullanıcı: "az daha uygun yap, yine cırtlak, biraz daha saydamlaştır ama çok değil" — `scoreToColor` %55→%38, `scoreToSubColor` %35→%24 (aynı ~1.55 oranı korunarak).

Bu ince ayarı doğrularken **gerçek bir bug** bulundu: `buildSubtechContainer()`'daki alt-teknik-daha-soluk-göster override'ı (`subCard.style.backgroundColor = scoreToSubColor(subScore)`), bir önceki "devam 8" turunda yapı+renk geri alma işlemi sırasında yanlışlıkla geri eklenmemişti — `applyTechniqueVisuals()` her zaman `scoreToColor` (ana kart alfası) kullandığı için flyout içindeki alt teknik kartları da ana kartla AYNI alfada görünüyordu, fark edilmeden. Restore edildi; artık alt teknik kartları gerçekten daha soluk (`rgba(...,0.24)` vs ana `rgba(...,0.38)`).

Doğrulandı: ana kart `rgba(218,147,48,0.38)`, alt teknik kartı `rgba(42,155,55,0.24)` — iki farklı alfa doğru uygulanıyor. 46/46 test, konsol hatası yok. `styles.css?v=128`, `app.js?v=134`.

### Renk + kart yapısı, kullanıcının yüklediği çalışır HTML örneğine göre yeniden yapıldı (2026-08-14, devam 10)

Önceki turlarda (devam 5-9) renk ekran görüntüsünden göz kararı tahmin ediliyordu — kullanıcı bu sefer *"Sana örnek bir tane html dosyası upload ediyorum çünkü genel arayüzü böyle istiyorum... html dosyasını çalıştır bak istiyorsan"* diyerek çalışan, tam kaynağı okunabilir bir referans dosyası (`gemini-code-1786730524519.html`) verdi — tahmine son vermek için. Dosyanın `getHeatColor()` algoritması birebir okunup uyarlandı (bizim skorumuz yüksek=iyi=yeşil, örneğin tam tersi yüksek=kötü=kırmızı olduğu için yön ters çevrildi, algoritmanın kendisi aynı):

- **Renk** — `_ZERO_COLOR` (`#31373E`, hiç tespit yok → düz gri) + `_SCORE_STOPS` (0.00 yumuşak kırmızı → 0.45 turuncu → 0.70 sarı → 1.00 yeşil) + `_scoreRgb()` (parçalı doğrusal enterpolasyon) örnekteki yapıyı birebir izliyor. `scoreToColor`/`scoreToSubColor` artık aynı (örnekte ana/alt ayrımı yok), opak `rgb(...)`. `scoreTextColor()` luminance eşiği 0.55.
- **Kart içeriği** — `fillTechniqueCell()` ana+alt teknik için TEK kod yoluna indirgendi: `<span class="tc-label">ID Ad</span>` (tek satır, taşarsa `…`). Eski `.tc-name`/`.tc-foot`/`.tc-id` üçlüsü CSS'ten de silindi (`.subtech-card .tc-label` ile alt teknikte küçültülüyor).
- **Hover pop** — `.technique-card:hover` örneğe yaklaştırıldı: `scale(1.18)`/`translateY(-5px)` gibi dramatik değerler yerine `scale(1.04) translateY(-2px)` + `box-shadow: 0 8px 25px rgba(0,0,0,.9)` + `filter:brightness(1.08)`.
- **Lejant imleç (canlı)** — `renderScoreLegend()`'in ürettiği `.score-legend-bar` içine `#scoreLegendCursor` eklendi (varsayılan `opacity:0`). `wireScoreTooltip()`'in zaten var olan `mouseenter`/`mouseleave` dinleyicileri genişletildi — yeni dinleyici eklemek yerine tooltip'in zaten hesapladığı `d.score` değeriyle `left:%` set edip `.active` class'ı ekleyip/kaldırıyor. Tooltip'in kendi `.tt-spectrum-marker`'ı ile aynı kaynaktan geldiği için ikisi hep aynı pozisyonu gösteriyor.

**Doğrulama sırasında bulunup düzeltilen 3 bug (kullanıcı bildirmedi, kendi taramamda çıktı):**
1. `_scoreGradientStops()` — `_SCORE_STOPS`'u `scoreToColor()`'dan geçirerek üretiyordu, ama `scoreToColor(0)` artık HER ZAMAN `_ZERO_COLOR`'a düşüyor (yeni `score<=0` özel durumu yüzünden) — ilk durak olan "yumuşak kırmızı" gradyanda hiç görünmüyordu. Düzeltme: gradyan artık elle kuruluyor — `%0-2` düz gri "kapak", ardından gerçek duraklar `%2`'den başlıyor (CSS, bir sonraki durağın nominal `%0` pozisyonunu önceki duraktan geriye gidemeyeceği için otomatik `%2`'ye sabitliyor — spec-garantili davranış, keskin gri→kırmızı geçişi bu şekilde oluşuyor).
2. Öksüz kalmış **ikinci bir** `.technique-card:hover` kuralı (satır ~361, bu turun üstündeki temel kart kuralının hemen altında, muhtemelen çok önceki bir turdan kalma) `border-color`/`color` set ediyordu — `filter` bu turun yeni kuralı tarafından ezilse de (dosyada sonra geldiği için kazanıyor), `border-color` hiçbir yerde ezilmediği için hover'da istenmeyen mavi kenarlık gerçekten görünüyordu. Silindi.
3. Aynı desen `.subtech-card:hover`'da da vardı (satır ~438, `filter:brightness(1.4);color:...` — asıl kullanılan kural çok daha aşağıda, satır ~2849'da `brightness(1.18)+box-shadow`). Bu ikisi şu an aktif çakışma yaratmıyordu (her iki özellik de ya ezilmiş ya inline stille örtülmüştü) ama aynı kök nedenden (redesign turlarında kart temel kuralı güncellenirken hemen altındaki eski hover kuralı hiç dokunulmadan kalmış) kaynaklandığı için tutarlılık adına o da silindi.

Doğrulandı (DOM/CSSOM, bu ortamda ekran görüntüsü yok — `javascript_tool` ile): gerçek `mouseenter` sonrası kart etiketi `"T1589 Gather Victim Identity Information"` (tek satır), `.tc-name` DOM'da yok, `#scoreLegendCursor.style.left` (`"53%"`) `.tt-spectrum-marker`'ınkiyle birebir aynı, `mouseleave`'de `.active` kalkıyor; sıfır skorlu kart tam `rgb(49,55,62)` + beyaz metin; alt teknik kartları da aynı paleti kullanıyor (`scoreToSubColor===scoreToColor`); stylesheet'te `.technique-card`/`.technique-card:hover`/`.subtech-card:hover` artık kesin 1'er kez tanımlı, `.tc-name`/`.tc-foot`/`.tc-id` kesin 0 kez. 46/46 test. `scripts/browser_smoke.py` bu ortamda çalıştırılmadı (selenium `requirements.txt`'te yok, önceki turlarda da aynı sebeple atlandı) — yukarıdaki DOM/CSSOM doğrulaması daha hassas olduğu için yeterli görüldü. `styles.css?v=129`, `app.js?v=135`.

Bilinçli olarak kapsam dışı bırakıldı (kullanıcı istemedi, örnek dosyada var ama bu turda konuşulmadı): taktik başlığı hover'ında toplam istatistik paneli (`.mtr-stats-container` benzeri), arama'da soluklaştırma (`.focused`/`.defocused`) — şu an aramada eşleşmeyenler tamamen gizleniyor, örnekte soluklaşıyor.

### Kart içeriği geri alındı + taktik kolonları kutudan çıktı + başlık hover istatistik paneli (2026-08-15)

Kullanıcının 3 ayrı geri bildirimi:

1. **Kart içeriği eski hale (ad üstte, ID altta hafif saydam)** — "devam 10"da uygulanan tek satır "ID Ad" (`.tc-label`) beğenilmedi: *"öncesinde isim altında teknik no yazıyorduya hafif saydam şekilde bundan önce onun gibi yapabilirsen"*. Git HEAD'deki (bu redesign zincirinin başladığı, hiç commit'lenmemiş taban) orijinal `.tc-name`/`.tc-foot`/`.tc-id` CSS'i aynen geri getirildi — kritik detay: `.tc-id`'nin `opacity:0.85`'i tam olarak "hafif saydam" dediği şey. **Bilinçli olarak GERİ GETİRİLMEYEN** kısım: HEAD'deki `fillTechniqueCell()` ayrıca `tc-count` (X/hedef), `tc-shield` (M rozeti), `tc-env` (ortam oranı) da basıyordu — bunlar çok daha ERKEN bir turda kullanıcı kararıyla kaldırılmıştı ("artık sadece renkler konuşacak"), o karar hâlâ geçerli, sadece ad+ID yerleşimi geri alındı. `.technique-card`/`.subtech-card` tekrar `flex-direction:column` (iki satır) oldu; bu turun renk algoritması (Task #53), hover pop (Task #55), lejant imleç (Task #56) DOKUNULMADI.
2. **Taktik kolonları "kutu" görünümünden çıktı** — *"o columnları iptal edelim tek bir column olsun... küçük kutuların içinde olması tüm taktikler dümdüz olsun bg nin üstünde"*. `.tactic-column`'ın kendi `background`/`border`/`padding`'i kaldırıldı (+ aynı özellikleri tekrar basan bir tema-override satırı da silindi — bu turun kendi taramasında bulunan, önceki turdaki hover-rule ikilisiyle AYNI kalıp: temel kural güncellenirken hemen yanındaki eski satır fark edilmeden kalmış). Kartlar artık taktik başına gruplu ama her taktik ayrı panelmiş gibi görünmüyor — hepsi ortak arka plan üzerinde. Yapısal `display:flex;flex-direction:column` grupla(y)ma aynen kaldı, sadece görsel kutu kalktı.
3. **Taktik başlığı hover istatistik paneli (yeni özellik)** — kullanıcı referans görsel gönderdi (Total / Unique Techniques +% / Average per Technique). `renderMatrix()`'in taktik döngüsünde her teknik için zaten hesaplanan `parentRollup` (kartın rengini belirleyenin AYNISI, tutarlılık için) `tacticTotal`/`tacticCovered` biriktiriyor — **arama filtresinden bağımsız** (erken-dönüş satırından ÖNCE biriktiriliyor), çünkü panel taktiğin gerçek durumunu göstermeli, kullanıcı ne ararsa arasın. Sonuç `header.dataset.tacticStats` JSON'una yazılıyor; yeni `wireTacticStatsTooltip()` (renderMatrix() sonunda `wireScoreTooltip()` ile birlikte çağrılıyor) `.tactic-header`'a mouseenter/mouseleave bağlıyor, `.score-tooltip` ile aynı görsel dili kullanan ama kendi class'ı (`.tactic-stats-tooltip`) olan, başlığın ALTINA (yana değil — başlık zaten en üstte) konumlanan, sağ kenara taşarsa clamp'lenen bir popup gösteriyor. Ortalama = Toplam/Tespitli teknik sayısı (Toplam kaydedilmeden ÖNCEKİ ham float'tan hesaplanıyor, yuvarlama hatası birikmesin diye).

Doğrulandı (DOM/CSSOM + gerçek `mouseenter`, bu ortamda ekran görüntüsü yok): kart `innerHTML`'i `<div class="tc-name">...</div><div class="tc-foot"><span class="tc-id">...</span></div>`, ID `opacity:0.85`; `.tactic-column` computed `background:rgba(0,0,0,0)`, `border-style:none`, `padding:0px` (eski tema-override satırı da doğrulandı — dosyada artık yok); taktik başlığı hover'ında ör. "Reconnaissance" → `{total:10.35, covered:5, techCount:12}` → panelde "10.4 / 5 (%42) / 2" (5/12=%41.7→42, 10.35/5=2.07→2, hepsi doğru); popup mouseleave'de kalkıyor; en sağdaki taktik başlığında (`left:2792`, viewport `1280px`) popup sağa taşmadan `right:1272px`'e clamp'leniyor; kart hover'ındaki `.score-tooltip` regresyona uğramadan çalışmaya devam ediyor; `.tactic-header`'ın iki (çakışmayan, tamamlayıcı) kuralı yeni bulgu değil, mevcut ve zararsız. 46/46 test, konsol hatası yok. `styles.css?v=130`, `app.js?v=136`.

### Kart küçültme + taktik başlığı animasyonu + Matrix üst alan temizliği (2026-08-15, devam 2)

Kullanıcının 4 maddelik geri bildirimi (renk hariç — bkz. altta):

1. **Kart/alt-kart boyutu küçültüldü** — `.technique-card` min-height 38→30px, `.subtech-card` 30→25px, `.tc-name` 11.5→10.5px, `.tc-foot`/`.tc-id` 9.5→8.5px (sub daha da küçük: 9.5/8px). Amaç: "ekrana daha çok harita gibi sığdırma" — aynı taktik kolonunda dikeyde daha fazla teknik görünüyor.
2. **`.tc-id` kontrast bugu düzeltildi** — kullanıcı "orda sıkıntı var" dedi, haklıydı: ID sabit `var(--d-text-3)` (gri) kullanıyordu, kartın otomatik siyah/beyaz kontrastını (`scoreTextColor`, `.tc-name`'in `color:inherit` ile zaten kullandığı) TAKİP ETMİYORDU — bazı arka plan renklerinde okunaksız kalabilirdi. `color:inherit` yapıldı (artık `.tc-name` ile birebir aynı, garanti kontrastlı renk), hiyerarşi `opacity:0.7` ile korunuyor.
3. **Taktik başlığı hover pop + panel animasyonlu açılış** — kullanıcı: "az aksiyon kat". `.tactic-header:hover` artık `.technique-card:hover` ile tutarlı bir dille (`scale(1.04)`, `brightness(1.25)`, gölge) tepki veriyor. `.tactic-stats-tooltip` artık JS ile eklenir eklenmez görünür olmuyor — başlangıç durumu `opacity:0;transform:translateY(-6px) scale(0.96)`, JS bir reflow zorlayıp `.visible` class'ı ekliyor, CSS transition ile "büyüyerek" açılıyor. (Bu ortamda rAF çalışmıyor — geçiş bizzat GÖRÜLEMEDİ ama `transition:none!important` debug override'ıyla hem başlangıç hem hedef durumun doğru CSS değerlerine sahip olduğu doğrulandı.)
4. **Matrix üst alanı sadeleştirildi** — dört ayrı kaldırma:
   - `#matrixStatBar` (Teknik/Tespit/Kapsamsız/Mitigation/Ort.Skor/Alt Teknik şeridi) HTML'den silindi. `updateMatrixStats()`/`setMatrixStatLabels()` JS'i BİLEREK SİLİNMEDİ — ikisi de zaten `getElementById`/`querySelectorAll` ile güvenli no-op'a düşüyor (element yoksa sessizce çıkıyor), kullanıcı "daha sonra daha sade biçimde ekleriz" dediği için hesaplama mantığı sıcak tutuluyor.
   - `#matrixModeDescription` ("Renk = kapsama skoru...") ipucu metni HTML'den silindi — hiçbir JS referansı yoktu, tek satırlık temiz kaldırma.
   - **"Liste Görünümü" (ttpPanel) tamamen söküldü** — `SECTIONS.map.tabs`'tan sekme kaldırıldı (`renderSectionTabs()` zaten "tek sekmeli bölümde çubuk gereksiz gürültü" mantığıyla çubuğu otomatik gizliyor, ekstra kod gerekmedi), `templates/index.html`'den `#ttpPanel` bloğu, `static/app.js`'den `loadTtpList`/`renderTtpList`/`_ttpRowBg`/`ttpToggle`/`openTechDetail`/`_TTP_TACTIC_LABELS`/`_ttpData`/`PANEL_LOADERS.ttpPanel` (152 satır), `static/styles.css`'den tüm `.ttp-*` kuralları (3 ayrı bölgede dağınık, 175 satır) silindi. Bu arada bulunan ilgisiz ama bariz ölü kod da temizlendi: `.importance-badge`/`.imp-level-*` (Faz 4b'de `importance` sütunu kaldırıldığında unutulmuş, hiçbir HTML/JS referansı yoktu).
     - **Backend'e BİLEREK dokunulmadı** — `/api/ttp-list`, `ttp_list()`, `TTP_LIST_CACHE`, `_invalidate_ttp_cache()` hâlâ `app.py`'de duruyor ama artık kesin öksüz; `_invalidate_ttp_cache()`'in 13 farklı yazma endpoint'indeki çağrısı riskli/geniş bir değişiklik olduğu için ayrı bir arka plan görevine (`task_915f910e`) devredildi. `docs/ACIK_SORULAR.md` madde 7 güncellendi (bu tutarsızlık zaten KARAR BEKLİYOR olarak işaretliydi — 2026-07-29'dan beri).
   - **"ATT&CK Coverage Matrix" başlık alanı daraltıldı** — matrise dikeyde daha çok yer açmak için `#matrixPanel .ms-page-header`/`#matrixPanel .ms-page-title` scope'lu override eklendi (margin/padding ~%50 küçüldü, font 20→15px). Diğer panellerin başlığı (paylaşılmıyor — `.ms-page-title` sadece Matrix'te kullanılıyordu) etkilenmedi. Artık boş kalan `.matrix-title-block > span` kuralı da silindi (ipucu metniyle birlikte gitti).

**Renk paleti (madde 1'in orijinal listesi) henüz UYGULANMADI** — kullanıcı "çok cırtlak... istersen beraber palet bakalım" dedi, doğrudan tahmin etmek yerine `mcp__visualize` ile 4 aday palet (soluk/pastel/soğuk-profesyonel/mevcut-tonlar-saydamlaştırılmış) örnek kartlar üzerinde gösterilip kullanıcının seçimi bekleniyor — bu turun geri kalanı (2-4) bağımsız olduğu için o beklerken tamamlandı.

Doğrulandı: `ttpPanelExists:false`, `matrixStatBarExists:false`, `matrixModeDescExists:false`, Harita bölümünün alt-sekme çubuğu artık boş+`.hidden` (tek sekme kaldığı için), kart `min-height:30px`, `.tc-id` rengi karttakiyle birebir aynı (hem açık hem koyu metin durumunda test edildi), taktik başlığı hover'ında `.visible` class'ı doğru ekleniyor, `#matrixPanel .ms-page-title` computed `font-size:15px`. 46/46 test, konsol hatası yok. `styles.css?v=131`, `app.js?v=137`.

### Öksüz `ttp-list` backend kodu kaldırıldı — `task_915f910e` tamamlandı (2026-08-15, devam 3)

Yukarıdaki notta ("Backend'e BİLEREK dokunulmadı") ayrı bir arka plan görevine devredilen temizlik yapıldı. `app.py`'den silindi:
- `@app.route("/api/ttp-list")` / `def ttp_list()` (~130 satır, kendi bağımsız STIX-parse + kural-sayma mantığı — `_compute_gap_analysis()`'i hiç çağırmıyordu)
- `TTP_LIST_CACHE` global dict (satır 42) ve `def _invalidate_ttp_cache()`
- `_invalidate_ttp_cache()`'in 12 çağrı sitesi (rules/mitigation CRUD, QRadar connector sync, data-quality repair, admin reset, technique-config update — hepsi `db.commit()`'ten hemen önceydi)

`_TACTIC_ORDER` (app.py:3792) BİLİNÇLİ OLARAK KORUNDU — `_compute_gap_analysis()` ve rapor/export kodu hâlâ kullanıyor; sadece `ttp_list()` içindeki 2 kullanımı gitti. `tests/test_app.py`'deki `TTP_LIST_CACHE` reset satırı ve `docs/rbac.md`'deki `ttp-list` yetki satırı da kaldırıldı. `docs/ACIK_SORULAR.md` madde 7 silindi (bu not onun yerini alıyor, dosyanın kendi "çözülenler buradan silinir" kuralına göre).

Doğrulandı: proje genelinde (`example/` ve `data/mitre.json` hariç) `ttp_list|ttp-list|TTP_LIST_CACHE|_invalidate_ttp_cache` için sıfır kod referansı kaldı — sadece bu geçmiş kayıtlar (yukarıdaki iki not) tarihsel referans olarak duruyor. `.venv\Scripts\python.exe -m unittest discover -s tests -v`: 46/46 test geçti, hata yok.

### Teknik detay modalı sadeleştirildi + matrix daha da daraldı (2026-08-15, devam 4)

Kullanıcının mesajı üç ayrı bağlamı art arda kapsıyordu: Matrix kart genişliği → **"kartlara tıklayınca açılan kutucuk"** (= teknik detay modalı, `openModal()`) → tekrar Matrix. Modalın kendi üç sekmesi (Mitigations/Tespitler/Aksiyonlar) kullanıcının 3 maddesiyle birebir eşleşiyordu; standalone Envanter/Boşluklar ekranlarıyla (Mitigation Listesi, Tespitler, Aksiyon Planı panelleri) karıştırılmadı, onlara HİÇ dokunulmadı.

1. **Matrix kartları yatayda daraltıldı** — `.matrix-container` grid-auto-columns 176-208px→142-168px, `.tactic-column` min-width aynı oranda. Tüm 15 taktik hâlâ sığmıyor (matematiksel olarak imkansız, ~2130px gerekir) ama kaydırma azaldı.
2. **Modal: "Teknik Yapılandırması" (admin rule_threshold override'ı) kaldırıldı** — kullanıcı: "başka yerden ayarlayalım bu ekranda olmasın artık". `openModal()`'daki `if (hasRole('admin'))` bloğu (41 satır) + `.tech-config-admin`/`.cfg-source-tag` CSS'i silindi. Backend (`PUT /api/technique-config/<id>`) DOKUNULMADAN kaldı — kullanıcı "kaldır" dedi, "sil" demedi; yeniden nereye konacağı henüz belirsiz, bu yüzden yeni bir ekran İNŞA EDİLMEDİ, sadece mevcut modal'dan çıkarıldı.
3. **Modal: "Aksiyonlar" sekmesi kaldırıldı** — üçüncü tab butonu + panel + `renderModalActions()` çağrısı gitti; fonksiyonun kendisi de (tek çağrı sitesiydi) silindi. `openNewActionForTech()` KORUNDU — GAP panelindeki "+ Aksiyon" butonu (`gap-critical-add`) hâlâ kullanıyor, çapraz bağımlılık önceden doğrulandı.
4. **Modal: Mitigations sekmesi kart görselliğine kavuştu** — `.mitigation-row` (eskiden 2 kolonlu grid + alt çizgi) artık matrix kartlarıyla aynı dilde (`border:1px solid rgba(0,0,0,.2);border-radius:3px;background:var(--d-bg)`) küçük bir kart. İç içe geçen `.mitigation-entry`/`.mitigation-entry-form`'un arka planı da `var(--d-bg)`'den `var(--d-surface)`'e çekildi — yoksa yeni kart rengiyle aynı tona düşüp görünmez olacaklardı (kendi taramamda bulunan bir regresyon, kullanıcı bildirmeden önce yakalandı). Fontlar 12→11px.
5. **Modal: Tespitler sekmesi sadeleştirildi + gerçek bir mojibake bug'ı düzeltildi** — `.sub-tech-group`/`.table` padding-font küçültüldü. Ayrıca "DoÄŸrudan EÅŸleÅŸmeler" diye render olan (gerçek, uzun süredir orada duran bir çift-kodlama hatası — tahmin değil, `fetch` ile canlı sunucudan doğrulandı) metin "Doğrudan Eşleşmeler" olarak düzeltildi.
6. **Modal: akıcı açılış animasyonu** — CSS `@keyframes` ile `display:none→flex` geçişinde otomatik tetiklenen fade+scale-in (JS'in çoklu `style.display` çağrı noktalarına dokunmadan). **İlk denemede yanlış hedefe uygulandı**: `.tech-detail-modal`/`.tech-detail-backdrop` (ve 12 kardeş selector, 196 satır — `.td-section`, `.td-mit-item` vb.) tamamen ÖLÜ CSS çıktı, gerçek modal `#ruleModal.modal > .modal-content` kullanıyor. Kendi doğrulamamda (canlı DOM'da `getComputedStyle(...).animationName` kontrolü) yakalandı; animasyon doğru sınıflara taşındı, 196 satırlık ölü blok da silindi (Faz 4b'den kalma `.tech-detail-importance-row` bunun parçasıydı — modal daha önce en az bir kez baştan yazılmış, eski CSS hiç temizlenmemiş).
7. **Matrix: ürün filtresi (lejant) küçültüldü, arama command-bar'a taşındı** — `.legend-box` 10→8px, `.legend-item` 12→11px. Ayrı `.filter-bar` satırı (yalnızca Matrix'in kullandığı, doğrulanmış) tamamen kaldırıldı; `#techSearch` artık `.ms-command-bar` içinde küçük bir `.ms-inline-search` (150px, 24px yükseklik, placeholder-only, label yok). Aynı ID korunduğu için mevcut arama JS'i (wireActions) hiç değişmeden çalışmaya devam etti. `.matrix-stat-bar`'ın (bilerek sıcak tutulan) CSS'i bu temizlikte YANLIŞLIKLA silinmesin diye ayrıca ayrıştırıldı.

**Renk paleti hâlâ kullanıcının seçimini bekliyor** (bkz. bir önceki round) — bu turdaki hiçbir değişiklik ona dokunmadı.

Doğrulandı (gerçek tıklama/etkileşimle): modal 2 sekmeli (Mitigations/Tespitler) açılıyor, Teknik Yapılandırması ve Aksiyonlar DOM'da yok; `.mitigation-row` kartları hem checked hem unchecked durumda doğru renk/boyutta, iç içe `.mitigation-entry` arka planı satırdan ayrışıyor; "Doğrudan Eşleşmeler" doğru render oluyor; modal/backdrop/tab-panel'in `animationName`'i doğru CSS sınıflarına bağlı; arama hâlâ 254→1 filtreliyor, `.filter-bar` DOM'da yok, lejant tıkla-izole hâlâ çalışıyor; 6 standalone panel (Mitigation/Tespitler/Aksiyon Planı/GAP/Kapsam/Ayarlar) hiç dokunulmamış, hepsi normal açılıyor. 46/46 test, konsol hatası yok. `styles.css?v=132`, `app.js?v=138`.

### Bug: uzun taktik adları başlığı 2 satıra sarıp kart yığınını kaydırıyordu (2026-08-15, devam 5)

Kullanıcı: *"Resource Development kutucuğu aşşa taşmış"*. Kök neden: bir önceki turda `.tactic-column`/`.matrix-container` yatayda daraltıldı (min 176→142px) ama `.tactic-header`'ın font/padding'i buna göre küçültülmedi — 15 taktikten 2'si ("Resource Development", "Command and Control") artık 142px'e tek satırda sığmıyordu, 2 satıra sarıp o kolonun başlığını (44.78px) diğer 13 kolonunkinden (31px) uzun yapıyordu; sonuç o iki kolonun kart yığını komşularına göre ~14px aşağı kaymış görünüyordu (üst üste binme değil, hizasızlık).

Canlı DOM'da ölçülerek doğrulandı: en uzun 2 ad, en dar kolon genişliğinde (142px − padding) `font-size:10px` ile tek satıra sığıyor (11px'te sığmıyordu). `.tactic-header`: `font-size` 11→10px, `padding` 6px 8px→5px 6px, artı savunma amaçlı `white-space:nowrap` (ölçüm yanlışsa sessizce sarıp hizasızlığı geri getirmesin, bunun yerine yatayda taşar — fark edilir, hizasızlık gibi sessiz değil).

Doğrulandı: `.venv` testleri bu turda çalıştırılmadı (salt CSS, testlerle kesişmiyor) ama canlı DOM'da 15 başlığın hepsi artık tam `height:31px` (tek yükseklik) ve hiçbiri `scrollWidth>clientWidth` değil (yatay taşma da yok). Konsol hatası yok. `styles.css?v=133`.

### Skorlama metodolojisi araştırıldı ve belgelendi — kod DEĞİŞMEDİ (2026-08-15, devam 6)

Kullanıcı ile uzun bir araştırma turu: mevcut renklendirmenin ("kaç tespit
hangi renk") hangi metodolojiye dayandığı sorgulandı. DeTT&CT, MITRE ATT&CK
Navigator layer formatı, MITRE INFORM (Center for Threat-Informed Defense),
ve çeşitli akademik/pratisyen kaynaklar tarandı — sonuç `docs/scoring_methodology.md`'ye
yazıldı. Özet kararlar (tam gerekçe ve kaynaklar belgede):

1. `coverage_level` 3→4 seviye (`düşük`/`yarım`/`iyi`/`tam` = 0.25/0.50/0.75/1.00) —
   DeTT&CT'nin Visibility Score'unun (1-4) birebir karşılığı.
2. `rule_threshold` tekdüze değil, `technique_config.group_count`'a (MITRE'nin
   kendi yaygınlık verisi) göre 3 dilim — gerçek veriyle doğrulandı: T1078
   Valid Accounts bizim en yüksek group_count'lu tekniğimiz VE Red Canary
   2026 raporunun "2 yıldır #1" bulgusuyla örtüşüyor.
3. Rollup formülü Navigator/DeTT&CT'nin `sum` varsayılanına dayanıyor ama ham
   etkin sayı yerine **"karşılanmamış boşluk" toplanıyor** (`eksik = max(0,
   hedef−etkin)`, alt teknik hedefini aşarsa fazlası üste taşınmaz) — bu hem
   çifte sayım bug'ını (aynı kural üst+birden fazla alt tekniğe eşliyse)
   hem de "çok alt tekniği olan aile = imkansız hedef" sorununu (gerçek
   veride T1027/T1546 18'er alt teknikle, DB'de sadece 323 kural/254 teknik
   varken eski toplama modeliyle asla yeşillenemezlerdi) tek mekanizmayla
   çözüyor.

Süreçte kendi kendine yakalanıp düzeltilen 2 hata (şeffaflık için not):
araştırmanın ilk turunda "DeTT&CT'de `max` yaygın" dendi, birincil kaynağa
(DeTT&CT'nin kendi `navigator_layer.py` kodu) bakılınca gerçekte `sum`
olduğu görüldü, düzeltildi. Aynı şekilde CISA "Best Practices for MITRE
ATT&CK Mapping" belgesi kaynak listesine alelacele eklenmişti — içeriği
kontrol edilince bunun skorlama değil eşleme-doğruluğu rehberi olduğu
anlaşıldı, kapsam dışı bırakıldı.

**Kod tarafında HENÜZ değişiklik yok** — bu tur salt araştırma+belgeleme.
Uygulama sırası ve dilim sınırları netleşince `familyRollup()` (app.js) ve
`_compute_gap_analysis()` (app.py) güncellenecek, ikisi senkron kalmalı.

### Skorlama metodolojisi uygulandı: 4 seviye + satır bazlı tiering + boşluk-tabanlı rollup (2026-08-15, devam 7)

Bir önceki turun ("devam 6") belgelediği metodoloji koda geçirildi. Kullanıcı: *"tamamdır artık kod tarafına girebiliriz. Tüm değişiklikleri yapalım"*.

1. **`coverage_level` 3→4 seviye.** Şema/validasyon (3 ayrı liste: import planlayıcı, Veri Kalitesi, `PATCH /api/rules/<id>/coverage`) `low/half/good/full` = 0.25/0.50/0.75/1.00'e genişledi. `migrate_coverage_level_partial_to_half()` mevcut `partial` (0.60) satırlarını `half`'a taşıdı — daha yakın sayısal komşu + "yanlış özgüvenden kaçınma" gerekçesiyle (kullanıcı: "kafana göre ayır"). Frontend: ağırlık sözlüğü, `COV_LABEL`, slider `snapLevel`/`levelColor` (4'e bölündü), bulk seçici, import-önizleme etiketi. Ölü `COV_CYCLE` silindi.
2. **`rule_threshold` tiering — planla FARK.** "devam 6"da "aile bazlı MAX group_count" olarak belgelenmişti; kodu yazarken (kullanıcıya danışılmadan, teknik gerekçeyle) SATIR bazlı tiering'e çevrildi: her teknik (ana/alt fark etmez) KENDİ `group_count`'una göre dilimlenir (`_prevalence_tier_threshold`: <5→1, 5-19→2, 20+→3). Gerekçe: aile-genel MAX, "18 alt tekniği olan ama çoğu nadir" bir ailede nadir alt tekniklere de yüksek hedef dayatırdı. Gerçek dağılımla kalibre edildi (714 satır: medyan 2, p90=17 → 508/145/61 satır dağılımı).
3. **Rollup boşluk-tabanlı model.** `eksik(alt)=max(0,hedef-etkin)`, `üst.hedef=kendi_hedef+Σeksik(alt)`, `üst.etkin=SADECE kendi` — `_compute_gap_analysis` (app.py) ve `familyRollup()` (app.js) senkron yeniden yazıldı. İki somut bug çözüldü: aynı kuralın üst+alt tekniğe eşliyse çifte sayılması, ve alt teknik SAYISIYLA (kapsanma durumuyla değil) orantılı büyüyen gerçekçi olmayan hedef.
4. **Kritik ek bug (uygulama sırasında bulundu, planda yoktu): geriye dönük veri geçişi eksikti.** `build_technique_config()`'in `INSERT OR IGNORE`'u var olan `tech_id` satırlarına asla dokunmaz — yeni tiering formülü, taze bir DB'de çalışır ama bu projenin aylardır biriken canlı `soc.db`'sinde (714 satırın hepsi zaten vardı) SESSİZCE hiç etkisi olmazdı. Canlı sunucuda `fetch('/api/gap-analysis')` ile T1546 ailesi kontrol edilirken yakalandı (T1546.008: group_count=6, ama threshold hâlâ eski değerdeydi). `drop_technique_importance()`'ın (Faz 4b) aynı sorunu çözdüğü desen tekrarlandı: yeni `migrate_technique_config_thresholds_to_prevalence_tiers()`, `source='auto'` satırlarını saklı `group_count` üzerinden `CASE` ile yeniden dilimler, `source='admin'` asla dokunulmaz; `build_technique_config(db)`'den hemen sonra çağrılır (`init_db()` zinciri).
5. **Doküman taraması** — `coverage_level` eski 3 değerine (`partial`) kalan referanslar: `docs/mitre_mapping_prompt.md` (KRİTİK — LLM içe aktarım prompt'u, örnek JSON + skor hesap örneği; ayrıca önceden hep yanlış olan bir örnek hesap da bu sırada düzeltildi: `PRODUCT_CLAIM_SCORE_WEIGHT` çarpanı eksikti), `README.md` (Kapsama Puanlaması bölümü baştan yazıldı), `templates/docs.html` (4 ayrı nokta: CSV alan tablosu, "Etkin tespit" bilgi kutusu + "Hedef" paragrafı — flat 2/1 varsayımından tiered açıklamaya çevrildi, 2 worked-example kartının sayıları). `monitoring_status` alanının (tamamen ayrı bir kavram) "partial" değeri kasıtlı olarak dokunulmadı.
6. **Testler: 46→49.** 3 bozuk çağrı sitesi (silinen `ensure_subtechnique_default_threshold`) temizlendi; rollup testi ve tiering testi yeni formüle göre yeniden hesaplanıp yeniden yazıldı (`test_parent_score_rolls_up_from_subtechniques_with_per_sub_cap`, `test_subtechnique_threshold_tiers_from_own_group_count_admin_override_preserved`). Paylaşılan `mitre_fixture()`'a T1000/T1001 için group_count=5 (tier 2) eklendi — `DEFAULT_RULE_THRESHOLD` varsayımına dolaylı bağımlı onlarca testi sıfır değişiklikle kurtardı. 3 yeni test: `test_rollup_effective_counts_shared_rule_once_not_per_mapping` (çifte sayım kanıtı), `test_coverage_level_weights_are_four_tiers` (4 ağırlık), `test_prevalence_tier_threshold_boundaries` (dilim sınırları, saf fonksiyon).

Doğrulandı: 49/49 test geçti. Canlı sunucuda (`fetch` ile gerçek `/api/technique-config` + `/api/gap-analysis`): 714 teknikten 9'u admin override (dokunulmadı, doğru), kalan 705'i doğru dilime taşındı; T1546 ailesi (18 alt teknik) gap-based rollup ile makul bir skor üretiyor (`rule_threshold=5.5`, eskiden sabit toplamla ulaşılamaz olurdu). Slider DOM'da 4 seviye render ediyor (`half`: `#ca8a04`/"Yarım" canlı veriyle doğrulandı; `low`/`good`'un DB'de henüz örneği yok ama CSS+bulk seçici doğrulandı), konsol hatası yok. `docs/scoring_methodology.md`'nin "Uygulama durumu" bölümü güncellendi. `styles.css?v=134`, `app.js?v=139`.

### `/docs` bilgilendirme wiki'si baştan taranıp güncellendi (2026-08-15, devam 8)

Kullanıcı: *"bilgilendirme sayfaını ogüncelle. çıakrdığımız şeyleri sil bide bu metodolojiyi falan ekleyelim oraya geeksiz fazlalaıları temizle"*. `templates/docs.html` (930 satır, /docs route) aylardır biriken görsel yeniden tasarım turlarından (Faz 4c'den bu yana ~20 tur) sonra hiç taranmamıştı — kod değişiklikleriyle wiki metni arasında ciddi bir makas açılmıştı. Her iddia canlı DOM/CSSOM'da veya ilgili backend fonksiyonunda doğrulanmadan düzeltilmedi (sadece task başlıklarından tahmin YOK).

**Kaldırılmış özelliklere ait dead dokümantasyon silindi:**
- **TTP Listesi** — nav butonu, overview kartı, Hızlı Başlangıç adımı, tüm `w-ttp` sayfası. Backend zaten "devam 3"te silinmişti (`/api/ttp-list`, `TTP_LIST_CACHE`); wiki hiç güncellenmemiş.
- **Teknik modalının "Admin" sekmesi** (rule_threshold override UI'ı) — modal'dan kaldırılalı uzun süre olmuş (bkz. yukarıda "devam 4"), API (`PUT /api/technique-config/<id>`) hâlâ çalışıyor ama ekranda hiçbir yolu yok; 2 ayrı bölüm bunu var gibi anlatıyordu, düzeltildi + "Teknik Bazlı Yapılandırma" adlı ayrı bölüm (fazlalıktı, Formül bölümündeki Hedef paragrafıyla örtüşüyordu) tamamen kaldırıldı.
- **Kapsam Envanteri "Varlık Grubu" seviyesi** — Faz 4a'da (`flatten_asset_groups`, `asset_groups` tablosu DROP) Ortam>Varlık Grubu>Ürün üç seviyeden Ortam>Ürün iki seviyeye indirilmişti; wiki hâlâ üç seviyeli sınıflandırma tablosu gösteriyordu, "Yetki ve Audit" paragrafı da "varlık grupları" yönetiminden bahsediyordu.

**Kod değiştiği halde hiç güncellenmemiş açıklamalar düzeltildi (canlı doğrulamayla):**
- **Renk sistemi tamamen yeniden yazıldı.** Wiki hâlâ eski RGBA-saydamlık modelini (5 durak: 0/0.30/0.50/0.70/1.00, ana kart %20 / alt kart %13 opaklık) anlatıyordu — gerçek sistem (`app.js` `_SCORE_STOPS`/`_ZERO_COLOR`, canlı DOM'da `getComputedStyle` ile doğrulandı) tamamen OPAK, 4 durak (0/0.45/0.70/1.00), ana/alt kart aynı renk, otomatik siyah/beyaz metin kontrastı. Hem "Renk Kodu" sayfası hem Matris sayfasındaki kısa özet hem de `styles.css`'teki `.wgb-track`'in kendi gradient CSS'i (bu da eski renklerle hardcode'lanmıştı) düzeltildi.
- **Kart göstergeleri tablosu** — "sağ altta ok, alt teknik var demek" iddiası yanlıştı (CSS/JS'de hiç ok yok, keşif salt hover ile); "sol renkli şerit" iddiası da yanlıştı (`.source-stripe` CSS'i var ama `app.js` hiçbir yerde kullanmıyor — dead code, dokunulmadı çünkü kapsam dışıydı, sadece dokümantasyonu düzeltildi). Gerçek: ad üstte + ID altta (kart yüzü), ürün noktaları sağ üst köşede (sağ ALT değil).
- **Veri Kalitesi kontrol listesi** — mevcut 4 madde ("kanıtsız doğrulamalar", "sahipsiz telemetry", "data component eşleşmesi") SOC-CMM döneminden kalma dead içerikti, `_compute_data_quality()` (app.py) bunların HİÇBİRİNİ kontrol etmiyor. Gerçek 7 kontrol + ağırlıklı Kalite Skoru formülüyle değiştirildi.
- **İçe Aktarım doğrulama tablosu** — "tanınmayan teknik ID'si hata üretir" artık yanlış; CLAUDE.md'deki düzeltmeye göre bu artık sadece UYARI (satır atlanır, kural yine oluşturulur, dosya bloklanmaz).
- **15 taktik / 220+ teknik** — "14 taktik / 200+" eskiydi (Defense Evasion → Stealth + Defense Impairment ayrımından sonra 15 oldu), canlı `/api/gap-analysis` ile sayıldı.

**Eklenen:** Puanlama sayfasına "Bu Yöntemin Dayanağı" bölümü — `docs/scoring_methodology.md`'nin özeti (DeTT&CT Visibility Score, MITRE Navigator/DeTT&CT'nin `sum` agregasyonu, T1078/Red Canary doğrulaması, MITRE INFORM'un "mühendislik kararı, uyarla" felsefesi), tam belgeye link.

**Not (kapsam dışı bırakıldı, sadece kayıt için):** `app.py`'deki `_score_to_report_color()` (PDF rapor renkleri) docstring'i hâlâ "uygulamanın koyu temadaki `scoreToColor()` ile aynı 5 duraklı gradyanı kullanır" diyor — bu artık yanlış (canlı gradyan 4 durak), ama raporun kendi renk paleti (açık/pastel, print için) BİLİNÇLİ olarak farklı tutulmuş, sadece docstring'deki "aynı" iddiası yanlış. Küçük, düşük öncelikli, bu turun kapsamı dışında.

Doğrulandı: `.venv\Scripts\python.exe -m unittest discover -s tests -v` 49/49 (docs/CSS değişikliği testleri etkilemedi ama regresyon kontrolü yapıldı). Canlı `/docs`'ta: nav'da 12 madde (TTP Listesi yok), `.wgb-track` computed background yeni gradyanla birebir, "Bu Yöntemin Dayanağı" başlığı DOM'da, konsol hatası yok. `styles.css?v=135` (hem `index.html` hem `docs.html`).

### Rollup formülü hibrit modele düzeltildi — bug kullanıcı tarafından ekran görüntüsüyle yakalandı (2026-08-15, devam 9)

Kullanıcı bir Matrix ekran görüntüsü paylaştı: T1205 (Traffic Signaling) ailesinde T1205.001 (Port Knocking) yeşil, T1205.002 (Socket Filters) sarı, ama üst teknik kartı dümdüz koyu (kapsanmamış) görünüyordu. Soru: *"biz böyle mi olsun istemiştik... metodolojimiz doğru mudur?"*

Canlı `/api/gap-analysis` ile doğrulandı: T1205.001 hedef=1/etkin=1.75 (skor 1.0), T1205.002 hedef=1/etkin=0.75 (skor 0.75), ama üst teknik hedef=0.25/etkin=**0**/skor=**0**. Bir önceki turun ("devam 7") "boşluk tabanlı" rollup formülü gerçek bir hataydı: payda (`kendi_hedef + Σ max(0,alt_hedef-alt_etkin)`) alt tekniklerin ilerlemesiyle küçülüyordu ama pay (`SADECE kendi doğrudan kuralı`) bunu hiç yakalamıyordu — üst teknikler pratikte neredeyse hiç doğrudan kural almadığı için (kurallar hep alt tekniğe yazılıyor), tek bir alt teknik bile %100 mükemmel değilse oran `0/pozitif=0`'a çöküyordu. Payda "kalan boşluk", pay "ayrı bir sayı" idi — ölçek uyuşmazlığı.

**Kullanıcının talimatı: "iki türlü sorun çıkarmayacak bir çözüm yap... çakışmayı da halledecek bu sorunu da çözecek bir yöntem bulacaksın"** — yani hem YENİ bulunan bug (T1205) hem ORİJİNAL motivasyon (T1027/T1546, 18 alt teknikli aileler "boşluk tabanlı" formülden ÖNCEKİ "ham toplama" modelinde asla yeşillenemiyordu) aynı anda çözülecekti, ödünleşim kabul edilmedi.

**Çözüm: `family_etkin = min(cappedSum, dedupedSum)`.**
- `cappedSum = min(kendi_etkin,kendi_hedef) + Σ min(alt_etkin,alt_hedef)` — her üye kendi hedefinde tavanlanıp TAM toplanır (eski "ham toplama" modelinin payı, tek başına çifte-sayıma açık).
- `dedupedSum` = ailenin (kendi+tüm altlar) dokunduğu BENZERSİZ `rule_id`'lerin toplam ağırlığı — aynı kural birden fazla üyeye eşliyse (built-in motor senaryosu) yalnızca bir kez sayılır.
- `family_hedef = kendi_hedef + Σ alt_hedef` (TAM toplam, boşluk değil — pay ile aynı ölçekte olması için şart).
- İki güvence FARKLI aşırı-sayma senaryosunu önler (cappedSum: paylaşılan tek kural N kez sayılmasın; dedupedSum: bir alt teknikteki bağımsız fazlalık kardeşe taşmasın), `min()` ikisini birden garanti eder.

**Implementasyon:** `rule_stats_by_tech`'i besleyen SQL sorgusu `GROUP BY` kaldırılıp ungrouped çekildi (rule_id'yi kaybetmemek için — dedup'a ihtiyaç var); Python'da hem eski per-tech toplamlar hem yeni `rule_weight`/`tech_to_rule_ids` sözlükleri tek geçişte kuruluyor. `familyRollup()` (app.js) aynı mantıkla `Map`-tabanlı dedup kullanacak şekilde yeniden yazıldı.

**Canlı doğrulama:**
| Aile | Eski (boşluk-tabanlı) | Yeni (hibrit) |
|---|---|---|
| T1205 (2 alt teknik) | %0 ← hatalı | **%87.5** |
| T1546 (18 alt teknik) | asla ulaşılamaz hedef | **%19.4** — ve gerçekten `dedupedSum` bağlayıcı: çoğu alt teknik aynı 0.75 değerini taşıyor (paylaşılan tek bir toplu ürün iddiası), `cappedSum` (14.5) değil `dedupedSum` (3.88) skoru belirliyor — tam tasarlandığı gibi çalışıyor. |

Frontend/backend senkronu canlı DOM'da doğrulandı: T1205 kartı artık `rgb(146,175,95)` (sarı-yeşil, %88) gösteriyor, `data-score-data` içindeki `weightedRuleCount`/`threshold`/`score` backend API'siyle birebir eşleşiyor.

Testler: `test_parent_score_rolls_up_from_subtechniques_with_per_sub_cap` ve `test_rollup_effective_counts_shared_rule_once_not_per_mapping` yeni sayılarla yeniden hesaplandı; yeni `test_rollup_sub_surplus_does_not_cover_sibling_gap` eklendi (cappedSum'un bağlayıcı olduğu, dedupedSum'un DEĞİL, senaryoyu doğrular — önceki testler yanlışlıkla hep dedupedSum'un bağlayıcı olmadığı veya iki değerin eşit çıktığı senaryolardı, bu boşluğu kapatır). `docs/scoring_methodology.md` #3 tamamen yeniden yazıldı — iki başarısız ara deneme de (ham toplama, boşluk-tabanlı) şeffaflık için belgede tutuluyor.

Doğrulandı: 50/50 test geçti. `app.js?v=140` (styles.css değişmedi, `v=135` kalıyor).

### Kullanıcının 6 maddelik geri bildirimi — UI düzeltmeleri ve yeni özellikler (2026-08-15, devam 10)

1. **Kapsam slider "buglı" bulundu — gerçek kök neden bulundu.** Slider'ın kendisi (CSS `[data-level]`, PATCH kaydı) doğru çalışıyordu — canlı DOM'da tavan testiyle (`transition:none` + zorla reflow) doğrulandı, PATCH de gerçekten kaydediyordu. Asıl bug: satır bazlı slider `renderMatrix()`'i hiç çağırmıyordu — kaydediyordu ama Harita ekranına dönünce renk eskiden kalıyordu, kullanıcı bunu "çalışmıyor" olarak yorumladı (toplu değiştirme butonu zaten `renderMatrix()` çağırıyordu, satır bazlı slider çağırmıyordu — tutarsızlık). `persistLevel()`'a `renderMatrix()` eklendi.
2. **"Kapsam" adı ve sarı kesikli çerçeve (`.claim-only`)** — kullanıcıya soruldu, cevap bekleniyor (aşağıda not).
3. **Viewer rolü artık sadece Harita'yı görüyor.** `applyRoleUI()`'a `.nav-item[data-section="inventory"|"gaps"]` için `!hasRole('editor')` kontrolü eklendi. Ayarlar bilinçli olarak HERKESE açık kalıyor (self-servis parola değişimi, önceden de böyleydi). Canlı test: gerçek viewer girişiyle doğrulandı (nav'da Envanter/Boşluklar `hidden`, Harita/Ayarlar değil).
4. **Modal: varsayılan sekme Tespitler oldu, açılış "yavaşlığı" asıl nedeni bulundu.** Animasyon süresi zaten hızlıydı (150-180ms) — asıl sorun `display:flex`'in fonksiyonun EN SONUNDA (tüm asenkron mitigation fetch'inden SONRA) atanmasıydı; kullanıcı tıklayınca hiçbir şey görünmeden bir süre bekliyordu, sonra her şey birden açılıyordu. `display:flex` artık fonksiyonun EN BAŞINA taşındı — modal anında açılır animasyonuyla belirir, içerik arkadan asenkron dolar. Tab sırası da değişti (Tespitler önce/varsayılan, Mitigations sonra). Bu değişikliği yaparken bir kopyala-yapıştır hatası (mitigationsTab hiç `body`'ye eklenmiyordu, rulesTab iki kez ekleniyordu) fark edilip aynı turda düzeltildi.
5. **PDF/yönetici raporu — somut bir sorun bulunup düzeltildi, tam yenileme değil.** Bu ortamda ekran görüntüsü alınamadığı için körü körüne "güzelleştirme" yapmak yerine DOM/CSSOM üzerinden ölçülebilir bir sorun arandı: dense matrix'teki hücrelerin **%79'unda** mor "M" (mitigation) rozeti vardı — canlı haritada Faz 4'te ZATEN terk edilmiş olan "mitigation kart yüzünü boğuyor" durumunun aynısı, rapora hiç yansıtılmamıştı. Rozet dense matrix'ten kaldırıldı (Tam Teknik Listesi ekindeki "Mitigation: Var/—" sütunu zaten bilgiyi taşıyor, kaybolmuyor), dead CSS (`.rpt-m-flag`, `.rpt-legend-flag`) silindi. Kullanıcıdan sayfayı kendi gözüyle görüp varsa BAŞKA somut sorunları işaret etmesi istendi — kör tahminle tam yenileme yapılmadı.
6. **Modal: Tespitler sekmesinden teknik eşlemesi kaldırma eklendi.** Her kural satırına "Bu Teknikten Kaldır" butonu — `DELETE /api/rules/<id>/techniques/<tech_id>` zaten vardı (backend değişikliği gerekmedi), yeni `unlinkRuleTechnique()` `deleteRule()`'un aynı düzenini izliyor (modal kapanır, liste+harita yenilenir). Canlı uçtan uca test edildi (gerçek bir eşleme kaldırılıp API'den doğrulandı, sonra test verisine zarar vermemek için geri eklendi).

**Açık kalan (kullanıcı cevabı bekleniyor):** "Kapsam" adının neye değişeceği, ve `.claim-only` sarı kesikli çerçevenin (yalnızca toplu ürün iddiasıyla kapsanmış, adı olan tespiti olmayan teknikleri işaretliyor — T1205 sohbetindeki tam konu) kaldırılıp kaldırılmayacağı.

Doğrulandı: `.venv\Scripts\python.exe -m unittest discover -s tests -v` 50/50 (tüm değişiklikler frontend/template, backend testi etkilemedi ama regresyon kontrolü yapıldı). Canlı doğrulama: slider→renderMatrix, gerçek viewer girişiyle nav gizleme, modal tab sırası+DOM bütünlüğü (mitigationsTab kaybı fark edilip düzeltildi), unlink→API round-trip, rapor M-flag sayısı 79%→0. `app.js?v=141`.

**Açık kalan 2 madde de kullanıcı cevabıyla kapatıldı (aynı gün, devam):**
- **"Kapsam" → "Tespit Gücü"** — Tespitler ekranındaki kolon başlığı, toplu değiştirme butonu/mesajları, içe aktarım önizleme tablosu ve `docs.html`'deki karşılık gelen madde. Yalnızca GÖRÜNEN Türkçe etiket değişti — `coverage_level` API/şema alan adı, CSV sütun adı ve `COV_LABEL` içindeki seviye adları (Düşük/Yarım/İyi/Tam) aynı kaldı, kapsam bilinçli olarak dar tutuldu.
- **`.claim-only` sarı kesikli çerçeve kaldırıldı** — kullanıcı anlamını öğrendikten sonra yine de kaldırılmasını istedi. CSS kuralı (`styles.css`) ve JS `classList.toggle('claim-only', ...)` (`app.js`) birlikte silindi — kalan tek referans olmadığı grep ile doğrulandı. Bu sinyal artık hiçbir yerde yok (hover tooltip'teki "Yalnız ürün iddiası" uyarı satırı ayrı bir mekanizma, ondan etkilenmedi).

Doğrulandı: 50/50 test. Canlı: kolon başlığı "Tespit Gücü", buton "Tespit Gücünü Değiştir", `.claim-only` DOM'da sıfır kart (T1205.002 örneğiyle özellikle kontrol edildi — `borderStyle:solid`, sarı yok). `styles.css?v=136`, `app.js?v=142`.

### Rapordan "hedef" gösterimi kaldırıldı + yeni "Teknik Hedefleri" admin ekranı (2026-08-15, devam 11)

Kullanıcı: *"Raporda tekniklerdeki hedef kısmını çıkar... hiçbir yerde yöneticiye falan hedef göstermeyelim"* + *"hangi tekniğe kaç tespit lazım olur — liste görünümü... admin görsün sadece envanter kısmına koyarız matrixde bulunmasın"*.

1. **`templates/report.html`'den TÜM "hedef" (rule_threshold) gösterimleri kaldırıldı** — kart altyazısı, matris notu ve hücre tooltip'i (artık sadece `%X`), Tam Teknik Listesi ekindeki **"Etkin / Hedef" sütunu tamamen silindi** (yanındaki "Skor" sütunu zaten yüzdeyi veriyordu, ikinci bir yüzde sütunu eklemek yerine var olanı yeterli görüldü — kullanıcının "yüzde koy" isteği zaten karşılanmış durumdaydı). `t.rule_threshold`/`t.effective_rule_count` backend'de hesaplanmaya devam ediyor (başka yerlerde kullanılıyor), sadece template'te render edilmiyor.
2. **Yeni "Teknik Hedefleri" ekranı — Envanter bölümünde, admin-only.** `SECTIONS.inventory.tabs`'a `{panel:'targetsPanel', role:'admin'}` eklendi (Audit'in `role:'admin'` deseniyle birebir aynı mekanizma — `visibleTabs()` zaten `role` alanına göre filtreliyor, yeni bir RBAC dalı gerekmedi). Liste görünümü: `techDetailsMap`'teki tüm teknikler (ana+alt, 697 satır), varsayılan `group_count` azalana göre sıralı (en yaygın/öncelikli önce), arama kutusu (ID/ad), her satırda düzenlenebilir "Hedef" input'u (`PUT /api/technique-config/<id>` — zaten vardı, Faz 4c'de modal'dan kaldırılan admin sekmesiyle aynı backend, yeni bir endpoint gerekmedi). Kaydedince kısa yeşil flaş + `renderMatrix()` (açıksa Matrix'teki kart hemen güncellensin diye). Alt tekniklerin "Taktik" sütunu üst tekniğin taktiğinden miras alınır (MITRE STIX verisinde alt tekniklerin kendi `kill_chain_phases`'ı `prepareMitreLookup()`'ta hiç işlenmiyor).
3. **Matrix'e KESİNLİKLE eklenmedi** — ayrı bir panel/tab, `renderMatrix()`'e hiç dokunulmadı, kullanıcının açık isteğiyle uyumlu.

Doğrulandı: 50/50 test. Canlı: rapor gövdesinde "hedef" kelimesi sıfır, ek tablo başlıkları `[ID, Ad, Skor, Mitigation, Ürünler]`. Yeni ekran: 697 satır render, T1205 ailesi üzerinden gerçek düzenleme testi (T1205.002 hedefini 1→2 değiştirip kaydettim, `/api/technique-config` üzerinden `source:"admin"` olarak doğruladım, T1205'in rollup skorunun buna göre değiştiğini gördüm — sonra gerçek veriye zarar vermemek için `sqlite3` ile satırı `rule_threshold=1, source='auto'` olarak eski haline döndürdüm). Editor girişiyle sekmenin görünmediği doğrulandı (sadece Tespitler/Ortam & Kapsam/Mitigation görünüyor). `app.js?v=143`, `styles.css?v=137`.

## Connector Yol Haritası

- **Faz 1 — QRadar:** Use Case Manager mapping API, native rule ID uzlaştırma, sync geçmişi, stale yönetimi ve Audit tamamlandı. Mock QRadar HTTP servisiyle duplicate önleme doğrulandı; kurum QRadar instance kabul testi bekliyor.
- **Faz 2 — QRadar genişletme:** log source activity/coverage, tuning findings, offense count ve son aktivite metrikleri.
- **Faz 3 — Defender (beklemede):** Microsoft Graph `alerts_v2` ile built-in aktivite; custom detection envanteri için Git/JSON öncelikli model. QRadar kabulü tamamlanana kadar uygulanmayacak.
- **Faz 4 — Detection as Code:** custom detection repository, sürüm ve deployment durumunun connector kayıtlarına bağlanması.
