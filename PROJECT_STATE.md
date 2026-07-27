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
