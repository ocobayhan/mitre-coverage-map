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
