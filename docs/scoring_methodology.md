# Kapsama Skorlama Metodolojisi

Bu belge, Matrix'teki her teknik kartının rengini belirleyen formülün **neye
dayandığını** ve **neden böyle tasarlandığını** kaydeder. Amaç: birisi
"neden bu teknik sarı, neden bu sayı" diye sorduğunda cevabın "kafamıza göre"
değil, işaret edilebilir bir kaynak/gerekçe olması. 2026-08-15'te, birden
çok araştırma turu ve gerçek veriyle test edilerek karara bağlandı.

Ana ilke, MITRE'nin kendi resmi olgunluk çerçevesinin (aşağıda madde 5)
söylediği gibi: bu formül "bilimsel olarak kanıtlanmış" değildir, **mühendislik
kararıdır** — ama her parçası isimlendirilmiş bir kaynağa veya ölçülmüş gerçek
veriye dayanır, rastgele seçilmemiştir.

---

## 1. Kural kalite ağırlığı (`rules.coverage_level`)

Her kural, tekniği ne kadar iyi kapsadığına göre 4 seviyeden birine
işaretlenir ve bu seviyeye göre ağırlıklanır:

| Seviye | Ağırlık | Kaynak (DeTT&CT Visibility Score) |
|---|---|---|
| düşük | 0.25 | Seviye 1/4 "Minimal" — *"sufficient data sources... to see **one aspect** of the technique's procedures"* |
| yarım | 0.50 | Seviye 2/4 "Medium" — *"...to see **more aspects**... compared to Minimal"* |
| iyi | 0.75 | Seviye 3/4 "Good" — *"...to see **almost all** known aspects"* |
| tam | 1.00 | Seviye 4/4 "Excellent" — *"**all** known aspects... available"* |

Kaynak: [DeTT&CT Wiki — Visibility Scoring](https://github.com/rabobank-cdc/DeTTECT/wiki/Visibility-scoring)
(tablo birebir alıntı, parafraz değil).

**Neden DeTT&CT'nin -1..5 (7 seviyeli) niteliksel tespit skoru değil de bu
basitleştirilmiş 4 seviye?** DeTT&CT'nin tam modeli her tespidi elle,
sübjektif kriterlerle (analitik karmaşıklık, gerçek-zamanlılık, atlatılma
direnci) puanlamayı gerektiriyor — bu, kural eklerken ek bir değerlendirme
adımı demek. Bulduğumuz pratisyen kaynakları, olgunluğun erken evresindeki
programların basit "stoplight" (3-4 kovalı) modelle başlamasının **beklenen
ve meşru** bir yaklaşım olduğunu, olgunlaştıkça daha ayrıntılı skalaya
geçilebileceğini belirtiyor (bkz. madde 6). Biz zaten bu basitleştirilmiş
modele (o zamanki adıyla "kapsam seviyesi") sahiptik; bu tur sadece onu
DeTT&CT'nin ölçeğine açıkça bağladı ve `partial` tek seviyesini ikiye
bölerek (`yarım`/`iyi`) DeTT&CT'nin 4 kullanılabilir seviyesiyle (1-4)
birebir örtüştürdü.

**Mevcut veri geçişi:** DB'deki eski `partial` (0.60) kayıtlarının hepsi
`yarım`'a (0.50) taşınır — 0.60'a en yakın komşu odur (0.75'ten 0.05 daha
yakın) ve kapsama aracında yanlış-güven vermektense düşük göstermek daha
güvenli taraftır. Editörler istedikleri kaydı sonradan tek tek `iyi`'ye
çekebilir.

---

## 2. Teknik başına hedef (`rule_threshold`) — yaygınlığa göre

Her tekniğin "yeterli kapsama" için kaç etkin tespit istediği, o tekniğin
gerçek dünyada ne kadar yaygın kullanıldığına göre değişir — hepsi aynı
sabit sayıda değil.

**Sinyal kaynağı:** `technique_config.group_count` — MITRE'nin kendi
mitre.json verisinden (`build_technique_config()`), kaç tehdit grubunun bu
tekniği kullandığı. Üçüncü parti raporları (yıllık, elle senkron tutulması
gereken) değil, otomatik güncellenen birincil MITRE verisini temel aldık.

**Neden yaygınlığa göre değişsin — literatür desteği:** Taradığımız risk
skorlama çerçevelerinin hemen hepsinde prevalans bir faktör olarak geçiyor
(örn. bir akademik model 7 metrikten birine prevalansı ağırlık veriyor; SANS
kaynaklı pratisyen tavsiyesi "önce credential theft/lateral movement gibi
yüksek riskli tekniklere odaklan, tekdüze kapsama peşinde koşma" diyor).

**Gerçek veriyle doğrulama:** Kendi `group_count` verimizde en yüksek
tekniklerden biri **T1078 Valid Accounts** (group_count=44, 4 ayrı taktikte
en yüksek teknik) — bu, Red Canary'nin 2026 Threat Detection Report'unda
"Cloud Accounts 2. yılıdır #1" bulgusuyla birebir örtüşüyor. MITRE'nin kendi
verisi ile gerçek dünya tehdit raporları aynı şeyi söylüyor; `group_count`'a
güvenmek tesadüfi değil.

Kaynaklar:
[Top ATT&CK Techniques — Red Canary](https://redcanary.com/threat-detection-report/techniques/) ·
[Red Canary 2026 Threat Detection Report](https://redcanary.com/blog/threat-detection/2026-threat-detection-report/) ·
[The Top Ten MITRE ATT&CK Techniques — Picus](https://www.picussecurity.com/resource/the-top-ten-mitre-attack-techniques)

**Aile (üst+alt teknikler) için hangi group_count kullanılır — önemli
düzeltme:** Üst tekniğin KENDİ `group_count`'u tek başına güvenilmez —
gerçek veride test ettik: **T1546 Event Triggered Execution**'ın 18 alt
tekniği var ama üst tekniğin kendi group_count'u **0** (CTI raporları hep
spesifik alt tekniğe atıf yapıyor, örn. `T1546.003` WMI Event Subscription
group_count=10, üst teknik ID'sinin kendisine neredeyse hiç). Bu yüzden aile
başına tek hedef, **üst teknik + tüm alt tekniklerin group_count'unun
MAX'ı** üzerinden 3 küçük dilime ayrılır (düşük/orta/yüksek — bugünkü sabit
değerle aynı büyüklük mertebesinde, örn. 1/2/3). Dilim sınırları henüz
kesinleşmedi, ayrı bir kararla netleştirilecek.

---

## 3. Alt teknik → üst teknik birleşimi (rollup)

**Temel:** MITRE ATT&CK Navigator'ın layer formatındaki `aggregateFunction`
alanının **varsayılanı `sum`**'dur — DeTT&CT'nin kendi katman üretici kodunda
da (`navigator_layer.py`, satır 41: `"aggregateFunction": "sum"`) aynı
varsayılan kullanılıyor. Yani biz de `sum` ailesindeyiz, uydurma değil.

Kaynak: [navigator_layer.py, satır 41](https://github.com/rabobank-cdc/DeTTECT/blob/master/navigator_layer.py#L41) ·
[Navigator Layer Format Spec v4.5](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)

*(Düzeltme notu — şeffaflık için: bu araştırma sürecinde önce yanlışlıkla
"DeTT&CT'de yaygın olan `max`" denmişti, ikincil bir arama özetine
dayanıyordu. Birincil kaynağa (kod) bakılınca `sum` çıktı, düzeltildi.)*

**Uygulanan `sum` iki güvenceli bir hibrittir — iki AYRI aşırı-sayma
senaryosunu aynı anda önler.** Süreç iki başarısız ara denemeden geçti,
üçüncüsü kaldı; şeffaflık için üçü de aşağıda.

**Formül (güncel, 2026-08-15):**
```
family_hedef = kendi_hedef + Σ(tüm alt tekniklerin TAM hedefi)

cappedSum    = min(kendi_etkin, kendi_hedef)
               + Σ min(alt_etkin, alt_hedef)   [her ÜYE kendi hedefinde
               tavanlanır — bir üyenin fazlası kardeşine taşmaz]

dedupedSum   = ailenin (kendi + tüm altlar) dokunduğu BENZERSİZ kural
               ID'lerinin toplam ağırlığı       [aynı kural birden fazla
               üyeye eşliyse YALNIZCA BİR KEZ sayılır]

family_etkin = min(cappedSum, dedupedSum)
skor         = min(family_etkin / family_hedef, 1.0)
```

**Neden iki ayrı güvence gerekiyor** — her biri FARKLI bir aşırı-sayma
senaryosunu önler, biri diğerinin yerini tutmuyor:

- **Yalnızca `cappedSum` olsaydı:** aynı kural hem üst tekniğe hem birden
  fazla alt tekniğe eşliyse (örn. bir ürünün geniş "built-in motoru"),
  her eşlendiği yerde ayrıca sayılır — N kez şişer.
- **Yalnızca `dedupedSum` olsaydı:** bir alt teknikte çok sayıda BAĞIMSIZ
  (paylaşılmamış) kural varsa (örn. hedefi 2 iken 10 farklı kural), o
  fazlalık diğer kardeşlerin eksiğini kapatmak için aileye "taşar" —
  kullanıcı kararına (2026-07-29) aykırı: *"alt teknikte 10 tane tespit
  var ama 2 ekleniyorsa fazlalığı üst tekniğe eklemeyelim, kendi yeşil
  olsun, sorun yok."*

`min()` ikisini de aynı anda garanti eder. Paylaşılmamış ve tavanı aşmayan
sıradan durumda ikisi zaten eşittir, hiçbir fark yaratmaz.

**İki başarısız ara deneme (şeffaflık için tutuluyor):**

1. *Ham toplama* (2026-07-29 – 2026-08-15): `üst_etkin = kendi + Σ alt_etkin`,
   `üst_hedef = kendi + Σ alt_hedef`. Çifte sayım sorunu vardı (yukarıdaki
   ilk madde) ve alt teknik SAYISIYLA orantılı sınırsız büyüyen bir hedef
   üretiyordu (18 alt tekniği olan T1027/T1546 gibi aileler, veritabanımızda
   toplam 323 kural/254 ana teknik varken asla ulaşılamaz bir hedefe
   çıkıyordu).
2. *Boşluk tabanlı* (2026-08-15, bir önceki tur): `üst_hedef = kendi +
   Σ max(0, alt_hedef−alt_etkin)`, `üst_etkin = SADECE kendi`. Çifte sayımı
   ve sınırsız büyümeyi çözdü ama YENİ bir hata yarattı: payda alt
   tekniklerin ilerlemesiyle küçülüyordu ama pay bunu HİÇ yakalamıyordu
   (üst tekniğin kendi doğrudan kuralı pratikte hep sıfır — kurallar hep
   alt tekniğe yazılıyor). Sonuç: tek bir alt teknik bile %100 mükemmel
   değilse, pay/payda oranı `0 / (pozitif) = 0`'a çöküyordu — **canlı
   örnek: T1205 (Traffic Signaling)**, T1205.001 %100 ve T1205.002 %75
   kapsanmışken üst teknik kartı dümdüz "hiç kapsanmamış" (koyu)
   görünüyordu. Kullanıcı bunu gerçek ekran görüntüsünden yakaladı. Kök
   neden: payda "kalan boşluk", pay "tamamen ayrı bir sayı" idi — aynı
   ölçekte değillerdi, oran anlamsızdı.

**Doğrulama (canlı sunucudan gerçek sayılar, 2026-08-15):**

| Aile | Alt teknik sayısı | Eski (boşluk-tabanlı) skor | Yeni (hibrit) skor |
|---|---|---|---|
| T1205 (Traffic Signaling) | 2 (%100, %75 kapsanmış) | **%0** ← hatalı | **%87.5** |
| T1546 (Event Triggered Execution) | 18 | (asla %100 hesaplanamazdı, eski problemin kaynağı) | **%19.4** — ulaşılabilir, ve `dedupedSum` gerçekten devrede: birçok alt teknik tam olarak aynı 0.75 değerini taşıyor (paylaşılan tek bir toplu ürün iddiası), `cappedSum` (14.5) yerine `dedupedSum` (3.88) bağlayıcı oluyor — tam da tasarlandığı gibi. |

---

## 4. Renk gradyanı

Skor (0-1), Navigator'ın kendi gradient mekanizmasıyla aynı mantıkla
(`colors` + `minValue`/`maxValue` arası doğrusal interpolasyon) sürekli bir
renk skalasına çevrilir — kesikli kova/eşik değil. Bu kısım zaten mevcut
`_scoreRgb()` implementasyonumuzla örtüşüyor, değişiklik gerekmiyor.

Kaynak: [Navigator Layer Format Spec v4.5 — gradient](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md)

---

## 5. Bilinçli olarak BENİMSENMEYENLER

- **DeTT&CT'nin tam -1..5 niteliksel tespit skoru** — her tespidi elle
  değerlendirmeyi gerektiriyor, bu ölçekteki bir SOC için gereksiz ağır
  (bkz. madde 1'deki gerekçe).
- **DeTT&CT'nin Data Quality / Visibility ayrımı** (log kaynağı kalitesini
  ayrı puanlayıp ondan görünürlük türetme) — biz doğrudan kural bazında
  çalışıyoruz, ayrı bir "veri kaynağı envanteri" katmanımız yok. İleride
  gerekirse ayrı bir konu.
- **CISA "Best Practices for MITRE ATT&CK Mapping"** — araştırma sırasında
  kaynak listesine girmişti ama içeriği kontrol edildiğinde bunun bir
  **skorlama** değil, bir **eşleme doğruluğu** (analistin doğru teknik
  ID'sini seçmesi) rehberi olduğu görüldü. Puanlama/renklendirme hakkında
  hiçbir tavsiyesi yok — kapsam dışı bırakıldı.

---

## 6. Genel ilke — neden "kesin" olmak zorunda değil

MITRE'nin kendi resmi olgunluk çerçevesi (Center for Threat-Informed
Defense — INFORM v2.0) kendi ağırlıklı formülü için birebir şunu diyor:

> *"This final formula is not meant to be extremely precise, but rather
> reflects the 'best engineering judgment' of the project team... each
> organization can, and should, tune and tailor this formula based on
> their needs and constraints."*

Kaynak: [MITRE INFORM v2.0 — Measuring TID](https://center-for-threat-informed-defense.github.io/inform/measuring-tid/)

Ayrıca, olgunluğun erken evresindeki programların basit stoplight/yüzde-eşik
modelle çalışmasının beklenen bir yaklaşım olduğu, sayıların "yaygınlık ×
tekdüze olmayan öncelik" ile ilişkilendirilmesinin (madde 2) ve sonucun
gerekçesinin yazılı olmasının (bu belge) asıl standart olduğu görüldü —
belirli sayıların "evrensel doğru" olması değil.

Kaynak: [Measuring Detection Coverage Without Lying to Yourself](https://medium.com/@itsmayank227/measuring-detection-coverage-without-lying-to-yourself-8eacd9924249) ·
[You Can't Detect What You Can't See — SANS Institute](https://www.sans.org/blog/you-cant-detect-what-you-cant-see-closing-gaps-detection-engineering)

---

## Uygulama durumu

Uygulandı (2026-08-15). Üç parça, plandan bir noktada saptı — aşağıda not
edildi:

1. **`coverage_level` 3→4 seviye.** Şema, validasyon (3 ayrı liste),
   `migrate_coverage_level_partial_to_half()` ile mevcut `partial`
   verisinin `half`'a taşınması, frontend ağırlık sözlüğü, slider/bulk
   seçici UI'ı, import prompt'u (`docs/mitre_mapping_prompt.md`) — hepsi
   senkron.
2. **`technique_config` hedef dilimi — planla FARK: aile bazlı (MAX
   group_count) değil, SATIR bazlı.** Uygulama sırasında (kod yazılırken)
   fark edildi: tek bir aile-genel dilim, "18 alt tekniği olan ama çoğu
   nadir kullanılan" bir ailede nadir alt tekniklere de yüksek hedef
   dayatırdı. Bunun yerine her SATIR (ana ya da alt fark etmez) kendi
   `group_count`'una göre ayrı dilimlenir — `_prevalence_tier_threshold()`,
   gerçek veri dağılımıyla kalibre edildi (714 satır: medyan 2, p90=17):
   `<5 → 1`, `5-19 → 2`, `20+ → 3` (508/145/61 satır dağılımı).
3. **Rollup — plan iki kez revize edildi, nihai hâl "hibrit" model.**
   İlk uygulama "boşluk-tabanlı"ydı; kullanıcı canlı bir ekran görüntüsüyle
   (T1205, iki alt teknik %100/%75 kapsanmışken üst kartın dümdüz koyu
   görünmesi) bunun hatalı olduğunu yakalayınca `min(cappedSum, dedupedSum)`
   hibrit modeline geçildi — `familyRollup()` (app.js) ve
   `_compute_gap_analysis()` (app.py) senkron. Ayrıntı, üç denemenin
   tam karşılaştırması ve canlı doğrulama sayıları yukarıda (#3).
4. **Geriye dönük veri geçişi gerekti, plana yoktu.**
   `build_technique_config()`'in `INSERT OR IGNORE`'u formül değiştiğinde
   halihazırda var olan satırları güncellemez — yalnızca yeni `tech_id`
   ekler. Yani ilk kod yazıldığında bu tiering, o ana kadar hiç
   `technique_config` satırı olmayan taze bir DB'de çalışırdı ama bu
   projenin aylardır biriken canlı `soc.db`'sinde HİÇ etkisi olmazdı — her
   satır zaten vardı. `drop_technique_importance()`'ın bir önceki geçişte
   (Faz 4b) yaptığının aynısı gerekti:
   `migrate_technique_config_thresholds_to_prevalence_tiers()`, `source=
   'auto'` satırlarını saklı `group_count`'larına göre yeniden dilimler,
   `source='admin'` asla dokunulmaz. Canlı DB'de doğrulandı: 714 teknikten
   9'u admin override (dokunulmadı), kalan 705'i doğru dilime taşındı
   (örnek: T1546.008, group_count=6, 1→2).
