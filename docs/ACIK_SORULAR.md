# Açık Sorular ve Çözülmemiş Sorunlar

Sadeleştirme çalışması sırasında tespit edilen ama **henüz karara bağlanmamış**
konular. Her madde: ne bulundu, neden önemli, hangi seçenekler var.

Çözülenler `PROJECT_STATE.md`'ye taşınır ve buradan silinir.

---

## 1. Mitigation kapsaması teknik bazında bilinçli olmalı ⚠️ İLERİYE DÖNÜK

*(Bu madde, çözülen "Kapsanan tanımı" tartışmasından çıktı — bkz. PROJECT_STATE.md)*

Faz 4b/4d'den sonra mitigation **skora hiç girmiyor** — haritada yalnızca `M`
rozeti olarak görünüyor. Bu, sorunun aciliyetini düşürdü ama çözmedi:
**hangi tekniğin mitigation ile karşılandığı hâlâ bilinçli bir karar değil**,
MITRE'nin toplu eşlemesinin yan etkisi:

- 9 kayıtlı mitigation → 392 tekniği etkiliyor (887 hücrenin 527'sinde `M` rozeti
  çıkıyor; bu yoğunlukta rozet bilgi taşımıyor)
- Tek başına `M1018 User Account Management` → **120 teknik**
- `M1056 "Pre-compromise"` bir kontrol bile değil (MITRE placeholder'ı) → 84 teknik

MITRE'nin mitigation↔teknik eşlemesi *"bu mitigation bu teknikle ilgilidir"*
demek, *"bu mitigation bu tekniği engeller"* demek değil.

**Öneri:** Teknik bazında "bu teknik için mitigation yeterli, tespit yazmayacağız"
işareti. Böylece karar denetlenebilir ve gerekçeli olur. Teknik detay modalındaki
mitigation listesi bunun doğal yeri.

---

## 2. Ürünlerin kategorileri henüz doğru değil 📋 KULLANICI GİRİŞİ BEKLİYOR

Faz 2 migration'ı mevcut 7 ürünün hepsini `tespit_kaynagi` olarak işaretledi —
bu bilinçliydi (kimsenin kapsama sayısı sessizce değişmesin diye). Ama gerçekte:

- `Fortigate Firewall` → büyük olasılıkla `onleyici_kontrol` olmalı
- `Manage Engine` → ne olduğuna göre değişir (yama yönetimiyse `onleyici_kontrol`)
- `Other` → içeriği belirsiz

Kategori artık skoru etkilemiyor (ürün çeşitliliği bileşeni Faz 4b'de kaldırıldı),
ama `_detection_source_names()` üzerinden **hangi tespitlerin sayılacağını** hâlâ
belirliyor: `onleyici_kontrol` işaretlenen bir ürünün kuralları kapsamaya girmez.
Yani yanlış kategori doğrudan yanlış kapsama demek.

**Yapılacak:** Ayarlar > Ürün Yönetimi'nden kullanıcı sınıflandırır.

---

---

## 4. `rules.source` hâlâ serbest metin (FK yok) 🔧 BİLİNÇLİ ERTELENDİ

Faz 2'de yazma anında doğrulama eklendi (katalogda olmayan kaynak reddediliyor)
ve Veri Kalitesi kontrolü kritiğe yükseltildi. Ancak şema seviyesinde hâlâ
`rules.source TEXT` ↔ `products.name TEXT` eşleşmesi var, foreign key yok.

Ürün **adı değiştirilirse** mevcut kuralların bağı kopar (PUT /api/products
şu an adı değiştirmiyor, sadece renk ve kategori — bu yüzden risk şimdilik
teorik).

**Seçenek:** `rules.product_id` FK migration'ı. Şu an gerekmiyor; ürün
yeniden adlandırma özelliği eklenirse zorunlu hale gelir.

---

## 5. Mitigation `team` alanı serbest metin (FK yok) 🧹 VERİ TEMİZLİĞİ

`mitigation_entries.team` bir `teams` FK'sı değil, kaydedildiği andaki ekip adının
kopyası. Form artık `teams` kataloğundan seçtiriyor ama eski kayıtlar öyle değil:
11 kaydın 3'ü artık var olmayan ekiplere bağlı (`DENBEME`, `DENEM`, `DENEME`).

Ekip **yeniden adlandırılırsa** eski kayıtlar eski adla kalır — `rules.source` ile
aynı sınıf sorun (bkz. madde 4).

**Seçenek:** `team_id` FK migration'ı, veya Veri Kalitesi ekranına "kataloğda
olmayan ekip" uyarısı. Şimdilik kullanıcının elle temizlemesi bekleniyor.

---

## 6. `technique_config`'te 17 artık-revoked satır kaldı 🧹 VERİ TEMİZLİĞİ

2026-07-28'de `data/mitre.json` v18.1 → v19.1'e güncellenirken (Defense
Evasion → Stealth + Defense Impairment ayrımı) eski `T1562` ailesi (Impair
Defenses ve tüm alt teknikleri) + `T1070.001`/`.002` MITRE tarafından
revoked/deprecated işaretlendi. `build_technique_config()` bunları yeni satır
olarak eklemekten kaçınıyor (revoked filtreli), ama **eski `auto` satırları
tablodan silmiyor** — 17 satır artık hiçbir canlı tekniğe karşılık gelmeden
tabloda duruyor.

Zararsız: `_known_technique_ids()` canlı `_mitre_catalog()`'u okuyor (revoked
otomatik dışlanıyor), yani içe aktarım bu ID'leri kabul etmiyor; harita da
bunları göstermiyor. Sadece `technique_config` tablosunda ölü satır.

**Seçenek:** `prune_stale_technique_config()` — canlı katalogda olmayan
`source='auto'` satırları silen bir migration. `source='admin'` satırlar asla
silinmemeli (kullanıcının bilinçli kararı, revoked olsa bile Veri Kalitesi
üzerinden görünür kalsın).
