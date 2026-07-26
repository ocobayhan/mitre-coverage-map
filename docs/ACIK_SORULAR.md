# Açık Sorular ve Çözülmemiş Sorunlar

Sadeleştirme çalışması sırasında tespit edilen ama **henüz karara bağlanmamış**
konular. Her madde: ne bulundu, neden önemli, hangi seçenekler var.

Çözülenler `PROJECT_STATE.md`'ye taşınır ve buradan silinir.

---

## 1. "Kapsanan" iki ekranda farklı şey ölçüyor ⚠️ KARAR BEKLİYOR

**Bulundu:** Faz 2 doğrulaması sırasında (Faz 2'den önce de vardı).

Aynı kelime, iki farklı hesap:

| Ekran | Pay (kapsanan sayılır) | Payda |
|---|---|---|
| Matris (`ms-covered`, `app.js`) | kural **veya** mitigation var | 250 — yalnız ana teknik |
| GAP / yönetici raporu (`coverage_pct`, `app.py`) | yalnız kural var | 691 — alt teknikler dahil |

Somut sonuç: aynı anda "%75 kapsanan" ve "%15,6 kapsanan" gösteriliyor.

**Neden önemli:** Bu, "her ekran kendi doğrusunu anlatıyor" şikayetinin
tam örneği. Yönetime hangi sayının söyleneceği belirsiz.

**Karar gereken sorular:**
1. Mitigation'ı olan ama tespiti olmayan bir teknik "kapsanan" sayılmalı mı?
   (Mitigation = önleme, tespit = görme — ikisi farklı yetenek.)
2. Payda 250 ana teknik mi, 691 (alt teknikler dahil) mi olmalı?
   Alt tekniklerin çoğu hiç kullanılmıyor; 691 payda oranı yapay düşürüyor.

**Not:** Backend zaten `parent_total` / `parent_covered` alanlarını da
döndürüyor, yani veri mevcut — sadece hangisinin gösterileceği kararı gerekiyor.

---

## 2. Ürünlerin kategorileri henüz doğru değil 📋 KULLANICI GİRİŞİ BEKLİYOR

Faz 2 migration'ı mevcut 7 ürünün hepsini `tespit_kaynagi` olarak işaretledi —
bu bilinçliydi (kimsenin kapsama sayısı sessizce değişmesin diye). Ama gerçekte:

- `Fortigate Firewall` → büyük olasılıkla `onleyici_kontrol` olmalı
- `Manage Engine` → ne olduğuna göre değişir (yama yönetimiyse `onleyici_kontrol`)
- `Other` → içeriği belirsiz

Doğru sınıflandırma yapılana kadar ürün çeşitliliği bileşeni (%20) olduğundan
yüksek hesaplanıyor.

**Yapılacak:** Ayarlar > Ürün Yönetimi'nden kullanıcı sınıflandırır.

---

## 3. Alt teknik kapsaması ana tekniğe yansımıyor ❓ İNCELENMELİ

`GET /api/gap-analysis` çıktısında "49 ana · 0 alt teknik" gibi değerler
görüldü — alt tekniklerin kapsanan sayısı 0 çıkıyor, çünkü tespitler
`rule_techniques` içinde çoğunlukla ana tekniğe bağlanmış.

**Soru:** Bir alt tekniğe (T1059.001) bağlı tespit yoksa ama ana tekniğe
(T1059) bağlı tespit varsa, alt teknik kapsanmış sayılmalı mı?
MITRE mantığında ana teknik kapsaması alt teknikleri garanti etmez, ama
pratikte çoğu kural ana tekniğe eşleniyor.

Bu, yukarıdaki 1. maddedeki payda sorusuyla doğrudan bağlantılı.

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
