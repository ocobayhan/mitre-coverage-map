# Açık Sorular ve Çözülmemiş Sorunlar

Sadeleştirme çalışması sırasında tespit edilen ama **henüz karara bağlanmamış**
konular. Her madde: ne bulundu, neden önemli, hangi seçenekler var.

Çözülenler `PROJECT_STATE.md`'ye taşınır ve buradan silinir.

---

## 1. Mitigation kapsaması teknik bazında bilinçli olmalı ⚠️ İLERİYE DÖNÜK

*(Bu madde, çözülen "Kapsanan tanımı" tartışmasından çıktı — bkz. PROJECT_STATE.md)*

Mitigation artık kapsama skorunun %30'u ve "Yalnız Mitigation" ayrı bir metrik.
Ancak **hangi tekniğin mitigation ile karşılandığı hâlâ bilinçli bir karar değil**,
global mitigation kutucuğunun yan etkisi:

- 9 işaretli mitigation → 392 tekniği etkiliyor
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

Doğru sınıflandırma yapılana kadar ürün çeşitliliği bileşeni (%20) olduğundan
yüksek hesaplanıyor.

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
