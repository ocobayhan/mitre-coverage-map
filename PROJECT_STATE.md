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

## SOC-CMM KPI Durumu

2026-07-19 itibarıyla ürün iki resmi KPI hattını ayrı hesaplar:

- ATT&CK 18.1 tabanlı, sürümlü ve onaylanabilir kurum profili
- Mapped, validated ve risk ağırlıklı detection coverage
- ATT&CK Data Components ve beş DeTT&CT kalite boyutundan türetilen visibility
- Detection / visibility / birleşik GAP heatmap modları
- Mevcut taktik sütunlu ATT&CK Matrix ile SOC-CMM KPI verisinin tek kart ve teknik detay akışında birleşimi
- Detection yaşam döngüsü, 0-5 skor, test yöntemi, kanıt, sahip ve geçerlilik takibi
- Telemetri kaynağı, kapsam, hedef platform, 0-5 kalite ve son veri takibi
- Formül sürümlü, hash'li ve append-only KPI snapshot'ları
- Snapshot trend görünümü ve ATT&CK Navigator Layer JSON export
- Profil, değerlendirme, override, telemetri ve snapshot işlemlerinin tam audit kaydı

Gerçek veri migrasyonu sonrasında taslak profil 691 ATT&CK tekniği içerir. 438 detection `active / untested` olarak envantere alınmıştır. Bu nedenle başlangıç KPI'ları mapped coverage `%15,6`, validated detection coverage `%0` ve visibility `%0` değerindedir. Bu sıfır değerler eksik kanıt ve telemetri envanterini açıkça gösterir; sistem kanıtsız coverage üretmez.

## Sonraki Öncelikler

1. Kapsam Envanteri'nde gerçek ortam/varlık gruplarının ve ürün izleme anketlerinin doldurulması
2. QRadar connector'ın kurum test instance'ında read-only SEC token ile kabul testi
3. Connector tespitlerinin bağlı varlık grubuna uygulanabilirliğini belirleyen scope doğrulama akışı
4. Kalan 5 tespitin analist tarafından MITRE tekniklerine bağlanması
5. Kurumsal ATT&CK profil kapsamının risk ekipleriyle gözden geçirilip onaylanması
6. İlk 25 detection için kanıt ve kontrollü doğrulama kampanyası
7. Kurumsal SSO/OIDC ve merkezi kullanıcı yaşam döngüsü
8. PostgreSQL geçişi ve çoklu uygulama instance desteği
9. CI pipeline ve test veritabanıyla otomatik release kontrolü
10. MITRE veri seti sürümleme ve kontrollü güncelleme iş akışı

## Connector Yol Haritası

- **Faz 1 — QRadar:** Use Case Manager mapping API, native rule ID uzlaştırma, sync geçmişi, stale yönetimi ve Audit tamamlandı. Mock QRadar HTTP servisiyle duplicate önleme doğrulandı; kurum QRadar instance kabul testi bekliyor.
- **Faz 2 — QRadar genişletme:** log source activity/coverage, tuning findings, offense count ve son aktivite metrikleri.
- **Faz 3 — Defender (beklemede):** Microsoft Graph `alerts_v2` ile built-in aktivite; custom detection envanteri için Git/JSON öncelikli model. QRadar kabulü tamamlanana kadar uygulanmayacak.
- **Faz 4 — Detection as Code:** custom detection repository, sürüm ve deployment durumunun connector kayıtlarına bağlanması.
