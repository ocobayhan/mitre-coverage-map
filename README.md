# SOC Coverage Map

Kurumsal tespit, mitigation ve aksiyon verisini MITRE ATT&CK Enterprise matrisi üzerinde birleştiren Flask tabanlı uygulama.

## Yerel Çalıştırma

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SOC_PORT='8888'
python app.py
```

Uygulama: `http://127.0.0.1:8888`

Yeni veritabanında geliştirme hesapları oluşturulur:

- `admin / Admin123!`
- `editor / Editor123!`
- `viewer / Viewer123!`

Bu parolalar yalnızca yerel başlangıç içindir. Kurum ortamında ilk açılıştan sonra değiştirilmelidir.

## Üretim Çalıştırma

Üretimde Flask geliştirme sunucusu yerine Waitress kullanılır. Güçlü ve kalıcı bir session secret zorunludur.

```powershell
$env:SOC_SECRET_KEY='<en-az-32-byte-rastgele-deger>'
$env:SOC_HOST='0.0.0.0'
$env:SOC_PORT='8000'
$env:SOC_COOKIE_SECURE='1'
.\.venv\Scripts\python.exe serve.py
```

TLS sonlandırması için ters proxy kullanın. `SOC_COOKIE_SECURE=1` yalnızca HTTPS üzerinden yayın yapılırken etkinleştirilmelidir.

## Veri

- MITRE Enterprise ATT&CK: `data/mitre.json`
- Başlangıç tespitleri: `data/rules_seed.json`
- SQLite veritabanı: `soc.db` (Git dışında)

MITRE veri seti değiştirildiğinde uygulamayı yeniden başlatın. Veri Kalitesi ekranı teknik ID, ürün, taktik ve eşleme tutarlılığını denetler.

## Audit

Audit kayıtları istek ID, kullanıcı, IP, user-agent, önce/sonra değerleri ve SHA-256 zincir hash'i içerir. Veritabanı trigger'ları audit satırlarının güncellenmesini veya silinmesini engeller. Admin kullanıcılar Audit ekranından filtreleme, detay inceleme, bütünlük doğrulama ve CSV export yapabilir. `Kanıt Paketi`, seçili filtrelerle kayıtları; üretim manifesti, tam zincir durumu, önceki/kayıt hash'leri ve bağımsız doğrulanabilir paket hash'i içeren JSON dosyası olarak dışa aktarır.

## SOC-CMM KPI

`SOC-CMM KPI` çalışma alanı detection coverage ile data source visibility metriklerini birbirinden ayırır:

- Kurum profili ATT&CK 18.1 teknik kapsamını, risk ağırlığını, gerekçeyi, sürümü ve onayı saklar.
- Mevcut detection eşlemeleri başlangıçta `active / untested` kabul edilir. Doğrulanmış coverage için skor, yöntem, kanıt ve doğrulama tarihi zorunludur.
- Visibility envanteri ATT&CK Data Components ile cihaz kapsamı, alan tamlığı, zamanındalık, tutarlılık ve retention kalite skorlarını kullanır.
- Birleşik heatmap kontrol edilen teknikleri, detection boşluklarını, zayıf visibility üzerine kurulmuş detection'ları ve kör noktaları ayrı gösterir.
- Ana ATT&CK Matrix tek veri yüzeyidir: operasyonel olgunluk, validated detection, data visibility ve birleşik GAP modları aynı teknik kartları üzerinde çalışır. Mevcut ürün/kural eşlemeleri SOC-CMM skorlarıyla birlikte görünür.
- Teknik detayında mitigation, detection eşlemeleri, validation skoru, sahip, kanıt durumu ve Data Component özeti birlikte gösterilir.
- Yalnız onaylı profiller resmi KPI snapshot'ı üretebilir. Snapshot payload'ları SHA-256 hash ile korunur ve veritabanı trigger'larıyla append-only tutulur.
- Dashboard görünümü MITRE ATT&CK Navigator Layer JSON olarak dışa aktarılabilir.

Resmi KPI formülü `soc-cmm-1.0` olarak sürümlenir. Validated detection coverage en az bir aktif ve geçerli doğrulanmış detection bulunan profil tekniklerinin oranıdır. Weighted detection, profil ağırlığı ile 0-5 detection skorunu; visibility ise profil ağırlığı ile 0-4 visibility skorunu normalize eder.

## QRadar Connector

Connector, QRadar Use Case Manager mapping envanterini salt-okunur alır. SEC token veritabanında saklanmaz; connector ayarında yalnızca token'ın okunacağı ortam değişkeni adı tutulur.

```powershell
$env:QRADAR_SEC_TOKEN='<read-only-authorized-service-token>'
```

Admin kullanıcı `Ayarlar > Connector'lar` ekranından birden fazla QRadar instance tanımlayabilir, bağlantıyı test edebilir ve senkronizasyon başlatabilir. İlk eşleştirmede native rule ID kullanılır; aynı ürün ve aynı ada sahip tek mevcut kayıt varsa bu kayıtla bağ kurulur. Yeni kayıtlar isteğe bağlı olarak `untested` ve düşük güvenle oluşturulur. Manuel ATT&CK eşleşmeleri ile validation kanıtları connector tarafından silinmez.

Zamanlanmış senkronizasyon için aynı ortam değişkenlerini taşıyan servis hesabıyla şu komut çalıştırılır:

```powershell
.\.venv\Scripts\python.exe scripts\sync_connectors.py
# Yalnızca tek bağlantı:
.\.venv\Scripts\python.exe scripts\sync_connectors.py --connector-id 1
```

Windows Task Scheduler için önerilen başlangıç sıklığı 6 saattir. Aynı connector için eşzamanlı sync engellenir; 15 dakikadan eski yarım kalmış çalışma zaman aşımı olarak kapatılır. Üç ardışık senkronizasyonda görünmeyen native kayıtlar silinmez, `stale` işaretlenir.

## Kapsam Envanteri

`Kapsam Envanteri`, ölçüm sınırını `Ortam > Varlık Grubu > Ürün İzleme` hiyerarşisiyle yönetir. Admin ortamları ve platform/varlık tipi bazlı grupları tanımlar; editor her ürün için `unknown`, `none`, `partial` veya `full` izleme durumunu, yöntemi, yüzdeyi, sahibi ve kapsam notunu kaydeder. Bir QRadar connector yalnızca aynı ürün etiketli izleme kaydına bağlanabilir.

Bu kayıt ürün bulunurluğu kanıtıdır, doğrudan MITRE detection coverage değildir. Connector'dan gelen native tespitlerin teknik eşlemesi ve validation kanıtı ayrı değerlendirilir. Tüm kapsam ve anket değişiklikleri önce/sonra değerleriyle Audit zincirine yazılır.

## Test

```powershell
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
python scripts\browser_smoke.py
```

Tarayıcı testi çalışan uygulamaya bağlanır ve ekran görüntülerini sistem geçici klasörüne yazar.

## Yedekleme

Uygulama kapalıyken `soc.db` dosyasını kopyalayın. Geri yükleme için çalışan süreci durdurup mevcut dosyayı doğrulanmış yedekle değiştirin. Audit export, veritabanı yedeğinin yerine geçmez.
