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

## Docker

```powershell
copy .env.example .env
# .env icine SOC_SECRET_KEY doldur
docker compose up -d --build
```

Canlı veri (`soc.db`) Docker'ın yönettiği bir named volume'de (`soc_data`), yedekler ise Docker'ın hiç bilmediği düz bir host klasöründe (`./backups`, bind mount) tutulur — böylece `docker compose down -v` veya `docker system prune --volumes` gibi komutlar yedekleri etkilemez. Zamanlanmış yedekleme, kurulum ve geri yükleme adımları için bkz. [docs/backup_restore.md](docs/backup_restore.md).

## Veri

- MITRE Enterprise ATT&CK: `data/mitre.json`
- Başlangıç tespitleri: `data/rules_seed.json`
- SQLite veritabanı: `soc.db` (Git dışında)

MITRE veri seti değiştirildiğinde uygulamayı yeniden başlatın. Veri Kalitesi ekranı teknik ID, ürün, taktik ve eşleme tutarlılığını denetler.

## Audit

Audit kayıtları istek ID, kullanıcı, IP, user-agent, önce/sonra değerleri ve SHA-256 zincir hash'i içerir. Veritabanı trigger'ları audit satırlarının güncellenmesini veya silinmesini engeller. Admin kullanıcılar Audit ekranından filtreleme, detay inceleme, bütünlük doğrulama ve CSV export yapabilir. `Kanıt Paketi`, seçili filtrelerle kayıtları; üretim manifesti, tam zincir durumu, önceki/kayıt hash'leri ve bağımsız doğrulanabilir paket hash'i içeren JSON dosyası olarak dışa aktarır.

## Kapsama Puanlaması

Her teknik için tek satırda açıklanabilen bir kapsama skoru hesaplanır ve kart rengini belirler:

```
skor = min(etkin tespit sayısı / teknik hedefi, 1)
```

**Etkin tespit sayısı** iki ağırlığın çarpımıdır:

```
etkin ağırlık = kapsam seviyesi (low 0.25 | partial 0.60 | full 1.00)
              × ortam izleme ağırlığı (full 1.00 | partial %/100 | none, unknown 0)
```

**Teknik hedefi** (`technique_config.rule_threshold`) tüm teknikler için aynı değerle başlar (`DEFAULT_RULE_THRESHOLD = 2`); admin teknik detayı modalinden teknik bazında değiştirir. Bir tekniğin hedefini yükseltmek kartını anında kırmızıya çeker — "bu teknik için 2 tespit yetmez" demenin yolu budur.

**Mitigation skora girmez.** Haritada ayrı bir kalkan işareti (⛨) olarak gösterilir; renk yalnızca tespite bakar çünkü haritanın cevapladığı soru *"bu tekniği görebiliyor muyuz"*. Ürün çeşitliliği de skora girmez — kartın üzerindeki ürün noktaları bunu zaten gösterir.

> Bu puan bir olgunluk göstergesidir; tek başına bir tespitin gerçekten çalıştığının kanıtı değildir.

### "Kapsanan" ne demek?

**İki ayrık kova** kullanılır; toplamları ana teknik sayısını verir:

| Metrik | Anlamı |
|---|---|
| **Tespit** | Tekniğe bağlı en az bir tespit (kural) var — *görebiliyoruz* |
| **Kapsamsız** | Hiç tespit yok — *asıl aksiyon listesi* |

`Mitigation` ayrıca sayılır ama bir kova değildir; kovalarla kesişir ve yalnızca bilgi amaçlıdır.

**Payda ana tekniklerdir.** Alt teknikler paydaya girmez: kurallar neredeyse tamamen ana tekniğe eşlenir ve bir alt tekniğe yazılan kural zaten ana tekniğe sayılır. Alt teknikler haritada görünür ve kendi renklerini alır, ayrıca bir metrikte bilgi olarak gösterilir — düşük değer "alt teknik eşlemesi yapılmamış" anlamına gelir.

Aynı tanım hem matris şeridinde hem `GET /api/gap-analysis` çıktısında (`detected_techniques` / `uncovered_techniques` / `mitigated_techniques`) ve yönetici raporunda kullanılır.

### Önceliklendirme

"Önem seviyesi" kavramı kaldırıldı — `data/mitre.json`'dan türetilen 0.3–1.0 arası opak bir puandı ve yönetilemiyordu. Yerine tespitsiz teknikler, **kaç tehdit grubunun o tekniği kullandığına** göre sıralanır (`technique_config.group_count`). Bu bir ayar değil, MITRE'den gelen objektif veridir.

## Ortam Bazlı Kapsama

Kurumda her ürün her yerde bulunmaz: Defender client'larda ve kurumsal server'larda varken Lumos ortamındaki server'larda olmayabilir; QRadar tüm server'lardan log alırken client'lardan almayabilir. Bu durumda bir QRadar kuralı client ortamında **geçerli değildir**.

Bu yüzden matrisin üstündeki **Ortam** seçicisi haritayı yeniden hesaplar:

> Bir teknik bir ortamda kapsanır ⟺ o tekniğe bağlı bir tespit vardır **ve** tespitin ürünü o ortamı izlemektedir.

```
etkin ağırlık = kapsam seviyesi ağırlığı × izleme ağırlığı
    izleme:  full → 1.00 | partial → coverage_percent/100 | none, unknown → 0
```

Ortam seçildiğinde, o ortamı izlemeyen ürünlerin tespitleri hesaptan düşer; matris altındaki şerit hangi tespit kaynaklarının sayıldığını ve hangilerinin izlemediğini açıkça listeler. İzleme durumları `Kapsam Envanteri` ekranından `Ortam > Ürün İzleme` yapısıyla girilir.

Aynı kural sunucu tarafında da uygulanır: `GET /api/gap-analysis?environment_id=<id>` — böylece GAP Analizi ekranı ve yönetici raporu matrisle aynı kapsamı gösterir.

## Ürün Kategorileri

`products.category` üç değer alır ve haritaya etkisi farklıdır:

| Kategori | Örnek | Etki |
|---|---|---|
| `tespit_kaynagi` (varsayılan) | QRadar, DFE, Defender for Identity, MDO365, Wazuh | Haritayı boyar; ürün çeşitliliği bileşenine **yalnızca bunlar** sayılır |
| `onleyici_kontrol` | Firewall, antivirüs, yama yönetimi, MFA | Tespit üretmez; kapsamaya sayılmaz |
| `zenginlestirme` | CTI beslemeleri | Önceliklendirmeyi besler, kapsamayı değil |

Mevcut kurulumlarda migration tüm ürünleri `tespit_kaynagi` olarak işaretler (kimsenin kapsama sayısı sessizce değişmesin diye); doğru sınıflandırma `Ayarlar > Ürün Yönetimi`'nden yapılır.

`rules.source` ile `products.name` arasında yabancı anahtar yoktur — köprü yalnızca isim eşitliğidir. Katalogda bulunmayan bir kaynak hiçbir ortama bağlanamayacağı için kural yazma anında reddedilir; mevcut uyumsuzluklar Veri Kalitesi ekranında **kritik** olarak listelenir.

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

`Kapsam Envanteri`, ölçüm sınırını `Ortam > Ürün İzleme` yapısıyla yönetir. Admin ortamları ve platform/varlık tipi bazlı grupları tanımlar; editor her ürün için `unknown`, `none`, `partial` veya `full` izleme durumunu, yöntemi, yüzdeyi, sahibi ve kapsam notunu kaydeder. Bir QRadar connector yalnızca aynı ürün etiketli izleme kaydına bağlanabilir.

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
