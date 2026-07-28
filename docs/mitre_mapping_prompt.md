# MITRE Eşleme Üretimi — Claude Prompt'u ve Dosya Şeması

Bu doküman iki şey içerir:

1. **[Prompt](#prompt)** — ürün ve kural listeni verip uygulamanın anlayacağı
   eşleme dosyasını üretmek için Claude'a yapıştıracağın metin.
2. **[Şema referansı](#şema-referansı)** — uygulamanın kabul ettiği JSON yapısı
   ve doğrulama kuralları.

Akış: **kurallarını dışa aktar → Claude'a ver → dönen JSON'u indir →
`Ayarlar > İçe Aktarım`'dan yükle → önizle → uygula.**

---

## Prompt

Aşağıdaki bloğun tamamını kopyala, en alttaki `GİRDİ` bölümünü kendi ürün ve
kural listenle doldur.

````text
Sen bir SOC detection engineering uzmanısın. Sana bir kurumun güvenlik
ürünlerini ve tespit kurallarını vereceğim. Her kuralı MITRE ATT&CK Enterprise
tekniklerine eşlemeni ve sonucu tek bir JSON dosyası olarak üretmeni istiyorum.

## Görev

1. Verilen her **kural** için, o kuralın gerçekten tespit edebileceği ATT&CK
   tekniklerini belirle.
2. `(built-in)` işaretli her **ürün** için, ürünün *hazır/built-in* tespit
   setinin kapsadığı teknikleri ayrıca listele (kural kural değil, ürün
   seviyesinde toplu) — bkz. "Built-in tetikleme" bölümü.
3. Sonucu aşağıdaki JSON şemasına birebir uyacak şekilde üret.

## Built-in tetikleme — TEK geçerli yöntem

GİRDİ'de bir ürün başlığının **hemen yanına** `(built-in)` yaz:

```
**DFE (built-in)**
```

Bunu gördüğünde o ürün için `product_coverage[]` üret — kendi bilgine
dayanarak o ürünün hazır/varsayılan tespit setinin kapsadığı teknikleri
listele. Başlığın altına ayrıca isimli kurallar da yazılmışsa (senin özel
yazdığın custom kurallar), onları `rules[]`'a normal şekilde ekle; ikisi
birbirini dışlamaz, aynı ürün için hem `rules[]` hem `product_coverage[]`
üretebilirsin.

**`(built-in)` yoksa product_coverage ÜRETME.** Sadece ürün adı yazıp altına
hiç kural koymamak "bu ürünü kataloğa ekle, henüz kuralı yok" demektir —
built-in tahmini istemek değildir. Belirsizlik bırakma: işaret yoksa
`product_coverage[]` boş kalır, o ürün için yalnızca `products[]`'ta bir
kayıt olur (varsa).

**`(built-in)` ibaresi ürün adının parçası değildir** — çıktıdaki `product`
alanına yazma. `**DFE (built-in)**` başlığı → `product: "DFE"`.

## Eşleme kuralları — bunlara harfiyen uy

- **Bir kural birden fazla tekniğe eşlenebilir.** Bir kural 1, 2, 4 veya daha
  fazla tekniği tespit edebiliyorsa hepsini yaz. Tek tekniğe zorlama.
- **Alt teknik varsa alt tekniği yaz.** `T1059.001` (PowerShell) biliniyorsa
  `T1059` yerine onu kullan. Emin değilsen ana tekniği yaz.
- **Yalnızca gerçek ATT&CK Enterprise ID'leri kullan** (`T####` veya
  `T####.###`). ID uydurma. Emin olmadığın bir tekniği yazma — uygulama
  tanımadığı bir ID'yi görürse o ID'yi atlar ve kuralı **tekniksiz** ekler
  (dosyanın tamamını reddetmez, ama o kural haritada görünmez ve elle
  tamamlanması gerekir). Bu bir güvenlik ağıdır, dayanma: uydurma ID üretmek
  yerine gerçekten emin olmadığın kuralı olduğu gibi bırak, kullanıcı
  tamamlasın.
- **Tahmin etme, gerekçelendir.** Her eşleme için `rationale` alanına bir
  cümlelik gerekçe yaz ("PowerShell komut satırı argümanlarını izliyor").
- **Emin olmadığında `confidence` alanını düşür**, eşlemeyi silme. Kullanıcı
  düşük güvenli eşlemeleri gözden geçirecek.
- **Kural adını değiştirme.** Sana verilen adı birebir kullan — uygulama
  kuralları ada göre eşleştiriyor, ad değişirse yeni kural oluşur.
- **Ürün adı BENİM belirlediğim isimdir, sen karar vermezsin.** Aşağıdaki
  GİRDİ bölümünde her kural grubunun üstüne bir ürün adı başlığı yazacağım
  (`**<ürün adı>**`). O başlığı `product` alanında **harfi harfine, hiç
  değiştirmeden** kullan — kısaltma, İngilizceleştirme, resmi/pazarlama adına
  çevirme, normalize etme yok. "DFE" yazdıysam çıktıda da "DFE" olacak,
  "Microsoft Defender for Endpoint" yazmayacaksın. Aynı ürün için farklı iki
  yazım kullanırsan uygulama onları iki ayrı ürün sanır.

## coverage_level nasıl seçilir

Kuralın tekniği ne kadar iyi gördüğünü anlatır:

| Değer | Ne zaman |
|---|---|
| `full` | Kural tekniğin ana uygulama biçimini güvenilir şekilde yakalıyor |
| `partial` | Tekniğin yalnızca bazı varyantlarını veya dolaylı izlerini yakalıyor |
| `low` | Zayıf sinyal; ancak başka kanıtla birlikte anlamlı |

Built-in ürün kapsamaları için varsayılan olarak `partial` kullan — bir ürünün
"bu tekniği kapsıyorum" demesi, o teknik için tam görünürlük anlamına gelmez.

## Çıktı formatı

SADECE aşağıdaki yapıda geçerli JSON üret. Açıklama, markdown kod bloğu
etiketi veya yorum satırı ekleme — çıktının tamamı doğrudan bir `.json`
dosyasına kaydedilebilir olmalı.

```json
{
  "schema": "soc-coverage-import",
  "version": 1,
  "generated_at": "YYYY-MM-DD",
  "products": [
    {
      "name": "Defender for Identity",
      "category": "tespit_kaynagi"
    }
  ],
  "rules": [
    {
      "name": "Suspicious PowerShell download",
      "product": "Defender for Endpoint",
      "kind": "custom",
      "techniques": ["T1059.001", "T1105"],
      "coverage_level": "full",
      "confidence": "high",
      "rationale": "PowerShell'in ağ üzerinden dosya indirme çağrılarını yakalar"
    }
  ],
  "product_coverage": [
    {
      "product": "Defender for Endpoint",
      "techniques": ["T1055", "T1003.001", "T1547.001"],
      "coverage_level": "partial",
      "note": "P2 built-in alert seti"
    }
  ]
}
```

### Alan kuralları

- `products[]` — GİRDİ'deki ürün başlıklarını **birebir aynı yazımla** buraya
  da kopyala (`rules[]`/`product_coverage[]` içindeki `product` alanıyla
  karakter karakter eşleşmeli). `category` şunlardan biri olmalı:
  `tespit_kaynagi` (tespit üretir, haritayı boyar), `onleyici_kontrol`
  (firewall/AV/yama — tespit üretmez), `zenginlestirme` (CTI beslemesi).
  Emin değilsen `tespit_kaynagi` yaz. Bu ürünün uygulamada zaten var olup
  olmadığını bilemezsin — varsa uygulama yok sayar (`noop`), sorun değil.
- `rules[]` — isimli her kural için bir kayıt. `kind`: kullanıcının kendi
  yazdığı kurallar için `custom`, ürünle gelenler için `builtin`.
- `product_coverage[]` — ürünün built-in setinin toplu kapsaması. **Yalnızca
  GİRDİ'de `(built-in)` işaretli ürünler için üret** (bkz. "Built-in
  tetikleme"). Uygulama bunu `"<Ürün> — Built-in kapsama"` adlı tek bir kayda
  dönüştürür. Built-in kuralların isimlerini biliyorsan onları ayrıca
  `rules[]` içinde tek tek de yazabilirsin — ikisi birbirini dışlamaz.

  > **Bunun ağırlığı bilinçli olarak düşüktür.** Ürün seviyesi bir iddia
  > tekniği "Tespit" kovasına sokmaz — yalnızca skora katkı yapar (kart amber
  > olur, kesikli çerçeveyle işaretlenir). Tek satırlık bir iddianın 120
  > tekniği birden kapsanmış göstermesi, haritanın cevapladığı soruyla
  > ("bu tekniği gerçekten görebiliyor muyuz") çelişirdi. İsimli kural her
  > zaman daha değerlidir.
- Boş kalan dizileri (`products`, `product_coverage`) yazmayabilirsin.

## GİRDİ

Ürün adlarını BEN belirliyorum — her grubun başlığı, o gruptaki kuralların
`product` alanına birebir geçecek isimdir. Aşağıya ürün başlığı + altına
kural adlarını yaz:

<!-- Örnek:

**DFE (built-in)**
- Özel yazdığım bir custom kural varsa buraya yazarım
(built-in işareti gördüğün için P2'nin hazır tespit setini de ayrıca
product_coverage olarak üretirsin — yukarıdaki "Built-in tetikleme" kuralı)

**QRadar**
- a kuralı
- b kuralı
(built-in yok, sadece bu iki isimli kural rules[]'a girer)
-->
````

---

## Şema referansı

Uygulamanın `POST /api/import/coverage/preview` ve `/apply` endpoint'lerinin
kabul ettiği yapı. Doğrulama `app.py` içindeki `_plan_coverage_import()`
fonksiyonundadır.

### Zorunlu üst alanlar

| Alan | Değer |
|---|---|
| `schema` | `"soc-coverage-import"` — başka bir değer dosyayı reddettirir |
| `version` | `1` |

### `products[]`

| Alan | Zorunlu | Not |
|---|---|---|
| `name` | evet | Katalogda varsa yok sayılır (`noop`) |
| `category` | hayır | `tespit_kaynagi` (varsayılan) / `onleyici_kontrol` / `zenginlestirme` |
| `color` | hayır | Verilmezse çakışmayan bir renk atanır |

> Yeni ürün oluşturmak **admin** yetkisi ister. Editor rolüyle yüklenen bir
> dosya yeni ürün içeriyorsa 403 döner ve hiçbir şey yazılmaz.

### `rules[]`

| Alan | Zorunlu | Not |
|---|---|---|
| `name` | evet | Kuralın adı; eşleştirme anahtarının yarısı |
| `product` | evet | Katalogda **veya** aynı dosyanın `products[]` bölümünde olmalı |
| `techniques` | evet | En az bir geçerli ATT&CK ID'si içeren dizi |
| `coverage_level` | hayır | `low` / `partial` / `full` (varsayılan `full`) |
| `kind` | hayır | `custom` / `builtin` — audit kaydına yazılır |
| `confidence`, `rationale` | hayır | Audit kaydına yazılır, karar izini korur |

### `product_coverage[]`

`rules[]` ile aynı alanlar, ama `name` yerine ürün adından türetilir:
`"<Ürün> — Built-in kapsama"`. `note` alanı `rationale` yerine geçer.
Varsayılan `coverage_level` burada `partial`.

Oluşan kayıt `rules.origin = 'product_claim'` ile işaretlenir. Etkisi:

| | İsimli kural (`rules[]`) | Ürün iddiası (`product_coverage[]`) |
|---|---|---|
| "Tespit" kovası | **girer** | girmez |
| Kapsama skoru | girer | **girer** (varsayılan `partial` = 0.60) |
| Harita | dolgu rengi + normal çerçeve | dolgu rengi + **kesikli amber çerçeve** |

Yani `partial` bir ürün iddiası, hedefi 2 olan bir teknikte 0.60/2 = **%30**
skor üretir — kart griden ambere döner ama asla yeşile ulaşmaz. Yeşil için
isimli tespit gerekir.

**Uyarı:** bir LLM'in bir ürünün built-in kural setine dair bilgisi
yaklaşıktır; senin tenant'ındaki gerçek alert kataloğu değildir. Mümkünse
konsoldan gerçek listeyi dışa aktar, model hafızasına dayanma.

### Doğrulama kuralları — hata (engelleyici) ve uyarı (engellemeyen) ayrımı

**Hata** yapısal bir sorundur; tek bir hata bile dosyanın tamamını reddettirir
(`/apply` 400 döner, hiçbir satır yazılmaz):

- `schema`/`version` yanlış veya eksik
- `name`/`product` eksik
- Katalogda olmayan ve `products[]`'ta da tanımlanmayan ürün
- Geçersiz `category` veya `coverage_level`

**Uyarı** dosyayı reddettirmez, o satırı etkiler:

- **Tanınmayan teknik ID'si.** Bir LLM'in ürettiği `T####` her zaman gerçek
  olmayabilir — `technique_config` tablosunda (senin `data/mitre.json`'ında)
  yoksa bu bir uyarıdır, hata değil. O ID satırdan atlanır; kuralın kalan
  geçerli teknikleri varsa onlarla, hiç kalmadıysa **tekniksiz** eklenir —
  elle "tekniksiz kural" eklemekle birebir aynı yol. Önizlemede "teknik yok"
  rozetiyle işaretlenir, uyguladıktan sonra **Veri Kalitesi** ekranında
  `unmapped_rule` olarak listelenir; oradan veya kural satırından elle teknik
  ekleyerek tamamlarsın.
- Boş `techniques: []` — aynı şekilde tekniksiz kural olarak eklenir.
- **Aynı `(name, product)` çifti dosyada birden fazla kez geçiyor.** Uzun
  listelerde bir LLM'in bir bloğu tekrarlaması bilinen bir hata modu —
  tekrar eden satırların teknikleri **birleştirilir** (union), ilk satırın
  `coverage_level`/`kind`/`rationale`'ı kullanılır. 300 satırlık bir dosyada
  13 satır ikişer kez tekrar etse bile geri kalan her şey uygulanır.

Yani **kısmi uygulama** teknik tanıma sorunları için vardır, yapısal
sorunlar için yoktur: bir dosyada hem uydurma ID'ler hem katalogda olmayan
bir ürün varsa, ürün hatası dosyanın tamamını yine de durdurur.

### Birleştirme semantiği

Mevcut bir kural (aynı ad + aynı ürün) yeniden yüklendiğinde:

- Kuralın **mevcut teknikleri asla silinmez**
- Dosyada olup kuralda olmayan teknikler **eklenir**
- Eklenecek bir şey yoksa satır `noop` olarak işaretlenir

Bunun bedeli: kaynak sistemden kaldırılan bir eşleme uygulamada kalır.
Karşılığında uygulamada elle yapılan eşlemeler asla kaybolmaz — bu bilinçli
bir tercihtir.

### CSV alternatifi

Basit durumlar için `Ayarlar > İçe Aktarım`'daki CSV yolu da aynı planlayıcıyı
kullanır. Başlık: `name,tech,source` (+ isteğe bağlı `coverage_level`).
Aynı kuralın birden fazla tekniği varsa her teknik için bir satır yaz; satırlar
tek kurala birleştirilir.

```csv
name,tech,source
Suspicious PowerShell download,T1059.001,Defender for Endpoint
Suspicious PowerShell download,T1105,Defender for Endpoint
```
