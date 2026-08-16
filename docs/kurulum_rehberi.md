# Sifirdan Kurulum ve Veri Geri Yukleme Rehberi (Linux)

Bu belge, uygulamayi bos bir Linux makinede Docker ile en bastan kurup
mevcut gercek veriyi (soc.db) geri yuklemek icin adim adim izlenecek
pratik rehberdir. Komutlar bash icindir (Ubuntu/Debian/RHEL farketmez,
sadece Docker'in kendi kurulum adimi dagitima gore degisebilir). Mimari
detaylar icin bkz. [backup_restore.md](backup_restore.md) — bu belge onun
tekrari degil, sirali "yap-bitir" versiyonudur.

Windows + PowerShell ile kuruyorsaniz onun yerine bu belgenin onceki
surumune bakin (git gecmisinde); asagidaki her komutun mantigi aynidir,
sadece sozdizimi farklidir.

## 0. Elinizde olmasi gerekenler

- En guncel yedek dosyasi ve imzasi (`backups/` klasorunden alinir veya
  sohbet uzerinden gonderilmis olabilir). Yazim aninda en guncel yedek:
  `soc-20260729-105350.db.gz` + `soc-20260729-105350.db.gz.sha256`.
  > Ileride yeni bir yedek alirsaniz (`scripts/backup_db.py`), asagidaki
  > adimlarda dosya adini o an elinizdeki EN YENI `.db.gz` ile degistirin.
- Hedef makinede internet baglantisi.
- `sudo` yetkisi (Docker kurulumu icin).

## 1. Docker kurulumu

En kolay ve dagitimdan bagimsiz yol, Docker'in resmi kurulum script'i:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Bu ikinci komuttan sonra **oturumu kapatip acin** (veya `newgrp docker`
calistirin) — yoksa her `docker` komutunda `sudo` gerekir. Kurulumu
dogrulayin:

```bash
docker --version
docker compose version
```

`git` kurulu degilse: `sudo apt install -y git` (Debian/Ubuntu) veya
dagitiminizin kendi paket yoneticisi.

## 2. Kodu cekin

```bash
git clone https://github.com/ocobayhan/mitre-coverage-map.git
cd mitre-coverage-map
```

`data/mitre.json` (MITRE ATT&CK veri seti) ve `data/rules_seed.json`
repoya dahildir — ayrica indirmenize gerek yok.

## 3. .env dosyasini olusturun

Tek komutla, elle duzenleme gerekmeden:

```bash
cat > .env <<EOF
SOC_SECRET_KEY=$(openssl rand -hex 32)
SOC_COOKIE_SECURE=0
EOF
```

Bu komut `openssl` ile 32 byte rastgele bir deger uretir ve dogrudan
`.env` dosyasina yazar (`openssl` neredeyse her Linux dagitiminda hazir
gelir; yoksa `sudo apt install -y openssl`). `SOC_COOKIE_SECURE`'u `0`
birakin — yalnizca HTTPS/ters proxy arkasindaysaniz `1` yapin.

Kontrol edin:

```bash
cat .env
```

`SOC_SECRET_KEY=` satirinda 64 karakterlik bir hex deger gormelisiniz.

> **Onemli:** Bu degeri baska bir kurulumdan kopyalamayin — her ortamin
> kendi benzersiz anahtarini `openssl rand -hex 32` ile uretmesi gerekir.
> Ayni anahtari birden fazla yerde kullanmak, o anahtari bilen herkesin
> oturum cerezlerini sahtelemesine izin verir.

## 4. Port ayari (gerekliyse)

Varsayilan `docker-compose.yml` uygulamayi host'ta 8000 portunda acar.
Farkli bir port istiyorsaniz (ornegin 9293):

```bash
sed -i 's/"8000:8000"/"9293:8000"/' docker-compose.yml
```

Sadece host tarafi (ilk sayi) degisir; container ici her zaman 8000'de
kalir, baska hicbir dosyaya dokunmaniza gerek yok. Rehberin geri
kalaninda `<PORT>` gordugunuz yerde sectiginiz portu (8000 veya 9293)
kullanin.

## 5. Ilk ayaga kaldirma (veri yuklemeden once)

```bash
docker compose up -d --build
```

Bu, `soc_data` adinda bir Docker named volume olusturur ve ilk
calistirmada `init_db()` varsayilan hesaplari (`admin/Admin123!` vb.) ve
`data/rules_seed.json`'daki ornek tespitleri olusturur. Birazdan bunlarin
uzerine gercek veriyi yazacagimiz icin simdi giris yapmaniza gerek yok.

Container'i durdurup kaldirin (volume silinmez, sadece calisan surec ve
container nesnesi kalkar):

```bash
docker compose down
```

## 6. Volume adini dogrulayin

```bash
docker volume ls
```

`mitre-coverage-map_soc_data` benzeri bir isim gormelisiniz (on ek,
klasor adindan turetilir — farkli bir klasor adiyla klonladiysaniz on ek
de farkli olur; listeden tam adi kopyalayin).

## 7. Yedek dosyalarini yerlestirin ve dogrulayin

```bash
mkdir -p backups
```

Iki dosyayi (`soc-20260729-105350.db.gz` ve `.sha256` imzasi) bu klasore
kopyalayin (`scp`, `sftp`, veya nasil tasidiysaniz).

Butunluk kontrolu:

```bash
sha256sum backups/soc-20260729-105350.db.gz
cat backups/soc-20260729-105350.db.gz.sha256
```

Iki ciktidaki hash (ilk 64 karakter) birebir eslesmeli.
> Not: `.sha256` dosyasi Windows'ta uretildigi icin satir sonu CRLF —
> `sha256sum -c backups/*.sha256` otomatik dogrulamasi bu yuzden hata
> verebilir. Yukaridaki gibi elle karsilastirmak en guvenlisi; otomatik
> `-c` calismasini istiyorsaniz once `sed -i 's/\r$//' backups/*.sha256`
> ile CRLF'yi temizleyin.

## 8. Gercek veriyi volume'e yazin

Asagidaki komut gecici bir container acar; hem `soc_data` named volume'u
hem de az once yedegi koydugunuz `backups` klasorunu ayni anda gorur,
yedegi acip `soc.db` olarak volume'un icine yazar. `<VOLUME_ADI>` yerine
6. adimda gordugunuz tam ismi yazin:

```bash
docker run --rm -v <VOLUME_ADI>:/instance -v "$(pwd)/backups:/backups" alpine sh -c "gunzip -c /backups/soc-20260729-105350.db.gz > /instance/soc.db"
```

## 9. Yeniden baslatin ve dogrulayin

```bash
docker compose up -d
```

Baska bir makineden tarayiciyla `http://<bu-makinenin-ip-adresi>:<PORT>`
adresine gidin (SOC_HOST=0.0.0.0 oldugu icin tum aglardan erisilebilir).
Makinenin kendi ucundan hizli bir kontrol icin:

```bash
curl -I http://localhost:<PORT>/login
```

`200 OK` beklenir. Tarayicidan **varsayilan degil, gercek hesabinizla**
giris yapin — veri gercek yedekten geldigi icin varsayilan seed hesaplari
artik yerinde degil. Kurallar sayfasinda kayit sayisinin beklediginiz
gibi oldugunu kontrol edin.

## 10. Sonrasi

- Duzenli yedekleme kurulumu, mimari detaylar ve alternatif kurtarma
  yontemleri icin: [backup_restore.md](backup_restore.md)
- Sorun giderme: `docker compose logs -f app`
