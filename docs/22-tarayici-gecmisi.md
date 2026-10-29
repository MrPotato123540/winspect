# 22 — Tarayıcı geçmişi ve indirmeler: kendi SQLite okuyucumuz

Bir olayda en sık sorulan sorulardan biri: **"Bu dosya nereden geldi?"**
Kullanıcı bir eki ya da "fatura.exe"yi tarayıcıyla indirdiyse cevap tarayıcının
geçmiş veritabanındadır. `browser` komutu bunu okur:

```
winspect browser                         # şu anki kullanıcı, tüm tarayıcılar/profiller
winspect browser --downloads --flagged   # yalnızca şüpheli indirmeler
winspect browser --all-users             # C:\Users altındaki herkes (yönetici)
winspect browser D:\kopya\History        # kopyalanmış tek bir veritabanı
winspect browser --home E:\Users\bob     # bir imajdaki tek kullanıcı klasörü
```

## Nerede, ne var

| Tarayıcı | Dosya | Tablolar |
|---|---|---|
| Chrome, Edge, Brave (Chromium) | `<User Data>\<profil>\History` | `urls` (URL, başlık, ziyaret sayısı, son ziyaret), `downloads` (kayıt yolu, başlangıç, boyut, **danger_type**), `downloads_url_chains` (yönlendirme zinciri; 0. sıra ilk URL) |
| Firefox | `Profiles\<profil>\places.sqlite` (+ `places.sqlite-wal`) | `moz_places` (URL, başlık, son ziyaret), `moz_annos` + `moz_anno_attributes` (`downloads/destinationFileURI` = indirilen dosyanın yolu) |

Zaman birimleri farklıdır: Chromium 1601'den beri mikrosaniye, Firefox
1970'ten beri mikrosaniye. İkisi de UTC'ye çevrilir.

**Sütunlar adla bulunur.** Chrome her sürümde `downloads` tablosuna sütun
ekliyor; sırayla okumak bir sonraki sürümde yanlış sütunu okumak demek. Bu
yüzden her tablonun sütun adları `sqlite_master`'daki `CREATE TABLE`
metninden çıkarılır (`sqlite_parse_columns`, birim testli). `ALTER TABLE ADD
COLUMN` o metnin sonuna eklendiği için onu da kapsar.

## İşaretler (`browser_reason`, birim testli)

| Gerekçe | Neden |
|---|---|
| user kept a download the browser warned about | Chromium `danger_type = 6`: tarayıcı uyardı, kullanıcı yine de tuttu |
| browser warned about this download | diğer sıfır olmayan `danger_type` değerleri |
| downloaded from a bare IP address | meşru siteler alan adı kullanır |
| downloaded a program or script | hedef `.exe/.dll/.ps1/.js/.hta/...` |
| visited a bare IP address | `http(s)://<IPv4>/...` |

## SQLite okuyucusu (`src/sqlite.c`)

SQL motoru yok; yalnızca dosya biçimini okur (sqlite.org'un "Database File
Format" belgesi):

- **Başlık** (100 bayt): sayfa boyutu, sayfa sonunda ayrılmış baytlar, metin
  kodlaması (UTF-8 / UTF-16le / UTF-16be).
- **B-ağacı sayfaları:** tablo yaprak (`0x0D`) ve iç (`0x05`) sayfaları, hücre
  işaretçileri.
- **Hücre:** yük boyutu (varint), rowid (varint), yük. Yük sayfaya sığmazsa
  bir **taşma sayfası zincirine** devam eder. Ne kadarının sayfada kalacağı
  belgedeki formülle hesaplanır.
- **Kayıt:** başlıkta her sütunun "seri tipi" (NULL, 1–8 baytlık tamsayı,
  ondalık, sabit 0/1, metin, blob), ardından değerler. `INTEGER PRIMARY KEY`
  sütunu kayıtta NULL olarak durur; değeri rowid'dir.
- **WAL:** Firefox yeni sayfaları önce `places.sqlite-wal` dosyasına yazar ve
  ancak "checkpoint"te ana dosyaya taşır. Tarayıcı açıkken alınan bir kopyada
  son ziyaretler **yalnızca WAL'dedir**. Okuyucu WAL'i uygular: tuzları (salt)
  geçerli ve son "commit" çerçevesine kadar olan çerçevelerden her sayfanın en
  yeni kopyası kazanır, tıpkı SQLite'ın kendisinin okuduğu gibi.

### Doğrulama

- **Diferansiyel test** (`tests/sqlite_diff.py`): Python'un standart
  `sqlite3` modülüyle rastgele veritabanları üretilir. Bunlarda şunlar var:
  - sayfa boyutu 512–65536,
  - üç metin kodlaması,
  - taşma sayfası gerektiren 70 KB'a kadar değerler,
  - her genişlikte tamsayılar ve ondalıklar,
  - silinmiş satırlar,
  - iç sayfalı büyük tablolar,
  - checkpoint yapılmamış WAL.

  Her satır Python'un okuduğuyla birebir aynı olmalı. Sütun adları da
  `PRAGMA table_info` ile karşılaştırılır (tırnaklı adlar, `ALTER TABLE`).
  Sonuç 0 fark.
- Bu test ilk turda **bir hata buldu**. UTF-16 bir veritabanı WAL modundayken
  metin kodlaması ana dosyada değil, WAL'deki 1. sayfanın yeni kopyasındaydı.
  Okuyucu tablo adlarını bulamıyordu. Düzeltildi.
- **Fuzz** (ASan/UBSan, gerçek bir veritabanı + WAL'in bozulmuş kopyaları)
  **ikinci bir hata buldu**. Bozuk bir WAL "veritabanı N sayfa" dediğinde,
  WAL'de olmayan sayfalar için ana dosyanın **dışı** okunuyordu. Artık ana
  dosyada gerçekten bulunmayan sayfa yok sayılıyor. Düzeltmeden sonra 20.000
  turda 3,9 milyon satır okundu, bulgu yok.
- wine'da uçtan uca: gerçek Chrome şemasıyla bir `History` (iki ziyaret, iki
  indirme; biri uyarıya rağmen tutulmuş exe) ve WAL modunda, satırları
  **yalnızca WAL'de** olan bir Firefox `places.sqlite`. Bütün işaretler ve
  işaretsiz kalması gerekenler kontrol edilir. Aynı History, `image` ve
  `timeline --root` testlerinde sentetik imajın içinde de kullanılır.

## Bağlantılar

- `timeline`: canlıda ve `--root` ile imajda kaynak (her ziyaretin son
  zamanı, her indirme).
- `image`: her profil için `browser --home` çalıştırılır; işaretli satırlar
  bulgu olur.
- `sweep`: `browser --all-users --flagged`.
