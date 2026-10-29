# 24 — SRUM ve ESE: hangi program ne kadar veri gönderdi?

Windows 8'den beri **System Resource Usage Monitor** (SRUM), her uygulamanın
ve kullanıcının kaynak kullanımını saat saat kaydeder:
`C:\Windows\System32\sru\SRUDB.dat`.

En değerli tablosu **ağ kullanımı**: hangi program, hangi kullanıcıyla, hangi
saatte, hangi arayüzden kaç bayt gönderdi / aldı. Veri sızdırma ("exfiltration")
şüphesinde ilk bakılacak yerlerden biri.

```
winspect srum C:\vaka\SRUDB.dat --summary        # uygulama başına toplam, en çok gönderen önce
winspect srum C:\vaka\SRUDB.dat --find rclone    # bir programın saatlik satırları
winspect srum C:\vaka\SRUDB.dat --apps           # CPU döngüleri, diske yazılan bayt
winspect srum C:\vaka\SRUDB.dat --connectivity   # bağlantı süreleri
```

Canlı dosya kilitlidir; önce kopyalanır:
`esentutl /y C:\Windows\System32\sru\SRUDB.dat /vss /d C:\vaka\SRUDB.dat`.

## ESE okuyucusu (`src/esedb.c`)

`SRUDB.dat` bir **ESE** (Extensible Storage Engine, "JET Blue")
veritabanıdır. Aynı biçim Windows Search, WebCache ve Active Directory'de de
kullanılır. Okuyucu SQL motoru değildir; tablo B+ ağaçlarını yürür ve
kayıtları çözer:

- **Dosya başlığı** (0. sayfa): imza `0x89ABCDEF`, biçim revizyonu, sayfa
  boyutu. N. sayfa `(N + 1) × sayfa boyutu` adresindedir.
- **Sayfa:** 40 baytlık başlık (16/32 KB sayfalarda 80). Bayraklar: kök,
  yaprak, dal, long-value ağacı. Girdiler sayfanın **sonundaki** etiket
  dizisiyle bulunur (her etiket: konum, boyut, bayraklar).
- **Girdi:** [ortak anahtar boyu] + yerel anahtar + veri. Dal sayfalarında veri,
  alt sayfanın numarasıdır.
- **Katalog** (`MSysObjects`, 4. sayfa): tablolar, sütunları (no, tip, boy) ve
  long-value ağaçları. Tablolar adla bulunur, sütunlar adla okunur.
- **Kayıt:** son sabit sütun no | son değişken sütun no | değişken alanın yeri |
  sabit sütunlar (+ NULL bit eşlemi) | değişken sütun bitiş konumları ve veri |
  etiketli sütunlar (no, konum, bayrak baytı). Büyük değerler long-value
  ağacından parça parça birleştirilir.

**Bulunan bir incelik:** uygulama kullanımı tablosu ilk okumada **0 satır**
verdi. Kök sayfası açıkça bir dal sayfasıydı (girdiler alt sayfa numarası
taşıyordu) ama "dal" bayrağı set değildi. Kural "yaprak değilse daldır" diye
düzeltildi ve tablo 16.183 satır verdi.

**İkinci incelik:** `TimeStamp` bir OLE otomasyon tarihi, yani 1899-12-30'dan
beri gün sayısını tutan bir `double`. 13:33:00, `…13:32:59.999997` olarak
okunuyor; saniyeyi kesen bir dönüşüm **13:32:59** basardı. Değer
milisaniyeye (anlamlı hassasiyetine) yuvarlanıyor.

## SRUM tabloları

| Tablo | İçerik |
|---|---|
| `{973F5D5C-…}` ağ kullanımı | zaman, uygulama, kullanıcı, arayüz LUID'i, gönderilen / alınan bayt |
| `{D10CA2FE-…}` uygulama kaynak kullanımı | ön/arka plan CPU döngüleri, okunan/yazılan bayt |
| `{DD6636C4-…}` ağ bağlantısı | bağlantı başlangıcı (FILETIME), süresi |
| `SruDbIdMapTable` | kimlik → program yolu / servis adı / uygulama kimliği (UTF-16) ya da SID |

İşaret: kullanıcının yazabildiği bir klasördeki (Downloads, Temp, AppData…)
program veri **gönderdiyse**. plaso'nun gerçek test veritabanında bu kural
Downloads'tan çalışmış iki kurulum programını gösteriyor.

## Doğrulama

- **plaso'nun `SRUDB.dat`'ı** (yalnızca veri, sabit commit):
  - üç tablodaki toplam kayıt **18283** (plaso testindeki sayı);
  - ağ satırı 3495: DiagTrack, 2076 bayt, arayüz LUID'i, S-1-5-18, 11:32;
  - uygulama satırı 22167: "Memory Compression";
  - bağlantı satırı 501: başlangıç 2017-11-05 10:30:48.1679714.

  Hepsi birebir aynı.
- Gerçek dosyanın bozulmuş kopyalarıyla ASan/UBSan fuzz: sayfa başlıkları,
  etiket dizileri, anahtar ve kayıt boyları, alt sayfa numaraları,
  long-value referansları. 150 tur, 1,1 milyon satır, bulgu yok.
- wine'da uçtan uca: satırlar, özet sırası, işaret, bağlantı zamanı
  yuvarlaması.
- `image`: imajda `Windows\System32\sru\SRUDB.dat` varsa
  `srum --summary` işaretleri bulgu olarak gelir.

**Sınır:** sıkıştırılmış değerler (Windows 8+ ESE, büyük metin / ikili
sütunlarda 7-bit / XPRESS) çözülmez, "sıkıştırılmış" olarak bildirilir. Test
veritabanında hiç yok; gerçek bir örnekle doğrulanmadan çözücü eklenmeyecek.
