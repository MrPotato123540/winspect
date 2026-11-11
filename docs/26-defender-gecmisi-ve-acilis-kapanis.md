# 26 — Defender tespit geçmişi ve açılış / kapanış geçmişi

Bu bölüm iki yeni komutu ve EVTX okuyucusunda bulunan bir sadakat hatasını
anlatır.

| Terim | Anlamı |
|---|---|
| **Tespit (detection)** | Defender'ın bir dosyayı zararlı bulduğu olay. |
| **Remediation** | Defender'ın tespit ettiği dosyaya müdahalesi (karantina, silme). |
| **FILETIME** | Windows'un zaman biçimi: 1601-01-01'den beri geçen 100 nanosaniyelik adım sayısı (64 bit). |
| **Klasik olay** | Alanları adsız, yalnızca sırayla verilen eski tip olay günlüğü kaydı (`<Data>` etiketlerinin `Name` özniteliği yoktur). |
| **Kayıt sırası** | Olayların günlüğe **yazıldığı** sıra. Zaman damgası sırasıyla aynı olmak zorunda değildir. |

---

## 1. `detections`: Defender daha önce ne yakaladı?

Defender her tespit için küçük bir ikili dosya yazar:

```
C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\<nn>\<GUID>
```

Bu dosyalar olay günlüğü temizlendikten ve karantina boşaltıldıktan sonra da
kalır. "Şu an temiz görünen bu makinede daha önce bir şey bulundu mu?"
sorusunun cevabı buradadır.

```
winspect detections                    # canlı (yönetici gerekir)
winspect detections E:\kopya\DetectionHistory
winspect detections --find mimikatz
```

Gerçek bir dosyadan çıktı:

```
[!] 2022-07-22 05:36:18  Virus:DOS/EICAR_Test_File
        file        C:\Users\testuser\Downloads\eicar_com.zip->eicar.com
        inside      C:\Users\testuser\Downloads\eicar_com.zip
        from        https://secure.eicar.org/eicar_com.zip
        sha256      275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
        user        FRYPTOP\testuser
        remediated  2022-07-22 05:37:02 by NT AUTHORITY\SYSTEM
```

- `file ... ->eicar.com`: dosya bir arşivin içindeydi; `inside` arşivin kendisi.
- `from`: Defender indirmenin geldiği URL'yi de kaydetmiş.
- `remediated`: ne zaman ve hangi hesapla müdahale edildiği. Bu satır
  `no remediation recorded` ise tehdit hâlâ yerinde olabilir.

### Dosya biçimi (`src/defhist.c`)

Dosyanın tamamı, art arda dizilmiş **değerlerden** oluşur. Her değer:

```
u32 boyut | u32 tür | <boyut> bayt veri | 8'in katına tamamlayan dolgu
```

| Tür | İçerik |
|---|---|
| `0x15` | UTF-16 metin |
| `0x06`, `0x05` | 32 bit sayı |
| `0x08` | 64 bit sayı (ilk değer: tehdit kimliği) |
| `0x0A` | FILETIME |
| `0x1E` | GUID |
| `0x28` | adlandırılmış özellikler bloğu (`ThreatTrackingSha256` burada) |

Sıra anlam taşır: önce tehdit adı, sonra her **kaynak** için
(`"Magic.Version:1.2"`, tür, konum, özellik bloğu), en sonda zamanlar ve
hesaplar. Ayrıştırıcı bu yüzden küçük bir durum makinesidir.

Güvenlik açısından önemli satır, her değerin boyutunun dosya sınırına karşı
denetlenmesi:

```c
if (size > n - (off + 8)) break;    // value runs past the file: stop, keep what we have
```

`size` dosyadan okunan, güvenilmeyen bir sayıdır. Bu satır olmasa bozuk bir
dosya ayrıştırıcıyı tamponun dışına okutabilirdi. Bilinmeyen bir tür
yorumlanmaz, boyutu kadar atlanır.

### Doğrulama

plaso projesinin test verisindeki **üç gerçek dosya** kullanıldı (yalnızca
veri, kod çalıştırılmadı):

- plaso'nun kendi testinin beklediği değerler: tehdit adı ve kimliği, dosya,
  kullanıcı, süreç, SHA-256, iki zaman damgası.
- Dosyanın içindeki GUID, dosyanın **adına** eşit olmalı. Bu, GUID
  çözümlemesinin bağımsız bir sağlamasıdır.
- EICAR dosyalarında SHA-256, EICAR test dizgisinin herkesçe bilinen özeti.

Ardından her dosyanın 300.000 bozulmuş kopyası ASan / UBSan altında
ayrıştırıldı.

---

## 2. `boots`: makine ne zaman açıktı?

Linux'taki `last -x` ve `uptime` fikri. Üç şeyi gösterir:

1. Her açılış ve kapanış; oturumun ne kadar sürdüğü ve temiz bitip bitmediği.
2. Kapanışı **kimin, hangi programla, hangi gerekçeyle** istediği.
3. Sistem saatinin bir dakika veya daha fazla değiştirildiği anlar.

Neden önemli: makine kapalıyken etkinlik olamaz; açıklanamayan bir yeniden
başlatma ya da çökme bir ipucudur; saati geri alınmış bir makinede o döneme
ait **tüm diğer zaman damgaları** şüphelidir.

| Olay | Kaynak | Anlamı |
|---|---|---|
| 12 | Kernel-General | işletim sistemi başladı |
| 13 | Kernel-General | işletim sistemi kapanıyor |
| 1 | Kernel-General | sistem saati değişti (eski ve yeni değer) |
| 41 | Kernel-Power | temiz kapanmadan yeniden başladı (elektrik, reset, çökme) |
| 6008 | EventLog | önceki kapanış beklenmedikti |
| 1074 | User32 | bir süreç kapatma / yeniden başlatma istedi |

Olay numarası tek başına yetmez: 12 ve 13 başka sağlayıcılarda başka anlama
gelir. Bu yüzden **sağlayıcı adı ile numara birlikte** denetlenir.

### Saat geri alınınca sıralama bozulur

Gerçek bir günlükten:

```
2015-08-08 09:14:04  shutdown   operating system shutting down
2015-08-08 09:12:25  clock      system clock set BACK by 8h 59m (2015-08-08 18:12:24 -> 2015-08-08 09:12:25)
2015-08-08 18:08:23  boot       ...; shut down cleanly (uptime unknown: the clock was changed in between)
```

Aşağıdan yukarı okunur (en yeni üstte). Makine saati 9 saat ileriyken açılmış
(18:08), saat düzeltilmiş (09:12), sonra kapanmış (09:14).

İlk sürüm satırları **zaman damgasına göre** sıralıyordu. O zaman 18:08'deki
açılış, 09:14'teki kapanıştan *sonra* görünüyor ve yanlış kapanışla
eşleşiyordu. Düzeltme: satırlar olayların **yazıldığı sırada** tutulur.

```c
// Rows stay in the order the events were WRITTEN (record order), not
// sorted by timestamp: when the clock is set back, a later event carries
// an earlier time, and sorting would pair boots with the wrong shutdown.
```

Saat değişiklikleri **işaretlenmez**: saat dilimi düzeltmesi, sanal makineler
ve Linux ile çift açılış bunları meşru olarak üretir. Bir dakikadan küçük
düzeltmeler (zaman eşitleme) hiç gösterilmez.

### 1074: kim istedi?

1074 klasik bir olaydır; yedi alanı adsız ve sıralıdır:

| Sıra | İçerik |
|---|---|
| 0 | süreç (ve parantez içinde makine adı) |
| 2 | gerekçe metni |
| 4 | tür (`restart`, `power off`) |
| 5 | yorum |
| 6 | kullanıcı |

Çıktı: `restart requested by NT AUTHORITY\SYSTEM via winlogon.exe: Operating System: Upgrade (Planned)`.

---

## 3. Bulunan hata: klasik olayların alanları birleşiyordu

`boots` yazılırken ortaya çıktı. Klasik olaylarda dizgiler dosyada bir
**dizi** olarak saklanır. Windows API'si bunu, öğeyi her dizgi için
tekrarlayarak yazar:

```xml
<Data>C:\Windows\system32\winlogon.exe (HOST)</Data><Data>HOST</Data><Data>Operating System: Upgrade (Planned)</Data>...
```

Kendi EVTX okuyucumuz ise hepsini tek öğede boşlukla birleştiriyordu:

```xml
<Data>C:\Windows\system32\winlogon.exe (HOST) HOST Operating System: Upgrade (Planned) ...</Data>
```

Boşluk içeren alanlar olduğu için bu geri ayrıştırılamaz. Şimdiye kadar fark
edilmemişti, çünkü `events` yalnızca **adlı** alanları (`<Data Name='...'>`)
okuyordu.

Düzeltme (`src/evtx.c`): bir öğenin içeriği bir dizgi dizisiyse, açılış
etiketi (öznitelikleriyle birlikte) her dizgi için yinelenir. plaso'nun
beklenen değerleriyle karşılaştırma ve fuzz testleri yeniden geçti. CI'da
gerçek Windows'ta `boots` çıktısı, canlı API ile dışa aktarılmış günlük
arasında satır satır karşılaştırılıyor; bu hata tekrar ederse orada kırılır.

## Doğrulama özeti

| Ne | Kaynak |
|---|---|
| `detections` ayrıştırıcısı | plaso'nun 3 gerçek dosyası + fuzz |
| `boots` olay sayıları | plaso `System.evtx`, sağlayıcı + numara ile bağımsız sayım (8 açılış, 5 kapanış, 9 istek, 2 × 41, 1 × 6008) |
| `boots` eşleştirme | ilk açılış 06:00:04 → 06:03:59 = 235 s, elle hesap |
| EVTX dizi düzeltmesi | 1074'ün belgelenmiş yedi alanı ayrı ayrı çıkıyor |
