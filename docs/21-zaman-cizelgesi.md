# 21 — Zaman çizelgesi: kanıtları tek sırada görmek

Bir olay incelemesinin ilk sorusu çoğu zaman şudur: **"Ne oldu, hangi
sırayla?"** winspect'in kanıt komutları bunu parça parça bilir:

- `prefetch` bir programın ne zaman çalıştığını,
- `recyclebin` bir dosyanın ne zaman silindiğini,
- `usb` bir belleğin ne zaman takıldığını…

`timeline` bu parçaları **tek, zamana göre sıralı** bir listede birleştirir.
Fikir plaso / log2timeline'ın "süper zaman çizelgesi"dir; bizimki çok daha
küçük ve yalnızca winspect'in kendi okuduğu kaynakları kullanır.

```
winspect timeline                         # her şey, yeniden eskiye (UTC)
winspect timeline --since 48              # son 48 saat
winspect timeline --sources prefetch,bam,recyclebin --flagged
winspect timeline --csv > zaman.csv       # tabloya
```

## Nasıl çalışıyor

Yeni bir ayrıştırıcı yok. Her kaynak zaten var olan bir komuttur:

1. Komut, süreç içinde `--json` ile çalıştırılır. stdout geçici bir dosyaya
   yönlendirilip yakalanır (`capture.c`; `sweep` de aynı mekanizmayı
   kullanıyor, kod oradan taşındı).
2. Çıktı küçük bir JSON okuyucuyla (`jsonmini.c`) ağaca çevrilir.
3. Her kaynağın birkaç satırlık bir **çıkarıcısı** kayıtlardan satır üretir:
   `zaman | kaynak | ne oldu | ayrıntı | şüpheli mi`.
4. Satırlar sıralanır. Bütün kaynaklar UTC'yi `YYYY-AA-GG ss:dd:nn` biçiminde
   bastığı için düz metin sıralaması zaman sıralamasıdır.

Bir satır, kaynak kaydın `suspicious` işaretini taşır. Böylece `--flagged`
yalnızca işaretli olayları gösterir.

## Hangi zaman ne anlama geliyor

Zaman çizelgesinin en kolay hatası, bir zaman damgasına taşımadığı bir anlam
yüklemektir. Bu yüzden her kaynak için yalnızca **anlamı belli** zamanlar
alınır:

| Kaynak | Kullanılan zaman | Not |
|---|---|---|
| prefetch | son 8 çalışma zamanının her biri | çalıştırma kanıtı |
| bam | son çalışma | çalıştırma kanıtı |
| userassist | son açılış | kabuktan (Explorer) açılan programlar |
| shimcache | dosyanın **değiştirilme** zamanı | satır "not a run time" der; çalıştırma zamanı DEĞİLDİR |
| jumplist | son kullanım | açılan dosya |
| lnk | hedefin oluşturulma / değiştirilme zamanı | kısayolun kaydettiği hâliyle |
| shellbags | anahtar zamanı, **yalnızca MRU sırası 0** | anahtarın zamanı yalnızca en son eklenen/kullanılan girdiye aittir |
| recyclebin | silinme zamanı | |
| usb | ilk kurulum, son takılma, son çıkarma | |
| rdp, mru | anahtar zamanı, **yalnızca MRU sırası 0** | shellbags ile aynı gerekçe |
| pshistory | dosyanın son yazılma zamanı, **dosya başına tek satır** | satırların kendi zamanı yoktur; son komut gösterilir |
| users | son oturum, parolanın değiştiği zaman | |
| bits | iş oluşturma / tamamlanma | |
| tasks | görev XML'indeki `Date` | görevi yazanın beyanıdır, değiştirilebilir |
| comhijack | kullanıcı başına CLSID anahtarının zamanı | `--all` ile: tüm kullanıcı sınıfları |
| events | olay zamanı | kanal başına en fazla 200 olay |
| sysinfo | Windows kurulumu, son temiz kapanma, profilin son yüklenmesi | ağların ilk/son bağlantı zamanları kayıt defterinde **yerel saattir**; UTC listeye karışmasın diye alınmaz |

Kullanıcı başına kaynaklar (userassist, mru, jumplist, lnk, shellbags,
pshistory, comhijack) **komutu çalıştıran kullanıcıyı** okur.

## jsonmini — küçük ama sıkı bir JSON okuyucu

`timeline` diğer komutların çıktısını okumak zorunda. Bunun için RFC 8259'a
uyan küçük bir okuyucu yazıldı:

- Nesne, dizi, metin, sayı, `true` / `false` / `null`.
- Tüm kaçışlar; `\uXXXX` ve vekil çiftleri (surrogate pairs) UTF-8'e çevrilir.
- 64 seviye iç içe geçme sınırı.
- Bozuk girdi `NULL` döner; tamponun sonunu asla aşmaz.

**Doğrulama:**

- Birim testleri: her değer türü, kaçışlar, emoji, 18 bozuk örnek, derinlik
  sınırı, kısaltılmış uzunluk.
- **Diferansiyel test** (`tests/jm_diff.py`): rastgele üretilen binlerce
  geçerli belge Python'un `json` modülüyle aynı değere çözülmeli. Rastgele
  bozulmuş belgeler de tam olarak Python'un reddettiği durumlarda
  reddedilmeli. Python'un gevşek davrandığı `NaN` / `Infinity` / tek vekil
  durumları atlanır.
- Bu test ilk koşuda **gerçek bir hata buldu**: bir yüksek vekilin ardından
  gelen `\u` kaçışı geçersiz hex içerdiğinde okuyucu reddetmek yerine `?`
  yazıp devam ediyordu. Düzeltildi; iki regresyon testi eklendi.
- ASan/UBSan altında 300 bin fuzz turu.

## timeline doğrulaması

wine'daki fixture'lar birleştirilip şunlar kontrol ediliyor:

- satırlar yeniden eskiye sıralı;
- `EVIL.EXE`'nin prefetch dosyasındaki iki çalışma zamanı, iki işaretli satır
  olarak geliyor;
- Geri Dönüşüm Kutusu'ndaki `dropper.exe` doğru zamanla ve işaretli;
- shimcache satırları "çalıştırma zamanı değil" diyor;
- PowerShell geçmişi dosya başına tek, işaretli satır;
- `--since 1` eski fixture'ları dışarıda bırakıyor, `--sources` yalnızca
  istenen kaynağı veriyor, bilinmeyen kaynak hata veriyor.

## Bir imajdan zaman çizelgesi: --root

`timeline --root E:\` aynı kaynakları canlı makine yerine bağlanmış bir imajın
dosyalarıyla çalıştırır. Kanıt bulma işi `image` ile ortaktır (`imgpaths.c`):

- **Makine geneli, bir kez:** Prefetch klasörü; SYSTEM hive'ından bam,
  shimcache, usb; Amcache; Geri Dönüşüm Kutusu; SAM'dan hesaplar; görev
  klasörü; SOFTWARE/SYSTEM'den sysinfo; bulunan `.evtx` dosyaları.
- **Her profil için:** NTUSER.DAT'tan userassist, mru, rdp; NTUSER +
  UsrClass'tan shellbags; `Recent` klasöründen lnk ve Jump List'ler;
  PSReadLine geçmişi; UsrClass + SOFTWARE'den kullanıcı başına COM sınıfları.

Kullanıcı başına satırlar profil adını taşır (`"user": "bob"`). Böylece birden
çok kullanıcılı bir imajda kimin ne yaptığı ayrışır.

**Amcache** yalnızca bu modda kaynaktır. Canlı makinede dosya kilitli
olduğundan okunamaz. Satır zamanı, Amcache'in o dosya için kaydı yazdığı
zamandır; yaklaşık olarak ilk çalışma ya da kurulum anını verir, kesin bir
çalışma zamanı değildir.

**Doğrulama:**

- Sentetik imaj (`C:\img2`): prefetch, geri dönüşüm, hesap, bob'un COM ve
  PowerShell satırları, yeniden eskiye sıra.
- regipy hive'larından kurulan imaj: shimcache, bob'un UserAssist / ShellBags
  / COM satırları ve SOFTWARE'deki kurulum zamanı (2010-11-10 16:28:55).
