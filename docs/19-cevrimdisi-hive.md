# 19 — Çevrimdışı registry: hive dosyası okuyucu

Canlı registry yalnızca **oturum açmış** kullanıcının hive'ını gösterir.
Bir başka kullanıcının `NTUSER.DAT`'ı, bir disk imajından çıkarılmış `SYSTEM`
ya da bir triage aracının topladığı `Amcache.hve` için Windows API'si işe
yaramaz; dosyayı kendimiz okumamız gerekir. Registry Explorer ve regipy bu
fikrin bilinen araçlarıdır. Biz yalnızca **fikri** aldık; okuyucu herkese açık
biçim notlarından sıfırdan yazıldı (`src/regf.c`, taşınabilir C).

## Biçim, kısaca

- **Temel blok (4096 bayt):** `regf` imzası, iki sıra numarası, son yazma
  zamanı, kök anahtar hücresi, sağlama toplamı (ilk 127 dword'ün XOR'u).
- **Hive bin'leri** ve içlerindeki **hücreler:** her hücre `i32 boyut` (negatif
  = kullanımda) + veri. Bütün ofsetler ilk bin'e göredir (dosya ofseti 4096).
- **`nk`** anahtardır: ad (Latin-1 ya da UTF-16), son yazma zamanı, alt anahtar
  ve değer listeleri. **`lf`/`lh`/`li`/`ri`** alt anahtar dizinleridir (`ri` =
  liste listesi).
- **`vk`** değerdir: 4 bayta kadar olan veri satır içi (inline) saklanır (veri
  boyutunun en üst biti). 16344 bayttan büyük veri bir **`db`** kaydı üzerinden
  parçalara bölünür.

Her ofset, boyut ve sayı dosya sınırına göre denetlenir. Dizin listeleri bir
derinlik sınırıyla yürünür; sahte ya da döngülü bir hive okuyucuyu sınırların
dışına okutamaz veya sonsuz döngüye sokamaz.

**Kirli hive:** iki sıra numarası farklıysa son değişiklikler `.LOG1`/`.LOG2`
dosyalarında durur. Bunları uygulamıyoruz; bunun yerine durumu açıkça
söylüyoruz (`dirty`). Sessizce eksik veri göstermek, eksik olduğunu söylemekten
kötüdür.

## Kullanım

```
winspect hive NTUSER.DAT "Software\Microsoft\Windows\CurrentVersion\Run"
winspect hive SYSTEM Select --json
winspect hive Amcache.hve --recurse --json

winspect userassist --hive C:\vaka\bob\NTUSER.DAT
winspect mru        --hive C:\vaka\bob\NTUSER.DAT
winspect bam        --hive C:\vaka\SYSTEM
winspect shimcache  --hive C:\vaka\SYSTEM
```

`--hive` ile çalışan komutlar canlı modla **aynı kodu** kullanır. Aradaki ince
katman `src/regsrc.c` ya Win32 registry API'sini ya da `regf.c`'yi çağırır.
`SYSTEM` hive'ında `CurrentControlSet` bağlantısı yoktur; geçerli control set
`Select\Current`'tan bulunur. Yabancı bir hive'da SID'ler ve Known Folder
GUID'leri bu makineye göre çözülmez, çünkü yanlış sonuç verir; oldukları gibi
gösterilir.

Çalışan Windows'un kendi kullandığı hive (`C:\Windows\System32\config\SYSTEM`)
kilitlidir. Komut bunu "in use" diye söyler; kopyalamak için `reg save` ya da
VSS kullanılmalı.

## Doğrulama: başkasının gerçeklerine karşı

Kahin, regipy projesinin gerçek Windows hive'larıdır (yalnızca `.xz` veri
dosyaları; kod çalıştırılmadı, CI sabit commit'ten çeker). O projenin
testlerinin bu dosyalar hakkında doğruladığı gerçekler:

| Kontrol | Sonuç |
|---|---|
| NTUSER.DAT başlığı: sıra numaraları, zaman, sürüm, kök ofseti, gömülü yol, sağlama toplamı | aynı |
| Kök anahtarın adı ve 11 alt anahtarı | aynı |
| Tüm ağaç: 1812 anahtar, 4094 değer, tip dağılımı | aynı |
| amcache.hve: 2105 anahtar, 17539 değer, tip dağılımı | aynı |
| Run anahtarının zamanı, ilk değeri (`Sidebar`, REG_EXPAND_SZ) | aynı |
| Satır içi REG_SZ (`"1"`, `"vm3dmp"`) ve REG_BINARY (`0904`) | aynı |
| UTF-16 emoji içeren anahtar adı | aynı |
| Aygıt özelliği değeri (tip `0xFFFF0012`) | aynı |
| Kısmi (dışa aktarılmış) hive: 6396 anahtar | aynı |

Komut düzeyinde (`tests/wine/hives.py`, wine altında gerçek `.exe`):

- **userassist:** 29 program; EXCEL.EXE ve RemoteDesktop'ın çalıştırma
  sayıları ve zamanları regipy ile aynı. regipy 62 diyor, çünkü iki
  `UEME_CTLCUACount` oturum sayacını da sayıyor ve her değeri iki kez listeliyor.
- **mru:** TypedPaths'in 16 yolu sırasıyla ve anahtar zamanı, regipy'nin
  "kesin beklenen sonucu" ile aynı.
- **bam:** 55 kayıt; regipy ile aynı. İlk sürümümüz 31 buluyordu. Fark bir
  **gerçek eksik** çıktı: 1709'dan yükseltilmiş makinelerde eski
  `bam\UserSettings` anahtarı da duruyor ve oradaki 24 kayıt yeni anahtarda
  yok. Artık iki konum da okunuyor ve her kayıt hangi konumdan geldiğini
  söylüyor. Bu canlı modu da düzeltti.
- **shimcache:** bu örnek bir **Windows 7** (x86) önbelleği. Win7 biçimi
  (Mandiant'ın herkese açık makalesindeki düzen) ve onunla gelen "executed"
  bayrağı eklendi. 330 girdi bulunuyor; mfeann.exe girdisi yolu, zamanı ve
  executed=true ile aynı. regipy'nin 660'ı, birebir aynı olan ControlSet001 ve
  ControlSet002 kopyalarını iki kez sayıyor.

Sağlamlık:

- Bozulmuş gerçek hive'larla (NTUSER, Amcache, kirli NTUSER, SYSTEM)
  ASan/UBSan altında mutasyon fuzz'ı (`tests/fuzz_regf.c`): bulgu yok.
- Gömülü küçük hive tohumuyla genel fuzz: bulgu yok.
- 117 bin anahtarlı SOFTWARE hive'ı sanitizer altında 0,25 sn'de okunuyor.

Windows CI'da bir de **iki yolun karşılaştırması** koşacak: `reg save
HKLM\SYSTEM` ile gerçek bir hive dosyası alınıp `shimcache` ve `bam`'ın canlı
API'den ve `--hive` ile dosyadan okunan kayıtları birebir eşit olmalı.
