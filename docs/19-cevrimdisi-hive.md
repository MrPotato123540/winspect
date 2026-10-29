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

## amcache

`Amcache.hve`, Program Uyumluluk Yardımcısı'nın kendi hive'ıdır. Her
çalıştırılabilir dosya için tam yolu ve **SHA-1**'i tutar. Bu yüzden dosya
silinmiş olsa bile tehdit istihbaratında aranabilir. Aynı dosyada iki düzen yan
yana bulunabilir:

- **`Root\File\{birim}\{dosya başvurusu}`:** sayısal adlı değerler taşır:
  `15` yol, `101` `0000`+SHA-1, `17` dosya değişiklik zamanı, `0`/`1` ürün ve
  şirket.
- **`Root\InventoryApplicationFile`:** Windows 10 1607 ve sonrası.
  `LowerCaseLongPath`, `FileId`, `Publisher`, `ProductName`, `Version` ve
  `LinkDate` değerlerini taşır.

Her iki düzende de girdi anahtarının son yazma zamanı, dosyanın kaydedildiği
andır. Bu tek başına çalıştırıldığını kanıtlamaz. `--sha1` ile karma değerine
göre arama yapılır. Canlı dosya Windows tarafından kilitlidir; bir yedek ya da
VSS kopyası verilmelidir.

**Doğrulama:** gerçek amcache.hve'de 1120 + 247 = **1367** girdi bulunuyor;
regipy'nin toplamıyla aynı. TPVMMondeu.dll girdisinde yol, SHA-1
(`056f4b9d…`), kayıt zamanı ve değişiklik zamanı aynı. SHA-1 çıkarımı
taşınabilir koddadır ve bozuk kimliklerin karma diye gösterilmediği birim
testiyle sınanır. Windows CI, canlı Amcache'in VSS kopyasını da okumayı
deneyecek.

Windows CI'da bir de **iki yolun karşılaştırması** koşacak: `reg save
HKLM\SYSTEM` ile gerçek bir hive dosyası alınıp `shimcache` ve `bam`'ın canlı
API'den ve `--hive` ile dosyadan okunan kayıtları birebir eşit olmalı.

## Çevrimdışı moda geçen diğer komutlar

Aynı okuyucu üzerine şunlar eklendi. Hepsi regipy'nin gerçek hive'larıyla ve
onun testlerinin doğruladığı değerlerle sınanır (`tests/wine/hives.py`).

| Komut | Ne okur | Doğrulanan |
|---|---|---|
| `usb --hive SYSTEM` | USBSTOR + aygıt özellik zamanları (`0064` kurulum, `0065` ilk kurulum, `0066` son takılma, `0067` son çıkarılma) + Partmgr DiskId + MountedDevices | Win10 1709 hive'ında regipy'nin kesin USBSTOR sonucu; Win7'de `E:` eşlemesi |
| `autoruns --software/--system/--ntuser` | tüm kayıt tabanlı başlangıç noktaları | HKLM Run'ın 7 değeri regipy'deki sırayla; LSA paketleri |
| `services --hive SYSTEM` | `Services` anahtarı (durum/PID "-") | Abiosdsk (Start 4), AdobeARMservice yapılandırması |
| `mru` (WordWheelQuery) | Explorer arama terimleri | 6 terim, en yenisi "alloy" + zaman |
| `rdp --hive NTUSER.DAT` | mstsc MRU + Servers (UsernameHint, CertHash) | örnek hive'da veri yok → `[]`; biçim wine fixture'ıyla |
| `sysinfo --software/--system` | ad, sürüm, kurulum, kapanış, saat dilimi, son kullanıcı, arayüzler, profiller, ağ geçmişi | regipy'nin bilgisayar adı, winver, shutdown, last_logon, network_data ve profile_list gerçekleri |

Bu karşılaştırma bir **gerçek tespit** de getirdi. regipy'nin SOFTWARE
örneğindeki Run anahtarında `c:\windows\system32\dllhost\svchost.exe` var:
svchost adı System32'nin bir **alt dizininde**. Eski autoruns bunu işaretlemezdi,
çünkü yol "kullanıcının yazabildiği" bir yer değil. Artık `asep_masquerade`
kuralı (birim testli) autoruns ve services'te bunu "masquerading" diye
işaretliyor.

NetworkList tarihleri 16 baytlık SYSTEMTIME olarak ve makinenin **yerel**
saatiyle tutulur (regipy bunları çözmüyor). Biz çözüyor ve "local" diye
etiketliyoruz; UTC değil.

## shellbags

Explorer, kullanıcının açtığı her klasörün görünüm ayarını saklar. Klasörün
kimliğini de bir **shell öğesi** ağacı olarak tutar (`BagMRU`). Klasör silinse
ya da USB bellek/paylaşım ortadan kalksa bile bu kayıtlar kalır.

Her değer bir öğedir; yolu, üst düzeylerdeki öğe adlarının zinciri verir.
Ayrıştırıcı taşınabilir koddadır (`src/shellitem.c`) ve şu türleri çözer:

- **kök klasör:** GUID; regipy'nin tablosuyla çapraz doğrulanmış bilinen adlar,
- **kabuk klasörü** (`0x2E`) ve **birim**,
- **dosya/dizin girdisi:** `0xBEEF0004` uzantı bloğundan uzun ad ve
  oluşturma/erişim zamanları,
- **ağ konumu:** tür baytında üst bit set olabilir (`0xC3`),
- **`CFSF` delegate öğeleri,**
- **property-store öğeleri:** [MS-PROPSTORE], `System.ItemNameDisplay`.

**Doğrulama:**

- NTUSER_BAGMRU'da 102, UsrClass'ta 29 girdi; regipy ile aynı.
- `Search Folder\tmp\rekall` yolu, üç öğe zamanı, anahtar zamanı ve MRU
  konumu regipy ile aynı.
- Dropbox kökü slot 9, MRU konumu 4; regipy ile aynı.
- Birim testleri elle kurulmuş öğelerle yazıldı.
- Fuzz iki katmanda koşuyor: gömülü tohumla ve gerçek ShellBag hive'larının
  bozulmuş kopyalarıyla (ASan/UBSan).

**Bilinen sınır:** bazı property-view öğeleri (`0x00`) ad taşımaz;
bunlar türüyle (`[type 0x00]`) gösterilir.

## certstore --software / --ntuser

Makine ve kullanıcı sertifika depolarının bir kısmı kayıt defterinde durur:

```
SOFTWARE  Microsoft\SystemCertificates\<depo>\Certificates\<SHA-1>\Blob
          Policies\Microsoft\SystemCertificates\<depo>\...   (Grup İlkesi kopyası)
NTUSER    Software\Microsoft\SystemCertificates\<depo>\...
```

`Blob` bir özellik listesidir: `u32 no | u32 1 | u32 uzunluk | veri`.
Özellik **32** DER sertifikanın kendisi, **3** saklanan SHA-1, **11** kolay ad.
Listeyi `certblob_prop` yürütür (taşınabilir, birim testli: sınır dışı uzunluk,
kesik blob). Yalnızca DER, çözülmek için CryptoAPI'ye
(`CertCreateCertificateContext`) verilir.

Parmak izi **her zaman sertifikanın kendisinden hesaplanır** (canlı modda da).
Saklanan SHA-1 (çevrimdışı: anahtar adı; canlı: önbellekteki özellik) farklıysa
kayıt "elle düzenlenmiş" diye işaretlenir.

**Doğrulama:**

- regipy'nin SOFTWARE hive'ındaki 6 ROOT + 17 AuthRoot sertifikası. Her biri
  için DER, `openssl x509` ve `hashlib` ile ayrıca okundu; geçerlilik tarihleri
  ve SHA-1 (= anahtar adı) 23/23 tuttu.
- Test yazıcısıyla üretilen hive'da yanlış SHA-1 taşıyan kayıt işaretli,
  dürüst kayıt işaretsiz.
- wine'da canlı karşılığı denenemedi: wine'ın crypt32'si ROOT deposunu kayıt
  defterinden değil ana makinenin sertifikalarından kuruyor.

## Olay günlüğü dosyaları: events --evtx

`events` canlı makinede `EvtQuery` kullanır. Bir disk imajından kopyalanmış
`System.evtx`, `Security.evtx` gibi dosyalar için artık kendi okuyucumuz var:
`src/evtx.c` (taşınabilir, Windows API'si yok).

```
winspect events --evtx D:\imaj\System.evtx --evtx D:\imaj\Security.evtx
winspect events --evtx Security.evtx --summary       # parola deneme / püskürtme
```

### Biçim

- **Dosya başlığı** (4096 bayt): `ElfFile\0`, chunk sayısı, "temiz kapanmadı" bayrağı.
- **Chunk'lar** (her biri 65536 bayt): `ElfChnk\0`, isim ve şablon tabloları,
  512. bayttan itibaren kayıtlar.
- **Kayıt:** `2a2a0000` imzası, boyut, kayıt no, yazılma zamanı, **binary XML**.

Binary XML bir belirteç (token) akışıdır:

| Belirteç | Anlamı |
|---|---|
| `0x01` / `0x41` | öğe başı (`0x41`: öznitelikleri var) |
| `0x02`, `0x03`, `0x04` | `>`, `/>`, `</öğe>` |
| `0x05` | metin değeri |
| `0x06` / `0x46` | öznitelik |
| `0x0C` | **şablon örneği**: bir şablon tanımına referans + değer dizisi |
| `0x0D` / `0x0E` | şablondaki (isteğe bağlı) yer tutucu: "buraya N. değeri koy" |

Windows bir olay türünün iskeletini (System bloğu, EventData alanları) chunk
içinde **bir kez** şablon olarak saklar; her kayıt yalnızca o şablona işaret
eder ve değerlerini taşır. Öğe adları da chunk başına bir kez saklanır, sonra
offset ile anılır; ilk kullanımda "satır içi" durur. Değerlerin tipi vardır:
UTF-16 metin, tamsayılar, GUID, FILETIME, SID, hex, ikili, hatta başka bir
binary XML parçası (gömülü, özyinelemeli).

Okuyucu her kaydı **EvtRender'ın verdiği XML metnine** çevirir. Bu sayede
`events`'in canlıda kullandığı alan çıkarıcıları (`evt_data`, `evt_system`,
`evt_time`) ve kanal / olay no / seviye süzgeçleri aynen çalışır. Süzgeçler
canlıda XPath olarak gider; dosyada aynı XPath metninden küçük bir eşleştirici
(`evt_xpath_match`, birim testli) karar verir. Tek kural iki yerde yazılmaz.

İnce nokta: değeri boş olan **isteğe bağlı** bir yer tutucu özniteliği
tamamen düşürür. Windows `<Correlation ActivityID=""/>` değil `<Correlation/>`
yazar; bizim çıktımız da öyle.

Kısaltılmış dosyalar: son chunk eksikse sıfırla doldurulmuş bir kopya
üzerinde çalışılır; tamamı dosyada olan kayıtlar okunur, yarım kalan atlanır.
Dosya "temiz kapanmadı" işaretliyse (çalışırken kopyalanmış) bu not edilir.

### Doğrulama

- **plaso'nun test dosyaları** (yalnızca veri): `System.evtx` için kayıt
  sayısı **5009** ve 1. kaydın **tam XML'i** plaso testlerindeki
  `expected_xml_string` ile karakteri karakterine aynı (girinti hariç).
- Elle kısaltılmış `System2.evtx`: plaso iki tam chunk'taki 194 kaydı okuyor;
  biz bunlara ek olarak kesik chunk'taki tamamı mevcut 89 kaydı da
  kurtarıyoruz. 179. kayıt plaso'nun değeriyle aynı (4624,
  2015-08-09 09:15:48.4341250).
- Okunan 5292 kaydın tamamı Python'un XML ayrıştırıcısına göre geçerli XML.
- Gerçek dosyanın bozulmuş kopyalarıyla **ASan/UBSan altında fuzz** (kayıt
  boyutları, belirteç baytları, isim/şablon offset'leri, değer sayıları):
  6000 tur, ~600 bin kayıt, bulgu yok.
- wine'da uçtan uca: `System.evtx`'teki 25 servis kurulumu (7045), en yeni ve
  en eski satır, `--max`, `--since`, iki dosyayla `--summary`.
- Windows CI: canlı System günlüğü `wevtutil epl` ile dışa aktarılır; dışa
  aktarma anından önceki satırlar canlı API ile dosya okuyucusunda **aynı**
  olmalı (henüz gerçek koşu görmedi).

## image: bütün bir kurulumu tek komutla incelemek

Çevrimdışı seçenekler tek tek güçlü ama bir disk imajında hepsini doğru
dosyayla çalıştırmak zahmetli. `image`, bağlanmış bir imajın (ya da klasör
yapısını koruyan bir toplama işinin) kök klasörünü alır, kanıtları kendisi
bulur ve ilgili komutları çalıştırır:

| Kanıt | Komutlar |
|---|---|
| `Windows\System32\config\SYSTEM`, `SOFTWARE`, `SAM` | sysinfo, users, posture, autoruns, services, programs, defender, certstore, shimcache, bam |
| `Windows\AppCompat\Programs\Amcache.hve` | amcache |
| `Windows\Prefetch`, `Windows\System32\Tasks` | prefetch, tasks |
| `Windows\System32\winevt\Logs\*.evtx` (6 kanal) | events |
| `$Recycle.Bin` | recyclebin |
| her `Users\<ad>`: NTUSER.DAT, UsrClass.dat, PSReadLine geçmişi | autoruns (kullanıcı), userassist, mru, comhijack, pshistory |

Komutlar süreç içinde `--json` ile çalıştırılır (sweep ve timeline'daki
yakalama mekanizması); çıktılar `jsonmini` ile okunur. Bir kaydın bulgu
sayılma kuralı tek ve şeffaf:

- komut onu işaretlemişse (`suspicious: true` + gerekçe),
- posture'da `WARN` satırları,
- defender'da her satır (dışlamalar ve kapatılmış koruma zaten başlı başına bulgu),
- bam / shimcache'te kullanıcının yazabildiği klasördeki programlar.

Rapor: makine bilgileri, yerel hesaplar, sonra bulgular **kaynak, kullanıcı ve
gerekçeye göre gruplu**. Her grupta en fazla 5 örnek gösterilir; birebir aynı
satırlar (aynı önbellek kaydının tekrarları) sayaçla birleşir. JSON'da hepsi
vardır.

Gruplama gerçek veride gerekli çıktı. regipy'nin hive'larıyla kurulan imajda
ilk sürüm 434 satır bastı: 368'i Amcache'te `ProgramData\chocolatey`
altındaki araçlar (kural doğru, ProgramData kullanıcıların yazabildiği bir
yer), 47'si ShimCache'te aynı `a.exe`'nin tekrarlarıydı. Gruplu rapor aynı
bilgiyi bir ekranda veriyor.

**Doğrulama:**

- Test yazıcısıyla kurulan sentetik imaj (`C:\img2`). İçine şunlar
  yerleştirildi:
  - kullanıcının yazabildiği bir yolda servis,
  - Downloads'tan çalışmış bir Prefetch kaydı,
  - Temp'ten çalışan görev,
  - silinmiş bir dropper,
  - bob'un Run anahtarı, COM override'ı ve günlük silen PowerShell satırı,
  - Guest'i etkin bir SAM,
  - elle düzenlenmiş kök sertifika.

  Hepsi doğru kaynak ve kullanıcıyla bulgu olarak geliyor; SAM `V`
  değerindeki kanarya hiçbir çıktıda yok.
- regipy hive'larıyla kurulan imaj: makine adı, build ve kurulum tarihi
  sysinfo'nun doğrulanmış değerleriyle aynı. Gerçek SOFTWARE hive'ının Run
  anahtarındaki `system32\dllhost\svchost.exe` "masquerading" bulgusu olarak
  çıkıyor.
