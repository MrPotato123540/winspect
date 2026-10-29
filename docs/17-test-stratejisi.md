# 17 — Test stratejisi: Windows aracını Linux'ta nasıl test ediyoruz?

winspect bir Windows aracı, ama geliştirme ve CI'ın büyük kısmı Linux'ta. Bu
belge, "çalıştığını nereden biliyoruz?" sorusunun dört katmanlı cevabı.

---

## Katman 1 — Taşınabilir birim testleri (`tests/test_util.c`)

Kural: **Windows API'si gerektirmeyen her mantığı ayrı, başlıksız (windows.h'siz)
bir modüle çıkar ve Linux'ta test et.** Bugün bu modüller:

| Modül | Ne test ediliyor |
|---|---|
| `md5.c` | RFC 1321 test vektörleri (imphash/exphash/Rich hash'in temeli) |
| `jsonutil.c` | JSON/CSV kaçışları (her `--json`/`--csv` çıktısının temeli) |
| `ioc.c` | IOC sınıflandırma (base64, kodlanmış PowerShell dahil), IPv4 kapsamı, user-writable yol, script host, komut satırından imaj çıkarma, port dönüşümü, bilinen pipe adları |
| `entropy.c`, `pecksum.c` | Shannon entropisi, PE checksum altın değerleri |
| `imphash_ords.c` | imphash kütüphane adı normalizasyonu |
| `pfparse.c` | Prefetch SCCA sürümleri, MAM başlığı, dosya/volume listeleri |
| `artparse.c` | ShimCache, firewall alanları, tırnaksız servis yolu, sürücü yolu |
| `capa.c` | Import yetenek kategorileri, packer section adları |
| `lnkparse.c` | .lnk (MS-SHLLINK) — sınır dışı offset ve kesik dosya dahil |
| `artparse.c` (lineage) | Hunt Evil ebeveyn kuralları, tekil süreçler, System32-only isimler |
| `artparse.c` (posture) | Sertleştirme kuralı değerlendirmesi |
| `rights.c` | Nesne türüne göre erişim maskesi adları (kesme güvenliği dahil) |
| `artparse.c` (events) | Olay XML'inden alan çekme, entity çözümü, kesik XML |
| `destlist.c`, `shellitem.c` | Jump List DestList sürümleri; kabuk öğeleri (kök, sürücü, dosya, ağ, delege), DOS zamanları |
| `artparse.c` (kalıcılık) | exefile ve zaman sağlayıcısı stok değerleri, ağ sağlayıcıları, sistem adlarının taklidi, COM sunucu yolu karşılaştırması, BITS kuralları |
| `artparse.c` (izler) | Amcache SHA-1, UserAssist, MRU listeleri, Geri Dönüşüm Kutusu (`$I` v1/v2, INFO2), SAM `F` kaydı ve makine SID'i, hesap kuralları, görev XML'i, sertifika blob'ları |
| `ioc.c` (PowerShell) | PSReadLine satırı kuralları (şifreli komut, indirme, AMSI/Defender, kimlik bilgisi dökümü, günlük silme, kalıcılık) |
| `jsonmini.c` | Her değer türü, kaçışlar ve vekil çiftleri, 18 bozuk örnek, derinlik sınırı |

Toplam **475** doğrulama. Her biri pozitif durum **ve** kenar durumları (kesik
buffer, sınır dışı offset, eski format, benzer ama farklı isim) içerir.

## Katman 2 — Wine altında smoke test (`tests/wine/wsmoke.py`)

MinGW ile çapraz derlenen gerçek `.exe`, Linux'ta **wine** ile çalıştırılır.
Her komut düz / `--json` / `--csv` biçimde koşar ve kontrol edilir:

- çıkış kodu **0 veya 1** (asla çökme),
- `--json` çıktısı **geçerli JSON**,
- `--csv` çıktısının **her satırı başlıkla aynı sütun sayısında**.

Wine bazı API'leri desteklemez (sürücü listesi, WMI, paylaşımlar, olay günlükleri...). Bu sorun
değil: o komutlar **temiz bir hata mesajıyla rc=1** dönmeli — ki dönüyorlar.
Bu katman gerçek bir hata buldu: `list` komutu `--csv` desteklemiyordu (README
"tablo komutları --csv alır" diyordu). Düzeltildi.

**Wine tuzağı:** çıktıyı pipe ile okumak testi sonsuza kadar asılı bırakır,
çünkü wine'ın yardımcı süreçleri (wineserver, services.exe) pipe'ı miras alıp
açık tutar. Çözüm: çıktıyı geçici **dosyaya** yazmak.

## Katman 3 — Fonksiyonel fixture'lar (`tests/wine/fixtures.py`)

Smoke test "çökmüyor" der, ama "doğru şeyi buluyor mu?" demez. Fixture'lar
**atılabilir** bir wine prefix'ine bilinen-kötü artefaktlar yerleştirir ve her
birinin **doğru nedenle** raporlandığını doğrular:

| Yerleştirilen | Beklenen |
|---|---|
| Run anahtarında `C:\Users\Public\upd.exe` | autoruns: `user-writable path` |
| IFEO `sethc.exe` Debugger | autoruns: `rarely legitimate location` (bir kez!) |
| BootExecute'ta `evilboot.exe` | autoruns: `non-default value` |
| LSA Notification Packages'ta `passfilt_x` | autoruns: `non-default value` |
| NetSh helper tam yolla | autoruns: `non-default value` |
| Startup'ta powershell çalıştıran `.lnk` | autoruns: `shortcut launches a script host` |
| `%APPDATA%` programına gelen-izin kuralı | firewall: `suspicious` |
| Defender yol dışlaması + RTP kapalı | defender: listelenir, `PROTECTION OFF` |
| Seri numarasız USB | usb: `generated_serial` |
| Temp'ten çalışan BAM kaydı | bam: `user_writable_dir` |
| Downloads'taki ShimCache girdisi | shimcache: listelenir |
| SD'siz görev | taskcache: `no SD value` |
| `Microsoft\` dışında gizli wscript görevi | tasks: `hidden task outside` |
| Tırnaksız `C:\Program Files\My App\svc.exe` | services: `unquoted path` |
| v30 prefetch dosyası (Temp'ten DLL yükleyen) | prefetch + `--files` |
| Recent'te USB'deki belgeye kısayol | lnk: hedef yolu |
| `C:\fake\svchost.exe` olarak çalışan süreç | hunt: `outside System32` (gerçek system32 süreçleri **işaretlenmez**) |
| hosts'ta engelleme + yönlendirme satırı | hosts: sadece yönlendirme işaretlenir |
| Zayıf ayarlar + AutoLogon şifresi `hunter2-SECRET` | posture: WARN; şifre **hiçbir** çıktıda geçmez |
| Gerçek `upx` ile paketlenmiş exe | pe: `packer` anomalisi tam **bir** kez |
| `net --json` | tüm portlar 0..65535 aralığında (regresyon) |
| ROT13'lü UserAssist kaydı (Temp'teki program) | userassist: çözülür, işaretlenir |
| AutomaticDestinations (CFB) + CustomDestinations (araya çöp bayt) | jumplist: 4 öğe; Downloads'taki exe ve mshta işaretli, PDF/DOCX işaretsiz |
| RunMRU'da `powershell -enc`, sıralı iki RecentDocs | mru: kodlanmış komut işaretli, sıra doğru, `notepad` işaretsiz |
| SCM başladıktan sonra registry'ye yazılan servis | hidden: `written straight into the registry`; sahte gizli süreç **yok** |
| `sweep --json` | tek geçerli JSON; tüm anahtarlar var; wine'ın desteklemediği bölümler `null` |
| `C:\users\Gülşen\...\ConsoleHost_history.txt` | pshistory --all-users: kullanıcı bulunur, adı doğru (UTF-8 manifest regresyonu) |
| Test yazıcısıyla üretilen SAM (Guest açık, `backup$`, parolasız hesap; V değerinde "kanarya") | users --sam: üçü işaretli, kanarya **hiçbir** çıktıda yok |
| Üretilen UsrClass.dat + SOFTWARE (Shortcut sınıfı kullanıcıda başka DLL'e) | comhijack çevrimdışı: işaretli |
| Üretilen SOFTWARE (biri dürüst, biri yanlış SHA-1 taşıyan iki ROOT kaydı) | certstore --software: yalnızca yanlış olan işaretli |

**Negatif kontroller de var** — bunlar en az pozitifler kadar önemli: stok LSA
paketi (`scecli`) ve sıradan bir firewall engelleme kuralı **işaretlenmemeli**.
Bir güvenlik aracında yanlış alarm, kaçırmak kadar zararlıdır.

Bu katman da gerçek hatalar buldu:

- `Wow6432Node` ile paylaşılan anahtarlardaki girdiler **iki kez** raporlanıyordu.
  Artık parmak iziyle tekilleştiriliyor.
- **`net` her port numarasını bozuk basıyordu** (`0.0.0.0:15206376`). Sebep:
  ağ sırasındaki portu çeviren byte-swap `n << 8`'i `int` içinde hesaplayıp
  sonucu 16 bite maskelemiyordu; `0x1234` → `0x123412` oluyordu. Bu hata
  gerçek Windows'ta da vardı — wine çıktısına bakınca göze çarptı. Düzeltme
  `ioc_port_from_net` olarak taşınabilir modüle alındı, birim testi ve
  fixture'da "her port 0..65535" kontrolü eklendi ki bir daha geri gelmesin.

Ders: "çökmüyor ve JSON geçerli" yeterli değil; **değerlerin anlamlı olduğunu**
da kontrol etmek gerekiyor.

### Test için hive yazıcısı

Çevrimdışı modlar (`--sam`, `--software`, `--usrclass`…) için gerçek hive'lar
(regipy verisi) değerli ama içerikleri sabit: içlerinde "işaretlenmesi
gereken" bir şey yok. Bu yüzden **yalnızca test kodu** olarak küçük bir regf
yazıcısı var: `tests/wine/regfwrite.py`. Ürettiği yapı Windows'unkiyle aynı:

- base block + checksum,
- 4 KiB katlarında hive bin,
- 8 bayt hizalı nk / vk / lh / sk hücreleri,
- değer listeleri, ≤ 4 bayt değerlerde satır içi veri.

Yazıcının kendisi de test ediliyor. `tests/regf_roundtrip.py` rastgele anahtar
ağaçları (Latin-1 olmayan adlar, boş anahtarlar, her boyutta değer) yazıp C
okuyucusuyla geri okur ve birebir karşılaştırır. Okuyucu da gerçek hive'larla
ayrıca doğrulanır. Böylece iki taraf birbirini "kendi kendine onaylamaz".

## Katman 4 — Sağlamlık: gerçek dosya taraması + fuzz

Bir güvenlik aracı, **saldırganın hazırladığı** dosyayı açtığında çökmemeli.

- **Gerçek PE taraması:** wine'ın system32/syswow64'ündeki **652** PE dosyasının
  her birinde `pe` ve `pe --json` → 0 sorun.
- **PE fuzz:** notepad.exe'den **209** varyant (kesilmiş başlıklar, devasa
  NumberOfSections / SizeOfOptionalHeader, sınır dışı veri dizini RVA'ları,
  kendine işaret eden import tablosu, rastgele bayt çevirmeleri) × 4 komut
  (`pe`, `pe --json`, `strings --json`, `hash`) → 0 çökme, JSON hep geçerli.
- **.lnk fuzz:** 500 bozuk kısayol üzerinde `lnk` → çökme yok.

Fuzz `tests/wine/fuzz.py` olarak repoda; CI daha küçük sayılarla her push'ta koşar.

## Katman 5 — Statik analiz ve sanitizer fuzz

- **GCC `-fanalyzer`** tüm kaynak dosyalarda çalıştırıldı (NULL dereference,
  sızıntı, başlatılmamış değer, tampon boyutu). 16 uyarının çoğu yanlış alarm
  çıktı (ör. `_dup2`'nin dönüş değerini fd sanması); gerçek olan tek kenar
  durumu, `WCHAR*` tamponu için **tek sayılı bayt** ayrılabilmesiydi (`events`,
  `firewall`) — boyut artık "WCHAR sayısı × sizeof(WCHAR)" olarak hesaplanıyor.
- **`tests/fuzz_parsers.c`:** taşınabilir ayrıştırıcıların hepsi (prefetch,
  MAM, ShimCache, .lnk, olay XML'i, Mark-of-the-Web, firewall alanları, IOC
  sınıflandırıcı, komut satırı → imaj, hak çözücü...) geçerli tohumlardan
  mutasyonla türetilmiş girdilerle **AddressSanitizer + UBSan** altında
  çalıştırılır: bayt çevirme, kesme, ekleme/silme, başlık alanlarına sınır
  değerleri (0, 0x7FFFFFFF, 0xFFFFFFFF...). Tek bir baytlık sınır dışı okuma
  bile çalıştırmayı durdurur. **2.000.000 iterasyon: bulgu yok.** CI her
  push'ta 300.000 iterasyon koşar; birim testleri de sanitizer altında çalışır.

## Katman 6 — Diferansiyel test (bağımsız bir uygulamayla karşılaştırma)

Bir ayrıştırıcının doğruluğunu kanıtlamanın en güçlü yolu, aynı girdiyi
**bağımsız** bir uygulamayla okuyup sonuçları karşılaştırmaktır. CFB okuyucu
(`src/cfb.c`) gerçek MSI dosyalarında Python `olefile` ile karşılaştırıldı
(`tests/cfb_dump.c` her akışın adını, boyutunu ve MD5'ini basar). İlk
karşılaştırma gerçek bir hata buldu — **kesik son sektör** — ve düzeltildi;
ardından 153 akışın hepsi eşleşti. CI'da olefile olmadığı için orada bir
**gidiş-dönüş** testi koşar: `tests/wine/cfbwrite.py` ile üretilen rastgele
dosyalar (mini akış sınırı 4096, boş akışlar, 512/513 gibi sınır boyutları)
C okuyucuyla aynı içerikle geri okunmalı.

`.lnk` ayrıştırıcısı (`src/lnkparse.c`) için kahin, LnkParse3 projesinin
deposundaki **34 gerçek dünya örneği** ve o projenin her örnek için sakladığı
beklenen JSON çıktısıdır. Yalnızca bu veri dosyaları kullanılır; o projenin
kodu çalıştırılmaz ve repoya hiçbir dosya kopyalanmaz. CI, depoyu sabit bir
commit'te çeker; böylece kahin kendiliğinden değişemez. `tests/lnk_dump.c`
bizim sonucumuzu JSON olarak basar, `tests/lnk_diff.py` alan alan karşılaştırır.
Karşılaştırılan alanlar:

- hedef yol (yerel veya ağ paylaşımı), göreli yol, çalışma dizini, argümanlar,
- sürücü tipi, seri numarası ve etiket,
- makine adı, MAC adresi, ortam değişkenli hedef.

İlk karşılaştırma gerçek bir eksik buldu: kötü amaçlı bir örnekte
WORKING_DIR'in karakter sayısı 1693 yazılmış, fakat kabuk bu alanı en fazla 260
karakter okuyup sonraki alana geçiyor. Gizlenen komut satırı tam o noktada
başlıyor. Sayıya güvenen ayrıştırıcımız argümanları hiç görmüyordu. Artık
260'ta kesip devam ediyor ve bu hileyi ayrıca işaretliyor; 34/34 eşleşiyor.

Shell öğesi ayrıştırıcısı (`src/shellitem.c`) bağlandıktan sonra
karşılaştırma, LinkTargetIDList'in öğelerini de **öğe öğe** kapsıyor:

- kök GUID'leri,
- birim adları ve kabuk klasörü GUID'leri,
- dosya girdilerinin kısa adları ve DOS değişiklik zamanları.

İlk çalıştırmada beş örnek uyuşmadı. Fark bizim hatamız değil, adlandırmadan
geliyordu: LnkParse3 `0x2E` öğelerini GUID ile gösteriyor, biz bilinen adıyla.
Ham GUID alanı eklendi ve 34/34 öğe düzeyinde de eşleşiyor. LinkInfo taşımayan
kısayolların hedefi artık IDList'ten kuruluyor (LECmd'in yaptığı gibi).

Daha sonra eklenen karşılaştırmalar (hepsi yalnızca o projelerin **test
verisini** kullanır, kodlarını çalıştırmaz):

| Ayrıştırıcı | Kahin | Sonuç |
|---|---|---|
| Jump List DestList | JumpList projesinin Win7–10 dosyaları | ilk turda 2 hata bulundu, düzeltildi |
| Hive okuyucu, ShimCache, BAM, UserAssist, Amcache, ShellBags | regipy'nin test hive'ları ve doğrulama değerleri | sayı farkları regipy'nin çift saymasından çıktı (belge 19) |
| SAM (`users --sam`) | regipy `samparse` / `local_sid` doğrulama durumları | hepsi tuttu |
| Geri Dönüşüm Kutusu | plaso'nun `$I` ve `INFO2` test dosyaları ve testlerindeki değerler | hepsi tuttu |
| Çevrimdışı sertifikalar | `openssl x509` + `hashlib` | 23/23 |
| `jsonmini` | Python `json` modülü, rastgele binlerce belge (`tests/jm_diff.py`) | bir vekil çifti hatası bulundu, düzeltildi |
| Test hive yazıcısı | C okuyucusu, rastgele ağaçlar (`tests/regf_roundtrip.py`) | 0 fark |

## CI'da hepsi

`.github/workflows/ci.yml` üç işi paralel koşar:

1. **unit** (Linux): yardım metni senkron mu, birim testleri (normal +
   ASan/UBSan), sanitizer fuzz, CFB ve hive gidiş-dönüşleri, yukarıdaki
   bütün diferansiyel karşılaştırmalar (veriler sabit commit'lere iğneli).
2. **wine** (Linux): MinGW çapraz derleme, fixture'lar, smoke, fuzz ve gerçek
   hive'larla çevrimdışı modlar.
3. **build** (Windows, MSVC + MinGW): gerçek Windows'ta derleme, her komutun
   smoke testi (yönetici hakkıyla) ve wine'ın taklit edemediği fonksiyonel
   kontroller: NTFS akışları ve Mark-of-the-Web, Security günlüğünde parola
   püskürtme özeti, açık tutulan bir dosyanın `handles --find` ile bulunması,
   canlı kayıt defteri ile `reg save` kopyasının aynı sonucu vermesi, askıya
   alınmış bir BITS işi, kullanıcı başına COM kaydı, `$` ile biten devre dışı
   bir hesap. Her geçici değişiklik adımın sonunda geri alınır.

Not: CI dosyası hazır ama henüz gerçek bir GitHub Actions koşusu görmedi.
Windows'a özgü kontrollerin ilk gerçek sonucu o koşuda alınacak.

## Dürüst sınırlar

Wine gerçek Windows değildir: süreç belleği, token'lar, ETW, kernel nesneleri
ve imza zinciri gibi şeyler orada ya yok ya da farklı davranır. `verify`,
`triage`, `handles` gibi canlı süreç komutlarının **doğruluğu** için asıl test
yine gerçek Windows'tur (Windows CI işi + elle kontrol listesi). Wine katmanı
çökmeleri, biçim hatalarını ve registry/dosya tabanlı mantığı yakalar.
