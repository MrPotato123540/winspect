# 14 — Mimari genel bakış (projenin bütünü)

Bu dosya, winspect'in tamamını tek yerden anlatır: nasıl bölünmüş, hangi
desenler her yere yayılmış, ve neden bu şekilde. Yeni bir komut eklerken ya da
kodu okurken buraya bak.

## Tek cümlelik kimlik

> winspect, Windows'un **zaten dışarı verdiği** bilgiyi okuyan; insan ve makine
> için okunur basan; mümkünse aynı gerçeği birden çok kaynaktan okuyup çelişkileri
> işaretleyen; **tek, scriptable, user-mode** bir inceleme aracıdır.

Üç sınır asla aşılmaz: **kernel sürücüsü yok**, **yazma/enjeksiyon/evasion yok**
(her şey salt-okunur), **kapalı/belgelenmemiş hileye güvenmeyiz** — belgelenmiş
API'ler ve iyi bilinen yapılarla çalışırız.

## Dosya düzeni

- `src/main.c` — komut dağıtım tablosu (`commands[]`) ve argüman dilimleme. Yeni
  komut = tabloya bir satır + bir `#include`. `usage()` komutları kategorilere
  (file / process / security / system) ayırarak basar.
- `src/<komut>.c` + `inc/<komut>.h` — her komut kendi çeviri biriminde, tek bir
  `int cmd_<ad>(int argc, char **argv)` ihraç eder.
- **Paylaşılan altyapı:**
  - `jsonutil.c` — `json_str()` (JSON string kaçışı) ve `csv_str()` (RFC 4180
    alan tırnaklama). Tüm `--json`/`--csv` yolları bunları kullanır; ortada
    güvenilecek bir JSON kütüphanesi yok, bozulacak durum yok.
  - `detect.c` — ağır, paylaşılan tespit mantığı (image tamper, IAT hook, unbacked
    thread, section-perm). Hem `verify` hem `triage` buradan çağırır — kopya yok.
  - `md5.c` / `imphash_ords.c` — imphash/exphash/Rich-hash için MD5 ve ordinal
    tabloları.
  - `ioc.c` — gösterge sınıflandırması (URL/IP/registry/path/base64/kodlanmış
    PowerShell), IPv4 kapsamı, user-writable yol, script host / LOLBin, komut
    satırından imaj çıkarma, bilinen araç pipe adları, port dönüşümü.
  - `entropy.c` — Shannon entropisi (packed section sezgisi).
  - `pecksum.c` — PE image checksum algoritması.
  - `imphash_ords.c` — imphash ordinal tabloları + pefile-uyumlu libname kuralı.
  - `pfparse.c` — Prefetch (SCCA) ayrıştırıcı: sürümler, MAM başlığı, dosya ve
    volume listeleri.
  - `artparse.c` — küçük artefakt ayrıştırıcıları ve kural tabloları: ShimCache,
    firewall kural alanları, tırnaksız servis yolu, sürücü yolu normalleştirme,
    süreç soy ağacı ("Hunt Evil") kuralları, posture değerlendirmesi, olay XML'i,
    Mark-of-the-Web.
  - `lnkparse.c` — .lnk ([MS-SHLLINK]) ayrıştırıcı.
  - `cfb.c` — Compound File ([MS-CFB]) okuyucu (Jump List'ler, MSI, eski Office).
  - `destlist.c` — Jump List DestList akışı; `shellitem.c` — kabuk öğeleri
    (ShellBags ve .lnk IDList yolları).
  - `regf.c` — kayıt defteri hive dosyası okuyucusu; `regsrc.c` aynı kodun
    canlı kayıt defteri ya da hive dosyasıyla çalışmasını sağlayan ince katman
    (Windows'a bağlı, ama hive yolu taşınabilir `regf.c`'yi kullanır).
  - `jsonmini.c` — küçük, sıkı JSON okuyucu (`timeline` diğer komutların
    `--json` çıktısını bununla okur).
  - `artparse.c` ayrıca: Geri Dönüşüm Kutusu (`$I`, `INFO2`), SAM `F` kaydı ve
    makine SID'i, görev XML'i, sertifika blob'ları, COM sunucu yolu
    karşılaştırması, BITS ve hesap kuralları.
  - `capa.c` — import yetenek kategorileri + packer section adları.
  - `rights.c` — nesne türüne göre erişim maskesi adları (secinfo + handles).
  - `capture.c` — bir komutun stdout'unu yakalayıp metin olarak döndürür
    (`sweep` ve `timeline` diğer komutları böyle çağırır).
  - `res/winspect.manifest` — exe'ye gömülü manifest: süreç kod sayfası UTF-8
    (aşağıda 3. desen).
  - `usage.c` — `winspect help <komut>` metinleri; başlık yorumlarından
    `tools/gen_usage.py` ile **üretilir**.
  `regsrc.c` ve `capture.c` dışındaki modüller **Windows başlığı içermez**:
  Linux'ta derlenip test edilir ve sanitizer altında fuzz edilir.
- `tests/test_util.c` — taşınabilir modüllerin host'ta koşan birim testleri;
  `tests/fuzz_parsers.c` — aynı modüllerin ASan/UBSan altında mutasyon fuzz'ı;
  `tests/wine/` — gerçek `.exe`'nin wine altında smoke, fonksiyonel fixture,
  gerçek hive ve fuzz testleri; `tests/wine/regfwrite.py` çevrimdışı
  fixture'lar için yalnızca testte kullanılan hive yazıcısı. Ayrıntı: [17 — Test stratejisi](17-test-stratejisi.md).
  Bir çekirdek mantığı modüle çıkarıp burada test etmek, Windows'ta çalıştıramadan
  doğruluğu kanıtlamanın yoludur.

## Her yere yayılmış desenler

1. **Çıktı modu**: hemen her komut `--json` (makine) ve tablo komutları `--csv`
   (RFC 4180) destekler. Desen: `enum out_mode` veya yerel `mode` int; metin
   dalında hizalı sütunlar, JSON dalında elle kurulmuş nesne/dizi, CSV dalında
   `csv_str()`. JSON dizilerinde virgül yönetimi için `first`/`emitted` bayrağı
   (atlanabilen eleman varsa `[,{...}]` üretmemek için).
2. **İki-adımlı boyut sorgusu**: `NtQuerySystemInformation`, `GetExtendedTcpTable`,
   `EnumServicesStatusEx`, `QueryServiceConfig`, `GetIpNetTable`, `CryptMsgGetParam`
   ... hepsi "önce NULL ile boyut sor, ayır, tekrar çağır" desenini izler.
3. **UTF-8 köprüsü**: Windows wide (UTF-16) döner; biz `WideCharToMultiByte(CP_UTF8)`
   ile UTF-8'e çevirip basarız, `main()` de konsolu `SetConsoleOutputCP(CP_UTF8)`
   ile UTF-8'e alır. Türkçe/yerelleştirilmiş adlar mojibake olmaz.
   Bazı komutlar `FindFirstFileA`, `LookupAccountSidA` gibi `A` API'lerini
   kullanır. Bunlar varsayılanda eski ANSI kod sayfasını (Türkçe sistemde
   cp1254, İngilizcede cp1252) konuşur. Bu yüzden exe'ye gömülü manifest
   (`res/winspect.manifest`) `activeCodePage = UTF-8` ister (Windows 10 1903+).
   Böylece `A` API'leri de UTF-8 konuşur.

   Bu bir süs değil, bir **hata düzeltmesiydi**. Manifest olmadan
   `C:\Users\Gülşen` profili `A` API'sinden `Gülsen` diye döndü (`ş` cp1252'de
   yok). O yol da var olmadığı için kullanıcı `pshistory --all-users`
   çıktısından **sessizce düştü**. Ayrıca `certstore --json`, `CertGetNameStringA`
   yüzünden geçersiz UTF-8 basıyordu ("Főtanúsítvány"); orası `W` API'sine
   çevrildi.
4. **Fonksiyon-işaretçisi dökümü**: ntdll'den `GetProcAddress` ile çözülen
   fonksiyonlar `(T)(void(*)(void))GetProcAddress(...)` ikili dökümüyle alınır —
   `-Wpedantic` (nesne↔fonksiyon) ve `-Wcast-function-type` ikisini de susturur.
5. **Sınırlı, hepsi-ya-hiç okuma**: `ReadProcessMemory` sarmalayıcısı (`rpm`) ve
   PE `read_at` yalnızca aralık tamamen geçerliyse kopyalar; güvenilmez girdiyle
   asla tamponun dışına taşmayız.
6. **Çıkış kodu sözleşmesi**: komutlar 0 (başarı) veya 1 (hata/uyarı) döner. CI
   smoke testi tam da buna dayanır: her komutu gerçek Windows'ta çalıştırıp çıkış
   kodu 0/1 dışındaysa (yani çökme) build'i kırar.

## Komut aileleri

- **Statik dosya** (`pe`, `sign`, `strings`, `hash`, `streams`): dosyayı
  çalıştırmadan okur.
- **Canlı process** (`list`, `inspect`, `modules`, `threads`, `handles`,
  `regions`, `token`, `secinfo`, `verify`, `triage`, `launch`, `ssn`, `net`):
  hedefi `OpenProcess` ile açıp user-mode okur.
- **Kalıcılık** (`autoruns`, `services`, `drivers`, `tasks`, `taskcache`,
  `wmi`, `bits`, `comhijack`, `defender`, `firewall`, `certstore`,
  `programs`): bir şeyi makinede tutan yerler.
- **Etkinlik kanıtı** (`prefetch`, `amcache`, `shimcache`, `bam`,
  `userassist`, `mru`, `jumplist`, `lnk`, `shellbags`, `recyclebin`,
  `pshistory`, `rdp`, `usb`, `events`): ne çalıştı, ne açıldı, ne silindi.
- **Makine ve hesaplar** (`sysinfo`, `users`, `posture`, `hunt`, `hidden`,
  `hosts`, `arp`, `routes`, `sessions`, `shares`, `pipes`, `objects`, `hive`).
- **Birleştiriciler** (`sweep`, `timeline`): diğer komutları süreç içinde
  çalıştırıp çıktılarını tek rapora ya da tek zaman çizelgesine toplar.

`winspect` (argümansız) ekranındaki dört başlık (file / process / security /
system) daha kaba bir gruplamadır; yeni komutlar oraya en yakın başlıkla
eklenir.

## İşaretleme ilkesi (bütün komutlarda)

Bir şeyi "şüpheli" işaretleyen her komut **nedenini** de söyler (`reason`
alanı / `<-` satırı). İşaretler hüküm değil, **bakılacak yer** önerisidir.
Yanlış alarm, kaçırmak kadar zararlı sayılır: varsayılan Windows değerleri
açıkça tanımlanır (posture, autoruns "non-default"), meşru varyasyonlar kural
dışı bırakılır (explorer ebeveyni, Microsoft\ altındaki gizli görevler),
belirsiz durumlar "doğrulanamadı / unresolved" diye raporlanır, asla sessizce
"temiz" ya da "kötü" sayılmaz.

## Yeni komut nasıl eklenir (özet)

1. `inc/foo.h` + `src/foo.c`, `int cmd_foo(int,char**)`. Prototipin hemen
   üstüne **kullanıcıya yönelik** bir yorum yaz: ne yapar, ne işaretler, ve
   `Usage:` satırı. Bu metin `winspect help foo`'nun çıktısı olur.
2. Çıktı modu desenini uygula (`--json`, uygunsa `--csv`), `jsonutil` kullan.
   İşaretlenen her satır bir **neden** (`reason`) taşısın.
3. `main.c`: `#include "foo.h"` + `commands[]`'e bir satır (kategori ile).
4. `CMakeLists.txt`: `src/foo.c` + gereken sistem kütüphanesi.
5. `python3 tools/gen_usage.py` ile `src/usage.c`'yi yeniden üret (CI eski
   kalmışsa kırılır).
6. Windows API'si gerektirmeyen mantığı (ayrıştırma, sınıflandırma) ayrı,
   başlıksız bir modüle koy; `tests/test_util.c`'ye test, gerekirse
   `tests/fuzz_parsers.c`'ye tohum ekle.
7. CI smoke listelerine (Windows + `tests/wine/wsmoke.py`) komutu ekle; bir
   bulgu üretiyorsa `tests/wine/fixtures.py`'ye **pozitif ve negatif** bir
   fixture ekle.
8. MSVC /W4 ve MinGW -Wall -Wextra (WIN32_LEAN_AND_MEAN ile) **ikisinde de**
   temiz derlenmeli.
9. Salt-okunur kal; kavram başka bir araçtan esinse yorumda belirt, kodu
   kopyalama.
