# 16 — Çalıştırma kanıtları, gizli görevler ve denetim (Dalga AA)

Bu dalga iki işi birlikte yapar: (1) DFIR'ın "bu program burada çalıştı mı?"
sorusuna üç bağımsız kaynak daha ekler, (2) mevcut komutları yeniden gözden
geçirip hem **yeni denetimler** ekler hem de **yanlış alarm (FP) kaynaklarını**
temizler. Kavramlar Autoruns, ListDLLs, PECmd, AppCompatCacheParser, Microsoft'un
Tarrask yazısı ve Binary Defense ARC Labs araştırmasından alındı; kod sıfırdan.

---

## Çalıştırma kanıtı: üç kaynak, üç farklı anlam

| Komut | Kaynak | Ne kanıtlar | Ne kanıtlamaz |
|---|---|---|---|
| `prefetch` | `Prefetch\*.pf` | Çalıştı, kaç kez, son 8 zaman | Kim çalıştırdı |
| `bam` | `bam\State\UserSettings\<SID>` | **Hangi kullanıcı** çalıştırdı, son zaman | Eski kayıtlar silinir |
| `shimcache` | `AppCompatCache` değeri | Dosya sistemde **vardı** (silinmiş olsa bile) | Win10+'da çalıştığını kanıtlamaz |

Bir analistin işi bu üçünü **birlikte** okumaktır: shimcache'te olup
prefetch/BAM'de olmayan bir exe "vardı ama belki çalışmadı" demektir.

### prefetch --files

`winspect prefetch <dosya.pf> --files` artık programın açılışta dokunduğu
**volume'ları** (cihaz yolu, seri no, oluşturma zamanı) ve **tüm dosyaları**
(DLL, config, veri) listeler. Temp/Downloads/AppData'dan yüklenen dosyalar
`[user-writable dir]` olarak işaretlenir. Ofsetler libscca belgesinden: dosya
bilgi bloğu (@84) her sürümde aynı işaretçi tablosuyla başlar — dosya adları
@100/@104, volume'lar @108/@112/@116; volume girdisi v17'de 40, v23/26'da 104,
v30/31'de 96 bayt.

### shimcache

Windows 10/11 düzeni: başlıktaki ilk u32 ilk girdinin ofsetidir (Creators
Update öncesi `0x30`, sonrası `0x34`). Her girdi `"10ts"` imzası, girdi boyutu,
yol uzunluğu, UTF-16 yol, son değişiklik FILETIME'ı ve veri bloğu taşır. Bir
sonraki girdiye tek bağlantı boyut alanı olduğu için, bozuk bir girdide
**tahmin yürütmek yerine dururuz** (sonuçta "stopped at a malformed entry" yazar).

İki dürüst uyarı çıktıda da basılır: değer **sadece kapanışta** yazılır, ve
zaman damgası **dosyanın** değişiklik zamanıdır, çalışma zamanı değil. Çevrimiçi
kaynaklarda geçen "executed" bayrağını (veri bloğundaki bir etiket) doğrulayamadık,
o yüzden **eklemedik** — emin olmadığımız bir şeyi göstermek, göstermemekten kötüdür.

### userassist

Explorer, kullanıcının **GUI'den** (Başlat menüsü, masaüstü, Explorer)
başlattığı programları sayar: `HKCU\...\Explorer\UserAssist\{GUID}\Count`.
Değer **adları** ROT13 ile kodlanmış yollardır (eski, basit bir gizleme) ve
çoğu zaman sürücü harfi yerine bir **Known Folder GUID**'iyle başlar
(`{6D809377-...}\app.exe` = Program Files). Her ikisi de çözülür. Veri:
Windows 7+ için çalışma sayısı @4, son çalışma FILETIME @60 (72 bayt); XP
formatı da tanınır. Kaynaklar "focus" alanlarında anlaşmadığı için o alanlar
**bilerek** alınmadı. Prefetch (her kullanıcı) ve BAM'i tamamlar: "**bu**
kullanıcı o programı başlattı mı?" Sadece o anki kullanıcının hive'ı okunur.

### mru — elle yazılan ve açılanlar

Üç küçük registry listesi bir kişinin **elle** yaptığını gösterir:
**RunMRU** (Win+R'ye yazılan komutlar; değerler `a..z`, sıra `MRUList` harf
dizisinde, her değer `\1` ile biter), **TypedPaths** (Explorer adres çubuğu;
`url1` en yeni) ve **RecentDocs** (son açılan belgeler; değerler ikili: UTF-16
ad + shell item, sıra `MRUListEx` = 0xFFFFFFFF ile biten u32 dizisi).
Klavye başındaki bir saldırgan (ya da bir RDP oturumu) çoğu zaman Run kutusunda
`powershell -nop -w hidden -enc ...` izi bırakır: kodlanmış PowerShell ve
script host'lar işaretlenir. Anahtarın son yazılma zamanı **en yeni girdinin**
eklendiği andır, bu yüzden her listede sadece o girdi zaman taşır. Format
yardımcıları portable, testli ve sanitizer fuzz'ında.

### jumplist — uygulama başına son açılanlar

Görev çubuğunda bir uygulamaya sağ tıklayınca çıkan "Son kullanılanlar" Jump
List'tir. Her uygulama (AppID = dosya adındaki hash) için iki tür dosya:

- `Recent\AutomaticDestinations\*.automaticDestinations-ms` — bir **Compound
  File** (OLE yapılandırılmış depolama). `DestList` dışındaki her akış bir
  .lnk.
- `Recent\CustomDestinations\*.customDestinations-ms` — art arda dizilmiş
  .lnk'ler; başlık imzasıyla (0x4C + CLSID) bulunur.

Bunun için sıfırdan bir **CFB okuyucu** yazıldı (`src/cfb.c`, [MS-CFB]): FAT,
DIFAT, mini FAT, mini akış; her zincir yürüyüşü tablo boyutuyla sınırlı (döngülü
ya da sahte bir zincir sonsuz döngüye sokamaz). Doğrulaması üç yoldan:

- **Diferansiyel:** 3 gerçek MSI dosyasındaki 153 akış, bağımsız Python
  `olefile` kütüphanesiyle **bayt bayt aynı** okundu. Bu test gerçek bir kenar
  durumu yakaladı: bir MSI'ın son sektörü **kesik**ti (dosya sektör boyutunun
  katı değil); okuyucu artık gereken baytlar mevcutsa kısmi son sektörü kabul
  ediyor.
- **Gidiş-dönüş:** küçük bir Python CFB yazıcısı (`tests/wine/cfbwrite.py`,
  çıktısı olefile ile de doğrulandı) rastgele dosyalar üretir; C okuyucu
  hepsini aynı içerikle geri okumalı (CI'da her push'ta).
- **Fuzz:** CFB, ASan/UBSan altındaki ayrıştırıcı fuzz'ına eklendi.

**DestList** (`src/destlist.c`) otomatik listenin dizinidir. Her öğe için şunları
tutar:

- en son kullanılandan başlayan sıra (MRU),
- son kullanım zamanı,
- sabitlenmiş mi (`pin != -1`),
- Windows 10'da etkileşim sayısı,
- makinenin NetBIOS adı,
- öğenin .lnk'sinin bulunduğu akışın adı (girdi numarası, onaltılık).

Dosya kimliği (droid) sürüm-1 bir UUID'dir; içinde makinenin MAC adresi ve bir
zaman damgası bulunur ("tracked since"). `jumplist` öğeleri bu sırayla basar ve
her birini kendi .lnk akışıyla birleştirir. DestList'te geçmeyen akışlar en
sonda listelenir. URL gibi .lnk'siz öğelerin yolu DestList'ten gelir.

Doğrulama:

- **Kahin:** Eric Zimmerman'ın JumpList projesindeki gerçek Win7, Win8, Win8.1
  ve Win10 dosyaları kullanıldı; yalnızca dosyalar, kod çalıştırılmadı.
  O projenin kendi testlerinin doğruladığı gerçekler kahin olarak alındı:
  girdi ve sabitlenmiş sayıları, sürüm, MRU sırası `7,9,8,1,2,6,5,4,3`,
  ilk girdinin yolu, makine adı, MAC, etkileşim sayısı ve 100 ns
  hassasiyetinde iki zaman damgası.
- **Tutarlılık:** her girdinin bir akışı olmalı; sabitlenmiş sayısı başlıktaki
  değerle eşleşmeli. 8 dosyada hepsi ilk denemede geçti.
- Ayrıca birim testi, fuzz ve wine fixture'ı da var.

AppID'leri program adına çeviren bir tablo **eklenmedi**: kaynaklarda
doğrulayamadığımız eşlemeler yanlış bilgi verirdi.

### bam

Her değer adı bir program yolu (`\Device\HarddiskVolumeN\...`), verinin ilk 8
baytı son çalışma FILETIME'ı. SID'ler `LookupAccountSid` ile `DOMAIN\kullanıcı`
biçimine çevrilir. Version/SequenceNumber gibi DWORD değerler atlanır.

---

## Gizli zamanlanmış görevler: `taskcache`

Task Scheduler her görevi `TaskCache\Tree` altında önbellekler (Id, Index, SD).
Bir görevin var olup araçlara görünmemesinin üç yolu var, üçünü de kontrol ediyoruz:

1. **SD değeri yok** — Tarrask tekniği. Microsoft'un önerdiği av tam olarak bu.
2. **SD'de deny ACE var** — ARC Labs'ın gösterdiği boşluk: geçerli ama okumayı
   reddeden bir SD görevi yine gizler ve 1. kontrolü atlatır.
3. **System32\Tasks altında XML yok** — görev API yerine doğrudan registry'ye
   yazılmış; dosya da, oluşturma olayı da yok.

Her işarette **hangi kontrolün** tetiklendiği yazılır. `--flagged` sadece
şüphelileri gösterir.

---

## Denetim ve FP temizliği

### autoruns: her işaretin bir nedeni var

Artık her `[!]` bir **neden** taşıyor (JSON'da `"reason"`, CSV'de yeni sütun):

- `user-writable path` — komut Temp/AppData/Downloads/... içinde
- `non-default value` — **her zaman var olan** konumlarda soru "değiştirilmiş
  mi?"dir: Winlogon `Shell` (stok: `explorer.exe`), `Userinit` (stok:
  `<System32>\userinit.exe,`), BootExecute (stok: `autocheck autochk *`), LSA
  paket listeleri, print monitor'lar, NetSh helper'lar
- `rarely legitimate location` — IFEO Debugger, SilentProcessExit, AppInit_DLLs,
  kullanıcı başına Shell: buraya giriş yazılması zaten olağandışı

Yeni konumlar: **BootExecute**, **LSA** (Authentication / Notification /
Security Packages — lsass'a DLL yükler, kimlik bilgilerini görebilir), **Print
Monitors** (spooler SYSTEM olarak yükler), **NetSh helper'ları**, HKCU Winlogon Shell.

**FP düzeltmesi:** Kullanıcının Startup klasörü zaten `AppData` altında. Eski kod
bu yüzden oradaki **her** girdiyi işaretliyordu. Artık Startup girdileri dosya
türüne göre değerlendirilir: `.lnk`/`.url` kısayolu normal; doğrudan bırakılmış
`.exe`/`.bat`/`.vbs` işaretlenir.

### services: tırnaksız yol + ServiceDll

- **Tırnaksız yol (unquoted service path):** `C:\Program Files\My App\svc.exe`
  tırnaksız yazılmışsa Windows önce `C:\Program.exe`, sonra
  `C:\Program Files\My.exe` dener. Klasik bir yapılandırma hatası; denetimi
  `svc_unquoted_path` (portable, testli) yapar. Kural: tırnakla başlamıyorsa ve
  **`.exe`'ye kadar olan kısımda** boşluk varsa. `.exe` sonrasındaki argümanlardaki
  boşluklar sayılmaz (FP olmasın diye).
- **svchost ServiceDll:** paylaşılan svchost servislerinde asıl kod
  `Services\<ad>\Parameters\ServiceDll`'dedir; artık gösteriliyor ve user-writable
  ise işaretleniyor.
- `--flagged` sadece işaretlileri gösterir.

### drivers --sig ve modules --unsigned (ListDLLs -u)

- `modules <pid> --sig` her modülün imzasını (gömülü veya katalog) kontrol eder;
  `--unsigned` **sadece güvenilir imzası olmayanları** listeler. Ayrıca modül
  yolları artık geniş karakter API'siyle alınıyor (Türkçe karakterli yollar
  bozulmuyor).
- `drivers --sig` aynısını sürücüler için yapar. Kernel yolları
  (`\SystemRoot\...`, `\??\C:\...`) önce Win32 yoluna çevrilir
  (`drv_path_normalize`, testli). **FP koruması:** tanımadığımız bir yol biçimi
  "dosya yok" ya da "imzasız" diye **değil**, `?` (çözümlenemedi) diye raporlanır.

### Tek kaynak: `ioc_user_writable`

"Bu yol kullanıcının yazabildiği bir dizinde mi?" kontrolü autoruns, tasks,
modules ve prefetch'te ayrı ayrı kopyalanmıştı. Artık `ioc.c`'de **tek, testli**
bir fonksiyon. `%APPDATA%` / `%TEMP%` gibi ortam değişkeni biçimlerini de tanıyor
(firewall kuralları ve görevler bu biçimi kullanır).

---

## firewall

Kurallar registry'den okunur (yerel + Group Policy deposu). Her kural
`v2.30|Action=Allow|Dir=In|...` biçiminde bir string; `fw_field` (portable,
testli) alanı **tam anahtar eşleşmesiyle** çeker — `Port` asla `LPort`'a
eşleşmez. Yerleşik kuralların adları `@FirewallAPI.dll,-28753` gibi dolaylı
string'lerdir; `SHLoadIndirectString` ile okunur hale getirilir.

İşaret: **aktif + gelen + izin veren** ve programı user-writable dizinde olan
kural. Dinlemek isteyen bir zararlının kendine açtığı kapının tipik şekli.
Filtreler: `--inbound`, `--allow`, `--active`.

---

## wmi — WMI kalıcı event subscription'ları

`root\subscription` altında üç nesne bir "kalıcı abonelik" oluşturur: **filter**
(tetikleyici WQL sorgusu), **consumer** (eylem) ve ikisini bağlayan **binding**.
Diske dosya bırakmayan, yeniden başlatmadan sağ çıkan bir kalıcılık yöntemi
(MITRE T1546.003) — Autoruns'un WMI sekmesinin baktığı yer.

Komut COM ile bağlanır ve sadece üç `SELECT` sorgusu çalıştırır.
`CommandLineEventConsumer` ve `ActiveScriptEventConsumer` (kod çalıştıranlar)
işaretlenir; Windows'un kendi `SCM Event Log Consumer`'ı (sadece olay günlüğüne
yazar) işaretsiz listelenir.

## tasks — gizli ve script host başlatan görevler

`tasks` artık `<Hidden>` ve `<RunLevel>HighestAvailable` ayarlarını da okur.
**FP dikkati:** Windows'un kendi görevlerinin çoğu zaten gizli ve rundll32 /
powershell başlatıyor. Bu yüzden bu iki işaret **sadece `Microsoft\` klasörü
dışındaki** görevlere uygulanır; aksi halde gerçek bulgular gürültüde kaybolurdu.

## pe — import yetenekleri (capa/pestudio fikri)

`pe` çıktısına **Import capabilities** bölümü eklendi: isimle import edilen
API'ler kaba davranış kategorilerine ayrılır (process-injection, process-access,
anti-debug, keyboard-input, network, crypto, privilege-token) ve her kategoriden
örnekler gösterilir. Tablo bizim, kısa ve eğitimsel (`src/capa.c`, testli).

**Bu bir hüküm değildir:** debugger'lar, kurulum programları, AV ve uzaktan
destek araçları bu API'lerin çoğunu meşru olarak import eder. Hatta kernel32.dll
bile "process-injection" gösterir (kernelbase'e forward ettiği için). Çok yaygın
API'ler (LoadLibrary, GetProcAddress, CreateProcess, RegSetValue...) bilerek
tabloda **yok**: her programda olduklarından sadece gürültü katarlar.

## lnk — kısayol dosyaları

`.lnk` dosyaları iki şekilde önemli: **kanıt** olarak (Windows, açılan her
dosya/klasör için `Recent` altına bir kısayol bırakır; hedefin yolu ve zamanları
o anki haliyle kaydedilir — hedef çoktan takılıp çıkarılmış bir USB'de olsa
bile) ve **başlatıcı** olarak (zararsız ikonlu bir kısayol `powershell -enc ...`
çalıştırabilir).

Ayrıştırıcı ([MS-SHLLINK] açık spesifikasyonu, `src/lnkparse.c`) başlık,
LinkInfo (yerel yol + ortak sonek, Unicode varyantları dahil) ve StringData
(açıklama, göreli yol, çalışma dizini, argümanlar, ikon) okur. Her offset ve
sayaç sınır kontrolünden geçer: .lnk dosyaları güvenilmez yerlerden gelir.

`winspect lnk` argümansız çalışınca kullanıcının **Recent** klasörünü okur.
**autoruns entegrasyonu:** Startup klasöründeki `.lnk`'ler artık çözülüyor —
"bu bir kısayol" yerine **neyi çalıştırdığı** gösteriliyor ve script host
başlatıyorsa `shortcut launches a script host / LOLBin` diye işaretleniyor.

## hunt — "Hunt Evil" soy ağacı kontrolleri

Sağlıklı bir Windows'ta süreç aile ağacı çok düzenlidir: `wininit` → `services`
ve `lsass`; `services` → `svchost` (her zaman `-k <grup>` ile). Kendine
`svchost.exe` ya da `lsass.exe` adını veren zararlı genelde bu kurallardan
birini çiğner. `hunt` tüm süreçlerde SANS "Hunt Evil" posterindeki kontrolleri
yapar:

- **beklenmeyen ebeveyn** (lsass'ı wininit değil başka biri başlatmış),
- **tek olması gereken sürecin kopyası** (iki `lsass.exe`),
- **System32 dışından çalışan çekirdek isim** (`C:\Users\x\svchost.exe`),
- **`-k` grubu olmayan svchost**.

Kural tablosu portable ve testli (`artparse.c`). **FP önlemleri:** PID yeniden
kullanımına karşı ebeveyn, ancak çocuktan **önce** oluşturulduysa sayılır;
ebeveyni çıkmış süreçler asla "yanlış ebeveyn" diye raporlanmaz; explorer.exe
kural dışı bırakıldı (kullanıcılar onu Görev Yöneticisi'nden meşru olarak
yeniden başlatır). SysWOW64'teki 32-bit kopyalar (rundll32, dllhost) meşru sayılır.

Wine testinde gerçek bir taklitçi kullanıldı: `C:\fake\svchost.exe` adıyla
çalışan bir süreç yakalandı, System32'deki gerçek süreçlerin hiçbiri işaretlenmedi.

## posture — makinenin sertleştirme durumu

Birçok zayıflık tek bir registry değerinden ibarettir. `posture` bunları tek
geçişte okur ve her biri için **OK / WARN / INFO** + tek satırlık anlam basar:

| Alan | Kontroller |
|---|---|
| UAC | EnableLUA, yöneticiye sormadan yükseltme, secure desktop |
| Kimlik bilgileri | LSA koruması (RunAsPPL), **WDigest düz metin şifre**, NTLM seviyesi, AutoLogon şifresi |
| Yetki | AlwaysInstallElevated (HKLM + HKCU — ikisi birden açıksa her kullanıcı MSI'yi SYSTEM olarak kurar) |
| Ağ | SMBv1 istemci/sunucu, LLMNR, RDP + NLA, firewall profilleri |
| Platform | Secure Boot, VBS |
| Kayıt | PowerShell script block logging |

İki tasarım kararı:

- **Değer yoksa ne demek?** Windows varsayılanları ayara göre değişir (NLA
  varsayılan açık, LLMNR varsayılan açık ama riskli). Bu yüzden her kural,
  değer **tanımlı değilken** ne söyleneceğini açıkça belirtir — "yok" asla
  otomatik olarak "kötü" ya da "iyi" sayılmaz.
- **Sırlar asla basılmaz.** AutoLogon kontrolü `DefaultPassword` değerinin
  sadece **var olup olmadığına** bakar; içeriği programa hiç okunmaz. Wine
  testinde şifre olarak `hunter2-SECRET` yerleştirilip text/JSON/CSV
  çıktılarının hiçbirinde geçmediği doğrulanıyor.

## events — olay günlüğünden yüksek sinyalli zaman çizelgesi

Olay günlükleri bir saldırganın yaptığı çoğu şeyi kaydeder — ama milyonlarca
rutin olayın arasında. Olay müdahalecileri neredeyse her zaman önemli olan kısa
bir ID listesiyle başlar (Chainsaw/Hayabusa'nın da çıkış noktası; biz sadece
fikri alıyoruz, kural motoru yok, kendi sabit listemiz var):

| Kanal | ID | Anlamı |
|---|---|---|
| System | 7045 | servis kuruldu (kalıcılık, PsExec) |
| System | 104 | bir olay günlüğü temizlendi |
| Security | 1102 | Security günlüğü temizlendi |
| Security | 4625 | başarısız oturum açma (parola deneme) |
| Security | 4720 | kullanıcı hesabı oluşturuldu |
| Security | 4728/4732/4756 | güvenlik grubuna üye eklendi (admin grubuysa işaretlenir) |
| Security | 4698 / 4697 | zamanlanmış görev / servis oluşturuldu |
| Defender | 1116/1117, 5001 | zararlı bulundu / işlem yapıldı, gerçek zamanlı koruma kapatıldı |
| TaskScheduler | 106 | görev kaydedildi |
| RDP | 1149 | uzak masaüstü kimlik doğrulaması başarılı |
| PowerShell | 4104 (**Warning**) | Windows'un kendisinin **şüpheli** bulduğu script bloğu — logging kapalı olsa bile kaydedilir |

Her kanal en yeniden geriye XPath filtresiyle sorgulanır (`EvtQuery`), her olay
XML'e çevrilir (`EvtRender`) ve gereken birkaç alan portable `evt_*`
yardımcılarıyla çekilir (XML entity çözümü dahil, testli). Tüm kanallar tek bir
zaman çizelgesinde birleşir. İşaretler: log temizleme, admin grubuna ekleme,
script host çalıştıran ya da user-writable dizindeki servis, Defender tespiti,
koruma kapatma, şüpheli PowerShell.

Security günlüğü yönetici ister; okunamayan kanal **sessizce atlanmaz**,
"channels not read" altında nedeniyle listelenir.

## hidden — çapraz görünüm (cross-view) tespiti

Rootkit tarzı gizleme genelde **tek bir yerde** yalan söyler: hook'lanmış bir
listeleme API'si ya da SCM'nin atlamasına yol açan bir güvenlik tanımlayıcısı.
Aynı gerçeği bağımsız bir yoldan okumak yalanı ortaya çıkarır — GMER, Unhide
ve RootkitRevealer'ın fikri.

- **Süreçler:** üç bağımsız liste — Toolhelp anlık görüntüsü, native
  `NtQuerySystemInformation` listesi ve **her PID'i doğrudan açmayı deneme**
  (4'ün katları, 65536'ya kadar; yalnızca hâlâ çalışanlar). Toolhelp'te
  olmayıp diğerlerinde olan PID raporlanır.
- **Servisler:** `HKLM\SYSTEM\CurrentControlSet\Services` altındaki her
  gerçek servis (Type + ImagePath) SCM'nin listesiyle karşılaştırılır. SCM'nin
  listelemediği ve açmayı **reddettiği** servis, kısıtlayıcı SDDL ile
  gizlenmiş servisin imzasıdır (kamuya belgelenmiş teknik, T1564). SCM'nin
  **hiç tanımadığı** anahtar ise doğrudan registry'ye yazılmıştır ve bir
  sonraki açılışta etkinleşir — o da raporlanır.

**FP koruması:** süreçler sürekli başlayıp bittiği için her aday, yazdırılmadan
önce **taze bir anlık görüntüyle yeniden kontrol edilir**; yeni başlamış bir
süreç "gizli" sayılmaz. Wine testinde gerçek bir registry-only servis yakalandı
ve hiçbir süreç yanlışlıkla gizli raporlanmadı.

## streams — alternate data streams ve Mark-of-the-Web

Bir NTFS dosyası, Explorer'ın ve `dir`'in göstermediği ek adlı veri akışları
taşıyabilir (`dosya.txt:gizli`) — bilinen bir saklanma yeri (T1564.004).
Gerçek hayattaki akışların çoğu zararsız meta veridir; en yaygını
**Zone.Identifier**: tarayıcılar ve e-posta istemcileri indirilen dosyaya
ekler ("Mark-of-the-Web") ve güvenlik bölgesini + URL'leri kaydeder. Bir
analist için bu, "bu dosya **nereden geldi**?" sorusunun cevabıdır.

`winspect streams <dosya|klasör> [--recurse]` akışları `FindFirstStreamW` ile
listeler, Zone.Identifier'ı okuyup (portable `motw_parse`, testli) bölgeyi ve
`HostUrl` / `ReferrerUrl`'yi gösterir. İşaretler:

- internet / restricted bölgesinden gelmiş **çalıştırılabilir içerik**
  (.exe, .dll, .ps1, .js, .hta, .lnk, .iso ...),
- bilinen zararsız meta veri akışı olmayan **olağandışı akış**.

Junction/symlink'ler izlenmez (döngü ve ağaç dışı yollar), en fazla 200.000
dosya taranır. Wine gerçek ADS desteklemediği için bu komut **Windows CI'ında
gerçek NTFS üzerinde** fonksiyonel olarak test ediliyor: bir dosyaya MOTW ve
gizli bir akış yazılıp ikisinin de doğru işaretlendiği doğrulanıyor.

## autoruns / services --sig — "Verify code signatures"

Autoruns'un en çok kullanılan seçeneği her girdinin çalıştırdığı dosyanın
imzasını kontrol etmektir. `--sig` aynısını yapar; zor kısım **komut
satırından doğrulanacak dosyayı bulmak**tır (`ioc_command_image`, testli):

- tırnaklı / tırnaksız exe yolu (boşluklu yollar dahil, `.exe`'ye kadar),
- `rundll32 x.dll,Entry` ve `regsvr32 /s /i:... x.dll` → asıl çalışan **DLL**,
- BootExecute'taki `autocheck autochk *` → `autochk`,
- `%SystemRoot%` gibi değişkenler açılır, çıplak adlar (`explorer.exe`,
  uzantısız `kerberos`) arama yolunda `.exe` sonra `.dll` olarak bulunur,
- sürücü yolları (`\SystemRoot\...`, `\??\C:\...`) Win32 yoluna çevrilir.

Sonuç her girdide `signature` alanında: `embedded`, `catalog`, `untrusted`
ya da `unresolved` (dosya bulunamadı — **asla** sessizce "güvenilir" sayılmaz).
Güvenilmeyen imaj, başka neden yoksa `image not signed / not trusted` olarak
işaretlenir. `services --sig` svchost servislerinde `svchost.exe` yerine asıl
kodu taşıyan **ServiceDll**'i doğrular.

## sweep — tek komutla makine taraması

`winspect sweep` sistem çapındaki tüm kontrolleri **sadece bulgular** modunda
sırayla çalıştırır: posture `--warn`, hunt, hidden, net `--flagged`, autoruns / services /
tasks / taskcache / firewall `--flagged`, defender, wmi, bits / recyclebin
`--flagged`, pshistory `--all-users --flagged` (20. belge), events. Böylece
"bu makinede bakılması gereken ne var?" sorusunun cevabı tek sayfa olur.

`--json` ile sonuç **tek bir nesne**dir: her kontrol bir anahtar. İnce nokta:
her komut kendi JSON'unu stdout'a yazar, yetki isteyen bir kontrol (ör.
Security günlüğü) hiçbir şey basmadan başarısız olabilir. Belgenin bozulmaması
için her kontrolün stdout'u geçici bir dosyaya yönlendirilip yakalanır;
çalışamayan kontrolün anahtarı `null` olur.

Bunun için autoruns, tasks ve firewall'a da `--flagged` seçeneği eklendi.

## triage — soy ağacı sinyalleri

`triage` artık `hunt`'ın kurallarını tek süreç için de uygular: **System32
dışından çalışan çekirdek süreç adı** (+40) ve **beklenmeyen ebeveyn** (+30).
Ebeveyn, PID yeniden kullanımına karşı oluşturulma zamanıyla doğrulanır. Wine
testinde `C:\fake\svchost.exe` HIGH (90) aldı.

## Ek denetimler: pipes, hosts, net, handles, triage

- **pipes:** Cobalt Strike'ın **kamuya belgelenmiş varsayılan** pipe adları
  (`MSSE-####-server`, `msagent_##`, `postex_####`, `status_##`) ve PsExec /
  RemCom / PAExec servis pipe'ları araç adıyla işaretlenir. Küçük bir desen
  eşleyici (`#` = rakam, `%` = hex) kullanılır; `msagent_3f1` gibi bir fazla
  karakter eşleşmez. Varsayılanlar kolayca değiştirilir: eşleşme yokluğu bir
  şey kanıtlamaz, eşleşme ise güçlü bir ipucudur. *(JSON biçimi değişti: artık
  string dizisi değil `{name, known_tool}` nesneleri.)*
- **hosts:** her satır **block** (127.x / 0.0.0.0 / ::1 — isim erişilemez
  yapılır) ya da **redirect** (başka bir adres — trafik sessizce yönlendirilir,
  işaretlenir) olarak sınıflanır.
- **net:** uzak adresin kapsamı (`public` / `private` / `cgnat` / `link-local`
  ...) eklendi. `--external` sadece public adreslere giden bağlantıları,
  `--exposed` sadece **tüm arayüzlerde** (0.0.0.0 / ::) dinleyen soketleri
  gösterir. **Hata düzeltmesi:** port numaraları yanlış basılıyordu (bkz. 17).
  Ayrıca her uç noktanın **süreç yolu** da alınıyor ve şu durumlar nedenleriyle
  işaretleniyor: public bir adrese bağlı **script host / LOLBin** (ör.
  `powershell.exe`), public adrese bağlı ya da tüm arayüzlerde dinleyen
  **user-writable dizindeki program**. `--flagged` sadece bunları gösterir ve
  `sweep`'e de dahildir. (Wine her soketi pid 0'a atadığı için bu kontrol
  Windows CI'ında, `%TEMP%`'ten çalışan gerçek bir dinleyiciyle doğrulanıyor.)
- **handles:** erişim maskesi artık **nesne türüne göre** çözülüyor. Aynı bit
  türe göre farklı anlam taşır (`0x10` process'te VM_READ, thread'de
  SET_CONTEXT). Tablolar secinfo ile ortak, portable `rights.c`'de; File, Key,
  Process, Thread, Token, Section, Event, Mutant, Semaphore, Directory, Job,
  KeyedEvent, IoCompletion, Timer ve Service türleri tanınıyor.
- **pe — packer section adları:** `UPX0/UPX1`, `.aspack`, `.MPRESS1`, `.vmp0`,
  `.themida`, `PEC2`, `.nsp0`, `.enigma1` gibi bilinen paketleyici/koruyucu
  section adları **packer** anomalisi olarak raporlanır (her packer bir kez).
  Bu genel bilgi; DIE gibi lisanslı imza veritabanı kullanılmadı. Paketli
  dosya kötü niyetli olmak zorunda değil (ticari yazılımlar da koruyucu
  kullanır) ama gerçek import'ları ve string'leri gizler. Wine testinde gerçek
  `upx` ile paketlenmiş bir dosya kullanılıyor.
- **strings — base64 ve kodlanmış PowerShell:** IOC sınıflandırıcısı artık
  `encoded-cmd` (`powershell -enc ...` / `-EncodedCommand`) ve `base64` (≥40
  karakter, geçerli dolgu, karışık karakter türleri — uzun kelimeler ve hex
  dökümleri sayılmaz) sınıflarını da tanıyor.
- **certstore:** Root deposunda iki şey işaretlenir: **özel anahtarı bu
  makinede olan kök** (yerelde üretilmiş kök — TLS trafiğini ele geçiren
  yazılımın şekli; Superfish / eDellRoot vakaları: o anahtara sahip olan her
  siteyi taklit edebilir) ve **self-signed olmayan "kök"**. Self-signed kararı
  artık görünen adların string karşılaştırmasıyla değil, kodlanmış ad
  alanlarının karşılaştırılmasıyla (`CertCompareCertificateName`) veriliyor.
  Süresi dolmuşlar da gösteriliyor. Wine'daki 126 kökün tamamı doğru
  sınıflandı, yanlış alarm yok.
- **triage:** "güçlü privilege etkin" gerekçesi artık **hangi** privilege'ların
  etkin olduğunu adıyla söylüyor (ör. `SeLoadDriverPrivilege,
  SeImpersonatePrivilege`).

---

## Testler

Birim testleri 62'den **217**'ye çıktı (capa, lnk, script host, soy ağacı, posture, pipe/IP kapsamı, port dönüşümü, hak tabloları ve olay XML'i dahil). Yeni portable parçalar: prefetch
dosya/volume listeleri, ShimCache ayrıştırıcı (normal, bozuk, eski düzen),
firewall alanları, `ioc_user_writable`, tırnaksız servis yolu, sürücü yolu
normalleştirme. CI smoke testi yeni komutları ve bayrak kombinasyonlarını da
(`modules --unsigned`, `drivers --sig`, `services --flagged`, `firewall --inbound
--allow --active --csv`) gerçek Windows'ta çalıştırır.

## Bilerek yapılmayanlar

Kural eklemek/silmek, görev gizlemek/göstermek, servis yolunu düzeltmek,
ShimCache/BAM/Prefetch temizlemek — hiçbiri yok. Araç sadece okur ve **neden**
şüphelendiğini söyler.
