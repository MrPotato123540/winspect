# 11 — Daha derin esin: AccessChk, pefile, netstat, pe-sieve/Moneta

Bu dalga (F–J), winspect'in kimliğine en yakın beş aracı (sigcheck, winchecksec,
AccessChk, pefile, netstat) ve bellek tarayıcı kavramlarını (pe-sieve/Moneta)
biraz daha inceleyip **salt-okunur, eğitimsel, temiz-oda** fikirlerle genişletir.
Tek satır kod kopyalanmadı; sadece *kavram* alındı.

---

## F. verify/triage: thread ve section-izni tespiti (pe-sieve/Moneta)

İki yeni kontrol `src/detect.c`'ye eklendi (verify hem triage ortak çağırır):

- **Thread başlangıç adresi** (check 7): her thread'in Win32 start address'i
  (`NtQueryInformationThread`) yüklü bir modülün aralığında mı? Değilse →
  enjekte/hijack edilmiş thread'in klasik şekli. Modül aralıkları zaten elimizde
  (`addr_backed`), o yüzden ucuz ve güçlü.
- **Section izin uyuşmazlığı** (check 8): modülün bellekteki section izinleri,
  PE header'ın bildirdiği izinlerden **daha geniş** mi (ör. header R-X diyor ama
  bellek RWX, ya da data section'ı çalıştırılabilir olmuş)? Moneta'nın ucuz
  sinyali. Yalnızca "tehlikeli yönde daha geniş" durumları işaretler; yükleyicinin
  izinleri daraltması (COW) normaldir, elenir.

Her ikisi triage skoruna bağlı. verify artık **8 kontrol** basıyor.

**Yanlış-alarm sertleştirmesi (önemli):** Bir güvenlik aracında *temiz* bir
process'i yanlışlıkla işaretlemek, kaçırmaktan daha kötüdür. İki noktayı
sertleştirdik:
- **Image tamper**: modül tercih edilen tabana yüklenmemiş (delta≠0) *ama*
  relocation tablosu yoksa, yükleyicinin adres düzeltmelerini geri alamayız —
  bu durumda "değişmiş" demek yerine "doğrulanamadı" deriz (checked=0), triage da
  bunu işaretlemez.
- **Unbacked thread**: JIT ve bazı yönetilen çalışma zamanları (.NET) meşru olarak
  backing'siz bellekte thread başlatabildiği için, bu sinyalin triage ağırlığı
  diğer disk/bellek sinyallerinden düşük tutuldu (+25) — tek başına "mahkûm etmez",
  katkıda bulunur.

---

## G. pe: anomali tarayıcısı (pefile `warnings`)

`pe`'ye statik bir **Anomalies** bölümü eklendi — pefile'ın bozuk/şüpheli değerleri
işaretlemesinin karşılığı. Hepsi dosyayı okumaktan ibaret, sıfır risk:

- **PE checksum uyuşmazlığı**: header'daki CheckSum sıfır değilse ve yeniden
  hesaplananla tutmuyorsa → dosya imzadan/linklemeden sonra düzenlenmiş.
- **Entry point section dışında**: başlangıç adresi hiçbir section'a düşmüyor.
- **W+X section**: hem yazılabilir hem çalıştırılabilir (W^X ihlali).
- **Boş kod section'ı**: çalıştırılabilir ama diskte ham verisi yok (runtime'da
  açılan packer stub'ı?).
- **Anormal section adı**: adında yazdırılamayan bayt.
- **Çakışan section'lar**, **gelecekteki build timestamp'i**.

JSON'da `"anomalies":[{type,detail}]`. Ayrıca manifest `requestedExecutionLevel`
(asInvoker / requireAdministrator / highestAvailable) de artık basılıyor —
"bu başlarken yönetici mi istiyor?" sorusu.

---

## H. net: process adı + filtreler (netstat -b / TcpView)

`net` artık her bağlantının **sahibi process'in adını** da gösteriyor (Toolhelp ile
kurulan PID→isim haritası; her process'i açmaya gerek yok, özel yetki istemez).
Yeni filtreler: `--tcp`, `--udp`, `--listening` (dinleyen/bağlı soketler),
`--established` (sadece canlı TCP). svchost gibi her yerde çıkan PID'leri isimle
ayırt etmeyi kolaylaştırır. (Daha derin seçenek `GetOwnerModuleFromTcpEntry`;
exe adı pratikte çoğu durumu karşıladığı için sade yolu seçtik.)

---

## I. sign: dizin tarama + manifest (sigcheck -u -e -s)

sigcheck'in en çok kullanılan modu eklendi: **`sign --scan <dir>`** bir klasörü
(alt klasörler dahil) gezer, MZ ile başlayan her dosyayı (uzantıya değil header'a
bakarak, `-e` gibi) imza açısından denetler ve **varsayılan olarak yalnızca
güvenilmeyen/imzasız** olanları listeler (`--all` hepsini). CSV/JSON destekli;
çıkış kodu güvenilmeyen bulunca non-zero, böylece CI/script kapı koyabilir.
"System32'de imzasız ne var?" sorusunun cevabı.

---

## J. secinfo: AccessChk kapsamı

`secinfo` artık dört nesne türünü anlıyor (AccessChk gibi):

- **process** (pid) ve **dosya** (yol) — zaten vardı.
- **servis**: `--service <ad>` (`GetNamedSecurityInfo` + `SE_SERVICE`).
- **registry anahtarı**: `--key <MACHINE\...|CURRENT_USER\...>` (`SE_REGISTRY_KEY`).

Üstüne:

- **Named-rights çözümü**: ham access mask artık nesne türüne göre okunur haklara
  çevriliyor (ör. servis için `START|STOP|CHANGE_CONFIG`, dosya için
  `READ_DATA|WRITE_DATA`, standart `WRITE_DAC` vb.). `--rights` ile her ACE'nin
  maskesi de açılır; effective-access satırında her zaman gösterilir.
- **Hesap hakları**: `--privileges <hesap>` — bir hesabın sistemde **sahip olduğu**
  privilege/logon haklarını listeler (`LsaEnumerateAccountRights`). Bu, nesnenin
  DACL'ı değil, öznenin kendi gücüdür (SeDebugPrivilege, SeServiceLogonRight...).
- (Dalga D'den gelen `--account <hesap>` zaten herhangi bir hesabın efektif
  erişimini Authz ile hesaplıyordu; artık named-rights ile birlikte.)

---

## Bilerek yapılmayanlar (kuralların gereği)

VirusTotal yükleme/sorgu (online + gizlilik), DIE'nin packer imza veritabanı
(lisans + boyut), disassembler/editör (kapsam + yazma). Araç salt-okunur kalır.

## Özet

Bu dalgayla winspect, kimliğine en yakın beş aracın **okuma/inceleme**
yeteneklerini tek binary altında topladı: AccessChk'in nesne kapsamı ve
named-rights'ı, pefile'ın anomali uyarıları, sigcheck'in dizin taraması, netstat'ın
process çözümü, ve pe-sieve/Moneta'nın thread/section sinyalleri — hepsi
`--json`/`--csv` ile ve hepsi defansif.
