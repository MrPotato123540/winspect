# 12 — Yeni komutlar ve derinleşen tespit (K–S)

Bu dalga altı yeni komut ekler ve mevcut üç komutu derinleştirir. Hepsi
salt-okunur, eğitimsel, temiz-oda; esin kaynakları Sysinternals (strings,
Autoruns, sigcheck), pefile ve pe-sieve/Moneta kavramları.

## Yeni komutlar

- **`strings <path>`** — dosyadan yazdırılabilir ASCII ve UTF-16LE string'leri
  çıkarır; URL / IP / registry yolu / dosya yolu gibi **göstergeleri (IOC)**
  işaretler. `-n <uzunluk>` asgari uzunluk, `--ioc` yalnızca işaretlileri gösterir.
  Statik triyajın ilk adımı.
- **`services`** — SCM'den servisleri listeler (durum, start tipi, sahip PID,
  binary yolu, çalıştığı hesap). `--drivers` sürücü servislerini de katar.
  Salt-okunur (yalnızca sorgu yetkisi).
- **`drivers`** — yüklü çekirdek sürücülerini (yükleme adresi + dosya yolu)
  `EnumDeviceDrivers` ile listeler. İmzasız/şüpheli sürücü avının başlangıcı.
- **`autoruns`** — yaygın oto-başlatma registry konumlarını (HKLM/HKCU Run &
  RunOnce, Wow6432Node, Winlogon Userinit/Shell) salt-okunur gezer; komutu
  kullanıcı-yazılabilir/temp konumdan çalışanları işaretler. Sysinternals
  Autoruns'ın küçük, şeffaf bir alt kümesi.
- **`pipes`** — sistemdeki named pipe'ları (`\\.\pipe\`) listeler. Named pipe'lar
  yaygın IPC ve C2 kanalıdır; isim listesine bakmak ucuz bir triyajdır.
- **`hash <path>`** — dosyanın MD5 / SHA1 / SHA256 özetini (CNG/BCrypt ile)
  hesaplar. Tehdit-istihbaratında bir örneğin kimliği bu üçüdür.

## Derinleşen komutlar

- **`pe`**: **exphash** (export adlarının MD5'i — kütüphane parmak izi) ve
  **.NET CLR header** (COM descriptor varsa: runtime sürümü, ILONLY/32BIT/
  STRONGNAME bayrakları, entry token) eklendi.
- **`handles`**: başka bir process'e açılmış, **enjeksiyon-yetenekli** erişim
  (Process: VM_WRITE/VM_OPERATION/CREATE_THREAD; Thread: SET_CONTEXT/
  SUSPEND_RESUME) taşıyan handle'lar hedef PID çözümüyle **[INJECTABLE]** diye
  işaretleniyor. Process'in kendine handle'ı işaretlenmez (normal).
- **`token`**: güçlü privilege'ler (SeDebug, SeTcb, SeLoadDriver, SeBackup,
  SeRestore, SeTakeOwnership, SeImpersonate, SeAssignPrimaryToken, ...)
  işaretleniyor; enabled olanlar ayrıca vurgulanıyor. `triage` de bunu bir sinyal
  olarak skora katıyor (+15).

## Sınırlar

Hepsi salt-okunur. `services` servisi başlatmaz/durdurmaz; `autoruns`/`pipes`
yalnızca listeler; `hash`/`strings`/`pe` dosyayı yalnızca okur; `drivers` sürücü
yüklemez. Hiçbir komut enjeksiyon/yama yapmaz.
