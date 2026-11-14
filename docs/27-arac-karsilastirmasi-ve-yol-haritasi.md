# 27 — Diğer araçlarla karşılaştırma ve yol haritası

Bu bölüm bir **envanterdir**: winspect'in esinlendiği araçların depoları
GitHub'dan çekildi, her birinin "ne yapıyor" listesi çıkarıldı ve winspect'le
tek tek karşılaştırıldı. Amaç üç soruya cevap vermek:

1. Onlarda olup bizde **olmayan** ne var?
2. Bunlardan hangisi bu turda eklendi?
3. Geri kalanı neden eklenmedi ve sırada ne var?

## Yöntem ve kural

**Kod kopyalanmadı.** Her depodan yalnızca *ne yaptığını söyleyen* listeler
okundu: dosya adları, artefakt tanımlarının adları, tablo adları, README.
Bu, projenin *clean-room* kuralıdır: fikir ve kapsam alınır, uygulama kendi
elimizle yazılır.

| Araç | Ne için bakıldı | Bakılan liste |
|---|---|---|
| **KAPE** (KapeFiles) | Bir olay müdahalesinde hangi dosyalar toplanır? | `Targets/Windows`, `Targets/Antivirus`, `Targets/Logs` (≈150 hedef) |
| **Velociraptor** | Uç noktada hangi sorular sorulur? | `artifacts/definitions/Windows` (≈230 artefakt) |
| **osquery** | İşletim sistemi tablo olarak nasıl görülür? | `specs/windows` (56 tablo) |
| **PersistenceSniper** | Hangi kalıcılık noktaları bilinir? | 58 tekniğin adı |
| **Volatility 3** | Bellekte neye bakılır? | `plugins/windows` (≈100 eklenti) |
| **plaso** | Hangi artefaktlar zaman çizelgesine girer? | `parsers/` (Windows ile ilgili ≈70 ayrıştırıcı) |
| **PEASS-ng (winPEAS)** | Hangi yanlış yapılandırmalar yetki yükseltir? | kontrol başlıkları |
| **pe-sieve** | Canlı process'te hangi implant türleri aranır? | README |
| **hayabusa / chainsaw** | Olay günlüğünde hangi kurallar çalışır? | kural klasörleri |

Terimler:

| Terim | Anlamı |
|---|---|
| **Artefakt** | Bir etkinliğin sistemde bıraktığı iz (dosya, kayıt defteri değeri, günlük kaydı). |
| **Kalıcılık (persistence)** | Saldırganın yeniden başlatmadan sonra da çalışmayı sürdürmesini sağlayan ayar. |
| **LOLBin** | Windows'la gelen, saldırganların kötüye kullandığı meşru araç (`certutil`, `mshta`, `rundll32`...). |
| **Shim** | Windows'un eski programları çalıştırmak için araya koyduğu uyumluluk yaması; özel bir shim veritabanı bir programa DLL enjekte edebilir. |
| **AMSI** | Betikleri çalışmadan önce antivirüse gösteren Windows arayüzü. |

---

## 1. Bu turda eklenenler

### `autoruns`: 22 yeni kalıcılık noktası

PersistenceSniper'ın 58 tekniğinden winspect 25'ini zaten okuyordu. Kalanlardan
19'u (aşağıdaki tablonun çoğu) bu turda eklendi; tabloda ayrıca o listede
olmayan birkaç nokta da var:

| Nokta | Ne zaman çalışır | Varsayılan |
|---|---|---|
| Eski tip `Load` / `Run` değerleri | oturum açılırken | **boş** |
| Winlogon `Notify` DLL'leri | oturum olaylarında (Vista'da kaldırıldı) | **anahtar yok** |
| AeDebug, .NET `DbgManagedDebugger` | herhangi bir program çöktüğünde | geliştirici makinelerinde dolu |
| WER `Hangs\Debugger`, `ReflectDebugger` | program donduğunda / WER devreye girdiğinde | **boş** |
| `SetupExecute`, `PlatformExecute` | Windows açılmadan önce (smss) | **boş** |
| `BootVerificationProgram` | her açılışta (SCM) | **boş** |
| LSA `Extensions` | lsass içine DLL | System32'deki çıplak adlar |
| Winlogon `mpnotify` | oturum açılırken, parolayı alır | **boş** |
| DNS `ServerLevelPluginDll` | DNS servisi SYSTEM olarak yükler | **boş** |
| WinSock `AutodialDLL` | ağ kullanan her process | `System32\rasadhlp.dll` |
| Group Policy uzantıları | her ilke yenilemesinde | hepsi System32 |
| `TelemetryController` komutları | uyumluluk telemetrisi zamanlamasında | `CompatTelRunner.exe` |
| Arama dizinleyici DLL geçersiz kılmaları | dizinleyici çalışırken | **boş** |
| Servis `FailureCommand` | servis **çöktüğünde** | çoğunlukla boş |
| AMSI sağlayıcıları | her PowerShell / betik çalıştığında | Defender'ın `MpOav.dll`'i |
| .NET profil / başlangıç kancası değişkenleri | **her** .NET process'inde | kullanıcı düzeyinde boş |
| Özel shim veritabanları + uygulandığı programlar | o program her başladığında | **boş** |
| `Setup\Scripts\ErrorHandler.cmd` | kurulum hata verdiğinde | dosya yok |
| PowerShell profilleri | her PowerShell oturumunda | makine düzeyinde yok |

**Yanlış alarm önlemi.** Varsayılanı olan listeler için tek bir ortak ölçüt
yazıldı (`asep_system_dir_default`): değer çıplak bir dosya adıysa ya da
klasörü tam olarak `System32` / `SysWOW64` ise varsayılandır.

```c
{ "C:\\Windows\\System32\\sub\\evil.dll", 0 },   // alt klasör: varsayılan DEĞİL
{ "C:\\Evil\\System32\\x.dll", 0 },              // başka yerdeki "System32": DEĞİL
```

Bir tuzak da burada çıktı: Defender'ın AMSI DLL'i `ProgramData` altında
durur ve genel "kullanıcı yazabilir klasör" kuralı onu işaretliyordu. Oysa o
klasöre yalnızca SYSTEM yazabilir. Artık bilinen-iyi konum önce denetleniyor.

### `posture`: altı yeni denetim

| Denetim | Neden |
|---|---|
| Port yönlendirme kuralları (`netsh portproxy`) | Saldırgan iç ağdaki bir makineye (çoğunlukla RDP'ye) bu makine üzerinden ulaşmak için ekler. `logons`'taki "127.0.0.1'den RDP" bayrağının öbür yarısı. |
| Kimlik doğrulamasız erişilebilen pipe'lar | Modern Windows'ta liste boştur. |
| Oturum açma ekranından gizlenmiş hesaplar | Arka kapı hesabını gözden saklamanın bilinen yolu. |
| WSUS sunucusu düz HTTP üzerinden | Güncelleme yolda değiştirilebilir. |
| Kullanıcı onayı olmadan RDP gölgeleme | Oturum uzaktan izlenebilir / yönetilebilir. |
| Sysmon var mı | Varsa çok daha zengin bir günlük mevcuttur. |

### `hunt`: adı değiştirilmiş sistem aracı

Velociraptor'ın *BinaryRename* fikri. Saldırgan `cmd.exe`'yi
`svc_update.exe` diye kopyalarsa ad temelli kurallar onu görmez. Ama dosyanın
**sürüm kaynağı** (version resource) hâlâ `OriginalFilename = Cmd.Exe` der.

```
svc_update.exe is cmd.exe under another name (OriginalFilename Cmd.Exe)
```

Yalnızca 26 bilinen araç (cmd, PowerShell, rundll32, mshta, certutil, PsExec,
ProcDump, rclone...) yargılanır. Sıradan yazılımların çoğunda bu alan dosya
adıyla zaten uyuşmaz; onlara dokunulmaz.

### `capability` (yeni komut): mikrofonu, kamerayı kim kullandı?

KAPE'nin *CapabilityAccessManager* hedefi. Windows, Ayarlar > Gizlilik
ekranında gösterdiği veriyi kayıt defterinde tutar: hangi program hangi
yeteneği **en son ne zaman** kullanmaya başladı ve bıraktı.

```
[!] microphone  2024-01-17 21:20:00  2024-01-17 21:21:00  Allow user  C:\Users\bob\AppData\Local\Temp\rat.exe
        <- program in a user-writable dir used the microphone
    microphone  2024-01-17 21:20:01  IN USE NOW           Allow user  C:\Program Files\Zoom\bin\Zoom.exe
```

Bitiş zamanı sıfırsa yetenek **şu an kullanımda**dır. İşaretlenen tek durum:
kullanıcının yazabildiği bir klasördeki masaüstü programının mikrofonu ya da
kamerayı kullanması.

### `logons`: başarısız girişler ve tutan parola tahmini

Velociraptor'ın *FailedLogBeforeSuccess* fikri.

- `--failed`, başarısız girişleri (4625) Windows'un kaydettiği **nedenle**
  listeler: yanlış parola, böyle bir kullanıcı yok, hesap kilitli...
- Aynı kaynaktan bir saat içinde **10 veya daha fazla** başarısızlıktan sonra
  gelen başarılı giriş işaretlenir.

Gerçek örnek (kayıtlı bir saldırı günlüğünden):

```
2020-09-09 13:18:23  FAILED  interactive  MSEDGEWIN10\IEUser  MSEDGEWIN10  wrong password, Negotiate, via chrome.exe
```

Chrome'un parola denemesi tek satırda görünüyor: bir tarayıcı neden Windows
parolası doğruluyor?

---

## 2. Kapsam tablosu: araç araç

Durum sütunu: **var** = önceden vardı · **yeni** = bu turda (25–27. bölümler)
eklendi · **sırada** = yapılabilir, yol haritasında · **dışı** = bilerek
yapılmıyor (nedeni yazılı).

### KAPE hedefleri

| Hedef | winspect | Durum |
|---|---|---|
| `$MFT`, `$J` (USN) | `mft`, `usn` | var |
| Amcache, Prefetch, SRUM, ShimCache, BAM | aynı adlı komutlar | var |
| LNK, Jump List, ShellBags, RecycleBin | `lnk`, `jumplist`, `shellbags`, `recyclebin` | var |
| EventLogs, EventLogs-RDP | `events`, `logons`, `boots` | var / yeni |
| ScheduledTasks, BITS, WBEM | `tasks`, `taskcache`, `bits`, `wmi` | var |
| AppCompatPCA, USBDevicesLogs | `pca`, `setupapi`, `usb` | var |
| WindowsTimeline, PowerShellConsole | `activities`, `pshistory` | var |
| **WER** | `wer` | yeni |
| **WinDefendDetectionHist** | `detections` | yeni |
| **CapabilityAccessManager** | `capability` | yeni |
| **SDB** (özel shim veritabanları) | `autoruns` (kayıtlı olanlar ve uygulandığı programlar) | yeni (kayıt kısmı) |
| MicrosoftOfficeBackstage, Office güveni | `office`, `mru` | yeni / var |
| NETCLRUsageLogs | — | sırada |
| StartupInfo (`WDI\LogFiles\StartupInfo\*.xml`) | — | sırada |
| CertUtil / CryptnetUrlCache | — | sırada (gerçek örnek gerek) |
| WindowsFirewall günlüğü (`pfirewall.log`) | — | sırada (plaso'da test verisi var) |
| SUM (User Access Logging, sunucu) | — | sırada (ESE okuyucumuz hazır, plaso'da veri var) |
| WindowsNotificationsDB | — | sırada (SQLite okuyucumuz hazır) |
| `$LogFile`, `$SDS`, `$I30`, `$Bitmap` | — | sırada (NTFS iç yapıları; büyük iş) |
| RDPCache (bitmap önbelleği), ThumbCache, IconCache | — | dışı: görüntü kurtarma, komut satırı aracına uymuyor |
| Notepad sekme durumu, Recall, Snipping Tool | — | dışı: kullanıcının yazdığı içerik; gizlilik kuralı |
| ActiveDirectoryNTDS, SAM parolaları | — | **dışı: parola özetleri okunmaz** |
| Antivirüs ürün günlükleri (25 ürün) | yalnızca Defender | sırada (ürün başına ayrı biçim) |

### Velociraptor artefaktları

| Artefakt | winspect | Durum |
|---|---|---|
| Sys/Services, Drivers, Programs, Users, Interfaces | aynı adlı komutlar | var |
| System/Handles, Pslist, DLLs, Threads, VAD | `handles`, `list`, `modules`, `threads`, `regions` | var |
| Network/Netstat, ArpCache, ListeningPorts | `net`, `arp` | var |
| System/DNSCache | `dns` | yeni |
| System/HostsFile, Shares, RootCAStore | `hosts`, `shares`, `certstore` | var |
| Persistence/PermanentWMIEvents, Debug, SilentProcessExit | `wmi`, `autoruns` | var |
| Persistence/PowershellProfile | `autoruns` | yeni |
| Sys/AppcompatShims | `autoruns` | yeni |
| Registry/PortProxy | `posture` | yeni |
| Registry/EnabledMacro | `office` | yeni |
| Detection/BinaryRename | `hunt` | yeni |
| EventLogs/RDPAuth, ExplicitLogon, AlternateLogon | `logons` | yeni |
| Events/FailedLogBeforeSuccess | `logons` | yeni |
| EventLogs/Cleared, ServiceCreationComspec, PsexecService | `events` | var |
| Forensics/Timeline, RecentApps | `timeline`, `userassist` | var |
| Registry/PuttyHostKeys | — | sırada (bağlanılan SSH sunucuları; açık anahtarlar gizli değildir) |
| System/AuditPolicy | — | sırada (`logons` boş çıkınca "denetim kapalı mı?" sorusu) |
| ETW/ETWSessions | — | sırada (günlükleme kurcalanmış mı?) |
| EventLogs/Kerberoasting (4769, RC4) | — | sırada |
| Detection/TemplateInjection, OfficeMacros | — | sırada (zip + deflate gerekir; şu an yok) |
| NTFS/I30, ExtendedAttributes | — | sırada |
| Detection/Yara/*, Carving/* | — | dışı: imza motoru ayrı bir proje |
| Memory/Acquisition, ProcessDump | — | **dışı: bellek dökümü parola içerir** |
| Applications/Chrome/Cookies | — | **dışı: oturum çerezleri gizlidir** |
| Remediation/* | — | **dışı: araç salt-okunurdur** |

### osquery tabloları

| Tablo | winspect | Durum |
|---|---|---|
| services, drivers, programs, scheduled_tasks, pipes, registry | var | var |
| prefetch, shimcache, userassist, shellbags, background_activities_moderator | var | var |
| authenticode, logon_sessions, shared_resources, windows_firewall_rules | `sign`, `sessions`, `shares`, `firewall` | var |
| wmi_event_filters / consumers / bindings | `wmi` | var |
| dns_cache | `dns` | yeni |
| windows_crashes | `wer` | yeni |
| appcompat_shims | `autoruns` | yeni |
| office_mru | `mru`, `office` | var / yeni |
| ntfs_journal_events | `usn` | var |
| bitlocker_info, tpm_info, deviceguard_status | — | sırada (WMI gerekir) |
| windows_security_center, windows_security_products | — | sırada |
| patches, windows_update_history | — | sırada |
| logical_drives, disk_info | — | sırada (`volumes`: LNK / Prefetch'teki birim seri numaralarıyla eşleştirme) |
| ie_extensions, chocolatey_packages | — | düşük öncelik |

### PersistenceSniper teknikleri (58)

| Durum | Teknikler |
|---|---|
| var (25) | RunAndRunOnce, RunExAndRunOnceEx, ImageFileExecutionOptions, SilentExitMonitor, AppInitDLLs, AppCertDlls, WinlogonUserinit, WinlogonShell, LsaAuthenticationPackages, LsaSecurityPackages, LsaPasswordFilter, CmdAutoRun, UserInitMprScript, TSInitialProgram, RDPWDSStartupPrograms, NetshHelperDLL, BootExecute, Screensaver, WMIEventsSubscrition, WindowsServices, ServiceDlls, ScheduledTasks, GhostTask, BitsJobsNotifyCmdLine, StartupPrograms |
| yeni (19) | ExplorerLoad, WinlogonNotificationPackages, AeDebug, WerFaultHangs, DotNetDebugger, LsaExtensions, ServerLevelPluginDll, AutodialDLL, WinlogonMPNotify, BootVerificationProgram, SetupExecute, PlatformExecute, AMSIProviders, NLDPDllOverridePath, GPExtensionDlls, TelemetryController, DotNetStartupHooks, ErrorHandlerCmd, PowershellProfiles |
| sırada (9) | AppPaths, ExplorerTools, ExplorerContextMenu, CHMHelperDll, HHCtrlHijacking, OfficeTemplates, MicrosoftOfficeAIHijacking, TerminalProfileStartOnUserLogin (JSON dosyası), PowerAutomate |
| sırada, dikkatli (5) | AccessibilityTools (dosya özeti karşılaştırması gerekir), ServiceControlManagerSecurityDescriptor, RidHijacking ve SubornerAttack (SAM'ın `F` değeri; parola özeti içermez ama dikkat ister), DSRMBackdoor |

### Volatility 3 eklentileri

Volatility bellek **dökümü** üzerinde çalışır; winspect canlı sistemde aynı
soruların kullanıcı kipinden cevaplanabilenlerini sorar.

| Eklenti | winspect | Durum |
|---|---|---|
| pslist, pstree, cmdline, dlllist, handles, privileges, getsids | `list`, `inspect`, `modules`, `handles`, `token` | var |
| malfind, vadinfo | `regions`, `verify` (özel çalıştırılabilir bellek) | var |
| hollowprocesses, ldrmodules, iat, unhooked_system_calls | `verify`, `hidden`, `ssn` | var (yama raporu yeni) |
| psxview | `hidden` | var |
| netscan, netstat | `net` | var |
| svcscan, svclist, svcdiff | `services` | var |
| suspicious_threads, suspended_threads | `threads`, `verify` | var |
| pebmasquerade, processghosting | — | sırada (PEB'deki yol ile gerçek imaj yolunun karşılaştırması) |
| envars | — | sırada (`COR_PROFILER` gibi değişkenler process başına; parola taşıyan değişkenler maskelenmeli) |
| mutantscan | `objects` | var |
| ssdt, callbacks, driverirp, modscan, timers | — | **dışı: çekirdek belleği; kullanıcı kipinden okunamaz** |
| hashdump, lsadump, cachedump | — | **dışı: parola özetleri** |

### plaso ayrıştırıcıları

| Ayrıştırıcı | winspect | Durum |
|---|---|---|
| winevtx, winlnk, winprefetch, recycler, usnjrnl, mft, winjob | var | var |
| esedb: srum, msie_webcache | `srum`, `webcache` | var |
| sqlite: chrome / firefox geçmişi, windows_timeline | `browser`, `activities` | var |
| winreg: amcache, appcompatcache, bam, bagmru, mrulist, userassist, usb, run, services, task_scheduler, terminal_server, typedurls, officemru, networks | var | var |
| winpca, setupapi, olecf / automatic_destinations | `pca`, `setupapi`, `jumplist` | var |
| windefender_history | `detections` | yeni |
| winreg: shutdown | `boots` (olay günlüğünden), `sysinfo` | yeni / var |
| esedb: user_access_logging, file_history | — | sırada |
| text: winfirewall, teamviewer, sccm, iis | — | sırada (plaso'da hepsinin test verisi var) |
| sqlite: windows_push_notification, eventtranscript | — | sırada |
| winreg: mountpoints, network_drives, winrar, ccleaner, outlook | kısmen (`mru`, `usb`) | sırada |
| chrome_cookies, firefox_cookies, chrome_autofill | — | **dışı: gizli veri** |

### winPEAS denetimleri

| Denetim | winspect | Durum |
|---|---|---|
| UAC, LSA koruması, WDigest, Credential Guard, AlwaysInstallElevated, AutoLogon (yalnızca "var"), LLMNR, SMB imzalama, PowerShell günlükleme | `posture` | var |
| tırnaksız servis yolu | `services` | var |
| WSUS HTTP, port yönlendirme, gizli hesap | `posture` | yeni |
| yazılabilir servis ikilisi / klasörü, `PATH` içindeki yazılabilir klasör | — | sırada (DACL altyapısı `secinfo`'da hazır) |
| LAPS, önbelleğe alınmış oturum sayısı, AppLocker ilkesi | — | sırada |
| kayıtlı parolalar (GPP, Wi-Fi, tarayıcı, kimlik bilgisi yöneticisi) | — | **dışı: parola okunmaz** |

---

## 3. Yol haritası (öncelik sırasıyla)

Sıralama ölçütü: *değer × doğrulanabilirlik*. Gerçek veriyle sınanamayan bir
ayrıştırıcı yazmak, bu projede "doğrulanmamış bayrak" eklemekle aynı şeydir.

| # | İş | Neden önce | Doğrulama kaynağı |
|---|---|---|---|
| 1 | `volumes`: birim seri numaraları, dosya sistemi, etiket | `lnk` ve `prefetch` çıktısındaki seri numaralarını bir sürücüye bağlar | wine'da çalışır |
| 2 | Denetim ilkesi (`auditpol` eşdeğeri) | `logons` boşsa nedenini söyler | gerçek Windows (CI) |
| 3 | Yazılabilir servis ikilisi ve `PATH` klasörü | en yaygın yetki yükseltme yolu | wine + CI |
| 4 | Güvenlik duvarı günlüğü, TeamViewer günlüğü | uzaktan erişim izleri; metin dosyası | plaso test verisi |
| 5 | User Access Logging (SUM) | sunucularda aylar geriye giden erişim kaydı | plaso test verisi |
| 6 | PuTTY / WinSCP bağlanılan sunucular (parolasız alanlar) | yanal hareket | wine (kayıt defteri) |
| 7 | StartupInfo XML, .NET UsageLogs | çalıştırma kanıtı | gerçek örnek gerek |
| 8 | Kerberoasting (4769), ETW oturumları | günlük analizi | EVTX-ATTACK-SAMPLES |
| 9 | Kalan 9 kalıcılık noktası | tamlık | wine (kayıt defteri) |
| 10 | `.sdb` içeriğini ayrıştırma | shim'in **ne yaptığını** (DLL enjeksiyonu mu?) gösterir | gerçek `.sdb` gerek |
| 11 | CryptnetUrlCache | `certutil` ile indirme kanıtı | gerçek örnek gerek |
| 12 | Office şablon enjeksiyonu, makro varlığı | zip + deflate çözücü yazmayı gerektirir | büyük iş |

## 4. Bilerek yapılmayanlar

Bunlar eksik değil, **sınır**dır:

- **Parola, özet, bilet, çerez, belirteç**: okunmaz, yazdırılmaz. `hashdump`,
  `lsadump`, tarayıcı çerezleri, Wi-Fi anahtarları, GPP parolaları bu yüzden yok.
- **Bellek dökümü alma**: döküm, yukarıdakilerin hepsini içerir.
- **Yazma / düzeltme / karantina**: araç salt-okunurdur.
- **Çekirdek belleği**: kullanıcı kipinden okunamaz; sürücü yüklemek aracın
  doğasına aykırı.
- **İmza motoru (YARA)**: ayrı ve büyük bir proje; `hash --match` ve `capa`
  benzeri kural tabanlı denetimler bunun dar bir alt kümesini karşılıyor.
- **Kullanıcının yazdığı içerik** (Notepad sekmeleri, Recall, ekran görüntüleri).
