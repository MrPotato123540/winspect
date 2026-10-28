# 20 — Kullanıcı izleri: PowerShell geçmişi ve Geri Dönüşüm Kutusu

Bu belge, bir kullanıcının (ya da onun hesabını kullanan birinin) bilgisayarda
**ne yaptığını** gösteren düz dosya izlerini anlatır. İkisi de kayıt defteri
gerektirmez; dosyalar bir disk imajından kopyalanıp da okunabilir.

## pshistory — PSReadLine komut geçmişi

Windows 10 / PowerShell 5'ten beri PSReadLine modülü, etkileşimli konsolda
yazılan her komutu kullanıcı başına bir metin dosyasına ekler:

```
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

- Dosya pencere kapansa da, oturum kapansa da kalır. Bir saldırgan etkileşimli
  bir PowerShell açtıysa ilk bakılacak yerlerden biridir.
- Satırlar eskiden yeniye sıralıdır. Dosyanın son yazılma zamanı kabaca son
  komutun zamanıdır; tek tek satırların zamanı **yoktur**.
- Birden çok satıra yayılan komutlarda iç satırlar ters tırnakla (`` ` ``)
  biter; her satır ayrı numaralanır.
- Betik (`-File`) ya da `-Command` ile çalışan komutlar bu dosyaya **yazılmaz**.
  Dosyanın boş olması "PowerShell kullanılmadı" demek değildir.

```
winspect pshistory                  # kendi geçmişim
winspect pshistory --all-users      # C:\Users altındaki tüm profiller (yönetici)
winspect pshistory D:\imaj\PSReadLine --flagged --json
```

### Neler işaretleniyor

Kurallar taşınabilir `ioc_ps_reason` işlevindedir ve birim testlidir. Hepsi
belgelenmiş, iyi bilinen örüntülerdir (MITRE ATT&CK teknik adlarıyla):

| Gerekçe | Örnek ipucu | ATT&CK |
|---|---|---|
| encoded command | `-EncodedCommand`, ` -enc `, ` -ec `, `powershell … -e ` | T1027 |
| download cradle | `DownloadString`, `Net.WebClient`, `Start-BitsTransfer`, `iwr … \| iex` | T1105 |
| AMSI tampering | `AmsiUtils`, `amsiInitFailed` | T1562.001 |
| Defender weakened | `Set-MpPreference -Disable…`, `Add-MpPreference -ExclusionPath` | T1562.001 |
| credential dumping | `mimikatz`, `sekurlsa`, `comsvcs … MiniDump`, `lsass.dmp` | T1003 |
| log / history clearing | `Clear-EventLog`, `wevtutil cl`, `ConsoleHost_history` geçen satır | T1070 |
| execution policy bypass | `-ExecutionPolicy Bypass` | T1059.001 |
| Invoke-Expression | `iex(`, `\| iex`, `Invoke-Expression` | T1059.001 |
| persistence | `Register-ScheduledTask`, `schtasks /create`, `New-Service`, `sc create`, `…\CurrentVersion\Run` anahtarına yazma | T1053 / T1543 / T1547 |

Bu bir **ipucu listesidir**, karar değildir. Yöneticiler de `-ExecutionPolicy
Bypass` yazar. Gerekçe, analistin satıra neden bakması gerektiğini söyler.

**Doğrulama:** 13 birim testi (her kural için pozitif, sıradan komutlar için
negatif) ve wine'da indirme + Defender satırı içeren bir geçmiş dosyası;
sıradan iki satırın işaretlenmemesi de kontrol edilir.

## recyclebin — Geri Dönüşüm Kutusu

Bir dosya Geri Dönüşüm Kutusu'na atılınca Windows (Vista ve sonrası) iki dosya
yazar, ikisi de `<sürücü>:\$Recycle.Bin\<kullanıcı SID'i>\` altında ve aynı
rastgele ekle:

- `$R……` dosyanın içeriği,
- `$I……` küçük bir kayıt: orijinal tam yol, boyut, **silinme zamanı** (UTC).

`$I` biçimi:

| Ofset | Alan | v1 (Vista – 8.1) | v2 (Windows 10+) |
|---|---|---|---|
| 0 | sürüm (u64) | 1 | 2 |
| 8 | orijinal boyut (u64) | ✓ | ✓ |
| 16 | silinme zamanı (FILETIME) | ✓ | ✓ |
| 24 | yol | sabit 260 UTF-16 karakter | u32 uzunluk (NUL dahil), ardından yol |

Windows XP ise kullanıcı başına tek bir `RECYCLER\<SID>\INFO2` dizini tutardı:
20 baytlık başlık ve 800 baytlık kayıtlar (ANSI yol, sıra no, sürücü no,
FILETIME, boyut, UTF-16 yol). Kutudan çıkan kaydın ANSI yolunun ilk baytı
sıfırlanır; sürücü harfi sürücü numarasından geri kazanılır.

Neden önemli?

- **Kim, ne zaman, ne sildi:** SID klasörü sahibi verir (`LookupAccountSid`
  ile ada çevrilir), `$I` zamanı verir.
- **`content: gone`:** `$I` var ama `$R` yok. İçerik kutudan elle silinmiş,
  ama silme kaydı kalmış. Temizlik yapan biri genelde `$I` dosyalarını unutur.
- Silinen **program ve betikler** (`.exe .dll .ps1 .bat .vbs .js .hta …`)
  işaretlenir: saldırganın bıraktığı aracı silmesi bilinen bir temizlik
  adımıdır (T1070.004). Bu da bir ipucudur; kurulum dosyası silmek suçsuzdur.

```
winspect recyclebin                       # tüm yerel sürücüler (başkalarının klasörü: yönetici)
winspect recyclebin E:\imaj\$Recycle.Bin  # kopyalanmış bir kutu
winspect recyclebin '$IAB12CD.exe' --json # tek bir kayıt
```

**Doğrulama:**

- Ayrıştırıcı taşınabilir koddadır (`rb_parse_i`, `rb_info2_*`); yaklaşık 30
  birim testi: v1/v2, kesik dosya, yanlış uzunluk, bilinmeyen sürüm, boşaltılmış
  INFO2 kaydı.
- plaso projesinin test verisindeki üç gerçek dosya (Vista `$I`, Windows 10
  `$I`, XP `INFO2`) yalnızca **veri** olarak indirilir; plaso'nun kendi
  testlerinde yazan yol, boyut ve zamanlarla karşılaştırılır (CI'da, sabit
  commit'e iğnelenmiş). Dört INFO2 kaydı dahil hepsi eşleşti.
- ASan/UBSan altında 300 bin fuzz turu.
- wine'da: bir kullanıcının kutusunda içeriği duran bir v2 program kaydı
  (işaretli) ve içeriği gitmiş bir v1 belge kaydı (işaretsiz).
