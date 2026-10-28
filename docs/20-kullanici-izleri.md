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
