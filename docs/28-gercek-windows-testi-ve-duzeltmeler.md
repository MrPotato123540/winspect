# 28 — Gerçek Windows testi: yanlış alarmlar ve düzeltmeler

Wine testleri bir komutun **çökmediğini** ve elle kurduğumuz örneklerde doğru
cevap verdiğini gösterir. Gerçek bir makine ise başka bir şey gösterir:
Windows'un kendi, sıradan davranışının araca nasıl göründüğünü. Bu bölüm,
gerçek bir Windows 11 (Türkçe) makinesinde çalıştırılan testin sonuçlarını,
bulunan yanlış alarmları ve düzeltmelerini anlatır.

İlke değişmedi (bkz. bölüm 25): **her [!] bir gerekçe taşır ve o gerekçe
sıradan bir makinede doğru olmamalıdır.** Aşağıdaki her madde bu ilkeye
aykırı düşen bir durumdu.

## 1. `triage explorer`: "fothk" bölümü (puan 85)

**Ne görüldü:** explorer.exe'nin bellekteki kodu diskteki dosyayla
karşılaştırılınca `fothk` adlı bölümde 4 bayt fark çıktı ve "kod
değiştirilmiş" sayıldı.

**Neden yanlış:** Windows 11 24H2 ile gelen `fothk` ("function override
thunks") bölümünü **Windows yükleyicisi** her süreçte, program başlarken
yazar. Yani bu bölüm diskteki halinden *her zaman* farklıdır; fark bir
saldırının değil, yükleyicinin izi.

**Düzeltme:** `patch_loader_written_section()` bu bölümleri tanır;
karşılaştırma onları atlar ve çıktıda açıkça söyler:
`not compared: fothk (written by the Windows loader in every process)`.
JSON'da `skipped_sections` alanı sayıyı verir. Atlanan bölüm gizlenmez,
"karşılaştırılmadı" diye yazılır: okuyucu neyin kontrol edilmediğini bilir.

## 2. `hunt`: csrss / wininit / winlogon "beklenmeyen ebeveyn"

**Ne görüldü:** Yönetici olmadan çalışınca bu üç sistem sürecinin ebeveyni
`svchost` göründü.

**Neden yanlış:** Bu süreçleri `smss.exe`'nin geçici bir kopyası başlatır ve
o kopya hemen çıkar. Çıkan sürecin PID numarası daha sonra başka bir sürece
(burada bir svchost'a) verilir: **PID yeniden kullanımı**. Yönetici
olmayınca sistem süreçlerinin başlama zamanı okunamıyordu, bu yüzden araç
"bu ebeveyn çocuğundan sonra mı doğdu?" kontrolünü yapamıyordu.

**Düzeltme:** Başlama zamanları, yetki istemeyen
`NtQuerySystemInformation(SystemProcessInformation)` çağrısından dolduruluyor
(`CreateTime` alanı). Ebeveyn ancak (a) iki zaman da biliniyorsa ve (b)
ebeveyn çocuktan önce başlamışsa kabul ediliyor. Bilinmiyorsa ebeveyn
"yok" sayılır; yanlış bir ebeveyn uydurulmaz.

## 3. `autoruns`: NVIDIA ve Microsoft uyumluluk düzeltmeleri

- **Servis FailureCommand:** NVIDIA servisinin "çökünce çalıştır" komutu,
  komut satırının *herhangi bir yerinde* kullanıcı-yazılabilir bir yol
  geçtiği için işaretleniyordu. Artık `asep_command_target()` komut
  satırının **gerçekten çalışacak dosyasını** buluyor (rundll32 /
  regsvr32'nin DLL'i, `cmd /c` sonrasındaki ilk yol, PowerShell'in `-File`
  değeri, wscript / cscript / mshta'nın betiği) ve yalnız o dosya
  kullanıcı-yazılabilir yerdeyse işaretliyor.
- **Shim veritabanı (T1546.011):** `%windir%\AppPatch\CustomSDB\` altındaki
  `{22221111-1111-1111-1111-111111111111}.sdb`, Microsoft'un kendi
  "Application Compatibility Fix Database"idir; Windows Update kurar.
  Bu GUID **ve** bu yol birlikte görülünce işaretlenmiyor, açıklaması
  yanına yazılıyor. Bu veritabanını kullanan programlar da (`Custom\<program>`)
  "Microsoft compatibility fixes" olarak gösteriliyor. Başka her shim
  veritabanı eskisi gibi işaretli.

## 4. `capability`: 61 işaret

**Ne görüldü:** Mikrofon / kamera kullanan, `AppData` altına kurulmuş
imzalı programlar (Discord, Teams, Zoom gibi) işaretleniyordu.

**Neden yanlış:** Bu programlar kullanıcı başına kurulur; `AppData` onların
normal yeridir. "Kullanıcı-yazılabilir klasör" tek başına şüphe değil.

**Düzeltme:** Canlı çalışırken her masaüstü programın **imzası**
kontrol ediliyor (yeni `signature` sütunu: signed / UNSIGNED / gone).
İşaret ancak şu durumlarda:
- imzasız ve kullanıcı-yazılabilir klasörde, ya da
- imza bilinmiyorsa (hive dosyası, program silinmiş) Temp, Downloads,
  Public veya Geri Dönüşüm Kutusu altında.

## 5. `logons`: "YEREL" kaynak adresi

Konsol oturumunda Windows adres alanına `LOCAL` sözcüğünü yazar; Türkçe
Windows'ta bu **çevrilir** ve `YEREL` olur. Araç bunu bir kaynak adı sanıyordu.
Artık adres yalnız bir IP adresiyse (IPv4 ya da IPv6) kaynak sayılıyor.

## 6. `boots`: "? tarafından istendi" ve 209 saat değişikliği

- **1074 (kapatma isteği):** Güncel Windows bu olayın dizgilerini
  `<Data Name="param1">` … `param7` olarak yazar; eski günlüklerde adsız
  `<Data>` vardı. Araç adsızları arıyordu, bu yüzden süreç ve hesap "?"
  çıkıyordu. Artık `evt_data_pos()` dizgileri **sırayla** okuyor; adlı
  ya da adsız fark etmiyor.
- **Saat değişikliği (Kernel-General 1):** Olayın bir `Reason` alanı var.
  `1` = "bir uygulama ya da sistem bileşeni saati değiştirdi". Diğer
  değerler Windows'un kendi ayarları: bir dizüstü uykudan her uyandığında
  saati ileri alır. 209 değişikliğin büyük çoğunluğu buydu.
  Artık **geri alınan her değişiklik** ve **bir uygulamanın yaptığı her
  değişiklik** listeleniyor; Windows'un kendi ileri ayarları sayılıyor ve
  gizleniyor (`--all` hepsini gösterir). Özet satırı kaç tanesinin
  gizlendiğini söyler. CSV / JSON'da `clock_reason` var.
- **Süre ifadesi:** "up 3d" yazısı makinenin 3 gün açık kaldığı izlenimini
  veriyordu; oysa bu açılış ile kapanış arasındaki **duvar saati** süresidir
  ve uykuyu içerir. Yazı artık bunu açıkça söylüyor.

## 7. `dns`: "önbellek boş"

Güncel Windows 11 sürümleri DNS önbelleğini yönetici olmayanlara vermiyor
(`ipconfig /displaydns` da "yükseltme gerekiyor" diyor). Araç bunu "önbellek
boş" diye raporluyordu. Artık erişim reddi "run as administrator" olarak,
belirsiz durum da hata koduyla ve olası nedenleriyle yazılıyor.

## 8. `usn`: uygulama takma adları ve tekrar eden silmeler

- `...\Microsoft\WindowsApps\python.exe` gibi dosyalar **uygulama
  çalıştırma takma adlarıdır**: kod içermeyen, Windows'un yeniden
  oluşturduğu *reparse point*'ler (öznitelik `0x400`). Silinmeleri artık
  işaretlenmiyor.
- Bir güncelleyicinin her seferinde yeniden oluşturup sildiği bir DLL
  (testte Intel DSA'nın `rules-verify.dll`'i, 4 kez) artık **bir kez**,
  son silinişinde, "(N times in this journal ...)" notuyla işaretleniyor.
  Böylece gürültü azalıyor ama bilgi kaybolmuyor.

## 9. `wer`: "praid:App"

Mağaza uygulamalarının çökme raporları program adı olarak paket içi bir
kimlik (`praid:App`) yazar. Artık bunun yerine program yolunun dosya adı
gösteriliyor.

## İkinci tur: tekrar testten çıkanlar

Düzeltilmiş sürüm aynı makinede yeniden çalıştırıldı. Sonuç: triage'da
`fothk` atlandı (puan 85 → 40), hunt 0 bulgu, capability 0 işaret
(23 imzalı, 82 silinmiş program), boots'ta süreç / hesap doğru ve 209 saat
ayarı gizlendi, usn'de `rules-verify.dll` tek satır "(4 times ...)" oldu.
Yeni bulunanlar ve düzeltmeleri:

- **dns yönetici olarak da okunamadı.** `DnsGetCacheDataTable` bu Windows
  11 sürümünde (24H2, build 26100) yöneticiye bile hata kodu vermeden
  FALSE döndürüyor; `ipconfig /displaydns` ise önbelleği gösteriyor. Artık
  bu durumda önbellek WMI üzerinden okunuyor:
  `ROOT\StandardCimv2` → `MSFT_DNSClientCache` sınıfı. Bu, PowerShell'in
  `Get-DnsClientCache` komutunun kullandığı kaynaktır. Başlık satırı hangi
  yolun kullanıldığını söyler.
- **`triage explorer` çalışmadı**, çünkü komut yalnız PID alıyordu. Artık
  tek bir süreçle çalışan bütün komutlar (`triage`, `verify`, `inspect`,
  `modules`, `threads`, `regions`, `token`, `handles`, `net`) süreç **adı**
  da alıyor: `explorer` ya da `explorer.exe`. Aynı adla birden fazla süreç
  varsa araç tahmin etmez; PID'leri listeler ve birini seçmeni ister.
- **Türkçe karakterler bozuk çıktı** ("ba┼şlat"). Bu araçtan değil,
  Windows PowerShell 5.1'in `>` yönlendirmesinden kaynaklanıyor: PowerShell
  programın UTF-8 çıktısını konsolun eski kod sayfasıyla (Türkçe'de 857)
  okuyup yeniden kodluyor. Yeni genel seçenek `--out <dosya>` çıktıyı
  dosyaya doğrudan UTF-8 olarak yazar. Var olan bir dosyanın üzerine
  yazmaz (önceki bir sonuç kaybolmasın diye).
- **Defender'ın kendi klasörü.** `ProgramData\Microsoft\Windows Defender`
  altı yalnız SYSTEM ve yöneticilere yazılabilir; orada silinen
  `mpengine.dll` yedeği Defender'ın güncellemesidir. Bu klasörler artık
  "kullanıcı-yazılabilir" sayılmıyor.
- **usn özetinde sayılar.** `--find` ile 8 satır gösterilirken "3
  flagged" yazıyordu: sayı bütün günlüğe aitti. Artık sayı gösterilen
  satırlar içindendir; günlüğün tamamındaki sayı farklıysa ayrıca yazılır.
- **wer'de aynı çökme iki kez.** Windows bir çökme için birden fazla rapor
  klasörü yazabiliyor. Metin görünümünde zamanı, programı, hata modülü ve
  kodu aynı olan raporlar tek satırda, "(2 report folders)" notuyla
  gösteriliyor. JSON ve CSV her klasörü ayrı tutar.
- **Silinen dosya $MFT'de bulunamadı, usn'de bulundu.** `deneme_sil.txt`
  silindikten birkaç saniye sonra `mft --deleted` onu göstermedi. NTFS boşalan
  kayıt numarasını hemen başka bir dosyaya verebilir; dosya adı da o zaman
  kaybolur. Bunu kanıtlamak için iki yardım eklendi: `usn --find` her satıra
  dosyanın **kayıt numarası ve sıra numarasını** (sequence) ekliyor;
  `mft --record <n>` da o kaydın **şu an** ne tuttuğunu gösteriyor. Kayıtta
  başka bir ad ya da daha büyük bir sıra numarası varsa kayıt yeniden
  kullanılmıştır. Bu durumda değişiklik günlüğü (usn), silinen dosyanın tek
  tanığıdır.

## Gerçek bulgu: Excel'de VBAWarnings = 1

`office` komutunun işaretlediği `VBAWarnings=1` bir yanlış alarm **değil**:
bu ayar Excel'de **tüm makroların uyarı vermeden çalışması** demektir
(Güven Merkezi → "Tüm makroları etkinleştir"). Kötü amaçlı belgeler için en
yaygın kapılardan biridir. Bilerek açılmadıysa 2'ye ("bildirimle devre dışı")
geri almak önerilir.

## Dersler

1. Bir alanın *varlığı* değil, *anlamı* önemlidir: `fothk` farkı, `YEREL`
   adresi, `Reason=2` saat ayarı — hepsi "beklenmeyen" görünen ama sıradan
   olan değerlerdi.
2. Konum tek başına şüphe değildir; imza, içerik ve bağlam ile birleşince
   anlamlıdır.
3. Bilinmeyen değer "kötü" sayılmaz: zaman bilinmiyorsa ebeveyn kurulmaz,
   imza bilinmiyorsa daha dar bir kural uygulanır.
4. Gizlenen her şey **sayılır ve söylenir** (`--all`, "not compared").
