# 18 — Kıyas turu: esin kaynağının yaptığı vs bizim yaptığımız

Bu turda her komutu, fikrini aldığı araçla yan yana koyup üç soru sorduk:

1. O araç bu konuda neyi gösteriyor?
2. Bizde eksik olan ne?
3. Eksiği kapatınca nasıl doğrularız?

Kurallar değişmedi:

- Sadece **kavram** alınır, kod kopyalanmaz.
- Her şey salt-okunurdur.
- Her işaretin bir gerekçesi (`reason`) vardır.

Karşılaştırma iki gerçek hata çıkardı (aşağıda **hata** diye işaretli). Bu turun
en değerli sonucu da bu oldu.

## autoruns ↔ Sysinternals Autoruns

| Autoruns'ta var | Önce bizde | Şimdi |
|---|---|---|
| AppCertDlls, cmd.exe AutoRun, logon script (`UserInitMprLogonScript`) | yoktu | var; Windows bunları hiç yazmaz, girdi olması başlı başına "nadir konum" |
| Active Setup `StubPath` | yoktu | var; meşru kullanımı çok, yalnızca kullanıcının yazabildiği yol işaretlenir |
| W32Time zaman sağlayıcıları | yoktu | var; stok değerler (`w32time.dll`, `vmictimeprovider.dll`, System32 altında) dışındakiler işaretlenir |
| Ekran koruyucu (`SCRNSAVE.EXE`) | yoktu | var |
| "Hijacks": `exefile\shell\open\command` | yoktu | var; stok değer `"%1" %*`, farkı işaretlenir |
| HKCU `ms-settings` / `exefile` handler'ları | yoktu | var; belgelenmiş UAC atlatma örüntüsü (T1548.002), Windows HKCU'da bunları oluşturmaz |
| "Office test" anahtarı (T1137.002) | yoktu | var |
| Sarı "File not found" satırları | `--sig` sadece "unresolved" diyordu | yol çözüldü ama dosya yoksa `missing` + "image file not found" |

Stok değer kontrolleri (`asep_exefile_default`, `asep_time_provider_default`)
taşınabilir koddadır ve birim testlidir. Her yeni konum için wine'da bir
pozitif fixture vardır. Stok değerler (`w32time.dll`, `"%1" %*`) için de
negatif kontrol bulunur.

## lnk / jumplist ↔ LECmd / JLECmd

LECmd, hedef yolun yanında kısayolun **nerede ve hangi makinede** oluştuğunu da
gösterir. Bizde bu yoktu. Eklenenler:

- **VolumeID:** sürücü tipi (`removable` = USB bellek), seri numarası, etiket.
- **Ağ paylaşımı:** `\\sunucu\paylaşım\...` hedefleri; önceden yalnızca
  sonek görünüyordu.
- **TrackerDataBlock:** kısayolun oluşturulduğu makinenin NetBIOS adı. "Droid"
  GUID'i sürüm-1 UUID ise son 6 baytı o makinenin **MAC adresidir** (RFC 4122).
- **EnvironmentVariableDataBlock:** `%windir%\...` biçimindeki hedef.

**Hata — gizlenmiş komut satırı.** LnkParse3 projesinin örneklerinden biri,
çalışma dizininin karakter sayısını 1693 yazıyor. Kabuk ise bu alanı en fazla
260 karakter okuyup sonraki alana geçiyor. Gerçek argümanlar tam 260.
karakterde başlıyor. Sayıya güvenen ayrıştırıcımız komutu **hiç görmüyordu**.

Artık NAME, RELATIVE_PATH ve WORKING_DIR alanları 260 karakterde kesiliyor.
Bu hile (`string count > 260`) ve komutu boşluklarla görünmez kılma (`padding`)
ayrıca işaretleniyor. `lnk`, `jumplist` ve autoruns'un Startup kısayolları aynı
gerekçeyi kullanıyor.

**Doğrulama:** 34 gerçek dünya örneğinde (bir kısmı kötü amaçlı) bağımsız
ayrıştırıcının beklenen çıktısıyla alan alan karşılaştırıldı. İlk turda 1 fark
(yukarıdaki hata) çıktı, düzeltmeden sonra 34/34 eşleşti. Ayrıca:

- elle kurulmuş birim testleri (260 sınırı, dolgu, VolumeID, tracker,
  sürüm-4 UUID'de MAC yok, taşan blok),
- yeni bloklarla zenginleştirilmiş tohumla 500 bin ASan/UBSan fuzz turu,
- wine'da USB'deki bir kısayolun makine adı, MAC ve gizli komutla raporlanması.

## prefetch ↔ PECmd

PECmd, programın **tam yolunu** dosyanın kendi referans listesinden bulur ve
şüpheli dizinleri vurgular. Bizde yalnızca `EVIL.EXE` adı vardı. Eklenenler:

- `pf_exe_path`: referans listesinde son bileşeni exe adına eşit olan yolu
  bulur. Başlıktaki ad en fazla 29 karakter tutulduğu için 29 karakterlik
  adlarda önek eşleşmesi yapılır.
- Kullanıcının yazabildiği dizinden (Temp, Downloads, AppData, Public) çalışan
  program "ran from a user-writable dir" diye işaretlenir.
- Yalnızca işaretli programları göstermek için `--flagged`; `sweep` artık
  bunu da çalıştırıyor.

## hunt ↔ SANS "Hunt Evil" posteri

Posterde her çekirdek süreç için beş sütun var: ebeveyn, kopya sayısı, yol,
**hesap**, **başlama zamanı**. Bizde ilk üçü vardı. Eklenenler:

- **Hesap:** smss, csrss, wininit, winlogon, services, lsass ve lsaiso yalnızca
  `S-1-5-18` (SYSTEM) ile çalışır. Token okunamazsa (PPL lsass) hiçbir
  yargıda bulunulmaz.
- **Başlama zamanı:** wininit, services, lsass ve lsaiso açılışta bir kez
  başlar ve yeniden başlatılamaz. Açılıştan 15 dakika sonra başlamış bir kopya
  orijinal değildir. csrss ve winlogon bilerek dışarıda; her RDP oturumu yeni
  bir çift başlatır.

wine her süreci kullanıcı hesabıyla çalıştırdığı için oradaki `services.exe`
hesap kuralına gerçekten takılıyor. Bu kuralın doğru pozitifi; fixture bunu
bekliyor. Açılış zamanı kuralının mantığı birim testli. Açılış anının
hesaplanması (şimdi − GetTickCount64) ise gerçek Windows'ta henüz denenmedi.

## events ↔ Chainsaw / Hayabusa

Bu araçlar zaman aralığı ve "logon özeti" sunar. Eklenenler:

- `--since <saat>`: XPath'e `TimeCreated[timediff(@SystemTime) <= ms]`
  eklenir. Filtre metni taşınabilir `evt_xpath_since` ile kurulur ve birim
  testlidir.
- `--summary`: 4625 olayları kaynak adrese göre gruplanır; her kaynak için
  hata sayısı, farklı hesap sayısı (büyük/küçük harf duyarsız), ilk ve son
  zaman verilir. Tek kaynaktan 5 veya daha fazla farklı hesap "password
  spraying?", 10 veya daha fazla hata "password guessing?" diye işaretlenir.

wine'da olay günlüğü olmadığı için Windows CI şunu sınar: altı farklı hesap
adıyla bilerek başarısız oturum açılır ve özetin bunu "spraying" diye
işaretlemesi beklenir. Denetim politikası kapalıysa kontrol atlanır ve bu
açıkça yazılır.

## handles ↔ Sysinternals Handle / Process Explorer

**Hata — 16 bitlik tablo.** Komut eski `SystemHandleInformation` (16) sınıfını
kullanıyordu. Bu sınıfta PID ve handle değeri **16 bit**. 65535'ten büyük bir
PID başka bir süreçle karışır, 0xFFFF'ten büyük bir handle kırpılır; yanlış
handle çoğaltılıp yanlış nesne anlatılabilir. Artık genişletilmiş sınıf (64)
kullanılıyor; eskisi yalnızca yedek.

**Hata — okuma-yazma dosyalarının adı yoktu.** Asılmayı önlemek için erişim
değeri tam `0x0012019F` olan handle'lar hiç sorgulanmıyordu. Bu değer aslında
`FILE_GENERIC_READ | FILE_GENERIC_WRITE`, yani okuma+yazma açılmış **her
sıradan dosyanın** değeri. wine'da tutucu programla görüldü. Artık File
nesnelerinin adı ayrı bir iş parçacığında 200 ms zaman aşımıyla soruluyor.
Takılan iş parçacığı sonlandırılmıyor, yalnızca bırakılıyor; dörtten sonra
dosya adları hiç sorulmuyor.

**Yeni — `--find <metin>`:** "bu dosyayı / anahtarı / mutex'i kim açık
tutuyor?" sorusu için tüm süreçler aranır. `--type` ile tipe göre süzülebilir.

**Doğrulama:** `tests/holder.c` okuma+yazma bir dosyayı açık tutar ve bir
boruda senkron okumada bekler.

- wine'da: `--find` dosyayı doğru PID ile buluyor, `handles <pid>` dosyayı
  adlandırıyor ve asılmıyor.
- Aynı kontrol Windows CI'da gerçek boru semantiğiyle de koşacak; 60 sn
  zaman aşımı asılmayı hata sayar.

## Hâlâ eksik olanlar (bilerek ertelendi)

- **jumplist:** DestList (sıra, erişim zamanı, sabitleme) çözümü yok.
  AppID → program adı tablosu da yok; doğrulanmış bir kaynak gerekiyor.
- **shimcache:** Windows 8/8.1 biçimi ve "executed" bayrağı yok; güvenilir
  kaynak olmadan eklenmiyor.
- **userassist / mru / bam:** diğer kullanıcılar ve çevrimdışı hive desteği
  yok; bunun için bir NTUSER.DAT okuyucusu gerekiyor.
- **certstore:** Microsoft güvenilir kök listesiyle (AuthRoot CTL)
  karşılaştırma yok (sigcheck `-tv` fikri). Bunu yalnızca gerçek Windows
  doğrulayabilir.
- **Gerçek Windows:** bu turdaki Windows'a özgü kısımlar (hesap/açılış
  zamanı, events özeti, handles'ın gerçek borularda zaman aşımı) CI ilk kez
  koştuğunda doğrulanacak.
