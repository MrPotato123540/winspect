# 23 — NTFS $MFT ve USN günlüğü: dosya kayıtları, silinmiş dosyalar, değişiklik geçmişi

NTFS her dosyanın kaydını **Master File Table**'da (`$MFT`) tutar. Dosya
silinse bile kaydı, üzerine yazılana kadar orada kalır. `mft` komutu,
toplama araçlarıyla kopyalanmış ya da bağlanmış bir imajdan alınmış bir
`$MFT` dosyasını okur. Canlı `$MFT` dosya olarak açılamaz.

```
winspect mft E:\toplama\$MFT --find Downloads
winspect mft $MFT --deleted --csv > silinenler.csv
winspect mft $MFT --timestomp
```

## Kayıt yapısı (`src/mft.c`)

- **Kayıt** (genellikle 1024 bayt), `FILE` imzasıyla başlar.
- **Fixup dizisi:** NTFS her 512 baytlık sektörün son iki baytını bir diziye
  taşır, yerlerine "güncelleme sıra numarası"nı yazar. Okurken geri konur.
  Bir sektörün sonu bu numarayı taşımıyorsa kayıt yarım yazılmıştır ve atlanır.
- **Başlık:** sıra numarası, ilk özniteliğin yeri, bayraklar (kullanımda mı,
  klasör mü), "uzantı kaydı" mı.
- **Öznitelikler:**

| Tip | Ad | Okunan |
|---|---|---|
| `0x10` | `$STANDARD_INFORMATION` | oluşturma, değiştirme, MFT değişikliği, erişim |
| `0x30` | `$FILE_NAME` | ebeveyn referansı, aynı dört zaman, boyut, ad (Win32 ad 8.3 DOS adına tercih edilir) |
| `0x40` | `$OBJECT_ID` | Dağıtık Bağlantı İzleme kimliği; sürüm-1 UUID ise oluşturma zamanı ve makinenin MAC'i |
| `0x80` | `$DATA` | gerçek boyut |

### Yol kurma ve $Orphan

Yol, `$FILE_NAME`'deki ebeveyn referansıyla köke (kayıt 5) kadar yürünerek
kurulur. Referans "kayıt no + sıra no"dur. Bir ebeveyn ancak hâlâ **o**
klasörse kabul edilir:

- sıra numarası aynıysa, ya da
- klasör sonradan silinmişse ve sıra numarası tam **bir fazlaysa**. NTFS bir
  kaydı serbest bırakırken numarayı artırır.

Kayıt başka bir dosyaya verilmişse (ör. artık klasör değil) zincir kopar ve
yol `$Orphan\...` ile başlar.

Bu kural plaso'nun beklediği yolla karşılaştırılarak bulundu. İlk sürüm
yalnızca "sıra numarası eşit mi" diye bakıyordu ve `$Orphan\menu.text.css`
üretti. plaso `$Orphan\session\menu.text.css` bekliyordu. İnceleme gösterdi
ki dosyadan sonra silinen `session` klasörünün sıra numarası tam bir artmış;
bir üstteki kayıt ise başka bir dosyaya verilmiş.

## Timestomping: neden bulgu değil, aday listesi?

`$STANDARD_INFORMATION` zamanlarını herhangi bir program değiştirebilir
(`SetFileTime`). `$FILE_NAME` zamanlarını ise yalnızca çekirdek yazar.
"$SI oluşturma zamanı $FN'inkinden açıkça daha eski" durumu, dosyanın geriye
tarihlendirildiğinin klasik işaretidir.

Ama gerçek veri başka bir şey söyledi. plaso'nun Windows XP `$MFT`'sinde bu
kural 13 bin dosyanın **4312'sine** uydu. Neredeyse hepsi şunlardı:

- kurulum medyasından gelen sistem dosyaları (`WINDOWS\system32`, `inf`,
  `Help`): $SI'da derleme zamanını taşırlar;
- arşivlerden açılmış sürücü paketleri;
- "geçici dosyaya yaz, sonra değiştir" yöntemiyle kaydeden uygulamalar
  (NTFS asıl oluşturma zamanını korur).

"Tam saniye" ek koşulu da ayırt etmiyor: ZIP ve FAT zamanları zaten tam
saniyedir. Bu yüzden `mft` hiçbir dosyayı **işaretlemez**.

- `--timestomp` yalnızca adayları listeler.
- Her adayın yanında `timestomp_hint` notu vardır.

Analist bunu başka kanıtla, örneğin dosyanın yeri ve Prefetch/Amcache
zamanlarıyla birlikte değerlendirmelidir.

## Doğrulama

- **plaso'nun `test_data/MFT`'si** (yalnızca veri, sabit commit). plaso'nun
  NTFS testlerindeki şu değerlerle birebir aynı:
  - `\WINDOWS\system32\config\SAM`'ın yolu ve zamanı;
  - silinmiş `CAJA1S19.js`'nin tam yolu, "kullanımda değil" durumu ve zamanı;
  - sahipsiz `$Orphan\session\menu.text.css` ve zamanı;
  - 462. kaydın nesne kimliği: UUID, v1 zamanı 2007-06-30 12:58:40.5000041
    ve MAC `db:30:99:be:ae:3c`. Bunlar Python'da C kodundan bağımsız olarak
    da çözülür.
- Elle kurulmuş bir kayıtla birim testleri: fixup'ın geri konması, yarım
  yazılmış kayıt, Win32 adın DOS adına tercih edilmesi, ebeveyn, boyut.
- Gerçek kayıtların bozulmuş kopyalarıyla ASan/UBSan fuzz (fixup dizileri,
  öznitelik boyları, döngüye giren ebeveyn referansları): 375 bin kayıt,
  bulgu yok.
- wine'da uçtan uca: `--find`, `--deleted`, `--csv`, `--timestomp`.

## usn — değişiklik günlüğü ($UsnJrnl:$J)

NTFS, birimdeki her dosya değişikliğini `$Extend\$UsnJrnl` dosyasının `$J`
akışına yazar: oluşturma, silme, yeniden adlandırma (eski ve yeni ad ayrı
kayıtlar), veri değişikliği, güvenlik değişikliği. `$MFT` bir dosyanın **şu
anki** hâlini söyler; USN günlüğü **ne olduğunu** sırayla anlatır. Silinmiş ve
çoktan üzerine yazılmış bir dosyanın adı bile burada kalabilir.

Kayıt biçimi Microsoft'un belgelediği `USN_RECORD_V2` / `V3` yapılarıdır
(`src/usn.c`):

```
uzunluk | sürüm | dosya referansı | ebeveyn referansı | USN | zaman | neden bitleri | ... | ad
```

Kopyalanmış bir `$J` çoğunlukla başta gigabaytlarca sıfırdan oluşur (seyrek
dosya). Okuyucu sıfır bölgelerini 8 baytlık adımlarla geçer. Bozuk bir
uzunluk görürse de bir sonraki geçerli kayda yeniden hizalanır.

`--mft` ile aynı birimin `$MFT` kopyası verilirse, her kaydın ebeveyn
referansı oradan klasör yoluna çevrilir. Sıra numarası kontrol edilir; klasör
kaydı başka bir şeye verilmişse yol uydurulmaz, "reused or missing" yazılır.

İşaretler (`usn_flag`, birim testli):

| Gerekçe | Ne zaman |
|---|---|
| program or script deleted | `FILE_DELETE` ve ad bir program/betik |
| renamed into a program or script | `RENAME_NEW_NAME` bir program adı, aynı dosyanın `RENAME_OLD_NAME`'i değil (ör. `fatura.pdf` → `fatura.exe`) |

Eski ve yeni ad, dosya referansıyla eşleştirilir.

**Doğrulama:**

- plaso'nun `UsnJrnl.raw`'ı: **19 kayıt** (plaso'nun aynı birimden yaptığı
  testteki sayı) ve ilk kayıt ("Nieuw - Tekstdocument.txt", FILE_CREATE,
  2015-11-30 21:15:27.2031250) plaso'nun beklediğiyle aynı. Ayrıca her kayıt,
  Microsoft'un yapı tanımından Python'da ayrıca yazılmış bir çözücüyle
  karşılaştırılır.
- Birim testleri: seyrek sıfırların arkasında V2 ve V3 kayıtları, bozuk
  uzunluktan sonra yeniden hizalanma, neden adları, işaret kuralları.
- Sanitizer fuzz (`fuzz_parsers`).
- wine'da: test için yazılmış küçük bir `$MFT` ve `$J`
  (`tests/wine/ntfswrite.py`). Bunlarda `fatura.pdf → fatura.exe` ve silinen
  `tool.ps1` işaretli; `notes.txt` işaretsiz; klasör yolları MFT'den geliyor;
  ebeveyni olmayan kayıt "reused or missing" gösteriyor.

Bu sırada `mft` / `usn` daha dayanıklı oldu. Kayıt boyutu artık 0. kayıttan
değil, ilk 64 KB içindeki ilk geçerli `FILE` kaydından bulunuyor; başı bozuk
bir kopya geri kalanını gizlemiyor.

### Canlı makinede: mft --live C:

`$MFT` çalışan sistemde kilitli olduğu için normal dosya gibi kopyalanamaz.
`--live`, birimi `\\.\C:` olarak **salt-okunur** açar (yönetici hakkı
gerekir) ve dosyayı kendi yapısından bulur:

1. Önyükleme kesimi (ilk 512 bayt): `NTFS    ` imzası, kesim ve küme boyutu,
   `$MFT`'nin başladığı küme (LCN) ve kayıt boyutu (`ntfs_parse_boot`).
2. O kümedeki ilk kayıt `$MFT`'nin kendisidir. Düzeltme dizisi uygulanır ve
   `$DATA` özniteliğinin veri dizileri (data runs) çözülür
   (`mft_data_runs`): her dizi bir uzunluk ve öncekine göre işaretli bir
   küme farkı taşır; farkı olmayan dizi seyrek (sparse) kabul edilir.
3. Diziler sırayla, kesim hizalı 1 MB parçalarla okunur ve kopya dosyadaki
   ile **aynı** ayrıştırma döngüsünden geçer.

Sınır: `$MFT`'nin `$DATA`'sı bir öznitelik listesine bölünmüşse (çok parçalı,
çok büyük birimlerde olabilir) yalnızca ilk kayıttaki diziler okunur; bu
durumda sonuç eksik kalabilir, yanlış olmaz.

Birim hiçbir zaman yazma için açılmaz. wine'da `C:` bir NTFS birimi olmadığı
için komut "is not an NTFS volume" diye temiz çıkar. Windows CI'da gerçek
deneme: oluşturulup silinen bir dosya kullanımda olmayan kayıt olarak tam
yoluyla, tutulan dosya ise kullanımda olarak görünmelidir (henüz gerçek koşu
görmedi). Çözücüler plaso'nun `MFT` dosyasıyla doğrulandı: 0. kaydın 4 dizisi
6544 küme × 2048 bayt = 13 402 112 bayt verir, bu da dosya boyutunun aynısı.

### Canlı makinede: usn --live C:

Kopya almaya gerek yok: Windows günlüğü belgelenmiş, salt-okunur denetim
kodlarıyla verir (yönetici hakkı gerekir):

- `FSCTL_QUERY_USN_JOURNAL`: günlüğün kimliği ve ilk kaydı,
- `FSCTL_READ_USN_JOURNAL`: kayıtlar, kopyalanmış `$J` ile **aynı**
  `USN_RECORD` biçiminde (aynı `usn_next` ayrıştırıcısından geçer),
- `FSCTL_ENUM_USN_DATA`: birimdeki her dosyanın numarası, ebeveyni ve adı.
  Bundan klasör tablosu kurulur ve her kaydın tam yolu çıkarılır.

İstek yapıları belgelenmiş V0 düzeniyle kodda tanımlıdır, çünkü SDK'lar bunlara
farklı adlar veriyor (`READ_USN_JOURNAL_DATA` / `..._V0`).

wine bu denetim kodlarını desteklemiyor; komut "no change journal" diye temiz
çıkar. Windows CI'da gerçek bir deneme yapılır: `.txt` → `.exe` yeniden
adlandırılan dosya ve silinen bir `.ps1` canlı günlükte işaretli ve klasörüyle
görünmelidir (henüz gerçek koşu görmedi).
