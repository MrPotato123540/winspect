# 23 — NTFS $MFT: dosya kayıtları, silinmiş dosyalar, timestomping

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
