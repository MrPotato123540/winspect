# 15 — DFIR artefaktları: kalıcılık, nesneler, Defender, USB, Prefetch

Bu dalga (Z1–Z5), winspect'i "şu an ne çalışıyor?" sorusunun ötesine, olay
müdahalesinin (DFIR) klasik sorularına taşır: *ne başlangıçta çalışacak, sistem
neyi taramıyor, hangi USB takıldı, hangi program çalıştı?* Kavramlar Autoruns,
WinObj, Get-MpPreference, USBDeview ve PECmd/libscca'dan alındı; kod tamamen
sıfırdan, hepsi **salt-okunur**.

---

## Z1. autoruns genişlemesi

Run/RunOnce ve Winlogon'a ek olarak artık şunlar da taranıyor:

| Konum | Neden önemli |
|---|---|
| `Policies\Explorer\Run` (HKLM/HKCU) | Normal Run'dan ayrı, daha az bakılan ikinci bir Run listesi |
| IFEO `Debugger` (+Wow6432Node) | Bir exe başlatılınca yerine "debugger" olarak başka program çalışır |
| `SilentProcessExit` `MonitorProcess` | Bir process kapanınca başka bir program tetiklenir |
| `AppInit_DLLs` (+WOW64) | user32 yükleyen her process'e DLL yüklenir (eski ama bilinen) |
| Startup klasörleri | Kullanıcı ve tüm kullanıcılar için `...\Start Menu\Programs\Startup` |

**Sağlamlık düzeltmesi:** Registry'den okunan `REG_SZ` verisinin NUL ile bitmesi
garanti değildir. Okuma tamponunun son 2 baytını ayırıp elle NUL koyuyoruz; boş
değerleri atlıyoruz. Bu, bozuk/kasıtlı uzun değerlerde taşmayı önler.

## Z2. objects — isimli kernel nesneleri

Bir mutex, event, section ya da semaphore **isimle** oluşturulduğunda Object
Manager'ın bir dizininde görünür (`\Sessions\<N>\BaseNamedObjects`, global için
`\BaseNamedObjects`). Zararlılar çoğu zaman "ikinci kopya çalışmasın" diye özgün
isimli bir mutex açar ve bu isimler IOC olarak yayımlanır.

- `NtOpenDirectoryObject` (yalnızca `DIRECTORY_QUERY`) + `NtQueryDirectoryObject`.
- Döngü sözleşmesi: `RestartScan` sadece ilk çağrıda, `Context` çağrılar arasında
  taşınır, `STATUS_NO_MORE_ENTRIES` gelince biter.
- Nesnelerin kendisi **asla açılmaz**, sadece isim ve tip okunur.

```
winspect objects --type Mutant
winspect objects --global --json
winspect objects "\RPC Control"
```

## Z3. defender — dışlamalar ve "kapatma" politikaları

Defender dışlamaları registry'de, her türün ayrı anahtarında, **değer adları**
olarak tutulur (veri sadece DWORD 0):

- Yerel: `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,Extensions,Processes,IpAddresses}`
- Group Policy: `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\...`

Yönetici yetkisi ele geçiren saldırgan sık sık kendi klasörünü dışlar; bu yüzden
liste gözden geçirmeye değer. Ayrıca `DisableAntiSpyware`,
`DisableRealtimeMonitoring` gibi politika anahtarları `[PROTECTION OFF]` diye
işaretlenir.

**Dürüst çıktı:** Windows 10'dan beri yerel Exclusions anahtarlarını sadece
yöneticiler okuyabilir. Erişim reddedilirse liste "boş" gösterilmez — açıkça
"access denied, run elevated" denir (JSON'da `"access_denied":true`). Boş liste
göstermek yanıltıcı olurdu.

## Z4. usb — USB depolama geçmişi

`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\<seri>`
cihaz çıkarıldıktan sonra da kalır. Vendor/product/revision cihaz id'sinden,
seri numarası alt anahtar adından, `FriendlyName` değerinden okunur.

- Seri numarasının **ikinci karakteri `&`** ise (ör. `7&2a5c3f1&0`), cihazın
  gerçek seri numarası yoktur ve Windows bir tane üretmiştir — işaretlenir.
- Anahtarın son yazılma zamanı **kesin takılma zamanı değildir** (sürücü
  güncellemesi de değiştirir); çıktıda "hint" olarak etiketlenir. Kesin
  zamanlar sadece SYSTEM'in okuyabildiği `Properties` altında — kapsam dışı.

## Z5. prefetch — çalıştırma kanıtı

Windows, programların açılışını hızlandırmak için `%SystemRoot%\Prefetch\
<EXE>-<HASH>.pf` dosyaları tutar. Yan etki: her dosya "bu exe çalıştı, N kez, en
son T zamanında" der.

**Format (libscca belgesinden kavram olarak):**

- 84 baytlık başlık: sürüm @0, `SCCA` @4, exe adı (UTF-16, 60 bayt) @16, hash @76.
- Sürüme göre sabit ofsetler:

| Sürüm | Windows | Son çalışma | Çalışma sayısı |
|---|---|---|---|
| 17 | XP | @120 (1 adet) | @144 |
| 23 | Vista/7 | @128 (1 adet) | @152 |
| 26 | 8.1 | @128 (8 adet) | @208 |
| 30/31 | 10/11 | @128 (8 adet) | @208, kısa varyantta @200 |

  Kısa/uzun varyant, dosya-bilgi bloğunun ilk alanından (metrics ofseti:
  `0x130` uzun, `0x128` kısa) ayırt edilir.
- **Windows 10+ sıkıştırma:** Dosya `MAM` + format baytı (alt 4 bit = 4, XPRESS
  Huffman; üst bit set ise 4 baytlık CRC var, veri 12'den başlar) + açılmış
  boyut ile başlar. Açmak için kendi decompressor'ımızı yazmıyoruz — ntdll'in
  `RtlDecompressBufferEx`'ini kullanıyoruz (OS'in kendi kodu).

**Test edilebilirlik:** SCCA ayrıştırma `src/pfparse.c`'de, Windows başlığı
olmadan yazıldı; Linux'ta sentetik başlıklarla birim testi var (v30 uzun/kısa,
v23, bilinmeyen sürüm, kesik dosya, MAM başlık + CRC). Toplam 62 test.

**Sınırlar:** Prefetch klasörü genelde yönetici ister; sunucularda ve bazı SSD
kurulumlarında prefetch kapalı olabilir — **dosyanın olmaması, programın
çalışmadığının kanıtı değildir.**

---

## Bilerek yapılmayanlar

Defender ayarlarını **değiştirmek**, dışlama eklemek/silmek, USB geçmişini
temizlemek, prefetch dosyalarını silmek — hiçbiri yok. Araç sadece okur ve
gösterir; savunmacının gözden geçirmesi içindir.
