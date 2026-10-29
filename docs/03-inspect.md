# 03 — inspect: Canlı Bir Process'in İçi (PEB)

`winspect inspect <pid>` çalışan bir process'in **belleğinden** bilgi okur:
komut satırı, image yolu, ortam değişkenleri, yüklü modüller ve "debugger bağlı
mı" bayrağı. Burada statik dünyadan (diskteki dosya) dinamik dünyaya (çalışan
process) geçiyoruz. Dosya: `src/inspect.c`.

Yürüdüğümüz zincir:
```
OpenProcess → NtQueryInformationProcess (PEB adresini al)
   → ReadProcessMemory (PEB'i oku)
      → ProcessParameters → CommandLine, ImagePathName, Environment
      → Ldr → modül listesi
```

---

## 1. En kritik fikir: her pointer "orada", "burada" değil

Bu dosyadaki **en önemli** şeyi baştan söyleyeyim: okuduğumuz yapıların içindeki
her pointer **hedef process'in** adres alanına işaret eder, bizimkine değil
(bak: [00 — sanal bellek](00-temel-kavramlar.md#3-sanal-bellek-adres-alanı-rva)).

Yani bir pointer'ı asla doğrudan `*ptr` diye okuyamayız. Her biri için ayrı bir
`ReadProcessMemory` gerekir. Bu yüzden her şeyi şu küçük sarmalayıcıdan geçiririz:

```c
static int rpm(HANDLE h, const void *remote, void *local, SIZE_T n)
{
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, remote, local, n, &got) || got != n) {
        return 0;   // tamamı okunamadıysa başarısız say
    }
    return 1;
}
```

`got != n` kontrolü neden? `ReadProcessMemory` aralığın **bir kısmı** okunamazsa
başarısız olabilir. Yarım okunmuş bir struct'ı yorumlamak çöp yorumlamaktır — ya
tamamı ya hiç.

---

## 2. Adım 1: process'i açmak (en az yetkiyle)

```c
HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
```

Sadece iki yetki istiyoruz:
- `PROCESS_QUERY_INFORMATION`: `NtQueryInformationProcess` için.
- `PROCESS_VM_READ`: `ReadProcessMemory` için.

Yazma ya da sonlandırma yetkisi **istemiyoruz**. Buna **en az ayrıcalık** (least
privilege) denir: işini görecek en küçük yetkiyi iste, fazlasını değil.

`OpenProcess` başarısız olursa en sık sebep `ERROR_ACCESS_DENIED`'dir. Bu
genelde bir **bütünlük seviyesi** (integrity) duvarıdır: Medium seviyedeki bizim
process'imiz, High (yükseltilmiş) ya da korumalı bir process'i okuyamaz. Kod bunu
fark edip "yönetici konsoldan dene" diye söyler — sessizce başarısız olmaz.

---

## 3. Adım 2: PEB nerede? NtQueryInformationProcess

PEB hedef process'in belleğindedir; biz sadece **adresini** öğrenmek istiyoruz:

```c
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(h, ProcessBasicInformation, &pbi, sizeof pbi, &retlen);
// pbi.PebBaseAddress artık PEB'in hedef process'teki adresi
```

`NtQueryInformationProcess` `ntdll.dll`'de yaşar. Bu yüzden CMakeLists'te
`ntdll` ile linkliyoruz (`target_link_libraries(winspect PRIVATE ntdll)`).

Dönüş değeri bir **NTSTATUS**'tur: negatifse hata. `if (st < 0)` ile kontrol
ederiz (normal Win32'deki "0 = başarı" kuralından farklı).

---

## 4. winternl.h ve gizli alanlar

Windows bu yapıların **tam** tanımını resmî olarak vermez; `winternl.h` kısmi bir
görünüm sunar (bazı alanlar `Reserved1`, `Reserved2`... diye isimlendirilir). İyi
haber: kullandığımız alanlar (`BeingDebugged`, `Ldr`, `ProcessParameters`,
`ImagePathName`, `CommandLine`) gerçek offsetlerinde duruyor, o yüzden struct'ı
elle tanımlamamıza gerek yok.

İki şey `winternl.h`'de gizli:
- **ImageBaseAddress**: `winternl`'in PEB'inde `Reserved3[1]`'dir (x64'te offset
  `0x10`). Kodda `peb.Reserved3[1]` olarak okuruz.
- **Environment pointer**: `RTL_USER_PROCESS_PARAMETERS`'ın `0x80` offsetinde,
  `winternl`'in beyan ettiği struct'ın dışında. Bu yüzden ham offsetle okuruz.

Bu tür "belgelenmemiş ama bilinen" offsetler Windows internals işinin normalidir.
WinDbg'de `dt ntdll!_PEB` komutuyla gerçek layout'u görüp doğrulayabilirsin.

---

## 5. Adım 3: komut satırı, yol, ortam

`peb.ProcessParameters` hedefteki bir pointer. Onu okuyup içinden
UNICODE_STRING'leri alırız:

```c
RTL_USER_PROCESS_PARAMETERS params;
rpm(h, peb.ProcessParameters, &params, sizeof params);
read_ustr(h, &params.ImagePathName, path, sizeof path);
read_ustr(h, &params.CommandLine,   cmd,  sizeof cmd);
```

**UNICODE_STRING** Windows'un dahili string tipidir: `{ Length, MaximumLength,
Buffer }`. `Length` bir **bayt** sayısıdır (karakter değil) ve string'in NUL ile
bittiği **garanti değildir**. Ayrıca `Buffer` yine hedef process'e işaret eder.
`read_ustr` bu yüzden: önce struct'ı (lokal) okur, sonra `Buffer`'dan `Length`
kadar baytı ayrıca `ReadProcessMemory` ile çeker, sonra UTF-16'dan UTF-8'e
çevirir.

**Güvenlik notu (masquerading):** PEB user-mode'da olduğu için bir process
kendi `CommandLine`/`ImagePathName`'ini değiştirip başka program gibi
görünebilir. Bu yüzden `verify` komutu bunu kernel'in bildiği gerçek yolla
karşılaştırır (bak: [07 — verify](07-verify.md)).

**BeingDebugged:** PEB'deki tek bir bayt. `IsDebuggerPresent()` fonksiyonu arka
planda sadece bunu okur. Basit anti-debug kontrolleri buna bakar.

---

## 6. Adım 4: modül listesi (Ldr)

Yüklü DLL'lerin listesi PEB'in `Ldr` alanından (loader data) gelir. Bu bir
**çift yönlü bağlı liste**dir (doubly-linked list): `LIST_ENTRY` düğümlerinden
oluşan bir halka.

Burada C'nin klasik `CONTAINING_RECORD` deseni var. Liste düğümleri, her modül
kaydının (`LDR_DATA_TABLE_ENTRY`) **içindeki** `InMemoryOrderLinks` alanıdır.
Yani düğümün adresinden kaydın başına gitmek için o alanın offset'ini
**çıkarırız**:

```c
const BYTE *entry_addr = (const BYTE *)node.Flink -
                         offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
LDR_DATA_TABLE_ENTRY entry;
rpm(h, entry_addr, &entry, sizeof entry);
```

Halkayı, tekrar başa (head) dönene kadar geziyoruz. Her kayıttan `DllBase`
(modülün yüklendiği adres) ve `FullDllName`'i (yine `read_ustr` ile) okuruz.

Neden "InMemoryOrder"? Loader üç ayrı sırayla üç liste tutar (yükleme sırası,
bellek sırası, başlatma sırası). Biz bellek sırasını geziyoruz; hangisi olduğu
önemli değil, üçü de aynı modülleri içerir.

---

## 7. Özet

- Başka process'in her pointer'ı "orada"dır; her biri ayrı `ReadProcessMemory`.
- `OpenProcess` en az yetkiyle; erişim reddi genelde integrity duvarıdır.
- `NtQueryInformationProcess` PEB'in adresini verir; gerisini biz okuruz.
- `winternl.h` kısmi yapı verir; birkaç offset'i elle biliriz, WinDbg ile
  doğrularız.
- PEB user-yazılabilir → tek başına güvenilmez → `verify` devreye girer.

Sıradaki: [04 — threads ve handles](04-threads-handles.md).
