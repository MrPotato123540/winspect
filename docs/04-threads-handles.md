# 04 — threads ve handles

İki yakın komut: biri process'in **işçilerini** (thread), diğeri elindeki
**biletleri** (handle) döker. Dosyalar: `src/threads.c`, `src/handles.c`.

---

## Bölüm A — threads

`winspect threads <pid>` bir process'in her thread'i için CPU register
anlık görüntüsünü okur: RIP (bir sonraki çalışacak komut) ve RSP (stack'in
tepesi), artı öncelik ve başlangıç adresi.

### 1. Register'ı okumak için thread'i dondurmak gerekir

Bir thread **çalışırken** register'ları sürekli değişir; o an okursan tutarsız
çöp alırsın. Değerler ancak thread **durduğunda** anlamlıdır. Bu yüzden her
thread için şu sıra:

```c
OpenThread → SuspendThread → GetThreadContext → ResumeThread
```

Yani thread'i kısa süre donduruyoruz, register'larını alıyoruz, hemen çözüyoruz.
**Her yolda** `ResumeThread` çağırmak hayati: başka bir process'in thread'ini
dondurulmuş bırakırsak o process asılır. Kodda `GetThreadContext` başarısız olsa
bile `ResumeThread` yine çağrılır.

```c
if (SuspendThread(th) != (DWORD)-1) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_CONTROL;   // sadece RIP/RSP/flags istiyoruz
    if (GetThreadContext(th, &ctx)) {
        // ctx.Rip, ctx.Rsp
    }
    ResumeThread(th);   // başarısız olsa bile çözülür
}
```

`ContextFlags = CONTEXT_CONTROL`: sadece kontrol register'larını istiyoruz
(RIP/RSP). Daha azını istemek hem hızlı hem de kullanmadığımız büyük FP/vektör
durumunu çekmekten kaçınır.

x64'te `ctx.Rip`/`ctx.Rsp`, 32-bit'te `ctx.Eip`/`ctx.Esp`. Kodda `#ifdef _WIN64`
ile ikisini de destekliyoruz.

### 2. RIP'i anlamlı kılmak: modül + offset

Çıplak bir `0x7FF....` adresi hiçbir şey ifade etmez. Onu "ntdll'in bekleme
fonksiyonunun içinde" gibi okunur hale getirmek için, hedefin modül tablosunu
(Toolhelp `TH32CS_SNAPMODULE`) çekip her modülün taban+boyutunu saklarız. Sonra
RIP hangi modülün aralığına düşüyorsa:

```
rip 0x7FFAB2C31234  →  ntdll.dll+0x1234
```

Bu, [03 — inspect](03-inspect.md)'teki modül listesi fikrinin pratik bir
uygulaması: bir adresi insana okunur hale getirmek.

### 3. Başlangıç adresi: NtQueryInformationThread

Thread'in **hangi fonksiyonu çalıştırmak için** yaratıldığını
`NtQueryInformationThread(ThreadQuerySetWin32StartAddress)` verir. Bu fonksiyon
her toolchain'in başlığında bildirilmez, o yüzden çalışma anında ntdll'den
`GetProcAddress` ile çözüyoruz. (Fonksiyon pointer'ı dönüşümünü `-Wpedantic`'e
takılmadan yapma numarası da kodda yorumlu.)

---

## Bölüm B — handles

`winspect handles <pid>` bir process'in elindeki kernel nesne handle'larını
döker: her birinin değeri, tipi (indeks) ve granted access maskesi.

### 1. Bütün sistemi iste, sonra süz

`inspect`/`threads`'ten farklı olarak burada hedefi **açmıyoruz**. Tek seferde
**tüm makinenin** handle tablosunu istiyoruz, sonra PID'imize göre süzüyoruz:

```c
NtQuerySystemInformation(SystemHandleInformation, buf, cap, &need);
```

Bu, Process Explorer tarzı araçların kullandığı bilinen yoldur.

### 2. Büyüyen tampon deseni

Handle sayısı sürekli değişir, tampon boyutunu önceden bilemeyiz. Klasik yöntem:
bir tahminle çağır, çekirdek `STATUS_INFO_LENGTH_MISMATCH` derse tamponu büyüt ve
tekrar dene:

```c
for (;;) {
    st = NtQSI(SystemHandleInformation, buf, cap, &need);
    if (st == STATUS_INFO_LENGTH_MISMATCH) { cap = büyüt(); continue; }
    break;
}
```

Sonsuza dek dönmesin diye bir tavan (256 MB) koyuyoruz.

### 3. Her girdi ne söyler

```c
typedef struct {
    USHORT UniqueProcessId;   // sahibi PID (bu eski görünümde 16-bit)
    ...
    UCHAR  ObjectTypeIndex;   // nesne tipi (sürüme göre değişen numara)
    USHORT HandleValue;       // handle'ın kendisi (hep 4'ün katı)
    PVOID  Object;            // nesnenin kernel adresi (sadece bilgi)
    ULONG  GrantedAccess;     // bu handle hangi erişimle açıldı
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;
```

`UniqueProcessId == pid` olanları basıyoruz.

**Granted access** maskesini çözüyoruz. Maskenin üst 16 biti **standart
haklardır** (her nesne tipinde aynı anlama gelir: `DELETE`, `READ_CONTROL`,
`SYNCHRONIZE`...). Alt 16 bit **nesneye özeldir** (bir dosyadaki `FILE_READ_DATA`
ile bir thread'deki `THREAD_SET_CONTEXT` farklı şeylerdir). Bu yüzden standart
bitleri isimle çözüp tam maskeyi yine hex basıyoruz — hiçbir şey saklanmıyor.

### 4. Tip ismini neden vermiyoruz (şimdilik)

Her girdide bir `ObjectTypeIndex` var ama onu `File`/`Event`/... ismine çevirmek
sürüme bağlıdır ve bariz yöntem (`NtQueryObject`'i handle'ı duplicate edip
çağırmak) bazı handle tiplerinde (örn. bekleyen okuması olan bir pipe)
**kilitlenebilir** (deadlock). Bu yüzden ilk versiyon tip indeksini ve erişim
maskesini basıyor — güvenli ve asla takılmaz. İleride bir worker-thread +
timeout koruması ile isim çözümü eklenebilir. (Bu, belgedeki "önce basit versiyon"
felsefesiyle aynı.)

---

## Özet

- **threads**: register ancak thread dururken anlamlı → suspend/oku/resume, her
  yolda resume. RIP'i modül+offset ile okunur yap.
- **handles**: tüm sistemin handle tablosunu al, PID'e göre süz, access maskesini
  çöz. Tip ismini güvenlik/deadlock yüzünden şimdilik indeks olarak bırak.

Sıradaki: [05 — token ve secinfo](05-token-secinfo.md).
