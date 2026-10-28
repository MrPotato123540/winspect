# 06 — ssn ve launch

Bu iki komut user-mode ile kernel-mode arasındaki sınırı somutlaştırır. **ssn**:
bir ntdll stub'ının syscall numarasını **okur**. **launch**: bir programı
askıya alınmış başlatıp doğuş anına bakar. Dosyalar: `src/ssn.c`, `src/launch.c`.

---

## Bölüm A — ssn

`winspect ssn <NtFonksiyonAdı>` bir native ntdll fonksiyonunun **System Service
Number (SSN)**'ını okur ve gösterir. Çalıştırmaz — sadece okur.

### 1. Bir syscall nasıl olur

Bir program dosya okumak istediğinde zincir şöyledir
(bak: [00 — syscall](00-temel-kavramlar.md#9-syscall-userdan-kernele-geçiş)):

```
senin kodun → kernel32 (ReadFile) → ntdll (NtReadFile) → [syscall] → kernel
```

Son kullanıcı-mode adımı `ntdll`'deki küçük bir stub'dır. Temiz bir x86-64
ntdll'de bu stub şöyle başlar:

```
mov r10, rcx          ; baytlar: 4C 8B D1
mov eax, <SSN>        ; baytlar: B8 <4 baytlık numara>
...                   ; sonra kernel'e geçiş
```

Yani **SSN**, `B8` baytından sonraki 4 baytlık (little-endian) değerdir. SSN,
çekirdekteki servis tablosunun kaçıncı girdisine gidileceğini söyleyen indekstir.

### 2. Numarayı okumak (çalıştırmadan)

`ntdll` zaten bizim de process'imize haritalı, o yüzden baytlarını düz bir
pointer'la okuyabiliriz — `ReadProcessMemory` bile gerekmez:

```c
HMODULE ntdll = GetModuleHandleA("ntdll.dll");
FARPROC stub = GetProcAddress(ntdll, name);   // export tablosunu bizim için gezer
// stub'ın ilk baytlarını oku, prologu kontrol et, B8'den sonraki 4 baytı al
```

Kod önce prologun beklendiği gibi (`4C 8B D1 B8`) olduğunu doğrular; öyleyse SSN'i
çıkarır. **Değilse** (örneğin ilk bayt bir `jmp` ise) stub yamalanmış demektir —
bu bir **inline hook**'tur ve kod "tanınmadı, muhtemelen hooked" der, uydurma bir
numara tahmin etmez.

### 3. Neden sadece okuyoruz, çalıştırmıyoruz

Bu komut SSN'i **gösterir**; kendi başına bir syscall kurup çalıştırmaz. Gerçek
bir "direct syscall" primitifi kurmak (ntdll'i tamamen atlayıp doğrudan kernel'e
geçmek — "Hell's Gate" tekniği) bir **kaçırma/atlatma** aracıdır ve bu projenin
kapsamı dışında bilerek tutuldu. Buradaki değer **anlamak ve doğrulamak**:

```
verify in WinDbg:  u ntdll!NtReadFile L3
```

Çıktı sana aynı numarayı WinDbg'de nasıl teyit edeceğini söyler. Araç hem öğretir
hem de kendini doğrulatır — hiçbir "gerçek" araç bunu sunmaz. Ayrıca bu prolog
kontrolü, `verify` komutunun hook tespitinin temelidir.

---

## Bölüm B — launch

`winspect launch <path>` bir programı **askıya alınmış** (suspended) başlatır,
entry point'ini hesaplar, oradaki ilk baytları gösterir, sonra çalıştırır. Bu,
bir debugger'ın/loader'ın yaptığının aynısıdır.

### 1. Askıya alınmış başlatmak

```c
CreateProcessA(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, ...);
```

`CREATE_SUSPENDED` bayrağı: Windows process'i ve ilk thread'ini yaratır, imajı
belleğe haritalar, ama thread'i **henüz çalıştırmaz**. Bu donmuş anda, kodun
nereden başlayacağına bakabiliriz.

### 2. Entry point'i bulmak: statik ve dinamiği birleştirmek

Entry point'i bulmak PE bilgisini ([02 — pe](02-pe.md)) canlı process'e bağlar:

1. Yeni process'in PEB'ini sor (`NtQueryInformationProcess`).
2. `PEB.ImageBaseAddress`'i oku — `.exe`'nin gerçekte yüklendiği yer (ASLR
   sonrası).
3. O imajın PE header'ından `AddressOfEntryPoint`'i (bir RVA) oku.
4. Entry sanal adresi = `ImageBase + AddressOfEntryPoint`.

`AddressOfEntryPoint`, NT header'ların başından `0x28` offsetinde durur
(signature 4 + File Header 20 + Optional Header'da 16). Bu offset PE32 ve PE32+
için aynıdır, o yüzden bitness'a bakmadan tek `ReadProcessMemory` ile okuruz.

Sonra entry adresindeki ilk 16 baytı okuyup basarız, en son `ResumeThread` ile
programı normal çalıştırırız. (Her yolda resume ederiz ki donmuş bir process
bırakmayalım. Programı kullanıcı kendi seçti, çalışması beklenen davranış.)

---

## Özet

- **ssn**: ntdll stub'ının ilk baytlarından SSN'i **okur**; prolog bozuksa hook
  uyarısı verir. Syscall'ı kurmaz/çalıştırmaz — analiz ve WinDbg doğrulaması.
- **launch**: `CREATE_SUSPENDED` ile başlat, PEB'den ImageBase + PE'den entry RVA
  ile entry point'i hesapla, ilk baytları göster, resume et.

Sıradaki: [07 — verify](07-verify.md).
