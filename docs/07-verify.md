# 07 — verify: Çelişkileri Yakalamak

`winspect verify <pid>` winspect'in **özgün kimliğinin kalbidir**. Fikir tek
cümle: Windows aynı gerçeği çoğu zaman birden fazla pencereden gösterir ve
**sağlıklı bir process'te bu pencereler birbirini tutar**. Tutmadıklarında ilginç
bir şey oluyor demektir. Dosya: `src/verify.c`.

Üç ucuz kontrol var; her biri var olan bir komutun okuma yöntemini yeniden
kullanıyor, yeni bir parse yok.

---

## 1. Neden "iki kaynak" yaklaşımı

Diğer araçlar (Process Explorer, Spy++...) her kaynağı ayrı bir sekmede gösterir
ve karşılaştırmayı **sana** bırakır. winspect karşılaştırmayı **kendisi** yapar
ve çelişkiyi işaretler. Bir uzman zaten kafasında "PEB şöyle diyor ama kernel
böyle diyor, bu tuhaf" diye düşünür; biz bu akıl yürütmeyi koda döküyoruz.

Hiçbir kontrol kernel sürücüsü gerektirmez — hepsi user-mode okuma. Bir kontrolün
göremediği bir şey varsa, kod bunu açıkça söyler, olduğundan fazla iddia etmez.

---

## 2. Kontrol 1: ntdll stub bütünlüğü (hook tespiti)

**Fikir:** Bir sistem DLL'i bir açılış boyunca tüm process'lerde **aynı adrese**
yüklenir (bak: [00 — ASLR](00-temel-kavramlar.md#4-aslr-adreslerin-rastgeleleşmesi)).
Yani `NtProtectVirtualMemory` gibi bir fonksiyonun **bizim** process'imizdeki
adresi, hedefte de aynıdır. O adresten hem kendi baytlarımızı hem hedefin
baytlarını okuyup **karşılaştırırız**:

```c
memcpy(local, fn_ptr, 8);               // bizim ntdll'imizdeki baytlar
rpm(h, fn_ptr, remote, 8);              // hedefin aynı adresindeki baytlar
if (memcmp(local, remote, 8) != 0) {    // farklıysa → stub yamalanmış (inline hook)
```

Fark varsa, hedefin stub'ı yamalanmış demektir — bir EDR/antivirüs ya da enjekte
edilmiş kod araya girmiş. Sık hook'lanan birkaç fonksiyonu kontrol ederiz
(`NtProtectVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`...).

**Dürüstlük notu:** Referansımız kendi ntdll'imiz. Eğer bir EDR **bizim**
process'imizi de hook'lamışsa karşılaştırma kör kalabilir. Daha güçlü bir sürüm
diskteki ntdll'i referans alır. Kod bu sınırı kabul eder — bir eğitim aracının
dürüst olması, olduğundan güçlü görünmesinden iyidir.

---

## 3. Kontrol 2: image yolu masquerade

**Fikir:** Bir process kendi kimliği hakkında **yalan söyleyebilir**, çünkü PEB
user-yazılabilir (bak: [03 — inspect](03-inspect.md)). İki kaynağı karşılaştırırız:

- **Kernel'in cevabı:** `QueryFullProcessImageName` — gerçek dosya yolu. Bu
  user-mode'dan PEB gibi sahte­lenemez.
- **PEB'in cevabı:** `ProcessParameters->ImagePathName` — process'in kendisi
  hakkında söylediği.

```c
QueryFullProcessImageNameA(h, 0, real, &rlen);        // kernel
read_ustr(h, &params.ImagePathName, peb_path, ...);   // PEB
if (_stricmp(real, peb_path) != 0) { /* uyuşmuyor → olası masquerade */ }
```

İkisi çelişiyorsa process başka bir program gibi görünmeye çalışıyor olabilir.
PEB bazen `\??\` gibi native formlar kullandığından, bir uyuşmazlık kesin hüküm
değil, "daha yakından bak" sinyalidir.

---

## 4. Kontrol 3: gizli modül

**Fikir:** Yüklü modül listesini iki kaynaktan al, karşılaştır:

- **PEB loader listesi:** `inspect`'teki gibi `InMemoryOrderModuleList`'i gezip
  `DllBase`'leri topla.
- **Bağımsız sayım:** `EnumProcessModulesEx`.

Birinde olup diğerinde olmayan bir modül → biri listeden koparılmış (gizlenmiş)
olabilir. Klasik "loader listesinden unlink ederek gizlenme" tekniğinin şekli
budur.

```c
// loader listesindeki her tabanı enumeration'da ara, yoksa uyar
// enumeration'daki her tabanı loader listesinde ara, yoksa uyar
```

**Dürüstlük notu:** `EnumProcessModulesEx` de aslında loader verisini okur, o
yüzden tek başına nadiren çelişir — asıl olarak biri kafası karışıp diğeri
karışmadığında yakalar. Daha güçlü bir kontrol, bellekteki image bölgelerini
`VirtualQueryEx` ile tarar. Kod bu sınırı not eder, ispatlamadığı şeyi iddia
etmez.

---

## 5. Sonuç satırı ve felsefe

Her kontrol bir "uyarı" sayısı döndürür; sonda toplanır:

```
result: no inconsistencies found
   ya da
result: 2 warning(s) - worth a closer look
```

Normal bir process'te hepsi geçer. Bir uyarı "kesin kötü" demek değil, "beklenen
≠ gerçek, bak buraya" demektir. Bu, "çalışan sistemde beklenen ile gerçek
ayrışıyorsa bu bir anomalidir" fikrinin somut hali — hem GUI hata ayıklamaya hem
güvenliğe aynı mekanizmayla hizmet eder.

Sıradaki: [08 — Build, CI ve git](08-build-ci-git.md).
