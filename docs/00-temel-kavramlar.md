# 00 — Temel Kavramlar

Bu dosya winspect'in dayandığı tüm kavramları tek yerde topluyor. Buradaki
terimler sonraki dosyalarda sürekli geçecek. Hiçbirini bildiğini varsaymıyorum.

---

## 1. İki dünya: user-mode ve kernel-mode

Windows'ta kod iki ayrıcalık seviyesinde çalışır. İşlemcinin (CPU) kendisi bu
ayrımı donanım seviyesinde zorlar.

- **Kernel-mode (çekirdek, Ring 0):** İşletim sisteminin kalbi. Donanıma, tüm
  belleğe doğrudan erişir. Buradaki bir hata **tüm sistemi** çökertir (mavi
  ekran). Sürücüler (driver) burada çalışır.
- **User-mode (kullanıcı, Ring 3):** Sıradan programların dünyası. Her program
  kendi **izole** adres alanında çalışır. Hata yaparsa sadece kendisi kapanır,
  sistem etkilenmez.

**winspect tamamen user-mode'dur.** Sürücü yazmıyoruz. Peki o zaman başka
programların içini nasıl görüyoruz? Çünkü Windows, yetkimiz varsa bunu yapmamız
için resmî kapılar sunuyor: `OpenProcess`, `ReadProcessMemory`,
`OpenProcessToken` gibi fonksiyonlar. Biz çekirdeğe girmiyoruz; çekirdeğin açık
bıraktığı pencerelerden bakıyoruz.

Neden bu önemli? Çünkü bazı bilgiler (örneğin bir thread'in çekirdekteki stack'i)
sadece kernel-mode'dan görülebilir. winspect o noktada "bunu göremiyorum" deyip
sana WinDbg'de nasıl görüleceğini söyler. Yapamadığını saklamaz.

---

## 2. Process (süreç) ve thread (iş parçacığı)

Bu ikisi en çok karıştırılan şey.

- **Process:** Çalışan bir programın **kabı**. Kendi adres alanı (belleği),
  kendi handle tablosu, kendi güvenlik bağlamı (token) vardır. Ama bir process
  **kendi başına hiçbir şey çalıştırmaz**. O sadece bir kutu.
- **Thread:** Asıl **çalışan** şey. CPU'da komut işleten budur. Bir process'in
  en az bir thread'i vardır; çoğu programın onlarca thread'i olur. Thread'ler
  aynı process'in belleğini paylaşır.

Benzetme: process bir ofis (masalar, dolaplar, kapı anahtarları), thread'ler o
ofiste çalışan insanlar. Ofis tek başına iş yapmaz; işi insanlar yapar, ama
hepsi aynı dolapları kullanır.

Her process'in bir **PID**'i (Process ID), her thread'in bir **TID**'i (Thread
ID) vardır. Bir de **PPID** (Parent PID): bir process'i hangi process başlattı.
`winspect list` bu PID/PPID ilişkisini kullanarak ağacı çizer.

---

## 3. Sanal bellek, adres alanı, RVA

Her process kendini **tüm belleğe sahipmiş gibi** hisseder. Gerçekte işletim
sistemi ve CPU, her process'e **sanal** bir adres alanı verir ve bunu arka
planda fiziksel RAM'e eşler. Bir process'in `0x140000000` adresi ile başka bir
process'in `0x140000000` adresi tamamen farklı fiziksel yerlerdir.

Bu yüzden başka bir process'in `0x...` adresindeki veriyi **doğrudan okuyamayız**.
O adres bizim adres alanımızda başka bir şeydir. Okumak için `ReadProcessMemory`
kullanırız: "şu process'in şu adresinden şu kadar bayt kopyala" deriz.

İki önemli adres türü:

- **VA (Virtual Address):** Bellekte gerçek, tam adres. Örn. `0x140001410`.
- **RVA (Relative Virtual Address):** Bir temel adrese (genelde modülün yüklendiği
  yere) göre **offset**. Örn. entry point `0x1410`. Gerçek adres =
  `ImageBase + RVA` = `0x140000000 + 0x1410`.

PE dosyalarının içindeki her adres RVA olarak saklanır, çünkü dosya yazılırken o
program belleğin neresine yükleneceğini bilmez (ASLR yüzünden her seferinde
değişebilir). RVA bu belirsizliği çözer: "nereye yüklenirsem yükleneyim, bu şey
başlangıçtan şu kadar ileride."

---

## 4. ASLR: adreslerin rastgeleleşmesi

**ASLR (Address Space Layout Randomization):** Güvenlik için Windows, bir
programı ve DLL'lerini her açılışta **rastgele** bir adrese yükler. Böylece bir
saldırgan "şu fonksiyon tam şu adreste" diye ezbere bir yere atlayamaz.

Bunun iki pratik sonucu:

1. Bir PE dosyasının "tercih ettiği" yükleme adresi (`ImageBase`) genelde
   tutmaz; gerçek adres farklı olur. İçindeki RVA'lar bu yüzden önemli.
2. Bir sistem DLL'i (örn. `ntdll.dll`) **bir açılış boyunca** tüm process'lerde
   **aynı** adrese yüklenir. Bu ilginç bir ayrıntı ve `verify` komutunda işimize
   yarıyor: kendi process'imizdeki ntdll fonksiyonunun adresi, hedef process'te
   de aynı adrestir.

---

## 5. PE: bir .exe/.dll dosyasının yapısı

**PE (Portable Executable)**, Windows'un çalıştırılabilir dosya formatıdır. Her
`.exe` ve `.dll` bu standarda göre dizilir. Kabaca bir kargo paketi gibi düşün:

- Dışta **etiketler** (header'lar): "ben AMD64 içinim, giriş noktam şurada,
  şu DLL'lerden şu fonksiyonları kullanıyorum."
- İçte numaralı **bölmeler** (section'lar): `.text` (kod), `.data` (değişkenler),
  `.rdata` (sabitler), `.reloc` (ASLR tablosu)...

Windows bir programı çalıştırmadan önce bu etiketleri okur, sonra bölmeleri RAM'e
yerleştirir. `winspect pe` tam olarak bu paketi baştan sona açar. Detayı
[02-pe.md](02-pe.md)'de.

Bir diskteki dosyada veriler sıkışık (sektör hizalı) durur; RAM'e yüklenince
ferah (sayfa hizalı) yayılır. Bu yüzden bir şeyin **diskteki yeri (Raw)** ile
**bellekteki yeri (Virtual)** farklıdır. PE parse ederken sürekli bu ikisi
arasında çeviri yaparız.

---

## 6. PEB: çalışan bir process'in kimlik kartı

**PEB (Process Environment Block)**, çalışan her process için işletim sisteminin
user-mode'da tuttuğu bir yapıdır. İçinde: komut satırı, ortam değişkenleri,
yüklü modüllerin listesi, "bana debugger bağlı mı?" bayrağı ve daha fazlası.

Process Explorer'ın sana bir process hakkında gösterdiği şeylerin çoğunun kaynağı
budur. `winspect inspect` bunu okur. Detayı [03-inspect.md](03-inspect.md)'de.

Önemli bir güvenlik noktası: PEB **user-mode'dadır**, yani process kendi PEB'ini
değiştirebilir. Bir program PEB'deki komut satırını ya da kendi yolunu değiştirip
başka bir program gibi görünebilir (buna **masquerading** denir). İşte bu yüzden
sadece PEB'e güvenmek yetmez; `verify` komutu bunu kernel'in bildiği gerçekle
karşılaştırır.

---

## 7. Handle: bir kaynağa tutacak

Bir process bir dosyayı açtığında, başka bir process'e eriştiğinde, bir olay
(event) oluşturduğunda, çekirdek bir **nesne** (kernel object) yaratır ve
process'e bir **handle** verir. Handle küçük bir sayıdır (her zaman 4'ün katı) ve
çekirdekteki process'e özel bir tablonun indeksidir.

Yani handle = "çekirdekteki şu nesneye erişim biletim". Her handle'ın bir
**granted access** (verilen erişim) maskesi vardır: o biletle ne yapabilirsin
(okuma? yazma? sonlandırma?).

`winspect handles` bir process'in elindeki tüm biletleri döker. Detay
[04-threads-handles.md](04-threads-handles.md)'de.

---

## 8. Token: "kimsin ve ne yapabilirsin"

Her process bir **access token** taşır. Token, çekirdeğin "bu process kim ve
neye izni var?" sorusuna cevabıdır. İçinde:

- **SID (Security Identifier):** Kullanıcıyı/grubu benzersiz tanımlayan kimlik.
  Örn. `S-1-5-21-...-500`. Sondaki sayı (**RID**) özeldir: 500 = yerleşik
  Administrator.
- **Groups:** Hangi gruplara üye.
- **Privileges:** Özel yetkiler (örn. `SeDebugPrivilege` = her process'e erişim).
  Çoğu varsayılan olarak **kapalıdır**, program kullanacağı an açar.
- **Integrity level:** Bütünlük seviyesi — Low / Medium / High / System. Bir
  **düşük** seviyedeki process, **yüksek** seviyedekine müdahale edemez.

`winspect token` bunu okur. Bir nesnenin "kime hangi erişim" kuralları ise
**DACL** içinde durur (bak: güvenlik tanımlayıcısı), onu da `secinfo` okur.
Detay [05-token-secinfo.md](05-token-secinfo.md)'de.

Token = **özne** tarafı (kim istiyor). DACL = **nesne** tarafı (kime izin var).
Erişim kontrolü bu ikisini karşılaştırır.

---

## 9. syscall: user'dan kernel'e geçiş

Bir program bir dosyayı okumak istediğinde aslında kernel'den yardım ister. Bu
geçiş şöyle olur (basitleştirilmiş):

```
senin kodun  ->  kernel32.dll (ReadFile)  ->  ntdll.dll (NtReadFile)  ->  [syscall]  ->  kernel
```

Son adımda `ntdll.dll`'deki küçük bir "stub", bir **numara** (SSN — System
Service Number) yükleyip `syscall` komutunu çalıştırır. Bu numara, çekirdekteki
fonksiyon tablosunun kaçıncı girdisine gidileceğini söyler.

`winspect ssn` bu numarayı ntdll'den **okur** (çalıştırmaz, sadece gösterir).
Neden değerli? Çünkü bir antivirüs ya da zararlı yazılım bu stub'ları
değiştirebilir (hook). Stub'ın ilk baytları beklenenden farklıysa birisi araya
girmiş demektir. Detay [06-ssn-launch.md](06-ssn-launch.md)'de.

---

## 10. DLL, import (IAT) ve export (EAT)

- Bir **DLL** (Dynamic Link Library), birçok programın paylaştığı fonksiyon
  kütüphanesidir (örn. `kernel32.dll`).
- Bir program bir DLL'den fonksiyon **ödünç alır**: buna **import** denir. Hangi
  DLL'den hangi fonksiyonları aldığının listesi **IAT (Import Address Table)**'da
  tutulur.
- Bir DLL dışarıya fonksiyon **sunar**: buna **export** denir. Sunduğu
  fonksiyonların kataloğu **EAT (Export Address Table)**'dadır.

`winspect pe` hem IAT'ı (bu dosya neyi kullanıyor) hem EAT'ı (bu DLL neyi sunuyor)
gösterir. `.exe`'ler genelde export etmez, DLL'ler eder.

---

## Sözlük (hızlı bakış)

| Terim | Tek cümle |
| --- | --- |
| user-mode / kernel-mode | Sıradan programlar / işletim sisteminin çekirdeği |
| process / thread | Çalışan programın kabı / asıl çalışan iş parçacığı |
| PID / TID / PPID | Process / thread / ebeveyn process kimliği |
| VA / RVA | Tam adres / bir temele göre offset |
| ASLR | Adresleri her açılışta rastgeleleştiren güvenlik önlemi |
| PE | Windows çalıştırılabilir dosya formatı (.exe/.dll) |
| section | PE'nin içindeki numaralı bölme (.text, .data...) |
| PEB | Çalışan process'in user-mode kimlik yapısı |
| handle | Bir kernel nesnesine erişim bileti |
| token | Process'in güvenlik kimliği (kim + ne yapabilir) |
| SID / RID | Güvenlik kimliği / onun sonundaki özel sayı |
| DACL / ACE | Erişim listesi / listedeki tek bir izin-ret kaydı |
| syscall / SSN | Kernel'e geçiş / o geçişin numarası |
| IAT / EAT | Import (ödünç alınan) / export (sunulan) fonksiyon tablosu |

Bunlar oturduysa geri kalan her dosya kolay gelecek. Sıradaki:
[01 — Mimari](01-mimari.md).
