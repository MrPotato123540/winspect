# 25 — Yama raporu, oturum geçmişi ve yeni komutlar

Bu bölüm tek bir oturumda eklenenleri anlatır. Hepsinin ortak fikri aynı:
**bir bayrağı (`[!]`) ya da bir "bulunamadı" cevabını, arkasındaki kanıtla
birlikte göstermek.** Kanıtsız bir uyarıya ne güvenebilirsin ne de itiraz
edebilirsin.

İçindekiler:

1. `verify` / `triage`: "bellek diskten farklı" uyarısının **neresi** farklı?
2. `mft`: parçalanmış `$MFT`, `--image` ve "eksik okudum" uyarısı
3. `logons`: Windows'un `last` komutu
4. `dns`, `wer`, `office`, `magic`, `hash`: beş küçük komut
5. Bunların testleri

Önce bu bölümde geçen terimler:

| Terim | Anlamı |
|---|---|
| **Section (bölüm)** | Bir `.exe` dosyasının parçası. `.text` kodu, `.data` değişkenleri tutar. |
| **RVA** | *Relative Virtual Address*: programın belleğe yüklendiği adresten (taban) itibaren uzaklık. `RVA 0x1480`, "tabandan 0x1480 bayt sonra" demektir. |
| **Hook (kanca)** | Bir fonksiyonun ilk baytlarını bir **atlama** komutuyla değiştirip çağrıyı başka koda yönlendirmek. Antivirüsler de, zararlı yazılımlar da yapar. |
| **Trampoline** | Hook'un atladığı küçük ara kod parçası; oradan asıl hedefe gidilir. |
| **Private memory** | Diskteki bir dosyaya dayanmayan, programın çalışırken ayırdığı bellek. |
| **Cluster (küme)** | Diskin dosya sisteminin kullandığı en küçük parça (çoğunlukla 4096 bayt). |
| **Data run** | "Şu kümeden başla, şu kadar küme devam et" diyen kayıt. Bir dosyanın diskte nerede durduğunu söyler. |
| **Logon ID** | Windows'un her oturuma verdiği numara. Oturum açma ve kapama olaylarını birbirine bağlar. |

---

## 1. `verify` / `triage`: fark tam olarak nerede?

### Sorun

`triage <explorer pid>` şu sonucu vermişti: skor 85, **HIGH**, gerekçe
"main image code in memory differs from the file on disk". Bu doğru bir
gözlem olabilir, ama tek başına karar verdirmez. İki çok farklı durum aynı
cümleyi üretir:

- Bir **hooking ürünü** (antivirüs, ekran kaydedici, kabuk eklentisi) birkaç
  fonksiyonun başına 5–12 baytlık atlama yazmıştır. Zararsız.
- Programın kodu **toptan değiştirilmiştir** (process hollowing). Ciddi.

Eski çıktı yalnızca "kaç section farklı" diyordu. Hangisi olduğunu
anlayamıyordun.

### Çözüm: her yamayı listele

Artık her **yama** (peş peşe değişmiş bayt grubu) ayrı satırda gösteriliyor:

```
image tamper 1 section(s) differ from disk
             1 patch(es), 12 byte(s) changed in 1 section(s); 1 of the 1 listed are jumps/calls into selfpatch.exe
             .text    RVA 0x00001480  12 byte(s)
                 disk: 8B 15 AA AB 00 00 8D 04 49 01 D0 89
                 mem : 48 B8 00 00 9D FE FF 7F 00 00 FF E0
                 -> mov+jmp to 0x7FFFFE9D0000 (private memory), which jumps on to 0x1400014BC (selfpatch.exe)
```

Satır satır:

- `disk:` dosyadaki özgün baytlar, `mem :` şu an bellekteki baytlar.
- `-> mov+jmp to ... (private memory)`: yeni baytlar bir atlama; hedefi hiçbir
  modüle ait olmayan özel bellek. Bu bir trampoline.
- `which jumps on to ... (selfpatch.exe)`: trampoline'ın içine de bakılıyor ve
  **kontrolü sonunda alan modül** adıyla yazılıyor.

Okuma kuralı: *adı belli bir DLL'e giden birkaç kısa atlama* bir hooking
ürünüdür. *Megabaytlarca fark* ya da *hiçbir modüle varmayan atlamalar*
incelenmeli.

**Ağırlıklar değişmedi.** Skor hâlâ aynı hesaplanıyor; yalnızca gerekçe
artık görülebiliyor. Explorer için gerçek Windows'ta çıkan listeye bakmadan
ağırlık değiştirmek, kanıtsız karar olurdu.

### Kod nasıl çalışıyor (`src/patchdec.c`)

İki küçük, işletim sisteminden bağımsız fonksiyon var. Bağımsız oldukları
için Linux'ta birim testiyle sınanıyorlar.

**a) Baytları yamalara gruplamak.** Aradaki eşit bayt sayısı en fazla 4 ise
iki fark aynı yama sayılır:

```c
#define PATCH_GAP 4
...
if (open && i - last <= (size_t)PATCH_GAP + 1) {
    cur.len = (uint32_t)(i - cur.off + 1);
    cur.diff++;
}
```

Neden? 5 baytlık bir atlamanın ortasındaki bir bayt tesadüfen özgün baytla
aynı olabilir. Boşluğa izin vermeseydik tek atlama iki ayrı "yama" gibi
görünürdü.

**b) Atlamayı tanımak.** Bu bir disassembler değil. Bir hook birkaç baytla
yön değiştirmek zorunda olduğu için pratikte şu kalıplardan biridir:

| Baytlar | Anlamı | Hedef nasıl bulunur |
|---|---|---|
| `E9 xx xx xx xx` | `jmp rel32` | komutun sonu + işaretli 32 bit uzaklık |
| `E8 xx xx xx xx` | `call rel32` | aynı |
| `EB xx` | kısa `jmp` | komutun sonu + işaretli 8 bit |
| `FF 25 xx xx xx xx` | `jmp [bellek]` | hedef adres bir **yuvada** durur; yuva okunur |
| `48 B8 <8 bayt> FF E0` | `mov rax, adres ; jmp rax` | adres doğrudan baytlarda |
| `49 BB <8 bayt> 41 FF E3` | `mov r11, adres ; jmp r11` | aynı |
| `68 <4 bayt> C3` | `push adres ; ret` | aynı |

Bunların dışındaki her şey dürüstçe `other` diye raporlanır: baytlar
değişmiştir ama ne yaptığını bildiğimizi iddia etmeyiz.

`rel32` hesabındaki incelik, uzaklığın **işaretli** olması:

```c
int64_t rel = (int32_t)le32(c + 1);
uint64_t t = addr + 5 + (uint64_t)rel;
```

`(int32_t)` dönüşümü olmasa geriye doğru atlamalar (negatif uzaklık) 4 GB
ileriye atlama gibi hesaplanırdı.

---

## 2. `mft`: parçalanmış `$MFT`

### `$MFT` nedir, neden parçalanır?

NTFS'te her dosyanın bir **kaydı** vardır (1024 bayt); bu kayıtların hepsi
`$MFT` adlı tek bir dosyada durur. `$MFT` de bir dosya olduğu için onun da
bir kaydı (0 numaralı kayıt) ve diskte nerede durduğunu söyleyen **data
run** listesi vardır.

Disk doldukça `$MFT` büyür ve parçalanır. Parça sayısı arttığında run listesi
0 numaralı kayda **sığmaz**. NTFS bu durumda listenin devamını başka
kayıtlara (*extension record*) yazar ve 0 numaralı kayda bir
**`$ATTRIBUTE_LIST`** ekler: "verinin şu kümeden sonraki kısmı şu kayıtta".

### Bulunan hata

`mft --live` yalnızca 0 numaralı kayıttaki run'ları okuyordu. Parçalanmış bir
diskte bu, `$MFT`'nin **yalnızca baş kısmını** okumak demek. Sonraki dosyalar
sessizce eksik kalıyordu. "Dosyayı bulamadım" ile "o kısmı hiç okumadım"
ayırt edilemiyordu.

### Düzeltme

`follow_attribute_list` (`src/mftcmd.c`) listeyi okur, her extension record'u
**o ana kadar toplanan run'larla** bulur (NTFS bu kayıtları, 0 numaralı kaydın
kendi gösterdiği bölgede tutar; yoksa kendisi de bulamazdı) ve run'larını
sona ekler. Her adımda bir tutarlılık kontrolü var:

```c
if (ext[i].start_vcn != mapped) {
    if (ext[i].start_vcn < mapped) continue;     // already covered
    snprintf(warn, wn, "gap in the $MFT's extents at cluster %llu; later parts are missing", ...);
    break;
}
```

`start_vcn`, bu parçanın dosyanın kaçıncı kümesinden başladığıdır. Topladığımız
küme sayısıyla (`mapped`) uyuşmuyorsa arada boşluk var demektir; uydurmak
yerine durup uyarırız.

Hâlâ tamamı eşlenemiyorsa `stderr`'e şu yazılır (çıktı `--json` olsa bile
temiz kalsın diye `stdout`'a değil):

```
mft: WARNING: only X of Y bytes of the $MFT are mapped by its extents; later records are missing
```

### `--image`

`mft --image disk.img`, tek bir NTFS bölümünün ham imajını (dd / FTK "raw")
aynı kodla okur; bağlamaya (mount) gerek yok. Bu seçenek aynı zamanda `--live`
kodunu **test edilebilir** yaptı: wine ham diske erişemez, ama bir dosyayı
okuyabilir.

### `deneme_sil` neden bulunamamış olabilir?

Üç olasılık var, artık ayırt edilebiliyor:

1. `$MFT` parçalıydı ve kayıt okunmayan kısımdaydı → **artık okunuyor**.
2. Kayıt yeniden kullanıldı (yoğun `Temp` klasöründe saniyeler içinde olur).
3. Dosya saniyeler içinde oluşturulup silindi ve kaydı diske **hiç
   yazılmadı**. NTFS kayıtları tembel yazar (*lazy write*): değişiklik önce
   bellekte durur. Ham diski okuyan bir araç bunu göremez.

2 ve 3 için çapraz kontrol: `winspect usn --live C: --find deneme_sil`.
USN günlüğü her değişikliği ayrıca kaydeder.

### Yan bulgu: tanımsız kaydırma

Statik analiz (`cppcheck`) boot sector ayrıştırıcısında şunu buldu:

```c
uint32_t sectors = spc <= 0x80 ? spc : (1u << (256 - spc));
```

`spc` 0x81 olursa 127 bit kaydırma yapılır; C'de 32 bitlik bir değeri 32 ve
üzeri kaydırmak **tanımsız davranıştır**. Gerçek diskte bu değer oluşmaz, ama
bozuk bir imajda oluşur. Şimdi önce sınır kontrol ediliyor ve fuzz testi bu
fonksiyonu da kapsıyor.

---

## 3. `logons`: kim, nasıl, nereden, ne kadar süre?

Linux'ta `last` komutu "bu makineye kim, nereden girdi, ne zaman çıktı"
sorusunu tek dosyadan cevaplar. Windows aynı bilgiyi Security günlüğünde
birkaç olaya böler:

| Olay | Anlamı |
|---|---|
| 4624 | oturum açıldı |
| 4634 / 4647 | oturum kapandı |
| 4648 | başka bir hesabın kimlik bilgisi açıkça kullanıldı (`runas`, `net use`) |
| 4672 | oturuma özel ayrıcalıklar verildi (yönetici eşdeğeri oturum) |
| 4778 / 4779 | oturuma yeniden bağlanıldı / bağlantı kesildi (RDP) |

`logons` bunları **Logon ID** üzerinden birleştirir:

```
4624 --(TargetLogonId)-->  4634 / 4647   => süre
     --(SubjectLogonId)--> 4672          => "admin"
```

```
winspect logons                         # canlı (yönetici gerekir)
winspect logons --evtx Security.evtx    # kopyalanmış günlük
winspect logons --summary               # hesap + tür + kaynak bazında özet
winspect logons --type 10 --flagged     # yalnızca işaretli RDP oturumları
```

### Oturum türleri (LogonType)

| No | Ad | Ne zaman |
|---|---|---|
| 2 | interactive | klavyeden giriş |
| 3 | network | paylaşıma erişim, uzaktan yönetim |
| 5 | service | servis başlatma |
| 7 | unlock | ekran kilidini açma |
| 8 | network cleartext | parola açık metin olarak ulaştı (IIS Basic auth) |
| 9 | new credentials | `runas /netonly` |
| 10 | remote desktop | RDP |
| 11 | cached interactive | etki alanına ulaşılamadı, önbellekten giriş |

### Gürültü

Bir Security günlüğünün büyük kısmı kimsenin klavyeden yapmadığı oturumlardır:
servisler (tür 5), `SYSTEM`, `DWM-1`, `UMFD-0`, sonu `$` ile biten makine
hesapları. Bunlar varsayılan olarak gizlenir; `--all` gösterir. Gerçek bir
günlükte: 92 olaydan 77'si gizlendi.

### Bayraklar ve gerekçeleri

Her bayrak, olayın **kendisinde yazan** bir olgudur:

| Bayrak | Neden |
|---|---|
| RDP / ağ oturumu, **genel (public) adresten** | makine internete açık demektir |
| RDP oturumu, **127.0.0.1'den** | RDP istemcisi aynı makinede: bağlantı bir port yönlendirmesinden (tünel) gelmiş |
| tür 8 | parola bu makineye şifresiz ulaşmış |
| tür 9 ve oturum süreci `seclogo` | `runas /netonly`; **pass-the-hash** araçları da birebir aynı olayı üretir |
| NTLMv1 | zayıf, aktarılabilir (relay) kimlik doğrulama |

### Gerçek veriyle bulunan yanlış alarm

İlk sürüm `ANONYMOUS LOGON` oturumlarını "NTLMv1" diye işaretledi. Gerçek bir
günlükte bunlardan üç tane çıktı. Sebep: boş oturumlar (*null session*) hiçbir
NTLM yanıtı hesaplanmadığı halde günlüğe **her zaman** "NTLM V1" diye yazılır.
Yani NTLMv1 kullanıldığını kanıtlamazlar. Kural düzeltildi:

```c
if (ci_eq(r->lm, "NTLM V1") && strstr(r->user, "ANONYMOUS LOGON") == NULL) return ...
```

Bu, projenin *"doğrulanmamış bayrak eklenmez"* ilkesinin tam örneği: kural
kâğıt üzerinde mantıklıydı, gerçek veri yanlış olduğunu gösterdi.

### Doğrulama

- **plaso'nun `System2.evtx` dosyası**: winspect'ten bağımsız bir `grep`,
  7 + 2 kapanış olayı buldu; `logons` tam 9 oturumu kapanışıyla eşleştirdi,
  iki etkileşimli oturumun süresi (145 s ve 137 s) elle hesapla aynı.
- **EVTX-ATTACK-SAMPLES** (kayıtlı gerçek saldırılar, yalnızca veri): RDP
  tüneli örneği ve pass-the-hash örneği işaretlendi; WMIC'in başka hesapla
  çalıştırıldığı örnek "kim, kimin hesabıyla, hangi programla" bilgisiyle
  listelendi.

---

## 4. Beş küçük komut

### `dns` — çözümleyici önbelleği

`ipconfig /displaydns`'in gösterdiği şey: makinenin yakın zamanda sorduğu
alan adları ve cevapları. Adı soran program kapandıktan sonra da dakikalarca
(bazen saatlerce) kalır. "Bu makine şu alan adıyla konuştu mu?" sorusunun
hızlı cevabı.

Ağa **hiçbir sorgu çıkmaz**: kayıtlar `DNS_QUERY_NO_WIRE_ONLY` ile yalnızca
önbellekten okunur. Hiçbir şey işaretlenmez; bir alan adı görünüşüne bakarak
şüpheli ilan edilemez.

### `wer` — çökme raporları

Bir program çöktüğünde Windows, `Report.wer` adlı bir metin dosyası yazar.
İçinde programın tam yolu, zaman, hata veren modül ve istisna kodu bulunur.
**Çöken program kesinlikle çalışmıştır**, ve rapor dosyanın kendisi
silindikten sonra da kalır. Zararlı yazılımlar ve exploit denemeleri
olağandan sık çöker.

İşaretlenen tek durum: çöken program kullanıcının yazabildiği bir klasörden
çalışmış. Kullanıcı klasöründen yüklenen **modüller** yalnızca `--modules` ile
gösterilir, işaretlenmez; çünkü oyun içi arayüzler ve eklentiler bunu meşru
olarak yapar.

### `office` — makro güveni

Kullanıcı bir Office belgesinde sarı çubuktaki **"İçeriği Etkinleştir"**
düğmesine bastığında, kayıt defterine o belge için bir satır yazılır
(*Trusted Documents*). Oltalama (phishing) ile başlayan bir saldırının ilk
adımı tam olarak bu kaydı bırakır.

24 baytlık değerin yapısı:

| Konum | İçerik |
|---|---|
| 0–7 | FILETIME: kararın verildiği an |
| 20–23 | `0x7FFFFFFF` = makrolar etkinleştirildi; başka değer = yalnızca düzenleme |

İşaretlenen: makrosu etkinleştirilmiş belge bir **e-posta eki**, **indirme**,
**geçici klasör** ya da **URL**'den açılmışsa. `Documents` klasöründeki kendi
makrolu tablon işaretlenmez.

Ayrıca makro ayarları (`VBAWarnings=1`: tüm makrolar sormadan çalışır) ve
**güvenilir konumlar** okunur. Güvenilir konumdaki dosyalar hiçbir makro
denetiminden geçmez; `Downloads` içinde bir güvenilir konum açık kapıdır.

Küçük bir tuzak: ilk sürüm `%APPDATA%\Microsoft\Templates` (Office'in kendi
varsayılanı) konumunu "temp klasörü" diye işaretledi, çünkü `\Templates`
metni `\Temp` ile başlıyor. Artık `\Temp`'in **tam bir klasör adı** olması
aranıyor.

### `magic` — dosya gerçekte ne?

Unix'in `file` komutunun fikri: dosyanın **adına** değil **içeriğine** bak.
Her biçimin başında tanıtıcı baytlar vardır (*magic number*): `MZ` bir
Windows programı, `%PDF-` bir PDF, `PK\x03\x04` bir zip.

```
winspect magic C:\Users\bob\Downloads -r --flagged
```

İşaretlenenler:

| Durum | Örnek |
|---|---|
| program içeriği, resim / belge uzantısı | `tatil.jpg` aslında bir `.exe` |
| çift uzantı | `fatura.pdf.exe` (Windows uzantıları gizlerse `fatura.pdf` görünür) |
| sağdan-sola yazım karakteri (U+202E) | `ann‮fdp.exe`, ekranda `annexe.pdf` gibi görünür |
| uzantıdan önce uzun boşluk | `fatura.pdf            .exe` |

Bayraklar yalnızca **kesin tanımada** çalışır. Tanınmayan dosya `data`'dır,
asla işaretlenmez.

### `hash` — klasör ve bilinen-hash listesi

Eskiden dosyanın tamamını belleğe alıyordu (1 GB sınırı). Şimdi dosya parça
parça okunup üç algoritmaya aynı anda veriliyor; boyut sınırı yok.

```
winspect hash C:\vaka -r --match iocs.txt
```

`--match`, her dosyanın hash'ini bir listede arar ve yalnızca listede
**olanları** bildirir. Liste biçimi serbesttir: yalın hash, `md5sum` çıktısı
(`hash  dosya`), CSV (`hash,etiket`); MD5, SHA-1 ve SHA-256 karışık olabilir.

---

## 5. Testler

| Ne | Nasıl doğrulandı |
|---|---|
| yama gruplama, atlama çözme | Linux'ta birim testi (ASan + UBSan) |
| yama raporu uçtan uca | wine'da kendi kodunu yamalayan yardımcı program (`tests/selfpatch.c`), doğrudan ve trampoline'lı |
| `$ATTRIBUTE_LIST` | sentetik, üç parçalı NTFS imajı; aranan dosya **son** parçada |
| eksik okuma uyarısı | aynı imajın liste **olmadan** üretilmiş hali |
| `logons` eşleştirme | plaso'nun gerçek günlüğü, bağımsız `grep` ile karşılaştırma |
| `logons` bayrakları | kayıtlı gerçek saldırı günlükleri |
| `hash` | Python `hashlib` ile karşılaştırma |
| `wer`, `office`, `magic` | "kötü" örnek işaretlenmeli, zararsız kontrol işaretlenmemeli |
| MFT ayrıştırıcısı | gerçek `$MFT` üzerinde fuzz (bozulmuş kayıtlar, yeni fonksiyonlar dahil) |

Her fixture'da bir **zararsız kontrol** vardır: bayrağın çalıştığını göstermek
yetmez, çalışmaması gereken yerde sustuğunu da göstermek gerekir.

## Gerçek Windows'ta bakılacaklar

Bunlar wine'da sınanamaz (wine'ın olay günlüğü, DNS önbelleği ve ham disk
erişimi yok):

- `triage <explorer pid>`: yama listesi şimdi ne gösteriyor? Atlamalar hangi
  DLL'e gidiyor?
- `mft --live C: --deleted --find deneme_sil`: uyarı çıkıyor mu, dosya
  bulunuyor mu?
- `logons` ve `dns`: canlı çıktı.
