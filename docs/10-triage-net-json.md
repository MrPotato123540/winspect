# 10 — Profesyonelleştirme: triage, net, JSON/CSV, catalog imza, çift tıklama

09'daki eklemelerden sonra aracı "kullanılabilir / profesyonel" seviyeye taşıyan
son dalga bu. Buradaki her şey yine user-mode, kernel sürücüsü yok. Amaç: çıktının
başka araçlara (jq, Excel, Timeline Explorer) girebilmesi, ve dağınık sinyalleri
tek bir karara toplamak.

---

## 1. Her yere `--json`, tablolara `--csv`

Önceki fazda birkaç komuta JSON eklemiştik; bu dalga **tüm** komutları kapsadı.
Mantık şu:

- **JSON** (`--json`): her komut, metin çıktısıyla aynı bilgiyi tek bir JSON
  nesnesi/dizisi olarak basar. Makineyle işlemek için (örn. `winspect triage 1234
  --json | jq .score`).
- **CSV** (`--csv`): yalnızca **tablo** biçimli komutlarda (`list`, `threads`,
  `handles`, `regions`, `net`). Satır-sütun veri; Excel ve Timeline Explorer bunu
  doğrudan açar. RFC 4180'e uyarız: içinde virgül, tırnak veya yeni satır olan
  alanı tırnağa alır, gömülü tırnağı ikiye katlarız.

Neden ikisi birden? DFIR dünyasının standardı budur. Bir olayı incelerken HTML
rapor değil, bir araçtan diğerine akan CSV/JSON istenir. winspect artık o akışın
içine düşüyor.

Kodda bu, ortak iki küçük yardımcıyla çözülür (`src/jsonutil.c`):
`json_str()` bir string'i JSON kurallarına göre kaçışlar, `csv_str()` bir alanı
RFC 4180'e göre tırnaklar. Her komut nesnenin/dizinin iskeletini kendi `printf`'i
ile kurar — ortada güvenilecek bir JSON kütüphanesi yok, bozulacak durum yok.

### JSON üretirken dikkat: virgül yönetimi

JSON'da diziyi `[a,b,c]` diye yazarken eleman **aralarına** virgül koyarsın, sona
koymazsın. Bir eleman bazen atlanabiliyorsa (örn. çözülemeyen bir kayıt), "şu ana
kadar bir şey bastım mı?" diye bir `first` bayrağı tutmak gerekir; yoksa `[,{...}]`
gibi geçersiz JSON çıkar. Kod bu yüzden her dizide `first`/`emitted` sayacı
kullanır ve virgülü sadece gerçekten bir eleman basıldığında ekler.

---

## 2. triage: tek komutta "bu process şüpheli mi?" (yeni komut)

Tek tek komutlar dar birer soru yanıtlar. Bilinmeyen bir process'e bakan biri ise
soruların **birlikte** sorulmasını ve cevapların **tartılmasını** ister. `triage`
tam olarak bunu yapar: ucuz, yüksek-sinyalli, user-mode kontrolleri toplar, bir
**skor** ve skoru açıklayan **sebepler** üretir.

Toplanan sinyaller ve ağırlıkları:

| Sinyal | Ağırlık | Ne anlama gelir |
| --- | --- | --- |
| private + executable bellek | +40 | diske bağlı modülü olmayan çalıştırılabilir kod — enjekte kodun şekli |
| PEB yolu ≠ kernel yolu | +30 | process kendi kimliği hakkında yalan söylüyor olabilir (masquerade) |
| imza güvenilir değil | +25 | ne geçerli embedded imza ne de catalog üyeliği var |
| ntdll stub'ları inline-hook'lu | +15 | EDR olabilir, ama enjekte hook da olabilir |
| kullanıcı-yazılabilir/temp konumdan çalışıyor | +15 | `\Temp\`, `\AppData\`, `\Downloads\`, `\Users\Public\` |
| elevated ama imzasız | +10 | yükseltilmiş yetki + güvenilmeyen imaj |

Skor → karar: **≥60 HIGH**, **≥30 MEDIUM**, aksi halde **LOW**.

Önemli dürüstlük notu: bunların hiçbiri tek başına kanıt değil. EDR'ler ntdll'i
hook'lar; installer'lar `%TEMP%`'ten çalışır. Ama birlikte tartıldığında
"sıradan" ile "yakından bak"ı ayırırlar — `triage`'ın iddiası tam olarak bu, ne
eksik ne fazla. Her sebep açıkça yazılır; skor asla bir kara kutu değildir.

`triage` koddaki diğer komutların mantığını (verify, sign, regions, token,
inspect) tek dosyada derli toplu tekrar kullanır: gerçek yolu kernel'den okur
(`QueryFullProcessImageName`), PEB yolunu okuyup karşılaştırır, 5 sıcak ntdll
stub'ını kendi ntdll'imizle bayt bayt kıyaslar, `VirtualQueryEx` ile private+exec
bölge sayar, token'dan integrity/elevation çeker, ve imzayı embedded + catalog
yoluyla doğrular.

---

## 3. net: process başına ağ bağlantıları (yeni komut)

`netstat -ano`'nun sorduğu soru: "bu process neyle konuşuyor, bu dinleyen portu
kim açtı?" Windows TCP/UDP endpoint tablolarını çekirdekte tutar; `iphlpapi`
bunları `GetExtendedTcpTable` / `GetExtendedUdpTable` ile dışa verir. `_OWNER_PID`
tablo türü, bu işi triyaj için değerli kılan tek alanı ekler: endpoint'i **hangi
PID** sahipleniyor.

winspect dört tabloyu okur — TCP/IPv4, TCP/IPv6, UDP/IPv4, UDP/IPv6 — ve her
endpoint için bir satır basar: protokol, yerel adres:port, uzak adres:port (TCP),
durum (LISTEN/ESTABLISHED...), PID. Bir `pid` argümanı verirsen tek process'e
filtreler.

İnce noktalar:
- Bu struct'larda adres ve portlar **network byte order** (big-endian). Port'u
  sayı olarak okumak için bayt takası gerekir; IPv4 adresi dört baytı sırayla
  basarız; IPv6'yı ntdll'in `RtlIpv6AddressToStringA`'sına veririz.
- Tablolar iki adımlı okunur: önce boyut sorulur (buffer NULL), sonra ayrılır ve
  okunur — winspect'in her yerde kullandığı desen.

---

## 4. sign: catalog imza desteği

Birçok Windows ikilisi (ör. `kernel32.dll`, hatta `notepad.exe`) **embedded**
imza taşımaz; Authenticode hash'leri imzalı bir **catalog** (`.cat`) dosyasında
listelenir. Bu yüzden düz bir `WinVerifyTrust` bu dosyalara "imzasız" der — oysa
dosya pekâlâ güvenilirdir.

`sign` artık embedded imza bulamazsa catalog yoluna düşer:

1. `CryptCATAdminCalcHashFromFileHandle` — dosyanın Authenticode hash'i.
2. `CryptCATAdminEnumCatalogFromHash` — bu hash'i listeleyen catalog var mı?
3. `WinVerifyTrust` + `WINTRUST_CATALOG_INFO` — o catalog üzerinden doğrula.

Çıktı artık **source** alanı taşır: `embedded`, `catalog` veya `none`; catalog ise
hangi `.cat` dosyası olduğunu da yazar. İmzalayan ad embedded imzadan okunamazsa,
catalog dosyasının imzalayanından (genelde "Microsoft Windows") okunur.

---

## 5. Çift tıklama dostu başlangıç

Araç komut satırıdır; birisi `.exe`'ye çift tıklarsa Windows yeni bir konsol açar,
program biter ve pencere **anında kapanır** — çıktı okunmadan uçar. Bunu
yakalamak için `GetConsoleProcessList` kullanırız: konsola bağlı **tek** process
biz isek, bizden önce kimse yoktu, yani çift tıklama durumundayız.

O durumda: komut verilmemişse komut listesini + birkaç kopyalanabilir örnek
basarız, ve her durumda çıkmadan önce "Press Enter to close" ile bekleriz.
Terminalden çalıştırıldığında (konsolda zaten başka process varken) bu davranış
devreye girmez; normal CLI gibi davranır.

---

## 6. verify + triage derin tespit (image tamper + IAT hook)

`verify`'a iki güçlü, salt-okunur kontrol daha eklendi. İkisi de tek bir soruyu
sorar: **bellekteki hâlâ diskteki dosyayla aynı mı?** Kod `src/detect.c`'de ortak
durur, hem `verify` hem `triage` oradan çağırır (kopyala-yapıştır yok). Kavramlar
pe-sieve gibi bellek tarayıcılardan esinlendi; **tek satır kod alınmadı**, sıfırdan
ve öğretmek için yazıldı. Hiçbir şey enjekte/yazmıyor, sadece okuyor.

**Check 5 — image tamper (hollowing / yamalı kod):** Ana modülün diskteki dosyası
okunur, bellekteki image'la **section section** kıyaslanır. Normal kod yüklendikten
sonra değişmez; çalıştırılabilir bir section'ın baytları farklıysa bu, *process
hollowing* veya bellekte kod yamasının şeklidir. Tek dürüst zorluk **relocation**:
modül tercih ettiği `ImageBase`'e yüklenemezse yükleyici koddaki mutlak adresleri
yeniden yazar; ham kıyas o yüzden her relocation'ı "değişmiş" sanırdı. Biz
`.reloc` tablosunu okuyup aynı relocation'ları **diskteki kopyaya da uygulayarak**
farkı sıfırlarız; geriye yalnızca *gerçek* değişiklikler kalır. (delta = yüklendiği
taban − tercih edilen taban; 0 ise hiç relocation uygulanmamıştır.)

**Check 6 — IAT hook:** Ana image'ın Import Address Table'ı bellekten yürünür.
Çözülmüş her slot bir yere işaret eder; o adres **yüklü herhangi bir modülün**
aralığına düşmüyorsa (yani backing'siz/private belleğe gidiyorsa) bu bir
yönlendirilmiş import — hook trambolininin şeklidir. Dikkat: "adını verdiği modülün
içine mi düşüyor" diye bakmıyoruz; modern Windows'ta **API-set** yönlendirmesi bir
`kernel32` import'unu meşru şekilde `kernelbase`'e sokar ve bu test yanlış alarm
verirdi. "Herhangi bir modül tarafından destekleniyor mu" testi hem sağlam hem
sessiz.

Her iki bulgu **triage skoruna** bağlı: image tamper +45, IAT hook +35. Yani bir
process'in kodu diskle uyuşmuyorsa triage onu doğrudan yüksek skora taşır.

---

## Özet

Bu dalganın tek cümlesi: **winspect'i bir oyuncaktan bir alete çevirmek.**
Çıktı artık başka araçlara akıyor (`--json`/`--csv`), dağınık sinyaller tek karara
toplanıyor (`triage`), ağ görünürlüğü var (`net`), sistem ikilileri doğru
"güvenilir" cevabını alıyor (catalog), ve çift tıklayan biri boş bir pencereyle
baş başa kalmıyor.
