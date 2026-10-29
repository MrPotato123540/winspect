# 09 — Geliştirmeler: Rakip Araçların Eksiklerini Kapatmak

Belgedeki 8 fazdan sonra aracı, diğer Windows inceleme araçlarının (Process
Explorer, System Informer, winchecksec, Detect It Easy...) gösterdiği ama tek bir
yerde toplamadığı şeylerle genişlettik. Bu dosya o eklemeleri anlatır. Hepsi
user-mode'dur, kernel sürücüsü yoktur.

---

## 1. pe: güvenlik özeti + entropy + debug/TLS/overlay

- **Güvenlik özeti** (`winchecksec` tarzı): `DllCharacteristics`'ten ASLR, DEP,
  CFG, HighEntropyVA, ForceIntegrity'yi tek bakışta "var/yok" basar. ASLR için
  ince nokta: `DYNAMIC_BASE` biti varsa ama relocation'lar strip edilmişse
  yükleyici imajı taşıyamaz, yani ASLR fiilen kapalıdır — bunu uyarırız.
- **Section entropy**: her section'ın baytlarının Shannon entropisi (0..8). Normal
  kod/veri 4-6 arası; sıkıştırılmış/şifreli içerik 8'e yaklaşır. **>7.0** olanları
  `!` ile işaretleriz — paketlenmiş (packed) section'ın klasik sinyali.
- **Debug directory → PDB yolu**: CODEVIEW kaydından, derleme makinesinin yazdığı
  `.pdb` yolunu çıkarırız. Proje adı, build dizini gibi şaşırtıcı bir parmak izi.
- **TLS callbacks**: TLS callback'leri her thread için, hatta ilk kez entry
  point'ten **önce** çalışır. Bu yüzden başlangıç kodu saklamanın klasik yeridir;
  "kaç tane var?" bilmek değerli.
- **Overlay**: son section'ın bittiği yerden sonra gelen baytlar. Authenticode
  imzası genelde buradadır, ama eklenmiş arşiv/installer yükü de olabilir.

---

## 2. inspect: canlı mitigation policies

`pe`'deki güvenlik özeti **diskteki** (build-time) niyeti gösterir. `inspect` ise
`GetProcessMitigationPolicy` ile çekirdeğin **çalışan process'e şu an dayattığı**
mitigation'ları gösterir: DEP, ASLR, CFG, imza politikası (sadece MS-imzalı DLL
yükle), ACG (dinamik kod yasağı). İkisi farklı olabilir; asıl güvenlik duruşu
canlı olandır.

---

## 3. sign: Authenticode (yeni komut)

İnsanların sürekli karıştırdığı iki ayrı soru:
- **İmzalı mı?** Dosyada imza baytları var mı.
- **Güvenilir mi?** O imza kriptografik olarak geçerli **ve** sertifika zinciri bu
  makinenin güvendiği bir köke bağlanıyor mu.

Bir dosya imzalı ama güvenilmez olabilir (self-signed, süresi dolmuş, imzadan
sonra değiştirilmiş). `WinVerifyTrust` güven kararını verir; ayrıca gömülü
sertifikadan **imzalayanın adını** (`CryptQueryObject` + `CertGetNameString`)
okuruz. `--json` ile script'lenebilir.

---

## 4. regions: bellek haritası (yeni komut)

`VirtualQueryEx` ile process'in adres alanını bölge bölge gezer: her bölgenin
adresi, boyutu, izinleri (rwx) ve türü (**image** = diskteki bir modül,
**mapped** = haritalı dosya, **private** = yığın/stack/VirtualAlloc). En önemlisi:
**private + executable** bir bölge, diske dayanmayan koddur — elle haritalanmış /
enjekte edilmiş kodun klasik şekli. Bunları işaretleriz.

---

## 5. handles: tip + nesne ismi

Önceki sürüm sadece tip numarası basıyordu. Artık hedefi `PROCESS_DUP_HANDLE` ile
açıp her handle'ı kendi process'imize `DuplicateHandle` ile kopyalar, sonra
`NtQueryObject` ile **tip ismini** (File/Key/Event...) ve **nesne ismini**
(`\Device\...\dosya`) çözeriz. Tuzak: senkron bir named pipe handle'ının ismini
sorgulamak **sonsuza dek kilitlenebilir**. Bunu, bu handle'ların bilinen erişim
maskesini (`0x0012019F`) atlayarak önleriz (Process Hacker da böyle yapar).

---

## 6. token: linked token, logon session, grup attribute'ları

- **Token tipi**: Primary (process'e ait) mi, Impersonation (bir thread'in geçici
  olarak giydiği) mı.
- **Logon session** (LUID): aynı oturumun handle'larını ilişkilendirmeye yarar.
- **Linked token**: UAC split-token bir yöneticide, kısıtlı (limited) token'ın
  tam (elevated) karşılığına bir bağı vardır. Öbür token'ın integrity'sini basmak
  split'i görünür kılar.
- **Grup attribute'ları**: her grubun enabled / deny-only / integrity durumu.
  Deny-only bir grup erişimi asla **veremez**, sadece **alabilir**.

---

## 7. threads: CPU süresi + call stack

- **CPU süresi**: `GetThreadTimes`'tan kernel+user zamanı (ms). Buradaki FILETIME
  bir **süredir**, duvar saati değil.
- **Call stack** (`-s`): "başlangıç adresi nerede başladı"yı değil, "şu an ne
  yapıyor"u gösterir — bir asılmayı ancak bu çözer. DbgHelp + `StackWalk64` ile
  thread'in çağrı yığınını açar, sembolleri çözer (`ntdll!NtWaitForSingleObject
  +0x14`). Sembol yüklemesi yavaş olabilir ve bir sembol sunucusuna gidebilir, o
  yüzden varsayılan değil, `-s` ile opsiyonel.

---

## 8. secinfo: integrity label + effective access

- **Integrity label**: nesnenin kendi bütünlük seviyesi (SACL'daki mandatory
  label ACE'inden). Düşük seviyeli bir özne, DACL izin verse bile yüksek seviyeli
  bir nesneye **yazamaz**.
- **Effective access** (`AccessCheck`): "bu kullanıcı bu nesneye aslında ne
  yapabilir?" — ACE'leri listelemek değil, **sonucu** hesaplamak. AccessChk'in
  meşhur özelliği. Kendi token'ımızı impersonate edip `MAXIMUM_ALLOWED` ile
  sorarız.

---

## 9. verify: bağımsız bellek taraması

Dördüncü kontrol eklendi: `VirtualQueryEx` ile **private + executable** bellek
bölgelerini tarar. Önceki "gizli modül" kontrolünden farkı: bu, loader verisine
**hiç** bakmaz, doğrudan sayfa tablolarını okur. Gizlenmiş bir modül loader
listesini kandırabilir ama belleğindeki çalıştırılabilir sayfaları saklayamaz.

---

## 10. --json (script'lenebilir çıktı)

Paylaşılan küçük bir JSON yazıcı (`src/jsonutil.c`) ekledik. Şu an `sign` ve
`list` komutlarında tam uygulanmış durumda (`--json` / `-j`). Diğer komutlara
yaymak mekanik bir iştir; her komutun JSON'u, önce Windows'ta doğrulanmış metin
çıktısını yansıtacak şekilde eklenmeli (yoksa sessiz alan hataları girer). Bu
yüzden kalanları çalıştırma testiyle birlikte yapmak en sağlıklısı.

---

Not: Bu eklemelerin hepsi **derlenerek** doğrulandı (iki derleyici, sıfır uyarı),
ama bu ortamda Windows olmadığı için **çalıştırma testi** senin makinende yapılacak.
Özellikle call stack (`-s`), effective access ve handle isim çözümü gibi parçalar
runtime'da ilk kez orada denenecek.
