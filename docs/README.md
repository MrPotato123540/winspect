# winspect — Öğrenme Dokümantasyonu

Bu klasör, winspect'i **hiç bilmeyen birine** baştan sona anlatmak için yazıldı.
Amaç sadece "bu komut ne yapıyor"u söylemek değil; her komutun arkasındaki
Windows kavramını, *neden* öyle olduğunu ve kodun *nasıl* çalıştığını anlatmak.

Kod yorumları İngilizce (kodun diliyle uyumlu olsun diye), ama bu dokümanlar
Türkçe ve mümkün olduğunca sade. Bir şeyi bildiğini varsaymıyorum.

## Nasıl okunur

Sırayla oku. Her dosya bir öncekinin üstüne kurulu:

1. **[00 — Temel kavramlar](00-temel-kavramlar.md)**
   user-mode / kernel-mode, process, thread, handle, PE, PEB, token, syscall.
   Her şeyin dayandığı sözlük. Önce bunu oku.
2. **[01 — Mimari: komutlar nasıl bağlanıyor](01-mimari.md)**
   `main.c`'deki komut tablosu, argümanların nasıl dağıtıldığı, dosya düzeni.
3. **[02 — pe: bir dosyayı çözmek](02-pe.md)**
   DOS header → NT header → Optional header → section tablosu → imports → exports.
4. **[03 — inspect: canlı bir process'in içi (PEB)](03-inspect.md)**
   `OpenProcess`, `ReadProcessMemory`, PEB, komut satırı, modül listesi.
5. **[04 — threads ve handles](04-threads-handles.md)**
   Register'lar (RIP/RSP), thread'i dondurup okumak; handle tablosu.
6. **[05 — token ve secinfo](05-token-secinfo.md)**
   Güvenlik: SID, privilege, integrity level, DACL ve ACE'ler.
7. **[06 — ssn ve launch](06-ssn-launch.md)**
   syscall numarası nedir, askıya alınmış process ve entry point.
8. **[07 — verify: çelişkileri yakalamak](07-verify.md)**
   Aynı gerçeği iki kaynaktan okuyup hook / masquerade / gizli modül tespiti.
9. **[08 — Build, CMake, CI ve git](08-build-ci-git.md)**
   Projeyi nasıl derlersin, iki derleyici neden, GitHub Actions ve git akışı.
10. **[09 — Geliştirmeler](09-gelistirmeler.md)**
    Belge fazlarından sonra eklenenler: güvenlik özeti, entropy, mitigation'lar,
    `sign`, `regions`, handle isim çözümü, call stack, effective access, `--json`.
11. **[10 — Profesyonelleştirme](10-triage-net-json.md)**
    `triage` (tek komutta şüphe skoru), `net` (process başına ağ bağlantıları),
    her yere `--json` / tablolara `--csv`, catalog imza desteği, çift tıklama.
12. **[11 — Daha derin esin](11-accesschk-pefile-netstat.md)**
    AccessChk (servis/registry/named-rights/hesap hakları), pefile anomalileri,
    sigcheck dizin taraması, netstat process adı + filtreler, pe-sieve/Moneta
    thread & section tespiti.
13. **[12 — Yeni komutlar](12-yeni-komutlar.md)**
    strings, services, drivers, autoruns, pipes, hash komutları; pe exphash + .NET;
    handles enjeksiyon işareti; token güçlü privilege vurgusu.
14. **[13 — Sistem görünümleri](13-sistem-gorunumleri.md)**
    hosts, certstore, tasks, modules, arp, sessions, shares, routes komutları;
    kategorili kullanım çıktısı.
15. **[14 — Mimari genel bakış](14-mimari-genel-bakis.md)**
    Projenin bütünü: dosya düzeni, paylaşılan altyapı, her yere yayılan desenler,
    komut aileleri, yeni komut nasıl eklenir.
16. **[15 — DFIR artefaktları](15-dfir-artefaktlari.md)**
    autoruns genişlemesi (IFEO, SilentProcessExit, AppInit, Startup), objects,
    defender, usb, prefetch komutları.
17. **[16 — Çalıştırma kanıtı ve denetim](16-calistirma-kaniti-ve-denetim.md)**
    shimcache, bam, prefetch --files, taskcache (gizli görevler), firewall;
    autoruns nedenleri, tırnaksız servis yolu, drivers/modules imza kontrolü,
    FP temizliği.
18. **[17 — Test stratejisi](17-test-stratejisi.md)**
    Windows aracını Linux'ta test etmek: birim testleri, wine smoke, fonksiyonel
    fixture'lar (pozitif + negatif kontroller), gerçek PE taraması ve fuzz.
19. **[18 — Kıyas turu](18-kiyas-turu.md)**
    Her komutun esin aldığı araçla yan yana karşılaştırılması: ne eksikti, ne
    eklendi, nasıl doğrulandı; karşılaştırmanın bulduğu üç gerçek hata.

## Aklında tut: tek cümlelik fikir

> winspect, Windows'un zaten dışarı verdiği bilgiyi okur, insan ve makine için
> okunur biçimde basar, ve mümkünse aynı gerçeği birden çok kaynaktan okuyup
> çelişkileri işaretler.

Her komut bu fikrin bir parçası. Okurken "bu komut hangi kaynaktan, hangi
bilgiyi okuyor?" diye sorarsan her şey yerine oturur.
