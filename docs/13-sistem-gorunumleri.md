# 13 — Sistem görünümleri: hosts, certstore, tasks, modules

Bu dalga dört read-only DFIR/triyaj komutu daha ekler ve `winspect`in komut
listesini kategorilere ayırır. Hepsi salt-okunur; hiçbiri bir şey değiştirmez.

- **`hosts`** — `%SystemRoot%\System32\drivers\etc\hosts` dosyasını okur, yorum ve
  boş satırları atlayıp gerçek girdileri (adres → ad) listeler. Tek bir satır bir
  alan adını saldırgana yönlendirebilir veya güvenlik sağlayıcılarını
  engelleyebilir; bakılması ucuz bir yerdir.

- **`certstore`** — makine (veya `--user` ile kullanıcı) sertifika deposunu
  (`--store` ile seçilir, varsayılan **Root**) `CertEnumCertificatesInStore` ile
  gezer: subject, issuer, SHA-1 thumbprint, geçerlilik tarihleri. Subject==issuer
  olanları **self-signed root** diye işaretler. Sahte bir güvenilen kök sertifika
  sessiz ama güçlü bir saldırıdır; Root deposunu "beklenmeyen bir şey var mı?"
  diye temel almak gerçek bir sorudur.

- **`tasks`** — `%SystemRoot%\System32\Tasks` altındaki görev XML'lerini COM'suz,
  salt-okunur gezer; her görevin `<Command>`, `<Arguments>`, `<Author>` alanlarını
  çıkarır ve komutu kullanıcı-yazılabilir/temp konumdan çalışanları işaretler.
  (Görev XML'leri UTF-16 saklanır; okurken UTF-8'e çeviririz.) Zamanlanmış
  görevler yaygın bir persistence noktasıdır.

- **`modules <pid>`** — bir process'in yüklü modüllerini (base, size, yol)
  `EnumProcessModulesEx` ile listeler. İki ucuz ama değerli bayrak: diskteki
  dosyası **kaybolmuş** modül (yüklenip silinmiş — hollowing/anti-forensik işareti)
  ve **kullanıcı-yazılabilir** konumdan yüklenmiş modül.

- **`arp`** — IPv4 komşu (ARP) önbelleğini (`GetIpNetTable`) listeler: IP ↔ MAC,
  adapter indeksi, tip (static/dynamic). `arp -a`'nın gösterdiği veri.
- **`sessions`** — makinedeki terminal/logon oturumlarını (`WTSEnumerateSessions`
  + `WTSQuerySessionInformation`) listeler: oturum id, pencere istasyonu, durum,
  oturum açan kullanıcı. "Kim, nasıl bağlı?" sorusunun cevabı.

## Kullanım çıktısı artık kategorili

Komut sayısı 24'e ulaştığı için `winspect` (argümansız) çıktısı dört başlık
altında gruplanıyor: **Static file analysis** (pe, sign, strings, hash),
**Live process inspection** (list, inspect, modules, threads, handles, regions,
token, launch), **Security / triage** (secinfo, verify, triage, ssn),
**System-wide views** (net, services, drivers, autoruns, tasks, pipes, hosts,
certstore).
