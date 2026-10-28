# 05 — token ve secinfo

Bu iki komut güvenliğin iki yüzünü okur. **token**: "kim istiyor?" (özne).
**secinfo**: "kime izin var?" (nesne). Erişim kontrolü bu ikisini karşılaştırır.
Dosyalar: `src/token.c`, `src/secinfo.c`.

---

## Bölüm A — token (özne tarafı)

`winspect token <pid>` bir process'in access token'ını okur: hangi kullanıcı,
hangi gruplar, hangi yetkiler, hangi bütünlük seviyesi.

### 1. İki adımlı sorgu deseni

`GetTokenInformation` her bilgi sınıfı için aynı dansı yapar: önce `NULL`
tamponla çağır (gereken boyutu öğren), sonra o boyutta tampon ayırıp tekrar çağır.
Bunu `query_token` yardımcısına sarmaladık:

```c
GetTokenInformation(tok, cls, NULL, 0, &len);   // len'i öğren
void *buf = malloc(len);
GetTokenInformation(tok, cls, buf, len, &len);  // asıl oku
```

İlk çağrının `ERROR_INSUFFICIENT_BUFFER` ile "başarısız" olması **beklenen**
davranıştır — bu, boyutu öğrenme yöntemidir.

### 2. SID ve RID

**SID (Security Identifier)** bir kullanıcıyı ya da grubu benzersiz tanımlar:
`S-1-5-21-...-1001` gibi. `ConvertSidToStringSid` ile okunur stringe çeviririz,
`LookupAccountSid` ile de arkasındaki hesap ismini (örn. `DESKTOP\berkin`)
buluruz — bu başarısız olabilir, o zaman string SID tek başına yeterli.

SID'in sonundaki sayı **RID**'dir (Relative ID) ve bazıları özeldir:
- `500` = yerleşik **Administrator**
- `501` = Guest
- `1000+` = normal kullanıcılar

Kod, kullanıcı SID'inin RID'i 500 ise bunu özellikle belirtir.

### 3. Integrity level (bütünlük seviyesi)

Token'ın bütünlük seviyesi, `TokenIntegrityLevel`'dan gelen özel bir SID'in
RID'inde saklanır:

| RID | Seviye |
| --- | --- |
| `0x1000` | Low |
| `0x2000` | Medium |
| `0x3000` | High (yükseltilmiş) |
| `0x4000` | System |

Kural: **düşük** seviye **yüksek** seviyeye müdahale edemez. Medium bir process,
High bir process'e kod enjekte edemez ya da belleğini okuyamaz. Bu, `inspect`'te
gördüğün `ERROR_ACCESS_DENIED`'ın asıl sebebidir. `TokenElevation` ile de
process'in yükseltilmiş olup olmadığını (`TokenIsElevated`) basıyoruz.

### 4. Privileges (yetkiler)

Yetkiler makine çapında özel güçlerdir: `SeDebugPrivilege` (her process'e eriş),
`SeLoadDriverPrivilege` (sürücü yükle) gibi. Çoğu token'da **kapalı** durur; kod
kullanacağı an `AdjustTokenPrivileges` ile açar. Bu yüzden "enabled/disabled"
sütunu ilginç olandır. `LookupPrivilegeName` ile LUID'i isme çeviririz.

### 5. Groups

Token'ın üye olduğu gruplar. Her birini SID + isim olarak basarız.
Deny-only ve logon-id gibi iç tutma gruplarını atlayıp listeyi gerçek
üyeliklere odaklıyoruz.

---

## Bölüm B — secinfo (nesne tarafı)

`winspect secinfo <pid|path>` bir nesnenin (bir process ya da bir dosya)
**güvenlik tanımlayıcısını** okur: sahibi (owner) ve DACL'ı.

### 1. pid mi, path mi?

Argüman tamamen rakamsa PID, değilse dosya yolu kabul ediyoruz:

```c
if (all_digits(argv[0])) { /* OpenProcess + GetSecurityInfo */ }
else                     { /* GetNamedSecurityInfo(path) */ }
```

- PID için: `OpenProcess(...READ_CONTROL)` + `GetSecurityInfo(h, SE_KERNEL_OBJECT, ...)`.
- Yol için: `GetNamedSecurityInfo(path, SE_FILE_OBJECT, ...)`.

İkisi de aynı `owner` + `dacl`'ı doldurur, tek bir `sd` (security descriptor)
tamponu geri verir. Sonunda `LocalFree(sd)` ile hepsini birden serbest bırakırız
(owner ve dacl o tamponun içine işaret eder).

### 2. DACL nedir

**DACL (Discretionary Access Control List)** bir **ACE** (Access Control Entry)
listesidir. Her ACE şunu der: "şu SID'e şu erişim **ALLOW** / **DENY**."

Birisi nesneyi açmaya çalıştığında çekirdek DACL'ı, çağıranın token'ına (özne
tarafı!) karşı gezer ve karar verir.

### 3. İki kafa karıştıran özel durum

```c
if (!dacl_present || dacl == NULL) {
    // NULL DACL: hiç erişim kontrolü yok → HERKES tam erişime sahip (ardına kadar açık)
}
if (dacl->AceCount == 0) {
    // Boş DACL: var ama 0 ACE → KİMSEYE hiç erişim yok (tamamen kilitli)
}
```

Bu ikisi **tam zıttır** ve çok karıştırılır:
- **NULL DACL** = "hiç kural yok" = herkese açık.
- **Boş DACL** = "kural var ama hiçbiri izin vermiyor" = kimseye kapalı.

Kod bu farkı açıkça yazar — çünkü NULL DACL gerçek bir güvenlik bulgusudur.

### 4. ACE'leri gezmek

```c
for (WORD i = 0; i < dacl->AceCount; i++) {
    GetAce(dacl, i, &raw);
    ACE_HEADER *hdr = raw;
    if (hdr->AceType == ACCESS_ALLOWED_ACE_TYPE) { verb = "ALLOW"; ... }
    else if (hdr->AceType == ACCESS_DENIED_ACE_TYPE) { verb = "DENY"; ... }
}
```

Her allow/deny ACE şu düzendedir: `{ header, erişim maskesi, SID }`. Tipi, maskeyi
ve SID'i basarız.

**Sıralama kuralı (önemli):** Bir **DENY** ACE, bir **ALLOW**'dan **önce**
geliyorsa kazanır. Bu yüzden Windows deny ACE'lerini listenin başına koyar.
Çıktıyı okurken sırayı dikkate al: üstteki bir deny, alttaki bir allow'u ezebilir.

---

## Özet

- **token** = özne: kim (SID/RID), hangi gruplar, hangi yetkiler (çoğu kapalı),
  hangi integrity (düşük yükseğe dokunamaz).
- **secinfo** = nesne: owner + DACL (ACE'ler). NULL DACL (herkese açık) ile boş
  DACL (kimseye kapalı) zıttır. Deny, allow'u ezer.
- Erişim kontrolü = token'ı DACL'a karşı kontrol etmek.

Sıradaki: [06 — ssn ve launch](06-ssn-launch.md).
