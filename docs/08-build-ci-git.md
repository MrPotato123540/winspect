# 08 — Build, CMake, CI ve git

Bu dosya kodun kendisini değil, **etrafındaki makineyi** anlatır: nasıl
derlenir, iki derleyici neden, CI nedir, ve git akışını nasıl yürütürsün.

---

## 1. CMake: tek tarif, iki derleyici

`CMakeLists.txt` projenin nasıl derleneceğini anlatır. Önemli satırlar:

```cmake
add_executable(winspect
    src/main.c  src/list.c  src/pe.c  src/inspect.c
    src/threads.c  src/handles.c  src/token.c  src/secinfo.c
    src/ssn.c  src/launch.c  src/verify.c
)
target_include_directories(winspect PRIVATE inc)
target_compile_features(winspect PRIVATE c_std_11)       # C11 (anonim union'lar için)
target_compile_definitions(winspect PRIVATE WIN32_LEAN_AND_MEAN)
target_link_libraries(winspect PRIVATE ntdll advapi32 psapi)
```

- **Her yeni komut** buraya bir `src/...c` satırı olarak eklenir.
- **Link edilen kütüphaneler:** `ntdll` (NtQuery...), `advapi32` (token/SID/DACL),
  `psapi` (EnumProcessModulesEx). Üçüncü parti kütüphane yok, hepsi Windows'un
  kendi parçası.
- Derleyiciye göre uyarı seviyesi:
  ```cmake
  if(MSVC) target_compile_options(winspect PRIVATE /W4)
  else()   target_compile_options(winspect PRIVATE -Wall -Wextra -Wpedantic)
  ```

### Derlemek

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
:: çıktı: build\Release\winspect.exe
```

`build.bat` bu iki satırı sarmalar.

---

## 2. Neden iki derleyici (MSVC + MinGW)

Aynı kod hem Microsoft'un derleyicisi (MSVC) hem GCC (MinGW) ile **temiz**
derlenmeli. Neden zahmet?

- "Benim makinemde çalışıyordu" sınıfı hataları yakalar. Bir derleyicinin
  hoş gördüğü bir header/flag varsayımını diğeri reddeder.
- Taşınabilirliği zorlar. Örneğin bu projede `GetProcAddress` sonucunu fonksiyon
  pointer'ına çevirirken GCC'nin `-Wpedantic`/`-Wcast-function-type` uyarılarını
  temizlemek gerekti (koda `void(*)(void)` ara dönüşümü bu yüzden kondu). MSVC bu
  uyarıyı vermezdi; iki derleyici olmasa fark edilmezdi.

---

## 3. CI nedir: kod her değiştiğinde otomatik build + test

**CI (Continuous Integration):** Her push ve her PR'da, bir robot (GitHub'ın
sunucusu) kodu baştan derler ve test eder. Bir şeyi bozduysan **dakikalar içinde**
haber alırsın, bir hafta sonra değil.

`.github/workflows/ci.yml` bunu tanımlar:

```yaml
on:
  push: { branches: [main] }
  pull_request:
jobs:
  build:
    runs-on: windows-latest
    strategy:
      matrix:
        toolchain: [msvc, mingw]   # aynı kod iki derleyicide
```

**matrix** sayesinde iş iki kez koşar: bir kez MSVC, bir kez MinGW. İkisi de
derlenip bir **smoke test** çalıştırır (`winspect pe notepad.exe` → çıkış kodu 0
mı?). Biri bile kırmızı yanarsa PR merge edilemez.

### Release: CD tarafı

`.github/workflows/release.yml`: bir sürüm tag'i (`v1.0.0`) push'ladığında, robot
Release build alır ve `winspect.exe`'yi GitHub Release'e **otomatik** asset olarak
ekler. "Etiketi at, gerisi otomatik" — CI/CD'nin "CD" (Continuous Delivery)
tarafı.

---

## 4. git akışı: her faz bir branch + PR

Belgenin öğrettiği disiplin, her fazı ayrı bir dalda yapıp kendine PR açmaktır.
Tek kişilik projede bile bu alışkanlığı kurmak, ekip çalışmasının standardıdır.

Tipik döngü (örnek: pe fazı):

```bash
# 1. main'den yeni bir feature branch aç
git switch -c feat/pe

# 2. çalış, parça parça commit'le
git add src/pe.c
git commit -m "feat(pe): add optional header parsing"
git add src/pe.c
git commit -m "feat(pe): add section table + imports/exports"

# 3. uzağa (GitHub'a) gönder
git push -u origin feat/pe

# 4. GitHub'da PR aç → CI yeşil yanınca → merge et
```

### Faz 2'nin öğrettiği git araçları (belge planı)

- **Interactive rebase** (`git rebase -i main`): Dalında `wip`, `typo` gibi
  dağınık commit'ler birikir. Merge'den önce bunları temizle: `squash` (birleştir),
  `fixup` (birleştir + mesajı at), `reword` (mesajı düzelt). Sonuç: tertemiz 3-4
  commit'lik anlaşılır bir hikaye.
- **Tag ve ilk release:** `git tag -a v0.1.0 -m "..."` ile annotated tag. Semver:
  `MAJOR.MINOR.PATCH` — kırıcı değişiklik büyük, yeni özellik orta, düzeltme küçük
  rakamı artırır. GitHub'da bu tag'den bir Release oluştur.

---

## 5. Antivirüs uyarısı (bilerek önceden söylüyorum)

winspect `ReadProcessMemory`, `SuspendThread`, ntdll stub okuma ve
`CreateProcess(CREATE_SUSPENDED)` gibi işlemleri bir arada yapıyor. Bu işlemler
**meşru** (Process Explorer, debugger'lar aynısını yapar), ama bazı antivirüsler
bu kombinasyonu heuristik olarak işaretleyebilir. Bunu azaltmak için:

- Belgenin Faz 6'da öğrettiği **imzalı/attested release** (çıkan `.exe`'nin senin
  pipeline'ından çıktığının kriptografik kanıtı).
- README'de ve bu dokümanlarda neyin **neden** yapıldığının açıkça yazılması.

Tamamen önlemek mümkün değil; önceden bilmek yeterli.

---

## 6. Özet

- **CMake** tek tarif, iki derleyici. Yeni komut = bir kaynak satırı.
- **İki derleyici** taşınabilirliği ve gizli varsayımları zorlar.
- **CI** her değişikliği otomatik derler + test eder; **Release** tag'den
  otomatik sürüm üretir.
- **git akışı**: faz başına branch → commit'ler → rebase ile temizle → PR →
  CI yeşil → merge → tag.

Bu dokümantasyonun sonu. Baştan okumak için: [README](README.md).
